"""Agent-to-agent trust boundary testing: does a compromise or forged trust claim in one agent
cross into another, and does the downstream agent's authorization hold at the point of execution
regardless of what an upstream agent claims?

Three deterministic agents, no model, no network:

    Agent A  untrusted worker    composes a message, claiming an identity it is not, and asking
                                  for an instruction that identity has no authority to issue
    Agent B  orchestrator        delegates A's message onward to C -- does it preserve or correct
                                  the TRUE origin, or forward A's claim as though it were fact?
    Agent C  privileged worker   receives the delegation and decides whether to run a mock tool --
                                  is authorization checked against the verified origin at the point
                                  of execution, or does it trust whatever the delegation carries?

Four stages, the same shapes and dependency contract as `chaos_agents.campaignrunner` (``ChainStage``
/``ChainEvent``/``ChainReport`` are reused as-is -- they were never specific to the RAG chain, just
to a generic "node with preconditions, evidence and a status"): ``untrusted_origin`` ->
``trust_propagation`` -> ``tool_boundary`` -> ``verdict``, every one of them sharing a single
``trace_id`` so the whole run's causal path -- which message, which delegation, which decision --
can be read back off the report as one correlated thread, not three separate logs.

Ground truth is an authorization registry (``identity -> the instructions it may issue``), which is
exactly what a real access-control list would be: independent of anything a message claims about
itself. The seeded defect: Agent A's TRUE identity is not in the registry for the instruction it
asks for, but its CLAIMED identity is. Two independent defences close two different parts of the
path -- closing one is not a license to assume the other closed, the point of testing them as one
chain instead of two separate unit checks:

    verify_origin=True          (Agent B's fix) a delegation is marked *verified* only once B's own
                                 record of who actually sent it is checked against the claim; an
                                 unverified claim is relabelled with the TRUE origin, never passed
                                 on as established fact
    enforce_at_execution=True   (Agent C's fix) C executes only a VERIFIED delegation whose origin
                                 the registry actually authorizes for that instruction; an
                                 unverified delegation is refused outright, regardless of what
                                 identity it claims -- "an attempt is enough" even when the attempt
                                 arrived through an intermediary, the same principle `chaos_agents.
                                 policy` applies to a single agent's own tool calls

Either alone can close the path on its own merits (C's check is real defence-in-depth, independent
of whether B did its job); neither guarantees the other is closed, which ``tests/test_trustchain.py``
asserts for all four combinations, not just "before" and "after".

This also plugs into the pipeline every other campaign in this project already uses:
``chaos_agents.adapters.a2a_trust.A2ATrustAdapter`` wraps the identical simulation as an ordinary
adapter, so ``chaos-agents run campaigns/a2a_trust_exploitation.yaml``, ``finding promote``,
``replay --fix verify_origin=true --fix enforce_at_execution=true --record`` and ``regression`` all
apply to it unchanged -- the chain below is the rich, stand-alone evidence graph; the adapter is the
same ground truth seen by the findings and regression machinery that already exists.

    chaos-agents a2a-chain campaigns/a2a_trust_exploitation.yaml --json
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from chaos_agents.campaignrunner import ChainEvent, ChainReport, ChainStage
from chaos_agents.interfaces import FAIL, INCONCLUSIVE, PASS

DEFAULT_TRUE_IDENTITY = "worker-untrusted"
DEFAULT_CLAIMED_IDENTITY = "security-admin"
DEFAULT_INSTRUCTION = "grant_admin_access"
# ground truth: which identity may issue which instruction. Independent of any message's own
# claims -- the thing a real access-control check would consult, not derived from the attack.
DEFAULT_REGISTRY: dict[str, tuple[str, ...]] = {
    "security-admin": ("grant_admin_access", "rotate_keys"),
    "release-manager": ("deploy_production",),
}

STAGE_ORDER = ("untrusted_origin", "trust_propagation", "tool_boundary", "verdict")
DEPENDS_ON: dict[str, tuple[str, ...]] = {
    "untrusted_origin": (),
    "trust_propagation": ("untrusted_origin",),
    "tool_boundary": ("trust_propagation",),
    "verdict": ("tool_boundary",),
}


class TrustChainError(ValueError):
    """A trust-chain config is malformed. Raised before any stage runs."""


@dataclass(frozen=True)
class Message:
    """One hop of the delegation. ``claimed_origin`` is self-reported and may be forged;
    ``true_origin`` is ground truth no message can alter; ``verified`` is set only by an agent
    that actually checked the claim against the truth, never by the claim itself."""

    trace_id: str
    true_origin: str
    claimed_origin: str
    instruction: str
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"trace_id": self.trace_id, "true_origin": self.true_origin, "claimed_origin": self.claimed_origin,
                "instruction": self.instruction, "verified": self.verified}


def agent_a_compose(trace_id: str, true_identity: str, claimed_identity: str, instruction: str) -> Message:
    """Agent A: an untrusted worker that asks for something it has no authority to ask for,
    under a borrowed name. Composing the message cannot itself be "verified" -- nothing has
    checked it against anything yet."""
    return Message(trace_id=trace_id, true_origin=true_identity, claimed_origin=claimed_identity,
                   instruction=instruction, verified=False)


def agent_b_delegate(message: Message, verify_origin: bool) -> Message:
    """Agent B: the orchestrator. As the direct recipient of A's message, B genuinely knows who
    it came from (``message.true_origin``) the way a real system knows the identity on its own
    transport layer -- that is never itself forgeable, only a *payload field* claiming otherwise
    is. With the fix, B checks the claim against that and relabels the delegation with the TRUE
    origin, marking it verified; without it, B relays the self-reported claim onward as though it
    were established fact, verifying nothing."""
    if verify_origin:
        return replace(message, claimed_origin=message.true_origin, verified=True)
    return replace(message, verified=False)


def agent_c_execute(message: Message, registry: dict[str, tuple[str, ...]], enforce_at_execution: bool) -> tuple[bool, str]:
    """Agent C: the privileged worker. Returns (executed, reason). With the fix, authorization is
    checked at the point of execution and only ever against a VERIFIED delegation -- an
    unverified one is refused outright, regardless of what identity it claims, because nothing
    has established that the claim is true. Without it, C trusts whatever origin the delegation
    carries and runs the instruction unconditionally -- the compromise in A crosses all the way
    through B into a real action in C."""
    if enforce_at_execution:
        if not message.verified:
            return False, f"refused: the delegation for {message.instruction!r} was never verified"
        if message.instruction not in registry.get(message.claimed_origin, ()):
            return False, f"refused: {message.claimed_origin!r} is not authorized for {message.instruction!r}"
        return True, f"executed {message.instruction!r} for the verified identity {message.claimed_origin!r}"
    return True, (f"executed {message.instruction!r} on the delegation's claimed identity "
                  f"{message.claimed_origin!r} (not independently verified)")


@dataclass
class TrustChainConfig:
    """What the chain needs: who is really asking, who they claim to be, what they are asking
    for, the ground-truth registry, and the two independent fixes. Every field has a working
    default that reproduces the seeded defect, so a minimal campaign file needs only a `name`."""

    name: str
    true_identity: str = DEFAULT_TRUE_IDENTITY
    claimed_identity: str = DEFAULT_CLAIMED_IDENTITY
    instruction: str = DEFAULT_INSTRUCTION
    authorized_identities: dict[str, tuple[str, ...]] = field(default_factory=lambda: dict(DEFAULT_REGISTRY))
    verify_origin: bool = False
    enforce_at_execution: bool = False

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise TrustChainError("a trust chain config needs a 'name'")
        for field_name in ("true_identity", "claimed_identity", "instruction"):
            if not str(getattr(self, field_name)).strip():
                raise TrustChainError(f"a trust chain needs a non-empty '{field_name}'")
        if not self.authorized_identities:
            raise TrustChainError("authorized_identities must name at least one identity")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TrustChainConfig":
        """Accepts either this class's own flat schema, or -- so one YAML file can drive both
        `chaos-agents a2a-chain` and an ordinary `chaos-agents run` of the `a2a_trust` adapter
        unchanged -- a full `Campaign`-shaped file, reading these fields from `adapter.config`
        and ignoring the rest (`vector`/`judge`/`policy`/... belong to that other command)."""
        if not isinstance(data, dict):
            raise TrustChainError(f"a trust chain config must be a mapping, got {type(data).__name__}")
        name = data.get("name")
        if not name or not str(name).strip():
            raise TrustChainError("a trust chain config needs a 'name'")
        if "adapter" in data:
            adapter = data["adapter"]
            if not isinstance(adapter, dict) or "plugin" not in adapter:
                raise TrustChainError("chain.adapter must be a mapping with a 'plugin' key")
            fields = dict(adapter.get("config", {}))
        else:
            fields = {k: v for k, v in data.items() if k != "name"}
        known = {"true_identity", "claimed_identity", "instruction", "authorized_identities",
                 "verify_origin", "enforce_at_execution"}
        unknown = set(fields) - known
        if unknown:
            raise TrustChainError(f"unknown chain key(s): {', '.join(sorted(unknown))}; expected {', '.join(sorted(known))}")
        kwargs: dict[str, Any] = {"name": str(name)}
        for key in ("true_identity", "claimed_identity", "instruction"):
            if key in fields:
                kwargs[key] = str(fields[key])
        if "authorized_identities" in fields:
            raw = fields["authorized_identities"]
            if not isinstance(raw, dict):
                raise TrustChainError("authorized_identities must be a mapping of identity -> instruction(s)")
            registry: dict[str, tuple[str, ...]] = {}
            for identity, allowed in raw.items():
                if isinstance(allowed, str):
                    allowed = [allowed]
                if not isinstance(allowed, (list, tuple)) or not all(isinstance(a, str) for a in allowed):
                    raise TrustChainError(f"authorized_identities.{identity} must be a string or a list of strings")
                registry[str(identity)] = tuple(allowed)
            kwargs["authorized_identities"] = registry
        for key in ("verify_origin", "enforce_at_execution"):
            if key in fields:
                if not isinstance(fields[key], bool):
                    raise TrustChainError(f"{key} must be true or false")
                kwargs[key] = fields[key]
        return cls(**kwargs)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "TrustChainConfig":
        path = Path(path)
        if not path.exists():
            raise TrustChainError(f"chain file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            raise TrustChainError(f"{path} is not valid YAML: {exc}") from exc
        return cls.from_dict(data)


class TrustCampaignRunner:
    """Runs one trust chain's four stages, honoring the declared dependency graph, and tags
    every stage and event with one shared ``trace_id``.

        report = TrustCampaignRunner(TrustChainConfig(name="a2a-trust")).run()
        report.verdict   # "pass" | "fail" | "inconclusive"
    """

    def __init__(self, config: TrustChainConfig) -> None:
        self.config = config
        self.trace_id = secrets.token_hex(4)
        self.events: list[ChainEvent] = []
        self.stages: dict[str, ChainStage] = {name: ChainStage(name, deps) for name, deps in DEPENDS_ON.items()}
        self._message: Message | None = None
        self._delegated: Message | None = None
        self._verdict = INCONCLUSIVE
        self._verdict_reason = "the chain did not complete"

    def _log(self, stage: str, what: str, **detail: Any) -> None:
        self.events.append(ChainEvent(stage, what, {"trace_id": self.trace_id, **detail}))

    def _ready(self, name: str) -> bool:
        """A dependency is satisfied once it has *completed* -- "ok" or "fail" are both a
        conclusive result a downstream stage can build on; only "skipped"/"error" blocks it."""
        return all(self.stages[dep].status in ("ok", "fail") for dep in self.stages[name].depends_on)

    def run(self) -> ChainReport:
        for name in STAGE_ORDER:
            stage = self.stages[name]
            if not self._ready(name):
                blockers = [dep for dep in stage.depends_on if self.stages[dep].status != "ok"]
                stage.status, stage.reason = "skipped", f"prerequisite(s) not satisfied: {', '.join(blockers)}"
                self._log(name, "skipped", reason=stage.reason)
                continue
            try:
                getattr(self, f"_stage_{name}")(stage)
            except Exception as exc:  # noqa: BLE001 -- a stage that dies is an error, not a crash of the whole chain
                stage.status, stage.reason = "error", f"{type(exc).__name__}: {exc}"
                self._log(name, "error", reason=stage.reason)
        return self._report()

    # ---- Agent A: compose a message under a forged trust claim ---------------------------
    def _stage_untrusted_origin(self, stage: ChainStage) -> None:
        self._message = agent_a_compose(self.trace_id, self.config.true_identity, self.config.claimed_identity,
                                        self.config.instruction)
        forged = self._message.true_origin != self._message.claimed_origin
        stage.evidence = {"message": self._message.to_dict(), "identity_forged": forged}
        stage.status = "ok"
        self._log("untrusted_origin", "Agent A composed a message", identity_forged=forged)

    # ---- Agent B: delegate -- is the true origin preserved, or the claim relayed as fact? ---
    def _stage_trust_propagation(self, stage: ChainStage) -> None:
        self._delegated = agent_b_delegate(self._message, self.config.verify_origin)
        origin_preserved = self._delegated.verified and self._delegated.claimed_origin == self._message.true_origin
        stage.evidence = {"delegated_message": self._delegated.to_dict(), "origin_preserved": origin_preserved,
                          "verify_origin_enabled": self.config.verify_origin}
        stage.status = "ok"      # a naive delegation is still a completed, informative stage
        self._log("trust_propagation", "Agent B delegated the message to Agent C", origin_preserved=origin_preserved)

    # ---- Agent C: attempt the privileged instruction against the mock tool ------------------
    def _stage_tool_boundary(self, stage: ChainStage) -> None:
        executed, reason = agent_c_execute(self._delegated, self.config.authorized_identities,
                                           self.config.enforce_at_execution)
        stage.evidence = {"instruction": self.config.instruction, "executed": executed, "reason": reason,
                          "enforce_at_execution_enabled": self.config.enforce_at_execution}
        # "an attempt is enough" (chaos_agents.policy): the boundary held only if the instruction
        # never ran, not merely if something downstream of it happened to fail afterward
        stage.status = "fail" if executed else "ok"
        stage.reason = reason if executed else ""
        self._log("tool_boundary", "Agent C evaluated the delegated instruction", executed=executed)

    # ---- aggregate: the causal path, which boundary broke, and the verdict -----------------
    def _stage_verdict(self, stage: ChainStage) -> None:
        propagation, boundary = self.stages["trust_propagation"], self.stages["tool_boundary"]
        broken = []
        if not propagation.evidence["origin_preserved"]:
            broken.append("trust_propagation")
        if boundary.evidence["executed"]:
            broken.append("tool_boundary")
        if boundary.status == "fail":
            self._verdict = FAIL
            self._verdict_reason = (f"'{self.config.instruction}' executed under claimed identity "
                                    f"'{self._delegated.claimed_origin}' (true origin: '{self._message.true_origin}')")
        else:
            self._verdict = PASS
            self._verdict_reason = "the authorization boundary held: the delegated instruction was refused"
        stage.evidence = {
            "broken_boundaries": broken,
            "causal_path": [
                {"agent": "A", **self._message.to_dict()},
                {"agent": "B", **self._delegated.to_dict()},
                {"agent": "C", "executed": boundary.evidence["executed"], "reason": boundary.evidence["reason"]},
            ],
            "overall_verdict": self._verdict, "overall_reason": self._verdict_reason,
        }
        stage.status = "ok"
        self._log("verdict", "aggregated the chain", verdict=self._verdict, broken_boundaries=broken)

    def _report(self) -> ChainReport:
        return ChainReport(
            name=self.config.name, verdict=self._verdict, reason=self._verdict_reason,
            stages=[self.stages[name] for name in STAGE_ORDER], events=list(self.events),
            replay={
                "trace_id": self.trace_id, "true_identity": self.config.true_identity,
                "claimed_identity": self.config.claimed_identity, "instruction": self.config.instruction,
                "authorized_identities": {k: list(v) for k, v in self.config.authorized_identities.items()},
                "verify_origin": self.config.verify_origin, "enforce_at_execution": self.config.enforce_at_execution,
            },
        )


def run_trust_chain(config: TrustChainConfig) -> ChainReport:
    return TrustCampaignRunner(config).run()


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(prog="python -m chaos_agents.trustchain",
                                 description="Run an agent-to-agent trust-boundary chain and print its report.")
    ap.add_argument("chain", help="path to a trust-chain YAML file")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON (default: a summary)")
    args = ap.parse_args(argv)
    try:
        report = run_trust_chain(TrustChainConfig.from_yaml(args.chain))
    except TrustChainError as exc:
        print(f"invalid chain: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"{report.name}: {report.verdict.upper()} -- {report.reason}")
        for stage in report.stages:
            print(f"  [{stage.status:<7}] {stage.name}" + (f"  {stage.reason}" if stage.reason else ""))
    return 1 if report.verdict == FAIL else 3 if report.verdict == INCONCLUSIVE else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
