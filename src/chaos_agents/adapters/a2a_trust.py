"""A demo target: the agent-to-agent trust-boundary scenario (see ``chaos_agents.trustchain``),
wrapped as an ordinary adapter.

The chain in ``trustchain.py`` is the rich, stand-alone evidence graph (``chaos-agents a2a-chain``).
This is the identical simulation -- the same `TrustCampaignRunner`, not a second implementation --
presented as something the existing pipeline already knows how to run, so `chaos-agents run`,
`finding promote`, `replay --fix KEY=VALUE --record` and `regression` all apply to it unchanged, the
same way they do to `toolbot`: one adapter, one payload in, one `Observation` out.

The payload is ignored -- the scenario's behavior is entirely config-driven (who is really asking,
who they claim to be, what they are asking for, and whether Agent B/C's two independent fixes are
on) -- so any vector that sends at least one trial works; the bundled campaign uses
``static_corpus`` with a single placeholder payload. If the privileged instruction executes, it
appears as a tool call named for the instruction itself, so an ordinary policy rule
(``capabilities: {grant_admin_access: deny}``) catches it exactly like any other tool-boundary
violation.
"""

from __future__ import annotations

from typing import Any

from chaos_agents.observation import Observation, ToolCall
from chaos_agents.trustchain import DEFAULT_REGISTRY, TrustCampaignRunner, TrustChainConfig


def _as_registry(raw: dict[str, Any] | None) -> dict[str, tuple[str, ...]]:
    if not raw:
        return dict(DEFAULT_REGISTRY)
    out: dict[str, tuple[str, ...]] = {}
    for identity, allowed in raw.items():
        out[str(identity)] = tuple(allowed) if isinstance(allowed, (list, tuple)) else (str(allowed),)
    return out


class A2ATrustAdapter:
    def __init__(
        self,
        true_identity: str = "worker-untrusted",
        claimed_identity: str = "security-admin",
        instruction: str = "grant_admin_access",
        authorized_identities: dict[str, Any] | None = None,
        verify_origin: bool = False,
        enforce_at_execution: bool = False,
    ) -> None:
        self.config = TrustChainConfig(
            name="a2a-trust", true_identity=true_identity, claimed_identity=claimed_identity,
            instruction=instruction, authorized_identities=_as_registry(authorized_identities),
            verify_origin=verify_origin, enforce_at_execution=enforce_at_execution,
        )

    def observe(self, payload: str) -> Observation:
        report = TrustCampaignRunner(self.config).run()
        boundary = next(s for s in report.stages if s.name == "tool_boundary")
        delegated = next(s for s in report.stages if s.name == "trust_propagation").evidence["delegated_message"]
        calls = []
        if boundary.evidence["executed"]:
            calls.append(ToolCall(
                name=self.config.instruction,
                arguments={"claimed_identity": delegated["claimed_origin"], "verified": delegated["verified"]},
                result="executed"))
        return Observation(response=boundary.evidence["reason"], tool_calls=calls, raw={"a2a_trust": report.to_dict()})

    def invoke(self, payload: str) -> str:
        return self.observe(payload).response

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"A2ATrustAdapter(verify_origin={self.config.verify_origin}, enforce_at_execution={self.config.enforce_at_execution})"
