"""The agent-to-agent trust chain: three deterministic agents, a seeded delegation-abuse defect,
two independent fixes, and the same regression/replay pipeline every other target uses."""

import json

import pytest

from chaos_agents.adapters.a2a_trust import A2ATrustAdapter
from chaos_agents.interfaces import FAIL, INCONCLUSIVE, PASS
from chaos_agents.trustchain import (
    DEFAULT_REGISTRY, TrustCampaignRunner, TrustChainConfig, TrustChainError, run_trust_chain,
)


def by_name(report):
    return {s.name: s for s in report.stages}


# ---- TrustChainConfig: construction and validation -----------------------------------------

def test_a_minimal_config_needs_only_a_name():
    cfg = TrustChainConfig(name="x")
    assert cfg.true_identity == "worker-untrusted" and cfg.instruction == "grant_admin_access"
    assert cfg.verify_origin is False and cfg.enforce_at_execution is False


@pytest.mark.parametrize("field_", ["true_identity", "claimed_identity", "instruction"])
def test_every_identity_field_must_be_non_empty(field_):
    with pytest.raises(TrustChainError):
        TrustChainConfig(name="x", **{field_: "  "})


def test_name_must_be_non_empty():
    with pytest.raises(TrustChainError, match="needs a 'name'"):
        TrustChainConfig(name="  ")


def test_the_registry_must_name_at_least_one_identity():
    with pytest.raises(TrustChainError, match="at least one identity"):
        TrustChainConfig(name="x", authorized_identities={})


def test_from_dict_flat_schema():
    cfg = TrustChainConfig.from_dict({
        "name": "x", "true_identity": "a", "claimed_identity": "b", "instruction": "do_it",
        "authorized_identities": {"b": "do_it"}, "verify_origin": True, "enforce_at_execution": True,
    })
    assert cfg.true_identity == "a" and cfg.authorized_identities == {"b": ("do_it",)}
    assert cfg.verify_origin and cfg.enforce_at_execution


def test_from_dict_reads_a_campaign_shaped_file_via_adapter_config():
    """One YAML file drives both `a2a-chain` and an ordinary `chaos-agents run` of `a2a_trust`
    unchanged: the fields live under adapter.config, and vector/judge/policy are simply not ours."""
    cfg = TrustChainConfig.from_dict({
        "name": "x", "category": "agent_to_agent", "technique": "delegation_abuse",
        "adapter": {"plugin": "a2a_trust", "config": {"claimed_identity": "root", "verify_origin": True}},
        "vector": {"plugin": "static_corpus", "config": {}},
        "policy": {"capabilities": {"grant_admin_access": "deny"}},
    })
    assert cfg.claimed_identity == "root" and cfg.verify_origin is True
    assert cfg.authorized_identities == DEFAULT_REGISTRY   # not overridden -> the default


def test_from_dict_rejects_unknown_keys_missing_name_and_bad_shapes():
    with pytest.raises(TrustChainError, match="unknown chain key"):
        TrustChainConfig.from_dict({"name": "x", "nope": 1})
    with pytest.raises(TrustChainError, match="needs a 'name'"):
        TrustChainConfig.from_dict({})
    with pytest.raises(TrustChainError, match="must be a mapping"):
        TrustChainConfig.from_dict("x")
    with pytest.raises(TrustChainError, match="'plugin' key"):
        TrustChainConfig.from_dict({"name": "x", "adapter": {}})
    with pytest.raises(TrustChainError, match="must be true or false"):
        TrustChainConfig.from_dict({"name": "x", "verify_origin": "yes"})
    with pytest.raises(TrustChainError, match="mapping of identity"):
        TrustChainConfig.from_dict({"name": "x", "authorized_identities": ["not", "a", "mapping"]})


def test_from_yaml_reads_the_shipped_demo_and_matches_the_default_registry():
    cfg = TrustChainConfig.from_yaml("campaigns/a2a_trust_exploitation.yaml")
    assert cfg.name == "a2a-trust-exploitation" and cfg.instruction == "grant_admin_access"
    assert cfg.authorized_identities["security-admin"] == ("grant_admin_access", "rotate_keys")


def test_from_yaml_missing_file():
    with pytest.raises(TrustChainError, match="not found"):
        TrustChainConfig.from_yaml("campaigns/does-not-exist.yaml")


# ---- the four-way truth table: the whole reason this is a chain, not one check -------------

@pytest.mark.parametrize("verify_origin,enforce_at_execution,expected,broken", [
    (False, False, FAIL, {"trust_propagation", "tool_boundary"}),   # the seeded defect, both naive
    (False, True, PASS, {"trust_propagation"}),                     # C's own check saves it alone
    (True, False, FAIL, {"tool_boundary"}),                         # B behaves; C still doesn't check -- still a violation
    (True, True, PASS, set()),                                      # both fixes: clean
])
def test_the_truth_table(verify_origin, enforce_at_execution, expected, broken):
    report = run_trust_chain(TrustChainConfig(name="x", verify_origin=verify_origin, enforce_at_execution=enforce_at_execution))
    assert report.verdict == expected
    assert set(by_name(report)["verdict"].evidence["broken_boundaries"]) == broken


def test_one_fix_does_not_imply_the_other_is_closed():
    """The specific lesson the chain exists to catch: Agent B doing the right thing is not a
    license to assume Agent C does too."""
    honest_b = run_trust_chain(TrustChainConfig(name="x", verify_origin=True, enforce_at_execution=False))
    assert honest_b.verdict == FAIL
    assert by_name(honest_b)["trust_propagation"].evidence["origin_preserved"] is True
    assert by_name(honest_b)["tool_boundary"].evidence["executed"] is True


# ---- causal evidence: trace_id, the exact path, replayable -----------------------------------

def test_every_stage_and_event_shares_one_trace_id():
    runner = TrustCampaignRunner(TrustChainConfig(name="x"))
    report = runner.run()
    assert runner.events and all(e.detail["trace_id"] == runner.trace_id for e in runner.events)
    verdict_evidence = by_name(report)["verdict"].evidence
    path_trace_ids = {hop["trace_id"] for hop in verdict_evidence["causal_path"][:2]}   # A and B carry one
    assert path_trace_ids == {runner.trace_id}


def test_the_causal_path_names_each_agent_and_identifies_the_broken_boundary():
    report = run_trust_chain(TrustChainConfig(name="x"))
    verdict = by_name(report)["verdict"].evidence
    agents = [hop["agent"] for hop in verdict["causal_path"]]
    assert agents == ["A", "B", "C"]
    assert verdict["causal_path"][0]["claimed_origin"] == "security-admin"
    assert verdict["causal_path"][1]["claimed_origin"] == "security-admin"   # B relayed the forged claim as fact
    assert verdict["causal_path"][2]["executed"] is True
    assert "trust_propagation" in verdict["broken_boundaries"] and "tool_boundary" in verdict["broken_boundaries"]


def test_the_report_is_fully_json_serializable_and_carries_a_replay_config():
    report = run_trust_chain(TrustChainConfig(name="x"))
    data = json.loads(json.dumps(report.to_dict()))
    assert data["replay"]["true_identity"] == "worker-untrusted"
    assert data["replay"]["authorized_identities"]["security-admin"] == ["grant_admin_access", "rotate_keys"]
    assert "trace_id" in data["replay"]
    assert len(data["events"]) >= 4


def test_replaying_the_recorded_config_reproduces_the_same_verdict():
    report = run_trust_chain(TrustChainConfig(name="x"))
    rebuilt = TrustChainConfig(
        name="replayed", true_identity=report.replay["true_identity"], claimed_identity=report.replay["claimed_identity"],
        instruction=report.replay["instruction"],
        authorized_identities={k: tuple(v) for k, v in report.replay["authorized_identities"].items()},
        verify_origin=report.replay["verify_origin"], enforce_at_execution=report.replay["enforce_at_execution"],
    )
    assert run_trust_chain(rebuilt).verdict == report.verdict == FAIL


def test_each_run_gets_its_own_trace_id():
    a = TrustCampaignRunner(TrustChainConfig(name="x"))
    b = TrustCampaignRunner(TrustChainConfig(name="x"))
    assert a.trace_id != b.trace_id


# ---- the dependency graph: a stage runs only once its prerequisites are satisfied -----------

def test_a_failed_stage_still_counts_as_satisfied_for_what_depends_on_it():
    """The same regression class the RAG chain caught: a confirmed violation at stage 3 must
    still reach the verdict stage, not vanish because it wasn't a pass."""
    report = run_trust_chain(TrustChainConfig(name="x"))
    verdict_stage = next(s for s in report.stages if s.name == "verdict")
    assert verdict_stage.status == "ok" and verdict_stage.depends_on == ("tool_boundary",)


def test_an_error_in_the_first_stage_cascades_as_skipped(monkeypatch):
    def boom(self, stage):
        raise RuntimeError("boom")

    monkeypatch.setattr(TrustCampaignRunner, "_stage_untrusted_origin", boom)
    report = run_trust_chain(TrustChainConfig(name="x"))
    statuses = {s.name: (s.status, s.reason) for s in report.stages}
    assert statuses["untrusted_origin"] == ("error", "RuntimeError: boom")
    assert statuses["trust_propagation"] == ("skipped", "prerequisite(s) not satisfied: untrusted_origin")
    assert statuses["tool_boundary"] == ("skipped", "prerequisite(s) not satisfied: trust_propagation")
    assert statuses["verdict"] == ("skipped", "prerequisite(s) not satisfied: tool_boundary")
    assert report.verdict == INCONCLUSIVE


def test_the_graph_lists_every_stage_and_the_declared_edges():
    report = run_trust_chain(TrustChainConfig(name="x"))
    graph = report.graph()
    assert {n["id"] for n in graph["nodes"]} == {"untrusted_origin", "trust_propagation", "tool_boundary", "verdict"}
    assert ["untrusted_origin", "trust_propagation"] in graph["edges"]
    assert ["tool_boundary", "verdict"] in graph["edges"]


# ---- the registry is ground truth, independent of any message's own claims -----------------

def test_an_identity_absent_from_the_registry_entirely_is_still_refused_not_an_error():
    """`registry.get(identity, ())` must handle an identity the registry never mentions at all,
    not just one it mentions for a different instruction."""
    cfg = TrustChainConfig(name="x", true_identity="totally-unlisted", claimed_identity="totally-unlisted",
                           verify_origin=True, enforce_at_execution=True)
    report = run_trust_chain(cfg)
    assert report.verdict == PASS
    assert by_name(report)["tool_boundary"].status == "ok"


def test_fully_defended_refuses_even_a_syntactically_valid_but_unauthorized_identity():
    cfg = TrustChainConfig(name="x", true_identity="intern", claimed_identity="intern",
                           authorized_identities={"security-admin": ("grant_admin_access",)},
                           verify_origin=True, enforce_at_execution=True)
    report = run_trust_chain(cfg)
    assert report.verdict == PASS
    assert "not authorized" in by_name(report)["tool_boundary"].evidence["reason"]


# ---- A2ATrustAdapter: the same simulation as an ordinary ObservingTarget --------------------

def test_the_adapter_reports_the_tool_call_when_the_instruction_executes():
    obs = A2ATrustAdapter().observe("payload is ignored")
    assert len(obs.tool_calls) == 1
    call = obs.tool_calls[0]
    assert call.name == "grant_admin_access" and call.arguments["claimed_identity"] == "security-admin"
    assert call.arguments["verified"] is False


def test_the_adapter_reports_no_tool_call_once_fixed():
    obs = A2ATrustAdapter(verify_origin=True, enforce_at_execution=True).observe("x")
    assert obs.tool_calls == []
    assert "refused" in obs.response


def test_the_adapter_carries_the_full_chain_report_in_raw():
    obs = A2ATrustAdapter().observe("x")
    assert obs.raw["a2a_trust"]["verdict"] == "fail"
    assert {s["name"] for s in obs.raw["a2a_trust"]["stages"]} == {"untrusted_origin", "trust_propagation", "tool_boundary", "verdict"}


def test_the_adapter_accepts_a_plain_dict_registry_from_yaml():
    adapter = A2ATrustAdapter(authorized_identities={"security-admin": ["grant_admin_access"]})
    assert adapter.config.authorized_identities == {"security-admin": ("grant_admin_access",)}


# ---- through the ordinary campaign pipeline: policy, findings, promote, replay, regression --

def test_the_shipped_campaign_is_a_policy_violation_through_the_real_pipeline(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/a2a_trust_exploitation.yaml")
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert len(records) == 1 and records[0].status == FAIL
    assert "grant_admin_access" in records[0].reason and records[0].fingerprint.startswith("sha256:")


def test_the_shipped_campaign_passes_once_both_fixes_are_applied(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/a2a_trust_exploitation.yaml")
    campaign.adapter.config.update({"verify_origin": True, "enforce_at_execution": True})
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert records[0].status == PASS


def test_cli_finding_promote_and_replay_fix_record_and_regression_all_work(tmp_path, capsys, monkeypatch):
    """The regression this project asked for: run the vulnerable chain, promote it, replay with
    both fixes applied, and confirm the regression corpus then guards the fixed target --
    the exact `finding promote` / `replay --fix --record` / `regression` pipeline, unmodified."""
    from chaos_agents.cli import main

    monkeypatch.chdir(tmp_path)
    campaign_path = str((__import__("pathlib").Path(__file__).resolve().parent.parent / "campaigns" / "a2a_trust_exploitation.yaml"))
    assert main(["run", campaign_path]) == 1
    capsys.readouterr()
    main(["finding", "list"])
    fid = next(w for w in capsys.readouterr().out.split() if w.startswith("CB-"))

    assert main(["finding", "promote", fid, "--campaign", campaign_path]) == 0
    assert main(["replay", fid]) == 1   # unmodified: still vulnerable
    capsys.readouterr()
    assert main(["replay", fid, "--fix", "verify_origin=true", "--fix", "enforce_at_execution=true", "--record"]) == 0
    assert "PASS" in capsys.readouterr().out
    assert main(["regression"]) == 0


# ---- the CLI: a2a-chain ----------------------------------------------------------------------

def test_cli_a2a_chain_runs_the_shipped_demo(capsys):
    from chaos_agents.cli import main

    code = main(["a2a-chain", "campaigns/a2a_trust_exploitation.yaml"])
    out = capsys.readouterr().out
    assert code == 1 and "a2a-trust-exploitation: FAIL" in out
    assert "[fail   ] tool_boundary" in out


def test_cli_a2a_chain_json_output(capsys):
    from chaos_agents.cli import main

    code = main(["a2a-chain", "campaigns/a2a_trust_exploitation.yaml", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1 and data["verdict"] == "fail" and "graph" in data and "replay" in data


def test_cli_a2a_chain_output_flag_writes_the_report(tmp_path, capsys):
    from chaos_agents.cli import main

    out_path = tmp_path / "report.json"
    main(["a2a-chain", "campaigns/a2a_trust_exploitation.yaml", "--output", str(out_path)])
    data = json.loads(out_path.read_text())
    assert data["name"] == "a2a-trust-exploitation"
    assert f"report written to: {out_path}" in capsys.readouterr().err


def test_cli_a2a_chain_exits_zero_once_fixed(tmp_path, capsys):
    import yaml

    from chaos_agents.cli import main

    data = yaml.safe_load(open("campaigns/a2a_trust_exploitation.yaml"))
    data["adapter"]["config"]["verify_origin"] = True
    data["adapter"]["config"]["enforce_at_execution"] = True
    path = tmp_path / "fixed.yaml"
    path.write_text(yaml.safe_dump(data))
    code = main(["a2a-chain", str(path)])
    assert code == 0 and "PASS" in capsys.readouterr().out


def test_cli_a2a_chain_rejects_an_invalid_file(tmp_path, capsys):
    from chaos_agents.cli import main

    path = tmp_path / "bad.yaml"
    path.write_text("name: x\nnope: 1\n")
    assert main(["a2a-chain", str(path)]) == 2
    assert "invalid chain" in capsys.readouterr().err


def test_cli_a2a_chain_is_listed_in_help(capsys):
    from chaos_agents.cli import main

    with pytest.raises(SystemExit):
        main(["--help"])
    assert "a2a-chain" in capsys.readouterr().out


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "a2a_trust" in registry.available("chaos_agents.adapters")
