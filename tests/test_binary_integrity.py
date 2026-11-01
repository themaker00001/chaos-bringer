"""Supply-chain binary tampering: deterministic, no model needed -- tests whether a tampered
binary actually gets "executed" (a label, never a real subprocess call) when its integrity
against a known manifest hash is or isn't checked first."""

import hashlib

from chaos_agents.adapters.binary_integrity import (
    DEFAULT_LEGITIMATE_CONTENT,
    DEFAULT_TAMPERED_CONTENT,
    BinaryIntegrityAdapter,
)


def test_the_legitimate_content_s_hash_is_the_manifest_hash():
    adapter = BinaryIntegrityAdapter()
    assert adapter.manifest_hash == hashlib.sha256(DEFAULT_LEGITIMATE_CONTENT).hexdigest()


def test_vulnerable_by_default_a_tampered_binary_runs_anyway():
    obs = BinaryIntegrityAdapter().observe("fetch and run the tool")
    assert obs.raw["tampered"] is True
    assert obs.raw["executed_tampered_binary"] is True
    assert "attacker.example" in obs.tool_calls[1].result


def test_the_fetch_step_never_exposes_the_tampered_content_itself():
    """Only a byte count and hash -- the attacker's payload text never appears here regardless
    of whether execution later happens, so the judge can only fire on real execution."""
    obs = BinaryIntegrityAdapter().observe("fetch and run the tool")
    assert "attacker.example" not in obs.tool_calls[0].result
    assert "sha256=" in obs.tool_calls[0].result


def test_verify_integrity_refuses_the_tampered_binary():
    obs = BinaryIntegrityAdapter(verify_integrity=True).observe("fetch and run the tool")
    assert obs.raw["tampered"] is True
    assert obs.raw["executed_tampered_binary"] is False
    assert obs.tool_calls[1].result.startswith("REFUSED")
    assert "attacker.example" not in obs.tool_calls[1].result


def test_verify_integrity_still_runs_a_genuinely_untampered_binary():
    obs = BinaryIntegrityAdapter(verify_integrity=True, delivered_content=DEFAULT_LEGITIMATE_CONTENT).observe("x")
    assert obs.raw["tampered"] is False
    assert obs.raw["executed_tampered_binary"] is False   # ran, but it was never tampered
    assert obs.tool_calls[1].result.startswith("EXECUTED")


def test_an_untampered_binary_runs_fine_even_without_verification():
    obs = BinaryIntegrityAdapter(verify_integrity=False, delivered_content=DEFAULT_LEGITIMATE_CONTENT).observe("x")
    assert obs.raw["tampered"] is False
    assert obs.raw["executed_tampered_binary"] is False


def test_invoke_returns_just_the_reply():
    assert BinaryIntegrityAdapter().invoke("x").startswith("Tool binary processed.")


def test_repr_shows_the_fix_state():
    assert "verify_integrity=True" in repr(BinaryIntegrityAdapter(verify_integrity=True))


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "binary_integrity" in registry.available("chaos_agents.adapters")


def test_the_campaign_is_a_finding_through_the_real_pipeline(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_binary_integrity.yaml")
    campaign.check_plugins()
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert any(r.status == FAIL for r in records)


def test_the_campaign_passes_once_the_fix_is_applied(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_binary_integrity.yaml")
    campaign.adapter.config["verify_integrity"] = True
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert not any(r.status == FAIL for r in records)
