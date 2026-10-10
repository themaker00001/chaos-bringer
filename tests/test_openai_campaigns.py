"""Structural checks only, for the OpenAI-backed demo campaigns: loading and validating a
campaign never touches the network (that only happens once an adapter is actually built), so
these run in CI with no key, no Ollama, and no spend against the real call budget."""

import pytest

from chaos_agents.campaign import Campaign

CAMPAIGNS = [
    "campaigns/demo_openai_chat.yaml",
    "campaigns/demo_openai_multiturn.yaml",
    "campaigns/demo_openai_mutation.yaml",
    "campaigns/demo_openai_llm_generated.yaml",
]


@pytest.mark.parametrize("path", CAMPAIGNS)
def test_the_campaign_loads_and_every_named_plugin_exists(path):
    campaign = Campaign.from_yaml(path)
    campaign.check_plugins()   # confirms openai_chat / ollama / llm / mutation / rule_based are all registered
    assert campaign.adapter.plugin == "openai_chat"
    assert campaign.adapter.config.get("model") == "gpt-6.1-sol"


@pytest.mark.parametrize("path", CAMPAIGNS)
def test_no_campaign_file_hardcodes_a_real_looking_key(path):
    text = open(path).read()
    assert "api_key" not in text   # the key comes from the environment only, never a YAML file


def test_the_llm_generated_campaign_keeps_its_own_spend_small():
    """count is how many attacks the (free) generator writes -- and how many of those land on
    the (paid, budget-limited) target. Catches an accidental bump before it costs real calls."""
    campaign = Campaign.from_yaml("campaigns/demo_openai_llm_generated.yaml")
    assert campaign.vector.config["count"] <= 5


def test_the_mutation_campaign_keeps_its_own_spend_small():
    campaign = Campaign.from_yaml("campaigns/demo_openai_mutation.yaml")
    assert campaign.vector.config["max_payloads"] <= 8
