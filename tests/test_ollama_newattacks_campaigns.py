"""Structural checks for the campaigns that validate the new Crescendo/mutator attacks for
free, before they're ever considered against a budget-limited paid target. Loading a campaign
never touches a model (only running it does), so these need no live Ollama server."""

import pytest

from chaos_agents.campaign import Campaign

CAMPAIGNS = ["campaigns/demo_ollama_crescendo.yaml", "campaigns/demo_ollama_newmutators.yaml"]


@pytest.mark.parametrize("path", CAMPAIGNS)
def test_the_campaign_loads_and_every_named_plugin_exists(path):
    campaign = Campaign.from_yaml(path)
    campaign.check_plugins()
    assert campaign.adapter.plugin == "ollama_chat"
