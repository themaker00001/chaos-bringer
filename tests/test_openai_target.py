"""The OpenAI provider and chat adapter: key resolution, the shared call budget, and response
parsing -- all mocked. No test here makes a real network call or needs a real key.

Every test that builds a provider/adapter runs inside a `tmp_path` cwd (`monkeypatch.chdir`),
so its call budget lands in an isolated `.chaos_agents/` and never touches the real counter this
project's own (rate-limited, real) key has been spending against.
"""

import pytest

from chaos_agents.adapters.openai_chat import OpenAIChatAdapter
from chaos_agents.callbudget import BudgetExhausted
from chaos_agents.interfaces import TargetError
from chaos_agents.providers.openai import OpenAIProvider, OpenAIProviderError, resolve_api_key


@pytest.fixture(autouse=True)
def isolated_budget(tmp_path, monkeypatch):
    """Every test in this file gets its own .chaos_agents/, never the real one."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CHAOS_AGENTS_OPENAI_CALL_BUDGET", raising=False)


class FakeResponse:
    def __init__(self, content="ok", status=200):
        self._content, self.status_code = content, status

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"{self.status_code}")

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


def fake_post(captured, content="ok"):
    def post(url, headers=None, json=None, timeout=None):
        # snapshot now: `json["messages"]` is the caller's own list, which it keeps mutating
        # (appending the reply) after this call returns -- a live reference would silently grow
        snapshot = {**json, "messages": [dict(m) for m in json["messages"]]}
        captured.append({"url": url, "headers": headers, "json": snapshot, "timeout": timeout})
        return FakeResponse(content)
    return post


# ---- key resolution ----------------------------------------------------------------------

def test_resolve_api_key_prefers_the_explicit_value():
    assert resolve_api_key("sk-explicit") == "sk-explicit"


def test_resolve_api_key_falls_back_to_the_environment(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
    assert resolve_api_key(None) == "sk-from-env"


def test_resolve_api_key_expands_a_placeholder(monkeypatch):
    monkeypatch.setenv("MY_OTHER_KEY", "sk-placeholder")
    assert resolve_api_key("${MY_OTHER_KEY}") == "sk-placeholder"


def test_resolve_api_key_raises_a_clear_error_for_an_unset_placeholder(monkeypatch):
    monkeypatch.delenv("MY_OTHER_KEY", raising=False)
    with pytest.raises(OpenAIProviderError, match="MY_OTHER_KEY"):
        resolve_api_key("${MY_OTHER_KEY}")


def test_resolve_api_key_raises_a_clear_error_when_nothing_is_set():
    with pytest.raises(OpenAIProviderError, match="OPENAI_API_KEY"):
        resolve_api_key(None)


def test_resolve_api_key_loads_a_local_env_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-from-dotenv\n")
    assert resolve_api_key(None) == "sk-from-dotenv"


# ---- OpenAIProvider ------------------------------------------------------------------------

def test_provider_sends_a_chat_completion_and_returns_the_content(monkeypatch):
    captured = []
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", fake_post(captured, "hello there"))
    p = OpenAIProvider(api_key="sk-test", model="gpt-6.1-sol")
    assert p.complete("hi") == "hello there"
    assert captured[0]["json"]["model"] == "gpt-6.1-sol"
    assert captured[0]["headers"]["Authorization"] == "Bearer sk-test"


def test_provider_charges_the_budget_once_per_call(monkeypatch):
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", fake_post([]))
    p = OpenAIProvider(api_key="sk-test", max_calls=5)
    p.complete("a"); p.complete("b")
    assert p.budget.used == 2 and p.budget.remaining == 3


def test_provider_refuses_once_its_budget_is_spent_and_makes_no_request(monkeypatch):
    captured = []
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", fake_post(captured))
    p = OpenAIProvider(api_key="sk-test", max_calls=1)
    p.complete("a")
    with pytest.raises(BudgetExhausted):
        p.complete("b")
    assert len(captured) == 1   # the refused call never reached the network


def test_provider_wraps_a_network_failure(monkeypatch):
    import requests

    def boom(*a, **k):
        raise requests.ConnectionError("down")
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", boom)
    with pytest.raises(OpenAIProviderError, match="could not reach OpenAI"):
        OpenAIProvider(api_key="sk-test").complete("a")


def test_provider_raises_on_an_unexpected_response_shape(monkeypatch):
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post",
                        lambda *a, **k: type("R", (), {"status_code": 200, "raise_for_status": lambda s: None,
                                                        "json": lambda s: {"nope": True}})())
    with pytest.raises(OpenAIProviderError, match="unexpected OpenAI response"):
        OpenAIProvider(api_key="sk-test").complete("a")


def test_provider_repr_never_includes_the_key(monkeypatch):
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", fake_post([]))
    p = OpenAIProvider(api_key="sk-super-secret-value")
    assert "sk-super-secret-value" not in repr(p)


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "openai" in registry.available("chaos_agents.providers")


# ---- OpenAIChatAdapter ----------------------------------------------------------------------

def test_adapter_invoke_is_a_single_turn(monkeypatch):
    captured = []
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", fake_post(captured, "a reply"))
    bot = OpenAIChatAdapter(api_key="sk-test")
    assert bot.invoke("hello") == "a reply"
    assert len(captured[0]["json"]["messages"]) == 2   # system + the one user turn


def test_adapter_converse_carries_state_across_turns(monkeypatch):
    captured = []
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", fake_post(captured, "ok"))
    bot = OpenAIChatAdapter(api_key="sk-test")
    replies = bot.converse(["first", "second", "third"])
    assert replies == ["ok", "ok", "ok"]
    assert len(captured) == 3
    assert len(captured[-1]["json"]["messages"]) == 1 + 5   # system + 3 user + 2 prior assistant replies


def test_adapter_and_provider_share_one_budget_by_name(monkeypatch):
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", fake_post([]))
    provider = OpenAIProvider(api_key="sk-test", max_calls=3)
    adapter = OpenAIChatAdapter(api_key="sk-test", max_calls=3)
    provider.complete("a")
    adapter.invoke("b")
    assert adapter.budget.used == 2            # the same on-disk counter, seen from either object
    with pytest.raises(BudgetExhausted):
        adapter.invoke("c")   # one more call: would be 2 already spent + 1 user turn = 3, then a 4th tips it
        adapter.invoke("d")


def test_adapter_wraps_a_provider_error_as_a_target_error(monkeypatch):
    import requests

    def boom(*a, **k):
        raise requests.ConnectionError("down")
    monkeypatch.setattr("chaos_agents.providers.openai.requests.post", boom)
    with pytest.raises(TargetError):
        OpenAIChatAdapter(api_key="sk-test").invoke("a")


def test_adapter_default_system_prompt_holds_a_canary_to_attack():
    bot = OpenAIChatAdapter(api_key="sk-test")
    assert "sk-demo-12345" in bot.system


def test_adapter_repr_never_includes_the_key(monkeypatch):
    bot = OpenAIChatAdapter(api_key="sk-another-secret")
    assert "sk-another-secret" not in repr(bot)


def test_registered_as_an_adapter_plugin():
    from chaos_agents import registry

    assert "openai_chat" in registry.available("chaos_agents.adapters")


# ---- the key never leaks into a run snapshot -------------------------------------------------

def test_an_explicit_api_key_in_a_campaign_is_redacted_in_the_snapshot():
    from chaos_agents.runstore import redact_campaign

    campaign = {"name": "x", "adapter": {"plugin": "openai_chat", "config": {"api_key": "sk-should-not-be-saved"}},
               "vector": {"plugin": "static_corpus", "config": {}}, "judge": {"plugin": "rule_based", "config": {}}}
    redacted = redact_campaign(campaign)
    assert redacted["adapter"]["config"]["api_key"] == "${API_KEY}"
    assert "sk-should-not-be-saved" not in str(redacted)
