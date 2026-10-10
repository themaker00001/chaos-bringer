"""The call budget: a hard, persistent cap, not an honor system."""

import pytest

from chaos_agents.callbudget import BudgetExhausted, CallBudget, from_env


def test_starts_at_zero_used(tmp_path):
    b = CallBudget("x", limit=5, directory=tmp_path)
    assert b.used == 0 and b.remaining == 5


def test_charge_increments_and_persists(tmp_path):
    b = CallBudget("x", limit=5, directory=tmp_path)
    assert b.charge() == 1
    assert b.charge() == 2
    assert b.used == 2 and b.remaining == 3


def test_a_second_instance_on_the_same_name_and_directory_sees_the_same_count(tmp_path):
    CallBudget("x", limit=5, directory=tmp_path).charge(3)
    fresh = CallBudget("x", limit=5, directory=tmp_path)
    assert fresh.used == 3 and fresh.remaining == 2


def test_raises_once_the_limit_would_be_exceeded_and_spends_nothing(tmp_path):
    b = CallBudget("x", limit=2, directory=tmp_path)
    b.charge()
    b.charge()
    with pytest.raises(BudgetExhausted, match="spent: 2 of 2"):
        b.charge()
    assert b.used == 2   # the failed attempt did not sneak through


def test_charging_more_than_one_at_once_is_all_or_nothing(tmp_path):
    b = CallBudget("x", limit=5, directory=tmp_path)
    b.charge(4)
    with pytest.raises(BudgetExhausted):
        b.charge(2)      # would be 6 of 5
    assert b.used == 4


def test_different_names_in_the_same_directory_are_independent_counters(tmp_path):
    a = CallBudget("a", limit=3, directory=tmp_path)
    b = CallBudget("b", limit=3, directory=tmp_path)
    a.charge(3)
    assert a.remaining == 0 and b.remaining == 3


def test_a_limit_under_one_is_rejected():
    with pytest.raises(ValueError, match="at least 1"):
        CallBudget("x", limit=0)


def test_a_corrupt_or_missing_counter_file_reads_as_zero_not_a_crash(tmp_path):
    b = CallBudget("x", limit=5, directory=tmp_path)
    assert b.used == 0
    (tmp_path / "x.json").write_text("not json")
    assert CallBudget("x", limit=5, directory=tmp_path).used == 0


def test_from_env_defaults_without_the_variable_set(monkeypatch):
    monkeypatch.delenv("CHAOS_AGENTS_OPENAI_CALL_BUDGET", raising=False)
    assert from_env("openai", 23).limit == 23


def test_from_env_honors_the_variable_when_set(monkeypatch):
    monkeypatch.setenv("CHAOS_AGENTS_OPENAI_CALL_BUDGET", "50")
    assert from_env("openai", 23).limit == 50


def test_from_env_rejects_a_non_integer_value(monkeypatch):
    monkeypatch.setenv("CHAOS_AGENTS_OPENAI_CALL_BUDGET", "lots")
    with pytest.raises(ValueError, match="must be an integer"):
        from_env("openai", 23)
