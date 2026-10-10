"""The minimal .env loader: no dependency, no surprises."""

import os

from chaos_agents import dotenv


def test_missing_file_is_not_an_error(tmp_path):
    assert dotenv.load(tmp_path / "nope.env") == 0


def test_loads_key_value_pairs(tmp_path, monkeypatch):
    monkeypatch.delenv("DOTENV_TEST_A", raising=False)
    monkeypatch.delenv("DOTENV_TEST_B", raising=False)
    f = tmp_path / ".env"
    f.write_text("DOTENV_TEST_A=hello\nDOTENV_TEST_B=world\n")
    assert dotenv.load(f) == 2
    assert os.environ["DOTENV_TEST_A"] == "hello"
    assert os.environ["DOTENV_TEST_B"] == "world"
    del os.environ["DOTENV_TEST_A"], os.environ["DOTENV_TEST_B"]


def test_comments_and_blank_lines_are_skipped(tmp_path, monkeypatch):
    monkeypatch.delenv("DOTENV_TEST_C", raising=False)
    f = tmp_path / ".env"
    f.write_text("# a comment\n\n   \nDOTENV_TEST_C=value\n# DOTENV_TEST_C=ignored\n")
    assert dotenv.load(f) == 1
    assert os.environ["DOTENV_TEST_C"] == "value"
    del os.environ["DOTENV_TEST_C"]


def test_surrounding_quotes_are_stripped(tmp_path, monkeypatch):
    monkeypatch.delenv("DOTENV_TEST_D", raising=False)
    monkeypatch.delenv("DOTENV_TEST_E", raising=False)
    f = tmp_path / ".env"
    f.write_text('DOTENV_TEST_D="quoted value"\nDOTENV_TEST_E=\'single quoted\'\n')
    dotenv.load(f)
    assert os.environ["DOTENV_TEST_D"] == "quoted value"
    assert os.environ["DOTENV_TEST_E"] == "single quoted"
    del os.environ["DOTENV_TEST_D"], os.environ["DOTENV_TEST_E"]


def test_an_already_set_environment_variable_always_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("DOTENV_TEST_F", "real-value")
    f = tmp_path / ".env"
    f.write_text("DOTENV_TEST_F=stale-file-value\n")
    assert dotenv.load(f) == 0
    assert os.environ["DOTENV_TEST_F"] == "real-value"


def test_a_line_with_no_equals_sign_is_skipped(tmp_path, monkeypatch):
    monkeypatch.delenv("NOT_A_VAR", raising=False)
    f = tmp_path / ".env"
    f.write_text("this is not a valid line\nNOT_A_VAR=ok\n")
    assert dotenv.load(f) == 1
    del os.environ["NOT_A_VAR"]
