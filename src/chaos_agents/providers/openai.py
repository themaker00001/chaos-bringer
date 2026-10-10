"""A paid cloud provider -- opt-in, never the default, and never free to hammer. Every other
provider in this project (Ollama) costs nothing, so this is the one place a real call budget
matters (see ``chaos_agents.callbudget``): every request is charged against a persistent,
on-disk counter before it is sent, and refuses once that counter is spent -- across however many
separate ``chaos-agents`` runs use it, not just the one in front of you.

The key is read from the environment only, never from a campaign file: set ``OPENAI_API_KEY`` in
your shell, or put it in a gitignored ``.env`` at the repo root (copy ``.env.example``;
``chaos_agents.dotenv`` loads it automatically). If a config value is given and looks like a
``${NAME}`` placeholder, it is expanded from the environment the same way a promoted finding's
snapshot is (see ``chaos_agents.runstore``) -- but the ordinary, recommended path needs no
``api_key`` in any YAML at all.
"""

from __future__ import annotations

import os
import re

import requests

from chaos_agents import dotenv
from chaos_agents.callbudget import from_env

DEFAULT_MODEL = "gpt-6.1-sol"   # the current mid-tier model: newer and cheaper than the flagship ("astra"), more capable than the efficiency tier ("luna") -- verified against GET /v1/models for this key, not guessed
DEFAULT_CALL_BUDGET = 23          # a hard, deliberate ceiling -- raise it only on purpose, see callbudget.from_env

_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


class OpenAIProviderError(RuntimeError):
    pass


def resolve_api_key(api_key: str | None) -> str:
    """`api_key` as given, a `${NAME}` placeholder expanded from the environment, or
    `OPENAI_API_KEY` -- in that order. Loads a local `.env` first if one exists."""
    dotenv.load()
    if api_key:
        m = _PLACEHOLDER.match(api_key.strip())
        resolved = os.environ.get(m.group(1)) if m else api_key
        if resolved:
            return resolved
        if m:
            raise OpenAIProviderError(f"{api_key} needs {m.group(1)} set in the environment, and it is not")
    resolved = os.environ.get("OPENAI_API_KEY")
    if not resolved:
        raise OpenAIProviderError(
            "no OpenAI API key found. Set OPENAI_API_KEY in your shell, or copy .env.example to "
            ".env and fill it in (gitignored, never committed) -- never put a real key in a campaign YAML.")
    return resolved


def chat_completion(base_url: str, api_key: str, model: str, messages: list[dict],
                    timeout: float, options: dict) -> str:
    """One real request -- the only place this module calls the network. Shared by
    `OpenAIProvider` and `OpenAIChatAdapter` so there is exactly one way this project talks to
    OpenAI, and exactly one place that could get the error handling wrong."""
    try:
        resp = requests.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model, "messages": messages, **options},
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise OpenAIProviderError(f"could not reach OpenAI at {base_url}: {exc}") from exc
    data = resp.json()
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise OpenAIProviderError(f"unexpected OpenAI response shape: {data!r}") from exc


class OpenAIProvider:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 60.0,
        max_calls: int = DEFAULT_CALL_BUDGET,
        options: dict | None = None,
    ) -> None:
        self.model = model
        self._api_key = resolve_api_key(api_key)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.options = options or {}
        self.budget = from_env("openai", max_calls)

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        self.budget.charge()      # spent before the request goes out, not after it comes back
        return chat_completion(self.base_url, self._api_key, self.model, messages, self.timeout, self.options)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic; the key is never included
        return f"OpenAIProvider(model={self.model!r}, remaining={self.budget.remaining}/{self.budget.limit})"
