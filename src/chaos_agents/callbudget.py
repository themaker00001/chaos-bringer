"""A hard, persistent cap on calls to a paid API, enforced in the code -- not just a number
someone remembers to respect.

Every free target in this project (Ollama, the model-free demo adapters) can be hammered all
day for nothing; a paid provider can't, and a single campaign's own ``budget``/``max_payloads``
only caps *that one run* -- nothing stops a second run, or a mistake, from spending again. This
keeps one counter on disk, under a name you choose, and refuses once it is spent, across however
many separate ``chaos-agents`` processes use it. There is no way to reset it from inside this
project's own code -- only by editing or deleting the file by hand -- so the cap means what it
says.

    budget = CallBudget("openai", limit=23)
    budget.charge()              # raises BudgetExhausted once 23 calls have ever been charged
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DIR = ".chaos_agents"


class BudgetExhausted(RuntimeError):
    """The call budget is spent. Raised before the call that would exceed it, not after."""


@dataclass
class CallBudget:
    name: str                     # e.g. "openai" -- one counter file per name
    limit: int
    directory: str | Path = DEFAULT_DIR

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError(f"a call budget needs a limit of at least 1, got {self.limit}")
        self._path = Path(self.directory) / f"{self.name}.json"

    def _read(self) -> int:
        try:
            return int(json.loads(self._path.read_text()).get("used", 0))
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            return 0

    @property
    def used(self) -> int:
        return self._read()

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def charge(self, n: int = 1) -> int:
        """Spend `n` calls against the budget, or raise BudgetExhausted and spend nothing.
        Returns the new total used. Not safe against two processes racing on the same counter
        file at the exact same instant -- this is a hard brake on a human's own usage, not a
        distributed rate limiter."""
        used = self._read()
        if used + n > self.limit:
            raise BudgetExhausted(
                f"the {self.name!r} call budget is spent: {used} of {self.limit} calls already used "
                f"(this run would need {n} more). Raise the limit yourself if that was deliberate -- "
                f"this project's own code never resets it.")
        used += n
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({"name": self.name, "limit": self.limit, "used": used}, indent=2))
        return used


def from_env(name: str, default_limit: int, env_var: str | None = None) -> CallBudget:
    """A CallBudget whose limit can be raised (never silently lowered past what's already
    spent) via an environment variable, so changing it is a deliberate, visible action."""
    var = env_var or f"CHAOS_AGENTS_{name.upper()}_CALL_BUDGET"
    raw = os.environ.get(var)
    limit = default_limit
    if raw is not None:
        try:
            limit = int(raw)
        except ValueError as exc:
            raise ValueError(f"{var} must be an integer, got {raw!r}") from exc
    return CallBudget(name, limit)
