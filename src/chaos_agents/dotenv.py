"""A minimal, dependency-free ``.env`` loader.

The project otherwise never needs a secret (Ollama needs no key, every demo target is
model-free), so this exists for exactly one reason: a real API key must never sit in a
campaign YAML, a commit, or this process's command line -- it lives in a single gitignored
file and is read into the environment, once, the same way any twelve-factor app would.

``KEY=VALUE`` lines, blank lines and ``#`` comments are skipped, surrounding quotes on a value
are stripped. An already-set environment variable always wins over the file -- a real
``export OPENAI_API_KEY=...`` in your shell is never overridden by a stale ``.env``.
"""

from __future__ import annotations

import os
from pathlib import Path


def load(path: str | Path = ".env") -> int:
    """Load `path` into ``os.environ`` (skipping names already set). Returns how many
    variables were newly set; 0 (not an error) if the file does not exist."""
    file = Path(path)
    if not file.exists():
        return 0
    set_count = 0
    for raw in file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not key or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ[key] = value
        set_count += 1
    return set_count
