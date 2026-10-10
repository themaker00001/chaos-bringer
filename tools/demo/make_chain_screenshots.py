#!/usr/bin/env python3
"""Proof screenshots for the two chain engines -- from the real CLI, not a mock-up.

    python tools/demo/make_chain_screenshots.py            # writes docs/proof/chain-rag-to-boundary.png
                                                             # and docs/proof/a2a-trust-chain.png

Reuses the exact terminal-window renderer `make_demo_gif.py` already built for the README demo GIF
(same font, colours, syntax highlighting), so these screenshots match the rest of the proof
gallery. Each image is two real runs of the same command: the shipped (vulnerable) campaign, then
the same campaign with its fix applied, run from a scratch copy of the repo's `campaigns/` so the
"fixed" variant is a real file a real run read, not a string pasted in afterward.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
PROOF = REPO / "docs" / "proof"

spec = importlib.util.spec_from_file_location("make_demo_gif", Path(__file__).resolve().parent / "make_demo_gif.py")
mdg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mdg
spec.loader.exec_module(mdg)


def run(cli: str, work: Path, command: str, cols: int, rows: int) -> tuple[list[str], int]:
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(work), "LANG": "en_US.UTF-8",
           "TERM": "xterm-256color", "PYTHONUNBUFFERED": "1"}
    argv = [cli] + command.split()[1:]
    out, code = mdg.run_in_pty(argv, work, cols, rows, env)
    lines = [row for line in out.split("\n") for row in mdg.hard_wrap(line, cols)]
    return lines, code


def screenshot(cli: str, out_path: Path, title: str, cols: int,
               comment_a: str, command_a: str, expect_a: int,
               comment_b: str, command_b: str, expect_b: int, work: Path) -> None:
    out_a, code_a = run(cli, work, command_a, cols, 40)
    out_b, code_b = run(cli, work, command_b, cols, 40)
    if code_a != expect_a or code_b != expect_b:
        sys.exit(f"{out_path.name}: expected exit codes ({expect_a}, {expect_b}), got ({code_a}, {code_b})\n"
                 + "\n".join(out_a) + "\n---\n" + "\n".join(out_b))
    rows_: list[tuple[str, str]] = [("comment", comment_a), ("prompt", command_a)] + [("out", l) for l in out_a]
    rows_ += [("out", ""), ("comment", comment_b), ("prompt", command_b)] + [("out", l) for l in out_b]
    rows_.append(("prompt", ""))
    rows = min(max(len(rows_) + 2, 20), 56)
    font = mdg.pick_font(None)
    term = mdg.Term(font, 13, cols, rows, title)
    term.frame(rows_, (len(rows_) - 1, 2)).convert("RGB").save(out_path)
    print(f"wrote {out_path}  {term.ww}x{term.wh}")


def _write_fixed(src: Path, dest: Path, overrides: dict) -> None:
    data = yaml.safe_load(src.read_text())
    data["adapter"]["config"] = {**data["adapter"].get("config", {}), **overrides}
    dest.write_text(yaml.safe_dump(data, sort_keys=False))


def main() -> None:
    cli = shutil.which("chaos-agents") or str(REPO / ".venv" / "bin" / "chaos-agents")
    if not os.path.exists(cli):
        sys.exit(f"chaos-agents not found at {cli}; install the project (pip install -e .) or edit `cli` above")
    PROOF.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="chaos-chain-shots-"))
    try:
        (work / "campaigns").symlink_to(REPO / "campaigns")
        _write_fixed(REPO / "campaigns" / "chain_rag_to_boundary.yaml", work / "chain_rag_to_boundary_fixed.yaml",
                    {"document_trusted": False, "hardened": True})
        _write_fixed(REPO / "campaigns" / "a2a_trust_exploitation.yaml", work / "a2a_trust_exploitation_fixed.yaml",
                    {"verify_origin": True, "enforce_at_execution": True})

        screenshot(
            cli, PROOF / "chain-rag-to-boundary.png", "chaos-agents  ·  cross-surface attack chain", 128,
            "# plant a poisoned document, see whether it changes behavior, then test the authorization boundary",
            "chaos-agents chain campaigns/chain_rag_to_boundary.yaml", 1,
            "# the two fixes applied (document_trusted: false, hardened: true)",
            "chaos-agents chain chain_rag_to_boundary_fixed.yaml", 0, work,
        )
        screenshot(
            cli, PROOF / "a2a-trust-chain.png", "chaos-agents  ·  agent-to-agent trust chain", 128,
            "# Agent A forges a trust claim; does it survive delegation through B and reach C's tool boundary?",
            "chaos-agents a2a-chain campaigns/a2a_trust_exploitation.yaml", 1,
            "# the two fixes applied (verify_origin: true, enforce_at_execution: true)",
            "chaos-agents a2a-chain a2a_trust_exploitation_fixed.yaml", 0, work,
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
