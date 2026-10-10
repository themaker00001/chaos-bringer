from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from chaos_agents import attackgraph, registry, report
from chaos_agents.campaign import Campaign, CampaignError
from chaos_agents.corpus import Corpus
from chaos_agents.interfaces import FAIL, INCONCLUSIVE
from chaos_agents.orchestrator import run_campaign


DEFAULT_REGRESSIONS = "regressions"


def _load_valid_campaign(path: str) -> Campaign:
    """Parse and fully validate a campaign before anything runs. Raises
    CampaignError with an actionable message."""
    campaign = Campaign.from_yaml(path)
    campaign.check_plugins()
    return campaign


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        campaign = _load_valid_campaign(args.campaign)
    except CampaignError as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 2
    tags = f" [{campaign.category}/{campaign.technique}]" if campaign.category else ""
    print(f"ok: {campaign.name}{tags}  "
          f"adapter={campaign.adapter.plugin} vector={campaign.vector.plugin} judge={campaign.judge.plugin}")
    if campaign.policy:
        n = len(campaign.policy.capabilities)
        print(f"policy: {n} capabilit{'y' if n == 1 else 'ies'}, default {campaign.policy.default}")
    return 0


def _print_graphs(records, style: str) -> None:
    """The attack graph of every confirmed finding, boxed or as Mermaid."""
    render = attackgraph.to_mermaid if style == "mermaid" else attackgraph.render_box
    graphs = [g for g in (render(r) for r in records) if g]
    for graph in graphs:
        print("\n" + graph)


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        campaign = _load_valid_campaign(args.campaign)
    except CampaignError as exc:
        print(f"invalid campaign: {exc}", file=sys.stderr)
        return 2
    corpus = Corpus(campaign.name, root=args.runs_dir)
    fmt = args.format

    if args.fancy and fmt == "terminal":
        from rich.console import Console

        from chaos_agents import report_rich

        console = Console()
        try:
            with report_rich.NergalStatus(console, mascot=not args.no_mascot, campaign=campaign) as status:
                records = run_campaign(campaign, corpus, on_step=status.thinking, on_result=status.result)
                status.done(records)
        except CampaignError as exc:
            print(f"invalid campaign: {exc}", file=sys.stderr)
            return 2
        report_rich.render(campaign.name, records)
        if args.svg:
            report_rich.render_svg(campaign.name, records, args.svg)
            print(f"\nSVG written to: {args.svg}")
    else:
        try:
            records = run_campaign(campaign, corpus)
        except CampaignError as exc:
            print(f"invalid campaign: {exc}", file=sys.stderr)
            return 2
        if fmt == "terminal":
            print(report.render(campaign.name, records, width=report.terminal_width()))

    if args.graph and fmt == "terminal":
        _print_graphs(records, args.graph)

    if fmt != "terminal":
        from chaos_agents import export

        rendered = export.FORMATS[fmt](campaign.name, records, run_id=corpus.run_id)
        if args.output:
            Path(args.output).write_text(rendered)
            print(f"{fmt} written to: {args.output}", file=sys.stderr)
        else:
            print(rendered)

    if args.promote:
        from chaos_agents import regression

        promoted = 0
        for r in records:
            if r.status == FAIL:
                regression.promote(r, campaign, args.promote, do_minimize=args.minimize)
                promoted += 1
        print(f"promoted {promoted} finding(s) to {args.promote}", file=sys.stderr)

    print(f"Full trace: {corpus.results_path}", file=sys.stderr)
    search_report = corpus.run_dir / "adaptive_search.json"
    if search_report.exists():
        print(f"Search report: {search_report}", file=sys.stderr)
    # exit non-zero only for a confirmed finding -- not for inconclusive/errored trials
    return 1 if any(r.status == FAIL for r in records) else 0


def _bench_progress(total: int):
    """A minimal carriage-return progress bar on stderr, one tick per probe."""
    from chaos_agents.interfaces import FAIL as _F
    from chaos_agents.interfaces import PASS as _P

    state = {"done": 0}
    width = 24

    def on_probe(outcome) -> None:
        state["done"] += 1
        done = state["done"]
        filled = int(width * done / total) if total else width
        bar = "#" * filled + "-" * (width - filled)
        mark = {_P: "held", _F: "LEAK"}.get(outcome.status, "skip")
        sys.stderr.write(f"\rChaosBench [{bar}] {done}/{total}  {outcome.probe.id:<6} {mark:<4}")
        sys.stderr.flush()
        if done == total:
            sys.stderr.write("\n")
            sys.stderr.flush()

    return on_probe


def _cmd_bench(args: argparse.Namespace) -> int:
    from chaos_agents import benchmark, benchreport, registry

    if args.suite not in benchmark.SUITES:
        print(f"unknown suite {args.suite!r}; available: {', '.join(benchmark.SUITES)}", file=sys.stderr)
        return 2
    try:
        campaign = Campaign.from_yaml(args.campaign)
    except CampaignError as exc:
        print(f"invalid campaign: {exc}", file=sys.stderr)
        return 2

    adapter = registry.load("chaos_agents.adapters", campaign.adapter.plugin, **campaign.adapter.config)
    suite = benchmark.SUITES[args.suite]
    # a live progress bar while probes run (useful when the target is a real
    # model and each probe takes a second or two); only when stderr is a TTY,
    # so CI logs and piped output stay clean.
    progress = _bench_progress(len(suite.probes)) if sys.stderr.isatty() else None
    card = benchmark.run_benchmark(suite, adapter, on_probe=progress, policy=campaign.policy)

    rendered = benchreport.FORMATS[args.format](card)
    if args.output:
        Path(args.output).write_text(rendered)
        print(f"{args.format} scorecard written to: {args.output}", file=sys.stderr)
    else:
        print(rendered)

    # gate: --min-resilience sets the bar; otherwise any failed probe is non-zero
    if args.min_resilience is not None:
        r = card.resilience
        return 1 if (r is not None and r < args.min_resilience) else 0
    return 1 if card.counts[FAIL] > 0 else 0


def _cmd_regression(args: argparse.Namespace) -> int:
    from chaos_agents import regression

    baseline = Path(args.baseline or DEFAULT_REGRESSIONS)
    if not baseline.is_dir():
        if args.baseline:       # a path you typed that isn't there is an error, not a clean bill of health
            print(f"regression directory not found: {baseline}", file=sys.stderr)
            return 2
        print(f"no {DEFAULT_REGRESSIONS}/ directory yet -- promote a finding first: chaos-agents finding promote CB-xxxx")
        return 0
    results = regression.run_regression(baseline)
    print(regression.summarize(results))
    return 1 if any(r.still_vulnerable for r in results) else 0


def _finding_args_error(exc: Exception) -> int:
    print(str(exc), file=sys.stderr)
    return 2


def _cmd_finding_list(args: argparse.Namespace) -> int:
    from chaos_agents import runstore, securityfinding

    from chaos_agents import regression

    located = runstore.list_findings(args.runs_dir)
    state = {f.id: regression.state_of(f.id, args.regressions_dir) for f in located}
    if args.json:
        print(json.dumps([securityfinding.from_record(f.record, f.run_info(), regression=state[f.id]).to_dict()
                          for f in located], indent=2))
        return 0
    if not located:
        print(f"no findings under {args.runs_dir}/ (run a campaign first)")
        return 0
    print(f"{len(located)} finding(s) under {args.runs_dir}/\n")
    for f in located:
        r = f.record
        status = (state[f.id] or {}).get("status", "open").upper()
        print(f"  {f.id}  {r.severity.upper():<8} {status:<6} {r.category}/{r.technique:<24} {f.campaign}"
              + (f"  x{f.occurrences}" if f.occurrences > 1 else ""))
    return 0


def _cmd_finding_show(args: argparse.Namespace) -> int:
    from chaos_agents import runstore, securityfinding

    try:
        found = runstore.find(args.id, args.runs_dir)
    except runstore.FindingNotFound as exc:
        return _finding_args_error(exc)
    except runstore.AmbiguousFinding as exc:
        return _finding_args_error(exc)
    from chaos_agents import regression

    finding = securityfinding.from_record(found.record, found.run_info(),
                                          regression=regression.state_of(found.id, args.regressions_dir))
    print(json.dumps(finding.to_dict(), indent=2) if args.json else finding.render(graph=args.graph or ""))
    return 0


def _cmd_finding_promote(args: argparse.Namespace) -> int:
    from chaos_agents import regression, runstore

    try:
        found = runstore.find(args.id, args.runs_dir)
        campaign = None
        if args.campaign:
            campaign = _load_valid_campaign(args.campaign).to_dict()
        promoted = regression.promote_finding(
            found, args.regressions_dir, campaign=campaign, minimize=not args.no_minimize,
            max_calls=args.max_calls, force=args.force)
    except (runstore.FindingNotFound, runstore.AmbiguousFinding, CampaignError) as exc:
        return _finding_args_error(exc)
    except runstore.MissingSecret as exc:
        return _finding_args_error(exc)
    except regression.PromoteError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    m = promoted.minimization
    print(f"promoted {found.id} -> {promoted.path}/")
    print(f"  {regression.ATTACK}  {regression.EXPECTED}  {regression.METADATA}  {regression.MINIMIZED}")
    if m["applied"]:
        print(f"  minimized: {m['original_length']} -> {m['minimized_length']} chars ({m['target_calls']} target calls)")
    elif promoted.entry.get("scenario"):
        print("  minimized: no (a memory scenario is replayed whole)")
    print(f"  reproducible: {'yes' if promoted.reproducible else 'NO (forced)'}")
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    from chaos_agents import replay as replay_mod
    from chaos_agents import runstore
    from chaos_agents.interfaces import INCONCLUSIVE, PASS

    try:
        found = runstore.find(args.id, args.runs_dir)
        campaign = _load_valid_campaign(args.campaign).to_dict() if args.campaign else None
        fix = replay_mod.parse_fix(args.fix or [])
        rp = replay_mod.replay(found, args.regressions_dir, fix=fix, campaign=campaign, record=args.record)
    except (runstore.FindingNotFound, runstore.AmbiguousFinding, CampaignError, replay_mod.ReplayError) as exc:
        return _finding_args_error(exc)
    print(json.dumps(rp.to_dict(), indent=2) if args.json else replay_mod.render(rp, width=report.terminal_width()))
    return 0 if rp.result == PASS else 3 if rp.result == INCONCLUSIVE else 1


def _cmd_chain(args: argparse.Namespace) -> int:
    from chaos_agents import campaignrunner

    try:
        chain = campaignrunner.ChainConfig.from_yaml(args.chain)
        report_ = campaignrunner.run_chain(chain)
    except campaignrunner.ChainError as exc:
        print(f"invalid chain: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report_.to_dict(), indent=2)
    if args.json:
        print(rendered)
    else:
        print(f"{report_.name}: {report_.verdict.upper()} -- {report_.reason}\n")
        for stage in report_.stages:
            print(f"  [{stage.status:<7}] {stage.name}" + (f"  -- {stage.reason}" if stage.reason else ""))
    if args.output:
        Path(args.output).write_text(rendered)
        print(f"report written to: {args.output}", file=sys.stderr)
    return 1 if report_.verdict == FAIL else 3 if report_.verdict == INCONCLUSIVE else 0


def _cmd_a2a_chain(args: argparse.Namespace) -> int:
    from chaos_agents import trustchain

    try:
        chain = trustchain.TrustChainConfig.from_yaml(args.chain)
        report_ = trustchain.run_trust_chain(chain)
    except trustchain.TrustChainError as exc:
        print(f"invalid chain: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report_.to_dict(), indent=2)
    if args.json:
        print(rendered)
    else:
        print(f"{report_.name}: {report_.verdict.upper()} -- {report_.reason}\n")
        for stage in report_.stages:
            print(f"  [{stage.status:<7}] {stage.name}" + (f"  -- {stage.reason}" if stage.reason else ""))
    if args.output:
        Path(args.output).write_text(rendered)
        print(f"report written to: {args.output}", file=sys.stderr)
    return 1 if report_.verdict == FAIL else 3 if report_.verdict == INCONCLUSIVE else 0


def _cmd_plugins(args: argparse.Namespace) -> int:
    for group in ("providers", "adapters", "vectors", "judges"):
        names = registry.available(f"chaos_agents.{group}")
        print(f"{group}:")
        for name, target in sorted(names.items()):
            print(f"  {name:<16} {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chaos-agents")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run a campaign against its target")
    run_p.add_argument("campaign", help="path to a campaign YAML file")
    run_p.add_argument("--runs-dir", default="runs", help="where to write the corpus (default: ./runs)")
    run_p.add_argument("--fancy", action="store_true", help="render with rich (requires: pip install chaos-agents[rich])")
    run_p.add_argument("--svg", metavar="PATH", help="also save the --fancy report as a terminal-styled SVG")
    run_p.add_argument("--no-mascot", action="store_true", help="with --fancy, skip the animated Nergal and show only the status line")
    run_p.add_argument("--format", choices=["terminal", "json", "sarif", "junit"], default="terminal",
                       help="output format (default: terminal). json/sarif/junit are for CI.")
    run_p.add_argument("--output", metavar="PATH", help="write the --format output to a file instead of stdout")
    run_p.add_argument("--graph", nargs="?", const="box", choices=["box", "mermaid"],
                       help="also draw each finding's attack graph (box, or mermaid for docs/PRs)")
    run_p.add_argument("--promote", metavar="DIR", help="promote confirmed findings into a regression corpus directory")
    run_p.add_argument("--minimize", action="store_true", help="with --promote, shrink each finding to a minimal reproducer first")
    run_p.set_defaults(func=_cmd_run)

    bench_p = sub.add_parser("bench", help="score a target against a ChaosBench suite (the adapter comes from a campaign file)")
    bench_p.add_argument("campaign", help="a campaign YAML; only its adapter block is used to build the target")
    bench_p.add_argument("--suite", default="chaos-bench-core", help="benchmark suite to run (default: chaos-bench-core)")
    bench_p.add_argument("--format", choices=["text", "json"], default="text", help="scorecard format (default: text)")
    bench_p.add_argument("--output", metavar="PATH", help="write the scorecard to a file instead of stdout")
    bench_p.add_argument("--min-resilience", type=float, metavar="PCT",
                         help="gate: exit non-zero if resilience is below PCT (default gate: any failed probe)")
    bench_p.set_defaults(func=_cmd_bench)

    reg_p = sub.add_parser("regression", help="re-run a regression corpus; non-zero if any reproducer still fires")
    reg_p.add_argument("baseline", nargs="?",
                       help=f"a regression directory (default: ./{DEFAULT_REGRESSIONS}); reads finding-promote folders "
                            f"and run --promote files")
    reg_p.set_defaults(func=_cmd_regression)

    finding_p = sub.add_parser("finding", help="list and inspect confirmed findings from earlier runs")
    finding_sub = finding_p.add_subparsers(dest="finding_command", required=True)
    flist = finding_sub.add_parser("list", help="every distinct confirmed finding under the runs directory")
    flist.add_argument("--runs-dir", default="runs", help="where runs were written (default: ./runs)")
    flist.add_argument("--regressions-dir", default=DEFAULT_REGRESSIONS,
                       help=f"where regression tests live, for status (default: ./{DEFAULT_REGRESSIONS})")
    flist.add_argument("--json", action="store_true", help="machine-readable output")
    flist.set_defaults(func=_cmd_finding_list)
    fshow = finding_sub.add_parser("show", help="show one finding in full: attack, evidence, path, standards")
    fshow.add_argument("id", help="finding id, e.g. CB-956b1f46 (any unambiguous prefix works)")
    fshow.add_argument("--runs-dir", default="runs", help="where runs were written (default: ./runs)")
    fshow.add_argument("--regressions-dir", default=DEFAULT_REGRESSIONS,
                       help=f"where regression tests live, for status (default: ./{DEFAULT_REGRESSIONS})")
    fshow.add_argument("--json", action="store_true", help="the finding as JSON")
    fshow.add_argument("--graph", nargs="?", const="box", choices=["box", "mermaid"],
                       help="also draw the attack graph (box, or mermaid)")
    fshow.set_defaults(func=_cmd_finding_show)
    fpromote = finding_sub.add_parser(
        "promote", help="turn a finding into a regression test: regressions/CB-xxxx/{attack,expected,metadata,minimized}")
    fpromote.add_argument("id", help="finding id, e.g. CB-956b1f46 (any unambiguous prefix works)")
    fpromote.add_argument("--runs-dir", default="runs", help="where runs were written (default: ./runs)")
    fpromote.add_argument("--regressions-dir", default=DEFAULT_REGRESSIONS,
                          help=f"where regression tests live (default: ./{DEFAULT_REGRESSIONS})")
    fpromote.add_argument("--campaign", metavar="FILE",
                          help="rebuild the target from this campaign file instead of the run's snapshot")
    fpromote.add_argument("--no-minimize", action="store_true", help="keep the original payload")
    fpromote.add_argument("--max-calls", type=int, default=100, help="target-call budget for minimizing (default: 100)")
    fpromote.add_argument("--force", action="store_true",
                          help="replace an existing regression, or promote one that did not reproduce")
    fpromote.set_defaults(func=_cmd_finding_promote)

    replay_p = sub.add_parser(
        "replay", help="re-run a finding's attack and show what happens now (optionally with a fix applied)")
    replay_p.add_argument("id", help="finding id, e.g. CB-956b1f46 (any unambiguous prefix works)")
    replay_p.add_argument("--fix", action="append", metavar="KEY=VALUE",
                          help="a change to the target's configuration, e.g. --fix hardened=true; the attack is "
                               "replayed against the original target first, then the fixed one (repeatable)")
    replay_p.add_argument("--record", action="store_true",
                          help="if the fix passes, write it into the regression and mark the finding fixed")
    replay_p.add_argument("--runs-dir", default="runs", help="where runs were written (default: ./runs)")
    replay_p.add_argument("--regressions-dir", default=DEFAULT_REGRESSIONS,
                          help=f"where regression tests live (default: ./{DEFAULT_REGRESSIONS})")
    replay_p.add_argument("--campaign", metavar="FILE",
                          help="rebuild the target from this campaign file instead of the run's snapshot")
    replay_p.add_argument("--json", action="store_true", help="the replay as JSON")
    replay_p.set_defaults(func=_cmd_replay)

    chain_p = sub.add_parser(
        "chain", help="run a cross-surface attack chain: RAG poisoning -> behavior change -> tool boundary -> verdict")
    chain_p.add_argument("chain", help="path to a chain YAML file (see campaigns/chain_rag_to_boundary.yaml)")
    chain_p.add_argument("--json", action="store_true", help="print the full report (graph, events, verdict, replay)")
    chain_p.add_argument("--output", metavar="PATH", help="also write the JSON report to a file")
    chain_p.set_defaults(func=_cmd_chain)

    a2a_chain_p = sub.add_parser(
        "a2a-chain", help="run an agent-to-agent trust chain: untrusted origin -> delegation -> tool boundary -> verdict")
    a2a_chain_p.add_argument("chain", help="path to a trust-chain YAML file (see campaigns/a2a_trust_exploitation.yaml)")
    a2a_chain_p.add_argument("--json", action="store_true", help="print the full report (graph, events, verdict, replay)")
    a2a_chain_p.add_argument("--output", metavar="PATH", help="also write the JSON report to a file")
    a2a_chain_p.set_defaults(func=_cmd_a2a_chain)

    validate_p = sub.add_parser("validate", help="check a campaign file without running it")
    validate_p.add_argument("campaign", help="path to a campaign YAML file")
    validate_p.set_defaults(func=_cmd_validate)

    plugins_p = sub.add_parser("plugins", help="list installed plugins by surface")
    plugins_p.set_defaults(func=_cmd_plugins)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
