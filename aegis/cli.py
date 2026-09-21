"""Terminal entry point: `python -m aegis.cli <command>`.

Everything the browser console can do, runnable headless -- which is what you
want in CI, and what you fall back to when the projector betrays you.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)

C = {
    "ok": "\033[92m", "bad": "\033[91m", "warn": "\033[93m",
    "dim": "\033[90m", "b": "\033[1m", "off": "\033[0m", "cyan": "\033[96m",
}


def c(text: str, style: str) -> str:
    return f"{C.get(style, '')}{text}{C['off']}"


def _rule(char: str = "─", n: int = 78) -> str:
    return c(char * n, "dim")


# ── commands ────────────────────────────────────────────────────────

def cmd_demo(args: argparse.Namespace) -> int:
    """Run both tickets through the governed workflow."""
    from .agents.workflow import BackOfficeWorkflow
    from .governor import Governor

    gov = Governor(enforce=True)
    wf = BackOfficeWorkflow(gov)
    print(c("\nAEGIS — governed back-office walkthrough", "b"))
    print(f"policies loaded: {', '.join(gov.loaded_policies)}\n")

    for ticket, label in [("T-501", "legitimate refund request"),
                          ("T-503", "ticket carrying a prompt injection")]:
        gov.reset()
        res = wf.run(ticket)
        print(_rule())
        print(f"{c(ticket, 'b')}  {c(label, 'dim')}")
        print(_rule())
        for s in res.steps:
            icon, style = {
                "ok": ("PASS", "ok"), "denied": ("DENY", "bad"),
                "approval_required": ("HOLD", "warn"), "error": ("ERR ", "warn"),
            }[s.outcome]
            ctl = c(f"[{s.control}]", "cyan") if s.control else ""
            print(f"  {c(icon, style)}  {s.agent:<9} {s.tool:<19} {ctl} "
                  f"{c(s.detail[:74], 'dim')}")
        sess = gov.session(res.session_id)
        print(f"\n  refunded ${res.refunded:.2f} · emails {res.emails_sent} · "
              f"blocked {res.denied_count} · ratchet={sess.ratchet.mark.label}\n")
    return 0


def cmd_redteam(args: argparse.Namespace) -> int:
    from .redteam.attacks import ATTACKS
    from .redteam.runner import compare

    print(c(f"\nRED-TEAM SUITE — {len(ATTACKS)} attacks, governed vs ungoverned", "b"))
    print(c("scoring: an attack 'lands' only if it caused observable harm\n", "dim"))
    result = compare()

    hdr = f"  {'ID':<8}{'ATTACK':<36}{'OWASP':<26}{'UNGOV':<9}{'GOVERNED':<10}STOPPED BY"
    print(c(hdr, "dim"))
    print(_rule("─", 118))
    for r in result.rows():
        ung = c("LANDED", "bad") if r["ungoverned"] else c("safe", "dim")
        gvn = c("LANDED", "bad") if r["governed"] else c("blocked", "ok")
        pad_u = " " * (9 - len("LANDED" if r["ungoverned"] else "safe"))
        pad_g = " " * (10 - len("LANDED" if r["governed"] else "blocked"))
        print(f"  {r['id']:<8}{r['name'][:34]:<36}{r['owasp'][:24]:<26}"
              f"{ung}{pad_u}{gvn}{pad_g}{c(', '.join(r['blocked_by'])[:32], 'cyan')}")

    h = result.to_dict()["headline"]
    print(_rule("─", 118))
    print(f"\n  ungoverned : {c(str(h['ungoverned_success_rate']) + '%', 'bad')} "
          f"of attacks landed")
    print(f"  governed   : {c(str(h['governed_success_rate']) + '%', 'ok')} "
          f"of attacks landed")
    print(f"  neutralised: {c(str(h['attacks_neutralised']), 'b')}"
          f"/{h['total_attacks']}")
    a = result.audit
    if a:
        print(f"  audit      : chain_intact={a.get('chain_intact')} "
              f"p99={a.get('latency_ms', {}).get('p99')}ms\n")
    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2, default=str))
        print(f"  wrote {args.json}\n")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from . import bench
    print()
    print(bench.format_report(bench.run(iterations=args.iterations)))
    print()
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    from .policytool import main as lint_main
    return lint_main([args.path])


def cmd_findings(args: argparse.Namespace) -> int:
    """Print the toolkit bugs this project found, with live re-verification."""
    import typing

    from agent_compliance import lint_policy as agt_lint
    from agentmesh.governance.policy import PolicyRule

    runtime = {a for a in typing.get_args(PolicyRule.model_fields["action"].annotation)
               if isinstance(a, str)}
    linter = set(agt_lint.KNOWN_ACTIONS)

    print(c("\nTOOLKIT FINDINGS — agent-governance-toolkit 4.1.0", "b"))
    print(c("re-verified live against the installed package\n", "dim"))

    print(c("1. agt lint-policy action vocabulary has drifted from the runtime", "warn"))
    print(f"     runtime accepts : {sorted(runtime)}")
    print(f"     linter accepts  : {sorted(linter)}")
    print(f"     overlap         : {sorted(runtime & linter)}")
    print(f"     {c('false positives', 'bad')} (valid, rejected) : {sorted(runtime - linter)}")
    print(f"     {c('false negatives', 'bad')} (invalid, passed) : {sorted(linter - runtime)}")
    print("     impact: a policy using `block` lints clean, then fails to load.")
    print("             In a fail-closed engine that is a governance outage.\n")

    print(c("2. `scope: global` does not scope anything", "warn"))
    print("     Policy.applies_to() matches only `agent`, `agents`, or `*`.")
    print("     A policy with `scope: global` and no `agents` loads, lists, and")
    print("     is never evaluated. Every call returns \"No policies loaded\".\n")

    print(c("3. The condition language has no negation", "warn"))
    print("     `not x` does not raise -- it falls through to the bare-boolean")
    print("     branch and evaluates False in both directions. The rule never")
    print("     fires and nothing warns you.\n")

    print(c("4. Detector config keys fall back silently", "warn"))
    print("     load_prompt_injection_config reads `direct_override`, not")
    print("     `direct_override_patterns`. A misspelled key silently yields")
    print("     the built-in defaults -- you believe you hardened it; you did not.\n")

    print(c("  all four are asserted in tests/test_toolkit_findings.py", "dim"))
    print(c("  run: pytest tests/test_toolkit_findings.py -v\n", "dim"))
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    """Print both graphs: the procedure the bank follows and the facts about it."""
    from .knowledge import build_graph
    from .procedure import GRAPH

    print(c("\nPROCEDURE GRAPH — (procedure, relation, procedure)", "b"))
    print(c("arXiv:2609.09153 structure, used as enforcement rather than "
            "guidance\n", "dim"))
    for node in GRAPH.nodes.values():
        tool = c(node.completed_by or "—", "cyan")
        print(f"  {c(node.key, 'b'):<32} {node.owner:<10} {tool}")
    print()
    for e in GRAPH.edges:
        print(f"  {e.src:<22} {c('--' + e.relation.value + '-->', 'dim')} "
              f"{c(e.dst, 'b')}")
        print(f"     {c('when: ' + e.condition, 'dim')}")
        if args.verbose:
            print(f"     {c('do  : ' + e.guidance, 'dim')}")
            print(f"     {c('risk: ' + e.pitfalls, 'dim')}")

    kg = build_graph()
    st = kg.stats()
    print(c(f"\nKNOWLEDGE GRAPH — {st['triples']} triples over "
            f"{st['nodes']} nodes", "b"))
    print(c("derived from live bank state, tool specs and the procedure "
            "graph\n", "dim"))
    for pred, n in sorted(st["predicates"].items(), key=lambda kv: -kv[1]):
        print(f"  {pred:<18}{n:>4}")
    if args.verbose:
        print()
        for t in kg.triples():
            print(f"  {c(str(t), 'dim')}")
    print()
    return 0


def cmd_policygen(args: argparse.Namespace) -> int:
    """Derive rules from the graphs and report what the current set misses."""
    from .policygen import generate

    holdout = [r.strip() for r in (args.holdout or "").split(",") if r.strip()]
    print(c("\nPOLICY GENERATION — rules derived from the graphs", "b"))
    print(c("enumerate dangerous paths -> probe the live governor -> propose "
            "-> validate\n", "dim"))
    if holdout:
        print(c(f"  holding out: {', '.join(holdout)}\n", "warn"))

    rep = generate(policy_dir=Path(args.policies) if args.policies else None,
                   holdout=holdout, do_validate=not args.no_validate)

    print(f"  probes enumerated : {rep.probes}")
    print(f"  already covered   : {c(str(len(rep.covered)), 'ok')} "
          f"({rep.coverage_pct}%)")
    print(f"  gaps found        : "
          f"{c(str(len(rep.gaps)), 'bad' if rep.gaps else 'ok')}\n")

    for g in rep.gaps:
        print(f"  {c(g.probe.id, 'b')} [{c(g.probe.kind, 'cyan')}] "
              f"{g.probe.description}")
        print(f"     {c('graph says: ' + g.probe.evidence, 'dim')}")
        print(f"     {c('governor says: ' + g.decision + ' — ' + g.reason[:70], 'dim')}")
        print(f"     {c('proposes: ' + g.probe.proposal['name'], 'warn')} "
              f"{c('· ' + g.probe.proposal['condition'], 'dim')}")

    if rep.validation:
        v = rep.validation
        ok = v["accepted"]
        print(f"\n  {c('VALIDATION GATE', 'b')} "
              f"{c('ACCEPTED' if ok else 'REJECTED', 'ok' if ok else 'bad')}")
        print(f"     closes every gap      : {v['closes_gaps']} "
              f"({v['gaps_remaining']} left)")
        print(f"     clean ticket completes: {v['workflow_completes']} "
              f"({v['workflow_stages']}/7 stages, ${v['workflow_refunded']:.2f})")
        print(f"     attack success rate   : {v['attack_success_rate']}%")
        print(c("     a proposal that blocked legitimate work would fail here",
                "dim"))

    if rep.proposals and args.out:
        from .policygen import render_policy
        Path(args.out).write_text(render_policy(rep.proposals))
        print(f"\n  wrote {args.out}")
    elif rep.proposals:
        print(f"\n{c('  proposed policy (use --out to write it):', 'dim')}\n")
        from .policygen import render_policy
        for line in render_policy(rep.proposals).splitlines():
            print(f"    {c(line, 'dim')}")
    print()
    return 0


def cmd_bottleneck(args: argparse.Namespace) -> int:
    """Replay the audit chain over the procedure graph and find where work stops."""
    from .bottleneck import format_report, run_corpus

    rep, _ = run_corpus(include_redteam=args.include_redteam)
    print(format_report(rep))
    if args.json:
        Path(args.json).write_text(json.dumps(rep.to_dict(), indent=2, default=str))
        print(f"  wrote {args.json}\n")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from .server import app
    print(c(f"\n  Aegis console -> http://{args.host}:{args.port}\n", "b"))
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


# ── parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis", description="Aegis — governed multi-agent back-office")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="run both tickets through the workflow"
                   ).set_defaults(fn=cmd_demo)

    rt = sub.add_parser("redteam", help="run the 15-attack suite both ways")
    rt.add_argument("--json", help="also write full results to this path")
    rt.set_defaults(fn=cmd_redteam)

    bn = sub.add_parser("bench", help="measure governance overhead")
    bn.add_argument("--iterations", type=int, default=250)
    bn.set_defaults(fn=cmd_bench)

    ln = sub.add_parser("lint", help="lint policies (schema-accurate)")
    ln.add_argument("path", nargs="?", default="policies")
    ln.set_defaults(fn=cmd_lint)

    sub.add_parser("findings", help="print the toolkit bugs, re-verified live"
                   ).set_defaults(fn=cmd_findings)

    gr = sub.add_parser("graph", help="print the procedure and knowledge graphs")
    gr.add_argument("--verbose", action="store_true",
                    help="include edge guidance/pitfalls and every triple")
    gr.set_defaults(fn=cmd_graph)

    pg = sub.add_parser("policygen",
                        help="derive rules from the graphs and find gaps")
    pg.add_argument("--policies", help="policy dir to audit (default: policies/)")
    pg.add_argument("--holdout",
                    help="comma-separated rule names to remove first, to check "
                         "the generator derives them back")
    pg.add_argument("--out", help="write the proposed policy to this path")
    pg.add_argument("--no-validate", action="store_true",
                    help="skip the validation gate (faster)")
    pg.set_defaults(fn=cmd_policygen)

    bt = sub.add_parser("bottleneck",
                        help="where does governed work actually stop?")
    bt.add_argument("--include-redteam", action="store_true",
                    help="also replay the attack sessions")
    bt.add_argument("--json", help="also write the full report to this path")
    bt.set_defaults(fn=cmd_bottleneck)

    sv = sub.add_parser("serve", help="start the live console")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
