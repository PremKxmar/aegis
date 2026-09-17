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
    from .redteam.runner import compare

    print(c("\nRED-TEAM SUITE — 15 attacks, governed vs ungoverned", "b"))
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
