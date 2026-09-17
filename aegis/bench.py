"""Overhead benchmark: what does the governance layer actually cost?

Blocking attacks is only half the engineering question. If enforcement added
50ms to every tool call it would be unshippable regardless of how safe it was.
This measures the tax.

Method
------
We time the *same* workload twice -- once with `enforce=True`, once with
`enforce=False` -- on a warmed-up interpreter, discarding a warmup round.
Because the underlying tools are in-memory dict lookups, the governed/
ungoverned ratio here is a deliberate worst case: real tools do network I/O
that dwarfs policy evaluation, so the percentage overhead in production is
strictly lower than what this prints. We report absolute per-call microseconds
alongside the ratio for exactly that reason -- the absolute number is the one
that transfers.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any

from .domain import GovernanceDenied, ToolCall
from .governor import Governor


@dataclass
class Sample:
    label: str
    per_call_us: list[float] = field(default_factory=list)

    def stats(self) -> dict[str, float]:
        if not self.per_call_us:
            return {}
        s = sorted(self.per_call_us)
        return {
            "n": len(s),
            "mean_us": round(statistics.fmean(s), 2),
            "p50_us": round(s[len(s) // 2], 2),
            "p95_us": round(s[min(len(s) - 1, int(len(s) * 0.95))], 2),
            "p99_us": round(s[min(len(s) - 1, int(len(s) * 0.99))], 2),
            "max_us": round(s[-1], 2),
        }


def _workload(gov: Governor, iterations: int, session_prefix: str) -> list[float]:
    """A representative mix: reads, a refund, an email. Times each call."""
    timings: list[float] = []
    plan = [
        ("triage", "read_ticket", {"ticket_id": "T-501"}),
        ("analyst", "lookup_customer", {"customer_id": "C-1001"}),
        ("payments", "issue_refund",
         {"customer_id": "C-1001", "amount": 25.0, "reason": "bench"}),
        ("comms", "send_email",
         {"to": "maya.r@example.test", "subject": "s", "body": "b"}),
    ]
    for i in range(iterations):
        # Fresh session each iteration so budgets and ratchets do not saturate
        # and start short-circuiting the very path we are trying to measure.
        sid = f"{session_prefix}-{i}"
        for agent, tool, args in plan:
            call = ToolCall(tool=tool, args=args, agent_id=agent, session_id=sid)
            t0 = time.perf_counter()
            try:
                gov.execute(call, agent)
            except GovernanceDenied:
                pass  # a denial is a legitimate outcome; still counts as work
            timings.append((time.perf_counter() - t0) * 1_000_000)
    return timings


def _decision_only(gov: Governor, iterations: int) -> list[float]:
    """Isolate policy evaluation from tool execution."""
    timings: list[float] = []
    call = ToolCall(tool="lookup_customer", args={"customer_id": "C-1001"},
                    agent_id="analyst", session_id="bench-decide")
    for _ in range(iterations):
        t0 = time.perf_counter()
        gov.evaluate(call, "analyst")
        timings.append((time.perf_counter() - t0) * 1_000_000)
    return timings


def run(iterations: int = 250, warmup: int = 25) -> dict[str, Any]:
    governed = Governor(enforce=True)
    ungoverned = Governor(enforce=False)

    # Warm up both: first-call costs (regex compilation, pydantic validators)
    # would otherwise land entirely on whichever we measured first.
    _workload(governed, warmup, "warm-g")
    _workload(ungoverned, warmup, "warm-u")
    governed.reset(); ungoverned.reset()

    g = Sample("governed", _workload(governed, iterations, "g"))
    u = Sample("ungoverned", _workload(ungoverned, iterations, "u"))
    d = Sample("decision_only", _decision_only(governed, iterations * 4))

    gs, us, ds = g.stats(), u.stats(), d.stats()
    overhead_us = round(gs["mean_us"] - us["mean_us"], 2)
    overhead_pct = round(100.0 * overhead_us / us["mean_us"], 1) if us["mean_us"] else 0.0

    # What the tax looks like once a realistic network tool is in the path.
    projections = {
        f"{lat}ms_tool": round(100.0 * (overhead_us / 1000.0) / lat, 2)
        for lat in (10, 50, 200)
    }

    return {
        "iterations": iterations,
        "calls_measured": gs["n"],
        "governed": gs,
        "ungoverned": us,
        "decision_only": ds,
        "overhead_us_per_call": overhead_us,
        "overhead_pct_inmemory": overhead_pct,
        "overhead_pct_projected": projections,
        "audit_p99_ms": governed.ledger.stats()["latency_ms"]["p99"],
        "note": ("In-memory tools make this a worst case. `overhead_pct_projected` "
                 "shows the same absolute cost against realistic tool latencies."),
    }


def format_report(r: dict[str, Any]) -> str:
    lines = [
        "GOVERNANCE OVERHEAD BENCHMARK",
        "=" * 62,
        f"  calls measured      : {r['calls_measured']}",
        f"  ungoverned mean     : {r['ungoverned']['mean_us']:>9.2f} us/call",
        f"  governed mean       : {r['governed']['mean_us']:>9.2f} us/call",
        f"  governed p99        : {r['governed']['p99_us']:>9.2f} us/call",
        f"  absolute overhead   : {r['overhead_us_per_call']:>9.2f} us/call",
        f"  overhead (in-memory): {r['overhead_pct_inmemory']:>9.1f} %  <- worst case",
        "",
        "  policy decision only:",
        f"    mean {r['decision_only']['mean_us']:.2f} us | "
        f"p50 {r['decision_only']['p50_us']:.2f} | "
        f"p99 {r['decision_only']['p99_us']:.2f} us",
        "",
        "  projected overhead against realistic tool latency:",
    ]
    for k, v in r["overhead_pct_projected"].items():
        lines.append(f"    tool taking {k.replace('_tool',''):>6} -> {v:>6.2f} % overhead")
    lines += ["", "  " + r["note"]]
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_report(run()))
