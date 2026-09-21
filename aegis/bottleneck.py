"""Process mining over the audit chain: where does governed work actually stop?

The gap this closes
-------------------
Every metric this project had before measured *refusal*. Attack success rate,
denial counts, controls fired -- all of them reward blocking. By those numbers
a governor that denied literally everything would score perfectly, and the
business would be dead.

Nothing measured whether the work got done. A session where triage read the
ticket and every subsequent step was refused looked, in the dashboard,
identical to a clean success.

What makes this cheap
---------------------
The hash-chained ledger already records every decision, with a session id, in
order. That is a trajectory dataset. Replaying it against the procedure graph
turns a pile of verdicts into process statistics: which stages complete, where
sessions die, which rule is responsible, and what the downstream cost is.

The output is meant to be read by whoever owns the policy, not by whoever
wrote the agent. "41% of cases never reach closure, all of them blocked at
notification by `injection-blocks-egress`" is an argument for a process
change. "17 denials" is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .procedure import NODES, TOOL_STAGE

STAGE_ORDER = [n.key for n in NODES]
STAGE_TITLE = {n.key: n.title for n in NODES}


@dataclass
class StageStats:
    stage: str
    title: str
    attempts: int = 0
    completed: int = 0
    blocked: int = 0
    # Sessions whose progress ended here -- they completed this stage and
    # never completed another. This is the number that identifies a
    # bottleneck, as distinct from a stage that merely gets probed a lot.
    terminal: int = 0
    by_control: dict[str, int] = field(default_factory=dict)
    by_rule: dict[str, int] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    @property
    def block_rate(self) -> float:
        return round(100.0 * self.blocked / self.attempts, 1) if self.attempts else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"stage": self.stage, "title": self.title,
                "attempts": self.attempts, "completed": self.completed,
                "blocked": self.blocked, "terminal": self.terminal,
                "block_rate": self.block_rate,
                "by_control": dict(self.by_control), "by_rule": dict(self.by_rule),
                "reasons": self.reasons[:3]}


@dataclass
class SessionTrace:
    session_id: str
    stages: list[str] = field(default_factory=list)
    reached: str = ""
    complete: bool = False
    blocked_at: str = ""
    blocked_by: str = ""
    blocked_rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class BottleneckReport:
    sessions: int = 0
    completed: int = 0
    stages: list[StageStats] = field(default_factory=list)
    traces: list[SessionTrace] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def completion_rate(self) -> float:
        return round(100.0 * self.completed / self.sessions, 1) if self.sessions else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "sessions": self.sessions,
            "completed": self.completed,
            "completion_rate": self.completion_rate,
            "stages": [s.to_dict() for s in self.stages],
            "traces": [t.to_dict() for t in self.traces],
            "findings": self.findings,
        }


# ── analysis ────────────────────────────────────────────────────────

def analyse(governor: Any, sessions: list[str] | None = None) -> BottleneckReport:
    """Replay a governor's ledger against the procedure graph.

    Only sessions that actually entered the procedure are counted. A red-team
    probe that fires one forbidden call and stops was never a case, and
    counting it as an incomplete one would make the completion rate meaningless
    -- the number has to describe real work, or nobody will trust it.
    """
    records = governor.ledger.records()
    wanted = set(sessions) if sessions else None

    by_session: dict[str, list[Any]] = {}
    for rec in records:
        if wanted is not None and rec.session_id not in wanted:
            continue
        by_session.setdefault(rec.session_id, []).append(rec)

    stats = {k: StageStats(k, STAGE_TITLE[k]) for k in STAGE_ORDER}
    report = BottleneckReport()

    for sid, recs in by_session.items():
        entered = any(TOOL_STAGE.get(r.tool) == "intake" and r.decision == "allow"
                      for r in recs)
        if not entered:
            continue

        trace = SessionTrace(session_id=sid)
        for rec in recs:
            stage = TOOL_STAGE.get(rec.tool)
            if not stage:
                continue
            st = stats[stage]
            st.attempts += 1
            if rec.decision == "allow":
                st.completed += 1
                if stage not in trace.stages:
                    trace.stages.append(stage)
                trace.reached = stage
            else:
                st.blocked += 1
                st.by_control[rec.control] = st.by_control.get(rec.control, 0) + 1
                if rec.matched_rule:
                    st.by_rule[rec.matched_rule] = st.by_rule.get(rec.matched_rule, 0) + 1
                if rec.reason and rec.reason not in st.reasons:
                    st.reasons.append(rec.reason)
                # First refusal is the one that defines where the case stalled;
                # everything after it is downstream fallout, not a new problem.
                if not trace.blocked_at:
                    trace.blocked_at = stage
                    trace.blocked_by = rec.control
                    trace.blocked_rule = rec.matched_rule or ""

        trace.complete = "closure" in trace.stages
        report.traces.append(trace)
        report.sessions += 1
        if trace.complete:
            report.completed += 1
        elif trace.reached:
            stats[trace.reached].terminal += 1

    report.stages = [stats[k] for k in STAGE_ORDER]
    report.findings = _findings(report)
    return report


def _findings(report: BottleneckReport) -> list[dict[str, Any]]:
    """Turn the counts into ranked, actionable statements.

    Ranked by how many cases each one strands, because that is the quantity a
    policy owner is trading against risk when they decide whether to change a
    rule.
    """
    out: list[dict[str, Any]] = []
    total = max(report.sessions, 1)

    for st in report.stages:
        if not st.terminal:
            continue
        idx = STAGE_ORDER.index(st.stage)
        downstream = STAGE_ORDER[idx + 1:]
        # The stage that actually refused work is the one after the last one
        # that completed, so name it: that is where the rule change belongs.
        blocker = STAGE_ORDER[idx + 1] if idx + 1 < len(STAGE_ORDER) else ""
        bstats = next((s for s in report.stages if s.stage == blocker), None)
        rule = max(bstats.by_rule, key=bstats.by_rule.get) if bstats and bstats.by_rule else ""
        control = (max(bstats.by_control, key=bstats.by_control.get)
                   if bstats and bstats.by_control else "")
        share = round(100.0 * st.terminal / total, 1)
        out.append({
            "severity": "high" if share >= 50 else "medium" if share >= 25 else "low",
            "stage": st.stage,
            "title": STAGE_TITLE[st.stage],
            "sessions_stranded": st.terminal,
            "share_pct": share,
            "blocked_entering": blocker,
            "control": control,
            "rule": rule,
            "unreached": downstream,
            "statement": (
                f"{st.terminal}/{total} cases ({share}%) stop after "
                f"'{STAGE_TITLE[st.stage]}'. They are refused entering "
                f"'{STAGE_TITLE.get(blocker, blocker)}'"
                + (f" by rule `{rule}`" if rule else
                   f" by the {control} control" if control else "")
                + f". Stages never reached: {', '.join(downstream) or 'none'}."),
            "recommendation": _recommend(st.stage, blocker, rule),
        })

    # A stage nothing ever reaches is either dead process or a mis-wired graph.
    for st in report.stages:
        if st.attempts == 0 and report.sessions:
            out.append({
                "severity": "low", "stage": st.stage, "title": st.title,
                "sessions_stranded": 0, "share_pct": 0.0,
                "blocked_entering": "", "control": "", "rule": "",
                "unreached": [],
                "statement": f"Stage '{st.title}' was never attempted in any "
                             f"case. It is either dead process or unreachable "
                             f"from the current graph.",
                "recommendation": "Confirm an inbound edge exists and that some "
                                  "agent owns this stage.",
            })

    out.sort(key=lambda f: (-f["sessions_stranded"], f["stage"]))
    return out


def _recommend(stage: str, blocker: str, rule: str) -> str:
    """Concrete next step. Deliberately never 'relax the rule'.

    A bottleneck report that recommends weakening controls is a liability. The
    useful recommendation is almost always an *additional path* -- a way for
    the case to reach a terminal state without the refused step -- not a
    loosened gate.
    """
    # Keyed on the rule before the stage: a case stopped by a poisoned ticket
    # needs a different answer from one stopped by its own position, whatever
    # stage the refusal happened to land on.
    if "injection" in rule:
        return ("These cases carry a live prompt injection, so degrading them "
                "to read-only is correct -- but they then have no terminal "
                "state and sit open indefinitely. Route flagged cases to a "
                "human review queue instead of letting them stall.")
    if blocker == "notification":
        return ("Add an escalation path: a case whose notification is refused "
                "currently cannot reach closure at all, so it stays open and "
                "invisible. An `escalate_to_human` stage converging to closure "
                "resolves the case without weakening the egress rule.")
    if blocker == "disbursement":
        return ("Cases stall before payment. If the refusals are correct, the "
                "declined branch should still reach notification and closure "
                "so the customer is told; check the CONVERGES_TO edge from "
                "eligibility_decision.")
    if blocker == "eligibility_decision":
        return ("Decisions are being refused, so nothing downstream can run. "
                "Check whether the integrity check is failing for a data "
                "reason rather than a security one.")
    if rule:
        return (f"Rule `{rule}` is the binding constraint here. Either the "
                f"cases it stops are genuinely unsafe -- in which case add a "
                f"path to a terminal state -- or the rule is over-broad.")
    return "Add a path that lets a refused case still reach a terminal state."


# ── corpus ──────────────────────────────────────────────────────────

def run_corpus(include_redteam: bool = False) -> tuple[BottleneckReport, Any]:
    """Run every seeded ticket through the governed workflow and analyse it.

    One governor, several sessions, so the ledger holds the whole corpus and
    the replay reads exactly the evidence an auditor would be handed.
    """
    from .agents.workflow import BackOfficeWorkflow
    from .governor import Governor

    gov = Governor(enforce=True)
    wf = BackOfficeWorkflow(gov)
    for ticket in sorted(gov.tools.state.tickets):
        wf.run(ticket)

    if include_redteam:
        from .redteam.attacks import ATTACKS
        for atk in ATTACKS:
            try:
                atk.run(gov)
            except Exception:
                pass          # a harness bug must not lose the corpus

    return analyse(gov), gov


# ── reporting ───────────────────────────────────────────────────────

def format_report(report: BottleneckReport) -> str:
    C = {"ok": "\033[92m", "bad": "\033[91m", "warn": "\033[93m",
         "dim": "\033[90m", "b": "\033[1m", "off": "\033[0m", "cyan": "\033[96m"}

    def c(t: str, s: str) -> str:
        return f"{C[s]}{t}{C['off']}"

    lines = [
        "", c("PROCESS COMPLETION — procedure graph replayed over the audit chain", "b"),
        c("every control so far measured refusal; this measures whether the "
          "work got done", "dim"), "",
    ]
    rate = report.completion_rate
    style = "ok" if rate >= 80 else "warn" if rate >= 50 else "bad"
    lines.append(f"  cases: {report.sessions}   completed end-to-end: "
                 f"{c(f'{report.completed}/{report.sessions} ({rate}%)', style)}")
    lines.append("")

    hdr = f"  {'STAGE':<26}{'DONE':>6}{'BLOCKED':>9}{'STUCK':>7}   BINDING CONSTRAINT"
    lines.append(c(hdr, "dim"))
    lines.append(c("─" * 100, "dim"))
    for st in report.stages:
        rule = max(st.by_rule, key=st.by_rule.get) if st.by_rule else ""
        ctl = max(st.by_control, key=st.by_control.get) if st.by_control else ""
        constraint = rule or ctl or ""
        stuck = c(str(st.terminal), "bad") if st.terminal else c("0", "dim")
        pad = " " * (7 - len(str(st.terminal)))
        lines.append(f"  {st.title[:24]:<26}{st.completed:>6}{st.blocked:>9}"
                     f"{pad}{stuck}   {c(constraint[:46], 'cyan')}")
    lines.append(c("─" * 100, "dim"))

    if report.findings:
        lines += ["", c("  FINDINGS", "b")]
        for i, f in enumerate(report.findings, 1):
            sev = {"high": "bad", "medium": "warn", "low": "dim"}[f["severity"]]
            lines.append(f"  {i}. [{c(f['severity'].upper(), sev)}] {f['statement']}")
            lines.append(f"     {c('-> ' + f['recommendation'], 'dim')}")
    else:
        lines += ["", c("  no bottlenecks: every case reached a terminal stage", "ok")]
    lines.append("")
    return "\n".join(lines)
