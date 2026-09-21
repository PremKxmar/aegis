"""Procedural graph — governance over *process*, not just over actions.

Why this exists
---------------
Every control in `governor.py` answers the same question: "may this agent call
this tool right now?" None of them answer "is this the right point in the
process to be doing it?" A refund that skips the eligibility decision, PII read
before the customer's identity was verified, a ticket closed before anyone told
the customer -- all of those pass the eight-control chain untouched, because
each individual call is permissible. Five red-team attacks (ATT-16..ATT-20)
exist to prove exactly that.

Relation to the literature
--------------------------
The structure follows "Procedural Graphs: Self-Evolving Execution Structures
for LLM Agents" (Lu, Chen, Wu, Arik; arXiv:2609.09153). Where a knowledge graph
stores facts as (entity, relation, entity), a procedural graph stores know-how
as (procedure, relation, procedure), and the paper uses the same four relation
types reproduced in `Relation` below. Each edge carries three textual
attributes -- condition, guidance, pitfalls.

The deliberate divergence
-------------------------
In the paper the graph is *advisory*: a guidance model turns the local
neighbourhood into a hint that "biases the solver's next action without
dictating it". The goal there is capability -- keep a long-horizon agent on
track.

Here the graph is *enforcement*. Every edge condition is compiled into a
deterministic predicate, evaluated at the same chokepoint as every other
control, and a failed precondition raises `GovernanceDenied`. Nothing is
biased; things are refused. That inversion -- advisory structure repurposed as
a compliance boundary -- is the point of this module.

The graph does not evaluate anything itself. It publishes facts into the policy
context (`procedure.*`) and `policies/50-procedure.yaml` decides what to do
with them, exactly like every other control in this project. The ordering
constraints are therefore reviewable YAML, not buried Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Relation(str, Enum):
    """The paper's relation vocabulary, used verbatim.

    Keeping the exact names matters: it is what lets the graph in this file be
    compared against the one in the paper without a translation table.
    """

    LEADS_TO = "LEADS_TO"
    TRIGGERS = "TRIGGERS"
    PROVIDES_INPUT_FOR = "PROVIDES_INPUT_FOR"
    CONVERGES_TO = "CONVERGES_TO"


@dataclass(frozen=True)
class ProcedureNode:
    """One stage of the bank's refund procedure."""

    key: str
    title: str
    description: str
    # The tool whose successful execution completes this stage. A stage with
    # no tool is structural (the entry node).
    completed_by: str = ""
    # Which agent is expected here. Advisory metadata for the UI and the
    # bottleneck report; enforcement of *who* lives in the capability layer.
    owner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "title": self.title,
                "description": self.description,
                "completed_by": self.completed_by, "owner": self.owner}


@dataclass(frozen=True)
class ProcedureEdge:
    """A permitted transition, with the paper's three attribute fields.

    `guard` is this project's addition: the name of a registered predicate that
    must hold for the transition to be legal. `condition` is its human-readable
    form and is what appears in the audit record, so an auditor reading the
    trail never has to open Python to find out why a step was refused.
    """

    src: str
    relation: Relation
    dst: str
    condition: str = "always"
    guidance: str = ""
    pitfalls: str = ""
    guard: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "relation": self.relation.value, "dst": self.dst,
                "condition": self.condition, "guidance": self.guidance,
                "pitfalls": self.pitfalls, "guard": self.guard}


# ── the bank's refund procedure ─────────────────────────────────────
#
# Read this as the process a human back-office would follow, because that is
# what it is: verify who you are talking to, confirm the account hangs together,
# decide whether they are owed money, pay, tell them, close the case.

NODES: list[ProcedureNode] = [
    ProcedureNode("intake", "Ticket intake",
                  "Read the inbound ticket. Everything after this point treats "
                  "the body as untrusted.",
                  completed_by="read_ticket", owner="triage"),
    ProcedureNode("kyc_verify", "KYC / identity verification",
                  "Confirm the customer on the ticket is a real account holder. "
                  "Nothing account-specific may happen before this.",
                  completed_by="lookup_customer", owner="analyst"),
    ProcedureNode("integrity_check", "Account data integrity",
                  "Confirm the ticket's subject matches the retrieved account "
                  "and the record is internally consistent.",
                  completed_by="verify_account_integrity", owner="analyst"),
    ProcedureNode("eligibility_decision", "Refund eligibility decision",
                  "Record an explicit, auditable decision on whether this "
                  "customer is owed money, and how much.",
                  completed_by="decide_refund_eligibility", owner="analyst"),
    ProcedureNode("disbursement", "Disbursement",
                  "Move the money. Irreversible.",
                  completed_by="issue_refund", owner="payments"),
    ProcedureNode("notification", "Customer notification",
                  "Tell the customer what happened. The egress boundary.",
                  completed_by="send_email", owner="comms"),
    ProcedureNode("closure", "Case closure",
                  "Mark the ticket resolved.",
                  completed_by="close_ticket", owner="analyst"),
]

EDGES: list[ProcedureEdge] = [
    ProcedureEdge(
        "intake", Relation.LEADS_TO, "kyc_verify",
        condition="a ticket has been read in this session",
        guidance="Look up the customer named on the ticket, not one named in "
                 "its body.",
        pitfalls="The ticket body is attacker-controlled. A customer id that "
                 "appears only in the body is not a verified subject.",
        guard="intake_done",
    ),
    ProcedureEdge(
        "kyc_verify", Relation.LEADS_TO, "integrity_check",
        condition="the customer record was retrieved and matches the ticket",
        guidance="Verify the account before forming any opinion about money.",
        pitfalls="Skipping straight to eligibility means deciding on data "
                 "nobody confirmed.",
        guard="kyc_passed",
    ),
    ProcedureEdge(
        "integrity_check", Relation.PROVIDES_INPUT_FOR, "eligibility_decision",
        condition="the integrity check passed",
        guidance="Decide eligibility from the verified record.",
        pitfalls="A failed integrity check is a stop, not a warning: the "
                 "eligibility decision would rest on data known to be wrong.",
        guard="integrity_passed",
    ),
    ProcedureEdge(
        "eligibility_decision", Relation.TRIGGERS, "disbursement",
        condition="the recorded decision is 'eligible' and the amount is within "
                  "the approved figure",
        guidance="Pay no more than the decision authorised.",
        pitfalls="The decision records an amount for a reason. Paying a "
                 "different figure makes the decision record meaningless.",
        guard="refund_approved",
    ),
    ProcedureEdge(
        "disbursement", Relation.LEADS_TO, "notification",
        condition="the refund was disbursed",
        guidance="Tell the customer what was paid.",
        pitfalls="Notifying before disbursement promises money that may never "
                 "move.",
        guard="always",
    ),
    # The refused-refund path. A customer who is told 'no' still gets told, so
    # `notification` converges from both the paid and the unpaid branch.
    ProcedureEdge(
        "eligibility_decision", Relation.CONVERGES_TO, "notification",
        condition="a decision was recorded, including a refusal",
        guidance="A declined refund is still a reply the customer is owed.",
        pitfalls="Silently dropping declined cases is how complaints become "
                 "regulatory findings.",
        guard="eligibility_recorded",
    ),
    ProcedureEdge(
        "notification", Relation.CONVERGES_TO, "closure",
        condition="the customer has been notified",
        guidance="Close only once the customer knows the outcome.",
        pitfalls="Closing an un-notified ticket hides an unresolved case from "
                 "every queue metric that matters.",
        guard="always",
    ),
]

# tool -> the stage it completes. Tools absent from this map (read_customer_pii)
# are not stages: they are side capabilities, gated on stage facts instead.
TOOL_STAGE: dict[str, str] = {
    n.completed_by: n.key for n in NODES if n.completed_by
}

ENTRY = "intake"


# ── per-session position and facts ──────────────────────────────────

@dataclass
class ProcedureState:
    """Where one session has got to, and what it established on the way.

    `facts` is the evidence the edge guards read. It is written only from
    *successful* tool results, never from an agent's claim about them -- the
    same principle as the DLP ratchet, which taints on observation rather than
    on intent.
    """

    completed: set[str] = field(default_factory=set)
    history: list[dict[str, Any]] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    violations: list[dict[str, Any]] = field(default_factory=list)
    # Stage the session stopped at, for the bottleneck report.
    last_stage: str = ""

    def is_done(self, stage: str) -> bool:
        return stage in self.completed

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed": sorted(self.completed),
            "history": list(self.history),
            "facts": dict(self.facts),
            "violations": list(self.violations),
            "last_stage": self.last_stage,
            "complete": "closure" in self.completed,
            "progress": len(self.completed),
            "total_stages": len(NODES),
        }


# ── guards ──────────────────────────────────────────────────────────
#
# Each guard is a pure function of (state, call args). They are deliberately
# tiny and total: a guard that raises would fail open, so none of them can.

Guard = Callable[[ProcedureState, dict[str, Any]], bool]


def _g_always(st: ProcedureState, args: dict[str, Any]) -> bool:
    return True


def _g_intake_done(st: ProcedureState, args: dict[str, Any]) -> bool:
    return st.is_done("intake")


def _g_kyc_passed(st: ProcedureState, args: dict[str, Any]) -> bool:
    return st.is_done("kyc_verify") and bool(st.facts.get("kyc_customer"))


def _g_integrity_passed(st: ProcedureState, args: dict[str, Any]) -> bool:
    return st.is_done("integrity_check") and st.facts.get("integrity_passed") is True


def _g_eligibility_recorded(st: ProcedureState, args: dict[str, Any]) -> bool:
    return st.is_done("eligibility_decision")


def _g_refund_approved(st: ProcedureState, args: dict[str, Any]) -> bool:
    """Eligible, and the *running total* stays within what was authorised.

    Cumulative rather than per-call on purpose. A per-call check passes a
    second payment of the same approved amount, which is how ATT-19 pays one
    refund twice. Comparing the total disbursed against the total approved
    catches double payment and salami-slicing inside a case with one
    comparison, and never collides with the session-wide structuring caps in
    `30-payments.yaml` -- those govern spend across a session, this governs
    spend against a decision.
    """
    if not st.is_done("eligibility_decision"):
        return False
    if st.facts.get("eligible") is not True:
        return False
    approved = float(st.facts.get("approved_amount") or 0.0)
    already = float(st.facts.get("disbursed_total") or 0.0)
    try:
        requested = float(args.get("amount") or 0.0)
    except (TypeError, ValueError):
        return False
    # A tenth of a cent of slack, so float noise never denies a correct refund.
    return already + requested <= approved + 0.001


GUARDS: dict[str, Guard] = {
    "always": _g_always,
    "intake_done": _g_intake_done,
    "kyc_passed": _g_kyc_passed,
    "integrity_passed": _g_integrity_passed,
    "eligibility_recorded": _g_eligibility_recorded,
    "refund_approved": _g_refund_approved,
}


# ── the graph ───────────────────────────────────────────────────────

class ProcedureGraph:
    """The procedure, plus the traversal logic the governor consults.

    Stateless with respect to sessions: all mutable position lives in a
    `ProcedureState` handed in by the caller, so one graph serves every
    concurrent session.
    """

    def __init__(self, nodes: list[ProcedureNode] | None = None,
                 edges: list[ProcedureEdge] | None = None) -> None:
        self.nodes = {n.key: n for n in (nodes or NODES)}
        self.edges = list(edges or EDGES)
        self.order = [n.key for n in (nodes or NODES)]
        self._inbound: dict[str, list[ProcedureEdge]] = {k: [] for k in self.nodes}
        for e in self.edges:
            self._inbound.setdefault(e.dst, []).append(e)
        self._validate()

    def _validate(self) -> None:
        """Fail loudly at import time rather than silently at runtime.

        A typo in an edge endpoint would otherwise produce a stage that can
        never be entered, which reads as "governance is working" right up until
        someone notices the process never completes.
        """
        for e in self.edges:
            if e.src not in self.nodes:
                raise ValueError(f"procedure edge from unknown stage '{e.src}'")
            if e.dst not in self.nodes:
                raise ValueError(f"procedure edge to unknown stage '{e.dst}'")
            if e.guard and e.guard not in GUARDS:
                raise ValueError(f"edge {e.src}->{e.dst} names unknown guard "
                                 f"'{e.guard}'")

    # ── traversal ───────────────────────────────────────────────────

    def stage_for_tool(self, tool: str) -> str:
        return TOOL_STAGE.get(tool, "")

    def enterable(self, stage: str, st: ProcedureState,
                  args: dict[str, Any] | None = None) -> tuple[bool, str]:
        """May this session enter `stage` right now?

        Graph semantics: a stage opens when *at least one* inbound edge has a
        completed source and a satisfied guard. "At least one" rather than
        "all" is what lets `notification` converge from both the paid and the
        declined branch without special-casing either.

        Returns (allowed, human-readable reason).
        """
        args = args or {}
        if stage == ENTRY:
            return True, "entry stage"

        inbound = self._inbound.get(stage, [])
        if not inbound:
            return False, f"stage '{stage}' is unreachable: no inbound edges"

        unmet: list[str] = []
        for e in inbound:
            if not st.is_done(e.src):
                unmet.append(f"'{e.src}' not completed")
                continue
            guard = GUARDS.get(e.guard or "always", _g_always)
            if guard(st, args):
                return True, f"{e.src} --{e.relation.value}--> {stage}"
            unmet.append(f"{e.src}->{stage} requires: {e.condition}")

        return False, "; ".join(unmet)

    def next_expected(self, st: ProcedureState) -> list[str]:
        """Stages the session could legally enter next. Drives the UI pipeline."""
        return [s for s in self.order
                if s not in st.completed and self.enterable(s, st)[0]]

    # ── advancement ─────────────────────────────────────────────────

    def observe(self, st: ProcedureState, tool: str, args: dict[str, Any],
                result: Any) -> str:
        """Record that `tool` ran successfully. Returns the stage completed.

        Called from the governor *after* execution, so the procedure advances
        on evidence rather than on intent -- an attempted step that was denied
        leaves the position untouched, which is what makes the bottleneck
        report able to see where sessions actually stall.
        """
        stage = self.stage_for_tool(tool)
        self._absorb_facts(st, tool, args, result)
        if not stage:
            return ""
        st.completed.add(stage)
        st.last_stage = stage
        st.history.append({"stage": stage, "tool": tool})
        return stage

    def _absorb_facts(self, st: ProcedureState, tool: str, args: dict[str, Any],
                      result: Any) -> None:
        """Extract edge-guard evidence from a real tool result."""
        res = result if isinstance(result, dict) else {}

        if tool == "read_ticket":
            st.facts["ticket_id"] = res.get("id") or args.get("ticket_id")
            # The ticket's *own* customer field -- never a customer id parsed
            # out of the body, which the attacker writes.
            st.facts["ticket_customer"] = res.get("customer_id")

        elif tool == "lookup_customer":
            st.facts["kyc_customer"] = res.get("id") or args.get("customer_id")
            st.facts["kyc_email"] = res.get("email")

        elif tool == "verify_account_integrity":
            st.facts["integrity_passed"] = bool(res.get("passed"))
            st.facts["integrity_findings"] = res.get("findings", [])

        elif tool == "decide_refund_eligibility":
            st.facts["eligible"] = bool(res.get("eligible"))
            st.facts["approved_amount"] = float(res.get("approved_amount") or 0.0)
            st.facts["decision_rationale"] = res.get("rationale", "")

        elif tool == "issue_refund":
            paid = float(args.get("amount") or 0.0)
            st.facts["disbursed_amount"] = paid
            st.facts["disbursed_total"] = round(
                float(st.facts.get("disbursed_total") or 0.0) + paid, 2)

        elif tool == "send_email":
            st.facts["notified"] = res.get("to") or args.get("to")

    def record_violation(self, st: ProcedureState, stage: str, tool: str,
                         reason: str) -> None:
        st.violations.append({"stage": stage, "tool": tool, "reason": reason})

    # ── the policy-context facts ────────────────────────────────────

    def context(self, st: ProcedureState, tool: str,
                args: dict[str, Any]) -> dict[str, Any]:
        """Flatten position into the `procedure.*` vocabulary policy reads.

        Every negative is published as a *positive* boolean (`kyc_incomplete`
        rather than `not kyc_complete`). The toolkit's condition evaluator has
        no `not` operator and fails silently when you write one -- see
        AEG030 in `policytool.py` -- so a rule needing a negation must be
        handed one pre-computed.
        """
        stage = self.stage_for_tool(tool)
        allowed, reason = (True, "not a procedure stage")
        replay = False
        if stage:
            replay = st.is_done(stage)
            allowed, reason = self.enterable(stage, st, args)

        nxt = self.next_expected(st)

        def done(s: str) -> bool:
            return st.is_done(s)

        return {
            "stage": stage,
            "current": st.last_stage or "none",
            "next_expected": ",".join(nxt) if nxt else "none",
            "in_order": bool(allowed),
            "out_of_order": bool(stage) and not allowed,
            "replay": replay,
            "blocked_reason": reason,
            "steps_done": len(st.completed),

            "intake_complete": done("intake"),
            "intake_incomplete": not done("intake"),
            "kyc_complete": done("kyc_verify"),
            "kyc_incomplete": not done("kyc_verify"),
            "integrity_complete": done("integrity_check"),
            "integrity_incomplete": not done("integrity_check"),
            "eligibility_complete": done("eligibility_decision"),
            "eligibility_incomplete": not done("eligibility_decision"),
            "disbursement_complete": done("disbursement"),
            "notification_complete": done("notification"),
            "notification_incomplete": not done("notification"),
            "complete": done("closure"),

            # "not approved" means a decision exists and it said no. A session
            # with no decision at all is described by `eligibility_incomplete`
            # instead, so exactly one rule fires and the audit record names the
            # actual problem rather than two overlapping ones.
            "refund_approved": st.facts.get("eligible") is True,
            "refund_refused": (done("eligibility_decision")
                               and st.facts.get("eligible") is not True),
            "amount_exceeds_approved": _amount_exceeds(st, tool, args),
            "disbursed_total": float(st.facts.get("disbursed_total") or 0.0),
            "approved_amount": float(st.facts.get("approved_amount") or 0.0),
        }

    # ── introspection ───────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [self.nodes[k].to_dict() for k in self.order],
            "edges": [e.to_dict() for e in self.edges],
            "tool_stage": dict(TOOL_STAGE),
        }


def _amount_exceeds(st: ProcedureState, tool: str, args: dict[str, Any]) -> bool:
    """True when this refund would push the case past its approved total.

    Cumulative, so it catches both "pay more than was approved" and "pay the
    approved amount twice" -- ATT-19 is the second of those.

    False for every non-refund tool, and false when no decision exists yet: in
    that case `eligibility_incomplete` is the fact that should deny, and two
    rules firing on one call makes the audit record harder to read, not safer.
    """
    if tool != "issue_refund" or not st.is_done("eligibility_decision"):
        return False
    if st.facts.get("eligible") is not True:
        return False
    try:
        requested = float(args.get("amount") or 0.0)
    except (TypeError, ValueError):
        return False
    approved = float(st.facts.get("approved_amount") or 0.0)
    already = float(st.facts.get("disbursed_total") or 0.0)
    return already + requested > approved + 0.001


GRAPH = ProcedureGraph()
