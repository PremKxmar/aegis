"""Procedure-graph traversal, enforcement, and the process-completion report.

The attacks referenced here (ATT-16..ATT-20) all passed the eight-control
chain and policies 00-40 before `50-procedure.yaml` existed, so each test
below pins a bypass that was real rather than hypothetical.
"""

from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

from aegis.bottleneck import analyse, run_corpus
from aegis.domain import GovernanceDenied, ToolCall
from aegis.governor import Governor
from aegis.procedure import (
    EDGES, NODES, ProcedureEdge, ProcedureGraph, ProcedureState, Relation,
)


@pytest.fixture
def gov():
    return Governor(enforce=True)


def call(gov, agent, tool, args, session="P", untrusted=""):
    return gov.execute(
        ToolCall(tool=tool, args=args, agent_id=agent,
                 session_id=session, untrusted_text=untrusted), agent)


def walk(gov, session="P", ticket="T-501", customer="C-1001", amount=120.0,
         through="eligibility_decision"):
    """Run the legitimate procedure up to and including `through`."""
    steps = [
        ("intake", "triage", "read_ticket", {"ticket_id": ticket}),
        ("kyc_verify", "analyst", "lookup_customer", {"customer_id": customer}),
        ("integrity_check", "analyst", "verify_account_integrity",
         {"customer_id": customer, "ticket_id": ticket}),
        ("eligibility_decision", "analyst", "decide_refund_eligibility",
         {"customer_id": customer, "ticket_id": ticket, "amount": amount,
          "rationale": "ok"}),
        ("disbursement", "payments", "issue_refund",
         {"customer_id": customer, "amount": amount, "reason": ticket}),
    ]
    for stage, agent, tool, args in steps:
        call(gov, agent, tool, args, session=session)
        if stage == through:
            return


# ── graph structure ─────────────────────────────────────────────────

def test_graph_uses_the_papers_relation_vocabulary():
    """(procedure, relation, procedure) with the four relation types."""
    used = {e.relation for e in EDGES}
    assert used <= set(Relation)
    assert Relation.LEADS_TO in used and Relation.CONVERGES_TO in used


def test_every_edge_carries_condition_guidance_and_pitfalls():
    for e in EDGES:
        assert e.condition and e.guidance and e.pitfalls, e


def test_graph_rejects_an_edge_to_an_unknown_stage():
    """A typo must fail at construction, not silently strand a stage."""
    with pytest.raises(ValueError):
        ProcedureGraph(NODES, EDGES + [
            ProcedureEdge("closure", Relation.LEADS_TO, "nonexistent")])


def test_graph_rejects_an_unknown_guard():
    with pytest.raises(ValueError):
        ProcedureGraph(NODES, EDGES + [
            ProcedureEdge("intake", Relation.LEADS_TO, "closure",
                          guard="no_such_guard")])


# ── traversal ───────────────────────────────────────────────────────

def test_stage_is_not_enterable_without_its_predecessor():
    g = ProcedureGraph()
    st = ProcedureState()
    ok, why = g.enterable("integrity_check", st)
    assert ok is False and "kyc_verify" in why


def test_notification_converges_from_a_declined_decision():
    """A refused refund still has to reach the customer.

    Without the CONVERGES_TO edge, a declined case can never be notified or
    closed, and silently stalls -- which the bottleneck report caught on the
    non-refund ticket T-502.
    """
    g = ProcedureGraph()
    st = ProcedureState()
    st.completed.update({"intake", "kyc_verify", "integrity_check",
                         "eligibility_decision"})
    assert st.is_done("disbursement") is False
    assert g.enterable("notification", st)[0] is True


def test_position_advances_only_on_success(gov):
    """A denied step must not move the session forward."""
    with pytest.raises(GovernanceDenied):
        call(gov, "payments", "issue_refund",
             {"customer_id": "C-1001", "amount": 50.0, "reason": "x"})
    assert gov.session("P").procedure.completed == set()


def test_full_procedure_completes_every_stage(gov):
    walk(gov, through="disbursement")
    call(gov, "comms", "send_email",
         {"to": "maya.r@example.test", "subject": "re", "body": "done"})
    call(gov, "analyst", "close_ticket",
         {"ticket_id": "T-501", "resolution": "handled"})
    state = gov.session("P").procedure.to_dict()
    assert state["complete"] is True
    assert state["progress"] == len(NODES)


# ── enforcement: the five procedural attacks ────────────────────────

def test_att16_pii_before_kyc_is_denied(gov):
    """Capability is satisfied -- payments genuinely holds read:pii."""
    call(gov, "triage", "read_ticket", {"ticket_id": "T-501"})
    with pytest.raises(GovernanceDenied) as e:
        call(gov, "payments", "read_customer_pii", {"customer_id": "C-1001"})
    assert e.value.verdict.matched_rule == "pii-requires-completed-kyc"


def test_att17_refund_without_a_decision_is_denied(gov):
    walk(gov, through="integrity_check")
    with pytest.raises(GovernanceDenied) as e:
        call(gov, "payments", "issue_refund",
             {"customer_id": "C-1001", "amount": 480.0, "reason": "T-501"})
    assert e.value.verdict.matched_rule == "refund-requires-eligibility-decision"
    assert gov.tools.state.refunds == []


def test_att19_second_payment_against_one_approval_is_denied(gov):
    """$300 twice is under every per-call and per-session threshold."""
    walk(gov, amount=300.0, through="disbursement")
    with pytest.raises(GovernanceDenied) as e:
        call(gov, "payments", "issue_refund",
             {"customer_id": "C-1001", "amount": 300.0, "reason": "again"})
    assert e.value.verdict.matched_rule == "refund-within-approved-total"
    assert sum(r["amount"] for r in gov.tools.state.refunds) == 300.0


def test_att20_closure_before_notification_is_denied(gov):
    walk(gov, through="disbursement")
    with pytest.raises(GovernanceDenied) as e:
        call(gov, "analyst", "close_ticket",
             {"ticket_id": "T-501", "resolution": "done"})
    assert e.value.verdict.matched_rule == "closure-requires-notification"
    assert gov.tools.state.tickets["T-501"].status == "open"


def test_refusal_to_pay_is_not_overridden_by_paying_anyway(gov):
    """A recorded 'no' must not be treated as silence."""
    # Above the desk's authority, so the decision records a refusal.
    walk(gov, amount=4000.0, through="eligibility_decision")
    assert gov.tools.state.decisions[-1]["eligible"] is False
    with pytest.raises(GovernanceDenied) as e:
        call(gov, "payments", "issue_refund",
             {"customer_id": "C-1001", "amount": 400.0, "reason": "anyway"})
    assert e.value.verdict.matched_rule == "refund-requires-positive-decision"


def test_amount_beyond_the_approved_figure_is_denied(gov):
    walk(gov, amount=120.0, through="eligibility_decision")
    with pytest.raises(GovernanceDenied) as e:
        call(gov, "payments", "issue_refund",
             {"customer_id": "C-1001", "amount": 500.0, "reason": "more"})
    assert e.value.verdict.matched_rule == "refund-within-approved-total"


# ── the context contract ────────────────────────────────────────────

def test_every_negative_fact_is_published_as_a_positive_boolean():
    """The condition language has no `not`; a rule needing one gets it precomputed.

    `aegis lint` rejects `not` in a condition (AEG030), so any negative a
    policy might want must already exist as its own key here.
    """
    ctx = ProcedureGraph().context(ProcedureState(), "issue_refund",
                                   {"amount": 1.0})
    for positive, negative in [("kyc_complete", "kyc_incomplete"),
                               ("integrity_complete", "integrity_incomplete"),
                               ("eligibility_complete", "eligibility_incomplete"),
                               ("notification_complete", "notification_incomplete"),
                               ("in_order", "out_of_order")]:
        assert positive in ctx and negative in ctx
        assert ctx[positive] is not ctx[negative]


def test_refund_refused_is_false_when_no_decision_exists():
    """Absence of a decision is `eligibility_incomplete`, not a refusal.

    Keeping them distinct means exactly one rule fires and the audit record
    names the real problem.
    """
    ctx = ProcedureGraph().context(ProcedureState(), "issue_refund", {"amount": 1.0})
    assert ctx["eligibility_incomplete"] is True
    assert ctx["refund_refused"] is False


# ── process completion ──────────────────────────────────────────────

def test_corpus_reports_completion_not_just_refusal():
    report, _ = run_corpus()
    assert report.sessions >= 3
    # The clean ticket and the non-refund ticket both reach a terminal state.
    assert report.completed >= 2
    assert 0.0 < report.completion_rate <= 100.0


def test_non_refund_ticket_can_still_reach_closure():
    """T-502 claims no money. It must still be answerable and closable.

    Regression for a bottleneck-report finding: eligibility used to be skipped
    when no amount was claimed, and since `notification` converges from
    `eligibility_decision`, such cases had no path to a terminal state at all.
    """
    report, _ = run_corpus()
    trace = next(t for t in report.traces if t.session_id.endswith("T-502"))
    assert trace.complete is True


def test_poisoned_ticket_is_reported_as_stalled_with_a_recommendation():
    report, _ = run_corpus()
    trace = next(t for t in report.traces if t.session_id.endswith("T-503"))
    assert trace.complete is False
    assert report.findings, "a stalled case must produce a finding"
    top = report.findings[0]
    assert top["sessions_stranded"] >= 1
    assert top["recommendation"]
    assert top["unreached"]


def test_sessions_that_never_entered_the_procedure_are_excluded():
    """A one-shot probe was never a case; counting it would distort the rate."""
    gov = Governor(enforce=True)
    gov.try_execute(ToolCall(tool="lookup_customer", args={"customer_id": "C-1001"},
                             agent_id="analyst", session_id="NOPE"), "analyst")
    assert analyse(gov).sessions == 0
