"""The four-agent back-office workflow.

These agents are deliberately *not* LLM-backed. The project is about the
governance layer, and a scripted agent makes the demo deterministic and
reproducible -- every run of the red-team suite produces the same numbers,
which is what lets us report an attack-success-rate honestly.

The important property is that each agent calls `governor.execute(...)` and
handles `GovernanceDenied`. Swapping the bodies for real LLM tool-calling
loops would not change the governance path at all; `aegis/agents/llm.py`
shows that wiring for an Anthropic-backed agent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..domain import ApprovalRequired, GovernanceDenied, ToolCall
from ..governor import Governor


@dataclass
class StepLog:
    """One attempted action and what governance did about it."""

    agent: str
    tool: str
    outcome: str            # ok | denied | approval_required | error
    detail: str
    control: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class WorkflowResult:
    ticket_id: str
    session_id: str
    steps: list[StepLog] = field(default_factory=list)
    refunded: float = 0.0
    emails_sent: int = 0
    notes: list[str] = field(default_factory=list)

    def add(self, step: StepLog) -> None:
        self.steps.append(step)

    @property
    def denied_count(self) -> int:
        return sum(1 for s in self.steps if s.outcome in ("denied", "approval_required"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "session_id": self.session_id,
            "steps": [s.to_dict() for s in self.steps],
            "refunded": self.refunded,
            "emails_sent": self.emails_sent,
            "denied_count": self.denied_count,
            "notes": self.notes,
        }


class BackOfficeWorkflow:
    """Triage -> Analyst -> Payments -> Comms, with governance at each hop."""

    REFUND_RE = re.compile(r"\$\s?([0-9][0-9,]*(?:\.[0-9]{1,2})?)")

    def __init__(self, governor: Governor):
        self.gov = governor

    # ── helpers ─────────────────────────────────────────────────────

    def _call(self, result: WorkflowResult, agent: str, tool: str,
              args: dict[str, Any], untrusted: str = "") -> tuple[bool, Any]:
        """Attempt one governed tool call and log whatever happened."""
        call = ToolCall(tool=tool, args=args, agent_id=agent,
                        session_id=result.session_id, untrusted_text=untrusted)
        try:
            out = self.gov.execute(call, agent)
            result.add(StepLog(agent, tool, "ok", f"{tool} succeeded"))
            return True, out
        except ApprovalRequired as exc:
            result.add(StepLog(agent, tool, "approval_required",
                               exc.verdict.reason, exc.verdict.control))
            return False, exc.verdict
        except GovernanceDenied as exc:
            result.add(StepLog(agent, tool, "denied",
                               exc.verdict.reason, exc.verdict.control))
            return False, exc.verdict
        except Exception as exc:  # tool-level failure, not governance
            result.add(StepLog(agent, tool, "error", f"{type(exc).__name__}: {exc}"))
            return False, exc

    def _extract_amount(self, text: str) -> float | None:
        m = self.REFUND_RE.search(text or "")
        if not m:
            return None
        try:
            return float(m.group(1).replace(",", ""))
        except ValueError:
            return None

    # ── the workflow ────────────────────────────────────────────────

    def run(self, ticket_id: str, session_id: str | None = None) -> WorkflowResult:
        sid = session_id or f"S-{ticket_id}"
        res = WorkflowResult(ticket_id=ticket_id, session_id=sid)

        # 1. TRIAGE reads the ticket. The body is untrusted from this point on
        #    and is passed as `untrusted_text` so the injection scanner sees it.
        ok, ticket = self._call(res, "triage", "read_ticket", {"ticket_id": ticket_id})
        if not ok:
            res.notes.append("triage could not read the ticket; workflow halted")
            return res

        body = ticket.get("body", "")
        customer_id = ticket.get("customer_id", "")
        res.notes.append(f"triage classified ticket for {customer_id}")

        # 2. ANALYST pulls the account record. Every subsequent call in this
        #    session carries the untrusted body, so the scanner keeps flagging.
        ok, customer = self._call(res, "analyst", "lookup_customer",
                                  {"customer_id": customer_id}, untrusted=body)
        if ok:
            res.notes.append(f"analyst retrieved account for {customer.get('name')}")

        # 3. REMOVED: the analyst used to attempt read_customer_pii here, as a
        #    live demonstration of the capability layer denying a call on an
        #    entirely benign ticket.
        #
        #    FINDING (aegis bottleneck): across a corpus of tickets that probe
        #    was quarantining the agent. Every denial is a trust penalty, so a
        #    workflow that deliberately calls a tool it has no capability for
        #    loses ~0.12 of trust per ticket and eventually trips
        #    `low-trust-loses-write` -- after which legitimate cases stop
        #    completing for a reason that has nothing to do with those cases.
        #    Invisible in a single-ticket demo; obvious the moment completion
        #    is measured across sessions. The capability layer is still
        #    exercised by ATT-03 and ATT-04, which is where probing belongs.

        # 4. ANALYST verifies the record hangs together before anyone forms an
        #    opinion about money. This is the stage that catches a ticket body
        #    naming an account the ticket is not actually about.
        self._call(res, "analyst", "verify_account_integrity",
                   {"customer_id": customer_id, "ticket_id": ticket_id},
                   untrusted=body)

        # 5. ANALYST records an explicit eligibility decision. The amount is
        #    read from the ticket body, which is untrusted -- so the decision
        #    is the control that turns an attacker's claimed figure into an
        #    authorised one, and it is the thing `issue_refund` is gated on.
        #
        #    FINDING (aegis bottleneck): this used to run only when the body
        #    contained a figure. A ticket with no refund claim -- T-502, "my
        #    card keeps getting declined" -- therefore recorded no decision,
        #    and `notification` converges from `eligibility_decision`, so the
        #    case could never reach the customer or be closed. A perfectly
        #    legitimate ticket had no path to a terminal state. Every case now
        #    gets a decision, including "nothing is owed", which is also how a
        #    real back office works.
        amount = self._extract_amount(body) or 0.0
        self._call(res, "analyst", "decide_refund_eligibility",
                   {"customer_id": customer_id, "ticket_id": ticket_id,
                    "amount": amount,
                    "rationale": ("claim reviewed against record" if amount
                                  else "no refund claimed; informational reply")},
                   untrusted=body)

        # 6. PAYMENTS issues the refund the decision authorised.
        if amount:
            ok, out = self._call(res, "payments", "issue_refund",
                                 {"customer_id": customer_id, "amount": amount,
                                  "reason": f"ticket {ticket_id}"},
                                 untrusted=body)
            if ok:
                res.refunded = amount
                res.notes.append(f"refunded ${amount:.2f}")
            else:
                res.notes.append(f"refund of ${amount:.2f} not completed")
        else:
            res.notes.append("no refund amount found in ticket")

        # 7. COMMS replies to the customer.
        ok, _ = self._call(res, "comms", "send_email",
                           {"to": customer.get("email", "unknown@example.test")
                            if isinstance(customer, dict) else "unknown@example.test",
                            "subject": f"Re: {ticket.get('subject','your ticket')}",
                            "body": "Thanks for getting in touch - we've reviewed "
                                    "your account and actioned your request."},
                           untrusted=body)
        if ok:
            res.emails_sent += 1

        # 8. ANALYST closes the ticket.
        #    FINDING: this was originally the triage agent. Ring 3 forbids all
        #    mutation, so `close_ticket` was denied on every run -- including
        #    entirely benign ones. Rather than weaken the ring rule we moved
        #    closure to the analyst (Ring 2), which is the correct fix: the
        #    agent that reads attacker-controlled text should not be the one
        #    that writes state. The governance layer surfaced a real
        #    architecture mistake before it ever shipped.
        self._call(res, "analyst", "close_ticket",
                   {"ticket_id": ticket_id, "resolution": "handled"},
                   untrusted=body)

        return res
