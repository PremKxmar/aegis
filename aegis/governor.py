"""The governor: the single chokepoint every tool call passes through.

Design note -- why the ordering below matters
---------------------------------------------
Controls run cheapest-and-most-absolute first:

  0. kill switch     no rule can satisfy it; not even evaluated if engaged
  1. capability      identity-derived; cannot be widened at runtime
  2. trust quarantine  behavioural; an agent that keeps probing loses access
  3. injection scan  ADVISORY ONLY -- raises risk, never the sole reason to allow
  4. policy engine   the declarative rulebook (AGT)
  5. DLP ratchet     information-flow; overrides an ALLOW from policy
  6. budget/rate     resource exhaustion
  7. approval gate   human sign-off

Layers 3 and 4-6 are deliberately independent. The injection detector is a
probabilistic classifier and *will* miss things (we demonstrate a bypass in
the red-team suite). When it misses, layers 1, 4 and 5 still hold, because
they reason about what the action *is*, not about what the text *looks like*.
That is the entire argument for deterministic runtime governance.
"""

from __future__ import annotations

import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

warnings.filterwarnings("ignore", category=DeprecationWarning)

from agent_os import PromptInjectionDetector  # noqa: E402
from agent_os.prompt_injection import load_prompt_injection_config  # noqa: E402
from agentmesh import PolicyEngine  # noqa: E402

from .audit import AuditLedger  # noqa: E402
from .controls import ApprovalQueue, Budget, KillSwitch  # noqa: E402
from .domain import (  # noqa: E402
    ApprovalRequired, Decision, GovernanceDenied, Ring, Sensitivity,
    Stage, ToolCall, ToolSpec, Verdict,
)
from .identity import AgentRegistry  # noqa: E402
from .ratchet import DLPRatchet  # noqa: E402
from .tools.banking import SPECS, BankingTools  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = ROOT / "policies"
DETECTOR_CONFIG = ROOT / "config" / "prompt-injection.yaml"


@dataclass
class SessionState:
    """Everything scoped to one unit of work (one ticket, typically)."""

    session_id: str
    ratchet: DLPRatchet = field(default_factory=DLPRatchet)
    budget: Budget = field(default_factory=Budget)
    injection_flags: list[dict[str, Any]] = field(default_factory=list)
    # Cumulative refund total. ATT-07 showed that a per-call approval
    # threshold is trivially defeated by splitting one large refund into many
    # small ones, so the session carries a running total that policy can gate.
    refund_total_usd: float = 0.0
    refund_count: int = 0
    # Addresses this session is permitted to mail: populated from the ticket
    # the work originated from. Empty means "no external mail authorised".
    allowed_recipients: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "ratchet": self.ratchet.to_dict(),
            "budget": self.budget.to_dict(),
            "injection_flags": self.injection_flags,
            "refund_total_usd": round(self.refund_total_usd, 2),
            "refund_count": self.refund_count,
            "allowed_recipients": sorted(self.allowed_recipients),
        }


class Governor:
    """Wraps a tool registry with the full control chain.

    `enforce=False` turns every control into a no-op *except* auditing, which
    is how the side-by-side demo gets a true apples-to-apples comparison: the
    ungoverned run still produces a decision log, it just never blocks.
    """

    def __init__(self, *, enforce: bool = True, policy_dir: Path | None = None,
                 registry: AgentRegistry | None = None,
                 tools: BankingTools | None = None,
                 on_event: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.enforce = enforce
        self.registry = registry or AgentRegistry()
        self.tools = tools or BankingTools()
        self.ledger = AuditLedger()
        self.approvals = ApprovalQueue()
        self.killswitch = KillSwitch()
        # Explicit ruleset: the built-in defaults miss politely-phrased
        # injections (see tests/test_detector_config.py).
        self.detector = PromptInjectionDetector(
            injection_config=load_prompt_injection_config(str(DETECTOR_CONFIG))
        )
        self.sessions: dict[str, SessionState] = {}
        self._on_event = on_event

        self.policy = PolicyEngine(conflict_strategy="deny_overrides")
        self.loaded_policies: list[str] = []
        self._load_policies(policy_dir or POLICY_DIR)

    # ── policy loading ──────────────────────────────────────────────

    def _load_policies(self, directory: Path) -> None:
        if not directory.exists():
            raise FileNotFoundError(f"policy directory missing: {directory}")
        for path in sorted(directory.glob("*.yaml")):
            pol = self.policy.load_yaml_file(str(path))
            self.loaded_policies.append(pol.name)
        if not self.loaded_policies:
            raise RuntimeError(f"no policies loaded from {directory}")

    # ── session handling ────────────────────────────────────────────

    def session(self, session_id: str) -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id=session_id)
        return self.sessions[session_id]

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        if self._on_event:
            try:
                self._on_event({"kind": kind, "at": time.time(), **payload})
            except Exception:
                pass  # telemetry must never break enforcement

    # ── the control chain ───────────────────────────────────────────

    def evaluate(self, call: ToolCall, agent_key: str) -> Verdict:
        """Run every control and return a verdict. Never executes anything."""
        started = time.perf_counter()
        spec = SPECS.get(call.tool)
        agent = self.registry.get(agent_key)
        sess = self.session(call.session_id)

        def done(decision: Decision, reason: str, control: str,
                 rule: str | None = None, policy: str | None = None,
                 approvers: list[str] | None = None) -> Verdict:
            return Verdict(
                decision=decision, reason=reason, control=control,
                call_id=call.call_id, agent_id=agent.did, tool=call.tool,
                matched_rule=rule, policy_name=policy, approvers=approvers or [],
                latency_ms=(time.perf_counter() - started) * 1000.0,
                context_snapshot={"ring": int(agent.ring),
                                  "trust": self.registry.trust(agent_key),
                                  "mark": sess.ratchet.mark.label},
            )

        # Unknown tools are refused even in ungoverned mode: there is nothing
        # to execute, so this is a dispatch error rather than a policy call.
        if spec is None:
            return done(Decision.DENY, f"unknown tool '{call.tool}'", "dispatch")

        if not self.enforce:
            return done(Decision.ALLOW, "enforcement disabled (ungoverned baseline)",
                        "disabled")

        # 0. kill switch ------------------------------------------------
        killed, why = self.killswitch.blocked(agent_key)
        if killed:
            return done(Decision.DENY, why, "killswitch")

        # 1. capability -------------------------------------------------
        if spec.required_capability and not agent.has(spec.required_capability):
            return done(
                Decision.DENY,
                f"agent '{agent_key}' lacks capability '{spec.required_capability}' "
                f"(holds {agent.capabilities})",
                "capability",
            )

        # 2. trust quarantine -------------------------------------------
        if self.registry.is_quarantined(agent_key):
            return done(
                Decision.DENY,
                f"agent quarantined: trust {self.registry.trust(agent_key)} "
                f"below threshold after repeated violations",
                "trust",
            )

        # 3. injection scan (ADVISORY) ----------------------------------
        injection_risk = "none"
        if call.untrusted_text:
            res = self.detector.detect(call.untrusted_text)
            if getattr(res, "is_injection", False):
                injection_risk = str(getattr(res, "threat_level", "high")).split(".")[-1].lower()
                flag = {
                    "call_id": call.call_id, "tool": call.tool,
                    "confidence": getattr(res, "confidence", 0.0),
                    "type": str(getattr(res, "injection_type", "")).split(".")[-1],
                    "patterns": list(getattr(res, "matched_patterns", []))[:4],
                }
                if flag not in sess.injection_flags:
                    sess.injection_flags.append(flag)
                self._emit("injection", flag)

        # 4. policy engine ----------------------------------------------
        ctx = self._build_context(call, agent, spec, sess, injection_risk)
        decision = self.policy.evaluate(agent.did, ctx, stage=Stage.PRE_TOOL.value)

        if decision.action == "deny":
            return done(Decision.DENY,
                        decision.reason or "denied by policy", "policy",
                        decision.matched_rule, decision.policy_name)

        if decision.action == "require_approval":
            return done(Decision.REQUIRE_APPROVAL,
                        decision.reason or "human approval required", "policy",
                        decision.matched_rule, decision.policy_name,
                        list(decision.approvers))

        # 5. DLP ratchet — can veto an ALLOW from policy -----------------
        if sess.ratchet.blocks_egress(spec):
            return done(Decision.DENY, sess.ratchet.explain(spec), "dlp_ratchet")

        # 6. budget / rate ----------------------------------------------
        ok, why = sess.budget.check(spec.unit_cost_usd)
        if not ok:
            return done(Decision.DENY, why, "budget")

        verdict = done(
            Decision.WARN if decision.action == "warn" else Decision.ALLOW,
            decision.reason or "permitted by policy", "policy",
            decision.matched_rule, decision.policy_name,
        )
        return verdict

    def _build_context(self, call: ToolCall, agent, spec: ToolSpec,
                       sess: SessionState, injection_risk: str) -> dict[str, Any]:
        """Flatten runtime state into the dict policy conditions read.

        Keys here are the vocabulary policy authors write against, so they are
        part of the project's public contract -- see policies/README.md.
        """
        return {
            "tool": {
                "name": call.tool, "args": dict(call.args), **spec.as_context(),
                # NOTE: expressed as a *positive* boolean because the
                # condition language has no negation. `not tool.x` does not
                # raise -- it silently evaluates to False, so a rule written
                # that way never fires and never warns. Every negative
                # condition in this project is therefore pre-computed here.
                # `aegis lint` fails the build on any `not ` in a condition.
                "recipient_blocked": (
                    spec.egress
                    and str(call.args.get("to", "")) not in sess.allowed_recipients
                ),
                "recipient_allowed": (
                    str(call.args.get("to", "")) in sess.allowed_recipients
                    if spec.egress else True
                ),
            },
            "agent": {
                "key": agent.key,
                "did": agent.did,
                "role": agent.role,
                "ring": int(agent.ring),
                "trust_score": self.registry.trust(agent.key),
                "depth": agent.identity.delegation_depth,
            },
            "session": {
                "id": sess.session_id,
                "mark": sess.ratchet.mark.label,
                "mark_level": int(sess.ratchet.mark),
                "tainted": not sess.ratchet.is_clean(),
                "spent_usd": sess.budget.spent_usd,
                "calls": sess.budget.total_calls,
                "refund_total_usd": round(sess.refund_total_usd, 2),
                "refund_count": sess.refund_count,
                # Projected total *including* the call being evaluated: the
                # gate has to fire before the money moves, not after.
                "refund_total_after": round(
                    sess.refund_total_usd
                    + (float(call.args.get("amount", 0) or 0)
                       if call.tool == "issue_refund" else 0.0), 2),
            },
            "risk": {"injection": injection_risk,
                     "injection_detected": injection_risk != "none"},
            # Cedar/Rego adapters read `action.type`; keep it populated so the
            # same context works if you swap engines.
            "action": {"type": call.tool, "mutating": spec.mutating,
                       "egress": spec.egress},
        }

    # ── execution ───────────────────────────────────────────────────

    def execute(self, call: ToolCall, agent_key: str) -> Any:
        """Evaluate, then run the tool only if permitted.

        Raises GovernanceDenied / ApprovalRequired otherwise. The audit record
        is written on *every* path, including the raises.
        """
        verdict = self.evaluate(call, agent_key)
        rec = self.ledger.record(verdict, agent_key, call.args, call.session_id)
        self._emit("verdict", {"verdict": verdict.to_dict(), "seq": rec.seq})

        if verdict.decision is Decision.REQUIRE_APPROVAL:
            req = self.approvals.open(agent_key, call.tool, call.args,
                                      verdict.reason, verdict.approvers)
            self.registry.record(agent_key, call.tool, success=False)
            self._emit("approval_opened", {"request": req.to_dict()})
            raise ApprovalRequired(verdict)

        if verdict.blocked:
            self.registry.record(agent_key, call.tool, success=False)
            raise GovernanceDenied(verdict)

        sess = self.session(call.session_id)
        spec = SPECS[call.tool]
        sess.budget.charge(spec.unit_cost_usd)

        result = self.tools.call(call.tool, call.args)

        if call.tool == "issue_refund":
            sess.refund_total_usd += float(call.args.get("amount", 0) or 0)
            sess.refund_count += 1

        # post_tool enrichment: a session may contact principals whose records
        # it legitimately retrieved. This is what turns "send_email" from
        # "mail anyone on the internet" into "reply to the customer you are
        # actually working on" -- ATT-09 and ATT-13 both exploited its absence.
        if isinstance(result, dict) and result.get("email"):
            sess.allowed_recipients.add(str(result["email"]))

        # Taint only after a successful read: attempting to read does not leak.
        ev = sess.ratchet.observe(spec, call.call_id)
        if ev:
            self._emit("ratchet", {"event": ev.to_dict(),
                                   "session": call.session_id})

        self.registry.record(agent_key, call.tool, success=True)
        return result

    def try_execute(self, call: ToolCall, agent_key: str) -> tuple[bool, Any]:
        """Non-raising variant. Returns (succeeded, result_or_verdict)."""
        try:
            return True, self.execute(call, agent_key)
        except GovernanceDenied as exc:
            return False, exc.verdict

    # ── approval replay ─────────────────────────────────────────────

    def execute_approved(self, request_id: str, agent_key: str,
                         session_id: str) -> Any:
        """Run a call that a human approved. Every other control still applies."""
        req = self.approvals.get(request_id)
        if req is None:
            raise KeyError(f"no approval request {request_id}")
        if req.state.value != "approved":
            raise PermissionError(f"request {request_id} is {req.state.value}, not approved")

        call = ToolCall(tool=req.tool, args=req.args, agent_id=agent_key,
                        session_id=session_id)
        spec = SPECS[call.tool]
        sess = self.session(session_id)

        # Re-check the controls that approval does NOT override. A human can
        # authorise an expensive refund; they cannot authorise exfiltration or
        # override a kill switch.
        killed, why = self.killswitch.blocked(agent_key)
        if killed:
            raise GovernanceDenied(Verdict(Decision.DENY, why, control="killswitch",
                                           tool=call.tool, agent_id=agent_key))
        if sess.ratchet.blocks_egress(spec):
            raise GovernanceDenied(Verdict(Decision.DENY, sess.ratchet.explain(spec),
                                           control="dlp_ratchet", tool=call.tool,
                                           agent_id=agent_key))

        v = Verdict(Decision.ALLOW,
                    f"executed under approval {request_id} by {req.decided_by}",
                    control="approval", tool=call.tool,
                    agent_id=self.registry.get(agent_key).did)
        self.ledger.record(v, agent_key, call.args, session_id)
        sess.budget.charge(spec.unit_cost_usd)
        result = self.tools.call(call.tool, call.args)
        sess.ratchet.observe(spec, call.call_id)
        return result

    # ── introspection ───────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        return {
            "enforce": self.enforce,
            "policies": self.loaded_policies,
            "agents": self.registry.snapshot(),
            "sessions": {k: v.to_dict() for k, v in self.sessions.items()},
            "approvals": [r.to_dict() for r in self.approvals.all()],
            "killswitch": self.killswitch.to_dict(),
            "audit": self.ledger.stats(),
            "bank": {
                "refunds": self.tools.state.refunds,
                "total_refunded": self.tools.state.total_refunded(),
                "emails_sent": self.tools.state.sent_email,
            },
        }

    def reset(self) -> None:
        self.tools.reset()
        self.ledger.reset()
        self.approvals.reset()
        self.killswitch.reset()
        self.registry.reset_trust()
        self.sessions.clear()
