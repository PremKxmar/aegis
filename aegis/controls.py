"""Operational controls: spend budgets, rate limits, kill switch, approvals.

These sit alongside the policy engine rather than inside it. Policy answers
"is this action permitted in principle"; these answer "can we afford it right
now, is this agent currently allowed to run at all, and has a human signed
off".
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── budget & rate limiting ──────────────────────────────────────────

@dataclass
class Budget:
    """Per-session spend and call-rate ceiling.

    Guards OWASP ASI "unbounded consumption": an agent stuck in a loop burns
    money and API quota just as effectively as a malicious one.
    """

    max_usd: float = 0.50
    max_calls: int = 60
    window_seconds: float = 10.0
    max_calls_in_window: int = 25

    spent_usd: float = 0.0
    total_calls: int = 0
    _window: deque[float] = field(default_factory=deque)

    def check(self, cost: float) -> tuple[bool, str]:
        now = time.time()
        while self._window and now - self._window[0] > self.window_seconds:
            self._window.popleft()

        if self.spent_usd + cost > self.max_usd:
            return False, (f"budget exhausted: ${self.spent_usd:.4f} + ${cost:.4f} "
                           f"exceeds cap ${self.max_usd:.2f}")
        if self.total_calls + 1 > self.max_calls:
            return False, f"call cap reached: {self.total_calls}/{self.max_calls}"
        if len(self._window) + 1 > self.max_calls_in_window:
            return False, (f"rate limit: {len(self._window)} calls in last "
                           f"{self.window_seconds:.0f}s (max {self.max_calls_in_window})")
        return True, ""

    def charge(self, cost: float) -> None:
        self.spent_usd = round(self.spent_usd + cost, 6)
        self.total_calls += 1
        self._window.append(time.time())

    def to_dict(self) -> dict[str, Any]:
        return {
            "spent_usd": round(self.spent_usd, 4),
            "max_usd": self.max_usd,
            "pct_spent": round(100 * self.spent_usd / self.max_usd, 1) if self.max_usd else 0,
            "total_calls": self.total_calls,
            "max_calls": self.max_calls,
        }

    def reset(self) -> None:
        self.spent_usd = 0.0
        self.total_calls = 0
        self._window.clear()


# ── kill switch ─────────────────────────────────────────────────────

class RunState(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    KILLED = "killed"


class KillSwitch:
    """Fleet-wide and per-agent emergency stop.

    A killed agent is refused at the very front of the control chain, before
    policy is even consulted -- there is no rule an attacker can satisfy to
    get past it.
    """

    def __init__(self) -> None:
        self._global = RunState.RUNNING
        self._agents: dict[str, RunState] = {}
        self._log: list[dict[str, Any]] = []

    def state_of(self, agent_key: str) -> RunState:
        if self._global is not RunState.RUNNING:
            return self._global
        return self._agents.get(agent_key, RunState.RUNNING)

    def kill(self, agent_key: str | None = None, reason: str = "manual") -> None:
        self._set(agent_key, RunState.KILLED, reason)

    def pause(self, agent_key: str | None = None, reason: str = "manual") -> None:
        self._set(agent_key, RunState.PAUSED, reason)

    def resume(self, agent_key: str | None = None) -> None:
        self._set(agent_key, RunState.RUNNING, "resume")

    def _set(self, agent_key: str | None, state: RunState, reason: str) -> None:
        if agent_key is None:
            self._global = state
            if state is RunState.RUNNING:
                self._agents.clear()
        else:
            self._agents[agent_key] = state
        self._log.append({"at": time.time(), "target": agent_key or "*",
                          "state": state.value, "reason": reason})

    def blocked(self, agent_key: str) -> tuple[bool, str]:
        st = self.state_of(agent_key)
        if st is RunState.RUNNING:
            return False, ""
        scope = "fleet-wide" if self._global is not RunState.RUNNING else "agent"
        return True, f"kill switch engaged ({scope}, state={st.value})"

    def to_dict(self) -> dict[str, Any]:
        return {"global": self._global.value,
                "agents": {k: v.value for k, v in self._agents.items()},
                "log": self._log[-10:]}

    def reset(self) -> None:
        self._global = RunState.RUNNING
        self._agents.clear()
        self._log.clear()


# ── human-in-the-loop approvals ─────────────────────────────────────

class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    id: str
    agent_key: str
    tool: str
    args: dict[str, Any]
    reason: str
    approvers: list[str]
    created_at: float = field(default_factory=time.time)
    state: ApprovalState = ApprovalState.PENDING
    decided_by: str | None = None
    decided_at: float | None = None
    ttl_seconds: float = 300.0

    def expired(self) -> bool:
        return (self.state is ApprovalState.PENDING
                and time.time() - self.created_at > self.ttl_seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "agent": self.agent_key, "tool": self.tool,
            "args": self.args, "reason": self.reason, "approvers": self.approvers,
            "state": (ApprovalState.EXPIRED if self.expired() else self.state).value,
            "created_at": self.created_at, "decided_by": self.decided_by,
            "age_seconds": round(time.time() - self.created_at, 1),
        }


class ApprovalQueue:
    """Holds calls that policy gated behind a human.

    Critically, a pending request is *not* executed. The agent's call raises
    and the work stops there; approving it later replays the call explicitly.
    """

    def __init__(self) -> None:
        self._items: dict[str, ApprovalRequest] = {}

    def open(self, agent_key: str, tool: str, args: dict[str, Any],
             reason: str, approvers: list[str]) -> ApprovalRequest:
        req = ApprovalRequest(
            id=f"AP-{uuid.uuid4().hex[:8]}", agent_key=agent_key, tool=tool,
            args=dict(args), reason=reason, approvers=approvers or ["duty-officer"],
        )
        self._items[req.id] = req
        return req

    def decide(self, req_id: str, approve: bool, who: str) -> ApprovalRequest:
        req = self._items.get(req_id)
        if req is None:
            raise KeyError(f"no approval request {req_id}")
        if req.expired():
            req.state = ApprovalState.EXPIRED
            return req
        if req.state is not ApprovalState.PENDING:
            return req
        if req.approvers and who not in req.approvers:
            raise PermissionError(
                f"'{who}' is not an authorised approver for {req_id} "
                f"(need one of {req.approvers})"
            )
        req.state = ApprovalState.APPROVED if approve else ApprovalState.REJECTED
        req.decided_by = who
        req.decided_at = time.time()
        return req

    def get(self, req_id: str) -> ApprovalRequest | None:
        return self._items.get(req_id)

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self._items.values()
                if r.state is ApprovalState.PENDING and not r.expired()]

    def all(self) -> list[ApprovalRequest]:
        return list(self._items.values())

    def reset(self) -> None:
        self._items.clear()
