"""Core domain types for the Aegis governed back-office.

These are deliberately framework-neutral: the governance layer only ever sees
a `ToolCall` and returns a `Verdict`, so the same enforcement path works for
in-process tools, MCP tools, or a remote agent framework.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any


class Sensitivity(IntEnum):
    """Data sensitivity lattice. Higher = more restricted.

    The ordering matters: the DLP ratchet only ever moves *up* this lattice,
    which is what makes it a ratchet rather than a toggle.
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    PII = 3
    PCI = 4

    @classmethod
    def parse(cls, raw: str | int | None) -> "Sensitivity":
        if raw is None:
            return cls.PUBLIC
        if isinstance(raw, int):
            return cls(raw)
        return cls[str(raw).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


class Ring(IntEnum):
    """Privilege rings, mirroring `agent_os.ProtectionRing`.

    Ring 0 is the governance kernel itself; agent code never runs there.
    Agents that read untrusted input are pinned to Ring 3.
    """

    KERNEL = 0
    DRIVERS = 1
    SERVICES = 2
    USER = 3


class Decision(str, Enum):
    """The five verdicts the Agent Control Specification defines."""

    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    LOG = "log"

    @property
    def permits(self) -> bool:
        """Whether execution may proceed *without* further gating."""
        return self in (Decision.ALLOW, Decision.WARN, Decision.LOG)


class Stage(str, Enum):
    """Lifecycle interception points, matching the toolkit's stage literals."""

    PRE_INPUT = "pre_input"
    PRE_TOOL = "pre_tool"
    POST_TOOL = "post_tool"
    PRE_OUTPUT = "pre_output"


@dataclass(frozen=True)
class ToolSpec:
    """Static declaration of a tool's governance-relevant properties.

    `reads` / `writes` describe the sensitivity the tool *can* touch; the
    policy layer uses these rather than trusting the agent's own claim.
    """

    name: str
    description: str
    reads: Sensitivity = Sensitivity.PUBLIC
    writes: Sensitivity = Sensitivity.PUBLIC
    egress: bool = False           # sends data outside the trust boundary
    mutating: bool = False         # changes state (money, records)
    unit_cost_usd: float = 0.0
    required_capability: str = ""

    def as_context(self) -> dict[str, Any]:
        return {
            "reads": self.reads.label,
            "writes": self.writes.label,
            "reads_level": int(self.reads),
            "writes_level": int(self.writes),
            "egress": self.egress,
            "mutating": self.mutating,
            "capability": self.required_capability,
        }


@dataclass
class ToolCall:
    """A single attempted action, the atomic unit of governance."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    agent_id: str = ""
    session_id: str = ""
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)
    # Free-text that originated outside the trust boundary (ticket bodies,
    # tool output). Anything in here is treated as hostile by default.
    untrusted_text: str = ""

    def summary(self) -> str:
        arg_preview = ", ".join(f"{k}={v!r}" for k, v in list(self.args.items())[:3])
        if len(arg_preview) > 90:
            arg_preview = arg_preview[:87] + "..."
        return f"{self.tool}({arg_preview})"


@dataclass
class Verdict:
    """The governance layer's answer, plus everything needed to audit it."""

    decision: Decision
    reason: str
    call_id: str = ""
    agent_id: str = ""
    tool: str = ""
    matched_rule: str | None = None
    policy_name: str | None = None
    approvers: list[str] = field(default_factory=list)
    # Which control produced this verdict — policy, ratchet, killswitch, ...
    control: str = "policy"
    latency_ms: float = 0.0
    # Populated when a control rewrote the arguments instead of denying.
    transformed_args: dict[str, Any] | None = None
    context_snapshot: dict[str, Any] = field(default_factory=dict)

    @property
    def permits(self) -> bool:
        return self.decision.permits

    @property
    def blocked(self) -> bool:
        return not self.permits

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "decision": self.decision.value,
            "permits": self.permits,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "policy_name": self.policy_name,
            "approvers": list(self.approvers),
            "control": self.control,
            "latency_ms": round(self.latency_ms, 4),
            "transformed": self.transformed_args is not None,
        }


class GovernanceDenied(Exception):
    """Raised when a tool call is refused. Carries the verdict for audit."""

    def __init__(self, verdict: Verdict):
        self.verdict = verdict
        super().__init__(f"[{verdict.control}] {verdict.decision.value}: {verdict.reason}")


class ApprovalRequired(GovernanceDenied):
    """Raised when a call is held pending human sign-off."""
