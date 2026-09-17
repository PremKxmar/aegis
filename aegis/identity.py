"""Zero-trust identity, delegation chains and trust scoring.

Every agent in Aegis has a cryptographic DID that traces back to an
accountable human sponsor. Capabilities flow *down* the delegation chain and
can only ever narrow -- `agentmesh` enforces that a parent cannot delegate a
capability it does not itself hold.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Any

warnings.filterwarnings("ignore", category=DeprecationWarning)

from agentmesh import AgentIdentity, TrustTracker  # noqa: E402

from .domain import Ring  # noqa: E402

SPONSOR = "ops-lead@aegisbank.test"
ORG = "AegisBank"

# Trust below this and the agent is considered untrustworthy; policy rules key
# off `agent.trust_score` so this threshold is enforced declaratively.
TRUST_QUARANTINE = 0.35


@dataclass
class AgentRecord:
    """An agent's identity plus the runtime state governance cares about."""

    key: str                      # stable short name, e.g. "triage"
    identity: AgentIdentity
    ring: Ring
    role: str
    description: str
    parent_key: str | None = None
    # Per-session mutable state lives in SessionState, not here.

    @property
    def did(self) -> str:
        return str(self.identity.did)

    @property
    def capabilities(self) -> list[str]:
        return sorted(self.identity.get_effective_capabilities())

    def has(self, capability: str) -> bool:
        return self.identity.has_capability(capability)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "did": self.did,
            "name": self.identity.name,
            "role": self.role,
            "description": self.description,
            "ring": int(self.ring),
            "ring_name": self.ring.name,
            "capabilities": self.capabilities,
            "parent": self.parent_key,
            "delegation_depth": self.identity.delegation_depth,
            "sponsor": self.identity.sponsor_email,
        }


class AgentRegistry:
    """Builds and owns the four-agent delegation tree.

    The tree is deliberately a *chain*, not a flat list:

        human sponsor
          └── triage      (Ring 3, reads untrusted email)
                └── analyst   (Ring 2, reads customer records)
                      ├── payments  (Ring 1, moves money)
                      └── comms     (Ring 2, external egress)

    Because capabilities narrow at each hop, a prompt-injected triage agent
    cannot mint itself refund rights: the delegation call would raise.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentRecord] = {}
        self._trust = TrustTracker(initial_score=0.75, reward=0.01, penalty=0.12)
        self._build()

    # ── construction ────────────────────────────────────────────────

    def _build(self) -> None:
        # The root holds the union of every capability in the system; each
        # delegation hands out a strict subset.
        root = AgentIdentity.create(
            name="aegis-root",
            sponsor=SPONSOR,
            organization=ORG,
            description="Root identity sponsored by a verified human operator.",
            capabilities=[
                "read:tickets",
                "read:customer",
                "read:pii",
                "write:refund",
                "send:email",
                "read:policy",
            ],
        )
        self._agents["root"] = AgentRecord(
            key="root", identity=root, ring=Ring.KERNEL, role="root",
            description="Sponsor-backed root identity. Never executes tools.",
        )

        triage = root.delegate(
            name="triage-agent",
            capabilities=["read:tickets", "read:customer"],
            description="Reads inbound support tickets. Untrusted input surface.",
        )
        self._register("triage", triage, Ring.USER, "triage",
                       "Classifies inbound customer tickets.", "root")

        analyst = triage.delegate(
            name="analyst-agent",
            capabilities=["read:customer", "read:tickets"],
            description="Looks up customer records. Read-only.",
        )
        self._register("analyst", analyst, Ring.SERVICES, "analyst",
                       "Retrieves account and transaction history.", "triage")

        # Payments and comms are delegated from the *root*, not from analyst:
        # they need capabilities analyst does not have, and delegation cannot
        # widen. This models a real approval boundary.
        payments = root.delegate(
            name="payments-agent",
            capabilities=["write:refund", "read:customer", "read:pii"],
            description="Issues refunds. Highest blast radius.",
        )
        self._register("payments", payments, Ring.DRIVERS, "payments",
                       "Issues refunds and adjustments.", "root")

        comms = root.delegate(
            name="comms-agent",
            capabilities=["send:email", "read:customer"],
            description="Sends customer-facing email. Egress surface.",
        )
        self._register("comms", comms, Ring.SERVICES, "comms",
                       "Drafts and sends customer replies.", "root")

    def _register(self, key: str, identity: AgentIdentity, ring: Ring,
                  role: str, description: str, parent: str) -> None:
        self._agents[key] = AgentRecord(
            key=key, identity=identity, ring=ring, role=role,
            description=description, parent_key=parent,
        )

    # ── lookup ──────────────────────────────────────────────────────

    def get(self, key: str) -> AgentRecord:
        try:
            return self._agents[key]
        except KeyError:
            raise KeyError(f"unknown agent '{key}'") from None

    def by_did(self, did: str) -> AgentRecord | None:
        return next((a for a in self._agents.values() if a.did == did), None)

    def all(self) -> list[AgentRecord]:
        return [a for a in self._agents.values() if a.key != "root"]

    # ── trust ───────────────────────────────────────────────────────

    def trust(self, key: str) -> float:
        return round(self._trust.get_score(self.get(key).did), 4)

    def record(self, key: str, action: str, success: bool) -> float:
        """Feed an outcome into the trust score.

        A denied action is a trust *penalty*: an agent that keeps trying
        forbidden things becomes progressively less trusted, and policy can
        quarantine it without anyone writing new rules.
        """
        rec = self.get(key)
        return self._trust.record_interaction(
            rec.did, peer_id="aegis-governor", action=action, success=success,
        )

    def is_quarantined(self, key: str) -> bool:
        return self.trust(key) < TRUST_QUARANTINE

    def reset_trust(self) -> None:
        # TrustTracker.reset() is per-agent, so clear each DID we own.
        for a in self._agents.values():
            try:
                self._trust.reset(a.did)
            except TypeError:  # older signature took no argument
                self._trust.reset()
                break

    # ── proof that escalation is impossible ─────────────────────────

    def attempt_escalation(self, key: str, capability: str) -> tuple[bool, str]:
        """Try to self-grant `capability` by delegating a new child.

        Used by the red-team suite. Returns (succeeded, detail). The library
        raises ValueError when the parent lacks the capability, so this is a
        structural guarantee rather than a policy rule we could forget.
        """
        rec = self.get(key)
        try:
            child = rec.identity.delegate(
                name=f"{rec.identity.name}-escalated", capabilities=[capability],
            )
            return True, f"ESCALATED: minted {child.did} with {capability}"
        except Exception as exc:  # ValueError from agentmesh
            return False, f"{type(exc).__name__}: {exc}"

    def snapshot(self) -> list[dict[str, Any]]:
        out = []
        for a in self.all():
            d = a.to_dict()
            d["trust_score"] = self.trust(a.key)
            d["quarantined"] = self.is_quarantined(a.key)
            out.append(d)
        return out
