"""Tamper-evident audit: hash-chained decision records + offline receipts.

Every verdict -- allow *and* deny -- becomes an `AuditEntry` linked to its
predecessor by hash. Editing any record after the fact breaks the chain, and
`verify()` reports exactly which entry was altered.

A "Decision BOM" is the exportable bundle an auditor actually wants: the
verdict, the rule that produced it, the policy version, and a Merkle proof
that the record belongs to the chain.
"""

from __future__ import annotations

import hashlib
import json
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore", category=DeprecationWarning)

from agentmesh import AuditChain, AuditEntry  # noqa: E402

from .domain import Verdict  # noqa: E402


def _hash_args(args: dict[str, Any]) -> str:
    """Hash arguments rather than storing them.

    Audit records outlive incidents and often leave the security boundary, so
    they must not themselves become a PII leak. The hash still proves *which*
    arguments were used if you have the original.
    """
    blob = json.dumps(args, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class DecisionRecord:
    """Flattened, exportable view of one governance decision."""

    seq: int
    entry_id: str
    ts: float
    agent_did: str
    agent_key: str
    tool: str
    decision: str
    control: str
    reason: str
    matched_rule: str | None
    policy_name: str | None
    policy_version: str
    args_hash: str
    session_id: str
    latency_ms: float
    entry_hash: str
    previous_hash: str | None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class AuditLedger:
    """Hash-chained ledger of every decision the governor made."""

    POLICY_VERSION = "aegis-policies/1.0.0"

    def __init__(self) -> None:
        self._chain = AuditChain()
        self._entries: list[AuditEntry] = []
        self._records: list[DecisionRecord] = []

    # ── writing ─────────────────────────────────────────────────────

    def record(self, verdict: Verdict, agent_key: str, args: dict[str, Any],
               session_id: str) -> DecisionRecord:
        entry = AuditEntry(
            event_type="tool_call",
            agent_did=verdict.agent_id or "did:mesh:unknown",
            action=verdict.tool or "unknown",
            outcome=verdict.decision.value,
            policy_decision=verdict.decision.value,
            matched_rule=verdict.matched_rule,
            policy_version=self.POLICY_VERSION,
            arguments_hash=_hash_args(args),
            session_id=session_id,
            resource=verdict.tool,
            data={"reason": verdict.reason, "control": verdict.control,
                  "agent": agent_key, "latency_ms": round(verdict.latency_ms, 4)},
        )
        self._chain.add_entry(entry)
        self._entries.append(entry)

        rec = DecisionRecord(
            seq=len(self._entries) - 1,
            entry_id=str(entry.entry_id),
            ts=time.time(),
            agent_did=entry.agent_did,
            agent_key=agent_key,
            tool=verdict.tool,
            decision=verdict.decision.value,
            control=verdict.control,
            reason=verdict.reason,
            matched_rule=verdict.matched_rule,
            policy_name=verdict.policy_name,
            policy_version=self.POLICY_VERSION,
            args_hash=entry.arguments_hash,
            session_id=session_id,
            latency_ms=round(verdict.latency_ms, 4),
            entry_hash=entry.entry_hash or "",
            previous_hash=entry.previous_hash,
        )
        self._records.append(rec)
        return rec

    # ── reading ─────────────────────────────────────────────────────

    def verify(self) -> tuple[bool, str | None]:
        """Re-walk the chain. Returns (intact, first_broken_entry)."""
        return self._chain.verify_chain()

    def root_hash(self) -> str | None:
        return self._chain.get_root_hash()

    def records(self, limit: int | None = None) -> list[DecisionRecord]:
        return self._records[-limit:] if limit else list(self._records)

    def denials(self) -> list[DecisionRecord]:
        return [r for r in self._records if r.decision != "allow"]

    def stats(self) -> dict[str, Any]:
        by_decision: dict[str, int] = {}
        by_control: dict[str, int] = {}
        for r in self._records:
            by_decision[r.decision] = by_decision.get(r.decision, 0) + 1
            by_control[r.control] = by_control.get(r.control, 0) + 1
        lat = [r.latency_ms for r in self._records] or [0.0]
        lat_sorted = sorted(lat)
        return {
            "total": len(self._records),
            "by_decision": by_decision,
            "by_control": by_control,
            "latency_ms": {
                "mean": round(sum(lat) / len(lat), 4),
                "p50": round(lat_sorted[len(lat_sorted) // 2], 4),
                "p99": round(lat_sorted[min(len(lat_sorted) - 1,
                                            int(len(lat_sorted) * 0.99))], 4),
                "max": round(max(lat), 4),
            },
            "root_hash": self.root_hash(),
            "chain_intact": self.verify()[0],
        }

    # ── evidence export ─────────────────────────────────────────────

    def decision_bom(self, seq: int) -> dict[str, Any]:
        """Everything an auditor needs to re-justify one decision offline."""
        rec = self._records[seq]
        entry = self._entries[seq]
        proof = self._chain.get_proof(str(entry.entry_id))
        return {
            "decision": rec.to_dict(),
            "inclusion_proof": proof,
            "root_hash": self.root_hash(),
            "chain_intact": self.verify()[0],
            "verifier": "aegis.audit.verify_receipt",
        }

    def tamper_probe(self) -> dict[str, Any]:
        """Deliberately corrupt a record, prove detection, then restore.

        Used live in the demo: it is one thing to claim the log is
        tamper-evident, another to show the alarm firing on stage.
        """
        if not self._entries:
            return {"ran": False, "reason": "empty ledger"}
        before_ok, _ = self.verify()
        target = self._entries[0]
        original = target.action
        # Forge to a guaranteed-different value. A fixed literal is a bug:
        # if the entry already held it, nothing changes and the probe
        # reports "tampering undetected" when nothing was tampered with.
        target.action = f"{original}__forged"
        after_ok, broken_at = self.verify()
        target.action = original                    # restore
        restored_ok, _ = self.verify()
        return {
            "ran": True,
            "before": before_ok,
            "after_tamper": after_ok,
            "detected_at": broken_at,
            "restored": restored_ok,
            "forged_field": "action",
        }

    def export(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        intact, broken = self.verify()
        payload = {
            "generated_at": time.time(),
            "policy_version": self.POLICY_VERSION,
            "root_hash": self.root_hash(),
            "chain_intact": intact,
            "broken_at": broken,
            "entry_count": len(self._records),
            "stats": self.stats(),
            "decisions": [r.to_dict() for r in self._records],
        }
        p.write_text(json.dumps(payload, indent=2, default=str))
        return p

    def reset(self) -> None:
        self._chain = AuditChain()
        self._entries.clear()
        self._records.clear()
