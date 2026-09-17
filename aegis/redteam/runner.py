"""Runs the attack catalogue against both configurations and scores it.

Each attack gets a *fresh* governor so results cannot contaminate each other
(ATT-14 engages the kill switch; ATT-15 tampers with the ledger). This costs
a little startup time and buys reproducibility.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..governor import Governor
from .attacks import ATTACKS, Attack, AttackResult


@dataclass
class SuiteResult:
    mode: str                       # "governed" | "ungoverned"
    results: list[AttackResult] = field(default_factory=list)
    wall_ms: float = 0.0

    @property
    def succeeded(self) -> int:
        return sum(1 for r in self.results if r.succeeded)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def success_rate(self) -> float:
        return round(100.0 * self.succeeded / self.total, 1) if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "succeeded": self.succeeded,
            "total": self.total,
            "success_rate": self.success_rate,
            "wall_ms": round(self.wall_ms, 2),
            "results": [r.to_dict() for r in self.results],
        }


@dataclass
class Comparison:
    governed: SuiteResult
    ungoverned: SuiteResult
    audit: dict[str, Any] = field(default_factory=dict)

    def rows(self) -> list[dict[str, Any]]:
        by_id = {r.id: r for r in self.ungoverned.results}
        out = []
        for g in self.governed.results:
            u = by_id.get(g.id)
            out.append({
                "id": g.id, "name": g.name, "owasp": g.owasp,
                "ungoverned": bool(u and u.succeeded),
                "governed": g.succeeded,
                "ungoverned_harm": u.harm if u else "",
                "governed_harm": g.harm,
                "blocked_by": g.blocked_by,
                "note": g.note,
            })
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "governed": self.governed.to_dict(),
            "ungoverned": self.ungoverned.to_dict(),
            "rows": self.rows(),
            "audit": self.audit,
            "headline": {
                "ungoverned_success_rate": self.ungoverned.success_rate,
                "governed_success_rate": self.governed.success_rate,
                "attacks_neutralised": self.ungoverned.succeeded - self.governed.succeeded,
                "total_attacks": self.governed.total,
            },
        }


def run_suite(mode: str, attacks: list[Attack] | None = None,
              on_result: Callable[[AttackResult], None] | None = None,
              ) -> tuple[SuiteResult, dict[str, Any]]:
    """Run every attack in `mode`. Returns (results, last governor's audit)."""
    catalogue = attacks or ATTACKS
    suite = SuiteResult(mode=mode)
    t0 = time.perf_counter()
    audit: dict[str, Any] = {}

    for atk in catalogue:
        gov = Governor(enforce=(mode == "governed"))
        try:
            res = atk.run(gov)
        except Exception as exc:  # an attack harness bug must not kill the run
            res = AttackResult(id=atk.id, name=atk.name, owasp=atk.owasp,
                               succeeded=False, harm=f"harness error: {exc}",
                               note="EXCLUDED from scoring")
        suite.results.append(res)
        if on_result:
            on_result(res)
        if mode == "governed":
            audit = gov.ledger.stats()

    suite.wall_ms = (time.perf_counter() - t0) * 1000
    return suite, audit


def compare(on_result: Callable[[str, AttackResult], None] | None = None) -> Comparison:
    """The headline number: same 15 attacks, with and without governance."""
    un, _ = run_suite("ungoverned",
                      on_result=(lambda r: on_result("ungoverned", r)) if on_result else None)
    gov, audit = run_suite("governed",
                           on_result=(lambda r: on_result("governed", r)) if on_result else None)
    return Comparison(governed=gov, ungoverned=un, audit=audit)
