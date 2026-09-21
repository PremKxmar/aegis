"""aegis-policylint: a schema-accurate linter for AGT policy files.

Why this exists
---------------
The toolkit ships `agt lint-policy`, and its docs recommend it as a CI gate.
It is unsafe in that role. Its `KNOWN_ACTIONS` whitelist is a hardcoded
frozenset that has drifted from the runtime's pydantic Literal:

    linter  : allow, deny, audit, block, escalate, rate_limit
    runtime : allow, deny, warn, require_approval, log

Overlap: `allow` and `deny`. The consequences run both ways.

  FALSE POSITIVE  a valid `require_approval` rule is reported as an error,
                  so a correct policy fails CI.

  FALSE NEGATIVE  a rule using `action: block` lints clean, then raises
                  ValidationError at load time. In a fail-closed engine the
                  policy never loads and `evaluate()` returns
                  "No policies loaded (deny by default)" -- a total outage
                  that the gate you installed to prevent it waved through.

Reproduced end-to-end in tests/test_toolkit_findings.py.

This linter derives its vocabulary from the runtime model by introspection,
so it cannot drift by construction. It also catches three silent-failure
traps in the condition language that nothing else checks.
"""

from __future__ import annotations

import re
import sys
import typing
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

warnings.filterwarnings("ignore", category=DeprecationWarning)

from agentmesh.governance.policy import Policy, PolicyRule  # noqa: E402


def _literal_values(model: Any, field: str) -> set[str]:
    """Pull a Literal's members straight off the live pydantic model."""
    ann = model.model_fields[field].annotation
    args = typing.get_args(ann)
    return {a for a in args if isinstance(a, str)}


# Derived at import time from the installed runtime -- never hardcoded.
VALID_ACTIONS: set[str] = _literal_values(PolicyRule, "action")
VALID_STAGES: set[str] = _literal_values(PolicyRule, "stage")

# The context vocabulary this project's governor actually publishes. A
# condition referencing anything else silently evaluates to None/False.
KNOWN_PATHS: set[str] = {
    "tool.name", "tool.reads", "tool.writes", "tool.reads_level",
    "tool.writes_level", "tool.egress", "tool.mutating", "tool.capability",
    "tool.recipient_allowed", "tool.recipient_blocked",
    "agent.key", "agent.did", "agent.role", "agent.ring",
    "agent.trust_score", "agent.depth",
    "session.id", "session.mark", "session.mark_level", "session.tainted",
    "session.spent_usd", "session.calls", "session.refund_total_usd",
    "session.refund_count", "session.refund_total_after",
    "risk.injection", "risk.injection_detected",
    "action.type", "action.mutating", "action.egress",
    # Procedural graph position (aegis/procedure.py). Every negative is
    # published pre-computed because the condition language has no `not`.
    "procedure.stage", "procedure.current", "procedure.next_expected",
    "procedure.in_order", "procedure.out_of_order", "procedure.replay",
    "procedure.blocked_reason", "procedure.steps_done",
    "procedure.intake_complete", "procedure.intake_incomplete",
    "procedure.kyc_complete", "procedure.kyc_incomplete",
    "procedure.integrity_complete", "procedure.integrity_incomplete",
    "procedure.eligibility_complete", "procedure.eligibility_incomplete",
    "procedure.disbursement_complete",
    "procedure.notification_complete", "procedure.notification_incomplete",
    "procedure.complete", "procedure.refund_approved", "procedure.refund_refused",
    "procedure.amount_exceeds_approved", "procedure.disbursed_total",
    "procedure.approved_amount",
    # Knowledge-graph relationship answers (aegis/knowledge.py).
    "kg.subject", "kg.subject_known", "kg.subject_mismatch", "kg.subject_matches",
    "kg.recipient", "kg.recipient_owner", "kg.recipient_known",
    "kg.recipient_unknown", "kg.recipient_unrelated", "kg.recipient_related",
    "kg.hops_to_recipient", "kg.reads_restricted",
}
# `tool.args.*` is open-ended by design (per-tool arguments).
OPEN_PREFIXES = ("tool.args.",)

SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


@dataclass
class Finding:
    severity: str
    file: str
    line: int
    rule: str
    code: str
    message: str

    def format(self) -> str:
        loc = f"{self.file}:{self.line}"
        return f"{loc}: {self.severity}: [{self.code}] {self.rule}: {self.message}"


class PolicyLinter:
    """Static checks that the toolkit's own linter does not perform."""

    PATH_RE = re.compile(r"\b([a-z_]+(?:\.[a-z_0-9]+)+)\b")
    COMPARATOR_RE = re.compile(r"(>=|<=|==|!=|>|<)")

    def __init__(self, known_paths: set[str] | None = None):
        self.known_paths = known_paths or KNOWN_PATHS
        self.findings: list[Finding] = []

    # ── entry points ────────────────────────────────────────────────

    def lint_dir(self, directory: str | Path) -> list[Finding]:
        for path in sorted(Path(directory).glob("*.yaml")):
            self.lint_file(path)
        return self.findings

    def lint_file(self, path: str | Path) -> list[Finding]:
        p = Path(path)
        raw = p.read_text()
        lines = raw.splitlines()

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            self._add("error", p.name, 1, "<file>", "AEG001", f"invalid YAML: {exc}")
            return self.findings

        if not isinstance(data, dict):
            self._add("error", p.name, 1, "<file>", "AEG001", "policy must be a mapping")
            return self.findings

        self._check_document(p.name, data, lines)
        for rule in data.get("rules") or []:
            if isinstance(rule, dict):
                self._check_rule(p.name, rule, lines)

        # Final authority: does the runtime actually accept it?
        try:
            Policy(**data)
        except Exception as exc:
            first = str(exc).splitlines()[0]
            self._add("error", p.name, 1, "<file>", "AEG002",
                      f"runtime rejects this policy: {first}")
        return self.findings

    # ── document-level ──────────────────────────────────────────────

    def _check_document(self, fname: str, data: dict, lines: list[str]) -> None:
        name = data.get("name", "<unnamed>")

        # THE trap: `scope: global` looks like it targets everyone. It does
        # not. Policy.applies_to() only matches `agent`, membership in
        # `agents`, or the "*" wildcard. Without one of those the policy loads,
        # lists, and is never consulted -- every evaluate() returns
        # "No policies loaded (deny by default)".
        has_target = bool(data.get("agent")) or bool(data.get("agents"))
        if not has_target:
            self._add("error", fname, self._find_line(lines, "name:"), name, "AEG010",
                      "policy targets no agents: set `agents: [\"*\"]` or `agent:`. "
                      "`scope:` is NOT used for matching and this policy will "
                      "never be evaluated.")

        if "version" not in data:
            self._add("warning", fname, 1, name, "AEG011",
                      "missing `version` (agt lint-policy treats this as an error)")

        if data.get("default_action") == "allow":
            self._add("warning", fname, self._find_line(lines, "default_action:"),
                      name, "AEG012",
                      "default_action: allow is fail-open; prefer `deny`")

    # ── rule-level ──────────────────────────────────────────────────

    def _check_rule(self, fname: str, rule: dict, lines: list[str]) -> None:
        name = rule.get("name", "<unnamed>")
        line = self._find_line(lines, f"name: {name}")

        action = rule.get("action")
        if action is not None and action not in VALID_ACTIONS:
            self._add("error", fname, line, name, "AEG020",
                      f"invalid action '{action}'. Runtime accepts: "
                      f"{sorted(VALID_ACTIONS)}")

        stage = rule.get("stage")
        if stage is not None and stage not in VALID_STAGES:
            self._add("error", fname, line, name, "AEG021",
                      f"invalid stage '{stage}'. Runtime accepts: {sorted(VALID_STAGES)}")

        if action == "require_approval" and not rule.get("approvers"):
            self._add("warning", fname, line, name, "AEG022",
                      "require_approval without `approvers` falls back to a "
                      "default approver; name them explicitly")

        cond = rule.get("condition")
        if not cond:
            self._add("error", fname, line, name, "AEG023", "missing `condition`")
            return
        self._check_condition(fname, name, str(cond), line)

    # ── condition language ──────────────────────────────────────────

    def _check_condition(self, fname: str, rule: str, cond: str, line: int) -> None:
        # Trap 1: there is no `not` operator. `not x` does not raise -- it
        # falls through to the bare-boolean branch, looks up a path literally
        # named "not x", finds nothing, and returns False. The rule silently
        # never fires.
        if re.search(r"(^|\s)not\s+", cond):
            self._add("error", fname, line, rule, "AEG030",
                      "`not` is not supported by the condition evaluator. It "
                      "silently evaluates to False, so this rule will NEVER "
                      "fire. Pre-compute a positive boolean in the context "
                      "instead (e.g. `tool.recipient_blocked`).")

        # Trap 2: comparing against a quoted boolean never matches, because
        # the evaluator compares the raw value to the *string*.
        if re.search(r"==\s*['\"](True|False|true|false)['\"]", cond):
            self._add("error", fname, line, rule, "AEG031",
                      "comparing to a quoted boolean never matches (bool != str). "
                      "Use the bare path for truthiness: `tool.flag`.")

        # Trap 3: numeric comparison only accepts a bare number on the right.
        for m in re.finditer(r"(>=|<=|>|<)\s*['\"]([^'\"]+)['\"]", cond):
            self._add("error", fname, line, rule, "AEG032",
                      f"numeric comparison against quoted value '{m.group(2)}' "
                      f"never matches; drop the quotes")

        # Trap 4: `in [...]` membership is string-only after stripping quotes,
        # so an int-valued path never matches.
        for m in re.finditer(r"([a-z_.]+)\s+in\s+\[", cond):
            path = m.group(1)
            if path.endswith("_level") or path.endswith("ring"):
                self._add("warning", fname, line, rule, "AEG033",
                          f"`{path}` is numeric but `in [...]` compares strings; "
                          f"use a range comparison instead")

        # Unknown context paths: silently None -> condition never true.
        for m in self.PATH_RE.finditer(cond):
            path = m.group(1)
            if path in self.known_paths:
                continue
            if any(path.startswith(pre) for pre in OPEN_PREFIXES):
                continue
            if re.match(r"^\d", path):
                continue
            self._add("warning", fname, line, rule, "AEG034",
                      f"unknown context path `{path}`; it resolves to None and "
                      f"the condition can never be true. Known roots: "
                      f"tool.*, agent.*, session.*, risk.*, action.*")

    # ── plumbing ────────────────────────────────────────────────────

    def _add(self, severity: str, fname: str, line: int, rule: str,
             code: str, message: str) -> None:
        self.findings.append(Finding(severity, fname, line, rule, code, message))

    @staticmethod
    def _find_line(lines: list[str], needle: str) -> int:
        for i, ln in enumerate(lines, 1):
            if needle in ln:
                return i
        return 1

    # ── reporting ───────────────────────────────────────────────────

    def report(self) -> tuple[str, int]:
        if not self.findings:
            return "aegis-policylint: no issues found.", 0
        ordered = sorted(self.findings,
                         key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
        out = [f.format() for f in ordered]
        errors = sum(1 for f in self.findings if f.severity == "error")
        warns = sum(1 for f in self.findings if f.severity == "warning")
        out.append("")
        out.append(f"{errors} error(s), {warns} warning(s)")
        return "\n".join(out), (1 if errors else 0)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    target = args[0] if args else "policies"
    linter = PolicyLinter()
    p = Path(target)
    if p.is_dir():
        linter.lint_dir(p)
    else:
        linter.lint_file(p)
    text, code = linter.report()
    print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
