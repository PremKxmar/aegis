"""Executable evidence for the four toolkit findings this project reports.

These are not tests of Aegis. They are regression tests against
agent-governance-toolkit 4.1.0 itself. If a future release fixes any of
them, the corresponding test fails loudly and the README claim must be
withdrawn -- which is the point. A finding you cannot re-run is a rumour.
"""

from __future__ import annotations

import typing
import warnings

import pytest
import yaml

warnings.filterwarnings("ignore", category=DeprecationWarning)

from agent_compliance import lint_policy as agt_lint
from agentmesh import PolicyEngine
from agentmesh.governance.policy import Policy, PolicyRule

from aegis.policytool import PolicyLinter


# ── Finding 1: linter/runtime action-vocabulary drift ───────────────

def test_finding1_linter_and_runtime_disagree_on_actions():
    runtime = {a for a in typing.get_args(PolicyRule.model_fields["action"].annotation)
               if isinstance(a, str)}
    linter = set(agt_lint.KNOWN_ACTIONS)

    assert runtime == {"allow", "deny", "warn", "require_approval", "log"}
    assert linter == {"allow", "deny", "audit", "block", "escalate", "rate_limit"}

    # They overlap on two values out of six.
    assert runtime & linter == {"allow", "deny"}
    # Valid runtime actions the linter rejects (false positives):
    assert runtime - linter == {"warn", "require_approval", "log"}
    # Linter-blessed actions the runtime rejects (false negatives):
    assert linter - runtime == {"audit", "block", "escalate", "rate_limit"}


def test_finding1_false_negative_lints_clean_but_crashes_runtime(tmp_path):
    """The dangerous direction: CI passes, production fails to load policy."""
    doc = {
        "apiVersion": "governance.toolkit/v1", "version": "1.0",
        "name": "drift", "agents": ["*"], "default_action": "deny",
        "rules": [{"name": "r", "stage": "pre_tool",
                   "condition": "tool.name == 'x'", "action": "block"}],
    }
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(doc))

    # agt's linter is happy: zero errors on a policy the runtime rejects.
    lint_result = agt_lint.lint_file(str(p))
    assert lint_result.passed is True, "agt lint-policy unexpectedly failed this file"
    assert len(lint_result.errors) == 0, f"agt reported errors: {lint_result.errors}"
    assert not any("action" in m for m in map(str, lint_result.messages))

    # The runtime is not.
    with pytest.raises(Exception) as exc:
        PolicyEngine().load_yaml_file(str(p))
    assert "block" in str(exc.value)

    # Ours catches it, and derives the valid set from the runtime model.
    lint = PolicyLinter()
    lint.lint_file(p)
    codes = {f.code for f in lint.findings}
    assert "AEG020" in codes


# ── Finding 2: `scope:` does not scope ──────────────────────────────

def test_finding2_scope_global_does_not_apply_to_anyone(tmp_path):
    doc = {
        "apiVersion": "governance.toolkit/v1", "version": "1.0",
        "name": "scoped", "scope": "global", "default_action": "deny",
        "rules": [{"name": "allow-read", "stage": "pre_tool",
                   "condition": "tool.name == 'read'", "action": "allow"}],
    }
    p = tmp_path / "scoped.yaml"
    p.write_text(yaml.safe_dump(doc))

    engine = PolicyEngine()
    loaded = engine.load_yaml_file(str(p))

    # It loads and lists...
    assert loaded.name == "scoped"
    assert "scoped" in engine.list_policies()

    # ...but applies to nobody, so the rule never runs.
    assert loaded.applies_to("did:mesh:anyone") is False
    d = engine.evaluate("did:mesh:anyone", {"tool": {"name": "read"}}, stage="pre_tool")
    assert d.action == "deny"
    assert "No policies loaded" in d.reason

    # Adding the wildcard fixes it.
    doc["agents"] = ["*"]
    p2 = tmp_path / "fixed.yaml"
    p2.write_text(yaml.safe_dump(doc))
    e2 = PolicyEngine()
    e2.load_yaml_file(str(p2))
    assert e2.evaluate("did:mesh:anyone", {"tool": {"name": "read"}},
                       stage="pre_tool").action == "allow"


# ── Finding 3: the condition language has no negation ───────────────

def test_finding3_not_operator_silently_evaluates_false():
    """`not x` does not raise; it silently never matches."""
    rule = PolicyRule(name="neg", condition="not tool.egress", action="deny")

    # Should be True when egress is False, if `not` worked.
    assert rule.evaluate({"tool": {"egress": False}}) is False
    # And also False when egress is True. It is inert in both directions.
    assert rule.evaluate({"tool": {"egress": True}}) is False

    # The positive form works, which is the required workaround.
    ok = PolicyRule(name="pos", condition="tool.blocked", action="deny")
    assert ok.evaluate({"tool": {"blocked": True}}) is True
    assert ok.evaluate({"tool": {"blocked": False}}) is False


def test_finding3_quoted_boolean_never_matches():
    rule = PolicyRule(name="q", condition="tool.egress == 'True'", action="deny")
    assert rule.evaluate({"tool": {"egress": True}}) is False


def test_our_linter_catches_both_negation_traps(tmp_path):
    doc = {
        "apiVersion": "governance.toolkit/v1", "version": "1.0",
        "name": "traps", "agents": ["*"], "default_action": "deny",
        "rules": [
            {"name": "uses-not", "stage": "pre_tool",
             "condition": "not tool.egress", "action": "deny"},
            {"name": "quoted-bool", "stage": "pre_tool",
             "condition": "tool.egress == 'True'", "action": "deny"},
        ],
    }
    p = tmp_path / "traps.yaml"
    p.write_text(yaml.safe_dump(doc))
    lint = PolicyLinter()
    lint.lint_file(p)
    codes = {f.code for f in lint.findings}
    assert "AEG030" in codes  # no `not`
    assert "AEG031" in codes  # quoted boolean


# ── Finding 4: detector config keys fall back silently ──────────────

def test_finding4_misspelled_detector_key_falls_back_silently(tmp_path):
    from agent_os.prompt_injection import load_prompt_injection_config

    # The documented-looking key name `direct_override_patterns` is wrong;
    # the loader reads `direct_override`. No error is raised either way.
    wrong = tmp_path / "wrong.yaml"
    wrong.write_text(yaml.safe_dump({
        "detection_patterns": {"direct_override_patterns": ["my-custom-pattern"]}
    }))
    cfg_wrong = load_prompt_injection_config(str(wrong))
    assert "my-custom-pattern" not in cfg_wrong.direct_override_patterns, \
        "toolkit now honours the *_patterns key; finding 4 is fixed"

    right = tmp_path / "right.yaml"
    right.write_text(yaml.safe_dump({
        "detection_patterns": {"direct_override": ["my-custom-pattern"]}
    }))
    cfg_right = load_prompt_injection_config(str(right))
    assert cfg_right.direct_override_patterns == ["my-custom-pattern"]
