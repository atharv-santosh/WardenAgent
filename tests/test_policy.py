"""Behavioral tests for the declarative policy engine."""

from __future__ import annotations

import pytest

from agent_sandbox.policy import Policy, PolicyEngine, PolicyError

SAMPLE_POLICY = """
default: deny
tools:
  fetch_url:
    allow: true
    network:
      hosts: [docs.trusted.example]
      schemes: [https]
    max_calls: 2
  read_file:
    allow: true
    args:
      path:
        type: path_jail
        roots: [/workspace/docs]
  send_email:
    allow: true
    sink: true
    requires_approval: true
    args:
      to:
        type: string
        pattern: "^[^@]+@[^@]+\\\\.[^@]+$"
  run_shell:
    allow: false
budgets:
  max_total_calls: 5
"""


def _engine() -> PolicyEngine:
    return PolicyEngine(Policy.from_yaml(SAMPLE_POLICY))


def test_unlisted_tool_is_denied_by_default() -> None:
    decision = _engine().evaluate("delete_everything", {})
    assert decision.allow is False
    assert decision.rule.startswith("default:")


def test_explicitly_disallowed_tool_is_denied() -> None:
    decision = _engine().evaluate("run_shell", {"cmd": "rm -rf /"})
    assert decision.allow is False


def test_allowed_tool_with_valid_args_is_permitted() -> None:
    decision = _engine().evaluate("fetch_url", {"url": "https://docs.trusted.example/page"})
    assert decision.allow is True
    assert decision.rule == "tool_allow:fetch_url"


def test_network_allowlist_rejects_unlisted_host() -> None:
    decision = _engine().evaluate("fetch_url", {"url": "https://evil.example/page"})
    assert decision.allow is False
    assert "network_allowlist" in decision.rule


def test_network_allowlist_rejects_subdomain_confusion() -> None:
    decision = _engine().evaluate("fetch_url", {"url": "https://docs.trusted.example.evil.example/page"})
    assert decision.allow is False


def test_network_allowlist_rejects_scheme_downgrade() -> None:
    decision = _engine().evaluate("fetch_url", {"url": "http://docs.trusted.example/page"})
    assert decision.allow is False


def test_network_allowlist_rejects_ip_literal() -> None:
    decision = _engine().evaluate("fetch_url", {"url": "https://198.51.100.4/page"})
    assert decision.allow is False


def test_path_jail_rejects_traversal() -> None:
    decision = _engine().evaluate("read_file", {"path": "/workspace/docs/../../etc/passwd"})
    assert decision.allow is False
    assert "arg_shape" in decision.rule


def test_path_jail_accepts_path_inside_root() -> None:
    decision = _engine().evaluate("read_file", {"path": "/workspace/docs/report.txt"})
    assert decision.allow is True


def test_arg_pattern_rejects_malformed_recipient() -> None:
    decision = _engine().evaluate("send_email", {"to": "not-an-email"})
    assert decision.allow is False


def test_requires_approval_flag_is_surfaced_on_allow() -> None:
    decision = _engine().evaluate("send_email", {"to": "ops@corp.example"})
    assert decision.allow is True
    assert decision.requires_approval is True


def test_per_tool_call_budget_enforced() -> None:
    engine = _engine()
    engine.evaluate("fetch_url", {"url": "https://docs.trusted.example/a"})
    engine.evaluate("fetch_url", {"url": "https://docs.trusted.example/b"})
    decision = engine.evaluate("fetch_url", {"url": "https://docs.trusted.example/c"})
    assert decision.allow is False
    assert "budget" in decision.rule


def test_total_call_budget_enforced() -> None:
    engine = _engine()
    for _ in range(5):
        engine.evaluate("read_file", {"path": "/workspace/docs/x.txt"})
    decision = engine.evaluate("read_file", {"path": "/workspace/docs/y.txt"})
    assert decision.allow is False
    assert decision.rule == "budget:max_total_calls"


def test_invalid_yaml_raises_policy_error() -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml("default: [not, a, mapping")


def test_invalid_default_value_raises_policy_error() -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml("default: maybe\ntools: {}\n")


def test_taint_flow_untouched_by_evaluate_allows_non_sink_tools() -> None:
    engine = _engine()
    assert engine.is_sink("fetch_url") is False
    assert engine.is_sink("send_email") is True
