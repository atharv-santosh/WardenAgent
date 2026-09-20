"""Behavioral tests for human approval gates."""

from __future__ import annotations

from agent_sandbox.approval import ApprovalDecision, ApprovalGate, auto_approve, auto_deny
from agent_sandbox.events import EventLog
from agent_sandbox.taint import Tainted


def test_auto_deny_denies() -> None:
    log = EventLog()
    gate = ApprovalGate(auto_deny, log)
    decision = gate.request("send_email", {"to": "x@corp.example"}, rule="tool_allow:send_email")
    assert decision.approved is False


def test_auto_approve_approves() -> None:
    log = EventLog()
    gate = ApprovalGate(auto_approve, log)
    decision = gate.request("send_email", {"to": "x@corp.example"}, rule="tool_allow:send_email")
    assert decision.approved is True


def test_request_emits_human_gate_events_with_request_and_decision_phases() -> None:
    log = EventLog()
    gate = ApprovalGate(auto_deny, log)
    gate.request("delete_file", {"path": "/workspace/scratch/x"}, rule="tool_allow:delete_file")
    gate_events = log.filter_type("human_gate")
    assert len(gate_events) == 2
    assert gate_events[0].payload["phase"] == "request"
    assert gate_events[1].payload["phase"] == "decision"
    assert gate_events[1].payload["approved"] is False


def test_request_includes_provenance_chain_in_the_request_event() -> None:
    log = EventLog()
    gate = ApprovalGate(auto_deny, log)
    tainted = Tainted.untrusted("body text", origin="fetch_url(https://evil.example)")
    gate.request("send_email", {"body": "body text"}, rule="tool_allow:send_email", tainted_args={"body": tainted})
    request_event = log.filter_type("human_gate")[0]
    assert "fetch_url" in request_event.payload["provenance"]["body"]


def test_history_records_every_decision() -> None:
    log = EventLog()

    def custom(request):
        return ApprovalDecision(approved=True, reason="looks fine", decided_by="reviewer@corp.example")

    gate = ApprovalGate(custom, log)
    gate.request("grant_admin", {"user": "new@corp.example"}, rule="tool_allow:grant_admin")
    assert len(gate.history) == 1
    req, decision = gate.history[0]
    assert req.tool == "grant_admin"
    assert decision.decided_by == "reviewer@corp.example"
