"""Human approval gates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from agent_sandbox.events import EventLog
from agent_sandbox.taint import Tainted


@dataclass(slots=True)
class ApprovalRequest:
    """A structured request for a human to approve or deny a tool call."""

    tool: str
    args: dict[str, Any]
    rule: str
    provenance: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "args": self.args,
            "rule": self.rule,
            "provenance": self.provenance,
        }


@dataclass(slots=True)
class ApprovalDecision:
    approved: bool
    reason: str
    decided_by: str


ApprovalCallback = Callable[[ApprovalRequest], ApprovalDecision]


def auto_deny(request: ApprovalRequest) -> ApprovalDecision:
    """Safe default callback: deny everything. Used when no human is attached."""
    return ApprovalDecision(approved=False, reason="no approver attached; fail closed", decided_by="system")


def auto_approve(request: ApprovalRequest) -> ApprovalDecision:
    """Callback that approves everything -- for tests exercising the happy path only."""
    return ApprovalDecision(approved=True, reason="auto-approved (test/demo callback)", decided_by="test-harness")


class ApprovalGate:
    """Suspends the agent loop for a human decision and logs the outcome."""

    def __init__(self, callback: ApprovalCallback, event_log: EventLog) -> None:
        self.callback = callback
        self.event_log = event_log
        self.history: list[tuple[ApprovalRequest, ApprovalDecision]] = []

    def request(
        self,
        tool: str,
        args: dict[str, Any],
        rule: str,
        tainted_args: dict[str, Tainted] | None = None,
    ) -> ApprovalDecision:
        provenance = {
            name: t.chain_description() for name, t in (tainted_args or {}).items()
        }
        req = ApprovalRequest(tool=tool, args=args, rule=rule, provenance=provenance)
        self.event_log.emit("human_gate", {"phase": "request", **req.to_dict()})
        decision = self.callback(req)
        self.event_log.emit(
            "human_gate",
            {
                "phase": "decision",
                "tool": tool,
                "approved": decision.approved,
                "reason": decision.reason,
                "decided_by": decision.decided_by,
            },
        )
        self.history.append((req, decision))
        return decision
