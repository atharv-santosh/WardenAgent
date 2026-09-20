"""JSON-serialization helpers for library dataclasses the web layer streams out over SSE / returns from REST endpoints."""

from __future__ import annotations

from typing import Any

from agent_sandbox.agent import RunResult
from agent_sandbox.llm_sim import ToolCallIntent
from agent_sandbox.quarantine import Digest

SINK_TOOLS = {"send_email", "http_post", "delete_file", "grant_admin", "run_shell"}


def intent_to_dict(intent: ToolCallIntent | None) -> dict[str, Any] | None:
    if intent is None:
        return None
    return {
        "tool": intent.tool,
        "args": intent.args,
        "triggered_by": intent.triggered_by,
        "source": intent.source,
        "arg_sources": intent.arg_sources,
        "is_sink": intent.tool in SINK_TOOLS,
    }


def digest_to_dict(digest: Digest) -> dict[str, Any]:
    return digest.to_dict()


def run_result_to_dict(result: RunResult, *, include_events: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        "scenario_id": result.scenario_id,
        "category": result.category,
        "variant": result.variant,
        "attack_succeeded": result.attack_succeeded,
        "blocked_by": result.blocked_by,
        "intent": intent_to_dict(result.intent),
    }
    if include_events:
        out["events"] = [evt.to_dict() for evt in result.log.events]
    return out
