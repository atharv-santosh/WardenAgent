"""Offline replay of recorded live-Gemini trajectory fixtures.

A fixture records the model's own outputs (digests, function calls). Per-argument
provenance is this project's code, not the model's, so replay recomputes it with
:func:`agent_sandbox.gemini_adapter.attribute_provenance` rather than reusing the
tag recorded at capture time.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_sandbox.gemini_adapter import attribute_provenance
from agent_sandbox.llm_sim import ToolCallIntent
from agent_sandbox.quarantine import Digest, QuarantineViolation, validate_digest


def load_fixture(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def list_fixtures(fixtures_dir: str | Path) -> list[Path]:
    return sorted(Path(fixtures_dir).glob("*.json"))


def _intent_from_function_call(record: dict[str, Any], *, source: str) -> ToolCallIntent | None:
    fc = record.get("function_call")
    if fc is None:
        return None
    return ToolCallIntent(
        tool=fc["name"],
        args={k: str(v) for k, v in fc["args"].items()},
        triggered_by="gemini function_call (replayed from fixture)",
        source=source,
        arg_sources=record.get("arg_sources"),
    )


def replay_naive_decide_fn(fixture: dict[str, Any]):
    """Build a ``decide_fn`` for :func:`agent_sandbox.agent.run_naive` that returns exactly what the fixture recorded, with no network call."""
    calls = fixture["naive"]["calls"]
    assert len(calls) == 1, f"expected exactly one naive decide call, got {len(calls)}"
    intent = _intent_from_function_call(calls[0], source="untrusted")

    def _decide(_context_text: str) -> ToolCallIntent | None:
        return intent

    return _decide


def replay_sandboxed_fns(fixture: dict[str, Any]):
    """Build ``(decide_fn, extract_fn)`` for :func:`agent_sandbox.agent.run_sandboxed` that replay exactly the fixture's recorded sandboxed-loop calls, with no network call."""
    calls = fixture["sandboxed"]["calls"]
    extract_records = [c for c in calls if c.get("kind") == "quarantine_extract"]
    decide_records = [c for c in calls if c.get("kind") == "sandboxed_decide"]
    assert len(decide_records) == 1, f"expected exactly one sandboxed decide call, got {len(decide_records)}"

    decide_record = decide_records[0]
    intent = _intent_from_function_call(decide_record, source="trusted")

    def _decide(trusted_text: str, digests: list[Digest]) -> ToolCallIntent | None:
        if intent is None:
            return None
        return ToolCallIntent(
            tool=intent.tool,
            args=dict(intent.args),
            triggered_by=intent.triggered_by,
            source=intent.source,
            arg_sources={
                name: attribute_provenance(value, trusted_text, digests)
                for name, value in intent.args.items()
            },
        )

    extract_iter = iter(extract_records)
    seen: dict[str, Digest] = {}

    def _extract(raw_text: str) -> Digest:
        if raw_text in seen:
            return seen[raw_text]
        record = next(extract_iter)
        if "error" in record:
            raise QuarantineViolation(record["error"])
        parsed = record["parsed"]
        digest = Digest(summary=parsed["summary"], entities=list(parsed["entities"]))
        validate_digest(digest)
        seen[raw_text] = digest
        return digest

    return _decide, _extract
