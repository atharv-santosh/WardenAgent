"""Tests for the shared trajectory event log."""

from __future__ import annotations

import json

import pytest

from agent_sandbox.events import EventLog


def test_emit_rejects_unknown_event_type() -> None:
    log = EventLog()
    with pytest.raises(ValueError):
        log.emit("not_a_real_type", {})


def test_emit_returns_event_matching_shared_schema() -> None:
    log = EventLog(run_id="run-123")
    evt = log.emit("run_start", {"scenario": "s1"})
    assert evt.run_id == "run-123"
    assert evt.seq == 0
    assert evt.type == "run_start"
    assert evt.payload == {"scenario": "s1"}


def test_as_jsonl_produces_one_json_object_per_line() -> None:
    log = EventLog()
    log.emit("run_start", {})
    log.emit("tool_call", {"tool": "fetch_url"})
    lines = log.as_jsonl().splitlines()
    assert len(lines) == 2
    for line in lines:
        obj = json.loads(line)
        assert set(obj.keys()) == {"run_id", "seq", "ts", "type", "payload"}


def test_writing_to_disk_produces_valid_jsonl(tmp_path) -> None:
    path = tmp_path / "trace.jsonl"
    log = EventLog(path=path)
    log.emit("run_start", {})
    log.emit("run_end", {"ok": True})
    log.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["type"] == "run_start"
    assert parsed[1]["type"] == "run_end"


def test_filter_type_returns_only_matching_events() -> None:
    log = EventLog()
    log.emit("run_start", {})
    log.emit("decision", {"allow": True})
    log.emit("decision", {"allow": False})
    decisions = log.filter_type("decision")
    assert len(decisions) == 2
