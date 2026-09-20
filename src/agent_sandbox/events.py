"""Trajectory event vocabulary shared across the three sibling portfolio projects."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

EventType = Literal[
    "run_start",
    "llm_call",
    "llm_result",
    "tool_call",
    "tool_result",
    "decision",
    "human_gate",
    "error",
    "run_end",
]

VALID_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "run_start",
        "llm_call",
        "llm_result",
        "tool_call",
        "tool_result",
        "decision",
        "human_gate",
        "error",
        "run_end",
    }
)


@dataclass(slots=True)
class Event:
    """A single trajectory event."""

    run_id: str
    seq: int
    ts: float
    type: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "seq": self.seq,
            "ts": self.ts,
            "type": self.type,
            "payload": self.payload,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)


@dataclass(slots=True)
class EventLog:
    """Append-only, in-memory + optionally-on-disk trajectory event log."""

    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    path: Path | None = None
    events: list[Event] = field(default_factory=list)
    _seq: int = field(default=0, init=False)
    _fh: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8")

    def emit(self, type_: str, payload: dict[str, Any]) -> Event:
        if type_ not in VALID_EVENT_TYPES:
            raise ValueError(f"invalid event type: {type_!r}")
        evt = Event(
            run_id=self.run_id,
            seq=self._seq,
            ts=time.time(),
            type=type_,
            payload=payload,
        )
        self._seq += 1
        self.events.append(evt)
        if self._fh is not None:
            self._fh.write(evt.to_json() + "\n")
            self._fh.flush()
        return evt

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def as_jsonl(self) -> str:
        return "\n".join(e.to_json() for e in self.events)

    def filter_type(self, type_: str) -> list[Event]:
        return [e for e in self.events if e.type == type_]
