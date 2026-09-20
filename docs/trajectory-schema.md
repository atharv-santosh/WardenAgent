# Trajectory event schema

This project is one of three sibling portfolio projects that share a single
trajectory event vocabulary, so events emitted by any of them can be
consumed by a common downstream viewer/analyzer. Every event, from any
component, has exactly this shape:

```json
{"run_id": "a1b2c3d4e5f6", "seq": 0, "ts": 1758312345.123, "type": "run_start", "payload": {}}
```

| field     | type   | meaning                                                             |
|-----------|--------|----------------------------------------------------------------------|
| `run_id`  | string | Stable identifier for one agent run. Shared by every event in that run. |
| `seq`     | int    | Strictly increasing, zero-based sequence number within the run. Total order over everything that happened. |
| `ts`      | float  | Unix timestamp (seconds) when the event was emitted.               |
| `type`    | string | One of the nine event types below.                                 |
| `payload` | object | Type-specific structured data. Never a raw model prompt/response blob -- always the extracted, structured fields relevant to that event type. |

## Event types

| `type`         | Emitted when...                                                              | Notable payload fields |
|----------------|-------------------------------------------------------------------------------|-------------------------|
| `run_start`    | A scenario/run begins.                                                       | `scenario`, `variant` |
| `llm_call`     | The agent brain is about to make a decision.                                 | `context_chars` (naive) or `trusted_chars`/`digests` (sandboxed) |
| `llm_result`   | The agent brain returned a decision.                                        | `intent` (tool name or `null`) |
| `tool_call`    | A tool is about to execute.                                                  | `tool`, `args` |
| `tool_result`  | A tool finished executing.                                                   | `tool`, `ok`, `output` |
| `decision`     | The policy engine (or the quarantine step) made an allow/deny decision.      | `allow`, `rule`, `reason`, `tool`, `requires_approval` |
| `human_gate`   | An approval gate opened (`phase: "request"`) or was resolved (`phase: "decision"`). | `tool`, `args`, `rule`, `provenance` / `approved`, `decided_by` |
| `error`        | A violation or failure occurred (taint violation, secret leakage, quarantine failure). | `kind`, `detail` |
| `run_end`      | The run finished.                                                             | `attack_succeeded`, `blocked_by` (sandboxed only) |

## Producing events in this project

`agent_sandbox.events.EventLog` is the single point that constructs and
serializes events. Every sandbox component (the agent loop in
`agent_sandbox.agent`, the approval gate in `agent_sandbox.approval`) is
handed the same `EventLog` instance for a run, so `seq` is a total order
over the whole run regardless of which component emitted the event.

Policy decisions always use `type: "decision"`, with `payload.rule` set to
the exact rule name that produced the outcome (e.g. `network_allowlist:fetch_url`,
`taint_flow`, `budget:max_total_calls`) -- this is what makes decisions
auditable: given any `decision` event you can find the rule in
`policies/default.yaml` (or the equivalent enforcement code in
`agent_sandbox/policy.py` / `agent_sandbox/taint.py`) that produced it.

Approval gates always use `type: "human_gate"`, emitted twice per gate: once
with `payload.phase == "request"` (before the human/callback is consulted)
and once with `payload.phase == "decision"` (after).

## Consuming the trajectory

`EventLog.as_jsonl()` returns the whole run as newline-delimited JSON, and
`EventLog(path=...)` will additionally append each event to a file on disk
as it is emitted, so a run's trajectory can be tailed live or replayed
later by any consumer that understands this schema -- including the other
two sibling projects.
