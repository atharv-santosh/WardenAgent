"""Runs the red-team + benign corpus against a REAL Gemini model over Vertex AI."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_sandbox.agent import RunResult, Scenario, run_naive, run_sandboxed
from agent_sandbox.approval import auto_approve, auto_deny
from agent_sandbox.llm_sim import ToolCallIntent
from agent_sandbox.gemini_adapter import (
    CallRecorder,
    build_client,
    make_live_naive_decide,
    make_live_quarantine_extract,
    make_live_sandboxed_decide,
)
from agent_sandbox.policy import Policy, PolicyEngine
from agent_sandbox.quarantine import Digest, QuarantineViolation
from agent_sandbox.redteam.corpus import ATTACK_CASES, BENIGN_CASES
from agent_sandbox.redteam.runner import CategoryStats, FP_CONFIGURATIONS, MeasurementReport


@dataclass(slots=True)
class LiveUsage:
    total_tokens: int = 0
    total_calls: int = 0
    per_scenario: dict[str, int] = field(default_factory=dict)


def _cached_decide_fn(cached_result: Any):
    def _decide(*_args: Any, **_kwargs: Any) -> Any:
        return cached_result

    return _decide


def _cached_extract_fn(cache: dict[str, Digest], live_extract: Any):
    def _extract(raw_text: str) -> Digest:
        if raw_text not in cache:
            cache[raw_text] = live_extract(raw_text)
        return cache[raw_text]

    return _extract


def run_live_corpus(
    policy_path: str,
    model: str,
    *,
    fixtures_dir: str | None = None,
    limit: int | None = None,
    include_benign: bool = True,
    skip_existing_fixtures: bool = False,
) -> tuple[dict[str, MeasurementReport], list[RunResult], LiveUsage]:
    """Run the attack corpus (and, unless ``include_benign`` is False, the benign corpus) against a real Gemini model."""
    client = build_client()
    policy = Policy.from_file(policy_path)

    attack = list(ATTACK_CASES)
    benign = list(BENIGN_CASES) if include_benign else []
    if limit is not None:
        attack = attack[:limit]
        benign = benign[: max(0, limit // 2)]

    reports = {name: MeasurementReport(declassify_via=value) for name, value in FP_CONFIGURATIONS}
    naive_results: list[RunResult] = []
    usage = LiveUsage()

    def _run_one(scenario: Scenario, is_benign: bool) -> None:
        if (
            skip_existing_fixtures
            and fixtures_dir is not None
            and (Path(fixtures_dir) / f"{scenario.id}.json").exists()
        ):
            return
        started = time.time()
        naive_recorder = CallRecorder()
        naive_decide = make_live_naive_decide(client, model, recorder=naive_recorder)
        naive_result = run_naive(scenario, decide_fn=naive_decide)
        naive_results.append(naive_result)

        sbx_recorder = CallRecorder()
        sandboxed_decide = make_live_sandboxed_decide(client, model, recorder=sbx_recorder)
        quarantine_extract_live = make_live_quarantine_extract(client, model, recorder=sbx_recorder)
        extract_cache: dict[str, Digest] = {}

        engine = PolicyEngine(policy)
        cb = auto_approve if is_benign else auto_deny
        cached_extract = _cached_extract_fn(extract_cache, quarantine_extract_live)
        first_result = run_sandboxed(
            scenario,
            engine,
            approval_callback=cb,
            declassify_via=FP_CONFIGURATIONS[0][1],
            decide_fn=sandboxed_decide,
            extract_fn=cached_extract,
        )
        sandboxed_by_config: dict[str, RunResult] = {FP_CONFIGURATIONS[0][0]: first_result}

        cached_intent = None
        for record in sbx_recorder.calls:
            if record.get("kind") == "sandboxed_decide" and record.get("function_call"):
                fc = record["function_call"]
                cached_intent = ToolCallIntent(
                    tool=fc["name"],
                    args={k: str(v) for k, v in fc["args"].items()},
                    triggered_by="gemini function_call (sandboxed, live, cached)",
                    source="trusted",
                    arg_sources=record.get("arg_sources"),
                )

        replay_decide = _cached_decide_fn(cached_intent)
        for name, declassify_via in FP_CONFIGURATIONS[1:]:
            engine = PolicyEngine(policy)
            result = run_sandboxed(
                scenario,
                engine,
                approval_callback=cb,
                declassify_via=declassify_via,
                decide_fn=replay_decide,
                extract_fn=cached_extract,
            )
            sandboxed_by_config[name] = result

        for name, _ in FP_CONFIGURATIONS:
            report = reports[name]
            result = sandboxed_by_config[name]
            if is_benign:
                report.benign_total += 1
                if not result.attack_succeeded:
                    report.benign_blocked.append(result)
            else:
                stats = report.categories.setdefault(
                    scenario.category, CategoryStats(category=scenario.category)
                )
                stats.total += 1
                if naive_result.attack_succeeded:
                    stats.naive_success += 1
                if result.attack_succeeded:
                    stats.sandboxed_success += 1
            report.naive_results.append(naive_result)
            report.sandboxed_results.append(result)

        scenario_tokens = naive_recorder.total_tokens() + sbx_recorder.total_tokens()
        scenario_calls = len(naive_recorder.calls) + len(sbx_recorder.calls)
        usage.total_tokens += scenario_tokens
        usage.total_calls += scenario_calls
        usage.per_scenario[scenario.id] = scenario_tokens

        if fixtures_dir is not None:
            fixture = {
                "scenario_id": scenario.id,
                "category": scenario.category,
                "is_benign": is_benign,
                "model": model,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "naive": {
                    "calls": naive_recorder.calls,
                    "attack_succeeded": naive_result.attack_succeeded,
                },
                "sandboxed": {
                    "calls": sbx_recorder.calls,
                    "results_by_config": {
                        name: {
                            "attack_succeeded": sandboxed_by_config[name].attack_succeeded,
                            "blocked_by": sandboxed_by_config[name].blocked_by,
                        }
                        for name, _ in FP_CONFIGURATIONS
                    },
                },
                "elapsed_seconds": round(time.time() - started, 2),
            }
            Path(fixtures_dir).mkdir(parents=True, exist_ok=True)
            (Path(fixtures_dir) / f"{scenario.id}.json").write_text(
                json.dumps(fixture, indent=2), encoding="utf-8"
            )

    for scenario in attack:
        _run_one(scenario, is_benign=False)
    for scenario in benign:
        _run_one(scenario, is_benign=True)

    return reports, naive_results, usage
