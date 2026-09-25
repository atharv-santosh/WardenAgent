"""Aggregate a full attack-success-rate / false-positive report from already-recorded live-Gemini trajectory fixtures."""

from __future__ import annotations

from pathlib import Path

from agent_sandbox.agent import RunResult, run_naive, run_sandboxed
from agent_sandbox.approval import auto_approve, auto_deny
from agent_sandbox.live_replay import list_fixtures, load_fixture, replay_naive_decide_fn, replay_sandboxed_fns
from agent_sandbox.policy import Policy, PolicyEngine
from agent_sandbox.redteam.adaptive import ADAPTIVE_CASES
from agent_sandbox.redteam.corpus import ATTACK_CASES, BENIGN_CASES
from agent_sandbox.redteam.runner import CategoryStats, FP_CONFIGURATIONS, MeasurementReport


def build_report_from_fixtures(
    fixtures_dir: str | Path, policy_path: str
) -> tuple[dict[str, MeasurementReport], list[RunResult]]:
    """Replay every fixture in ``fixtures_dir`` and rebuild the same ``{config_name: MeasurementReport}`` shape :func:`agent_sandbox.redteam."""
    policy = Policy.from_file(policy_path)
    all_scenarios = {s.id: s for s in [*ATTACK_CASES, *BENIGN_CASES, *ADAPTIVE_CASES]}

    reports = {name: MeasurementReport(declassify_via=value) for name, value in FP_CONFIGURATIONS}
    naive_results: list[RunResult] = []

    for path in list_fixtures(fixtures_dir):
        fixture = load_fixture(path)
        scenario = all_scenarios[fixture["scenario_id"]]
        is_benign = fixture["is_benign"]

        naive_decide = replay_naive_decide_fn(fixture)
        naive_result = run_naive(scenario, decide_fn=naive_decide)
        naive_results.append(naive_result)

        sbx_decide, sbx_extract = replay_sandboxed_fns(fixture)
        cb = auto_approve if is_benign else auto_deny

        for name, declassify_via in FP_CONFIGURATIONS:
            engine = PolicyEngine(policy)
            result = run_sandboxed(
                scenario,
                engine,
                approval_callback=cb,
                declassify_via=declassify_via,
                decide_fn=sbx_decide,
                extract_fn=sbx_extract,
            )
            report = reports[name]
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

    return reports, naive_results


def build_adaptive_cells_from_fixtures(fixtures_dir: str | Path, policy_path: str):
    """Replay adaptive-set fixtures through :func:`agent_sandbox.redteam.runner.run_adaptive`, so the live grid is measured by the same code as the offline one."""
    from agent_sandbox.redteam.adaptive import ADAPTIVE_CASES
    from agent_sandbox.redteam.runner import run_adaptive

    fixtures = {load_fixture(p)["scenario_id"]: load_fixture(p) for p in list_fixtures(fixtures_dir)}
    cases = [s for s in ADAPTIVE_CASES if s.id in fixtures]
    naive: dict[str, bool] = {}
    for scenario in cases:
        result = run_naive(scenario, decide_fn=replay_naive_decide_fn(fixtures[scenario.id]))
        naive[scenario.id] = result.attack_succeeded
    cells = run_adaptive(
        policy_path,
        cases=cases,
        decide_fn=lambda s: replay_sandboxed_fns(fixtures[s.id])[0],
        extract_fn=lambda s: replay_sandboxed_fns(fixtures[s.id])[1],
    )
    return cells, naive
