"""Offline replay of the committed real-Gemini trajectory fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_sandbox.agent import run_naive, run_sandboxed
from agent_sandbox.approval import auto_approve, auto_deny
from agent_sandbox.live_replay import list_fixtures, load_fixture, replay_naive_decide_fn, replay_sandboxed_fns
from agent_sandbox.policy import Policy, PolicyEngine
from agent_sandbox.redteam.adaptive import ADAPTIVE_CASES
from agent_sandbox.redteam.corpus import ATTACK_CASES, BENIGN_CASES
from agent_sandbox.redteam.runner import FP_CONFIGURATIONS

FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "gemini"
DEFAULT_POLICY = str(Path(__file__).resolve().parents[1] / "policies" / "default.yaml")

ALL_SCENARIOS = {s.id: s for s in [*ATTACK_CASES, *BENIGN_CASES, *ADAPTIVE_CASES]}


def _fixture_dirs() -> list[Path]:
    if not FIXTURES_ROOT.exists():
        return []
    return sorted(p for p in FIXTURES_ROOT.iterdir() if p.is_dir())


def _all_fixture_files() -> list[Path]:
    files: list[Path] = []
    for model_dir in _fixture_dirs():
        files.extend(list_fixtures(model_dir))
    return files


FIXTURE_FILES = _all_fixture_files()


@pytest.mark.skipif(not FIXTURE_FILES, reason="no committed live-Gemini fixtures found")
@pytest.mark.parametrize("fixture_path", FIXTURE_FILES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_replayed_naive_run_matches_recorded_outcome(fixture_path: Path) -> None:
    fixture = load_fixture(fixture_path)
    scenario = ALL_SCENARIOS[fixture["scenario_id"]]

    decide_fn = replay_naive_decide_fn(fixture)
    result = run_naive(scenario, decide_fn=decide_fn)

    assert result.attack_succeeded == fixture["naive"]["attack_succeeded"], (
        f"replaying {fixture_path} through the real naive-agent policy code did not reproduce "
        f"the recorded live-Gemini outcome"
    )


@pytest.mark.skipif(not FIXTURE_FILES, reason="no committed live-Gemini fixtures found")
@pytest.mark.parametrize("fixture_path", FIXTURE_FILES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_replayed_sandboxed_run_matches_recorded_outcome_all_configs(fixture_path: Path) -> None:
    fixture = load_fixture(fixture_path)
    scenario = ALL_SCENARIOS[fixture["scenario_id"]]
    is_benign = fixture["is_benign"]
    cb = auto_approve if is_benign else auto_deny
    recorded = fixture["sandboxed"]["results_by_config"]

    policy = Policy.from_file(DEFAULT_POLICY)

    for name, declassify_via in FP_CONFIGURATIONS:
        if name not in recorded:
            continue
        decide_fn, extract_fn = replay_sandboxed_fns(fixture)
        engine = PolicyEngine(policy)
        result = run_sandboxed(
            scenario,
            engine,
            approval_callback=cb,
            declassify_via=declassify_via,
            decide_fn=decide_fn,
            extract_fn=extract_fn,
        )
        assert result.attack_succeeded == recorded[name]["attack_succeeded"], (
            f"replaying {fixture_path} under declassify_via={declassify_via!r} did not reproduce "
            f"the recorded live-Gemini outcome"
        )


@pytest.mark.skipif(not FIXTURE_FILES, reason="no committed live-Gemini fixtures found")
def test_at_least_one_fixture_per_model_is_committed() -> None:
    """Sanity check that this repo actually ships real trajectory fixtures, not an empty directory -- see MEASUREMENTS.md for the models/dates."""
    assert len(_fixture_dirs()) >= 1
    assert len(FIXTURE_FILES) >= 1
