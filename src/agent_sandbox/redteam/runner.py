"""Runs the red-team and benign corpora against both agent variants."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_sandbox.agent import RunResult, run_naive, run_sandboxed
from agent_sandbox.approval import auto_approve, auto_deny
from agent_sandbox.policy import Policy, PolicyEngine
from agent_sandbox.redteam.corpus import ATTACK_CASES, BENIGN_CASES


@dataclass(slots=True)
class CategoryStats:
    category: str
    total: int = 0
    naive_success: int = 0
    sandboxed_success: int = 0

    @property
    def naive_asr(self) -> float:
        return self.naive_success / self.total if self.total else 0.0

    @property
    def sandboxed_asr(self) -> float:
        return self.sandboxed_success / self.total if self.total else 0.0


@dataclass(slots=True)
class MeasurementReport:
    declassify_via: str | None = None
    categories: dict[str, CategoryStats] = field(default_factory=dict)
    naive_results: list[RunResult] = field(default_factory=list)
    sandboxed_results: list[RunResult] = field(default_factory=list)
    benign_blocked: list[RunResult] = field(default_factory=list)
    benign_total: int = 0

    @property
    def overall_naive_asr(self) -> float:
        total = sum(c.total for c in self.categories.values())
        success = sum(c.naive_success for c in self.categories.values())
        return success / total if total else 0.0

    @property
    def overall_sandboxed_asr(self) -> float:
        total = sum(c.total for c in self.categories.values())
        success = sum(c.sandboxed_success for c in self.categories.values())
        return success / total if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        return len(self.benign_blocked) / self.benign_total if self.benign_total else 0.0


FP_CONFIGURATIONS: list[tuple[str, str | None]] = [
    ("no_declassification", None),
    ("declassify_via_approval", "approval"),
    ("declassify_via_quarantine", "quarantine"),
]


def run_corpus(policy_path: str, declassify_via: str | None = None) -> MeasurementReport:
    """Run the full attack corpus and benign corpus under one declassification configuration, return a report."""
    policy = Policy.from_file(policy_path)
    report = MeasurementReport(declassify_via=declassify_via)

    for scenario in ATTACK_CASES:
        stats = report.categories.setdefault(scenario.category, CategoryStats(category=scenario.category))
        stats.total += 1

        naive_result = run_naive(scenario)
        report.naive_results.append(naive_result)
        if naive_result.attack_succeeded:
            stats.naive_success += 1

        engine = PolicyEngine(policy)
        sandboxed_result = run_sandboxed(
            scenario, engine, approval_callback=auto_deny, declassify_via=declassify_via
        )
        report.sandboxed_results.append(sandboxed_result)
        if sandboxed_result.attack_succeeded:
            stats.sandboxed_success += 1

    report.benign_total = len(BENIGN_CASES)
    for scenario in BENIGN_CASES:
        engine = PolicyEngine(policy)
        result = run_sandboxed(
            scenario, engine, approval_callback=auto_approve, declassify_via=declassify_via
        )
        if not result.attack_succeeded:
            report.benign_blocked.append(result)

    return report


def run_fp_matrix(policy_path: str) -> dict[str, MeasurementReport]:
    """Run the full corpus under every configuration in :data:`FP_CONFIGURATIONS`."""
    return {name: run_corpus(policy_path, declassify_via=value) for name, value in FP_CONFIGURATIONS}
