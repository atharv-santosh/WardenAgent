"""Tests for the sbx CLI."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_sandbox.cli import main


def test_policy_check_prints_table_and_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["policy", "check", "policies/default.yaml"])
    assert result.exit_code == 0
    assert "send_email" in result.output


def test_policy_check_reports_error_on_invalid_policy(tmp_path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("default: maybe\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["policy", "check", str(bad)])
    assert result.exit_code != 0


def test_redteam_command_writes_json_and_prints_table(tmp_path) -> None:
    out = tmp_path / "results.json"
    runner = CliRunner()
    result = runner.invoke(main, ["redteam", "--json-out", str(out)])
    assert result.exit_code == 0
    assert "Naive ASR" in result.output
    payload = json.loads(out.read_text())
    assert "overall_naive_asr" in payload
    assert payload["benign_total"] > 0


def test_report_command_writes_html_file(tmp_path) -> None:
    out = tmp_path / "report.html"
    runner = CliRunner()
    result = runner.invoke(main, ["report", "--out", str(out)])
    assert result.exit_code == 0
    content = out.read_text(encoding="utf-8")
    assert "<html" in content
    assert "Red-Team" in content


def test_run_command_with_known_scenario_id() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["run", "indirect_injection-01"])
    assert result.exit_code == 0
    assert "naive" in result.output
    assert "sandboxed" in result.output


def test_run_command_with_unknown_scenario_id_exits_nonzero() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["run", "does-not-exist"])
    assert result.exit_code != 0
