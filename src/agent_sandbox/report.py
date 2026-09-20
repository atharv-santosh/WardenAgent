"""Self-contained single-file HTML report generator."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from agent_sandbox.redteam.runner import MeasurementReport

_CSS = """
body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem auto; max-width: 900px; color: #1a1a1a; background: #fafafa; }
h1 { font-size: 1.6rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: 0.3rem; }
table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }
th { background: #eee; }
tr.zero-sandboxed td.sandboxed { color: #0a7a0a; font-weight: bold; }
tr td.naive { color: #a10000; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
.badge-ok { background: #e3f7e3; color: #0a7a0a; }
.badge-warn { background: #fff2cc; color: #8a6d00; }
.summary { display: flex; gap: 1rem; margin-top: 1rem; flex-wrap: wrap; }
.card { border: 1px solid #ddd; border-radius: 6px; padding: 0.8rem 1.2rem; background: white; min-width: 180px; }
.card .value { font-size: 1.6rem; font-weight: bold; }
.card .label { font-size: 0.8rem; color: #666; }
footer { margin-top: 2rem; font-size: 0.8rem; color: #888; }
code { background: #eee; padding: 0.1rem 0.3rem; border-radius: 3px; }
"""


def generate_html_report(report: MeasurementReport, *, matrix: dict[str, MeasurementReport] | None = None, command: str = "") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for cat in sorted(report.categories):
        stats = report.categories[cat]
        rows.append(
            f"<tr><td>{html.escape(cat)}</td><td>{stats.total}</td>"
            f"<td class='naive'>{stats.naive_asr:.0%} ({stats.naive_success}/{stats.total})</td>"
            f"<td class='sandboxed'>{stats.sandboxed_asr:.0%} ({stats.sandboxed_success}/{stats.total})</td></tr>"
        )
    table_rows = "\n".join(rows)

    fp_examples = "".join(
        f"<li><code>{html.escape(r.scenario_id)}</code> blocked by <code>{html.escape(r.blocked_by or '?')}</code></li>"
        for r in report.benign_blocked
    ) or "<li>none</li>"

    matrix_section = ""
    if matrix:
        matrix_rows = []
        for name, rpt in matrix.items():
            matrix_rows.append(
                f"<tr><td>{html.escape(name)}</td>"
                f"<td>{rpt.overall_sandboxed_asr:.0%}</td>"
                f"<td>{rpt.false_positive_rate:.0%}</td>"
                f"<td>{len(rpt.benign_blocked)}/{rpt.benign_total}</td></tr>"
            )
        matrix_section = f"""
<h2>False-positive rate by declassification configuration</h2>
<p>Naive taint enforcement with no declassification path is unusably strict on legitimate
untrusted-to-privileged-sink forwarding tasks. This table is the headline result: how much a
declassification path actually costs (or fixes), measured, not estimated.</p>
<table>
<thead><tr><th>Configuration</th><th>Sandboxed ASR (attack corpus)</th><th>FP rate (benign corpus)</th><th>Benign tasks blocked</th></tr></thead>
<tbody>
{"".join(matrix_rows)}
</tbody>
</table>
"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Agent Sandbox Red-Team Report</title>
<style>{_CSS}</style>
</head>
<body>
<h1>Agent Sandbox: Red-Team Measurement Report</h1>
<p>Generated {ts}{" via <code>" + html.escape(command) + "</code>" if command else ""}.</p>

<div class="summary">
  <div class="card"><div class="value">{report.overall_naive_asr:.0%}</div><div class="label">Naive baseline ASR</div></div>
  <div class="card"><div class="value">{report.overall_sandboxed_asr:.0%}</div><div class="label">Sandboxed ASR</div></div>
  <div class="card"><div class="value">{report.false_positive_rate:.0%}</div><div class="label">Benign false-positive rate</div></div>
  <div class="card"><div class="value">{sum(c.total for c in report.categories.values())}</div><div class="label">Attack cases run</div></div>
  <div class="card"><div class="value">{report.benign_total}</div><div class="label">Benign cases run</div></div>
</div>

<h2>Attack success rate by category (naive vs sandboxed)</h2>
<table>
<thead><tr><th>Category</th><th>Cases</th><th>Naive ASR</th><th>Sandboxed ASR</th></tr></thead>
<tbody>
{table_rows}
</tbody>
</table>

<h2>Benign corpus false positives (this report's primary configuration)</h2>
<p>{len(report.benign_blocked)} of {report.benign_total} legitimate tasks were incorrectly blocked.</p>
<ul>{fp_examples}</ul>
{matrix_section}
<footer>
agent-sandbox &middot; deterministic offline simulation, no API keys used.
See MEASUREMENTS.md in the repository for the exact command and raw counts.
</footer>
</body>
</html>
"""
