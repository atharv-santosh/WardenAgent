"""``sbx`` command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agent_sandbox.agent import run_naive, run_sandboxed
from agent_sandbox.approval import auto_deny
from agent_sandbox.policy import Policy, PolicyEngine, PolicyError
from agent_sandbox.redteam.corpus import ATTACK_CASES, BENIGN_CASES
from agent_sandbox.redteam.runner import FP_CONFIGURATIONS, run_adaptive, run_corpus, run_fp_matrix
from agent_sandbox.report import generate_html_report

console = Console()

DEFAULT_POLICY = str(Path(__file__).resolve().parents[2] / "policies" / "default.yaml")


@click.group()
def main() -> None:
    """Capability-scoped agent sandbox: policy engine, taint tracking, red-team harness."""


@main.group()
def policy() -> None:
    """Inspect and validate policy files."""


@policy.command("check")
@click.argument("policy_path", type=click.Path(exists=True))
def policy_check(policy_path: str) -> None:
    """Parse POLICY_PATH and print the effective per-tool rules."""
    try:
        parsed = Policy.from_file(policy_path)
    except PolicyError as exc:
        console.print(f"[bold red]policy error:[/bold red] {exc}")
        sys.exit(1)

    table = Table(title=f"Policy: {policy_path} (default={'deny' if parsed.default_deny else 'allow'})")
    table.add_column("Tool")
    table.add_column("Allow")
    table.add_column("Sink")
    table.add_column("Approval")
    table.add_column("Max calls")
    table.add_column("Constraints")
    for name, tool in sorted(parsed.tools.items()):
        constraints = []
        if tool.network_hosts:
            constraints.append(f"hosts={tool.network_hosts}")
        for arg_name, spec in tool.args.items():
            if spec.type == "path_jail":
                constraints.append(f"{arg_name}: jail={spec.roots}")
            elif spec.pattern:
                constraints.append(f"{arg_name}: pattern={spec.pattern}")
        table.add_row(
            name,
            "yes" if tool.allow else "no",
            "yes" if tool.sink else "no",
            "yes" if tool.requires_approval else "no",
            str(tool.max_calls) if tool.max_calls else "-",
            "; ".join(constraints) or "-",
        )
    console.print(table)
    if parsed.max_total_calls:
        console.print(f"budget: max_total_calls={parsed.max_total_calls}")


@main.command("run")
@click.argument("scenario_id")
@click.option("--policy-path", default=DEFAULT_POLICY, show_default=True)
@click.option("--variant", type=click.Choice(["naive", "sandboxed", "both"]), default="both")
def run_scenario(scenario_id: str, policy_path: str, variant: str) -> None:
    """Run one corpus scenario by id and print its trajectory."""
    all_scenarios = {s.id: s for s in [*ATTACK_CASES, *BENIGN_CASES]}
    scenario = all_scenarios.get(scenario_id)
    if scenario is None:
        console.print(f"[bold red]unknown scenario id:[/bold red] {scenario_id}")
        console.print(f"available: {', '.join(sorted(all_scenarios))}")
        sys.exit(1)

    if variant in ("naive", "both"):
        result = run_naive(scenario)
        console.print(f"[bold]naive[/bold] attack_succeeded={result.attack_succeeded}")
        for evt in result.log.events:
            console.print(f"  [{evt.type}] {evt.payload}")

    if variant in ("sandboxed", "both"):
        parsed_policy = Policy.from_file(policy_path)
        engine = PolicyEngine(parsed_policy)
        result = run_sandboxed(scenario, engine, approval_callback=auto_deny)
        console.print(
            f"[bold]sandboxed[/bold] attack_succeeded={result.attack_succeeded} blocked_by={result.blocked_by}"
        )
        for evt in result.log.events:
            console.print(f"  [{evt.type}] {evt.payload}")


def _report_to_dict(report) -> dict:
    return {
        "declassify_via": report.declassify_via,
        "categories": {
            cat: {
                "total": s.total,
                "naive_success": s.naive_success,
                "sandboxed_success": s.sandboxed_success,
                "naive_asr": s.naive_asr,
                "sandboxed_asr": s.sandboxed_asr,
            }
            for cat, s in report.categories.items()
        },
        "overall_naive_asr": report.overall_naive_asr,
        "overall_sandboxed_asr": report.overall_sandboxed_asr,
        "false_positive_rate": report.false_positive_rate,
        "benign_total": report.benign_total,
        "benign_blocked": [r.scenario_id for r in report.benign_blocked],
    }


@main.command("redteam")
@click.option("--policy-path", default=DEFAULT_POLICY, show_default=True)
@click.option(
    "--declassify-via",
    type=click.Choice(["none", "approval", "quarantine"]),
    default="none",
    show_default=True,
    help="Declassification path used when untrusted data reaches a privileged sink.",
)
@click.option("--fp-matrix", is_flag=True, help="Also run the benign corpus under all three declassification configurations.")
@click.option("--json-out", type=click.Path(), default=None, help="Write raw JSON results to this path.")
def redteam(policy_path: str, declassify_via: str, fp_matrix: bool, json_out: str | None) -> None:
    """Run the full attack + benign corpus, print a terminal table."""
    mode = None if declassify_via == "none" else declassify_via
    report = run_corpus(policy_path, declassify_via=mode)

    table = Table(title=f"Red-team results: attack success rate (naive vs sandboxed, declassify_via={declassify_via})")
    table.add_column("Category")
    table.add_column("Cases", justify="right")
    table.add_column("Naive ASR", justify="right")
    table.add_column("Sandboxed ASR", justify="right")
    for cat in sorted(report.categories):
        stats = report.categories[cat]
        table.add_row(cat, str(stats.total), f"{stats.naive_asr:.0%}", f"{stats.sandboxed_asr:.0%}")
    console.print(table)
    console.print(
        f"[bold]Overall:[/bold] naive ASR={report.overall_naive_asr:.0%} "
        f"sandboxed ASR={report.overall_sandboxed_asr:.0%} "
        f"false-positive rate={report.false_positive_rate:.0%} "
        f"({len(report.benign_blocked)}/{report.benign_total} benign tasks blocked)"
    )

    payload: dict = _report_to_dict(report)

    if fp_matrix:
        matrix = run_fp_matrix(policy_path)
        fp_table = Table(title="False-positive rate on the benign corpus, by declassification configuration")
        fp_table.add_column("Configuration")
        fp_table.add_column("Sandboxed ASR (attack corpus)", justify="right")
        fp_table.add_column("FP rate (benign corpus)", justify="right")
        fp_table.add_column("Benign tasks blocked", justify="right")
        for name, _ in FP_CONFIGURATIONS:
            r = matrix[name]
            fp_table.add_row(
                name,
                f"{r.overall_sandboxed_asr:.0%}",
                f"{r.false_positive_rate:.0%}",
                f"{len(r.benign_blocked)}/{r.benign_total}",
            )
        console.print(fp_table)
        payload["fp_matrix"] = {name: _report_to_dict(matrix[name]) for name, _ in FP_CONFIGURATIONS}

    if json_out:
        Path(json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"wrote {json_out}")


@main.command("adaptive")
@click.option("--policy-path", default=DEFAULT_POLICY, show_default=True)
@click.option("--json-out", type=click.Path(), default=None, help="Write raw JSON results to this path.")
def adaptive_cmd(policy_path: str, json_out: str | None) -> None:
    """Run the adaptive attack set: attacks written against this codebase's own defenses, under every declassification configuration and both approver models."""
    cells = run_adaptive(policy_path)

    table = Table(title="Adaptive attack set: success rate by declassification config and approver model")
    table.add_column("Declassify via")
    table.add_column("Approver")
    table.add_column("ASR", justify="right")
    table.add_column("Succeeded", justify="left")
    for cell in cells:
        table.add_row(
            str(cell.declassify_via),
            cell.approver,
            f"{cell.asr:.1%} ({len(cell.succeeded)}/{cell.total})",
            ", ".join(cell.succeeded) or "-",
        )
    console.print(table)

    if json_out:
        payload = [
            {
                "declassify_via": c.declassify_via,
                "approver": c.approver,
                "asr": c.asr,
                "succeeded": c.succeeded,
                "blocked_by": c.blocked_by,
                "total": c.total,
            }
            for c in cells
        ]
        Path(json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"wrote {json_out}")


@main.command("report")
@click.option("--policy-path", default=DEFAULT_POLICY, show_default=True)
@click.option("--out", type=click.Path(), default="redteam-report.html", show_default=True)
def report_cmd(policy_path: str, out: str) -> None:
    """Run the full corpus under every declassification configuration and write a self-contained HTML report including the false-positive matrix."""
    matrix = run_fp_matrix(policy_path)
    primary = matrix["no_declassification"]
    html_doc = generate_html_report(
        primary,
        matrix=matrix,
        command=f"sbx report --policy-path {policy_path} --out {out}",
    )
    Path(out).write_text(html_doc, encoding="utf-8")
    console.print(f"wrote {out}")


@main.command("redteam-live")
@click.option("--policy-path", default=DEFAULT_POLICY, show_default=True)
@click.option("--model", default="gemini-2.5-flash-lite", show_default=True, help="Vertex AI Gemini model id.")
@click.option("--limit", type=int, default=None, help="Only run the first N attack (and N//2 benign) cases -- for a cheap smoke test.")
@click.option("--no-benign", is_flag=True, help="Skip the benign corpus (attack corpus only).")
@click.option("--adaptive", is_flag=True, help="Run the adaptive attack set instead of the standard attack corpus.")
@click.option("--fixtures-dir", type=click.Path(), default=None, help="Write one trajectory fixture JSON per scenario here.")
@click.option("--json-out", type=click.Path(), default=None, help="Write raw JSON results to this path.")
@click.option(
    "--yes-spend-money",
    is_flag=True,
    required=True,
    help="Required. This command makes real, billed calls to Vertex AI Gemini -- never the default measurement path.",
)
def redteam_live(
    policy_path: str,
    model: str,
    limit: int | None,
    no_benign: bool,
    adaptive: bool,
    fixtures_dir: str | None,
    json_out: str | None,
    yes_spend_money: bool,
) -> None:
    """Run the attack (+ benign) corpus against a REAL Gemini model over Vertex AI."""
    from agent_sandbox.gemini_adapter import GeminiUnavailable, credentials_available
    from agent_sandbox.redteam.adaptive import ADAPTIVE_CASES
    from agent_sandbox.redteam.live_runner import run_live_corpus

    if not credentials_available():
        console.print(
            "[bold red]no usable Google Application Default Credentials found.[/bold red] "
            "Run `gcloud auth application-default login` first, or set GOOGLE_APPLICATION_CREDENTIALS."
        )
        sys.exit(1)

    try:
        reports, naive_results, usage = run_live_corpus(
            policy_path,
            model,
            fixtures_dir=fixtures_dir,
            limit=limit,
            include_benign=not no_benign,
            attack_cases=list(ADAPTIVE_CASES) if adaptive else None,
        )
    except GeminiUnavailable as exc:
        console.print(f"[bold red]Gemini unavailable:[/bold red] {exc}")
        sys.exit(1)

    primary = reports[FP_CONFIGURATIONS[0][0]]
    table = Table(title=f"LIVE red-team results against {model} (real Vertex AI calls)")
    table.add_column("Category")
    table.add_column("Cases", justify="right")
    table.add_column("Naive ASR", justify="right")
    table.add_column("Sandboxed ASR", justify="right")
    for cat in sorted(primary.categories):
        stats = primary.categories[cat]
        table.add_row(cat, str(stats.total), f"{stats.naive_asr:.0%}", f"{stats.sandboxed_asr:.0%}")
    console.print(table)
    console.print(
        f"[bold]Overall (live, {model}):[/bold] naive ASR={primary.overall_naive_asr:.0%} "
        f"sandboxed ASR={primary.overall_sandboxed_asr:.0%}"
    )

    fp_table = Table(title="LIVE false-positive rate on the benign corpus, by declassification configuration")
    fp_table.add_column("Configuration")
    fp_table.add_column("Sandboxed ASR (attack corpus)", justify="right")
    fp_table.add_column("FP rate (benign corpus)", justify="right")
    fp_table.add_column("Benign tasks blocked", justify="right")
    for name in [name for name, _ in FP_CONFIGURATIONS]:
        r = reports[name]
        fp_table.add_row(
            name,
            f"{r.overall_sandboxed_asr:.0%}",
            f"{r.false_positive_rate:.0%}",
            f"{len(r.benign_blocked)}/{r.benign_total}" if r.benign_total else "-",
        )
    console.print(fp_table)
    console.print(
        f"[bold]Token usage:[/bold] {usage.total_tokens} tokens across {usage.total_calls} live model calls"
    )

    if json_out:
        payload = {
            "model": model,
            "usage": {"total_tokens": usage.total_tokens, "total_calls": usage.total_calls},
            "fp_matrix": {name: _report_to_dict(reports[name]) for name, _ in FP_CONFIGURATIONS},
        }
        Path(json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"wrote {json_out}")


@main.command("serve")
@click.option("--port", default=8711, show_default=True, type=int)
@click.option("--host", default="127.0.0.1", show_default=True, help="Binds to localhost by default -- change deliberately if you want this reachable off-box.")
@click.option("--reload", is_flag=True, help="Auto-reload on source changes (development only).")
def serve(port: int, host: str, reload: bool) -> None:
    """Launch the Injection Playground: a local web app to interactively run the naive and sandboxed agents (simulator or real Gemini) and watch the defense work, including the live human-approval gate."""
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[bold red]the web UI requires the '[web]' extra.[/bold red] "
            "Install it with: pip install -e '.[web]' (or '.[web,gemini]' for real-model mode)."
        )
        sys.exit(1)

    console.print(f"[bold]Injection Playground[/bold] starting at http://{host}:{port}")
    uvicorn.run("agent_sandbox.web.app:create_app", factory=True, host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()
