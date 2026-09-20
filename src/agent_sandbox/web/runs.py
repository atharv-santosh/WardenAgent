"""Background execution + live event plumbing for the Injection Playground."""

from __future__ import annotations

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agent_sandbox.agent import Scenario, UntrustedInput, run_naive, run_sandboxed
from agent_sandbox.approval import ApprovalCallback, ApprovalDecision, ApprovalRequest
from agent_sandbox.events import EventLog
from agent_sandbox.llm_sim import naive_decide, sandboxed_decide
from agent_sandbox.policy import Policy, PolicyEngine
from agent_sandbox.quarantine import Digest
from agent_sandbox.quarantine import extract as sim_extract
from agent_sandbox.redteam.corpus import ATTACK_CASES, BENIGN_CASES
from agent_sandbox.web.pricing import estimate_cost_usd
from agent_sandbox.web.serialize import digest_to_dict, run_result_to_dict

DEFAULT_POLICY_PATH = str(Path(__file__).resolve().parents[3] / "policies" / "default.yaml")

CARRIER_DEFAULTS: dict[str, dict[str, str]] = {
    "fetch_url": {"url": "https://docs.trusted.example/playground"},
    "read_email": {"msg_id": "playground-msg-1"},
    "read_file": {"path": "/workspace/docs/playground.txt"},
}


class SSEQueue:
    """A blocking queue of ``(event_type, payload)`` pairs one HTTP request reads from with a generator while a background thread writes into it."""

    def __init__(self) -> None:
        self._q: queue.Queue[tuple[str, dict[str, Any]] | None] = queue.Queue()

    def put(self, event_type: str, payload: dict[str, Any]) -> None:
        self._q.put((event_type, payload))

    def close(self) -> None:
        self._q.put(None)

    def stream(self):
        while True:
            item = self._q.get()
            if item is None:
                return
            yield item


@dataclass(slots=True)
class PendingApproval:
    event: threading.Event = field(default_factory=threading.Event)
    decision: ApprovalDecision | None = None


class InteractiveRun:
    """One live playground run: background thread + SSE queue + approval bridge."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.queue = SSEQueue()
        self.status = "running"
        self.created_at = time.time()
        self._lock = threading.Lock()
        self._pending: dict[str, PendingApproval] = {}
        self._approval_seq = 0

    def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        self.queue.put(event_type, payload)

    def finish(self, status: str) -> None:
        self.status = status
        self.queue.close()

    def make_approval_callback(self) -> ApprovalCallback:
        """Bridge agent_sandbox.approval.ApprovalCallback (a blocking, synchronous function the agent loop calls in-thread) to a human clicking Approve/Deny in the browser."""

        def callback(request: ApprovalRequest) -> ApprovalDecision:
            with self._lock:
                self._approval_seq += 1
                approval_id = f"appr-{self._approval_seq}"
                pending = PendingApproval()
                self._pending[approval_id] = pending

            self.emit("approval_request", {"approval_id": approval_id, **request.to_dict()})

            got_it = pending.event.wait(timeout=900)
            with self._lock:
                self._pending.pop(approval_id, None)

            if not got_it or pending.decision is None:
                decision = ApprovalDecision(
                    approved=False,
                    reason="no response from approver within the time limit; fail closed",
                    decided_by="system",
                )
                self.emit(
                    "approval_decision",
                    {"approval_id": approval_id, "approved": False, "reason": decision.reason, "decided_by": "system"},
                )
                return decision
            return pending.decision

        return callback

    def resolve_approval(self, approval_id: str, approved: bool, reason: str, decided_by: str) -> bool:
        with self._lock:
            pending = self._pending.get(approval_id)
            if pending is None:
                return False
            pending.decision = ApprovalDecision(
                approved=approved,
                reason=reason or ("approved by operator" if approved else "denied by operator"),
                decided_by=decided_by or "operator",
            )
            pending.event.set()
        self.emit(
            "approval_decision",
            {"approval_id": approval_id, "approved": approved, "reason": reason, "decided_by": decided_by},
        )
        return True


_POLICY = Policy.from_file(DEFAULT_POLICY_PATH)


def _build_scenario(
    trusted_task: str,
    untrusted_text: str,
    carrier_tool: str | None,
    scenario_id: str = "playground",
) -> Scenario:
    inputs: list[UntrustedInput] = []
    if untrusted_text.strip():
        if carrier_tool in CARRIER_DEFAULTS:
            inputs.append(
                UntrustedInput(
                    text=untrusted_text,
                    carrier_tool=carrier_tool,
                    carrier_args=dict(CARRIER_DEFAULTS[carrier_tool]),
                )
            )
        else:
            inputs.append(
                UntrustedInput(text=untrusted_text, carrier_tool=None, origin_label="pasted/forwarded content")
            )

    from agent_sandbox.web.serialize import SINK_TOOLS

    def check_success(world: Any) -> bool:
        return any(name in SINK_TOOLS for name, _args in world.call_log)

    return Scenario(
        id=scenario_id,
        category="playground",
        trusted_task=trusted_task,
        untrusted_inputs=inputs,
        check_success=check_success,
        notes="Interactive playground scenario composed in the browser.",
    )


def _classify_model_error(exc: Exception) -> str:
    message = str(exc)
    lower = message.lower()
    if "429" in message or "resource_exhausted" in lower or "quota" in lower:
        return (
            "The model provider rate-limited this request (HTTP 429 / RESOURCE_EXHAUSTED). "
            "Wait a moment and try again, or switch to a lighter model."
        )
    if "permission" in lower or "unauthenticated" in lower or "401" in message or "403" in message:
        return (
            "Authentication to Vertex AI failed. Run `gcloud auth application-default login` "
            "and confirm the ADC project has the Vertex AI API enabled, then retry."
        )
    if "timeout" in lower or "deadline" in lower:
        return "The request to the model timed out. This is usually transient -- try again."
    if "not found" in lower or "404" in message:
        return (
            f"The model id was not found or is not servable in this project/location "
            f"({message[:200]}). Pick a different model."
        )
    return f"The live model call failed: {message[:300]}"


def _decide_and_extract_fns(simulate: bool, client: Any, model: str, naive_rec: Any, sbx_rec: Any):
    if simulate:
        return naive_decide, sandboxed_decide, sim_extract
    from agent_sandbox.gemini_adapter import (
        make_live_naive_decide,
        make_live_quarantine_extract,
        make_live_sandboxed_decide,
    )

    return (
        make_live_naive_decide(client, model, recorder=naive_rec),
        make_live_sandboxed_decide(client, model, recorder=sbx_rec),
        make_live_quarantine_extract(client, model, recorder=sbx_rec),
    )


def run_playground(
    run: InteractiveRun,
    *,
    trusted_task: str,
    untrusted_text: str,
    carrier_tool: str | None,
    model: str,
    simulate: bool,
    declassify_via: str | None,
) -> None:
    """The background-thread body for one interactive playground run."""
    try:
        scenario = _build_scenario(trusted_task, untrusted_text, carrier_tool)
        run.emit("scenario", {"trusted_task": trusted_task, "untrusted_text": untrusted_text, "carrier_tool": carrier_tool})

        client = None
        if not simulate:
            from agent_sandbox.gemini_adapter import GeminiUnavailable, build_client, credentials_available

            if not credentials_available():
                run.emit(
                    "fatal_error",
                    {
                        "message": (
                            "No usable Google Application Default Credentials were found, so a real-model "
                            "run cannot proceed. Run `gcloud auth application-default login`, or switch the "
                            "mode toggle to 'Simulator' to use the deterministic offline brain (no credentials needed)."
                        )
                    },
                )
                run.finish("error")
                return
            try:
                client = build_client()
            except GeminiUnavailable as exc:
                run.emit("fatal_error", {"message": str(exc)})
                run.finish("error")
                return

        naive_rec = sbx_rec = None
        if not simulate:
            from agent_sandbox.gemini_adapter import CallRecorder

            naive_rec = CallRecorder()
            sbx_rec = CallRecorder()

        naive_decide_fn, sandboxed_decide_fn, extract_fn = _decide_and_extract_fns(
            simulate, client, model, naive_rec, sbx_rec
        )

        captured_digests: list[Digest] = []

        def extract_wrapper(raw_text: str) -> Digest:
            digest = extract_fn(raw_text)
            captured_digests.append(digest)
            return digest

        run.emit("phase", {"phase": "naive", "status": "running"})
        naive_log = EventLog()
        try:
            naive_result = run_naive(scenario, decide_fn=naive_decide_fn, event_log=naive_log)
        except Exception as exc:  # noqa: BLE001
            run.emit("fatal_error", {"message": _classify_model_error(exc), "phase": "naive"})
            run.finish("error")
            return
        run.emit("phase_result", {"phase": "naive", **run_result_to_dict(naive_result)})

        run.emit("phase", {"phase": "sandboxed", "status": "running"})
        engine = PolicyEngine(_POLICY)
        sbx_log = EventLog()
        try:
            sandboxed_result = run_sandboxed(
                scenario,
                engine,
                approval_callback=run.make_approval_callback(),
                declassify_via=declassify_via,
                decide_fn=sandboxed_decide_fn,
                extract_fn=extract_wrapper,
                event_log=sbx_log,
            )
        except Exception as exc:  # noqa: BLE001
            run.emit("fatal_error", {"message": _classify_model_error(exc), "phase": "sandboxed"})
            run.finish("error")
            return

        sbx_payload = run_result_to_dict(sandboxed_result)
        sbx_payload["digests"] = [digest_to_dict(d) for d in captured_digests]
        run.emit("phase_result", {"phase": "sandboxed", **sbx_payload})

        total_tokens = 0
        prompt_tokens = 0
        candidate_tokens = 0
        total_calls = 0
        if naive_rec is not None and sbx_rec is not None:
            for rec in (*naive_rec.calls, *sbx_rec.calls):
                usage = rec.get("usage", {})
                total_tokens += usage.get("total_tokens", 0)
                prompt_tokens += usage.get("prompt_tokens", 0)
                candidate_tokens += usage.get("candidates_tokens", 0)
            total_calls = len(naive_rec.calls) + len(sbx_rec.calls)
        cost = estimate_cost_usd(model, prompt_tokens, candidate_tokens) if total_calls else 0.0

        run.emit(
            "usage",
            {
                "simulate": simulate,
                "model": model,
                "total_calls": total_calls,
                "prompt_tokens": prompt_tokens,
                "output_tokens": candidate_tokens,
                "total_tokens": total_tokens,
                "estimated_cost_usd": round(cost, 6),
            },
        )
        run.emit("done", {"status": "done"})
        run.finish("done")
    except Exception as exc:  # noqa: BLE001 - last-resort: never leave the UI hanging
        run.emit("fatal_error", {"message": f"Unexpected internal error: {exc}"})
        run.finish("error")


def corpus_cases(category: str | None, include_benign: bool) -> list[Scenario]:
    cases = list(ATTACK_CASES)
    if include_benign:
        cases += list(BENIGN_CASES)
    if category:
        cases = [c for c in cases if c.category == category]
    return cases


def corpus_categories() -> list[str]:
    return sorted({c.category for c in (*ATTACK_CASES, *BENIGN_CASES)})


class CorpusRun:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.queue = SSEQueue()
        self.status = "running"

    def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        self.queue.put(event_type, payload)

    def finish(self, status: str) -> None:
        self.status = status
        self.queue.close()


def run_corpus_job(
    run: CorpusRun,
    *,
    category: str | None,
    model: str,
    simulate: bool,
    declassify_via: str | None,
    include_benign: bool,
    limit: int | None,
) -> None:
    """Stream a corpus (or one category of it) through both agent variants."""
    try:
        cases = corpus_cases(category, include_benign)
        if limit is not None:
            cases = cases[:limit]
        total = len(cases)
        run.emit("start", {"total": total, "category": category or "all", "model": model, "simulate": simulate})

        client = None
        if not simulate:
            from agent_sandbox.gemini_adapter import GeminiUnavailable, build_client, credentials_available

            if not credentials_available():
                run.emit(
                    "fatal_error",
                    {"message": "No Google Application Default Credentials found; run `gcloud auth application-default login` or switch to Simulator mode."},
                )
                run.finish("error")
                return
            try:
                client = build_client()
            except GeminiUnavailable as exc:
                run.emit("fatal_error", {"message": str(exc)})
                run.finish("error")
                return

        categories: dict[str, dict[str, int]] = {}
        naive_success_total = 0
        sandboxed_success_total = 0
        benign_total = 0
        benign_blocked = 0
        total_tokens = 0
        prompt_tokens = 0
        output_tokens = 0
        total_calls = 0

        for i, scenario in enumerate(cases, start=1):
            naive_rec = sbx_rec = None
            if not simulate:
                from agent_sandbox.gemini_adapter import CallRecorder

                naive_rec = CallRecorder()
                sbx_rec = CallRecorder()
            naive_decide_fn, sandboxed_decide_fn, extract_fn = _decide_and_extract_fns(
                simulate, client, model, naive_rec, sbx_rec
            )

            try:
                naive_result = run_naive(scenario, decide_fn=naive_decide_fn)
                engine = PolicyEngine(_POLICY)
                cb = _auto_approve_or_deny(scenario.is_benign)
                sandboxed_result = run_sandboxed(
                    scenario,
                    engine,
                    approval_callback=cb,
                    declassify_via=declassify_via,
                    decide_fn=sandboxed_decide_fn,
                    extract_fn=extract_fn,
                )
            except Exception as exc:  # noqa: BLE001
                run.emit(
                    "scenario_error",
                    {"index": i, "total": total, "scenario_id": scenario.id, "message": _classify_model_error(exc)},
                )
                continue

            if scenario.is_benign:
                benign_total += 1
                if not sandboxed_result.attack_succeeded:
                    benign_blocked += 1
            else:
                naive_success_total += int(naive_result.attack_succeeded)
                sandboxed_success_total += int(sandboxed_result.attack_succeeded)
                stats = categories.setdefault(scenario.category, {"total": 0, "naive_success": 0, "sandboxed_success": 0})
                stats["total"] += 1
                stats["naive_success"] += int(naive_result.attack_succeeded)
                stats["sandboxed_success"] += int(sandboxed_result.attack_succeeded)

            if naive_rec is not None and sbx_rec is not None:
                for rec in (*naive_rec.calls, *sbx_rec.calls):
                    usage = rec.get("usage", {})
                    total_tokens += usage.get("total_tokens", 0)
                    prompt_tokens += usage.get("prompt_tokens", 0)
                    output_tokens += usage.get("candidates_tokens", 0)
                total_calls += len(naive_rec.calls) + len(sbx_rec.calls)

            run.emit(
                "progress",
                {
                    "index": i,
                    "total": total,
                    "scenario_id": scenario.id,
                    "category": scenario.category,
                    "is_benign": scenario.is_benign,
                    "naive_attack_succeeded": naive_result.attack_succeeded,
                    "sandboxed_attack_succeeded": sandboxed_result.attack_succeeded,
                    "blocked_by": sandboxed_result.blocked_by,
                },
            )

        attack_total = sum(s["total"] for s in categories.values())
        cost = estimate_cost_usd(model, prompt_tokens, output_tokens) if total_calls else 0.0
        run.emit(
            "done",
            {
                "categories": categories,
                "overall_naive_asr": (naive_success_total / attack_total) if attack_total else 0.0,
                "overall_sandboxed_asr": (sandboxed_success_total / attack_total) if attack_total else 0.0,
                "benign_total": benign_total,
                "benign_blocked": benign_blocked,
                "false_positive_rate": (benign_blocked / benign_total) if benign_total else 0.0,
                "usage": {
                    "total_calls": total_calls,
                    "prompt_tokens": prompt_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": total_tokens,
                    "estimated_cost_usd": round(cost, 6),
                },
            },
        )
        run.finish("done")
    except Exception as exc:  # noqa: BLE001
        run.emit("fatal_error", {"message": f"Unexpected internal error: {exc}"})
        run.finish("error")


def _auto_approve_or_deny(is_benign: bool) -> ApprovalCallback:
    from agent_sandbox.approval import auto_approve, auto_deny

    return auto_approve if is_benign else auto_deny


_interactive_runs: dict[str, InteractiveRun] = {}
_corpus_runs: dict[str, CorpusRun] = {}
_registry_lock = threading.Lock()


def new_interactive_run() -> InteractiveRun:
    run = InteractiveRun(uuid.uuid4().hex[:12])
    with _registry_lock:
        _interactive_runs[run.run_id] = run
    return run


def get_interactive_run(run_id: str) -> InteractiveRun | None:
    with _registry_lock:
        return _interactive_runs.get(run_id)


def new_corpus_run() -> CorpusRun:
    run = CorpusRun(uuid.uuid4().hex[:12])
    with _registry_lock:
        _corpus_runs[run.run_id] = run
    return run


def get_corpus_run(run_id: str) -> CorpusRun | None:
    with _registry_lock:
        return _corpus_runs.get(run_id)
