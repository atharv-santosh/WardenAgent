"""FastAPI app for the Injection Playground: the interactive front end to agent_sandbox."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from agent_sandbox.redteam.corpus import ATTACK_CASES, BENIGN_CASES
from agent_sandbox.web import runs
from agent_sandbox.web.pricing import DEFAULT_MODEL, SUPPORTED_MODELS, rough_precall_estimate

_HERE = Path(__file__).resolve().parent


class PlaygroundRequest(BaseModel):
    trusted_task: str
    untrusted_text: str = ""
    carrier_tool: str | None = None
    model: str = DEFAULT_MODEL
    simulate: bool = True
    declassify_via: str | None = None


class ApprovalDecisionRequest(BaseModel):
    approval_id: str
    approved: bool
    reason: str = ""
    decided_by: str = "operator"


class CorpusEstimateRequest(BaseModel):
    category: str | None = None
    model: str = DEFAULT_MODEL
    include_benign: bool = True
    limit: int | None = None


class CorpusRunRequest(BaseModel):
    category: str | None = None
    model: str = DEFAULT_MODEL
    simulate: bool = True
    declassify_via: str | None = None
    include_benign: bool = True
    limit: int | None = None


def create_app() -> FastAPI:
    app = FastAPI(title="Injection Playground")
    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")
    templates = Jinja2Templates(directory=str(_HERE / "templates"))


    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Any:
        return templates.TemplateResponse(request, "index.html", {})


    @app.get("/api/status")
    def status() -> dict[str, Any]:
        try:
            from agent_sandbox.gemini_adapter import (
                credentials_available,
                resolve_location,
                resolve_project,
            )

            creds = credentials_available()
            project = resolve_project()
            location = resolve_location()
        except ImportError:
            creds = False
            project = None
            location = None
        return {
            "credentials_available": creds,
            "project": project,
            "location": location,
            "models": SUPPORTED_MODELS,
            "default_model": DEFAULT_MODEL,
            "policy_path": runs.DEFAULT_POLICY_PATH,
            "note": (
                "Real-model mode calls Vertex AI Gemini using local Application Default "
                "Credentials for the agent's *decisions* only. Every tool the agent can call "
                "(send_email, http_post, delete_file, grant_admin, run_shell, fetch_url, "
                "read_email, read_file) always runs against an in-memory simulated world -- "
                "this app never performs real network egress or a real side effect."
            ),
        }


    @app.get("/api/corpus")
    def corpus() -> dict[str, Any]:
        def to_case(s: Any) -> dict[str, Any]:
            first = s.untrusted_inputs[0] if s.untrusted_inputs else None
            untrusted_text = "\n\n".join(i.text for i in s.untrusted_inputs) if s.untrusted_inputs else ""
            return {
                "id": s.id,
                "category": s.category,
                "is_benign": s.is_benign,
                "trusted_task": s.trusted_task,
                "untrusted_text": untrusted_text,
                "carrier_tool": first.carrier_tool if first else None,
                "notes": s.notes,
            }

        return {
            "attack_cases": [to_case(s) for s in ATTACK_CASES],
            "benign_cases": [to_case(s) for s in BENIGN_CASES],
            "categories": runs.corpus_categories(),
        }


    @app.post("/api/playground/run")
    def playground_run(req: PlaygroundRequest) -> dict[str, str]:
        if not req.trusted_task.strip():
            raise HTTPException(400, "trusted_task must not be empty")
        if req.declassify_via not in (None, "approval", "quarantine"):
            raise HTTPException(400, "declassify_via must be null, 'approval', or 'quarantine'")
        if req.model not in SUPPORTED_MODELS:
            raise HTTPException(400, f"model must be one of {SUPPORTED_MODELS}")

        run = runs.new_interactive_run()
        thread = threading.Thread(
            target=runs.run_playground,
            kwargs=dict(
                run=run,
                trusted_task=req.trusted_task,
                untrusted_text=req.untrusted_text,
                carrier_tool=req.carrier_tool,
                model=req.model,
                simulate=req.simulate,
                declassify_via=req.declassify_via,
            ),
            daemon=True,
        )
        thread.start()
        return {"run_id": run.run_id}

    @app.get("/api/playground/{run_id}/events")
    def playground_events(run_id: str) -> StreamingResponse:
        run = runs.get_interactive_run(run_id)
        if run is None:
            raise HTTPException(404, "unknown run_id")
        return StreamingResponse(_sse(run.queue), media_type="text/event-stream")

    @app.post("/api/playground/{run_id}/approve")
    def playground_approve(run_id: str, req: ApprovalDecisionRequest) -> dict[str, bool]:
        run = runs.get_interactive_run(run_id)
        if run is None:
            raise HTTPException(404, "unknown run_id")
        ok = run.resolve_approval(req.approval_id, req.approved, req.reason, req.decided_by)
        if not ok:
            raise HTTPException(404, "unknown or already-resolved approval_id")
        return {"ok": True}


    @app.post("/api/corpus/estimate")
    def corpus_estimate(req: CorpusEstimateRequest) -> dict[str, Any]:
        cases = runs.corpus_cases(req.category, req.include_benign)
        if req.limit is not None:
            cases = cases[: req.limit]
        num_calls = 0
        for s in cases:
            num_calls += 2 + len(s.untrusted_inputs)
        estimate = rough_precall_estimate(req.model, num_calls)
        estimate["num_scenarios"] = len(cases)
        return estimate

    @app.post("/api/corpus/run")
    def corpus_run(req: CorpusRunRequest) -> dict[str, str]:
        if req.declassify_via not in (None, "approval", "quarantine"):
            raise HTTPException(400, "declassify_via must be null, 'approval', or 'quarantine'")
        if req.model not in SUPPORTED_MODELS:
            raise HTTPException(400, f"model must be one of {SUPPORTED_MODELS}")
        run = runs.new_corpus_run()
        thread = threading.Thread(
            target=runs.run_corpus_job,
            kwargs=dict(
                run=run,
                category=req.category,
                model=req.model,
                simulate=req.simulate,
                declassify_via=req.declassify_via,
                include_benign=req.include_benign,
                limit=req.limit,
            ),
            daemon=True,
        )
        thread.start()
        return {"run_id": run.run_id}

    @app.get("/api/corpus/run/{run_id}/events")
    def corpus_run_events(run_id: str) -> StreamingResponse:
        run = runs.get_corpus_run(run_id)
        if run is None:
            raise HTTPException(404, "unknown run_id")
        return StreamingResponse(_sse(run.queue), media_type="text/event-stream")

    return app


def _sse(sse_queue: "runs.SSEQueue"):
    for event_type, payload in sse_queue.stream():
        yield f"event: {event_type}\ndata: {json.dumps(payload, default=str)}\n\n"
