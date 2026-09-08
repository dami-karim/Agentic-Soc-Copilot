"""
Week 8 — FastAPI backend for the Agentic SOC Co-Pilot.

Production API layer providing:
  - POST  /api/v1/alerts      — ingest a SIEM alert and start investigation
  - GET   /api/v1/investigations/{id} — check investigation status/result
  - POST  /api/v1/hil/{id}     — submit HIL analyst decisions
  - GET   /api/v1/metrics      — evaluation metrics summary
  - POST  /api/v1/config       — tenant configuration

Run with:  uvicorn src.api.main:app --reload --port 8000
"""
import asyncio
import uuid
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
from pathlib import Path

from src.config import load_config
from src.nodes.ingest import make_initial_input

# ── STORAGE (in-memory for demo; would be Redis/Postgres in prod) ─────────────

_investigation_store: dict[str, dict] = {}
_hil_pending: dict[str, asyncio.Future] = {}


# ── PYDANTIC SCHEMAS ──────────────────────────────────────────────────────────

class AlertIngestRequest(BaseModel):
    alert: dict = Field(..., description="Raw SIEM alert dictionary")
    org_id: str = Field(default="default", description="Tenant/organization ID")
    config_overrides: Optional[dict] = Field(default=None, description="Per-request config overrides")
    auto_approve_hil: bool = Field(default=False, description="Auto-approve HIL gates (for automated eval)")


class HILDecisionRequest(BaseModel):
    decisions: dict = Field(..., description="Analyst decisions keyed by action_key")
    analyst_id: str = Field(default="manual", description="Analyst identifier")


class FPFilterBatchRequest(BaseModel):
    alerts: list[dict] = Field(..., description="List of raw SIEM alerts to classify")
    ground_truth: list | None = Field(
        default=None,
        description="Optional aligned labels (bool, {'is_false_positive': bool}, "
                    "or 'fp'/'tp' strings) to compute accuracy metrics",
    )
    use_llm: bool = Field(default=False, description="Resolve REVIEW alerts via local LLM")


# ── APP SETUP ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Agentic SOC Co-Pilot API",
    description="Week 8 — Production API for autonomous alert triage.",
    version="1.0.0",
)


@app.on_event("startup")
async def startup():
    config_dir = Path("config")
    config_dir.mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)


# ── ENDPOINTS ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/api/v1/alerts")
async def ingest_alert(request: AlertIngestRequest, background: BackgroundTasks):
    """
    Ingest a SIEM alert and start the investigation pipeline.

    Returns immediately with a workflow_id. The investigation runs in the
    background. When it hits an HIL gate, status becomes 'awaiting_hil'.
    Use GET /api/v1/investigations/{id} to poll for results.
    """
    workflow_id = str(uuid.uuid4())[:8]

    # Load tenant config (with per-request overrides)
    config = load_config(request.org_id)
    if request.config_overrides:
        config.update(request.config_overrides)

    # Initialize state
    state = make_initial_input(request.alert)
    state["workflow_id"] = f"{request.org_id}-{workflow_id}"
    state["alert_id"] = f"alert-{workflow_id}"

    _investigation_store[workflow_id] = {
        "workflow_id": state["workflow_id"],
        "org_id": request.org_id,
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
        "config": config,
        "auto_approve_hil": request.auto_approve_hil,
    }

    # Start investigation
    background.add_task(_run_pipeline, workflow_id, state)

    return JSONResponse(
        status_code=202,
        content={
            "workflow_id": workflow_id,
            "org_id": request.org_id,
            "status": "accepted",
            "message": "Investigation started. Poll GET /api/v1/investigations/{workflow_id}",
        }
    )


@app.get("/api/v1/investigations/{workflow_id}")
async def get_investigation(workflow_id: str):
    """Get the current status or final result of an investigation."""
    record = _investigation_store.get(workflow_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Investigation {workflow_id} not found")

    if record["status"] == "completed":
        return record["result"]
    elif record["status"] == "awaiting_hil":
        return {
            "workflow_id": workflow_id,
            "status": "awaiting_hil",
            "gate": record.get("hil_gate"),
            "high_risk_actions": record.get("hil_payload", {}).get("high_risk_actions", []),
            "message": "Analyst decision required at HIL gate.",
        }
    else:
        return {
            "workflow_id": workflow_id,
            "status": record["status"],
            "message": "Investigation in progress...",
        }


@app.post("/api/v1/hil/{workflow_id}")
async def submit_hil_decision(workflow_id: str, request: HILDecisionRequest):
    """Submit analyst decisions for an awaiting investigation."""
    record = _investigation_store.get(workflow_id)
    if not record or record["status"] != "awaiting_hil":
        raise HTTPException(status_code=404, detail="No HIL gate waiting for this investigation")

    future = _hil_pending.get(workflow_id)
    if future and not future.done():
        future.set_result({
            "decisions": request.decisions,
            "analyst_id": request.analyst_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return JSONResponse(content={"status": "decision submitted", "workflow_id": workflow_id})
    else:
        return JSONResponse(content={"status": "no pending HIL gate", "workflow_id": workflow_id})


@app.post("/api/v1/fp-filter/batch")
async def fp_filter_batch(request: FPFilterBatchRequest):
    """
    Classify a batch of alerts as false positives or true positives.

    Runs the rule-based filter over every alert (fast, no LLM/DB calls) and
    returns a per-alert verdict plus a batch summary. Pass use_llm=True to
    resolve borderline (REVIEW) alerts via the local model.

    Example body:
        {"alerts": [{...}, {...}], "ground_truth": [true, false], "use_llm": false}
    """
    from src.fp_filter.batch import run_batch

    if not request.alerts:
        raise HTTPException(status_code=422, detail="alerts list must not be empty")

    if request.ground_truth is not None and len(request.ground_truth) != len(request.alerts):
        raise HTTPException(
            status_code=422,
            detail=f"ground_truth has {len(request.ground_truth)} entries but "
                   f"alerts has {len(request.alerts)}",
        )

    report = run_batch(
        request.alerts,
        ground_truth=request.ground_truth,
        use_llm=request.use_llm,
        verbose=False,
    )
    return JSONResponse(content=report)


@app.get("/api/v1/metrics")
async def get_metrics():
    """Get summary metrics across all completed investigations."""
    completed = [r for r in _investigation_store.values() if r["status"] == "completed"]
    if not completed:
        return {"message": "No completed investigations yet"}

    from src.eval.metrics import compute_mttr
    summaries = []
    for record in completed:
        result = record["result"]
        techniques = result.get("attack_techniques", [])
        event_log = result.get("event_log", [])
        summaries.append({
            "workflow_id": record["workflow_id"],
            "final_status": str(result.get("final_status")),
            "techniques": len(techniques),
            "ioCs": len(result.get("ioc_list", [])),
            "mttr_seconds": compute_mttr(event_log),
            "guardrail_flags": len(result.get("guardrail_flags", [])),
        })

    return {"total": len(summaries), "investigations": summaries}


@app.get("/api/v1/config/{org_id}")
async def get_config(org_id: str):
    """Get tenant configuration."""
    config = load_config(org_id)
    return JSONResponse(content=config)


# ── BACKGROUND PIPELINE RUNNER ─────────────────────────────────────────────────

async def _run_pipeline(workflow_id: str, state: dict):
    """Run the full investigation pipeline in the background."""
    from src.graph import build_graph

    record = _investigation_store[workflow_id]
    auto_approve = record["auto_approve_hil"]

    app_graph = build_graph(with_hil=not auto_approve)
    record["status"] = "running"

    try:
        result = await asyncio.to_thread(app_graph.invoke, state)
        record["status"] = "completed"
        record["result"] = result
    except Exception as e:
        record["status"] = "error"
        record["error"] = str(e)


if __name__ == "__main__":
    import uvicorn
    config = load_config()
    uvicorn.run(
        "src.api.main:app",
        host=config["api"]["host"],
        port=config["api"]["port"],
        reload=config["api"].get("docs_enabled", True),
    )
