"""
DarkShield Audit Routes - Full orchestration pipeline.
Wires Nova Act browser agent + Nova 2 Lite classifier + storage.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from pydantic import BaseModel

from ..agents.browser_agent import DarkPatternAgent, AuditResult
from ..agents.classifier import DarkPatternClassifier
from ..config import settings
from ..services.storage import storage

logger = logging.getLogger("darkshield.routes.audit")

router = APIRouter(prefix="/api/v1", tags=["audit"])

# ---------------------------------------------------------------------------
# In-memory tracking for active audits and WebSocket connections
# ---------------------------------------------------------------------------
active_audits: dict[str, AuditResult] = {}
audit_connections: dict[str, list[WebSocket]] = {}

# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------
class AuditRequest(BaseModel):
    url: str
    scenarios: Optional[list[str]] = None

class AuditResponse(BaseModel):
    audit_id: str
    status: str
    message: str

class AuditStatusResponse(BaseModel):
    audit_id: str
    target_url: str
    status: str
    total_patterns: int
    risk_score: float
    started_at: str
    completed_at: Optional[str] = None

# ---------------------------------------------------------------------------
# WebSocket event broadcaster
# ---------------------------------------------------------------------------
async def broadcast_event(audit_id: str, event: dict):
    """Send event to all WebSocket connections for this audit."""
    connections = audit_connections.get(audit_id, [])
    event["timestamp"] = datetime.now(timezone.utc).isoformat()

    dead = []
    for ws in connections:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)

    for ws in dead:
        connections.remove(ws)

# ---------------------------------------------------------------------------
# Core audit pipeline
# ---------------------------------------------------------------------------
async def run_audit_pipeline(audit_id: str, url: str, scenarios: Optional[list[str]] = None):
    """
    Full audit pipeline:
    1. Launch Nova Act browser agent to detect patterns
    2. Classify each finding with Nova 2 Lite via Bedrock
    3. Save screenshots and results to local storage
    """
    try:
        await broadcast_event(audit_id, {
            "type": "pipeline_started",
            "audit_id": audit_id,
            "url": url,
            "message": "Initializing dark pattern detection agent...",
        })

        # Phase 1: Browser Agent
        # on_event callback from browser_agent is sync-called inside asyncio.to_thread,
        # so we wrap it with asyncio.run_coroutine_threadsafe to safely schedule the
        # coroutine back onto the main event loop.
        loop = asyncio.get_event_loop()

        def on_event_sync(event: dict):
            asyncio.run_coroutine_threadsafe(broadcast_event(audit_id, event), loop)

        agent = DarkPatternAgent(api_key=settings.nova_act_api_key)

        results = await agent.run_all_scenarios(
            url=url,
            scenarios=scenarios,
            on_event=on_event_sync,
        )

        # Collect all Finding instances from all scenario results
        all_raw_findings = []
        for scenario_result in results:
            all_raw_findings.extend(scenario_result.findings)

        await broadcast_event(audit_id, {
            "type": "classification_started",
            "audit_id": audit_id,
            "message": f"Classifying {len(all_raw_findings)} findings with AI...",
        })

        # Phase 2: Classify findings (classify_batch accepts Finding instances)
        classifier = DarkPatternClassifier(
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            region_name=settings.aws_region,
        )

        classified_findings = await classifier.classify_batch(all_raw_findings)
        # classified_findings is a list of plain dicts

        await broadcast_event(audit_id, {
            "type": "classification_completed",
            "audit_id": audit_id,
            "classified": len(classified_findings),
        })

        # Phase 3: Compute risk score (works on list of dicts)
        risk_score = _compute_risk_score(classified_findings)

        # Phase 4: Save to storage
        audit_data = {
            "audit_id": audit_id,
            "target_url": url,
            "status": "completed",
            "findings": classified_findings,
            "risk_score": risk_score,
            "total_patterns": len(classified_findings),
            "started_at": active_audits[audit_id].started_at if audit_id in active_audits else "",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "scenario_results": [
                {
                    "scenario_name": r.scenario,
                    "status": r.status,
                    "duration_seconds": r.duration_seconds,
                    "patterns_found": [
                        {
                            "pattern_type": f.pattern_type,
                            "severity": f.severity,
                            "description": f.description,
                        }
                        for f in r.findings
                    ],
                }
                for r in results
            ],
        }

        storage.save_audit(audit_id, audit_data)

        # Update in-memory state
        if audit_id in active_audits:
            active_audits[audit_id].status = "completed"
            active_audits[audit_id].findings = classified_findings
            active_audits[audit_id].risk_score = risk_score
            active_audits[audit_id].completed_at = audit_data["completed_at"]

        await broadcast_event(audit_id, {
            "type": "pipeline_completed",
            "audit_id": audit_id,
            "total_patterns": len(classified_findings),
            "risk_score": risk_score,
            "message": f"Audit complete. Found {len(classified_findings)} dark patterns.",
        })

    except Exception as e:
        logger.exception("Audit pipeline failed for %s", audit_id)
        if audit_id in active_audits:
            active_audits[audit_id].status = "failed"
        await broadcast_event(audit_id, {
            "type": "pipeline_error",
            "audit_id": audit_id,
            "error": str(e),
            "message": f"Audit failed: {e}",
        })

def _compute_risk_score(findings: list) -> float:
    """Compute 0-100 risk score from classified findings (list of dicts)."""
    if not findings:
        return 0.0
    severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    total = sum(severity_weights.get(f.get("severity", "low"), 1) for f in findings)
    max_possible = len(findings) * 10
    return round((total / max_possible) * 100, 1) if max_possible > 0 else 0.0

# ---------------------------------------------------------------------------
# HTTP Endpoints
# ---------------------------------------------------------------------------
@router.post("/audit", response_model=AuditResponse)
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks):
    """Start a new dark pattern audit."""
    audit_id = str(uuid.uuid4())

    # Validate config
    missing = settings.validate()
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"Missing required configuration: {', '.join(missing)}"
        )

    # Track audit
    active_audits[audit_id] = AuditResult(
        audit_id=audit_id,
        target_url=request.url,
        status="running",
    )

    background_tasks.add_task(run_audit_pipeline, audit_id, request.url, request.scenarios)

    return AuditResponse(
        audit_id=audit_id,
        status="started",
        message=f"Audit started for {request.url}",
    )

@router.get("/audit/{audit_id}", response_model=AuditStatusResponse)
async def get_audit_status(audit_id: str):
    """Get current status of an audit."""
    # Check in-memory first
    if audit_id in active_audits:
        result = active_audits[audit_id]
        return AuditStatusResponse(
            audit_id=audit_id,
            target_url=result.target_url,
            status=result.status,
            total_patterns=len(result.findings),
            risk_score=result.risk_score,
            started_at=result.started_at,
            completed_at=result.completed_at,
        )

    # Fall back to storage
    audit_data = storage.load_audit(audit_id)
    if not audit_data:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")

    return AuditStatusResponse(
        audit_id=audit_id,
        target_url=audit_data.get("target_url", ""),
        status=audit_data.get("status", "unknown"),
        total_patterns=audit_data.get("total_patterns", 0),
        risk_score=audit_data.get("risk_score", 0.0),
        started_at=audit_data.get("started_at", ""),
        completed_at=audit_data.get("completed_at"),
    )

@router.get("/audits")
async def list_audits():
    """List all audits."""
    return storage.list_audits()

# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------
@router.websocket("/ws/audit/{audit_id}")
async def audit_websocket(websocket: WebSocket, audit_id: str):
    """WebSocket endpoint for real-time audit progress."""
    await websocket.accept()

    if audit_id not in audit_connections:
        audit_connections[audit_id] = []
    audit_connections[audit_id].append(websocket)

    try:
        # Send current state if audit exists
        if audit_id in active_audits:
            result = active_audits[audit_id]
            await websocket.send_json({
                "type": "connected",
                "audit_id": audit_id,
                "status": result.status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "keepalive"})
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    finally:
        if audit_id in audit_connections:
            audit_connections[audit_id] = [
                ws for ws in audit_connections[audit_id] if ws != websocket
            ]
