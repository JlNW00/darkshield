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
from pydantic import BaseModel, field_validator
from urllib.parse import urlparse

from ..agents.browser_agent import DarkPatternAgent, AuditResult
from ..agents.classifier import DarkPatternClassifier
from ..config import settings
from ..services.storage import storage

logger = logging.getLogger("darkshield.routes.audit")

router = APIRouter(prefix="/api/v1", tags=["audit"])

# ------------------------------------------------------------------------------
# In-memory tracking for active audits and WebSocket connections
# ------------------------------------------------------------------------------
active_audits: dict[str, AuditResult] = {}
audit_connections: dict[str, list[WebSocket]] = {}
_audit_semaphore = asyncio.Semaphore(settings.max_concurrent_audits)

# ------------------------------------------------------------------------------
# Request / Response Models
# ------------------------------------------------------------------------------
class AuditRequest(BaseModel):
    url: str
    scenarios: Optional[list[str]] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must start with http:// or https://")
        if not parsed.netloc:
            raise ValueError("URL must have a valid domain")
        return v

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

# ------------------------------------------------------------------------------
# WebSocket event broadcaster
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# Core audit pipeline
# ------------------------------------------------------------------------------
async def run_audit_pipeline(audit_id: str, url: str, scenarios: Optional[list[str]] = None):
    """
    Full audit pipeline:
    1. Launch Nova Act browser agent to detect patterns
    2. Classify each finding with Nova 2 Lite via Bedrock
    3. Save screenshots and results to local storage
    """
    async with _audit_semaphore:
        try:
            await broadcast_event(audit_id, {
                "type": "pipeline_started",
                "audit_id": audit_id,
                "url": url,
                "message": "Initializing dark pattern detection agent...",
            })

            # Phase 1: Browser Agent
            # on_event callback from browser agent is synchronous (called from thread)
            # We need to schedule coroutines back on the event loop
            loop = asyncio.get_event_loop()

            def on_browser_event(event: dict):
                asyncio.run_coroutine_threadsafe(
                    broadcast_event(audit_id, event), loop
                )

            agent = DarkPatternAgent(api_key=settings.nova_act_api_key)
            scenario_results = await agent.run_all_scenarios(url, scenarios, on_event=on_browser_event)

            # Update in-memory state
            audit = active_audits[audit_id]
            audit.scenarios = scenario_results

            # Build flat findings list for classification
            all_findings = []
            for sr in scenario_results:
                for i, f in enumerate(sr.findings):
                    pid = f"{audit_id}_{sr.scenario}_{i}"

                    # Save screenshot if present
                    if f.screenshot_b64:
                        storage.save_screenshot(audit_id, f"{sr.scenario}_{i}", f.screenshot_b64)

                    all_findings.append({
                        "pattern_id": pid,
                        "pattern_type": f.pattern_type,
                        "description": f.description,
                        "severity": f.severity,
                        "element_text": f.element_text or "",
                        "scenario": sr.scenario,
                    })

            # Phase 2: Classification
            if all_findings:
                await broadcast_event(audit_id, {
                    "type": "classification_started",
                    "message": f"Classifying {len(all_findings)} findings with AI...",
                })

                classifier = DarkPatternClassifier(
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                    region=settings.aws_region,
                    model_id=settings.bedrock_model_id,
                )

                def on_classify_event(event: dict):
                    asyncio.run_coroutine_threadsafe(
                        broadcast_event(audit_id, event), loop
                    )

                classifications = await classifier.classify_all(all_findings, on_event=on_classify_event)

                await broadcast_event(audit_id, {
                    "type": "classification_completed",
                    "classified": len(classifications),
                })
            else:
                classifications = []

            # Phase 3: Finalize
            audit.total_patterns = len(all_findings)
            audit.risk_score = audit.compute_risk_score()
            audit.status = "completed"
            audit.completed_at = datetime.now(timezone.utc).isoformat()

            # Build serializable scenarios for storage
            scenarios_data = []
            for sr in scenario_results:
                scenarios_data.append({
                    "scenario_name": sr.scenario,
                    "status": sr.status,
                    "duration_seconds": sr.duration_seconds,
                    "patterns_found": [
                        {
                            "pattern_id": f"{audit_id}_{sr.scenario}_{i}",
                            "pattern_type": f.pattern_type,
                            "description": f.description,
                            "severity": f.severity,
                            "element_text": f.element_text,
                        }
                        for i, f in enumerate(sr.findings)
                    ],
                })

            audit_data = {
                "audit_id": audit_id,
                "target_url": url,
                "status": "completed",
                "total_patterns": audit.total_patterns,
                "risk_score": audit.risk_score,
                "started_at": audit.started_at,
                "completed_at": audit.completed_at,
                "scenarios": scenarios_data,
                "classifications": classifications,
            }

            storage.save_audit(audit_id, audit_data)

            await broadcast_event(audit_id, {
                "type": "pipeline_completed",
                "audit_id": audit_id,
                "total_patterns": audit.total_patterns,
                "risk_score": audit.risk_score,
                "message": f"Audit complete: {audit.total_patterns} patterns found",
            })

        except Exception as e:
            logger.exception(f"Audit pipeline failed: {e}")
            if audit_id in active_audits:
                active_audits[audit_id].status = "failed"
            try:
                storage.save_audit(audit_id, {
                    "audit_id": audit_id,
                    "target_url": url,
                    "status": "failed",
                    "error": str(e),
                    "total_patterns": 0,
                    "risk_score": 0,
                    "scenarios": [],
                    "classifications": [],
                })
            except Exception:
                logger.exception("Failed to persist error audit")
            await broadcast_event(audit_id, {
                "type": "pipeline_error",
                "error": str(e),
            })

# ------------------------------------------------------------------------------
# REST Endpoints
# ------------------------------------------------------------------------------
@router.post("/audit", response_model=AuditResponse)
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks):
    """Start a new dark pattern audit."""
    audit_id = str(uuid.uuid4())

    audit = AuditResult(
        audit_id=audit_id,
        target_url=request.url,
        status="running",
    )
    active_audits[audit_id] = audit
    audit_connections[audit_id] = []

    background_tasks.add_task(run_audit_pipeline, audit_id, request.url, request.scenarios)

    return AuditResponse(
        audit_id=audit_id,
        status="running",
        message=f"Audit started for {request.url}",
    )


@router.get("/audit/{audit_id}", response_model=AuditStatusResponse)
async def get_audit_status(audit_id: str):
    """Get the current status of an audit."""
    # Check in-memory first
    if audit_id in active_audits:
        audit = active_audits[audit_id]
        return AuditStatusResponse(
            audit_id=audit_id,
            target_url=audit.target_url,
            status=audit.status,
            total_patterns=audit.total_patterns,
            risk_score=audit.risk_score,
            started_at=audit.started_at,
            completed_at=audit.completed_at,
        )

    # Fall back to storage
    audit_data = storage.load_audit(audit_id)
    if audit_data is None:
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


@router.get("/audit/{audit_id}/patterns")
async def get_audit_patterns(audit_id: str):
    """Get all patterns and classifications for a completed audit."""
    audit_data = storage.load_audit(audit_id)
    if audit_data is None:
        # Check in-memory
        if audit_id not in active_audits:
            raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")
        audit = active_audits[audit_id]
        return {"audit_id": audit_id, "patterns": [], "classifications": []}

    return {
        "audit_id": audit_id,
        "patterns": [
            p
            for s in audit_data.get("scenarios", [])
            for p in s.get("patterns_found", [])
        ],
        "classifications": audit_data.get("classifications", []),
    }


@router.get("/audits")
async def list_audits():
    """List all audits (in-memory + storage)."""
    audits = []

    # In-memory active audits
    for audit_id, audit in active_audits.items():
        audits.append({
            "audit_id": audit_id,
            "target_url": audit.target_url,
            "status": audit.status,
            "total_patterns": audit.total_patterns,
            "risk_score": audit.risk_score,
            "started_at": audit.started_at,
        })

    # Completed audits from storage (not already in memory)
    stored = storage.list_audits()
    in_memory_ids = set(active_audits.keys())
    for audit_data in stored:
        if audit_data.get("audit_id") not in in_memory_ids:
            audits.append({
                "audit_id": audit_data.get("audit_id", ""),
                "target_url": audit_data.get("target_url", ""),
                "status": audit_data.get("status", ""),
                "total_patterns": audit_data.get("total_patterns", 0),
                "risk_score": audit_data.get("risk_score", 0.0),
                "started_at": audit_data.get("started_at", ""),
            })

    return {"audits": audits}


# ------------------------------------------------------------------------------
# WebSocket
# ------------------------------------------------------------------------------
@router.websocket("/ws/audit/{audit_id}")
async def audit_websocket(websocket: WebSocket, audit_id: str):
    """WebSocket endpoint for real-time audit events."""
    await websocket.accept()

    if audit_id not in audit_connections:
        audit_connections[audit_id] = []
    audit_connections[audit_id].append(websocket)

    try:
        # Send current audit state if already running
        if audit_id in active_audits:
            audit = active_audits[audit_id]
            await websocket.send_json({
                "type": "audit_started",
                "audit_id": audit_id,
                "url": audit.target_url,
                "scenarios": [s.scenario for s in audit.scenarios],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        # Keep connection alive with heartbeat
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "keepalive"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error for audit {audit_id}: {e}")
    finally:
        if audit_id in audit_connections:
            try:
                audit_connections[audit_id].remove(websocket)
            except ValueError:
                pass
