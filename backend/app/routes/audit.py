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
from pydantic import BaseModel, HttpUrl

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
        agent = DarkPatternAgent(nova_act_api_key=settings.nova_act_api_key)

        async def on_agent_event(event: dict):
            await broadcast_event(audit_id, event)

        audit_result = await agent.run_audit(
            url=url,
            audit_id=audit_id,
            scenarios=scenarios,
            on_event=on_agent_event,
        )

        active_audits[audit_id] = audit_result

        # Save screenshots from findings
        for scenario in audit_result.scenarios:
            for pattern in scenario.patterns_found:
                if pattern.screenshot_b64:
                    path = storage.save_screenshot(
                        audit_id=audit_id,
                        name=f"{pattern.scenario}_{pattern.pattern_id}",
                        image_b64=pattern.screenshot_b64,
                    )
                    pattern.screenshot_path = path
                    pattern.screenshot_b64 = None  # Free memory

        await broadcast_event(audit_id, {
            "type": "classification_started",
            "audit_id": audit_id,
            "message": f"Classifying {audit_result.total_patterns} detected patterns with AI...",
        })

        # Phase 2: Classification
        all_patterns = [
            p for s in audit_result.scenarios for p in s.patterns_found
        ]

        classifications = []
        if all_patterns:
            try:
                classifier = DarkPatternClassifier(
                    aws_region=settings.aws_region,
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                )

                pattern_dicts = [
                    {
                        "pattern_id": p.pattern_id,
                        "category": p.category.value if hasattr(p.category, "value") else p.category,
                        "description": p.description,
                        "evidence": p.evidence,
                        "screenshot_b64": p.screenshot_b64,
                    }
                    for p in all_patterns
                ]

                classifications = await classifier.classify_batch(pattern_dicts)

                await broadcast_event(audit_id, {
                    "type": "classification_completed",
                    "audit_id": audit_id,
                    "classified": len(classifications),
                })

            except Exception as exc:
                logger.exception("Classification pipeline failed")
                await broadcast_event(audit_id, {
                    "type": "classification_error",
                    "audit_id": audit_id,
                    "error": str(exc),
                    "message": "Classification failed - using browser agent's raw findings",
                })

        # Phase 3: Save results
        result_data = audit_result.to_dict()
        result_data["classifications"] = [c.to_dict() for c in classifications]

        storage.save_audit(audit_id, result_data)

        await broadcast_event(audit_id, {
            "type": "pipeline_completed",
            "audit_id": audit_id,
            "total_patterns": audit_result.total_patterns,
            "risk_score": audit_result.risk_score,
            "message": f"Audit complete. Found {audit_result.total_patterns} dark patterns. Risk score: {audit_result.risk_score}/10",
        })

    except Exception as exc:
        logger.exception("Audit pipeline failed for %s", url)
        await broadcast_event(audit_id, {
            "type": "pipeline_error",
            "audit_id": audit_id,
            "error": str(exc),
            "message": f"Audit failed: {exc}",
        })

        # Save error state
        storage.save_audit(audit_id, {
            "audit_id": audit_id,
            "target_url": url,
            "status": "failed",
            "error": str(exc),
            "started_at": datetime.now(timezone.utc).isoformat(),
        })

# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------
@router.post("/audit", response_model=AuditResponse)
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks):
    """Start a new dark pattern audit."""
    # Validate
    config_warnings = settings.validate()
    if any("NOVA_ACT_API_KEY" in w for w in config_warnings):
        raise HTTPException(
            status_code=503,
            detail="NOVA_ACT_API_KEY not configured. Set it in your .env file.",
        )

    # Check concurrent audit limit
    running = sum(1 for a in active_audits.values() if a.status == "running")
    if running >= settings.max_concurrent_audits:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum {settings.max_concurrent_audits} concurrent audits. Try again later.",
        )

    audit_id = f"audit-{uuid.uuid4().hex[:12]}"

    # Launch pipeline in background
    background_tasks.add_task(run_audit_pipeline, audit_id, str(request.url), request.scenarios)

    return AuditResponse(
        audit_id=audit_id,
        status="started",
        message=f"Audit started for {request.url}. Connect to WebSocket /ws/audit/{audit_id} for real-time updates.",
    )

@router.get("/audit/{audit_id}")
async def get_audit(audit_id: str):
    """Get audit results."""
    # Check in-memory first (for running audits)
    if audit_id in active_audits:
        return active_audits[audit_id].to_dict()

    # Check storage
    result = storage.load_audit(audit_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")

    return result

@router.get("/audit/{audit_id}/patterns")
async def get_audit_patterns(audit_id: str):
    """Get just the patterns from an audit."""
    result = storage.load_audit(audit_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")

    patterns = []
    for scenario in result.get("scenarios", []):
        for pattern in scenario.get("patterns_found", []):
            pattern["scenario_name"] = scenario.get("scenario_name", "")
            patterns.append(pattern)

    return {
        "audit_id": audit_id,
        "total": len(patterns),
        "patterns": patterns,
        "classifications": result.get("classifications", []),
    }

@router.get("/audits")
async def list_audits():
    """List all completed audits."""
    return {"audits": storage.list_audits()}

@router.delete("/audit/{audit_id}")
async def delete_audit(audit_id: str):
    """Delete an audit and its data."""
    if storage.delete_audit(audit_id):
        active_audits.pop(audit_id, None)
        return {"message": f"Audit {audit_id} deleted"}
    raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")

@router.get("/audit/{audit_id}/screenshots")
async def list_audit_screenshots(audit_id: str):
    """List screenshots for an audit."""
    screenshots = storage.list_screenshots(audit_id)
    return {"audit_id": audit_id, "screenshots": screenshots}

@router.get("/health")
async def health_check():
    """Health check with config validation."""
    warnings = settings.validate()
    return {
        "status": "healthy",
        "warnings": warnings,
        "nova_act_configured": bool(settings.nova_act_api_key),
        "aws_configured": bool(settings.aws_access_key_id and settings.aws_secret_access_key),
    }

# ---------------------------------------------------------------------------
# WebSocket for real-time audit streaming
# ---------------------------------------------------------------------------
@router.websocket("/ws/audit/{audit_id}")
async def websocket_audit(websocket: WebSocket, audit_id: str):
    """WebSocket endpoint for real-time audit progress."""
    await websocket.accept()

    if audit_id not in audit_connections:
        audit_connections[audit_id] = []
    audit_connections[audit_id].append(websocket)

    logger.info("WebSocket connected for audit %s", audit_id)

    try:
        # Send current state if audit exists
        existing = storage.load_audit(audit_id)
        if existing:
            await websocket.send_json({
                "type": "audit_state",
                "audit_id": audit_id,
                "data": existing,
            })

        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Handle ping/pong
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send keepalive
                try:
                    await websocket.send_json({"type": "keepalive"})
                except Exception:
                    break

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for audit %s", audit_id)
    except Exception:
        logger.exception("WebSocket error for audit %s", audit_id)
    finally:
        if audit_id in audit_connections:
            try:
                audit_connections[audit_id].remove(websocket)
            except ValueError:
                pass
