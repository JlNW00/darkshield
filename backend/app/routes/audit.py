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

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel, HttpUrl

from app.config import settings
from app.services.storage import get_storage

logger = logging.getLogger("darkshield.audit")
router = APIRouter(prefix="/api/v1", tags=["audit"])


# ── Models ────────────────────────────────────────────────────────

class AuditRequest(BaseModel):
    url: str
    scenarios: Optional[list[str]] = None


class AuditStatus(BaseModel):
    audit_id: str
    status: str
    url: str
    created_at: str
    scenarios_total: int = 0
    scenarios_completed: int = 0
    findings_count: int = 0
    risk_score: Optional[float] = None


class AuditResult(BaseModel):
    audit_id: str
    status: str  # pending, running, completed, failed
    url: str
    created_at: str
    completed_at: Optional[str] = None
    scenarios: list[dict] = []
    findings: list[dict] = []
    risk_score: Optional[float] = None
    summary: Optional[dict] = None


# ── In-memory state ───────────────────────────────────────────────

active_audits: dict[str, AuditResult] = {}
audit_connections: dict[str, list[WebSocket]] = {}
# Track running count explicitly for concurrency limiting
_running_count: int = 0
_running_lock = asyncio.Lock()


# ── WebSocket event broadcasting ──────────────────────────────────

async def broadcast_event(audit_id: str, event: dict):
    """Send event to all WebSocket connections for an audit."""
    connections = audit_connections.get(audit_id, [])
    dead = []
    for ws in connections:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        connections.remove(ws)


# ── Audit pipeline ────────────────────────────────────────────────

async def run_audit_pipeline(audit_id: str, url: str, scenarios: Optional[list[str]]):
    """Main audit orchestration: browser agent -> classifier -> storage."""
    global _running_count

    audit = active_audits[audit_id]
    audit.status = "running"
    await broadcast_event(audit_id, {"type": "status", "status": "running"})

    storage = get_storage()

    try:
        # 1. Run browser agent scenarios
        from app.agents.browser_agent import DarkPatternAgent

        agent = DarkPatternAgent(api_key=settings.nova_act_api_key)

        async def on_agent_event(event: dict):
            await broadcast_event(audit_id, event)

        scenario_results = await agent.run_all_scenarios(
            url=url,
            scenarios=scenarios,
            on_event=on_agent_event,
        )

        audit.scenarios_total = len(scenario_results)

        # 2. Collect findings and classify them
        raw_findings = []
        for sr in scenario_results:
            audit.scenarios_completed += 1
            scenario_data = {
                "scenario": sr.scenario,
                "status": sr.status,
                "duration_seconds": sr.duration_seconds,
                "steps_completed": sr.steps_completed,
                "findings_count": len(sr.findings),
                "error": sr.error,
            }
            audit.scenarios.append(scenario_data)

            for finding in sr.findings:
                raw_findings.append({
                    "context": f"Scenario: {sr.scenario}. Pattern: {finding.pattern_type}. "
                               f"Description: {finding.description}. "
                               f"Element: {finding.element_text or 'N/A'}",
                    "screenshot_b64": finding.screenshot_b64,
                    "source_scenario": sr.scenario,
                    "original_severity": finding.severity,
                })

            await broadcast_event(audit_id, {
                "type": "scenario_complete",
                "scenario": sr.scenario,
                "status": sr.status,
                "findings": len(sr.findings),
            })

        # 3. Classify with Nova 2 Lite
        classified_findings = []
        if raw_findings:
            await broadcast_event(audit_id, {
                "type": "status",
                "status": "classifying",
                "message": f"Classifying {len(raw_findings)} findings...",
            })

            try:
                from app.agents.classifier import DarkPatternClassifier
                classifier = DarkPatternClassifier()
                classifications = await classifier.classify_batch(raw_findings)

                for i, cr in enumerate(classifications):
                    finding_data = {
                        "pattern_type": cr.pattern_type,
                        "category_name": cr.category_name,
                        "severity": cr.severity,
                        "confidence": cr.confidence,
                        "description": cr.description,
                        "oecd_reference": cr.oecd_reference,
                        "remediation": cr.remediation,
                        "source_scenario": raw_findings[i]["source_scenario"],
                    }

                    # Save screenshot if present
                    if raw_findings[i].get("screenshot_b64"):
                        screenshot_path = storage.save_screenshot(
                            audit_id=audit_id,
                            scenario=raw_findings[i]["source_scenario"],
                            step=cr.pattern_type,
                            data=base64.b64decode(raw_findings[i]["screenshot_b64"]),
                        )
                        finding_data["screenshot_path"] = screenshot_path

                    classified_findings.append(finding_data)

            except Exception as e:
                logger.error(f"Classification failed, using raw findings: {e}")
                for i, rf in enumerate(raw_findings):
                    classified_findings.append({
                        "pattern_type": "unclassified",
                        "category_name": "Unclassified",
                        "severity": rf["original_severity"],
                        "confidence": 0.0,
                        "description": rf["context"],
                        "oecd_reference": "N/A",
                        "remediation": "Manual review required.",
                        "source_scenario": rf["source_scenario"],
                    })

        audit.findings = classified_findings
        audit.findings_count = len(classified_findings)

        # 4. Calculate risk score
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        if classified_findings:
            total_weight = sum(
                severity_weights.get(f.get("severity", "low"), 1)
                for f in classified_findings
            )
            max_possible = len(classified_findings) * 10
            audit.risk_score = round((total_weight / max_possible) * 100, 1)
        else:
            audit.risk_score = 0.0

        # 5. Build summary
        severity_counts = {}
        category_counts = {}
        for f in classified_findings:
            sev = f.get("severity", "low")
            cat = f.get("category_name", "Unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1

        audit.summary = {
            "total_findings": len(classified_findings),
            "risk_score": audit.risk_score,
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "scenarios_run": len(scenario_results),
        }

        audit.status = "completed"
        audit.completed_at = datetime.now(timezone.utc).isoformat()

        # 6. Persist result
        storage.save_result(audit_id, audit.model_dump())

        await broadcast_event(audit_id, {
            "type": "complete",
            "status": "completed",
            "summary": audit.summary,
        })

    except Exception as e:
        logger.error(f"Audit {audit_id} failed: {e}")
        audit.status = "failed"
        audit.summary = {"error": str(e)}
        await broadcast_event(audit_id, {
            "type": "error",
            "status": "failed",
            "error": str(e),
        })

    finally:
        async with _running_lock:
            _running_count -= 1


# ── REST Endpoints ────────────────────────────────────────────────

import base64

@router.post("/audit", response_model=AuditStatus)
async def start_audit(request: AuditRequest):
    """Start a new dark pattern audit."""
    global _running_count

    async with _running_lock:
        if _running_count >= settings.max_concurrent_audits:
            raise HTTPException(
                status_code=429,
                detail=f"Max concurrent audits ({settings.max_concurrent_audits}) reached. Try again later.",
            )
        _running_count += 1

    audit_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()

    audit = AuditResult(
        audit_id=audit_id,
        status="pending",
        url=request.url,
        created_at=now,
    )
    active_audits[audit_id] = audit

    # Launch pipeline in background
    asyncio.create_task(run_audit_pipeline(audit_id, request.url, request.scenarios))

    return AuditStatus(
        audit_id=audit_id,
        status="pending",
        url=request.url,
        created_at=now,
        scenarios_total=len(request.scenarios) if request.scenarios else 4,
    )


@router.get("/audit/{audit_id}", response_model=AuditResult)
async def get_audit(audit_id: str):
    """Get audit status and results."""
    # Check in-memory first
    if audit_id in active_audits:
        return active_audits[audit_id]

    # Check persistent storage
    storage = get_storage()
    result = storage.load_result(audit_id)
    if result:
        return AuditResult(**result)

    raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")


@router.get("/audits", response_model=list[AuditStatus])
async def list_audits():
    """List all audits."""
    audits = []
    for audit in active_audits.values():
        audits.append(AuditStatus(
            audit_id=audit.audit_id,
            status=audit.status,
            url=audit.url,
            created_at=audit.created_at,
            scenarios_total=audit.scenarios_total,
            scenarios_completed=audit.scenarios_completed,
            findings_count=len(audit.findings),
            risk_score=audit.risk_score,
        ))
    return audits


# ── WebSocket Endpoint ────────────────────────────────────────────

@router.websocket("/ws/audit/{audit_id}")
async def audit_websocket(websocket: WebSocket, audit_id: str):
    """Real-time audit event stream."""
    await websocket.accept()

    if audit_id not in audit_connections:
        audit_connections[audit_id] = []
    audit_connections[audit_id].append(websocket)

    try:
        # Send current status immediately
        if audit_id in active_audits:
            audit = active_audits[audit_id]
            await websocket.send_json({
                "type": "status",
                "status": audit.status,
                "scenarios_completed": audit.scenarios_completed,
                "findings_count": len(audit.findings),
            })

        # Keep connection alive until client disconnects
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        pass
    finally:
        if audit_id in audit_connections:
            conns = audit_connections[audit_id]
            if websocket in conns:
                conns.remove(websocket)
            if not conns:
                del audit_connections[audit_id]
