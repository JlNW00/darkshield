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


# -- Models --------------------------------------------------------

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


# -- In-memory state -----------------------------------------------

active_audits: dict[str, AuditResult] = {}
audit_connections: dict[str, list[WebSocket]] = {}
_running_count: int = 0
_running_lock = asyncio.Lock()


# -- WebSocket event broadcasting -----------------------------------

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


# -- Audit pipeline -------------------------------------------------

async def run_audit_pipeline(audit_id: str, url: str, scenarios: Optional[list[str]]):
    """Main audit orchestration: browser agent -> classifier -> storage."""
    global _running_count

    audit = active_audits[audit_id]
    audit.status = "running"
    await broadcast_event(audit_id, {"type": "status", "status": "running"})

    storage = get_storage()

    try:
        # ----------------------------------------------------------------
        # 1. Run browser agent  (async run_audit, NOT run_scenario)
        # ----------------------------------------------------------------
        from app.agents.browser_agent import DarkPatternAgent

        # FIX #5: config uses nova_act_api_key (not nova_api_key)
        agent = DarkPatternAgent(nova_act_api_key=settings.nova_act_api_key)

        # FIX #6: config has no default_scenarios; hardcode fallback list
        selected = scenarios or [
            "cookie_consent",
            "subscription_cancel",
            "checkout_flow",
            "account_deletion",
        ]

        audit.scenarios = [{"name": s, "status": "pending"} for s in selected]

        await broadcast_event(audit_id, {
            "type": "scenarios_init",
            "scenarios": selected,
            "total": len(selected),
        })

        # FIX #9: agent exposes async run_audit(url, audit_id, scenarios, on_event)
        #         which handles all scenarios internally and returns AuditResult.
        async def _on_agent_event(event: dict):
            """Bridge browser-agent events to our WebSocket clients."""
            etype = event.get("type", "")

            if etype == "scenario_started":
                name = event.get("scenario", "")
                for s in audit.scenarios:
                    if s["name"] == name:
                        s["status"] = "running"
                await broadcast_event(audit_id, {
                    "type": "scenario_start",
                    "scenario": name,
                })

            elif etype == "scenario_completed":
                name = event.get("scenario", "")
                count = event.get("patterns_found", 0)
                for s in audit.scenarios:
                    if s["name"] == name:
                        s["status"] = "completed"
                        s["findings_count"] = count
                await broadcast_event(audit_id, {
                    "type": "scenario_complete",
                    "scenario": name,
                    "findings_count": count,
                })

            else:
                # Forward agent_action / agent_observation / etc. as-is
                await broadcast_event(audit_id, event)

        agent_result = await agent.run_audit(
            url=url,
            audit_id=audit_id,
            scenarios=selected,
            on_event=_on_agent_event,
        )

        # Collect all DetectedPattern objects across scenarios
        # browser_agent returns ScenarioResult.patterns_found (list of DetectedPattern)
        all_patterns = [
            p
            for scenario_result in agent_result.scenarios
            for p in scenario_result.patterns_found
        ]

        # Save screenshots
        for pattern in all_patterns:
            if pattern.screenshot_b64:
                ss_path = storage.save_screenshot(
                    audit_id, pattern.pattern_id, pattern.screenshot_b64
                )
                pattern.screenshot_path = ss_path

        # ----------------------------------------------------------------
        # 2. Classify findings with Nova 2 Lite
        # ----------------------------------------------------------------
        if all_patterns:
            await broadcast_event(audit_id, {"type": "status", "status": "classifying"})

            from app.agents.classifier import DarkPatternClassifier

            # FIX #8: classifier __init__ takes aws_region, aws_access_key_id,
            #         aws_secret_access_key  (NOT model_id / region)
            classifier = DarkPatternClassifier(
                aws_region=settings.aws_region,
                aws_access_key_id=settings.aws_access_key_id,
                aws_secret_access_key=settings.aws_secret_access_key,
            )

            classified = []
            for pattern in all_patterns:
                try:
                    # FIX #8: method is classify_pattern() with keyword args,
                    #         NOT classify(pattern)
                    classification = await classifier.classify_pattern(
                        pattern_id=pattern.pattern_id,
                        category=(
                            pattern.category.value
                            if hasattr(pattern.category, "value")
                            else str(pattern.category)
                        ),
                        description=pattern.description,
                        evidence=pattern.evidence,
                        screenshot_b64=pattern.screenshot_b64,
                        dom_context=pattern.dom_snapshot,
                    )

                    finding = {
                        "pattern_id": pattern.pattern_id,
                        "category": classification.ai_category,
                        "severity": classification.severity,
                        "scenario": pattern.scenario,
                        "description": classification.description,
                        "evidence": classification.evidence_summary,
                        "url": pattern.url,
                        "confidence": classification.ai_confidence,
                        "screenshot_path": getattr(pattern, "screenshot_path", None),
                        # Classification enrichment
                        "oecd_guideline": classification.oecd_reference.get("guideline"),
                        "remediation": classification.remediation,
                        "regulatory_risk": classification.oecd_reference.get("regulation"),
                        "ai_reasoning": classification.ai_reasoning,
                    }
                    classified.append(finding)

                except Exception as e:
                    logger.error(f"Classification failed for {pattern.pattern_id}: {e}")
                    classified.append({
                        "pattern_id": pattern.pattern_id,
                        "category": (
                            pattern.category.value
                            if hasattr(pattern.category, "value")
                            else str(pattern.category)
                        ),
                        "severity": (
                            pattern.severity.value
                            if hasattr(pattern.severity, "value")
                            else str(pattern.severity)
                        ),
                        "scenario": pattern.scenario,
                        "description": pattern.description,
                        "evidence": pattern.evidence,
                        "url": pattern.url,
                        "confidence": pattern.confidence,
                        "screenshot_path": getattr(pattern, "screenshot_path", None),
                    })

            audit.findings = classified
        else:
            audit.findings = []

        # ----------------------------------------------------------------
        # 3. Calculate risk score
        # ----------------------------------------------------------------
        risk_score = _calculate_risk_score(audit.findings)
        audit.risk_score = risk_score

        # ----------------------------------------------------------------
        # 4. Build summary
        # ----------------------------------------------------------------
        audit.summary = _build_summary(audit.findings, risk_score)

        # ----------------------------------------------------------------
        # 5. Persist results
        # FIX #7: storage exposes save_result(audit_id, data), NOT save_audit(record)
        # ----------------------------------------------------------------
        storage.save_result(audit_id, audit.model_dump())

        # ----------------------------------------------------------------
        # 6. Mark complete
        # ----------------------------------------------------------------
        audit.status = "completed"
        audit.completed_at = datetime.now(timezone.utc).isoformat()

        await broadcast_event(audit_id, {
            "type": "complete",
            "status": "completed",
            "risk_score": risk_score,
            "findings_count": len(audit.findings),
            "summary": audit.summary,
        })

        logger.info(
            f"Audit {audit_id} completed: {len(audit.findings)} findings, "
            f"risk={risk_score:.1f}"
        )

    except Exception as e:
        audit.status = "failed"
        audit.completed_at = datetime.now(timezone.utc).isoformat()
        logger.error(f"Audit {audit_id} failed: {e}")
        await broadcast_event(audit_id, {
            "type": "error",
            "status": "failed",
            "error": str(e),
        })

    finally:
        async with _running_lock:
            _running_count -= 1


def _calculate_risk_score(findings: list[dict]) -> float:
    """Calculate overall risk score 0-100 from classified findings."""
    if not findings:
        return 0.0

    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    total = 0.0
    for f in findings:
        sev = f.get("severity", "low").lower()
        confidence = f.get("confidence", 0.5)
        weight = severity_weights.get(sev, 3)
        total += weight * confidence

    score = min(total, 100.0)
    return round(score, 1)


def _build_summary(findings: list[dict], risk_score: float) -> dict:
    """Build a structured summary of audit results."""
    by_severity = {}
    by_category = {}

    for f in findings:
        sev = f.get("severity", "unknown")
        cat = f.get("category", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1

    risk_level = "low"
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 45:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"

    return {
        "total_findings": len(findings),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "by_severity": by_severity,
        "by_category": by_category,
    }


# -- REST endpoints -------------------------------------------------
# FIX #1, #2, #3: routes match what useApi.js calls:
#   POST /api/v1/audit          (singular)
#   GET  /api/v1/audit/{id}     (singular)
#   GET  /api/v1/audit/{id}/patterns
#   GET  /api/v1/audits         (plural - list only)

@router.post("/audit", response_model=AuditStatus)
async def start_audit(request: AuditRequest):
    """Start a new dark pattern audit for a URL."""
    global _running_count

    async with _running_lock:
        if _running_count >= settings.max_concurrent_audits:
            raise HTTPException(
                status_code=429,
                detail=f"Max concurrent audits ({settings.max_concurrent_audits}) reached. Try again later.",
            )
        _running_count += 1

    audit_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    audit = AuditResult(
        audit_id=audit_id,
        status="pending",
        url=str(request.url),
        created_at=now,
    )
    active_audits[audit_id] = audit

    asyncio.create_task(run_audit_pipeline(audit_id, str(request.url), request.scenarios))

    selected = request.scenarios or [
        "cookie_consent",
        "subscription_cancel",
        "checkout_flow",
        "account_deletion",
    ]

    return AuditStatus(
        audit_id=audit_id,
        status="pending",
        url=str(request.url),
        created_at=now,
        scenarios_total=len(selected),
    )


@router.get("/audit/{audit_id}", response_model=AuditResult)
async def get_audit(audit_id: str):
    """Get current audit status and results."""
    if audit_id not in active_audits:
        storage = get_storage()
        data = storage.load_audit(audit_id)
        if data:
            return AuditResult(**data)
        raise HTTPException(status_code=404, detail="Audit not found")
    return active_audits[audit_id]


@router.get("/audit/{audit_id}/patterns")
async def get_audit_patterns(audit_id: str):
    """Get classified patterns for an audit."""
    if audit_id not in active_audits:
        storage = get_storage()
        data = storage.load_audit(audit_id)
        if data:
            return data.get("findings", [])
        raise HTTPException(status_code=404, detail="Audit not found")
    return active_audits[audit_id].findings


@router.get("/audits", response_model=list[AuditStatus])
async def list_audits():
    """List all audits (in-memory + stored)."""
    results = []

    for audit in active_audits.values():
        results.append(AuditStatus(
            audit_id=audit.audit_id,
            status=audit.status,
            url=audit.url,
            created_at=audit.created_at,
            scenarios_total=len(audit.scenarios),
            scenarios_completed=sum(
                1 for s in audit.scenarios if s.get("status") == "completed"
            ),
            findings_count=len(audit.findings),
            risk_score=audit.risk_score,
        ))

    storage = get_storage()
    stored_ids = storage.list_audit_ids()
    for sid in stored_ids:
        if sid not in active_audits:
            data = storage.load_audit(sid)
            if data:
                results.append(AuditStatus(
                    audit_id=data["audit_id"],
                    status=data["status"],
                    url=data["url"],
                    created_at=data["created_at"],
                    scenarios_total=len(data.get("scenarios", [])),
                    scenarios_completed=sum(
                        1 for s in data.get("scenarios", [])
                        if s.get("status") == "completed"
                    ),
                    findings_count=len(data.get("findings", [])),
                    risk_score=data.get("risk_score"),
                ))

    return sorted(results, key=lambda x: x.created_at, reverse=True)


# -- WebSocket endpoint ---------------------------------------------
# FIX #4: path is /ws/audit/{id} to match useApi.js

@router.websocket("/ws/audit/{audit_id}")
async def audit_websocket(websocket: WebSocket, audit_id: str):
    """WebSocket endpoint for real-time audit progress updates."""
    await websocket.accept()

    if audit_id not in audit_connections:
        audit_connections[audit_id] = []
    audit_connections[audit_id].append(websocket)

    try:
        if audit_id in active_audits:
            audit = active_audits[audit_id]
            await websocket.send_json({
                "type": "state",
                "audit_id": audit_id,
                "status": audit.status,
                "scenarios": audit.scenarios,
                "findings_count": len(audit.findings),
                "risk_score": audit.risk_score,
            })

        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "heartbeat"})

    except WebSocketDisconnect:
        pass
    finally:
        if audit_id in audit_connections:
            try:
                audit_connections[audit_id].remove(websocket)
            except ValueError:
                pass
