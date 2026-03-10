"""
DarkShield Report Routes - PDF generation and download.
"""
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, HTMLResponse

from ..services.storage import storage
from ..services.report_generator import generate_pdf, generate_report_html

logger = logging.getLogger("darkshield.routes.report")

router = APIRouter(prefix="/api/v1", tags=["report"])


@router.get("/audit/{audit_id}/report")
async def download_report(audit_id: str, format: str = "pdf"):
    """
    Generate and download an audit report.
    
    Query params:
        format: 'pdf' (default) or 'html'
    """
    audit_data = storage.load_audit(audit_id)
    if audit_data is None:
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")

    if audit_data.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Audit is not yet completed")

    if format == "html":
        html = generate_report_html(audit_data)
        return HTMLResponse(content=html)

    # PDF
    try:
        # Check cache first
        cached_path = storage.get_report_path(audit_id)
        if cached_path:
            import os
            if os.path.exists(cached_path):
                with open(cached_path, "rb") as f:
                    pdf_bytes = f.read()
                return Response(
                    content=pdf_bytes,
                    media_type="application/pdf",
                    headers={
                        "Content-Disposition": f'attachment; filename="darkshield-{audit_id}.pdf"'
                    },
                )

        # Generate fresh
        pdf_bytes = generate_pdf(audit_data)
        
        # Cache it
        storage.save_report(audit_id, pdf_bytes)

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="darkshield-{audit_id}.pdf"'
            },
        )

    except ImportError:
        # WeasyPrint not installed - fall back to HTML
        logger.warning("WeasyPrint not available, returning HTML report")
        html = generate_report_html(audit_data)
        return HTMLResponse(content=html)

    except Exception as exc:
        logger.exception("Report generation failed")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")