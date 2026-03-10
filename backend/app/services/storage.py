"""
DarkShield Storage Service - Local file storage for hackathon.
Saves screenshots, audit results, and reports to local data/ directory.
"""
import base64
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("darkshield.storage")

class LocalStorage:
    """Local file-based storage for audit data."""

    def __init__(self, base_dir: str = "data"):
        self.base_dir = Path(base_dir)
        self.screenshots_dir = self.base_dir / "screenshots"
        self.audits_dir = self.base_dir / "audits"
        self.reports_dir = self.base_dir / "reports"
        self._ensure_dirs()

    def _ensure_dirs(self):
        for d in [self.screenshots_dir, self.audits_dir, self.reports_dir]:
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Screenshots
    # ------------------------------------------------------------------
    def save_screenshot(
        self, audit_id: str, name: str, image_b64: str
    ) -> str:
        """Save a base64 screenshot to disk. Returns the file path."""
        audit_dir = self.screenshots_dir / audit_id
        audit_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{name}.png"
        filepath = audit_dir / filename

        try:
            image_bytes = base64.b64decode(image_b64)
            filepath.write_bytes(image_bytes)
            logger.info("Saved screenshot: %s", filepath)
            return str(filepath)
        except Exception:
            logger.exception("Failed to save screenshot %s", name)
            return ""

    def get_screenshot_path(self, audit_id: str, name: str) -> Optional[str]:
        """Get path to a saved screenshot."""
        filepath = self.screenshots_dir / audit_id / f"{name}.png"
        return str(filepath) if filepath.exists() else None

    def list_screenshots(self, audit_id: str) -> list[str]:
        """List all screenshots for an audit."""
        audit_dir = self.screenshots_dir / audit_id
        if not audit_dir.exists():
            return []
        return [str(f) for f in audit_dir.glob("*.png")]

    # ------------------------------------------------------------------
    # Audit Results
    # ------------------------------------------------------------------
    def save_audit(self, audit_id: str, audit_data: dict) -> str:
        """Save audit results as JSON. Returns the file path."""
        filepath = self.audits_dir / f"{audit_id}.json"

        audit_data["saved_at"] = datetime.now(timezone.utc).isoformat()

        try:
            filepath.write_text(json.dumps(audit_data, indent=2, default=str))
            logger.info("Saved audit: %s", filepath)
            return str(filepath)
        except Exception:
            logger.exception("Failed to save audit %s", audit_id)
            return ""

    def load_audit(self, audit_id: str) -> Optional[dict]:
        """Load audit results from JSON."""
        filepath = self.audits_dir / f"{audit_id}.json"
        if not filepath.exists():
            return None
        try:
            return json.loads(filepath.read_text())
        except Exception:
            logger.exception("Failed to load audit %s", audit_id)
            return None

    def list_audits(self) -> list[dict]:
        """List all saved audits with basic metadata."""
        audits = []
        for f in sorted(self.audits_dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(f.read_text())
                audits.append({
                    "audit_id": data.get("audit_id", f.stem),
                    "target_url": data.get("target_url", ""),
                    "status": data.get("status", "unknown"),
                    "total_patterns": data.get("total_patterns", 0),
                    "risk_score": data.get("risk_score", 0),
                    "started_at": data.get("started_at", ""),
                    "completed_at": data.get("completed_at", ""),
                })
            except Exception:
                continue
        return audits

    def delete_audit(self, audit_id: str) -> bool:
        """Delete an audit and its screenshots."""
        deleted = False

        audit_file = self.audits_dir / f"{audit_id}.json"
        if audit_file.exists():
            audit_file.unlink()
            deleted = True

        screenshot_dir = self.screenshots_dir / audit_id
        if screenshot_dir.exists():
            import shutil
            shutil.rmtree(screenshot_dir)
            deleted = True

        report_file = self.reports_dir / f"{audit_id}.pdf"
        if report_file.exists():
            report_file.unlink()
            deleted = True

        return deleted

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def save_report(self, audit_id: str, pdf_bytes: bytes) -> str:
        """Save a generated PDF report."""
        filepath = self.reports_dir / f"{audit_id}.pdf"
        try:
            filepath.write_bytes(pdf_bytes)
            logger.info("Saved report: %s", filepath)
            return str(filepath)
        except Exception:
            logger.exception("Failed to save report %s", audit_id)
            return ""

    def get_report_path(self, audit_id: str) -> Optional[str]:
        """Get path to a saved report PDF."""
        filepath = self.reports_dir / f"{audit_id}.pdf"
        return str(filepath) if filepath.exists() else None

# Singleton
storage = LocalStorage()


def get_storage() -> LocalStorage:
    """Return the storage singleton."""
    return storage
