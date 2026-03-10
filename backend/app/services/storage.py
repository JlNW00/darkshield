"""
DarkShield Local Storage Service.
Handles screenshot and audit result persistence.
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("darkshield.storage")


class LocalStorage:
    """File-based storage for audit results and screenshots."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            from app.config import settings
            base_dir = settings.data_dir
        self.base_dir = Path(base_dir)
        self.screenshots_dir = self.base_dir / "screenshots"
        self.results_dir = self.base_dir / "results"
        self.reports_dir = self.base_dir / "reports"
        self._ensure_dirs()

    def _ensure_dirs(self):
        """Create storage directories if they don't exist."""
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Storage initialized at {self.base_dir}")

    def save_screenshot(self, audit_id: str, scenario: str, step: str, data: bytes) -> str:
        """Save a screenshot and return relative path."""
        filename = f"{audit_id}_{scenario}_{step}_{datetime.now(timezone.utc).strftime('%H%M%S')}.png"
        filepath = self.screenshots_dir / filename
        filepath.write_bytes(data)
        logger.debug(f"Screenshot saved: {filepath}")
        return str(filepath.relative_to(self.base_dir))

    def save_result(self, audit_id: str, result: dict) -> str:
        """Save audit result as JSON."""
        filepath = self.results_dir / f"{audit_id}.json"
        filepath.write_text(json.dumps(result, indent=2, default=str))
        logger.info(f"Result saved: {filepath}")
        return str(filepath)

    def load_result(self, audit_id: str) -> Optional[dict]:
        """Load audit result by ID."""
        filepath = self.results_dir / f"{audit_id}.json"
        if not filepath.exists():
            return None
        return json.loads(filepath.read_text())

    def load_audit(self, audit_id: str) -> Optional[dict]:
        """Load audit data by ID. Alias for load_result used by report routes."""
        return self.load_result(audit_id)

    def get_report_path(self, audit_id: str) -> Optional[str]:
        """Get the cached PDF report path for an audit, or None if not cached."""
        filepath = self.reports_dir / f"{audit_id}.pdf"
        if filepath.exists():
            return str(filepath)
        return None

    def save_report(self, audit_id: str, pdf_bytes: bytes) -> str:
        """Save a generated PDF report to the reports directory."""
        filepath = self.reports_dir / f"{audit_id}.pdf"
        filepath.write_bytes(pdf_bytes)
        logger.info(f"Report saved: {filepath}")
        return str(filepath)

    def list_results(self) -> list[str]:
        """List all audit result IDs."""
        return [f.stem for f in self.results_dir.glob("*.json")]

    def get_screenshot_path(self, relative_path: str) -> Optional[Path]:
        """Get absolute path for a screenshot."""
        full_path = self.base_dir / relative_path
        return full_path if full_path.exists() else None


def get_storage() -> LocalStorage:
    """Get or create the storage singleton, using config.data_dir."""
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = LocalStorage()
    return _storage_instance


_storage_instance: Optional[LocalStorage] = None
