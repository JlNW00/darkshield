"""
DarkShield Configuration - Environment variable management.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env file before reading any env vars
load_dotenv()


@dataclass
class Settings:
    """Application settings loaded from environment variables."""

    # Nova Act
    nova_act_api_key: str = os.getenv("NOVA_ACT_API_KEY", "")

    # AWS / Bedrock
    aws_access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    aws_secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    bedrock_model_id: str = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")

    # App
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    data_dir: str = os.getenv("DATA_DIR", "data")
    max_concurrent_audits: int = int(os.getenv("MAX_CONCURRENT_AUDITS", "3"))
    cors_origins: list[str] = field(default_factory=lambda: [
        os.getenv("CORS_ORIGIN", "http://localhost:5173"),
    ])

    # Timeouts
    scenario_timeout: int = int(os.getenv("SCENARIO_TIMEOUT", "120"))
    audit_timeout: int = int(os.getenv("AUDIT_TIMEOUT", "600"))

    @property
    def screenshots_dir(self) -> str:
        """Path to screenshots directory."""
        return os.path.join(self.data_dir, "screenshots")

    def ensure_dirs(self) -> None:
        """Create required data directories if they don't exist."""
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.screenshots_dir).mkdir(parents=True, exist_ok=True)

    def validate(self) -> list[str]:
        """Return list of missing required config keys."""
        missing = []
        if not self.nova_act_api_key:
            missing.append("NOVA_ACT_API_KEY")
        if not self.aws_access_key_id:
            missing.append("AWS_ACCESS_KEY_ID")
        if not self.aws_secret_access_key:
            missing.append("AWS_SECRET_ACCESS_KEY")
        return missing


settings = Settings()
