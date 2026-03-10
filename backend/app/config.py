"""
DarkShield Configuration - Environment variable management.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    """Application settings loaded from environment variables."""
    
    # Nova Act
    nova_act_api_key: str = ""
    
    # AWS Bedrock
    aws_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    
    # Storage (local for hackathon)
    data_dir: str = "data"
    screenshots_dir: str = "data/screenshots"
    audits_dir: str = "data/audits"
    reports_dir: str = "data/reports"
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = field(default_factory=lambda: ["http://localhost:5173", "http://localhost:3000"])
    
    # Audit defaults
    max_concurrent_audits: int = 3
    default_scenarios: list[str] = field(default_factory=lambda: [
        "cookie_consent", "subscription_cancel", "checkout_flow", "account_deletion"
    ])

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables."""
        settings = cls(
            nova_act_api_key=os.getenv("NOVA_ACT_API_KEY", ""),
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", ""),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", ""),
            data_dir=os.getenv("DATA_DIR", "data"),
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", "8000")),
        )
        settings.screenshots_dir = f"{settings.data_dir}/screenshots"
        settings.audits_dir = f"{settings.data_dir}/audits"
        settings.reports_dir = f"{settings.data_dir}/reports"
        
        cors = os.getenv("CORS_ORIGINS", "")
        if cors:
            settings.cors_origins = [o.strip() for o in cors.split(",")]
        
        return settings

    def ensure_dirs(self):
        """Create data directories if they don't exist."""
        for d in [self.data_dir, self.screenshots_dir, self.audits_dir, self.reports_dir]:
            Path(d).mkdir(parents=True, exist_ok=True)

    def validate(self) -> list[str]:
        """Check for missing required config. Returns list of warnings."""
        warnings = []
        if not self.nova_act_api_key:
            warnings.append("NOVA_ACT_API_KEY not set - browser agent will fail")
        if not self.aws_access_key_id or not self.aws_secret_access_key:
            warnings.append("AWS credentials not set - classifier will fall back to defaults")
        return warnings


# Singleton
settings = Settings.from_env()
