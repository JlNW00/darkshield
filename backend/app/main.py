"""DarkShield API - AI-powered dark pattern detection."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import settings
from .routes.audit import router as audit_router


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-25s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("darkshield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    settings.ensure_dirs()
    warnings = settings.validate()
    if warnings:
        for w in warnings:
            logger.warning("Config: %s", w)
    logger.info("DarkShield API started on %s:%s", settings.host, settings.port)
    logger.info("Data directory: %s", settings.data_dir)
    yield
    # Shutdown
    logger.info("DarkShield API shutting down")


app = FastAPI(
    title="DarkShield",
    description="AI-powered dark pattern detection and auditing tool",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS for frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount audit routes
app.include_router(audit_router)

# Serve screenshots as static files
try:
    app.mount("/screenshots", StaticFiles(directory=settings.screenshots_dir), name="screenshots")
except Exception:
    pass  # Directory may not exist yet at import time; created at startup


@app.get("/")
async def root():
    return {
        "app": "DarkShield",
        "version": "0.1.0",
        "description": "AI-powered dark pattern detection",
        "docs": "/docs",
        "health": "/api/v1/health",
    }
