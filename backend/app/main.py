"""DarkShield API - AI-powered dark pattern detection."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.audit import router as audit_router

app = FastAPI(
    title="DarkShield API",
    description="AI-powered dark pattern detection and auditing tool",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(audit_router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "darkshield"}
