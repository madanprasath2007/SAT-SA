"""
SAT-SA Backend — Main FastAPI Application (Phase 1)
Supervisory Analytics Tool for SOC Assessment
NCIIPC / NTRO — Air-Gapped Deployment
"""  # noqa: D205

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Import routers
from routers import ingest, analytics, dashboard, threat_intel, traceback as traceback_router, review, auth, export, admin, feedback

app = FastAPI(
    title="SAT-SA: Supervisory Analytics Tool for SOC Assessment",
    description="NCIIPC/NTRO compliant offline supervisory analytics platform — Phase 5",
    version="5.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(ingest.router,       prefix="/api/ingest",       tags=["Data Ingestion"])
app.include_router(analytics.router,    prefix="/api/analytics",    tags=["Analytics"])
app.include_router(dashboard.router,    prefix="/api/dashboard",    tags=["Dashboard"])
app.include_router(threat_intel.router, prefix="/api/threat-intel", tags=["Threat Intelligence"])
app.include_router(traceback_router.router, prefix="/api/traceback",    tags=["Attack Traceback"])
app.include_router(review.router,       prefix="/api/reviews",      tags=["Human Review & Feedback"])
app.include_router(feedback.router,     prefix="/api/feedback",     tags=["Feedback Loop & Rule Tuning"])
app.include_router(auth.router,         prefix="/api/auth",         tags=["Authentication & RBAC"])
app.include_router(export.router,       prefix="/api/export",       tags=["Regulatory Reports & Exports"])
app.include_router(export.router,       prefix="/api/reports",      tags=["Regulatory Reports & Exports (Alias)"])
app.include_router(admin.router,        prefix="/api/admin",        tags=["Administration & Audit"])

DASHBOARD_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "dashboard.html")
)


@app.get("/")
@app.get("/ui")
def get_dashboard():
    if os.path.exists(DASHBOARD_PATH):
        return FileResponse(DASHBOARD_PATH, media_type="text/html")
    return {"status": "operational", "system": "SAT-SA", "version": "1.1.0", "phase": 1}


@app.on_event("startup")
def on_startup():
    from models import init_db
    init_db()


@app.get("/api/health")
def health_check():
    return {"status": "operational", "system": "SAT-SA", "version": "1.1.0", "phase": 1}
