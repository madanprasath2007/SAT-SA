"""
SAT-SA Backend: Main FastAPI Application
Supervisory Analytics Tool for SOC Assessment
NCIIPC / NTRO — Air-Gapped Deployment
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import ingest, analytics, dashboard

app = FastAPI(
    title="SAT-SA: Supervisory Analytics Tool for SOC Assessment",
    description="NCIIPC/NTRO compliant offline supervisory analytics platform",
    version="1.0.0",
)

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from routers import ingest, analytics, dashboard

app = FastAPI(
    title="SAT-SA: Supervisory Analytics Tool for SOC Assessment",
    description="NCIIPC/NTRO compliant offline supervisory analytics platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest.router, prefix="/api/ingest", tags=["Data Ingestion"])
app.include_router(analytics.router, prefix="/api/analytics", tags=["Analytics"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])

DASHBOARD_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "dashboard.html")
)


@app.get("/")
@app.get("/dashboard")
def get_dashboard():
    if os.path.exists(DASHBOARD_PATH):
        return FileResponse(DASHBOARD_PATH, media_type="text/html")
    return {
        "status": "operational",
        "system": "SAT-SA",
        "version": "1.0.0",
        "mode": "air-gapped",
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "operational",
        "system": "SAT-SA",
        "version": "1.0.0",
        "mode": "air-gapped",
    }

