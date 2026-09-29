"""
Admin & Audit Log Router (Phase 5)
Provides system administration endpoints, comprehensive audit trail querying,
and operational health telemetry for NCIIPC/NTRO SOC supervisors.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
import duckdb

from database import get_connection
from auth import get_current_user, require_role
from audit import get_audit_logs

router = APIRouter()


@router.get("/audit-logs")
def view_audit_logs(
    action: Optional[str] = None,
    role: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(require_role(["Admin", "Supervisor"])),
):
    """
    Returns paginated audit events. Accessible by Admins and Supervisors.
    """
    con = get_connection()
    try:
        return get_audit_logs(con, limit=limit, offset=offset, action=action, role=role)
    finally:
        con.close()


@router.get("/system-status")
def get_system_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns system status, active database counts, and storage metrics.
    """
    con = get_connection()
    try:
        def _cnt(table: str) -> int:
            try:
                return con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except Exception:
                return 0

        counts = {
            "cses": _cnt("cses"),
            "alerts": _cnt("alerts"),
            "cases": _cnt("cases"),
            "investigations": _cnt("investigations"),
            "escalations": _cnt("escalations"),
            "findings": _cnt("findings"),
            "reviews": _cnt("reviews"),
            "audit_logs": _cnt("audit_logs"),
            "threat_intel_iocs": _cnt("threat_intel_iocs"),
            "threat_intel_cves": _cnt("threat_intel_cves"),
            "traceback_reports": _cnt("traceback_reports"),
            "feedback_logs": _cnt("feedback_logs"),
            "users": _cnt("users"),
        }

        return {
            "status": "operational",
            "environment": "air_gapped_on_prem",
            "classification": "RESTRICTED / NCIIPC-NTRO",
            "version": "3.5.0",
            "counts": counts,
        }
    finally:
        con.close()
