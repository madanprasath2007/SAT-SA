"""
Analytics Router — Steps 3 of SAT-SA pipeline.
Runs Execution-Gap and Negative-Space engines, persists findings.
"""

import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from database import get_connection
from engines.execution_gap import run_execution_gap_engine
from engines.negative_space import run_negative_space_engine
from seed_data import generate_telemetry_obs, generate_baselines, generate_cse_alert_counts

router = APIRouter()


def _load_alerts_from_db():
    con = get_connection()
    rows = con.execute("""
        SELECT alert_id, cse_id, category, severity,
               mttr_seconds, closure_notes, analyst_id, asset_id,
               source_ip, dest_ip, created_at, closed_at
        FROM alerts
    """).fetchall()
    cols = ["alert_id","cse_id","category","severity","mttr_seconds",
            "closure_notes","analyst_id","asset_id","source_ip","dest_ip",
            "created_at","closed_at"]
    con.close()
    return [dict(zip(cols, r)) for r in rows]


def _persist_findings(findings: List[dict]):
    if not findings:
        return
    con = get_connection()
    for f in findings:
        try:
            con.execute(
                """INSERT OR REPLACE INTO findings
                   (finding_id, alert_id, cse_id, engine, finding_type, severity, description, score, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                [
                    f["finding_id"], f.get("alert_id"), f["cse_id"],
                    f["engine"], f["finding_type"], f["severity"],
                    f["description"], f["score"],
                    f.get("created_at", datetime.utcnow().isoformat()),
                ],
            )
        except Exception:
            pass
    con.close()


@router.post("/run")
def run_all_engines():
    """Run all analytics engines against current DB data."""
    alerts = _load_alerts_from_db()
    if not alerts:
        return {"status": "no_data", "message": "Seed the database first via /api/ingest/seed"}

    # Execution-Gap Engine
    eg_findings = run_execution_gap_engine(alerts)
    _persist_findings(eg_findings)

    # Negative-Space Engine (uses synthetic real-time telemetry obs)
    telemetry_obs = generate_telemetry_obs()
    baselines     = generate_baselines()
    cse_counts    = generate_cse_alert_counts()
    ns_findings   = run_negative_space_engine(telemetry_obs, baselines, cse_counts)
    _persist_findings(ns_findings)

    return {
        "status": "complete",
        "execution_gap_findings": len(eg_findings),
        "negative_space_findings": len(ns_findings),
        "total_findings": len(eg_findings) + len(ns_findings),
    }


@router.get("/findings")
def get_findings(engine: str = None, severity: str = None, cse_id: str = None):
    """Return all findings, optionally filtered."""
    con = get_connection()
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if engine:
        query += " AND engine = ?"
        params.append(engine)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if cse_id:
        query += " AND cse_id = ?"
        params.append(cse_id)
    query += " ORDER BY created_at DESC"
    rows = con.execute(query, params).fetchall()
    cols = ["finding_id","alert_id","cse_id","engine","finding_type","severity","description","score","created_at"]
    con.close()
    return [dict(zip(cols, r)) for r in rows]


@router.get("/summary")
def get_summary():
    """Return aggregate finding counts per severity and engine."""
    con = get_connection()
    by_sev = con.execute(
        "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
    ).fetchall()
    by_engine = con.execute(
        "SELECT engine, COUNT(*) as count FROM findings GROUP BY engine"
    ).fetchall()
    by_cse = con.execute(
        "SELECT cse_id, COUNT(*) as count FROM findings GROUP BY cse_id ORDER BY count DESC"
    ).fetchall()
    con.close()
    return {
        "by_severity": [{"severity": r[0], "count": r[1]} for r in by_sev],
        "by_engine":   [{"engine": r[0], "count": r[1]} for r in by_engine],
        "by_cse":      [{"cse_id": r[0], "count": r[1]} for r in by_cse],
    }
