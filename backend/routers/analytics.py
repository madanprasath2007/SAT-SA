"""
Analytics Router — Supervisory Analytics Layer & Risk Scoring (Phase 2)
Orchestrates the 5 supervisory analytics engines, persists evidence-linked findings,
and serves explainable composite risk scores.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from models import get_connection
from engines import (
    get_all_engines,
    persist_findings,
    calculate_cse_risk,
    update_risk_scores,
)

router = APIRouter()


def _format_finding_row(row: tuple, cols: List[str]) -> Dict[str, Any]:
    item = dict(zip(cols, row))
    # Parse evidence JSON string if present
    if item.get("evidence"):
        try:
            item["evidence"] = json.loads(item["evidence"])
        except Exception:
            pass
    return item


@router.post("/run")
def run_analytics(cse_id: Optional[str] = Query(None, description="Optional CSE ID to restrict analysis")):
    """
    Run all 5 supervisory analytics engines against normalized DB records.
    Idempotent: replaces prior findings for the analyzed scope.
    Also recalculates and persists composite risk scores.
    """
    if not isinstance(cse_id, str):
        cse_id = None
    con = get_connection()

    # Check that we have data
    alert_count = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if alert_count == 0:
        con.close()
        return {
            "status": "no_data",
            "message": "No alert data found. Ingest synthetic or real data before running analytics.",
            "total_findings": 0,
        }

    engines = get_all_engines()
    all_findings = []
    by_engine = {}

    for engine in engines:
        try:
            findings = engine.run(con, cse_id=cse_id)
            all_findings.extend(findings)
            by_engine[engine.name] = len(findings)
        except Exception as e:
            print(f"[Analytics] Error running {engine.name}: {e}")
            by_engine[engine.name] = 0

    # Persist findings idempotently
    engine_names = [e.name for e in engines]
    persist_findings(con, all_findings, cse_id=cse_id, engine_names=engine_names)

    # Recalculate and update composite risk scores
    risk_results = update_risk_scores(con, cse_id=cse_id)

    # Group counts by severity
    by_sev = {}
    for f in all_findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    con.close()

    return {
        "status": "complete",
        "scope": cse_id or "all",
        "total_findings": len(all_findings),
        "by_engine": by_engine,
        "by_severity": by_sev,
        "risk_scores": [
            {"cse_id": r["cse_id"], "overall_score": r["overall_score"], "risk_level": r["risk_level"]}
            for r in risk_results
        ],
    }


@router.get("/findings")
def list_findings(
    cse_id: Optional[str] = Query(None, description="Filter by CSE ID"),
    engine: Optional[str] = Query(None, description="Filter by Engine name"),
    severity: Optional[str] = Query(None, description="Filter by Severity"),
    date: Optional[str] = Query(None, description="Filter by date substring (YYYY-MM-DD)"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Return all supervisory findings, with optional multi-attribute filtering."""
    con = get_connection()
    query = """
        SELECT finding_id, alert_id, cse_id, engine, finding_type, severity, description, score, evidence, created_at
        FROM findings
        WHERE 1=1
    """
    params = []
    if cse_id:
        query += " AND cse_id = ?"
        params.append(cse_id)
    if engine:
        query += " AND engine = ?"
        params.append(engine)
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if date:
        query += " AND (CAST(created_at AS VARCHAR) LIKE ? OR evidence LIKE ?)"
        params.append(f"%{date}%")
        params.append(f"%{date}%")

    # Count total matching
    count_query = f"SELECT COUNT(*) FROM ({query}) sub"
    total = con.execute(count_query, params).fetchone()[0]

    query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, created_at DESC"
    query += f" LIMIT {limit} OFFSET {offset}"

    rows = con.execute(query, params).fetchall()
    cols = ["finding_id", "alert_id", "cse_id", "engine", "finding_type", "severity", "description", "score", "evidence", "created_at"]
    con.close()

    data = [_format_finding_row(r, cols) for r in rows]
    return {"data": data, "total": total, "limit": limit, "offset": offset}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    """Fetch a single finding with full evidence details by ID."""
    con = get_connection()
    cols = ["finding_id", "alert_id", "cse_id", "engine", "finding_type", "severity", "description", "score", "evidence", "created_at"]
    query = f"SELECT {', '.join(cols)} FROM findings WHERE finding_id = ?"
    row = con.execute(query, [finding_id]).fetchone()
    con.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Finding with ID '{finding_id}' not found.")

    return {"data": _format_finding_row(row, cols)}


@router.get("/risk-scores")
def get_risk_scores():
    """Return latest composite risk scores for all CSEs."""
    con = get_connection()

    # Check if table exists or is empty
    count = con.execute("SELECT COUNT(*) FROM risk_scores").fetchone()[0]
    if count == 0:
        # Compute on the fly if not yet populated
        update_risk_scores(con)

    rows = con.execute("""
        SELECT cse_id, overall_score, risk_level, breakdown_json, calculated_at
        FROM risk_scores
        ORDER BY overall_score DESC
    """).fetchall()
    con.close()

    data = []
    for r in rows:
        cid, score, level, b_json, calc_at = r
        breakdown = json.loads(b_json) if b_json else {}
        data.append({
            "cse_id": cid,
            "overall_score": score,
            "risk_level": level,
            "calculated_at": str(calc_at),
            "breakdown": breakdown,
        })
    return {"data": data}


@router.get("/risk-scores/{cse_id}/breakdown")
def get_risk_score_breakdown(cse_id: str):
    """Return full explainable risk score breakdown for a specific CSE."""
    con = get_connection()

    # Verify CSE exists
    exists = con.execute("SELECT COUNT(*) FROM cses WHERE cse_id = ?", [cse_id]).fetchone()[0]
    if exists == 0:
        # Check alerts
        exists = con.execute("SELECT COUNT(*) FROM alerts WHERE cse_id = ?", [cse_id]).fetchone()[0]
        if exists == 0:
            con.close()
            raise HTTPException(status_code=404, detail=f"CSE '{cse_id}' not found.")

    breakdown = calculate_cse_risk(con, cse_id)
    con.close()
    return {"data": breakdown}


@router.get("/summary")
def get_summary():
    """Return aggregate finding counts per severity and engine for dashboard widgets."""
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
        "data": {
            "by_severity": [{"severity": r[0], "count": r[1]} for r in by_sev],
            "by_engine":   [{"engine": r[0], "count": r[1]} for r in by_engine],
            "by_cse":      [{"cse_id": r[0], "count": r[1]} for r in by_cse],
        }
    }
