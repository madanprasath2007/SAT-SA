"""
Traceback Router (Phase 3)
Exposes endpoints for running AI attack traceback, fetching incident reports,
and retrieving React Flow graph nodes and edges.
"""

import json
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from models import get_connection
from traceback.service import run_attack_traceback

router = APIRouter()


class TracebackRunRequest(BaseModel):
    cse_id: str
    finding_id: Optional[str] = None
    llm_backend: Optional[str] = None


@router.post("/run")
def trigger_traceback(req: TracebackRunRequest):
    """
    Executes attack traceback reconstruction using offline LLM and evidence verification.
    Reconstructs chronological MITRE attack stages and correlation graph.
    """
    con = get_connection()
    try:
        report = run_attack_traceback(
            con,
            cse_id=req.cse_id,
            finding_id=req.finding_id,
            llm_backend=req.llm_backend,
        )
        con.close()
        return {"data": report}
    except Exception as e:
        con.close()
        raise HTTPException(status_code=500, detail=f"Traceback execution error: {str(e)}")


@router.get("/{finding_id}")
def get_traceback_report(finding_id: str):
    """
    Fetch an existing traceback report by finding_id or incident_id.
    If not yet computed, automatically computes it using the finding's CSE.
    """
    con = get_connection()
    row = con.execute("""
        SELECT incident_id, cse_id, finding_id, title, confidence_score, why_flagged,
               narrative, stages_json, ioc_matches_json, evidence_ids_json, graph_json, created_at
        FROM traceback_reports
        WHERE finding_id = ? OR incident_id = ?
        ORDER BY created_at DESC
        LIMIT 1
    """, [finding_id, finding_id]).fetchone()

    if row:
        con.close()
        return {
            "data": {
                "incident_id": row[0],
                "cse_id": row[1],
                "finding_id": row[2],
                "title": row[3],
                "confidence_score": row[4],
                "why_flagged": row[5],
                "how_attack_happened": row[6],
                "stages": json.loads(row[7]) if row[7] else [],
                "matched_iocs": json.loads(row[8]) if row[8] else [],
                "evidence_ids": json.loads(row[9]) if row[9] else [],
                "graph": json.loads(row[10]) if row[10] else {"nodes": [], "edges": []},
                "created_at": str(row[11]),
            }
        }

    # If not found directly, check if finding exists in findings table
    finding_row = con.execute("SELECT cse_id FROM findings WHERE finding_id = ?", [finding_id]).fetchone()
    if not finding_row:
        # Check alerts table
        alert_row = con.execute("SELECT cse_id FROM alerts WHERE alert_id = ?", [finding_id]).fetchone()
        if not alert_row:
            # Fallback: check if finding_id is a CSE ID like CSE-A
            cse_row = con.execute("SELECT cse_id FROM cses WHERE cse_id = ?", [finding_id]).fetchone()
            if cse_row:
                cse_id = cse_row[0]
            else:
                con.close()
                raise HTTPException(status_code=404, detail=f"No traceback or entity found matching '{finding_id}'.")
        else:
            cse_id = alert_row[0]
    else:
        cse_id = finding_row[0]

    # Generate on the fly
    try:
        report = run_attack_traceback(con, cse_id=cse_id, finding_id=finding_id)
        con.close()
        return {"data": report}
    except Exception as e:
        con.close()
        raise HTTPException(status_code=500, detail=f"Failed to generate traceback: {str(e)}")


@router.get("/{finding_id}/graph")
def get_traceback_graph(finding_id: str):
    """
    Retrieve React Flow formatted nodes and edges for the incident graph.
    """
    report_res = get_traceback_report(finding_id)
    report_data = report_res.get("data", {})
    graph = report_data.get("graph", {"nodes": [], "edges": []})
    return {"data": graph}
