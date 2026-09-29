"""
Human Review & Decision Workflow Router (Phase 5)
Enables supervisors to validate findings, attach notes, request deeper investigation,
and maintain an immutable audit trail of review decisions.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
import duckdb

from database import get_connection
from auth import get_current_user, require_role
from audit import log_audit

router = APIRouter()


class ReviewDecisionRequest(BaseModel):
    decision: str  # "VALID", "FALSE_POSITIVE", "NEEDS_MORE_DATA"
    notes: Optional[str] = ""
    investigation_requested: Optional[bool] = False


@router.post("/{finding_id}")
def submit_review(
    finding_id: str,
    req: ReviewDecisionRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role(["Supervisor", "Admin"])),
):
    """
    Submits a supervisory review decision for a finding.
    Enforces that only Supervisors or Admins can record determinations.
    """
    decision = req.decision.strip().upper()
    valid_decisions = ["VALID", "FALSE_POSITIVE", "NEEDS_MORE_DATA"]
    if decision not in valid_decisions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decision must be one of {valid_decisions}. Received '{req.decision}'.",
        )

    con = get_connection()
    try:
        # Check if finding exists and get its cse_id
        finding_row = con.execute("""
            SELECT finding_id, cse_id, engine, finding_type, severity
            FROM findings
            WHERE finding_id = ?
        """, [finding_id]).fetchone()

        if not finding_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found.",
            )

        _, cse_id, engine, finding_type, severity = finding_row

        review_id = f"rev-{uuid.uuid4().hex[:10]}"
        reviewer_name = current_user.get("full_name") or current_user.get("username", "supervisor")
        reviewer_role = current_user.get("role", "Supervisor")
        now_dt = datetime.utcnow()

        con.execute("""
            INSERT INTO reviews (
                review_id, finding_id, cse_id, reviewer, reviewer_role,
                decision, notes, investigation_requested, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            review_id,
            finding_id,
            cse_id,
            reviewer_name,
            reviewer_role,
            decision,
            req.notes or "",
            bool(req.investigation_requested),
            now_dt,
        ])

        # Record in audit log
        client_ip = request.client.host if request.client else "127.0.0.1"
        log_audit(
            con,
            action="REVIEW_FINDING",
            user=current_user,
            target_entity=finding_id,
            details={
                "review_id": review_id,
                "cse_id": cse_id,
                "engine": engine,
                "finding_type": finding_type,
                "decision": decision,
                "notes": req.notes,
                "investigation_requested": req.investigation_requested,
            },
            ip_address=client_ip,
        )

        return {
            "status": "success",
            "message": f"Review recorded as {decision}.",
            "review": {
                "review_id": review_id,
                "finding_id": finding_id,
                "cse_id": cse_id,
                "reviewer": reviewer_name,
                "reviewer_role": reviewer_role,
                "decision": decision,
                "notes": req.notes,
                "investigation_requested": req.investigation_requested,
                "created_at": str(now_dt),
            },
        }
    finally:
        con.close()


@router.get("/queue")
def get_review_queue(
    decision_filter: Optional[str] = Query(None, alias="status"),
    cse_id: Optional[str] = None,
    engine: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """
    Returns the supervisory review queue with aggregate counts and filter capabilities.
    """
    con = get_connection()
    try:
        # Base query to fetch findings with their latest review decision
        base_query = """
            WITH latest_reviews AS (
                SELECT
                    review_id,
                    finding_id,
                    reviewer,
                    reviewer_role,
                    decision,
                    notes,
                    investigation_requested,
                    created_at as review_time,
                    ROW_NUMBER() OVER (PARTITION BY finding_id ORDER BY created_at DESC) as rn
                FROM reviews
            )
            SELECT
                f.finding_id,
                f.cse_id,
                f.engine,
                f.finding_type,
                f.severity,
                f.score,
                f.description,
                f.evidence,
                f.created_at,
                COALESCE(lr.decision, 'PENDING') as review_status,
                lr.reviewer,
                lr.reviewer_role,
                lr.notes,
                lr.investigation_requested,
                lr.review_time
            FROM findings f
            LEFT JOIN latest_reviews lr ON f.finding_id = lr.finding_id AND lr.rn = 1
            WHERE 1=1
        """
        params = []

        if decision_filter and decision_filter.upper() != "ALL":
            base_query += " AND COALESCE(lr.decision, 'PENDING') = ?"
            params.append(decision_filter.upper())

        if cse_id and cse_id.upper() != "ALL":
            base_query += " AND f.cse_id = ?"
            params.append(cse_id)

        if engine and engine.upper() != "ALL":
            base_query += " AND f.engine = ?"
            params.append(engine)

        if severity and severity.upper() != "ALL":
            base_query += " AND f.severity = ?"
            params.append(severity)

        if search:
            base_query += " AND (f.description ILIKE ? OR f.finding_id ILIKE ? OR f.finding_type ILIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param])

        count_query = f"SELECT COUNT(*) FROM ({base_query}) sub"
        total = con.execute(count_query, params).fetchone()[0]

        # Order by score DESC, then created_at DESC
        data_query = base_query + " ORDER BY f.score DESC, f.created_at DESC LIMIT ? OFFSET ?"
        data_params = params + [limit, offset]

        rows = con.execute(data_query, data_params).fetchall()

        items = []
        for r in rows:
            items.append({
                "finding_id": r[0],
                "cse_id": r[1],
                "engine": r[2],
                "finding_type": r[3],
                "severity": r[4],
                "score": r[5],
                "description": r[6],
                "evidence": r[7],
                "created_at": str(r[8]),
                "review_status": r[9],
                "latest_reviewer": r[10],
                "reviewer_role": r[11],
                "review_notes": r[12],
                "investigation_requested": bool(r[13]) if r[13] is not None else False,
                "reviewed_at": str(r[14]) if r[14] else None,
            })

        # Calculate queue summary metrics
        counts_res = con.execute("""
            WITH latest_reviews AS (
                SELECT finding_id, decision,
                       ROW_NUMBER() OVER (PARTITION BY finding_id ORDER BY created_at DESC) as rn
                FROM reviews
            )
            SELECT
                COUNT(f.finding_id) as total_findings,
                COUNT(CASE WHEN lr.decision = 'VALID' THEN 1 END) as valid_count,
                COUNT(CASE WHEN lr.decision = 'FALSE_POSITIVE' THEN 1 END) as fp_count,
                COUNT(CASE WHEN lr.decision = 'NEEDS_MORE_DATA' THEN 1 END) as needs_more_count,
                COUNT(CASE WHEN lr.decision IS NULL THEN 1 END) as pending_count
            FROM findings f
            LEFT JOIN latest_reviews lr ON f.finding_id = lr.finding_id AND lr.rn = 1
        """).fetchone()

        summary = {
            "total_findings": counts_res[0],
            "valid_count": counts_res[1],
            "false_positive_count": counts_res[2],
            "needs_more_data_count": counts_res[3],
            "pending_count": counts_res[4],
        }

        return {
            "summary": summary,
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    finally:
        con.close()


@router.get("/history/{finding_id}")
def get_finding_review_history(finding_id: str):
    """
    Returns all historical review determinations and notes recorded for a specific finding.
    """
    con = get_connection()
    try:
        rows = con.execute("""
            SELECT review_id, finding_id, cse_id, reviewer, reviewer_role,
                   decision, notes, investigation_requested, created_at
            FROM reviews
            WHERE finding_id = ?
            ORDER BY created_at DESC
        """, [finding_id]).fetchall()

        history = []
        for r in rows:
            history.append({
                "review_id": r[0],
                "finding_id": r[1],
                "cse_id": r[2],
                "reviewer": r[3],
                "reviewer_role": r[4],
                "decision": r[5],
                "notes": r[6],
                "investigation_requested": bool(r[7]),
                "created_at": str(r[8]),
            })

        return {
            "finding_id": finding_id,
            "history": history,
            "total_reviews": len(history),
        }
    finally:
        con.close()


@router.get("/stats")
def get_review_stats():
    """
    Returns high-level statistics across all supervisor reviews.
    """
    con = get_connection()
    try:
        # Decision breakdown
        decisions_res = con.execute("""
            SELECT decision, COUNT(*)
            FROM reviews
            GROUP BY decision
        """).fetchall()
        decisions = {d[0]: d[1] for d in decisions_res}

        # By reviewer
        reviewers_res = con.execute("""
            SELECT reviewer, COUNT(*), MAX(created_at)
            FROM reviews
            GROUP BY reviewer
            ORDER BY COUNT(*) DESC
        """).fetchall()
        reviewers = [{"reviewer": r[0], "count": r[1], "last_active": str(r[2])} for r in reviewers_res]

        # Investigation requests
        inv_res = con.execute("""
            SELECT COUNT(*) FROM reviews WHERE investigation_requested = TRUE
        """).fetchone()[0]

        return {
            "decisions": decisions,
            "top_reviewers": reviewers,
            "total_investigations_requested": inv_res,
        }
    finally:
        con.close()
