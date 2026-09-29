"""
Review & Feedback Router (Phase 5)
Handles:
1. Human-in-the-loop review workflow (Valid / False Positive / Needs More Data)
2. Review Queue with priority ordering
3. Full reviewer history per finding
4. Feedback Loop: engine false-positive rates and rule tuning suggestions
5. Approval workflow for supervisor-reviewed changes
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from models import get_connection
from auth import get_current_user, require_role
from audit import log_audit

router = APIRouter()


class ReviewSubmissionRequest(BaseModel):
    finding_id: str
    cse_id: str
    decision: str  # VALID, FALSE_POSITIVE, NEEDS_MORE_DATA
    notes: Optional[str] = ""
    investigation_requested: Optional[bool] = False


class SuggestionActionRequest(BaseModel):
    action: str  # APPROVE, REJECT
    justification: Optional[str] = ""


@router.post("/")
def submit_review(
    req: ReviewSubmissionRequest,
    user: Dict[str, Any] = Depends(require_role(["Admin", "Supervisor"])),
):
    """
    Submits a human supervisory review decision on a finding.
    Closes the loop: generates tuning feedback if marked FALSE_POSITIVE,
    and logs audit entry.
    """
    decision = req.decision.upper().strip()
    if decision not in ("VALID", "FALSE_POSITIVE", "NEEDS_MORE_DATA"):
        raise HTTPException(
            status_code=400,
            detail="Invalid decision. Must be one of: 'VALID', 'FALSE_POSITIVE', 'NEEDS_MORE_DATA'.",
        )

    con = get_connection()
    review_id = f"rev-{uuid.uuid4().hex[:10]}"

    # Verify finding exists and get its metadata
    f_row = con.execute("""
        SELECT finding_id, cse_id, engine, finding_type, severity, description
        FROM findings WHERE finding_id = ?
    """, [req.finding_id]).fetchone()

    engine_name = f_row[2] if f_row else "UnknownEngine"
    finding_type = f_row[3] if f_row else req.finding_id

    # Insert review
    con.execute("""
        INSERT INTO reviews (review_id, finding_id, cse_id, reviewer, reviewer_role, decision, notes, investigation_requested, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        review_id,
        req.finding_id,
        req.cse_id,
        user.get("full_name") or user.get("username"),
        user.get("role"),
        decision,
        req.notes,
        req.investigation_requested,
        datetime.utcnow(),
    ])

    # If FALSE_POSITIVE, create a feedback tuning suggestion
    suggested_log_id = None
    if decision == "FALSE_POSITIVE":
        suggested_log_id = f"fb-{uuid.uuid4().hex[:10]}"
        suggestion_text = f"Adjust sensitivity threshold on {engine_name} ({finding_type}) to mitigate recurring false positive classifications."
        justification_text = f"Supervisor note: {req.notes or 'Determined non-malicious under formal review'}"

        con.execute("""
            INSERT INTO feedback_logs (log_id, engine, rule_id, suggested_change, justification, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
        """, [suggested_log_id, engine_name, finding_type, suggestion_text, justification_text, datetime.utcnow()])

    # Record audit log
    log_audit(
        con,
        action="REVIEW_SUBMITTED",
        user=user,
        target_entity=req.cse_id,
        details={
            "review_id": review_id,
            "finding_id": req.finding_id,
            "decision": decision,
            "investigation_requested": req.investigation_requested,
            "feedback_generated": suggested_log_id,
        },
    )

    con.close()
    return {
        "status": "success",
        "review_id": review_id,
        "decision": decision,
        "feedback_log_id": suggested_log_id,
    }


class SingleFindingReviewRequest(BaseModel):
    decision: str  # VALID, FALSE_POSITIVE, NEEDS_MORE_DATA
    notes: Optional[str] = ""
    investigation_requested: Optional[bool] = False
    cse_id: Optional[str] = None


@router.post("/{finding_id}")
def submit_finding_review(
    finding_id: str,
    req: SingleFindingReviewRequest,
    user: Dict[str, Any] = Depends(require_role(["Admin", "Supervisor"])),
):
    """
    Submits a review targeting a finding_id in URL path.
    """
    cse_id = req.cse_id
    if not cse_id:
        con = get_connection()
        row = con.execute("SELECT cse_id FROM findings WHERE finding_id = ?", [finding_id]).fetchone()
        con.close()
        cse_id = row[0] if row else "CSE-A"
    return submit_review(
        ReviewSubmissionRequest(
            finding_id=finding_id,
            cse_id=cse_id,
            decision=req.decision,
            notes=req.notes,
            investigation_requested=req.investigation_requested,
        ),
        user=user,
    )


@router.get("/")
def list_reviews(
    finding_id: Optional[str] = None,
    cse_id: Optional[str] = None,
    decision: Optional[str] = None,
    limit: int = 100,
):
    """List historical review records."""
    con = get_connection()
    query = "SELECT review_id, finding_id, cse_id, reviewer, reviewer_role, decision, notes, investigation_requested, created_at FROM reviews WHERE 1=1"
    params = []
    if finding_id:
        query += " AND finding_id = ?"
        params.append(finding_id)
    if cse_id:
        query += " AND cse_id = ?"
        params.append(cse_id)
    if decision and isinstance(decision, str):
        query += " AND decision = ?"
        params.append(decision.upper())

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = con.execute(query, params).fetchall()
    cols = ["review_id", "finding_id", "cse_id", "reviewer", "reviewer_role", "decision", "notes", "investigation_requested", "created_at"]
    data = []
    for r in rows:
        d = dict(zip(cols, r))
        d["created_at"] = str(d["created_at"])
        data.append(d)

    con.close()
    return {"data": data, "total": len(data)}


@router.get("/history/{finding_id}")
def get_finding_review_history(finding_id: str):
    """Retrieve full audit history of decisions and notes for a specific finding."""
    return list_reviews(finding_id=finding_id)


@router.get("/queue")
def get_review_queue(
    cse_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = 50,
):
    """
    Returns findings prioritized by severity and review status,
    with summary stats enabling efficient supervisor queue triage.
    """
    con = get_connection()
    query = """
        SELECT f.finding_id, f.cse_id, f.engine, f.finding_type, f.severity, f.description, f.score, f.created_at,
               r.decision, r.reviewer, r.notes, r.investigation_requested
        FROM findings f
        LEFT JOIN (
            SELECT finding_id, decision, reviewer, notes, investigation_requested, created_at,
                   ROW_NUMBER() OVER (PARTITION BY finding_id ORDER BY created_at DESC) as rn
            FROM reviews
        ) r ON f.finding_id = r.finding_id AND r.rn = 1
        WHERE 1=1
    """
    params = []
    if cse_id and cse_id.upper() != "ALL":
        query += " AND f.cse_id = ?"
        params.append(cse_id)

    if status and status.upper() != "ALL":
        st = status.upper()
        if st == "PENDING":
            query += " AND r.decision IS NULL"
        else:
            query += " AND r.decision = ?"
            params.append(st)

    query += """
        ORDER BY
            CASE WHEN r.decision IS NULL THEN 0 ELSE 1 END ASC,
            CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END ASC,
            f.score DESC
        LIMIT ?
    """
    params.append(limit)

    rows = con.execute(query, params).fetchall()
    cols = ["finding_id", "cse_id", "engine", "finding_type", "severity", "description", "score", "created_at", "decision", "reviewer", "notes", "investigation_requested"]
    data = []
    for r in rows:
        d = dict(zip(cols, r))
        d["created_at"] = str(d["created_at"])
        d["is_reviewed"] = d["decision"] is not None
        d["review_status"] = d["decision"] or "PENDING"
        data.append(d)

    # Compute summary counts
    counts_res = con.execute("""
        WITH latest_r AS (
            SELECT finding_id, decision,
                   ROW_NUMBER() OVER (PARTITION BY finding_id ORDER BY created_at DESC) as rn
            FROM reviews
        )
        SELECT
            COUNT(f.finding_id) as total,
            COUNT(CASE WHEN lr.decision = 'VALID' THEN 1 END) as valid_count,
            COUNT(CASE WHEN lr.decision = 'FALSE_POSITIVE' THEN 1 END) as fp_count,
            COUNT(CASE WHEN lr.decision = 'NEEDS_MORE_DATA' THEN 1 END) as nmd_count,
            COUNT(CASE WHEN lr.decision IS NULL THEN 1 END) as pending_count
        FROM findings f
        LEFT JOIN latest_r lr ON f.finding_id = lr.finding_id AND lr.rn = 1
    """).fetchone()

    summary = {
        "total": counts_res[0],
        "valid": counts_res[1],
        "false_positive": counts_res[2],
        "needs_more_data": counts_res[3],
        "pending": counts_res[4],
    }

    con.close()
    return {"data": data, "total": len(data), "summary": summary}


@router.get("/feedback/stats")
def get_feedback_stats():
    """
    Computes false-positive rate and decision distribution per engine and per rule.
    """
    con = get_connection()

    # Per engine stats
    rows = con.execute("""
        SELECT f.engine,
               COUNT(r.review_id) as total_reviewed,
               SUM(CASE WHEN r.decision = 'VALID' THEN 1 ELSE 0 END) as valid_count,
               SUM(CASE WHEN r.decision = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) as fp_count,
               SUM(CASE WHEN r.decision = 'NEEDS_MORE_DATA' THEN 1 ELSE 0 END) as nmd_count
        FROM findings f
        JOIN reviews r ON f.finding_id = r.finding_id
        GROUP BY f.engine
    """).fetchall()

    engine_stats = []
    for eng, tot, val, fp, nmd in rows:
        fp_rate = round((fp / tot * 100.0), 1) if tot > 0 else 0.0
        engine_stats.append({
            "engine": eng,
            "total_reviews": tot,
            "valid": val,
            "false_positive": fp,
            "needs_more_data": nmd,
            "false_positive_rate": fp_rate,
        })

    # Summary overall
    total_reviews = sum(s["total_reviews"] for s in engine_stats)
    total_fp = sum(s["false_positive"] for s in engine_stats)
    overall_fp_rate = round((total_fp / total_reviews * 100.0), 1) if total_reviews > 0 else 0.0

    con.close()
    return {
        "data": {
            "overall": {
                "total_reviews": total_reviews,
                "total_false_positives": total_fp,
                "overall_fp_rate": overall_fp_rate,
            },
            "by_engine": engine_stats,
        }
    }


@router.get("/feedback/suggestions")
def get_feedback_suggestions(status: Optional[str] = Query(None)):
    """List rule tuning suggestions created from reviewer decisions."""
    con = get_connection()
    query = "SELECT log_id, engine, rule_id, suggested_change, justification, status, reviewed_by, action_taken_at, created_at FROM feedback_logs WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status.upper())

    query += " ORDER BY created_at DESC"
    rows = con.execute(query, params).fetchall()
    cols = ["log_id", "engine", "rule_id", "suggested_change", "justification", "status", "reviewed_by", "action_taken_at", "created_at"]
    data = []
    for r in rows:
        d = dict(zip(cols, r))
        d["created_at"] = str(d["created_at"])
        if d.get("action_taken_at"):
            d["action_taken_at"] = str(d["action_taken_at"])
        data.append(d)

    con.close()
    return {"data": data, "total": len(data)}


@router.post("/feedback/suggestions/{log_id}/action")
def action_feedback_suggestion(
    log_id: str,
    req: SuggestionActionRequest,
    user: Dict[str, Any] = Depends(require_role(["Admin", "Supervisor"])),
):
    """
    Approve or reject a suggested rule modification.
    Supervisory control: threshold and rule changes are never auto-applied;
    they require explicit supervisory approval.
    """
    act = req.action.upper()
    if act not in ("APPROVE", "REJECT"):
        raise HTTPException(status_code=400, detail="Action must be 'APPROVE' or 'REJECT'.")

    new_status = "APPROVED" if act == "APPROVE" else "REJECTED"
    con = get_connection()

    con.execute("""
        UPDATE feedback_logs
        SET status = ?, reviewed_by = ?, action_taken_at = CURRENT_TIMESTAMP
        WHERE log_id = ?
    """, [new_status, user.get("full_name") or user.get("username"), log_id])

    log_audit(
        con,
        action=f"FEEDBACK_SUGGESTION_{new_status}",
        user=user,
        details={"log_id": log_id, "action": act, "justification": req.justification},
    )

    con.close()
    return {"status": "success", "log_id": log_id, "new_status": new_status}
