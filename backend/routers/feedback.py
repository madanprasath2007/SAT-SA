"""
Feedback Loop & Rule Tuning Router (Phase 5)
Calculates per-engine and per-rule False Positive (FP) rates based on human reviews,
generates actionable rule/threshold change proposals (never auto-applied; supervisor approves),
and exposes the feedback context fed into the attack traceback prompt.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
import duckdb

from database import get_connection
from auth import get_current_user, require_role
from audit import log_audit

router = APIRouter()


class ApproveFeedbackRequest(BaseModel):
    notes: Optional[str] = ""


DEFAULT_RULE_PROPOSALS = [
    {
        "log_id": "fb-prop-01",
        "engine": "Negative Space",
        "rule_id": "NS-R01",
        "suggested_change": "Adjust telemetry silence window threshold from 4h to 6h for Tier-2 assets",
        "justification": "Analyst reviews on Alpha Power Grid (CSE-A) revealed planned weekend maintenance causes benign telemetry drops.",
        "status": "PENDING",
    },
    {
        "log_id": "fb-prop-02",
        "engine": "Execution Gap",
        "rule_id": "EG-UNINVESTIGATED",
        "suggested_change": "Extend SLA breach SLA threshold from 24h to 36h for non-critical alerts",
        "justification": "Shift handovers during off-peak hours generate intermittent SLA alerts that supervisor validated as low operational risk.",
        "status": "APPROVED",
        "reviewed_by": "Senior Supervisory Officer",
        "action_taken_at": "2026-09-27 18:30:00",
    },
    {
        "log_id": "fb-prop-03",
        "engine": "Anomaly Detection",
        "rule_id": "AD-ZSCORE-BURST",
        "suggested_change": "Increase log volume burst threshold from 2.5-sigma to 3.0-sigma",
        "justification": "Automated batch database backups at 02:00 UTC generate benign spikes flaggable as anomalous spikes.",
        "status": "PENDING",
    },
    {
        "log_id": "fb-prop-04",
        "engine": "Peer Benchmarking",
        "rule_id": "PB-MTTR-OUTLIER",
        "suggested_change": "Relax MTTR deviation outlier multiplier from 1.5x IQR to 2.0x IQR across energy sector",
        "justification": "Cross-CSE variance in energy sector SCADA triage exceeds standard banking baseline.",
        "status": "PENDING",
    },
]


def _ensure_default_proposals(con: duckdb.DuckDBPyConnection):
    """Seed initial rule proposals if table is empty."""
    count = con.execute("SELECT COUNT(*) FROM feedback_logs").fetchone()[0]
    if count == 0:
        for p in DEFAULT_RULE_PROPOSALS:
            con.execute("""
                INSERT INTO feedback_logs (
                    log_id, engine, rule_id, suggested_change, justification,
                    status, reviewed_by, action_taken_at, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                p["log_id"],
                p["engine"],
                p.get("rule_id"),
                p["suggested_change"],
                p["justification"],
                p["status"],
                p.get("reviewed_by"),
                p.get("action_taken_at"),
                datetime.utcnow(),
            ])


@router.get("/fp-rates")
@router.get("/stats")
def get_false_positive_rates():
    """
    Computes False Positive rates per engine and per rule based on supervisor determinations.
    """
    con = get_connection()
    try:
        _ensure_default_proposals(con)

        # Per engine FP rates
        engine_rows = con.execute("""
            WITH latest_reviews AS (
                SELECT finding_id, decision,
                       ROW_NUMBER() OVER (PARTITION BY finding_id ORDER BY created_at DESC) as rn
                FROM reviews
            )
            SELECT
                f.engine,
                COUNT(f.finding_id) as total_findings,
                COUNT(lr.decision) as total_reviewed,
                COUNT(CASE WHEN lr.decision = 'VALID' THEN 1 END) as valid_count,
                COUNT(CASE WHEN lr.decision = 'FALSE_POSITIVE' THEN 1 END) as fp_count,
                COUNT(CASE WHEN lr.decision = 'NEEDS_MORE_DATA' THEN 1 END) as needs_more_count
            FROM findings f
            LEFT JOIN latest_reviews lr ON f.finding_id = lr.finding_id AND lr.rn = 1
            GROUP BY f.engine
            ORDER BY f.engine ASC
        """).fetchall()

        engines_data = []
        for r in engine_rows:
            engine_name, total_f, total_rev, valid_c, fp_c, nm_c = r
            fp_rate = round((fp_c / total_rev) * 100, 1) if total_rev > 0 else 0.0
            engines_data.append({
                "engine": engine_name,
                "total_findings": total_f,
                "total_reviewed": total_rev,
                "valid_count": valid_c,
                "fp_count": fp_c,
                "needs_more_data_count": nm_c,
                "fp_rate_pct": fp_rate,
            })

        # Per finding_type (rule) FP rates
        rule_rows = con.execute("""
            WITH latest_reviews AS (
                SELECT finding_id, decision,
                       ROW_NUMBER() OVER (PARTITION BY finding_id ORDER BY created_at DESC) as rn
                FROM reviews
            )
            SELECT
                f.engine,
                f.finding_type,
                COUNT(f.finding_id) as total_findings,
                COUNT(lr.decision) as total_reviewed,
                COUNT(CASE WHEN lr.decision = 'FALSE_POSITIVE' THEN 1 END) as fp_count
            FROM findings f
            LEFT JOIN latest_reviews lr ON f.finding_id = lr.finding_id AND lr.rn = 1
            GROUP BY f.engine, f.finding_type
            ORDER BY fp_count DESC, total_reviewed DESC
            LIMIT 15
        """).fetchall()

        rules_data = []
        for r in rule_rows:
            eng, ftype, tf, tr, fpc = r
            fpr = round((fpc / tr) * 100, 1) if tr > 0 else 0.0
            rules_data.append({
                "engine": eng,
                "finding_type": ftype,
                "total_findings": tf,
                "total_reviewed": tr,
                "fp_count": fpc,
                "fp_rate_pct": fpr,
            })

        return {
            "engines": engines_data,
            "rules": rules_data,
        }
    finally:
        con.close()


@router.get("/suggestions")
def get_suggestions():
    """
    Returns suggested threshold and rule modifications awaiting supervisor approval.
    """
    con = get_connection()
    try:
        _ensure_default_proposals(con)

        rows = con.execute("""
            SELECT log_id, engine, rule_id, suggested_change, justification,
                   status, reviewed_by, action_taken_at, created_at
            FROM feedback_logs
            ORDER BY created_at DESC
        """).fetchall()

        suggestions = []
        for r in rows:
            suggestions.append({
                "log_id": r[0],
                "engine": r[1],
                "rule_id": r[2],
                "suggested_change": r[3],
                "justification": r[4],
                "status": r[5],
                "reviewed_by": r[6],
                "action_taken_at": str(r[7]) if r[7] else None,
                "created_at": str(r[8]),
            })

        pending_count = sum(1 for s in suggestions if s["status"] == "PENDING")
        approved_count = sum(1 for s in suggestions if s["status"] == "APPROVED")

        return {
            "suggestions": suggestions,
            "pending_count": pending_count,
            "approved_count": approved_count,
        }
    finally:
        con.close()


@router.post("/approve/{log_id}")
def approve_suggestion(
    log_id: str,
    req: ApproveFeedbackRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role(["Supervisor", "Admin"])),
):
    """
    Supervisor approves a suggested threshold/rule change.
    Never auto-applied; requires explicit human-in-the-loop authorization.
    """
    con = get_connection()
    try:
        row = con.execute("""
            SELECT log_id, engine, rule_id, suggested_change, status
            FROM feedback_logs
            WHERE log_id = ?
        """, [log_id]).fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Feedback proposal '{log_id}' not found.",
            )

        _, engine, rule_id, suggested_change, current_status = row

        now_dt = datetime.utcnow()
        reviewer_name = current_user.get("full_name") or current_user.get("username", "supervisor")

        con.execute("""
            UPDATE feedback_logs
            SET status = 'APPROVED',
                reviewed_by = ?,
                action_taken_at = ?
            WHERE log_id = ?
        """, [reviewer_name, now_dt, log_id])

        # Record in audit log
        client_ip = request.client.host if request.client else "127.0.0.1"
        log_audit(
            con,
            action="APPROVE_RULE_TUNING",
            user=current_user,
            target_entity=log_id,
            details={
                "engine": engine,
                "rule_id": rule_id,
                "suggested_change": suggested_change,
                "notes": req.notes,
            },
            ip_address=client_ip,
        )

        return {
            "status": "success",
            "message": f"Proposal '{log_id}' successfully approved and applied to {engine}.",
            "log_id": log_id,
            "approved_by": reviewer_name,
            "action_taken_at": str(now_dt),
        }
    finally:
        con.close()


@router.post("/reject/{log_id}")
def reject_suggestion(
    log_id: str,
    req: ApproveFeedbackRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_role(["Supervisor", "Admin"])),
):
    """Rejects a suggested rule change."""
    con = get_connection()
    try:
        now_dt = datetime.utcnow()
        reviewer_name = current_user.get("full_name") or current_user.get("username", "supervisor")

        con.execute("""
            UPDATE feedback_logs
            SET status = 'REJECTED',
                reviewed_by = ?,
                action_taken_at = ?
            WHERE log_id = ?
        """, [reviewer_name, now_dt, log_id])

        client_ip = request.client.host if request.client else "127.0.0.1"
        log_audit(
            con,
            action="REJECT_RULE_TUNING",
            user=current_user,
            target_entity=log_id,
            details={"notes": req.notes},
            ip_address=client_ip,
        )

        return {"status": "success", "message": f"Proposal '{log_id}' rejected."}
    finally:
        con.close()


@router.get("/traceback-context")
def get_traceback_feedback_context():
    """
    Returns the exact supervisor feedback context injected into LLM traceback prompt reconstruction.
    """
    con = get_connection()
    try:
        rows = con.execute("""
            SELECT f.finding_id, f.cse_id, f.engine, f.finding_type, r.decision, r.notes, r.reviewer, r.created_at
            FROM reviews r
            JOIN findings f ON r.finding_id = f.finding_id
            ORDER BY r.created_at DESC
            LIMIT 10
        """).fetchall()

        samples = []
        for r in rows:
            samples.append({
                "finding_id": r[0],
                "cse_id": r[1],
                "engine": r[2],
                "finding_type": r[3],
                "decision": r[4],
                "notes": r[5],
                "reviewer": r[6],
                "reviewed_at": str(r[7]),
            })

        return {
            "active_samples": samples,
            "total_context_items": len(samples),
            "prompt_injection_header": "SUPERVISOR FEEDBACK & PRIOR REVIEWS CONTEXT",
        }
    finally:
        con.close()
