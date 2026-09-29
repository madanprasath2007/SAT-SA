"""
Phase 1 Ingest Router
POST /api/ingest/{cse_id}/{data_type}  — upload CSV or JSON file
GET  /api/rejects                       — list rejected rows
GET  /api/normalization/preview         — before/after pairs for a CSE
GET  /api/cses/{id}/stats               — per-CSE ingestion statistics
GET  /api/ingest/status                 — total counts (kept for compat)

Legacy endpoints (seed, upload/alerts) are preserved below.
"""

import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

import pandas as pd
from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse

from models import get_connection, seed_cses
from pipeline.orchestrator import run_pipeline

router = APIRouter()

SUPPORTED_DATA_TYPES = {"alerts", "cases", "investigations", "escalations", "assets", "others"}
SUPPORTED_CSE_IDS    = {"CSE-A", "CSE-B", "CSE-C", "CSE-D"}
FILE_FORMAT_MAP      = {"text/csv": "csv", "application/json": "json",
                        "application/octet-stream": "csv"}  # default to csv for binary


# ── POST /api/ingest/{cse_id}/{data_type} ────────────────────────────────────
@router.post("/{cse_id}/{data_type}")
async def ingest_file(
    cse_id: str,
    data_type: str,
    file: UploadFile = File(...),
):
    """
    Upload a CSV or JSON file for a CSE and data type.
    Runs the full 5-stage pipeline and returns accepted/rejected counts.
    """
    cse_id    = cse_id.upper()
    data_type = data_type.lower()

    if cse_id not in SUPPORTED_CSE_IDS:
        raise HTTPException(status_code=400, detail=f"Unknown cse_id '{cse_id}'. Must be one of {sorted(SUPPORTED_CSE_IDS)}")
    if data_type not in SUPPORTED_DATA_TYPES:
        raise HTTPException(status_code=400, detail=f"Unknown data_type '{data_type}'. Must be one of {sorted(SUPPORTED_DATA_TYPES)}")

    # Detect file format from name or content-type
    fname  = file.filename or "upload"
    if fname.endswith(".json"):
        fmt = "json"
    elif fname.endswith(".csv"):
        fmt = "csv"
    else:
        ct  = (file.content_type or "").lower()
        fmt = FILE_FORMAT_MAP.get(ct, "csv")

    content = await file.read()

    con = get_connection()
    seed_cses(con)   # idempotent — ensures CSE rows exist
    try:
        result = run_pipeline(
            content=content,
            file_format=fmt,
            cse_id=cse_id,
            data_type=data_type,
            file_name=fname,
            con=con,
        )
    finally:
        con.close()

    return JSONResponse(content=result)


# ── GET /api/rejects ─────────────────────────────────────────────────────────
@router.get("/rejects")
def get_rejects(
    cse_id:    Optional[str] = Query(None),
    data_type: Optional[str] = Query(None),
    stage:     Optional[str] = Query(None),
    limit:     int           = Query(200, le=1000),
):
    """Return rejected rows, optionally filtered."""
    con = get_connection()
    where_clauses, params = [], []
    if cse_id:
        where_clauses.append("cse_id = ?")
        params.append(cse_id.upper())
    if data_type:
        where_clauses.append("data_type = ?")
        params.append(data_type.lower())
    if stage:
        where_clauses.append("stage = ?")
        params.append(stage)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    rows = con.execute(
        f"SELECT * FROM rejects {where_sql} ORDER BY rejected_at DESC LIMIT ?",
        params + [limit],
    ).fetchall()
    cols = ["reject_id", "batch_id", "cse_id", "data_type", "row_index",
            "raw_data", "reject_reason", "stage", "rejected_at"]
    con.close()
    data = [dict(zip(cols, r)) for r in rows]
    return {"total": len(data), "data": data}


# ── GET /api/normalization/preview ───────────────────────────────────────────
@router.get("/normalization/preview")
def normalization_preview(
    cse_id:    str = Query(...),
    data_type: str = Query("alerts"),
    limit:     int = Query(20, le=100),
):
    """
    Return before/after pairs showing raw vs normalised values.
    'Before' = raw fields stored on the row (severity_raw, etc.)
    'After'  = normalised fields.
    """
    cse_id    = cse_id.upper()
    data_type = data_type.lower()
    con = get_connection()

    if data_type == "alerts":
        rows = con.execute("""
            SELECT alert_id, cse_id,
                   severity_raw  AS severity_before,
                   severity      AS severity_after,
                   created_at,
                   source_ip,
                   mttr_seconds,
                   category
            FROM alerts
            WHERE cse_id = ?
            LIMIT ?
        """, [cse_id, limit]).fetchall()
        cols = ["alert_id", "cse_id", "severity_before", "severity_after",
                "created_at_iso", "source_ip", "mttr_seconds", "category"]
        pairs = [dict(zip(cols, r)) for r in rows]

    elif data_type == "assets":
        rows = con.execute("""
            SELECT asset_id, cse_id, asset_name, criticality, ip_address, last_seen
            FROM assets WHERE cse_id = ? LIMIT ?
        """, [cse_id, limit]).fetchall()
        cols = ["asset_id", "cse_id", "asset_name", "criticality_normalised", "ip_address", "last_seen_iso"]
        pairs = [dict(zip(cols, r)) for r in rows]

    else:
        pairs = []

    con.close()
    return {
        "cse_id":    cse_id,
        "data_type": data_type,
        "count":     len(pairs),
        "data":      pairs,
    }


# ── GET /api/cses/{id}/stats ─────────────────────────────────────────────────
@router.get("/cses/{cse_id}/stats")
def cse_stats(cse_id: str):
    """Per-CSE ingestion statistics."""
    cse_id = cse_id.upper()
    con = get_connection()

    # Batch summary
    batches = con.execute("""
        SELECT data_type,
               COUNT(*)         AS batch_count,
               SUM(rows_received) AS total_received,
               SUM(rows_accepted) AS total_accepted,
               SUM(rows_rejected) AS total_rejected,
               MAX(ingested_at)   AS last_ingested
        FROM ingest_batches
        WHERE cse_id = ?
        GROUP BY data_type
        ORDER BY data_type
    """, [cse_id]).fetchall()
    batch_cols = ["data_type", "batch_count", "total_received",
                  "total_accepted", "total_rejected", "last_ingested"]

    # Alert severity breakdown
    sev_rows = con.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM alerts WHERE cse_id = ?
        GROUP BY severity ORDER BY severity
    """, [cse_id]).fetchall()

    # Entity counts
    entity_rows = con.execute("""
        SELECT entity_type, COUNT(*) as cnt
        FROM entities WHERE cse_id = ?
        GROUP BY entity_type
    """, [cse_id]).fetchall()

    con.close()

    return {
        "cse_id": cse_id,
        "batches": [dict(zip(batch_cols, r)) for r in batches],
        "alert_severity_breakdown": {r[0]: r[1] for r in sev_rows},
        "entity_counts":            {r[0]: r[1] for r in entity_rows},
    }


# ── GET /api/ingest/status (compat) ──────────────────────────────────────────
@router.get("/status")
def ingestion_status():
    con = get_connection()
    counts = {}
    for tbl in ("alerts", "cases", "investigations", "escalations", "assets",
                "entities", "rejects", "ingest_batches"):
        try:
            n = con.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        except Exception:
            n = 0
        counts[tbl] = n
    con.close()
    return counts


# ── POST /api/ingest/seed (legacy compat) ────────────────────────────────────
@router.post("/seed")
def seed_database():
    """Seed CSE metadata; does not add alerts (use synthetic generator)."""
    con = get_connection()
    seed_cses(con)
    con.close()
    return {"status": "seeded", "message": "CSE metadata seeded. Use synthetic generator for alert data."}


# ── POST /api/ingest/upload/alerts (legacy compat) ───────────────────────────
@router.post("/upload/alerts")
async def upload_alerts_csv_legacy(file: UploadFile = File(...)):
    """Legacy endpoint — routes to CSE-A alerts ingest."""
    content = await file.read()
    con = get_connection()
    seed_cses(con)
    result = run_pipeline(
        content=content, file_format="csv",
        cse_id="CSE-A", data_type="alerts",
        file_name=file.filename or "upload.csv",
        con=con,
    )
    con.close()
    return {"status": "uploaded", "rows_ingested": result["rows_accepted"], **result}
