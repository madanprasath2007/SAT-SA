"""
Ingest Router — Step 1 & 2 of SAT-SA pipeline.
Handles CSV/JSON upload, normalisation, and DuckDB insertion.
"""

import io
import json
import uuid
from datetime import datetime
from typing import List

import pandas as pd
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

from database import get_connection
from seed_data import (
    generate_alerts, generate_assets, generate_telemetry_obs,
    generate_baselines, generate_cse_alert_counts, ASSETS,
)

router = APIRouter()

REQUIRED_ALERT_COLS = {
    "alert_id", "cse_id", "category", "severity",
    "created_at", "closed_at", "mttr_seconds", "closure_notes",
    "analyst_id", "asset_id",
}


@router.post("/seed")
def seed_database():
    """Populate DuckDB with synthetic demo data."""
    con = get_connection()
    alerts = generate_alerts(500)

    # Insert alerts
    df_alerts = pd.DataFrame(alerts)
    df_alerts["created_at"] = pd.to_datetime(df_alerts["created_at"])
    df_alerts["closed_at"]  = pd.to_datetime(df_alerts["closed_at"])
    con.execute("DELETE FROM alerts")
    con.register("df_alerts_tmp", df_alerts)
    con.execute("INSERT INTO alerts SELECT * FROM df_alerts_tmp")

    # Insert assets
    for asset in ASSETS:
        asset_row = {**asset, "cse_id": "CSE-ALPHA", "last_seen": datetime.utcnow().isoformat()}
        con.execute(
            "INSERT OR REPLACE INTO assets VALUES (?,?,?,?,?,?)",
            [asset_row[k] for k in ["asset_id","asset_name","asset_type","cse_id","criticality","last_seen"]],
        )

    # Insert telemetry baselines
    baselines = generate_baselines()
    con.execute("DELETE FROM telemetry_baseline")
    for asset_id, hours in baselines.items():
        for h, stats in hours.items():
            con.execute(
                "INSERT OR REPLACE INTO telemetry_baseline VALUES (?,?,?,?)",
                [asset_id, h, stats["mu"], stats["sigma"]],
            )

    con.close()
    return {"status": "seeded", "alerts_inserted": len(alerts)}


@router.post("/upload/alerts")
async def upload_alerts_csv(file: UploadFile = File(...)):
    """Upload a CSV file of alerts for ingestion."""
    content = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV parse error: {e}")

    missing = REQUIRED_ALERT_COLS - set(df.columns)
    if missing:
        raise HTTPException(status_code=422, detail=f"Missing columns: {missing}")

    # Normalise timestamps
    for col in ["created_at", "closed_at"]:
        df[col] = pd.to_datetime(df[col], errors="coerce")

    con = get_connection()
    con.register("upload_df", df)
    inserted = len(df)
    con.execute("""
        INSERT OR IGNORE INTO alerts
        SELECT alert_id, cse_id, category, severity,
               created_at, closed_at, mttr_seconds, closure_notes,
               analyst_id, asset_id,
               COALESCE(source_ip, '') as source_ip,
               COALESCE(dest_ip, '')   as dest_ip
        FROM upload_df
    """)
    con.close()
    return {"status": "uploaded", "rows_ingested": inserted}


@router.get("/status")
def ingestion_status():
    con = get_connection()
    alert_count = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    asset_count = con.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    finding_count = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    con.close()
    return {
        "alerts": alert_count,
        "assets": asset_count,
        "findings": finding_count,
    }
