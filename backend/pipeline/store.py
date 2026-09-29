"""
Stage 5 — Store
Writes normalized DataFrames into DuckDB tables.
Uses INSERT OR REPLACE (upsert) on primary key to be idempotent.
"""

from typing import Any

import duckdb
import pandas as pd

# Column order must match CREATE TABLE in models.py
TABLE_COLUMNS: dict[str, list[str]] = {
    "alerts": [
        "alert_id", "cse_id", "batch_id", "category", "severity", "severity_raw",
        "created_at", "closed_at", "mttr_seconds", "closure_notes",
        "analyst_id", "asset_id", "source_ip", "dest_ip", "status",
    ],
    "cases": [
        "case_id", "cse_id", "batch_id", "title", "severity", "status",
        "opened_at", "closed_at", "analyst_id", "linked_alert_ids",
    ],
    "investigations": [
        "investigation_id", "cse_id", "batch_id", "case_id", "analyst_id",
        "started_at", "completed_at", "outcome", "notes",
    ],
    "escalations": [
        "escalation_id", "cse_id", "batch_id", "alert_id", "case_id",
        "escalated_by", "escalated_to", "escalated_at", "reason", "resolved",
    ],
    "assets": [
        "asset_id", "cse_id", "batch_id", "asset_name", "asset_type",
        "criticality", "ip_address", "hostname", "last_seen",
    ],
}

PRIMARY_KEYS: dict[str, str] = {
    "alerts":         "alert_id",
    "cases":          "case_id",
    "investigations": "investigation_id",
    "escalations":    "escalation_id",
    "assets":         "asset_id",
}


def _ensure_columns(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    """Add missing columns as empty strings, select in order."""
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols]


def store(
    df: pd.DataFrame,
    data_type: str,
    con: duckdb.DuckDBPyConnection,
) -> int:
    """
    Insert rows from df into the appropriate table.
    Returns number of rows inserted.
    """
    if data_type not in TABLE_COLUMNS:
        # Unknown data_type — skip silently
        return 0

    cols = TABLE_COLUMNS[data_type]
    df = _ensure_columns(df.copy(), cols)

    # Register as temp view and INSERT OR REPLACE
    tmp_name = f"_store_tmp_{data_type}"
    con.register(tmp_name, df)

    pk = PRIMARY_KEYS[data_type]
    cols_sql = ", ".join(cols)
    try:
        con.execute(f"""
            INSERT OR REPLACE INTO {data_type} ({cols_sql})
            SELECT {cols_sql} FROM {tmp_name}
        """)
    finally:
        try:
            con.unregister(tmp_name)
        except Exception:
            pass

    return len(df)


def store_rejects(rejects: list[dict[str, Any]], con: duckdb.DuckDBPyConnection):
    """Insert reject records; generate reject_id on the fly."""
    import uuid
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for r in rejects:
        con.execute("""
            INSERT OR IGNORE INTO rejects
                (reject_id, batch_id, cse_id, data_type, row_index, raw_data, reject_reason, stage, rejected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            str(uuid.uuid4()),
            r.get("batch_id", ""),
            r.get("cse_id", ""),
            r.get("data_type", ""),
            r.get("row_index", -1),
            r.get("raw_data", ""),
            r.get("reject_reason", ""),
            r.get("stage", ""),
            now,
        ])


def store_batch(
    batch_id: str,
    cse_id: str,
    data_type: str,
    file_name: str,
    file_format: str,
    rows_received: int,
    rows_accepted: int,
    rows_rejected: int,
    con: duckdb.DuckDBPyConnection,
):
    con.execute("""
        INSERT OR REPLACE INTO ingest_batches
            (batch_id, cse_id, data_type, file_name, file_format,
             rows_received, rows_accepted, rows_rejected)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, [batch_id, cse_id, data_type, file_name, file_format,
          rows_received, rows_accepted, rows_rejected])
