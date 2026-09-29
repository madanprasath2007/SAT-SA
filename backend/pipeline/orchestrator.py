"""
Pipeline Orchestrator
Runs all 5 stages in sequence:
  parse → validate → clean → normalize → entity_map → store
"""

import io
import json
import uuid
from typing import Any

import pandas as pd

import duckdb
from pipeline.validation    import validate
from pipeline.cleaning      import clean
from pipeline.normalization import normalize
from pipeline.entity_mapping import map_entities
from pipeline.store         import store, store_rejects, store_batch


def run_pipeline(
    content: bytes,
    file_format: str,    # "csv" or "json"
    cse_id: str,
    data_type: str,
    file_name: str,
    con: duckdb.DuckDBPyConnection,
) -> dict[str, Any]:
    """
    Full pipeline: parse → validate → clean → normalize → entity_map → store.
    Returns a result dict with counts.
    """
    batch_id = str(uuid.uuid4())

    # ── Parse ────────────────────────────────────────────────────────────────
    try:
        if file_format == "csv":
            df_raw = pd.read_csv(io.BytesIO(content), dtype=str, keep_default_na=False)
        else:
            data = json.loads(content)
            if isinstance(data, dict):
                data = [data]
            df_raw = pd.DataFrame(data).astype(str)
    except Exception as e:
        return {
            "batch_id":      batch_id,
            "cse_id":        cse_id,
            "data_type":     data_type,
            "rows_received": 0,
            "rows_accepted": 0,
            "rows_rejected": 0,
            "error":         f"Parse error: {e}",
        }

    rows_received = len(df_raw)

    # Stamp batch_id and cse_id onto every row before pipeline
    df_raw["batch_id"] = batch_id
    if "cse_id" not in df_raw.columns or df_raw["cse_id"].eq("").all():
        df_raw["cse_id"] = cse_id

    # ── Stage 1: Schema Validation ───────────────────────────────────────────
    valid_df, rejects = validate(df_raw, data_type, batch_id, cse_id)

    # ── Stage 2: Cleaning ────────────────────────────────────────────────────
    rows_before_clean = len(valid_df)
    if not valid_df.empty:
        valid_df = clean(valid_df, data_type)
    # Deduped rows count as additional rejected (for accounting)
    deduped = rows_before_clean - len(valid_df)
    if deduped > 0:
        for i in range(deduped):
            rejects.append({
                "batch_id":      batch_id,
                "cse_id":        cse_id,
                "data_type":     data_type,
                "row_index":     -1,
                "raw_data":      "{}",
                "reject_reason": "Duplicate row removed during cleaning",
                "stage":         "cleaning",
            })

    # ── Stage 3: Normalization ───────────────────────────────────────────────
    if not valid_df.empty:
        valid_df = normalize(valid_df, data_type)

    # ── Stage 4: Entity Mapping ──────────────────────────────────────────────
    if not valid_df.empty:
        map_entities(valid_df, data_type, cse_id, con)

    # ── Stage 5: Store ───────────────────────────────────────────────────────
    rows_accepted = 0
    if not valid_df.empty:
        rows_accepted = store(valid_df, data_type, con)

    rows_rejected = len(rejects)
    store_rejects(rejects, con)
    store_batch(
        batch_id, cse_id, data_type, file_name, file_format,
        rows_received, rows_accepted, rows_rejected, con,
    )

    return {
        "batch_id":      batch_id,
        "cse_id":        cse_id,
        "data_type":     data_type,
        "file_name":     file_name,
        "rows_received": rows_received,
        "rows_accepted": rows_accepted,
        "rows_rejected": rows_rejected,
    }
