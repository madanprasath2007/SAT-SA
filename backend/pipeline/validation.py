"""
Stage 1 — Schema Validation
Checks required fields, basic type constraints.
Invalid rows are tagged with a reason and sent to rejects.
Returns (valid_rows, reject_records).
"""

import json
from typing import Any

import pandas as pd

# Required fields per data type
REQUIRED_FIELDS: dict[str, set[str]] = {
    "alerts": {
        "alert_id", "cse_id", "category", "severity",
        "created_at", "closed_at", "analyst_id", "asset_id",
    },
    "cases": {"case_id", "cse_id", "title", "severity", "status", "opened_at"},
    "investigations": {"investigation_id", "cse_id", "case_id", "analyst_id", "started_at"},
    "escalations": {"escalation_id", "cse_id", "alert_id", "escalated_by", "escalated_at"},
    "assets": {"asset_id", "cse_id", "asset_name", "asset_type", "criticality"},
    "others": set(),
}


def validate(
    df: pd.DataFrame,
    data_type: str,
    batch_id: str,
    cse_id: str,
) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    """
    Validate rows in `df` against the schema for `data_type`.
    Returns (valid_df, rejects_list).
    """
    required = REQUIRED_FIELDS.get(data_type, set())
    rejects: list[dict[str, Any]] = []
    valid_indices: list[int] = []

    for idx, row in df.iterrows():
        reason = _check_row(row, required, data_type)
        if reason:
            rejects.append({
                "batch_id":    batch_id,
                "cse_id":      cse_id,
                "data_type":   data_type,
                "row_index":   int(idx),
                "raw_data":    json.dumps(row.to_dict(), default=str),
                "reject_reason": reason,
                "stage":       "schema_validation",
            })
        else:
            valid_indices.append(idx)

    valid_df = df.loc[valid_indices].copy() if valid_indices else df.iloc[0:0].copy()
    return valid_df, rejects


def _check_row(row: pd.Series, required: set[str], data_type: str) -> str | None:
    """Return a rejection reason string, or None if row is valid."""
    # Missing required columns
    for field in required:
        if field not in row.index:
            return f"Missing column: {field}"
        val = row[field]
        if pd.isna(val) or str(val).strip() == "":
            return f"Empty required field: {field}"

    # Type checks for alerts
    if data_type == "alerts":
        # mttr_seconds must be numeric if present
        if "mttr_seconds" in row.index:
            try:
                v = row["mttr_seconds"]
                if not pd.isna(v):
                    float(v)
            except (ValueError, TypeError):
                return f"Non-numeric mttr_seconds: {row.get('mttr_seconds')}"

    return None
