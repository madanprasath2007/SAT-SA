"""
Stage 2 — Cleaning
- Deduplication (by primary key per data_type)
- Strip leading/trailing whitespace from strings
- Fill optional missing values with defaults
- Flag (but retain) rows with non-critical missing fields
Returns cleaned DataFrame.
"""

import pandas as pd

PRIMARY_KEYS: dict[str, str] = {
    "alerts":         "alert_id",
    "cases":          "case_id",
    "investigations": "investigation_id",
    "escalations":    "escalation_id",
    "assets":         "asset_id",
    "others":         "id",
}

STRING_DEFAULTS: dict[str, dict[str, str]] = {
    "alerts": {
        "closure_notes": "",
        "source_ip":     "",
        "dest_ip":       "",
        "status":        "closed",
        "severity_raw":  "",
        "batch_id":      "",
    },
    "assets": {
        "ip_address":  "",
        "hostname":    "",
        "batch_id":    "",
    },
    "cases": {
        "closed_at":       "",
        "linked_alert_ids": "",
        "batch_id":         "",
    },
    "investigations": {
        "completed_at": "",
        "outcome":      "pending",
        "notes":        "",
        "batch_id":     "",
    },
    "escalations": {
        "resolved": "false",
        "reason":   "",
        "batch_id": "",
    },
}


def clean(df: pd.DataFrame, data_type: str) -> pd.DataFrame:
    """
    Clean the DataFrame in place (returns a new copy).
    Steps: strip strings → fill defaults → deduplicate.
    """
    df = df.copy()

    # Strip all string columns
    for col in df.select_dtypes(include=["object", "string"]).columns:
        df[col] = df[col].astype(str).str.strip()
        df[col] = df[col].replace({"nan": "", "None": "", "NaN": ""})

    # Fill optional defaults
    defaults = STRING_DEFAULTS.get(data_type, {})
    for col, default in defaults.items():
        if col in df.columns:
            df[col] = df[col].replace("", default)
            df[col] = df[col].fillna(default)
        else:
            df[col] = default

    # Deduplicate on primary key (keep first)
    pk = PRIMARY_KEYS.get(data_type)
    if pk and pk in df.columns:
        before = len(df)
        df = df.drop_duplicates(subset=[pk], keep="first")
        dupes = before - len(df)
        if dupes:
            print(f"[CLEAN] Removed {dupes} duplicate rows (key={pk})")

    return df.reset_index(drop=True)
