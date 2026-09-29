"""
Stage 3 — Normalization
- Parse and convert all timestamps to ISO-8601 UTC
- Map severity strings to canonical CRITICAL|HIGH|MEDIUM|LOW
- Validate and clean IP addresses
- Build common schema output per data_type
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

import pandas as pd

# ── Severity mapping ──────────────────────────────────────────────────────────
SEVERITY_MAP: dict[str, str] = {
    # Standard
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
    # Abbrevs
    "crit": "CRITICAL", "crit.": "CRITICAL",
    "hi":   "HIGH",     "med":   "MEDIUM",   "lo": "LOW",
    # Verbose
    "moderate": "MEDIUM", "severe": "HIGH",
    # Numeric / info (downmap)
    "info":    "LOW",  "informational": "LOW",
    "warning": "MEDIUM", "warn": "MEDIUM",
    "unknown": "LOW",
}


def map_severity(raw: str) -> str:
    """Map a raw severity string to canonical CRITICAL|HIGH|MEDIUM|LOW."""
    normalized = str(raw).strip().lower()
    return SEVERITY_MAP.get(normalized, "LOW")   # default LOW for unknown


# ── Timestamp parsing ─────────────────────────────────────────────────────────
_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%d/%m/%y %H:%M",            # 20/08/25 10:30
    "%d/%m/%Y %H:%M",            # 20/08/2025 10:30
    "%m-%d-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
    "%d-%b-%Y %H:%M",            # 20-Aug-2025 10:30
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d",
]


def parse_timestamp(value: Any) -> datetime | None:
    """Try multiple formats; return UTC datetime or None."""
    if pd.isna(value) or str(value).strip() in ("", "nan", "None", "NaT"):
        return None
    s = str(value).strip()
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    # Last-ditch: pandas parser
    try:
        ts = pd.to_datetime(s, utc=True)
        return ts.to_pydatetime()
    except Exception:
        return None


def to_iso(value: Any) -> str | None:
    """Return ISO-8601 UTC string or None."""
    dt = parse_timestamp(value)
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── IP validation ─────────────────────────────────────────────────────────────
def validate_ip(ip: str) -> str:
    """Return ip if valid, else empty string."""
    try:
        ipaddress.ip_address(str(ip).strip())
        return str(ip).strip()
    except ValueError:
        return ""


# ── Per-type normalization ────────────────────────────────────────────────────
def normalize_alerts(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["severity_raw"] = df["severity"].astype(str)
    df["severity"]     = df["severity"].apply(lambda x: map_severity(str(x)))
    df["created_at"]   = df["created_at"].apply(to_iso)
    df["closed_at"]    = df["closed_at"].apply(to_iso)
    if "source_ip" in df.columns:
        df["source_ip"] = df["source_ip"].apply(lambda x: validate_ip(str(x)))
    if "dest_ip" in df.columns:
        df["dest_ip"]   = df["dest_ip"].apply(lambda x: validate_ip(str(x)))
    if "mttr_seconds" in df.columns:
        df["mttr_seconds"] = pd.to_numeric(df["mttr_seconds"], errors="coerce")
    return df


def normalize_cases(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["severity"]   = df["severity"].apply(lambda x: map_severity(str(x)))
    df["opened_at"]  = df["opened_at"].apply(to_iso)
    if "closed_at" in df.columns:
        df["closed_at"] = df["closed_at"].apply(to_iso)
    return df


def normalize_investigations(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["started_at"]    = df["started_at"].apply(to_iso)
    if "completed_at" in df.columns:
        df["completed_at"] = df["completed_at"].apply(to_iso)
    return df


def normalize_escalations(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["escalated_at"] = df["escalated_at"].apply(to_iso)
    if "resolved" in df.columns:
        df["resolved"] = df["resolved"].apply(
            lambda x: str(x).strip().lower() in ("true", "1", "yes")
        )
    return df


def normalize_assets(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["criticality"] = df["criticality"].apply(lambda x: map_severity(str(x)))
    if "last_seen" in df.columns:
        df["last_seen"] = df["last_seen"].apply(to_iso)
    if "ip_address" in df.columns:
        df["ip_address"] = df["ip_address"].apply(lambda x: validate_ip(str(x)))
    return df


_NORMALIZERS = {
    "alerts":         normalize_alerts,
    "cases":          normalize_cases,
    "investigations": normalize_investigations,
    "escalations":    normalize_escalations,
    "assets":         normalize_assets,
}


def normalize(df: pd.DataFrame, data_type: str) -> pd.DataFrame:
    """Dispatch to the right normalizer."""
    fn = _NORMALIZERS.get(data_type)
    if fn:
        return fn(df)
    return df
