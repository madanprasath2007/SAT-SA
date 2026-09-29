"""
Unit tests for pipeline stages:
  - validation
  - cleaning
  - normalization
  - entity_mapping
  - store
"""

import sys
import os
import json
import tempfile
import pytest
import pandas as pd

# Ensure backend root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.validation    import validate
from pipeline.cleaning      import clean
from pipeline.normalization import (
    map_severity, parse_timestamp, validate_ip,
    normalize_alerts, normalize_assets,
)
from pipeline.entity_mapping import map_entities
from pipeline.store          import store, store_rejects, store_batch

import duckdb
from models import init_db, get_connection


# ── Helpers ───────────────────────────────────────────────────────────────────
def make_alert_df(**overrides) -> pd.DataFrame:
    base = {
        "alert_id":      "ALT-0001",
        "cse_id":        "CSE-A",
        "batch_id":      "BATCH-001",
        "category":      "Suspicious Login",
        "severity":      "CRIT",
        "created_at":    "20/08/25 10:30",
        "closed_at":     "2025-08-20T11:30:00Z",
        "mttr_seconds":  "3600",
        "closure_notes": "Test note",
        "analyst_id":    "ANA-001",
        "asset_id":      "ASSET-001",
        "source_ip":     "203.0.113.5",
        "dest_ip":       "10.0.0.1",
        "status":        "closed",
        "severity_raw":  "",
    }
    base.update(overrides)
    return pd.DataFrame([base])


def make_in_memory_db():
    """Create a fresh in-memory DuckDB with Phase 1 schema."""
    con = duckdb.connect(":memory:")
    # Run schema from models
    os.environ["DB_PATH"] = ":memory:"
    # Create tables inline
    for ddl in [
        """CREATE TABLE IF NOT EXISTS alerts (
            alert_id VARCHAR PRIMARY KEY, cse_id VARCHAR, batch_id VARCHAR,
            category VARCHAR, severity VARCHAR, severity_raw VARCHAR,
            created_at VARCHAR, closed_at VARCHAR, mttr_seconds DOUBLE,
            closure_notes TEXT, analyst_id VARCHAR, asset_id VARCHAR,
            source_ip VARCHAR, dest_ip VARCHAR, status VARCHAR DEFAULT 'closed'
        )""",
        """CREATE TABLE IF NOT EXISTS rejects (
            reject_id VARCHAR PRIMARY KEY, batch_id VARCHAR, cse_id VARCHAR,
            data_type VARCHAR, row_index INTEGER, raw_data VARCHAR,
            reject_reason VARCHAR, stage VARCHAR, rejected_at VARCHAR
        )""",
        """CREATE TABLE IF NOT EXISTS ingest_batches (
            batch_id VARCHAR PRIMARY KEY, cse_id VARCHAR, data_type VARCHAR,
            file_name VARCHAR, file_format VARCHAR, rows_received INTEGER,
            rows_accepted INTEGER, rows_rejected INTEGER, ingested_at VARCHAR,
            status VARCHAR DEFAULT 'completed'
        )""",
        """CREATE TABLE IF NOT EXISTS entities (
            entity_id VARCHAR PRIMARY KEY, entity_type VARCHAR, identifier VARCHAR,
            cse_id VARCHAR, first_seen VARCHAR, last_seen VARCHAR, linked_asset_ids VARCHAR
        )""",
        """CREATE TABLE IF NOT EXISTS assets (
            asset_id VARCHAR PRIMARY KEY, cse_id VARCHAR, batch_id VARCHAR,
            asset_name VARCHAR, asset_type VARCHAR, criticality VARCHAR,
            ip_address VARCHAR, hostname VARCHAR, last_seen VARCHAR
        )""",
    ]:
        con.execute(ddl)
    return con


# ═══════════════════════════════════════════════════════════════════════════
# Stage 1: Validation
# ═══════════════════════════════════════════════════════════════════════════
class TestValidation:
    def test_valid_alert_passes(self):
        df = make_alert_df()
        valid, rejects = validate(df, "alerts", "BATCH-1", "CSE-A")
        assert len(valid) == 1
        assert len(rejects) == 0

    def test_empty_alert_id_rejected(self):
        df = make_alert_df(alert_id="")
        valid, rejects = validate(df, "alerts", "BATCH-1", "CSE-A")
        assert len(valid) == 0
        assert len(rejects) == 1
        assert "alert_id" in rejects[0]["reject_reason"]
        assert rejects[0]["stage"] == "schema_validation"

    def test_empty_severity_rejected(self):
        df = make_alert_df(severity="")
        valid, rejects = validate(df, "alerts", "BATCH-1", "CSE-A")
        assert len(valid) == 0
        assert len(rejects) == 1

    def test_non_numeric_mttr_rejected(self):
        df = make_alert_df(mttr_seconds="abc")
        valid, rejects = validate(df, "alerts", "BATCH-1", "CSE-A")
        assert len(valid) == 0
        assert len(rejects) == 1
        assert "mttr_seconds" in rejects[0]["reject_reason"]

    def test_missing_required_column_rejected(self):
        df = make_alert_df()
        df = df.drop(columns=["alert_id"])
        valid, rejects = validate(df, "alerts", "BATCH-1", "CSE-A")
        assert len(rejects) == 1

    def test_reject_contains_raw_data(self):
        df = make_alert_df(severity="")
        _, rejects = validate(df, "alerts", "BATCH-1", "CSE-A")
        raw = json.loads(rejects[0]["raw_data"])
        assert "alert_id" in raw

    def test_assets_validation(self):
        df = pd.DataFrame([{
            "asset_id": "A1", "cse_id": "CSE-A",
            "asset_name": "Server", "asset_type": "server",
            "criticality": "HIGH",
        }])
        valid, rejects = validate(df, "assets", "BATCH-1", "CSE-A")
        assert len(valid) == 1
        assert len(rejects) == 0

    def test_multiple_rows_partial_reject(self):
        rows = [
            {"alert_id": "A1", "cse_id": "CSE-A", "category": "X", "severity": "HIGH",
             "created_at": "2025-01-01", "closed_at": "2025-01-02",
             "analyst_id": "ANA1", "asset_id": "ASSET1"},
            {"alert_id": "",   "cse_id": "CSE-A", "category": "X", "severity": "HIGH",
             "created_at": "2025-01-01", "closed_at": "2025-01-02",
             "analyst_id": "ANA1", "asset_id": "ASSET1"},
        ]
        df = pd.DataFrame(rows)
        valid, rejects = validate(df, "alerts", "BATCH-1", "CSE-A")
        assert len(valid) == 1
        assert len(rejects) == 1


# ═══════════════════════════════════════════════════════════════════════════
# Stage 2: Cleaning
# ═══════════════════════════════════════════════════════════════════════════
class TestCleaning:
    def test_deduplication(self):
        row = {"alert_id": "A1", "cse_id": "CSE-A", "severity": "HIGH"}
        df = pd.DataFrame([row, row])   # exact duplicate
        cleaned = clean(df, "alerts")
        assert len(cleaned) == 1

    def test_whitespace_stripped(self):
        df = pd.DataFrame([{"alert_id": "  A1  ", "cse_id": " CSE-A ", "severity": " HIGH "}])
        cleaned = clean(df, "alerts")
        assert cleaned.iloc[0]["alert_id"] == "A1"
        assert cleaned.iloc[0]["cse_id"] == "CSE-A"

    def test_nan_strings_replaced(self):
        df = pd.DataFrame([{"alert_id": "A1", "cse_id": "nan", "severity": "None"}])
        cleaned = clean(df, "alerts")
        assert cleaned.iloc[0]["cse_id"] == ""
        assert cleaned.iloc[0]["severity"] == ""

    def test_missing_optional_columns_added(self):
        df = pd.DataFrame([{"alert_id": "A1", "severity": "HIGH"}])
        cleaned = clean(df, "alerts")
        assert "status" in cleaned.columns
        assert cleaned.iloc[0]["status"] == "closed"


# ═══════════════════════════════════════════════════════════════════════════
# Stage 3: Normalization
# ═══════════════════════════════════════════════════════════════════════════
class TestNormalization:
    # ── Severity mapping ──
    @pytest.mark.parametrize("raw, expected", [
        ("CRITICAL", "CRITICAL"),
        ("CRIT",     "CRITICAL"),
        ("crit.",    "CRITICAL"),
        ("critical", "CRITICAL"),
        ("HIGH",     "HIGH"),
        ("high",     "HIGH"),
        ("MEDIUM",   "MEDIUM"),
        ("med",      "MEDIUM"),
        ("Moderate", "MEDIUM"),
        ("LOW",      "LOW"),
        ("lo",       "LOW"),
        ("info",     "LOW"),
        ("NOTASEV",  "LOW"),    # unknown → LOW
    ])
    def test_severity_map(self, raw, expected):
        assert map_severity(raw) == expected

    # ── Timestamp parsing ──
    @pytest.mark.parametrize("raw, expect_not_none", [
        ("20/08/25 10:30",           True),
        ("2025-08-20T10:30:00Z",     True),
        ("08-20-2025 10:30:00",      True),
        ("20-Aug-2025 10:30",        True),
        ("not-a-date",               False),
        ("",                         False),
        ("nan",                      False),
    ])
    def test_parse_timestamp(self, raw, expect_not_none):
        result = parse_timestamp(raw)
        if expect_not_none:
            assert result is not None, f"Expected non-None for {raw!r}"
        else:
            assert result is None, f"Expected None for {raw!r}"

    def test_timestamp_is_utc(self):
        from datetime import timezone
        dt = parse_timestamp("2025-08-20T10:30:00Z")
        assert dt.tzinfo == timezone.utc

    def test_messy_date_parsed(self):
        dt = parse_timestamp("20/08/25 10:30")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 8
        assert dt.day == 20

    # ── IP validation ──
    @pytest.mark.parametrize("ip, valid", [
        ("203.0.113.5",    True),
        ("10.0.0.1",       True),
        ("999.999.999.999", False),
        ("not-an-ip",      False),
        ("",               False),
    ])
    def test_validate_ip(self, ip, valid):
        result = validate_ip(ip)
        assert bool(result) == valid

    # ── Full alert normalization ──
    def test_normalize_alerts_severity(self):
        df = make_alert_df(severity="CRIT")
        normed = normalize_alerts(df)
        assert normed.iloc[0]["severity"] == "CRITICAL"
        assert normed.iloc[0]["severity_raw"] == "CRIT"

    def test_normalize_alerts_timestamp(self):
        df = make_alert_df(created_at="20/08/25 10:30")
        normed = normalize_alerts(df)
        ts = normed.iloc[0]["created_at"]
        assert ts is not None
        assert "2025" in str(ts)

    def test_normalize_alerts_invalid_ip_cleared(self):
        df = make_alert_df(source_ip="999.999.999.999")
        normed = normalize_alerts(df)
        assert normed.iloc[0]["source_ip"] == ""

    def test_normalize_assets_criticality(self):
        df = pd.DataFrame([{
            "asset_id": "A1", "cse_id": "CSE-A",
            "asset_name": "S1", "asset_type": "server",
            "criticality": "crit", "batch_id": "B1",
            "ip_address": "10.0.0.1", "hostname": "srv1",
            "last_seen": "2025-08-20T10:00:00Z",
        }])
        normed = normalize_assets(df)
        assert normed.iloc[0]["criticality"] == "CRITICAL"


# ═══════════════════════════════════════════════════════════════════════════
# Stage 4: Entity Mapping
# ═══════════════════════════════════════════════════════════════════════════
class TestEntityMapping:
    def test_analyst_entity_created(self):
        con = make_in_memory_db()
        df = make_alert_df(analyst_id="ANA-001", source_ip="203.0.113.5")
        map_entities(df, "alerts", "CSE-A", con)
        count = con.execute("SELECT COUNT(*) FROM entities WHERE entity_type='user'").fetchone()[0]
        assert count >= 1
        identifier = con.execute(
            "SELECT identifier FROM entities WHERE entity_type='user' LIMIT 1"
        ).fetchone()[0]
        assert identifier == "ANA-001"

    def test_ip_entity_created(self):
        con = make_in_memory_db()
        df = make_alert_df(source_ip="203.0.113.5")
        map_entities(df, "alerts", "CSE-A", con)
        count = con.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_type='ip' AND identifier='203.0.113.5'"
        ).fetchone()[0]
        assert count == 1

    def test_asset_entity_from_asset_table(self):
        con = make_in_memory_db()
        df = pd.DataFrame([{
            "asset_id": "SRV-01", "cse_id": "CSE-A",
            "batch_id": "B1", "asset_name": "Server 01",
            "asset_type": "server", "criticality": "CRITICAL",
            "ip_address": "10.0.0.1", "hostname": "SRV-01",
            "last_seen": "2025-08-20T00:00:00Z",
        }])
        map_entities(df, "assets", "CSE-A", con)
        count = con.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_type='system'"
        ).fetchone()[0]
        assert count >= 1


# ═══════════════════════════════════════════════════════════════════════════
# Stage 5: Store
# ═══════════════════════════════════════════════════════════════════════════
class TestStore:
    def test_store_alert(self):
        con = make_in_memory_db()
        df = make_alert_df()
        df["severity_raw"] = "CRIT"
        df["mttr_seconds"] = 3600.0
        n = store(df, "alerts", con)
        assert n == 1
        count = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        assert count == 1

    def test_store_idempotent(self):
        con = make_in_memory_db()
        df = make_alert_df()
        df["severity_raw"] = "CRIT"
        df["mttr_seconds"] = 3600.0
        store(df, "alerts", con)
        store(df, "alerts", con)   # second insert = upsert
        count = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        assert count == 1

    def test_store_rejects(self):
        con = make_in_memory_db()
        rejects = [{
            "batch_id": "B1", "cse_id": "CSE-A", "data_type": "alerts",
            "row_index": 0, "raw_data": '{"alert_id":""}',
            "reject_reason": "Empty required field: alert_id",
            "stage": "schema_validation",
        }]
        store_rejects(rejects, con)
        count = con.execute("SELECT COUNT(*) FROM rejects").fetchone()[0]
        assert count == 1

    def test_store_batch_metadata(self):
        con = make_in_memory_db()
        store_batch("B1", "CSE-A", "alerts", "test.csv", "csv", 100, 90, 10, con)
        row = con.execute("SELECT rows_received, rows_accepted, rows_rejected FROM ingest_batches WHERE batch_id='B1'").fetchone()
        assert row == (100, 90, 10)

    def test_unknown_data_type_returns_zero(self):
        con = make_in_memory_db()
        df = pd.DataFrame([{"foo": "bar"}])
        n = store(df, "unknown_type", con)
        assert n == 0
