"""
Integration & API Tests — Supervisory Analytics Layer (Phase 2)
Tests:
- POST /api/analytics/run
- GET /api/analytics/findings (and filtering by CSE, Engine, Severity, Date)
- GET /api/analytics/findings/{finding_id}
- GET /api/analytics/risk-scores
- GET /api/analytics/risk-scores/{cse_id}/breakdown
- Planted scenario detection verification (S1, S2, S3, S4)
- Idempotency verification
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from models import get_connection, init_db, seed_cses
from pipeline.orchestrator import run_pipeline

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
SYNTHETIC_DIR = os.path.join(REPO_ROOT, "data", "synthetic")
TEST_DB = os.path.join(REPO_ROOT, "data", "test_phase2.duckdb")


@pytest.fixture(scope="module")
def api_client():
    """Setup clean test DB, ingest synthetic data, and return TestClient."""
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass

    os.environ["DB_PATH"] = TEST_DB
    import importlib
    import models
    importlib.reload(models)
    models.init_db()

    con = models.get_connection()
    models.seed_cses(con)

    # Ingest synthetic data for all 4 CSEs
    for cse in ["CSE-A", "CSE-B", "CSE-C", "CSE-D"]:
        cse_dir = os.path.join(SYNTHETIC_DIR, cse)
        if not os.path.isdir(cse_dir):
            pytest.skip(f"Synthetic data not found at {cse_dir}. Run generate.py first.")
        for fname in sorted(os.listdir(cse_dir)):
            if not fname.endswith(".csv"):
                continue
            data_type = os.path.splitext(fname)[0]
            fpath = os.path.join(cse_dir, fname)
            with open(fpath, "rb") as f:
                content = f.read()
            run_pipeline(content, "csv", cse, data_type, fname, con)

    con.close()

    client = TestClient(app)
    yield client

    # Teardown
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass


class TestAnalyticsAPI:
    def test_run_analytics_all(self, api_client):
        """POST /api/analytics/run executes all 5 engines and returns summary."""
        res = api_client.post("/api/analytics/run")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "complete"
        assert data["total_findings"] > 0
        assert "RuleEngine" in data["by_engine"]
        assert "AnomalyDetectionEngine" in data["by_engine"]
        assert "PeerBenchmarkingEngine" in data["by_engine"]
        assert "ExecutionGapEngine" in data["by_engine"]
        assert "NegativeSpaceEngine" in data["by_engine"]
        assert len(data["risk_scores"]) == 4

    def test_idempotent_rerun(self, api_client):
        """Re-running POST /api/analytics/run does not duplicate findings."""
        res1 = api_client.get("/api/analytics/findings")
        total1 = res1.json()["total"]

        # Run analytics again
        run_res = api_client.post("/api/analytics/run")
        assert run_res.status_code == 200

        res2 = api_client.get("/api/analytics/findings")
        total2 = res2.json()["total"]
        assert total1 == total2, f"Idempotency failed: total changed from {total1} to {total2}"

    def test_filter_findings_by_cse(self, api_client):
        res = api_client.get("/api/analytics/findings?cse_id=CSE-D")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) > 0
        for item in data:
            assert item["cse_id"] == "CSE-D"

    def test_filter_findings_by_engine(self, api_client):
        res = api_client.get("/api/analytics/findings?engine=NegativeSpaceEngine")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) > 0
        for item in data:
            assert item["engine"] == "NegativeSpaceEngine"

    def test_filter_findings_by_severity(self, api_client):
        res = api_client.get("/api/analytics/findings?severity=CRITICAL")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) > 0
        for item in data:
            assert item["severity"] == "CRITICAL"

    def test_get_single_finding_by_id(self, api_client):
        res = api_client.get("/api/analytics/findings?limit=1")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) == 1
        finding_id = data[0]["finding_id"]

        single_res = api_client.get(f"/api/analytics/findings/{finding_id}")
        assert single_res.status_code == 200
        item = single_res.json()["data"]
        assert item["finding_id"] == finding_id
        assert "evidence" in item

    def test_get_risk_scores(self, api_client):
        res = api_client.get("/api/analytics/risk-scores")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) == 4
        cses = {r["cse_id"] for r in data}
        assert cses == {"CSE-A", "CSE-B", "CSE-C", "CSE-D"}
        for r in data:
            assert 0 <= r["overall_score"] <= 100
            assert r["risk_level"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
            assert "components" in r["breakdown"]

    def test_get_risk_score_breakdown_per_cse(self, api_client):
        res = api_client.get("/api/analytics/risk-scores/CSE-D/breakdown")
        assert res.status_code == 200
        b = res.json()["data"]
        assert b["cse_id"] == "CSE-D"
        assert "components" in b
        assert "rule_violations" in b["components"]
        assert "anomalies" in b["components"]
        assert "peer_deviations" in b["components"]
        assert "silent_assets" in b["components"]
        assert len(b["recommendations"]) > 0


class TestPlantedScenariosDetection:
    """Verifies that the supervisory layer detects planted scenarios S1–S4."""

    def test_s1_cse_a_execution_gap(self, api_client):
        """S1: 5-stage APT attack with rapid alert closure after log clearing."""
        res = api_client.get("/api/analytics/findings?cse_id=CSE-A&engine=ExecutionGapEngine")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) >= 1, "Expected ExecutionGapEngine findings for CSE-A (S1 rapid closure)"

    def test_s2_cse_b_rapid_closure_and_missing_investigation(self, api_client):
        """S2: 15 critical alerts closed <2 min with no investigation notes."""
        # 1. Execution Gap: rapid closure
        res_eg = api_client.get("/api/analytics/findings?cse_id=CSE-B&engine=ExecutionGapEngine")
        assert res_eg.status_code == 200
        eg_data = res_eg.json()["data"]
        # Look for S2 alert IDs or rapid closure
        rapid_findings = [f for f in eg_data if "Rapid Closure" in f["finding_type"] or "Superficial" in f["finding_type"]]
        assert len(rapid_findings) >= 1, "Expected rapid closure findings for CSE-B (S2)"

        # 2. Rule Engine: closed case lacks investigation notes
        res_re = api_client.get("/api/analytics/findings?cse_id=CSE-B&engine=RuleEngine")
        assert res_re.status_code == 200
        re_data = res_re.json()["data"]
        case_findings = [f for f in re_data if "Closed Case Lacks Investigation Notes" in f["finding_type"]]
        assert len(case_findings) >= 1, "Expected missing investigation notes finding for S2-CASE-0001"
        assert any(f.get("evidence", {}).get("case_id") == "S2-CASE-0001" for f in case_findings)

    def test_s3_cse_c_silent_critical_asset(self, api_client):
        """S3: Critical asset ASSET-CSE-C-SILENT-01 has zero alerts for 30 days."""
        res = api_client.get("/api/analytics/findings?cse_id=CSE-C&engine=NegativeSpaceEngine")
        assert res.status_code == 200
        ns_data = res.json()["data"]
        silent_findings = [f for f in ns_data if "Silent Critical Asset" in f["finding_type"]]
        assert len(silent_findings) >= 1, "Expected silent critical asset finding for CSE-C (S3)"
        assert any(f.get("evidence", {}).get("asset_id") == "ASSET-CSE-C-SILENT-01" for f in silent_findings)

    def test_s4_cse_d_unescalated_critical_and_spike(self, api_client):
        """S4: 10 critical alerts never escalated + 50-alert spike on 2025-08-20."""
        # 1. Rule Engine: unescalated critical alerts
        res_re = api_client.get("/api/analytics/findings?cse_id=CSE-D&engine=RuleEngine")
        assert res_re.status_code == 200
        re_data = res_re.json()["data"]
        unescalated = [f for f in re_data if "Unescalated Critical Alert" in f["finding_type"]]
        assert len(unescalated) >= 10, f"Expected >= 10 unescalated critical alerts for S4, got {len(unescalated)}"

        # 2. Anomaly Detection: 50-alert spike on 2025-08-20
        res_anom = api_client.get("/api/analytics/findings?cse_id=CSE-D&engine=AnomalyDetectionEngine")
        assert res_anom.status_code == 200
        anom_data = res_anom.json()["data"]
        spikes = [f for f in anom_data if "Alert Volume Spike" in f["finding_type"]]
        assert len(spikes) >= 1, "Expected volume spike anomaly for CSE-D on 2025-08-20"
        assert any(f.get("evidence", {}).get("day") == "2025-08-20" for f in spikes)
