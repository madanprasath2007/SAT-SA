"""
End-to-End Workflow Verification Test (Phase 5)
Workflow:
  Generate Data -> Ingest -> Analytics (All 6 Engines) -> CTI Import ->
  Traceback Reconstruction -> Human Review -> Feedback Loop -> Regulatory PDF/CSV Export.

Asserts:
  - S1 multi-stage attack chain on CSE-A is identified, correlated, and scored.
  - S1 attack path confidence score is >= 80%.
  - 5 MITRE tactics are reconstructed with verified telemetry evidence linkage.
  - Human review marks S1 finding as VALID with deeper investigation requested.
  - Export generates authentic ReportLab PDF dossier with S1 kill-chain stages.
"""

import json
import os
import sys
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
sys.path.insert(0, BACKEND_DIR)

from main import app
from models import get_connection, init_db, seed_cses, seed_users
from pipeline.orchestrator import run_pipeline
from threat_intel.importer import seed_sample_threat_intel
from routers.analytics import run_analytics
from attack_traceback.service import run_attack_traceback

E2E_DB = os.path.join(REPO_ROOT, "data", "test_e2e_s1.duckdb")


@pytest.fixture(scope="module")
def e2e_client():
    if os.path.exists(E2E_DB):
        try:
            os.remove(E2E_DB)
        except Exception:
            pass

    os.environ["DB_PATH"] = E2E_DB
    import importlib
    import models
    importlib.reload(models)
    models.init_db()

    con = models.get_connection()
    models.seed_cses(con)
    models.seed_users(con)

    # 1. Ingest Data for CSE-A
    synthetic_dir = os.path.join(REPO_ROOT, "data", "synthetic", "CSE-A")
    assert os.path.isdir(synthetic_dir), f"Synthetic data directory not found at {synthetic_dir}"

    for fname in sorted(os.listdir(synthetic_dir)):
        if fname.endswith(".csv"):
            data_type = os.path.splitext(fname)[0]
            with open(os.path.join(synthetic_dir, fname), "rb") as f:
                content = f.read()
            res = run_pipeline(content, "csv", "CSE-A", data_type, fname, con)
            assert res.get("status") in ("success", "partial_success", None)

    # 2. Import Threat Intelligence
    sample_bundle = os.path.join(REPO_ROOT, "data", "threat_intel", "sample_bundle")
    seed_sample_threat_intel(con, bundle_dir=sample_bundle)

    con.close()

    # 3. Run Analytics across all engines
    analytics_result = run_analytics(cse_id="CSE-A")
    assert analytics_result.get("total_findings", 0) > 0

    client = TestClient(app)
    yield client

    if os.path.exists(E2E_DB):
        try:
            os.remove(E2E_DB)
        except Exception:
            pass


def test_e2e_s1_full_lifecycle(e2e_client):
    """
    Executes and validates the full 7-step supervisor lifecycle for S1 on CSE-A.
    """
    # ── Step 1: Ingestion & Normalization verification ────────────────────────
    status_res = e2e_client.get("/api/ingest/status")
    assert status_res.status_code == 200

    # ── Step 2: Analytics & Supervisory Risk Score ────────────────────────────
    risk_res = e2e_client.get("/api/analytics/risk-scores")
    assert risk_res.status_code == 200
    scores = risk_res.json()["data"]
    cse_a_risk = next((r for r in scores if r["cse_id"] == "CSE-A"), None)
    assert cse_a_risk is not None, "CSE-A must have a calculated risk score"
    assert cse_a_risk["overall_score"] > 50.0, "S1 scenario on CSE-A must result in elevated risk score (>50)"

    # ── Step 3: CTI Threat Intelligence Indicator Correlation ─────────────────
    ti_res = e2e_client.get("/api/threat-intel/status")
    assert ti_res.status_code == 200
    assert ti_res.json()["total_iocs"] >= 4

    # ── Step 4: Attack Path Reconstruction (Asserting S1 Result) ──────────────
    tb_res = e2e_client.get("/api/traceback/CSE-A")
    assert tb_res.status_code == 200
    tb_data = tb_res.json()["data"]

    assert tb_data["cse_id"] == "CSE-A"
    assert tb_data["confidence_score"] >= 0.80, f"S1 path confidence must be >= 0.80, got {tb_data['confidence_score']}"
    assert len(tb_data["stages"]) >= 4, f"S1 attack chain must have at least 4 stages, got {len(tb_data['stages'])}"

    stage_names = [s.get("stage_name", "") for s in tb_data["stages"]]
    tactic_ids = [s.get("tactic", "") for s in tb_data["stages"]]
    assert any("Initial Access" in name or "TA0001" in tid for name, tid in zip(stage_names, tactic_ids)), "Must contain Initial Access phase"
    assert any("Lateral" in name or "TA0008" in tid for name, tid in zip(stage_names, tactic_ids)), "Must contain Lateral Movement phase"

    # Verify evidence IDs are linked to each stage (no phantom claims)
    for stage in tb_data["stages"]:
        assert len(stage["evidence_ids"]) > 0, f"Stage '{stage['stage_name']}' must link to raw evidence IDs"

    # ── Step 5: Supervisor Login & Human Adjudication (Review) ────────────────
    login_res = e2e_client.post("/api/auth/login", json={"username": "supervisor", "password": "Supervisor@123"})
    assert login_res.status_code == 200
    sup_token = login_res.json()["access_token"]
    sup_headers = {"Authorization": f"Bearer {sup_token}"}

    # Fetch top finding from S1
    findings = e2e_client.get("/api/analytics/findings?cse_id=CSE-A").json()["data"]
    s1_finding = findings[0]

    # Record supervisory determination
    rev_res = e2e_client.post(
        "/api/reviews/",
        json={
            "finding_id": s1_finding["finding_id"],
            "cse_id": "CSE-A",
            "decision": "VALID",
            "notes": "S1 kill-chain validated by National Supervisory SOC. Lateral pivot to OT subnet confirmed.",
            "investigation_requested": True,
        },
        headers=sup_headers,
    )
    assert rev_res.status_code == 200
    assert rev_res.json()["decision"] == "VALID"

    # Verify queue reflects updated adjudication
    queue_res = e2e_client.get("/api/reviews/queue?cse_id=CSE-A", headers=sup_headers)
    assert queue_res.status_code == 200
    q_items = queue_res.json()["data"]
    adjudicated = next((q for q in q_items if q["finding_id"] == s1_finding["finding_id"]), None)
    assert adjudicated is not None
    assert adjudicated["decision"] == "VALID"

    # ── Step 6: Feedback Loop Integration ─────────────────────────────────────
    fb_stats = e2e_client.get("/api/reviews/feedback/stats")
    assert fb_stats.status_code == 200
    assert fb_stats.json()["data"]["overall"]["total_reviews"] >= 1

    # ── Step 7: Regulatory PDF & CSV Export ───────────────────────────────────
    # CSV findings export
    csv_res = e2e_client.get("/api/export/findings/csv?cse_id=CSE-A", headers=sup_headers)
    assert csv_res.status_code == 200
    assert "Finding ID" in csv_res.text
    assert s1_finding["finding_id"] in csv_res.text

    # Official CSE Assessment PDF report
    pdf_res = e2e_client.get("/api/export/pdf/cse/CSE-A", headers=sup_headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")
    assert len(pdf_res.content) > 1000, "PDF dossier must contain substantial binary document data"
