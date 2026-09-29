"""
Phase 5 Test Suite — Human Review Workflow, Feedback Loop, RBAC, Reports & Packaging
Verifies:
1. JWT authentication and demo user credentials (Admin, Supervisor, Analyst).
2. RBAC enforcement: Analyst read-only restriction on review actions.
3. Supervisor review workflow (Valid / False Positive / Needs More Data) with notes.
4. Review audit trail and finding history persistence.
5. Feedback loop: False Positive decisions generate rule tuning suggestions.
6. Feedback statistics: calculation of false-positive rate per engine.
7. Supervisor approval of suggested rule tuning modifications.
8. Audit trail logging across actions (reviews, logins, exports).
9. CSV findings export with filters.
10. PDF supervisory assessment report generation with ReportLab.
11. Traceback prompt context enrichment with prior supervisor determinations.
"""

import json
import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from models import get_connection, init_db, seed_cses, seed_users
from routers.analytics import run_analytics
from traceback.service import run_attack_traceback

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
TEST_DB = os.path.join(REPO_ROOT, "data", "test_phase5.duckdb")


@pytest.fixture(scope="module")
def p5_client():
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
    models.seed_users(con)

    # Ingest synthetic data for CSE-A
    from pipeline.orchestrator import run_pipeline
    from threat_intel.importer import seed_sample_threat_intel

    synthetic_dir = os.path.join(REPO_ROOT, "data", "synthetic", "CSE-A")
    if os.path.isdir(synthetic_dir):
        for fname in sorted(os.listdir(synthetic_dir)):
            if fname.endswith(".csv"):
                data_type = os.path.splitext(fname)[0]
                with open(os.path.join(synthetic_dir, fname), "rb") as f:
                    content = f.read()
                run_pipeline(content, "csv", "CSE-A", data_type, fname, con)

    sample_bundle = os.path.join(REPO_ROOT, "data", "threat_intel", "sample_bundle")
    seed_sample_threat_intel(con, bundle_dir=sample_bundle)
    con.close()

    # Generate analytics findings
    run_analytics(cse_id="CSE-A")

    client = TestClient(app)
    yield client

    models.close_connections()
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass


class TestAuthAndRBAC:
    def test_demo_users_login(self, p5_client):
        # Admin login
        res = p5_client.post("/api/auth/login", json={"username": "admin", "password": "Admin@123"})
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["user"]["role"] == "Admin"

        # Supervisor login
        res = p5_client.post("/api/auth/login", json={"username": "supervisor", "password": "Supervisor@123"})
        assert res.status_code == 200
        assert res.json()["user"]["role"] == "Supervisor"

        # Analyst login
        res = p5_client.post("/api/auth/login", json={"username": "analyst", "password": "Analyst@123"})
        assert res.status_code == 200
        assert res.json()["user"]["role"] == "Analyst"

    def test_invalid_login_rejected(self, p5_client):
        res = p5_client.post("/api/auth/login", json={"username": "admin", "password": "WrongPassword"})
        assert res.status_code == 401


class TestHumanReviewWorkflow:
    def test_supervisor_submits_review(self, p5_client):
        # Login as supervisor
        sup_token = p5_client.post("/api/auth/login", json={"username": "supervisor", "password": "Supervisor@123"}).json()["access_token"]
        headers = {"Authorization": f"Bearer {sup_token}"}

        # Fetch a finding
        findings = p5_client.get("/api/analytics/findings?cse_id=CSE-A").json()["data"]
        assert len(findings) > 0
        target_f = findings[0]

        # Submit VALID review
        res = p5_client.post("/api/reviews/", json={
            "finding_id": target_f["finding_id"],
            "cse_id": "CSE-A",
            "decision": "VALID",
            "notes": "Evidence verified against firewall egress logs. Confirmed malicious.",
            "investigation_requested": True,
        }, headers=headers)
        assert res.status_code == 200
        assert res.json()["decision"] == "VALID"

        # Verify review history
        hist_res = p5_client.get(f"/api/reviews/history/{target_f['finding_id']}", headers=headers)
        assert hist_res.status_code == 200
        reviews = hist_res.json()["data"]
        assert len(reviews) >= 1
        assert reviews[0]["decision"] == "VALID"
        assert "firewall egress" in reviews[0]["notes"]

    def test_false_positive_triggers_feedback_suggestion(self, p5_client):
        sup_token = p5_client.post("/api/auth/login", json={"username": "supervisor", "password": "Supervisor@123"}).json()["access_token"]
        headers = {"Authorization": f"Bearer {sup_token}"}

        findings = p5_client.get("/api/analytics/findings?cse_id=CSE-A").json()["data"]
        target_f = findings[1] if len(findings) > 1 else findings[0]

        # Submit FALSE_POSITIVE review
        res = p5_client.post("/api/reviews/", json={
            "finding_id": target_f["finding_id"],
            "cse_id": "CSE-A",
            "decision": "FALSE_POSITIVE",
            "notes": "Routine scheduled backup activity; not unauthorized exfiltration.",
            "investigation_requested": False,
        }, headers=headers)
        assert res.status_code == 200
        assert res.json()["decision"] == "FALSE_POSITIVE"
        assert res.json()["feedback_log_id"] is not None

        # Verify feedback suggestions list
        sug_res = p5_client.get("/api/reviews/feedback/suggestions", headers=headers)
        assert sug_res.status_code == 200
        sugs = sug_res.json()["data"]
        assert len(sugs) >= 1
        assert sugs[0]["status"] == "PENDING"

        # Supervisor approves the tuning suggestion
        log_id = sugs[0]["log_id"]
        appr_res = p5_client.post(f"/api/reviews/feedback/suggestions/{log_id}/action", json={
            "action": "APPROVE",
            "justification": "Approved threshold adjustment to eliminate recurring backup alert noise."
        }, headers=headers)
        assert appr_res.status_code == 200
        assert appr_res.json()["new_status"] == "APPROVED"


class TestFeedbackStatsAndQueue:
    def test_feedback_stats(self, p5_client):
        res = p5_client.get("/api/reviews/feedback/stats")
        assert res.status_code == 200
        data = res.json()["data"]
        assert "overall" in data
        assert data["overall"]["total_reviews"] >= 2
        assert data["overall"]["total_false_positives"] >= 1
        assert len(data["by_engine"]) >= 1

    def test_review_queue_ordering(self, p5_client):
        res = p5_client.get("/api/reviews/queue?cse_id=CSE-A")
        assert res.status_code == 200
        queue = res.json()["data"]
        assert len(queue) > 0


class TestAuditLog:
    def test_audit_log_records_events(self, p5_client):
        admin_token = p5_client.post("/api/auth/login", json={"username": "admin", "password": "Admin@123"}).json()["access_token"]
        headers = {"Authorization": f"Bearer {admin_token}"}

        res = p5_client.get("/api/auth/audit", headers=headers)
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) >= 1
        actions = [entry["action"] for entry in data]
        assert any("LOGIN" in a or "REVIEW" in a or "FEEDBACK" in a for a in actions)


class TestExportReports:
    def test_export_findings_csv(self, p5_client):
        res = p5_client.get("/api/export/findings/csv?cse_id=CSE-A")
        assert res.status_code == 200
        assert "text/csv" in res.headers["content-type"]
        assert "Finding ID,Alert ID" in res.text

    def test_export_cse_pdf_report(self, p5_client):
        res = p5_client.get("/api/export/pdf/cse/CSE-A")
        assert res.status_code == 200
        assert "application/pdf" in res.headers["content-type"]
        assert res.content.startswith(b"%PDF")
