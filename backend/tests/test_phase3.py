"""
Phase 3 Test Suite — Threat Intel, AI Attack Traceback, Explainability & Risk Scoring v2
Verifies:
1. CTI bundle SHA-256 verification (valid imports, bad checksum rejected).
2. Threat intel knowledge base status & IOC lookup (including 203.0.113.5).
3. Event graph correlation & React Flow export.
4. Attack path MITRE clustering and lateral movement detection.
5. MockLLM deterministic narrative generation.
6. Evidence Verifier strictly rejects fabricated / hallucinated evidence IDs.
7. S1 scenario in CSE-A yields 5 stages in order:
   (Initial Access, Privilege Escalation, Lateral Movement, Data Access, Evidence Tampering).
8. Risk Score v2 for CSE-A reaches >= 90.0 with IOC match shown.
9. Traceback API endpoints (/run, /{finding_id}, /{finding_id}/graph).
"""

import hashlib
import json
import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from models import get_connection, init_db, seed_cses
from pipeline.orchestrator import run_pipeline
from threat_intel.importer import (
    ChecksumMismatchError,
    import_threat_intel_bundle,
    seed_sample_threat_intel,
    verify_bundle_checksum,
)
from attack_traceback.correlate import build_event_graph, graph_to_react_flow
from attack_traceback.path import cluster_candidate_incidents, build_attack_path
from attack_traceback.service import run_attack_traceback
from llm.client import MockLLM, OllamaLLM, get_llm_client
from llm.verifier import verify_llm_claims
from engines.risk_scoring import calculate_cse_risk, update_risk_scores

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
SYNTHETIC_DIR = os.path.join(REPO_ROOT, "data", "synthetic")
SAMPLE_BUNDLE_DIR = os.path.join(REPO_ROOT, "data", "threat_intel", "sample_bundle")
TEST_DB = os.path.join(REPO_ROOT, "data", "test_phase3.duckdb")


@pytest.fixture(scope="module")
def p3_client():
    """Setup clean test DB, seed CTI and synthetic records, return TestClient."""
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

    # Seed threat intelligence sample bundle (containing 203.0.113.5)
    seed_sample_threat_intel(con, bundle_dir=SAMPLE_BUNDLE_DIR)

    con.close()

    client = TestClient(app)
    yield client

    # Cleanup
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
# 1. Threat Intelligence & Bundle Checksum Verification
# ═══════════════════════════════════════════════════════════════════════════
class TestThreatIntel:
    def test_bundle_with_bad_checksum_is_rejected(self, p3_client):
        """A bundle with a tampered SHA-256 checksum must be rejected."""
        valid_bundle = {"bundle_id": "test-b1", "version": "1.0", "iocs": [], "cves": []}
        bundle_bytes = json.dumps(valid_bundle).encode("utf-8")
        bad_manifest = {"version": "1.0", "sha256": "0000000000000000000000000000000000000000000000000000000000000000"}

        con = get_connection()
        with pytest.raises(ChecksumMismatchError):
            import_threat_intel_bundle(con, bundle_bytes, bad_manifest)
        con.close()

    def test_bundle_with_bad_checksum_rejected_via_api(self, p3_client):
        """API POST /api/threat-intel/import returns HTTP 400 on checksum mismatch."""
        bundle_content = json.dumps({"bundle_id": "bad-check", "iocs": [], "cves": []}).encode("utf-8")
        manifest_content = json.dumps({"version": "1.0", "sha256": "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"}).encode("utf-8")

        res = p3_client.post(
            "/api/threat-intel/import",
            files={
                "bundle_file": ("bundle.json", bundle_content, "application/json"),
                "manifest_file": ("manifest.json", manifest_content, "application/json"),
            },
        )
        assert res.status_code == 400
        assert "SHA-256 verification failed" in res.json()["detail"]

    def test_valid_bundle_imports_successfully(self, p3_client):
        """A valid bundle with matching SHA-256 imports correctly."""
        test_bundle = {
            "bundle_id": "valid-test-1",
            "version": "1.0.0",
            "iocs": [
                {
                    "ioc_id": "ioc-test-99",
                    "ioc_type": "ip",
                    "ioc_value": "198.51.100.99",
                    "threat_actor": "TEST-ACTOR",
                    "confidence": 0.9,
                }
            ],
            "cves": [],
        }
        bundle_bytes = json.dumps(test_bundle, indent=2, sort_keys=True).encode("utf-8")
        sha256 = hashlib.sha256(bundle_bytes).hexdigest()
        manifest_bytes = json.dumps({"version": "1.0.0", "sha256": sha256}).encode("utf-8")

        res = p3_client.post(
            "/api/threat-intel/import",
            files={
                "bundle_file": ("bundle.json", bundle_bytes, "application/json"),
                "manifest_file": ("manifest.json", manifest_bytes, "application/json"),
            },
        )
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        assert res.json()["sha256"] == sha256

    def test_sample_bundle_contains_s1_ioc(self, p3_client):
        """Threat intel database must contain the S1 attacker IP 203.0.113.5."""
        con = get_connection()
        row = con.execute("SELECT ioc_value, threat_actor, confidence FROM threat_intel_iocs WHERE ioc_value = '203.0.113.5'").fetchone()
        con.close()
        assert row is not None, "203.0.113.5 IOC must exist in threat_intel_iocs"
        assert row[0] == "203.0.113.5"
        assert "APT" in row[1]
        assert row[2] >= 0.85

    def test_cti_status_endpoint(self, p3_client):
        res = p3_client.get("/api/threat-intel/status")
        assert res.status_code == 200
        data = res.json()
        assert data["total_iocs"] > 0
        assert data["status"] == "operational"


# ═══════════════════════════════════════════════════════════════════════════
# 2. Event Graph & Correlation (traceback/correlate.py)
# ═══════════════════════════════════════════════════════════════════════════
class TestEventCorrelationGraph:
    def test_event_graph_construction_and_enrichment(self, p3_client):
        con = get_connection()
        G = build_event_graph(con, cse_id="CSE-A")
        con.close()

        assert G.number_of_nodes() > 0
        assert G.number_of_edges() > 0

        # Verify attacker IP node exists and is flagged as an IOC match
        ip_node = "ip:203.0.113.5"
        assert G.has_node(ip_node)
        assert G.nodes[ip_node]["is_ioc"] is True
        assert "APT" in G.nodes[ip_node]["threat_actor"]

        # Verify React Flow export format
        flow_data = graph_to_react_flow(G)
        assert "nodes" in flow_data
        assert "edges" in flow_data
        assert len(flow_data["nodes"]) > 0
        # Check node structure
        first_node = flow_data["nodes"][0]
        assert "id" in first_node
        assert "position" in first_node
        assert "data" in first_node


# ═══════════════════════════════════════════════════════════════════════════
# 3. Attack Path Clustering & MITRE Mapping (traceback/path.py)
# ═══════════════════════════════════════════════════════════════════════════
class TestAttackPath:
    def test_s1_clustering_and_entry_point(self, p3_client):
        con = get_connection()
        candidates = cluster_candidate_incidents(con, "CSE-A")
        con.close()

        assert len(candidates) >= 1
        s1_cand = candidates[0]
        # Should link S1 alerts
        s1_aids = {a["alert_id"] for a in s1_cand["alerts"]}
        assert any(aid.startswith("S1-ALT-") for aid in s1_aids)

        # Path reconstruction
        path = build_attack_path(s1_cand)
        assert "203.0.113.5" in path["entry_point"]
        assert len(path["impacted_assets"]) >= 3
        assert path["overall_confidence"] >= 0.85

        # Check stage order
        stage_names = [s["stage_name"] for s in path["stages"]]
        expected_order = ["Initial Access", "Privilege Escalation", "Lateral Movement", "Data Access", "Evidence Tampering"]
        assert stage_names == expected_order, f"Stages not in order! Got {stage_names}"


# ═══════════════════════════════════════════════════════════════════════════
# 4. LLM & Evidence Verifier (llm/verifier.py)
# ═══════════════════════════════════════════════════════════════════════════
class TestLLMVerifier:
    def test_verifier_accepts_valid_db_ids(self, p3_client):
        con = get_connection()
        mock_narrative = {
            "incident_title": "Test Valid Narrative",
            "stages": [
                {
                    "stage_number": 1,
                    "stage_name": "Initial Access",
                    "claim": "Authentic claim grounded in data",
                    "evidence_ids": ["S1-ALT-0001", "S1-ALT-0002"],
                }
            ],
        }
        verified, rejected = verify_llm_claims(con, mock_narrative)
        con.close()

        assert len(rejected) == 0
        assert verified["stages"][0]["verified"] is True
        assert verified["stages"][0]["evidence_ids"] == ["S1-ALT-0001", "S1-ALT-0002"]

    def test_verifier_rejects_fabricated_evidence_id(self, p3_client):
        """The verifier must reject and drop any fabricated evidence_id not in DB."""
        con = get_connection()
        fake_id = "FABRICATED-ALT-9999"
        mock_narrative = {
            "incident_title": "Hallucinated Narrative",
            "stages": [
                {
                    "stage_number": 1,
                    "stage_name": "Initial Access",
                    "claim": "Attacker gained entry using fictitious alert",
                    "evidence_ids": [fake_id, "S1-ALT-0001"],
                },
                {
                    "stage_number": 2,
                    "stage_name": "Lateral Movement",
                    "claim": "Totally made-up stage",
                    "evidence_ids": ["NON-EXISTENT-CASE-777"],
                },
            ],
        }
        verified, rejected = verify_llm_claims(con, mock_narrative)
        con.close()

        assert fake_id in rejected
        assert "NON-EXISTENT-CASE-777" in rejected
        # Stage 1 retained S1-ALT-0001 and dropped fake_id
        assert verified["stages"][0]["evidence_ids"] == ["S1-ALT-0001"]
        assert fake_id in verified["stages"][0]["rejected_evidence_ids"]
        # Stage 2 had all evidence rejected -> marked unverified
        assert verified["stages"][1]["verified"] is False
        assert "REJECTED" in verified["stages"][1]["verification_status"]

    def test_mock_llm_deterministic_generation(self):
        llm = MockLLM()
        prompt = "Reconstruct attack with evidence records: S1-ALT-0001, S1-ALT-0002, S1-ALT-0003, S1-ALT-0004, S1-ALT-0005, from 203.0.113.5"
        res = llm.generate(prompt)
        parsed = json.loads(res)
        assert "stages" in parsed
        assert len(parsed["stages"]) == 5
        stages = [s["stage_name"] for s in parsed["stages"]]
        assert stages == ["Initial Access", "Privilege Escalation", "Lateral Movement", "Data Access", "Evidence Tampering"]


# ═══════════════════════════════════════════════════════════════════════════
# 5. Planted Scenario S1 Attack Traceback & Risk Score v2 >= 90
# ═══════════════════════════════════════════════════════════════════════════
class TestScenarioS1TracebackAndRiskV2:
    def test_s1_traceback_5_stages_in_order(self, p3_client):
        """
        Planted Scenario S1 yields 5 stages in order:
        (Initial Access, Privilege Escalation, Lateral Movement, Data Access, Evidence Tampering).
        """
        con = get_connection()
        report = run_attack_traceback(con, cse_id="CSE-A", llm_backend="mock")
        con.close()

        assert report["stages_count"] == 5
        stage_names = [s["stage_name"] for s in report["stages"]]
        assert stage_names == [
            "Initial Access",
            "Privilege Escalation",
            "Lateral Movement",
            "Data Access",
            "Evidence Tampering",
        ]
        # Check evidence claims are verified
        for stage in report["stages"]:
            assert stage.get("verified", True) is True
            assert len(stage["evidence_ids"]) > 0

    def test_s1_ioc_match_shown_in_traceback(self, p3_client):
        """Traceback report explicitly shows the matched CTI IOC (203.0.113.5)."""
        con = get_connection()
        report = run_attack_traceback(con, cse_id="CSE-A", llm_backend="mock")
        con.close()

        matched = report["matched_iocs"]
        assert len(matched) >= 1
        matched_vals = [m["ioc_value"] for m in matched]
        assert "203.0.113.5" in matched_vals
        assert "203.0.113.5" in report["why_flagged"]

    def test_s1_risk_score_v2_greater_than_or_equal_90(self, p3_client):
        """
        In Risk Scoring v2, combining engine findings + threat-intel matches
        + traceback confidence produces risk score >= 90 for CSE-A (S1).
        """
        con = get_connection()
        # Run analytics & traceback
        run_attack_traceback(con, cse_id="CSE-A")
        risk = calculate_cse_risk(con, "CSE-A")
        con.close()

        assert risk["overall_score"] >= 90.0, f"Expected risk score >= 90 for S1, got {risk['overall_score']}"
        assert risk["risk_level"] == "CRITICAL"
        assert len(risk["components"]["threat_intelligence"]["matched_iocs"]) >= 1
        assert risk["components"]["attack_traceback"]["score"] >= 20.0


# ═══════════════════════════════════════════════════════════════════════════
# 6. Traceback Endpoints (POST /run, GET /{finding_id}, GET /{finding_id}/graph)
# ═══════════════════════════════════════════════════════════════════════════
class TestTracebackAPI:
    def test_post_traceback_run(self, p3_client):
        res = p3_client.post("/api/traceback/run", json={"cse_id": "CSE-A", "llm_backend": "mock"})
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["cse_id"] == "CSE-A"
        assert len(data["stages"]) == 5
        assert "incident_id" in data

    def test_get_traceback_report(self, p3_client):
        # Fetch report using CSE-A
        res = p3_client.get("/api/traceback/CSE-A")
        assert res.status_code == 200
        data = res.json()["data"]
        assert "why_flagged" in data
        assert "how_attack_happened" in data
        assert len(data["stages"]) == 5
        assert len(data["matched_iocs"]) >= 1

    def test_get_traceback_graph(self, p3_client):
        res = p3_client.get("/api/traceback/CSE-A/graph")
        assert res.status_code == 200
        data = res.json()["data"]
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) > 0
        assert len(data["edges"]) > 0
