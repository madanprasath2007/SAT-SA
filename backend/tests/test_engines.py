"""
Unit Tests — Supervisory Analytics Engines (Phase 2)
Tests each of the 5 supervisory analytics engines, engine registry, and risk scoring.
"""

import os
import sys
import pytest
import duckdb

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import init_db
from engines.base import (
    Engine,
    Finding,
    register_engine,
    get_engine,
    get_all_engines,
    persist_findings,
    clear_registry,
)
from engines.rule_engine import RuleEngine
from engines.anomaly_detection import AnomalyDetectionEngine
from engines.peer_benchmarking import PeerBenchmarkingEngine
from engines.execution_gap import ExecutionGapEngine, zscore_mttr_anomalies, template_note_anomalies
from engines.negative_space import NegativeSpaceEngine
from engines.risk_scoring import calculate_cse_risk, update_risk_scores


@pytest.fixture
def mem_db():
    """In-memory DuckDB initialized with Phase 1/2 schema."""
    con = duckdb.connect(":memory:")
    # Schema setup
    con.execute("""
        CREATE TABLE cses (
            cse_id VARCHAR PRIMARY KEY, cse_name VARCHAR, sector VARCHAR, contact_email VARCHAR, onboarded_at TIMESTAMP
        );
        CREATE TABLE alerts (
            alert_id VARCHAR PRIMARY KEY, cse_id VARCHAR, batch_id VARCHAR, category VARCHAR,
            severity VARCHAR, severity_raw VARCHAR, created_at TIMESTAMP, closed_at TIMESTAMP,
            mttr_seconds DOUBLE, closure_notes TEXT, analyst_id VARCHAR, asset_id VARCHAR,
            source_ip VARCHAR, dest_ip VARCHAR, status VARCHAR DEFAULT 'closed'
        );
        CREATE TABLE cases (
            case_id VARCHAR PRIMARY KEY, cse_id VARCHAR, batch_id VARCHAR, title VARCHAR,
            severity VARCHAR, status VARCHAR, opened_at TIMESTAMP, closed_at TIMESTAMP,
            analyst_id VARCHAR, linked_alert_ids VARCHAR
        );
        CREATE TABLE investigations (
            investigation_id VARCHAR PRIMARY KEY, cse_id VARCHAR, batch_id VARCHAR, case_id VARCHAR,
            analyst_id VARCHAR, started_at TIMESTAMP, completed_at TIMESTAMP, outcome VARCHAR, notes TEXT
        );
        CREATE TABLE escalations (
            escalation_id VARCHAR PRIMARY KEY, cse_id VARCHAR, batch_id VARCHAR, alert_id VARCHAR,
            case_id VARCHAR, escalated_by VARCHAR, escalated_to VARCHAR, escalated_at TIMESTAMP,
            reason TEXT, resolved BOOLEAN DEFAULT FALSE
        );
        CREATE TABLE assets (
            asset_id VARCHAR PRIMARY KEY, cse_id VARCHAR, batch_id VARCHAR, asset_name VARCHAR,
            asset_type VARCHAR, criticality VARCHAR, ip_address VARCHAR, hostname VARCHAR, last_seen TIMESTAMP
        );
        CREATE TABLE findings (
            finding_id VARCHAR PRIMARY KEY, alert_id VARCHAR, cse_id VARCHAR, engine VARCHAR,
            finding_type VARCHAR, severity VARCHAR, description TEXT, score DOUBLE,
            evidence TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE risk_scores (
            cse_id VARCHAR PRIMARY KEY, overall_score DOUBLE, risk_level VARCHAR,
            breakdown_json TEXT, calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Seed test CSEs
    con.execute("INSERT INTO cses VALUES ('CSE-A', 'Power Grid Alpha', 'power', 'soc@a.in', CURRENT_TIMESTAMP)")
    con.execute("INSERT INTO cses VALUES ('CSE-B', 'Beta Banking Corp', 'banking', 'soc@b.in', CURRENT_TIMESTAMP)")
    con.execute("INSERT INTO cses VALUES ('CSE-C', 'Charlie Telecom', 'telecom', 'soc@c.in', CURRENT_TIMESTAMP)")
    con.execute("INSERT INTO cses VALUES ('CSE-D', 'Delta Health', 'health', 'soc@d.in', CURRENT_TIMESTAMP)")

    yield con
    con.close()


class TestEngineRegistryAndBase:
    def test_registered_engines_count(self):
        engines = get_all_engines()
        engine_names = [e.name for e in engines]
        assert "RuleEngine" in engine_names
        assert "AnomalyDetectionEngine" in engine_names
        assert "PeerBenchmarkingEngine" in engine_names
        assert "ExecutionGapEngine" in engine_names
        assert "NegativeSpaceEngine" in engine_names

    def test_idempotent_persist_findings(self, mem_db):
        f1 = Finding(cse_id="CSE-A", engine="RuleEngine", finding_type="Test Violation", severity="HIGH", description="Test 1")
        f2 = Finding(cse_id="CSE-A", engine="RuleEngine", finding_type="Test Violation 2", severity="LOW", description="Test 2")

        # First run
        n = persist_findings(mem_db, [f1, f2], cse_id="CSE-A", engine_names=["RuleEngine"])
        assert n == 2
        count = mem_db.execute("SELECT COUNT(*) FROM findings WHERE cse_id='CSE-A'").fetchone()[0]
        assert count == 2

        # Re-run with new set (idempotent replace)
        f3 = Finding(cse_id="CSE-A", engine="RuleEngine", finding_type="Replaced Violation", severity="CRITICAL", description="Test 3")
        n2 = persist_findings(mem_db, [f3], cse_id="CSE-A", engine_names=["RuleEngine"])
        assert n2 == 1
        count2 = mem_db.execute("SELECT COUNT(*) FROM findings WHERE cse_id='CSE-A'").fetchone()[0]
        assert count2 == 1


class TestRuleEngine:
    def test_detects_unescalated_critical_alert(self, mem_db):
        # Insert a CRITICAL alert without escalation
        mem_db.execute("""
            INSERT INTO alerts (alert_id, cse_id, category, severity, created_at)
            VALUES ('ALT-CRIT-001', 'CSE-A', 'Ransomware', 'CRITICAL', '2025-08-01 10:00:00')
        """)

        engine = RuleEngine()
        findings = engine.run(mem_db, cse_id="CSE-A")

        unescalated = [f for f in findings if "Unescalated Critical Alert" in f.finding_type]
        assert len(unescalated) == 1
        assert unescalated[0].alert_id == "ALT-CRIT-001"
        assert unescalated[0].severity == "CRITICAL"
        assert unescalated[0].evidence["alert_id"] == "ALT-CRIT-001"

    def test_detects_closed_case_without_investigation(self, mem_db):
        mem_db.execute("""
            INSERT INTO cases (case_id, cse_id, title, severity, status, closed_at)
            VALUES ('CASE-001', 'CSE-B', 'Unauthorized DB Dump', 'CRITICAL', 'closed', '2025-08-02 12:00:00')
        """)

        engine = RuleEngine()
        findings = engine.run(mem_db, cse_id="CSE-B")

        no_notes = [f for f in findings if "Closed Case Lacks Investigation Notes" in f.finding_type]
        assert len(no_notes) == 1
        assert no_notes[0].evidence["case_id"] == "CASE-001"


class TestAnomalyDetectionEngine:
    def test_detects_alert_spike(self, mem_db):
        # 10 baseline days with 5 alerts each, then 1 day with 60 alerts
        for d in range(1, 11):
            for i in range(5):
                mem_db.execute(f"""
                    INSERT INTO alerts (alert_id, cse_id, severity, created_at)
                    VALUES ('ALT-BASE-{d}-{i}', 'CSE-D', 'LOW', '2025-08-{d:02d} 10:00:00')
                """)

        for i in range(60):
            mem_db.execute(f"""
                INSERT INTO alerts (alert_id, cse_id, severity, created_at)
                VALUES ('ALT-SPIKE-{i}', 'CSE-D', 'CRITICAL', '2025-08-20 10:00:00')
            """)

        engine = AnomalyDetectionEngine()
        findings = engine.run(mem_db, cse_id="CSE-D")

        spikes = [f for f in findings if "Alert Volume Spike" in f.finding_type]
        assert len(spikes) >= 1
        assert spikes[0].evidence["day"] == "2025-08-20"
        assert spikes[0].evidence["observed_count"] == 60
        assert spikes[0].severity in ("CRITICAL", "HIGH")


class TestPeerBenchmarkingEngine:
    def test_flags_gamed_mttr_and_zero_escalation(self, mem_db):
        # CSE-A: standard alerts (MTTR 1800s, 20% escalations)
        # CSE-B: gamed MTTR (60s)
        # CSE-D: 0 escalations
        for i in range(30):
            mem_db.execute(f"""
                INSERT INTO alerts (alert_id, cse_id, severity, mttr_seconds, created_at)
                VALUES ('ALT-A-{i}', 'CSE-A', 'CRITICAL', 1800, '2025-08-01 10:00:00')
            """)
            mem_db.execute(f"""
                INSERT INTO alerts (alert_id, cse_id, severity, mttr_seconds, created_at)
                VALUES ('ALT-B-{i}', 'CSE-B', 'CRITICAL', 60, '2025-08-01 10:00:00')
            """)
            mem_db.execute(f"""
                INSERT INTO alerts (alert_id, cse_id, severity, mttr_seconds, created_at)
                VALUES ('ALT-D-{i}', 'CSE-D', 'CRITICAL', 1500, '2025-08-01 10:00:00')
            """)

        # Add escalations for CSE-A and CSE-B
        for i in range(6):
            mem_db.execute(f"""
                INSERT INTO escalations (escalation_id, cse_id, alert_id)
                VALUES ('ESC-A-{i}', 'CSE-A', 'ALT-A-{i}')
            """)
            mem_db.execute(f"""
                INSERT INTO escalations (escalation_id, cse_id, alert_id)
                VALUES ('ESC-B-{i}', 'CSE-B', 'ALT-B-{i}')
            """)
        # CSE-D has 0 escalations!

        engine = PeerBenchmarkingEngine()
        findings = engine.run(mem_db)

        # Verify CSE-B is flagged for fast MTTR
        b_findings = [f for f in findings if f.cse_id == "CSE-B" and "Abnormally Fast Closure" in f.finding_type]
        assert len(b_findings) >= 1

        # Verify CSE-D is flagged for zero/low escalation
        d_findings = [f for f in findings if f.cse_id == "CSE-D" and "Low Escalation Rate" in f.finding_type]
        assert len(d_findings) >= 1


class TestExecutionGapEngine:
    def test_rapid_critical_closure(self, mem_db):
        mem_db.execute("""
            INSERT INTO alerts (alert_id, cse_id, category, severity, mttr_seconds, closure_notes, analyst_id)
            VALUES ('ALT-FAST-01', 'CSE-B', 'Malware', 'CRITICAL', 45.0, 'Closed swiftly.', 'ANA-01')
        """)

        engine = ExecutionGapEngine()
        findings = engine.run(mem_db, cse_id="CSE-B")

        rapid = [f for f in findings if "Unjustified Rapid Closure" in f.finding_type]
        assert len(rapid) >= 1
        assert rapid[0].alert_id == "ALT-FAST-01"


class TestNegativeSpaceEngine:
    def test_detects_silent_critical_asset(self, mem_db):
        # Insert critical asset with NO alerts
        mem_db.execute("""
            INSERT INTO assets (asset_id, cse_id, asset_name, asset_type, criticality)
            VALUES ('ASSET-SILENT-01', 'CSE-C', 'Core Switch 01', 'switch', 'CRITICAL')
        """)

        engine = NegativeSpaceEngine()
        findings = engine.run(mem_db, cse_id="CSE-C")

        silent = [f for f in findings if "Silent Critical Asset" in f.finding_type]
        assert len(silent) == 1
        assert silent[0].evidence["asset_id"] == "ASSET-SILENT-01"
        assert silent[0].severity == "CRITICAL"


class TestRiskScoring:
    def test_risk_score_calculation(self, mem_db):
        # Insert findings of various types
        mem_db.execute("""
            INSERT INTO findings (finding_id, cse_id, engine, finding_type, severity, description, score)
            VALUES
                ('F-1', 'CSE-D', 'RuleEngine', 'Rule Violation: Unescalated Critical Alert', 'CRITICAL', 'desc', 90.0),
                ('F-2', 'CSE-D', 'AnomalyDetectionEngine', 'Anomaly: Alert Volume Spike', 'CRITICAL', 'desc', 8.5),
                ('F-3', 'CSE-D', 'PeerBenchmarkingEngine', 'Peer Benchmark Outlier: Low Escalation Rate', 'HIGH', 'desc', 80.0)
        """)

        breakdown = calculate_cse_risk(mem_db, "CSE-D")
        assert 0 <= breakdown["overall_score"] <= 100
        assert breakdown["risk_level"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
        assert "components" in breakdown
        assert "recommendations" in breakdown
        assert len(breakdown["recommendations"]) > 0

        # Test persistence
        scores = update_risk_scores(mem_db, "CSE-D")
        assert len(scores) == 1
        saved = mem_db.execute("SELECT overall_score, risk_level FROM risk_scores WHERE cse_id='CSE-D'").fetchone()
        assert saved[0] == breakdown["overall_score"]
