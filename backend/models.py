"""
DB Models — Phase 1 Schema
All tables for the SAT-SA ingestion and normalization pipeline.
DuckDB DDL (no ORM needed for embedded analytics store).
"""

import duckdb
import os

DB_PATH = os.environ.get("DB_PATH", "/tmp/sat_sa.duckdb" if os.environ.get("VERCEL") else "./data/sat_sa.duckdb")
_SHARED_CONNS = {}


def get_connection(db_path: str = None) -> duckdb.DuckDBPyConnection:
    target_path = db_path or os.environ.get("DB_PATH", DB_PATH)
    target_dir = os.path.dirname(target_path)
    if target_dir:
        os.makedirs(target_dir, exist_ok=True)
    if target_path == ":memory:":
        return duckdb.connect(target_path)
    abs_path = os.path.abspath(target_path)
    if abs_path not in _SHARED_CONNS:
        _SHARED_CONNS[abs_path] = duckdb.connect(abs_path)
    return _SHARED_CONNS[abs_path].cursor()


def close_connections():
    """Closes all cached DuckDB root connections (used primarily in test fixtures)."""
    global _SHARED_CONNS
    for path, c in list(_SHARED_CONNS.items()):
        try:
            c.close()
        except Exception:
            pass
    _SHARED_CONNS.clear()



def init_db():
    con = get_connection()

    # ── CSEs (Cyber Security Entities) ──────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS cses (
            cse_id          VARCHAR PRIMARY KEY,
            cse_name        VARCHAR NOT NULL,
            sector          VARCHAR,
            contact_email   VARCHAR,
            onboarded_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Ingest Batches ───────────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS ingest_batches (
            batch_id        VARCHAR PRIMARY KEY,
            cse_id          VARCHAR,
            data_type       VARCHAR,
            file_name       VARCHAR,
            file_format     VARCHAR,
            rows_received   INTEGER,
            rows_accepted   INTEGER,
            rows_rejected   INTEGER,
            ingested_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status          VARCHAR DEFAULT 'completed'
        )
    """)

    # ── Rejects ──────────────────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS rejects (
            reject_id       VARCHAR PRIMARY KEY,
            batch_id        VARCHAR,
            cse_id          VARCHAR,
            data_type       VARCHAR,
            row_index       INTEGER,
            raw_data        VARCHAR,
            reject_reason   VARCHAR,
            stage           VARCHAR,
            rejected_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Alerts ───────────────────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id        VARCHAR PRIMARY KEY,
            cse_id          VARCHAR,
            batch_id        VARCHAR,
            category        VARCHAR,
            severity        VARCHAR,
            severity_raw    VARCHAR,
            created_at      TIMESTAMP,
            closed_at       TIMESTAMP,
            mttr_seconds    DOUBLE,
            closure_notes   TEXT,
            analyst_id      VARCHAR,
            asset_id        VARCHAR,
            source_ip       VARCHAR,
            dest_ip         VARCHAR,
            status          VARCHAR DEFAULT 'closed'
        )
    """)

    # ── Cases ────────────────────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id         VARCHAR PRIMARY KEY,
            cse_id          VARCHAR,
            batch_id        VARCHAR,
            title           VARCHAR,
            severity        VARCHAR,
            status          VARCHAR,
            opened_at       TIMESTAMP,
            closed_at       TIMESTAMP,
            analyst_id      VARCHAR,
            linked_alert_ids VARCHAR
        )
    """)

    # ── Investigations ───────────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id VARCHAR PRIMARY KEY,
            cse_id           VARCHAR,
            batch_id         VARCHAR,
            case_id          VARCHAR,
            analyst_id       VARCHAR,
            started_at       TIMESTAMP,
            completed_at     TIMESTAMP,
            outcome          VARCHAR,
            notes            TEXT
        )
    """)

    # ── Escalations ──────────────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS escalations (
            escalation_id   VARCHAR PRIMARY KEY,
            cse_id          VARCHAR,
            batch_id        VARCHAR,
            alert_id        VARCHAR,
            case_id         VARCHAR,
            escalated_by    VARCHAR,
            escalated_to    VARCHAR,
            escalated_at    TIMESTAMP,
            reason          TEXT,
            resolved        BOOLEAN DEFAULT FALSE
        )
    """)

    # ── Assets ───────────────────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            asset_id        VARCHAR PRIMARY KEY,
            cse_id          VARCHAR,
            batch_id        VARCHAR,
            asset_name      VARCHAR,
            asset_type      VARCHAR,
            criticality     VARCHAR,
            ip_address      VARCHAR,
            hostname        VARCHAR,
            last_seen       TIMESTAMP
        )
    """)

    # ── Entities (users / systems / IPs) ────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            entity_id       VARCHAR PRIMARY KEY,
            entity_type     VARCHAR,
            identifier      VARCHAR,
            cse_id          VARCHAR,
            first_seen      TIMESTAMP,
            last_seen       TIMESTAMP,
            linked_asset_ids VARCHAR
        )
    """)

    # ── Findings (engine outputs — Phase 2 supervisory findings) ───────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id      VARCHAR PRIMARY KEY,
            alert_id        VARCHAR,
            cse_id          VARCHAR,
            engine          VARCHAR,
            finding_type    VARCHAR,
            severity        VARCHAR,
            description     TEXT,
            score           DOUBLE,
            evidence        TEXT,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try:
        con.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence TEXT")
    except Exception:
        pass

    # ── Composite Risk Scores (Phase 2) ──────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS risk_scores (
            cse_id          VARCHAR PRIMARY KEY,
            overall_score   DOUBLE,
            risk_level      VARCHAR,
            breakdown_json  TEXT,
            calculated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Telemetry Baseline ────────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_baseline (
            asset_id        VARCHAR,
            hour_of_day     INTEGER,
            mu_logs         DOUBLE,
            sigma_logs      DOUBLE,
            PRIMARY KEY (asset_id, hour_of_day)
        )
    """)

    # ── Phase 3: Threat Intelligence Knowledge Base ──────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_iocs (
            ioc_id          VARCHAR PRIMARY KEY,
            ioc_type        VARCHAR NOT NULL,
            ioc_value       VARCHAR NOT NULL,
            threat_actor    VARCHAR,
            malware_family  VARCHAR,
            description     TEXT,
            confidence      DOUBLE DEFAULT 0.8,
            mitre_tactics   VARCHAR,
            mitre_techniques VARCHAR,
            first_seen      TIMESTAMP,
            source          VARCHAR
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_cves (
            cve_id          VARCHAR PRIMARY KEY,
            description     TEXT,
            cvss_score      DOUBLE,
            affected_products VARCHAR,
            published_date  TIMESTAMP
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_bundles (
            bundle_id       VARCHAR PRIMARY KEY,
            version         VARCHAR,
            sha256          VARCHAR,
            imported_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            record_count    INTEGER,
            status          VARCHAR DEFAULT 'verified'
        )
    """)

    # ── Phase 3: Attack Traceback Reports ────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS traceback_reports (
            incident_id     VARCHAR PRIMARY KEY,
            cse_id          VARCHAR NOT NULL,
            finding_id      VARCHAR,
            title           VARCHAR,
            confidence_score DOUBLE,
            why_flagged     TEXT,
            narrative       TEXT,
            stages_json     TEXT,
            ioc_matches_json TEXT,
            evidence_ids_json TEXT,
            graph_json      TEXT,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Phase 5: Users & Access Control ──────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id         VARCHAR PRIMARY KEY,
            username        VARCHAR UNIQUE NOT NULL,
            email           VARCHAR UNIQUE NOT NULL,
            password_hash   VARCHAR NOT NULL,
            role            VARCHAR NOT NULL DEFAULT 'Analyst',
            full_name       VARCHAR,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Phase 5: Audit Log ───────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id          VARCHAR PRIMARY KEY,
            action          VARCHAR NOT NULL,
            user_id         VARCHAR,
            username        VARCHAR,
            role            VARCHAR,
            target_entity   VARCHAR,
            details_json    TEXT,
            ip_address      VARCHAR,
            timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Phase 5: Human Review & Decision Workflow ────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            review_id       VARCHAR PRIMARY KEY,
            finding_id      VARCHAR NOT NULL,
            cse_id          VARCHAR NOT NULL,
            reviewer        VARCHAR NOT NULL,
            reviewer_role   VARCHAR NOT NULL,
            decision        VARCHAR NOT NULL,
            notes           TEXT,
            investigation_requested BOOLEAN DEFAULT FALSE,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── Phase 5: Feedback Log & Rule Recommendations ─────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS feedback_logs (
            log_id          VARCHAR PRIMARY KEY,
            engine          VARCHAR NOT NULL,
            rule_id         VARCHAR,
            suggested_change TEXT NOT NULL,
            justification   TEXT NOT NULL,
            status          VARCHAR DEFAULT 'PENDING',
            reviewed_by     VARCHAR,
            action_taken_at TIMESTAMP,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    seed_users(con)
    con.close()
    print(f"[DB] Database schema initialised at {DB_PATH}")


def seed_users(con: duckdb.DuckDBPyConnection):
    """Seed default demo accounts: Admin, Supervisor, Analyst."""
    import hashlib
    def _hash(pw: str) -> str:
        return hashlib.sha256(f"satsa_salt_{pw}".encode()).hexdigest()

    demo_users = [
        ("usr-admin-01", "admin", "admin@satsa.gov.in", _hash("Admin@123"), "Admin", "National SOC Administrator"),
        ("usr-sup-01", "supervisor", "supervisor@satsa.gov.in", _hash("Supervisor@123"), "Supervisor", "Senior Supervisory Officer"),
        ("usr-ana-01", "analyst", "analyst@satsa.gov.in", _hash("Analyst@123"), "Analyst", "Cyber Triage Analyst"),
    ]
    for u in demo_users:
        con.execute("""
            INSERT INTO users (user_id, username, email, password_hash, role, full_name)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (user_id) DO NOTHING
        """, list(u))



def seed_cses(con: duckdb.DuckDBPyConnection):
    """Insert the 4 canonical CSEs used across Phase 1."""
    cses = [
        ("CSE-A", "Alpha Power Grid", "power", "soc@alpha-power.in"),
        ("CSE-B", "Beta Banking Corp", "banking", "soc@beta-bank.in"),
        ("CSE-C", "Charlie Telecom", "telecom", "soc@charlie-tel.in"),
        ("CSE-D", "Delta Healthcare", "health", "soc@delta-health.in"),
    ]
    for row in cses:
        con.execute("""
            INSERT INTO cses (cse_id, cse_name, sector, contact_email)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (cse_id) DO NOTHING
        """, list(row))

try:
    init_db()
except Exception:
    pass
