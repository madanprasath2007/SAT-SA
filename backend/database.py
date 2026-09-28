"""
Database initialisation — DuckDB embedded OLAP store.
Creates all schema tables on first run.
"""

import duckdb
import os

DB_PATH = os.environ.get("DB_PATH", "./data/sat_sa.duckdb")


def get_connection() -> duckdb.DuckDBPyConnection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return duckdb.connect(DB_PATH)


def init_db():
    con = get_connection()
    con.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id        VARCHAR PRIMARY KEY,
            cse_id          VARCHAR,
            category        VARCHAR,
            severity        VARCHAR,
            created_at      TIMESTAMP,
            closed_at       TIMESTAMP,
            mttr_seconds    DOUBLE,
            closure_notes   TEXT,
            analyst_id      VARCHAR,
            asset_id        VARCHAR,
            source_ip       VARCHAR,
            dest_ip         VARCHAR
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            asset_id        VARCHAR PRIMARY KEY,
            asset_name      VARCHAR,
            asset_type      VARCHAR,
            cse_id          VARCHAR,
            criticality     VARCHAR,
            last_seen       TIMESTAMP
        )
    """)
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
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_baseline (
            asset_id        VARCHAR,
            hour_of_day     INTEGER,
            mu_logs         DOUBLE,
            sigma_logs      DOUBLE,
            PRIMARY KEY (asset_id, hour_of_day)
        )
    """)
    con.close()
    print(f"[DB] Initialised DuckDB at {DB_PATH}")


init_db()
