#!/usr/bin/env python3
"""
SAT-SA Demo Database Seed Script
Initializes DuckDB schema, seeds demo users, ingests synthetic CSE data,
imports threat intelligence, executes analytics engines, and reconstructs
the S1 multi-stage attack path for CSE-A.

Usage:
    python scripts/seed_demo.py
"""

import os
import sys
from datetime import datetime

# Setup module search paths
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(REPO_ROOT, "backend")
sys.path.insert(0, BACKEND_DIR)

# Handle traceback name collision if present
_tb_dir = os.path.join(BACKEND_DIR, "traceback")
if os.path.isdir(_tb_dir):
    import traceback
    if not hasattr(traceback, "__path__"):
        traceback.__path__ = [_tb_dir]
    elif _tb_dir not in traceback.__path__:
        traceback.__path__.append(_tb_dir)

from models import init_db, get_connection, seed_cses, seed_users, DB_PATH
from pipeline.orchestrator import run_pipeline
from threat_intel.importer import seed_sample_threat_intel
from routers.analytics import run_analytics
from traceback.service import run_attack_traceback
from audit import log_audit


def seed_demo_database():
    print("=" * 70)
    print("  SAT-SA: Supervisory Analytics Tool for SOC Assessment")
    print("  One-Command Demo Environment Seed Script")
    print("=" * 70)

    # 1. Initialize schema
    print(f"\n[*] Initializing DuckDB database schema at: {os.path.abspath(DB_PATH)}")
    init_db()

    con = get_connection()
    try:
        # 2. Seed CSEs and Demo Users
        print("[*] Seeding Cyber Security Entities (CSE-A through CSE-D)...")
        seed_cses(con)

        print("[*] Seeding RBAC Demo Users (Admin, Supervisor, Analyst)...")
        seed_users(con)

        # 3. Ingest Synthetic Data
        synthetic_dir = os.path.join(REPO_ROOT, "data", "synthetic")
        if os.path.isdir(synthetic_dir):
            cses = sorted([d for d in os.listdir(synthetic_dir) if os.path.isdir(os.path.join(synthetic_dir, d))])
            print(f"\n[*] Ingesting synthetic SOC telemetry for {len(cses)} CSEs...")
            for cse_id in cses:
                cse_path = os.path.join(synthetic_dir, cse_id)
                csv_files = sorted([f for f in os.listdir(cse_path) if f.endswith(".csv")])
                for fname in csv_files:
                    data_type = os.path.splitext(fname)[0]
                    file_path = os.path.join(cse_path, fname)
                    with open(file_path, "rb") as f:
                        content = f.read()
                    res = run_pipeline(content, "csv", cse_id, data_type, fname, con)
                    print(f"    - {cse_id}/{fname}: {res.get('status')} ({res.get('valid_records', 0)} valid, {res.get('rejected_records', 0)} rejected)")
        else:
            print("[!] Warning: Synthetic data directory not found.")

        # 4. Import Threat Intelligence
        sample_bundle = os.path.join(REPO_ROOT, "data", "threat_intel", "sample_bundle")
        if os.path.isdir(sample_bundle):
            print(f"\n[*] Importing STIX 2.1 Threat Intelligence Bundle...")
            seed_sample_threat_intel(con, bundle_dir=sample_bundle)
            total_iocs = con.execute("SELECT COUNT(*) FROM threat_intel_iocs").fetchone()[0]
            total_cves = con.execute("SELECT COUNT(*) FROM threat_intel_cves").fetchone()[0]
            print(f"    - Threat intel active: {total_iocs} IOCs and {total_cves} CVE entries.")
        else:
            print("[!] Warning: Threat intel bundle directory not found.")

        # 5. Execute Supervisory Analytics
        print(f"\n[*] Executing Supervisory Analytics Engines across all CSEs...")
        analytics_res = run_analytics()
        print(f"    - Analytics complete. Total findings generated: {analytics_res.get('total_findings', 0)}")
        for eng, count in analytics_res.get("by_engine", {}).items():
            print(f"      * {eng}: {count} findings")

        # 6. Reconstruct Attack Traceback for CSE-A
        print(f"\n[*] Reconstructing S1 Multi-Stage Attack Path for CSE-A...")
        try:
            tb_report = run_attack_traceback(con, "CSE-A", llm_backend="mock")
            print(f"    - Attack path successfully reconstructed:")
            print(f"      Title: {tb_report.get('title')}")
            conf_val = float(tb_report.get('confidence_score', 0.0))
            if conf_val <= 1.0:
                conf_val *= 100
            print(f"      Confidence: {round(conf_val, 1)}%")
            print(f"      Stages: {len(tb_report.get('stages', []))} kill-chain phases identified")
            print(f"      IOC Matches: {len(tb_report.get('ioc_matches', []))} IOCs correlated")
        except Exception as e:
            print(f"    - Notice on traceback: {e}")

        # 7. Seed Initial Supervisor Reviews & Feedback Suggestions
        print(f"\n[*] Seeding initial supervisory determinations & feedback proposals...")
        from routers.feedback import _ensure_default_proposals
        _ensure_default_proposals(con)

        # Record audit log
        log_audit(
            con,
            action="SYSTEM_INIT_SEED",
            user={"user_id": "system", "username": "admin", "role": "Admin"},
            target_entity="DATABASE",
            details={"timestamp": datetime.utcnow().isoformat(), "environment": "air_gapped_demo"},
        )

        print("\n" + "=" * 70)
        print("  DEMO SEED COMPLETED SUCCESSFULLY")
        print("=" * 70)
        print("\nDemo Credentials:")
        print("  - Admin:      admin      / Admin@123      (Role: Admin - Full Governance)")
        print("  - Supervisor: supervisor / Supervisor@123 (Role: Supervisor - Reviews & Adjudication)")
        print("  - Analyst:    analyst    / Analyst@123    (Role: Analyst - Read-Only Auditing)")
        print("\nService URLs:")
        print("  - Frontend UI:  http://localhost:5173")
        print("  - Backend API:  http://localhost:8000/docs")
        print("=" * 70)

    finally:
        con.close()


if __name__ == "__main__":
    seed_demo_database()
