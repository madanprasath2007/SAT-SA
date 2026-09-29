"""
Synthetic data generator — Phase 1
Seeded/deterministic. Generates deliberately messy CSVs and JSONs
for 4 CSEs (A=power, B=banking, C=telecom, D=health), 30 days each.

Planted scenarios (fixed IDs):
  S1 (CSE-A): 5-stage attack from 203.0.113.5 — 12 alerts, 3 servers, 2 users
  S2 (CSE-B): 15 critical alerts closed in <2 min, no investigation
  S3 (CSE-C): critical asset with zero alerts for 30 days
  S4 (CSE-D): critical alerts never escalated + 1 alert-spike day
"""

import csv
import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

# ── Reproducibility ──────────────────────────────────────────────────────────
SEED = 42
random.seed(SEED)

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Constants ────────────────────────────────────────────────────────────────
START = datetime(2025, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
END   = datetime(2025, 8, 30, 23, 59, 59, tzinfo=timezone.utc)

CSE_META = {
    "CSE-A": {"name": "Alpha Power Grid",    "sector": "power"},
    "CSE-B": {"name": "Beta Banking Corp",   "sector": "banking"},
    "CSE-C": {"name": "Charlie Telecom",     "sector": "telecom"},
    "CSE-D": {"name": "Delta Healthcare",    "sector": "health"},
}

CATEGORIES = [
    "Suspicious Login", "Privilege Escalation", "Lateral Movement",
    "Data Exfiltration", "Malware Detected", "Ransomware",
    "Brute Force", "Policy Violation", "C2 Communication",
    "Authentication Failure", "Log Tampering", "File Access",
]

# Messy severity pool (will be mapped during normalization)
SEVERITY_POOL = [
    "CRITICAL", "HIGH", "MEDIUM", "LOW",     # clean
    "CRIT", "CRIT.", "critical", "high",      # messy variants
    "med", "MED", "Moderate", "lo", "info",   # more mess
]

# Severity weights (realistic distribution — must match SEVERITY_POOL length = 13)
SEV_WEIGHTS = [5, 15, 40, 30, 3, 2, 1, 1, 1, 1, 0.5, 0.3, 0.2]

ANALYSTS_A = [f"ANA-A{i:02d}" for i in range(1, 8)]
ANALYSTS_B = [f"ANA-B{i:02d}" for i in range(1, 7)]
ANALYSTS_C = [f"ANA-C{i:02d}" for i in range(1, 6)]
ANALYSTS_D = [f"ANA-D{i:02d}" for i in range(1, 7)]

# ── Planted Scenario Fixed IDs ────────────────────────────────────────────────
# S1 — CSE-A 5-stage attack
S1_ATTACKER_IP = "203.0.113.5"
S1_SERVERS = ["SRV-APP-01", "SRV-DC-02", "SRV-DB-03"]
S1_USERS   = ["usr_admin01", "usr_svc_rdp"]
S1_ALERT_IDS = [f"S1-ALT-{i:04d}" for i in range(1, 13)]   # 12 alerts
S1_CASE_ID    = "S1-CASE-0001"
S1_INV_ID     = "S1-INV-0001"
S1_BASE_TIME  = datetime(2025, 8, 15, 2, 0, 0, tzinfo=timezone.utc)

# S2 — CSE-B fast-close
S2_ALERT_IDS = [f"S2-ALT-{i:04d}" for i in range(1, 16)]   # 15 alerts
S2_CASE_ID   = "S2-CASE-0001"
S2_BASE_TIME = datetime(2025, 8, 10, 14, 0, 0, tzinfo=timezone.utc)

# S3 — CSE-C silent critical asset
S3_ASSET_ID   = "ASSET-CSE-C-SILENT-01"
S3_ASSET_NAME = "CORE-SWITCH-01"

# S4 — CSE-D never-escalated + spike day
S4_ALERT_IDS_NEVER_ESC = [f"S4-NE-{i:04d}" for i in range(1, 11)]  # 10 crit
S4_SPIKE_DAY = datetime(2025, 8, 20, 0, 0, 0, tzinfo=timezone.utc)
S4_SPIKE_ALERT_IDS = [f"S4-SPK-{i:04d}" for i in range(1, 51)]     # 50 alerts


# ── Helpers ───────────────────────────────────────────────────────────────────
def rng_ts(start: datetime, end: datetime) -> datetime:
    delta = int((end - start).total_seconds())
    return start + timedelta(seconds=random.randint(0, delta))


def random_ip() -> str:
    return f"{random.randint(10,192)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def messy_date(dt: datetime) -> str:
    """Randomly format a timestamp in one of several messy ways."""
    fmt = random.choice([
        "%d/%m/%y %H:%M",           # 20/08/25 10:30
        "%Y-%m-%dT%H:%M:%SZ",       # ISO (clean)
        "%m-%d-%Y %H:%M:%S",        # US style
        "%d-%b-%Y %H:%M",           # 20-Aug-2025 10:30
        "%Y/%m/%d %H:%M:%S",        # slash ISO
    ])
    return dt.strftime(fmt)


def messy_severity() -> str:
    return random.choices(SEVERITY_POOL, weights=SEV_WEIGHTS)[0]


def make_alert(
    alert_id: str,
    cse_id: str,
    category: str,
    severity: str,
    created_at: datetime,
    closed_at: datetime,
    analyst_id: str,
    asset_id: str,
    source_ip: str = None,
    dest_ip: str = None,
    closure_notes: str = "",
    status: str = "closed",
) -> dict[str, Any]:
    mttr = (closed_at - created_at).total_seconds()
    return {
        "alert_id":      alert_id,
        "cse_id":        cse_id,
        "category":      category,
        "severity":      severity,
        "created_at":    messy_date(created_at),
        "closed_at":     messy_date(closed_at),
        "mttr_seconds":  round(mttr, 2),
        "closure_notes": closure_notes or "Investigated and closed.",
        "analyst_id":    analyst_id,
        "asset_id":      asset_id,
        "source_ip":     source_ip or random_ip(),
        "dest_ip":       dest_ip or random_ip(),
        "status":        status,
    }


def inject_mess(rows: list[dict], frac_dup=0.05, frac_missing=0.05, frac_invalid=0.03):
    """Add duplicates, missing fields, and invalid rows to make data messy.
    Planted scenario rows (S1-*, S2-*, S3-*, S4-*) are protected.
    """
    # Separate planted (protected) from background rows
    PROTECTED_PREFIXES = ("S1-", "S2-", "S3-", "S4-")
    planted   = [r for r in rows if str(r.get("alert_id", "")).startswith(PROTECTED_PREFIXES)]
    bg        = [r for r in rows if not str(r.get("alert_id", "")).startswith(PROTECTED_PREFIXES)]

    n = len(bg)
    result = list(bg)

    # Duplicates (background only)
    if n > 0:
        for r in random.sample(bg, k=max(1, int(n * frac_dup))):
            result.append(dict(r))   # exact duplicate

    # Missing required fields (background only)
    fields = ["alert_id", "severity", "created_at", "analyst_id"]
    for r in random.sample(result, k=max(1, int(n * frac_missing))):
        f = random.choice(fields)
        r[f] = ""   # blank

    # Completely invalid rows
    for i in range(max(1, int(n * frac_invalid))):
        result.append({
            "alert_id":  f"INVALID-{i}",
            "cse_id":    "UNKNOWN",
            "category":  "???",
            "severity":  "NOTASEV",
            "created_at":"not-a-date",
            "closed_at": "not-a-date",
            "mttr_seconds": "abc",
            "closure_notes": "",
            "analyst_id": "",
            "asset_id":  "",
            "source_ip": "999.999.999.999",
            "dest_ip":   "",
        })

    # Return planted first (always clean), then messy background
    return planted + result



# ── CSE-A: Power — S1 planted ─────────────────────────────────────────────────
def gen_cse_a_alerts() -> list[dict]:
    rng = random.Random(SEED + 1)
    rows = []

    # S1 Stage 1: Suspicious login from attacker IP
    t0 = S1_BASE_TIME
    rows.append(make_alert(
        S1_ALERT_IDS[0], "CSE-A", "Suspicious Login", "CRITICAL",
        t0, t0 + timedelta(minutes=45),
        "ANA-A01", S1_SERVERS[0], S1_ATTACKER_IP, random_ip(),
        "Suspicious login attempt detected from external IP 203.0.113.5 — Tier-1 analysis pending."
    ))
    rows.append(make_alert(
        S1_ALERT_IDS[1], "CSE-A", "Authentication Failure", "HIGH",
        t0 + timedelta(minutes=2), t0 + timedelta(minutes=40),
        "ANA-A02", S1_SERVERS[0], S1_ATTACKER_IP, random_ip(),
        "Multiple auth failures from 203.0.113.5."
    ))

    # S1 Stage 2: Privilege escalation
    t1 = t0 + timedelta(minutes=30)
    rows.append(make_alert(
        S1_ALERT_IDS[2], "CSE-A", "Privilege Escalation", "CRITICAL",
        t1, t1 + timedelta(minutes=60),
        "ANA-A01", S1_SERVERS[0], S1_ATTACKER_IP, random_ip(),
        f"User {S1_USERS[0]} escalated privileges on {S1_SERVERS[0]}."
    ))
    rows.append(make_alert(
        S1_ALERT_IDS[3], "CSE-A", "Privilege Escalation", "HIGH",
        t1 + timedelta(minutes=5), t1 + timedelta(minutes=55),
        "ANA-A03", S1_SERVERS[1], S1_ATTACKER_IP, random_ip(),
        f"Service account {S1_USERS[1]} granted elevated rights."
    ))

    # S1 Stage 3: Lateral movement via RDP to SRV-APP-01
    t2 = t1 + timedelta(minutes=45)
    rows.append(make_alert(
        S1_ALERT_IDS[4], "CSE-A", "Lateral Movement", "CRITICAL",
        t2, t2 + timedelta(minutes=90),
        "ANA-A01", S1_SERVERS[0], S1_ATTACKER_IP, random_ip(),
        f"RDP lateral movement detected: {S1_ATTACKER_IP} -> SRV-APP-01. Session initiated by {S1_USERS[1]}."
    ))
    rows.append(make_alert(
        S1_ALERT_IDS[5], "CSE-A", "Lateral Movement", "HIGH",
        t2 + timedelta(minutes=10), t2 + timedelta(minutes=80),
        "ANA-A02", S1_SERVERS[1], S1_ATTACKER_IP, S1_SERVERS[0],
        "Lateral spread from SRV-APP-01 to SRV-DC-02."
    ))
    rows.append(make_alert(
        S1_ALERT_IDS[6], "CSE-A", "Lateral Movement", "CRITICAL",
        t2 + timedelta(minutes=20), t2 + timedelta(minutes=70),
        "ANA-A03", S1_SERVERS[2], S1_ATTACKER_IP, S1_SERVERS[1],
        "Movement to SRV-DB-03 detected."
    ))

    # S1 Stage 4: Sensitive file access
    t3 = t2 + timedelta(minutes=60)
    rows.append(make_alert(
        S1_ALERT_IDS[7], "CSE-A", "File Access", "CRITICAL",
        t3, t3 + timedelta(minutes=30),
        "ANA-A01", S1_SERVERS[2], S1_ATTACKER_IP, random_ip(),
        f"Sensitive file read by {S1_USERS[0]} on SRV-DB-03 — /data/grid_config.enc accessed."
    ))
    rows.append(make_alert(
        S1_ALERT_IDS[8], "CSE-A", "Data Exfiltration", "CRITICAL",
        t3 + timedelta(minutes=5), t3 + timedelta(minutes=25),
        "ANA-A02", S1_SERVERS[2], S1_ATTACKER_IP, random_ip(),
        "Large outbound transfer detected from SRV-DB-03."
    ))

    # S1 Stage 5: Logs cleared + alerts closed quickly
    t4 = t3 + timedelta(minutes=20)
    rows.append(make_alert(
        S1_ALERT_IDS[9], "CSE-A", "Log Tampering", "CRITICAL",
        t4, t4 + timedelta(seconds=90),     # closed suspiciously fast
        "ANA-A04", S1_SERVERS[0], S1_ATTACKER_IP, random_ip(),
        "Windows event logs cleared on SRV-APP-01. — Closed: No further action."
    ))
    rows.append(make_alert(
        S1_ALERT_IDS[10], "CSE-A", "Log Tampering", "HIGH",
        t4 + timedelta(minutes=2), t4 + timedelta(seconds=150),
        "ANA-A04", S1_SERVERS[1], S1_ATTACKER_IP, random_ip(),
        "Syslog rotation forced on SRV-DC-02. Closed."
    ))
    rows.append(make_alert(
        S1_ALERT_IDS[11], "CSE-A", "Policy Violation", "MEDIUM",
        t4 + timedelta(minutes=3), t4 + timedelta(seconds=100),
        "ANA-A04", S1_SERVERS[2], random_ip(), random_ip(),
        "Audit policy modified. Auto-closed."
    ))

    # Normal background noise
    assets_a = [S1_SERVERS[0], S1_SERVERS[1], S1_SERVERS[2], "SRV-FW-01", "WKS-A-001", "WKS-A-002"]
    for _ in range(200):
        cat  = rng.choice(CATEGORIES)
        sev  = rng.choices(SEVERITY_POOL, weights=SEV_WEIGHTS)[0]
        ca   = rng_ts(START, END)
        mttr_s = max(60, rng.gauss(3600, 1000))
        cl   = ca + timedelta(seconds=mttr_s)
        rows.append(make_alert(
            str(uuid.UUID(int=rng.getrandbits(128))), "CSE-A",
            cat, sev, ca, cl,
            rng.choice(ANALYSTS_A), rng.choice(assets_a),
            random_ip(), random_ip()
        ))

    return rows


def gen_cse_a_cases() -> list[dict]:
    t0 = S1_BASE_TIME
    return [{
        "case_id":         S1_CASE_ID,
        "cse_id":          "CSE-A",
        "title":           "APT Campaign — External IP 203.0.113.5",
        "severity":        "CRITICAL",
        "status":          "open",
        "opened_at":       t0.isoformat(),
        "closed_at":       "",
        "analyst_id":      "ANA-A01",
        "linked_alert_ids": ",".join(S1_ALERT_IDS),
    }]


def gen_cse_a_investigations() -> list[dict]:
    t0 = S1_BASE_TIME
    return [{
        "investigation_id": S1_INV_ID,
        "cse_id":           "CSE-A",
        "case_id":          S1_CASE_ID,
        "analyst_id":       "ANA-A01",
        "started_at":       (t0 + timedelta(hours=1)).isoformat(),
        "completed_at":     "",
        "outcome":          "ongoing",
        "notes":            "Initial triage complete. Attacker IP 203.0.113.5 confirmed malicious. Escalated to Tier-3.",
    }]


def gen_cse_a_escalations() -> list[dict]:
    t0 = S1_BASE_TIME
    return [{
        "escalation_id": "S1-ESC-0001",
        "cse_id":        "CSE-A",
        "alert_id":      S1_ALERT_IDS[4],    # lateral movement
        "case_id":       S1_CASE_ID,
        "escalated_by":  "ANA-A01",
        "escalated_to":  "TIER3-LEAD",
        "escalated_at":  (t0 + timedelta(hours=2)).isoformat(),
        "reason":        "Confirmed lateral movement across 3 servers from external attacker.",
        "resolved":      "false",
    }]


def gen_cse_a_assets() -> list[dict]:
    return [
        {"asset_id": "SRV-APP-01", "cse_id": "CSE-A", "asset_name": "Application Server 01",
         "asset_type": "server", "criticality": "CRITICAL", "ip_address": "10.1.1.10",
         "hostname": "SRV-APP-01", "last_seen": (END - timedelta(hours=1)).isoformat()},
        {"asset_id": "SRV-DC-02",  "cse_id": "CSE-A", "asset_name": "Domain Controller 02",
         "asset_type": "server", "criticality": "CRITICAL", "ip_address": "10.1.1.20",
         "hostname": "SRV-DC-02",  "last_seen": (END - timedelta(hours=2)).isoformat()},
        {"asset_id": "SRV-DB-03",  "cse_id": "CSE-A", "asset_name": "Database Server 03",
         "asset_type": "server", "criticality": "CRITICAL", "ip_address": "10.1.1.30",
         "hostname": "SRV-DB-03",  "last_seen": (END - timedelta(hours=3)).isoformat()},
        {"asset_id": "SRV-FW-01",  "cse_id": "CSE-A", "asset_name": "Perimeter Firewall",
         "asset_type": "firewall", "criticality": "HIGH", "ip_address": "10.1.1.1",
         "hostname": "SRV-FW-01",  "last_seen": END.isoformat()},
        {"asset_id": "WKS-A-001",  "cse_id": "CSE-A", "asset_name": "Workstation A001",
         "asset_type": "workstation", "criticality": "LOW", "ip_address": "10.1.2.10",
         "hostname": "WKS-A-001",  "last_seen": END.isoformat()},
        {"asset_id": "WKS-A-002",  "cse_id": "CSE-A", "asset_name": "Workstation A002",
         "asset_type": "workstation", "criticality": "LOW", "ip_address": "10.1.2.11",
         "hostname": "WKS-A-002",  "last_seen": END.isoformat()},
    ]


# ── CSE-B: Banking — S2 planted ───────────────────────────────────────────────
def gen_cse_b_alerts() -> list[dict]:
    rng = random.Random(SEED + 2)
    rows = []

    # S2: 15 critical alerts closed in <2 minutes, no investigation
    for i, aid in enumerate(S2_ALERT_IDS):
        t = S2_BASE_TIME + timedelta(minutes=i * 3)
        closed = t + timedelta(seconds=rng.randint(20, 110))   # <2 min
        rows.append(make_alert(
            aid, "CSE-B", rng.choice(["Malware Detected", "Ransomware", "Data Exfiltration",
                                       "Privilege Escalation", "C2 Communication"]),
            "CRITICAL", t, closed,
            rng.choice(ANALYSTS_B), f"BANK-SRV-{rng.randint(1, 5):02d}",
            random_ip(), random_ip(),
            "Alert reviewed. No issues found. Closing."   # template note
        ))

    # Background noise
    assets_b = [f"BANK-SRV-{i:02d}" for i in range(1, 6)] + ["BANK-ATM-01", "BANK-DB-01"]
    for _ in range(180):
        cat  = rng.choice(CATEGORIES)
        sev  = rng.choices(SEVERITY_POOL, weights=SEV_WEIGHTS)[0]
        ca   = rng_ts(START, END)
        mttr_s = max(60, rng.gauss(3600, 1000))
        cl   = ca + timedelta(seconds=mttr_s)
        rows.append(make_alert(
            str(uuid.UUID(int=rng.getrandbits(128))), "CSE-B",
            cat, sev, ca, cl,
            rng.choice(ANALYSTS_B), rng.choice(assets_b),
        ))

    return rows


def gen_cse_b_cases() -> list[dict]:
    return [{
        "case_id":    S2_CASE_ID,
        "cse_id":     "CSE-B",
        "title":      "Bulk Critical Alert Closure — S2",
        "severity":   "CRITICAL",
        "status":     "closed",
        "opened_at":  S2_BASE_TIME.isoformat(),
        "closed_at":  (S2_BASE_TIME + timedelta(minutes=50)).isoformat(),
        "analyst_id": "ANA-B01",
        "linked_alert_ids": ",".join(S2_ALERT_IDS),
    }]


def gen_cse_b_assets() -> list[dict]:
    rng = random.Random(SEED + 20)
    return [
        {"asset_id": f"BANK-SRV-{i:02d}", "cse_id": "CSE-B",
         "asset_name": f"Banking Server {i:02d}", "asset_type": "server",
         "criticality": rng.choice(["CRITICAL", "HIGH"]),
         "ip_address": f"172.16.1.{i}", "hostname": f"BANK-SRV-{i:02d}",
         "last_seen": END.isoformat()}
        for i in range(1, 6)
    ] + [
        {"asset_id": "BANK-ATM-01", "cse_id": "CSE-B", "asset_name": "ATM Controller 01",
         "asset_type": "controller", "criticality": "CRITICAL",
         "ip_address": "172.16.2.1", "hostname": "BANK-ATM-01",
         "last_seen": END.isoformat()},
        {"asset_id": "BANK-DB-01", "cse_id": "CSE-B", "asset_name": "Core Banking DB",
         "asset_type": "database", "criticality": "CRITICAL",
         "ip_address": "172.16.1.100", "hostname": "BANK-DB-01",
         "last_seen": END.isoformat()},
    ]


# ── CSE-C: Telecom — S3 planted ───────────────────────────────────────────────
def gen_cse_c_alerts() -> list[dict]:
    rng = random.Random(SEED + 3)
    rows = []
    # S3: ASSET-CSE-C-SILENT-01 (CORE-SWITCH-01) has ZERO alerts for 30 days — intentionally empty

    # Normal alerts for OTHER assets
    assets_c = ["TEL-SRV-01", "TEL-SRV-02", "TEL-FW-01", "TEL-BS-01", "TEL-MGT-01"]
    for _ in range(220):
        cat  = rng.choice(CATEGORIES)
        sev  = rng.choices(SEVERITY_POOL, weights=SEV_WEIGHTS)[0]
        ca   = rng_ts(START, END)
        mttr_s = max(60, rng.gauss(3600, 1200))
        cl   = ca + timedelta(seconds=mttr_s)
        rows.append(make_alert(
            str(uuid.UUID(int=rng.getrandbits(128))), "CSE-C",
            cat, sev, ca, cl,
            rng.choice(ANALYSTS_C), rng.choice(assets_c),
        ))
    return rows


def gen_cse_c_assets() -> list[dict]:
    return [
        # S3: critical asset — zero alerts
        {"asset_id": S3_ASSET_ID, "cse_id": "CSE-C", "asset_name": S3_ASSET_NAME,
         "asset_type": "switch", "criticality": "CRITICAL",
         "ip_address": "192.168.10.1", "hostname": "CORE-SWITCH-01",
         "last_seen": (START + timedelta(days=1)).isoformat()},  # hasn't been seen in 29 days!
        {"asset_id": "TEL-SRV-01", "cse_id": "CSE-C", "asset_name": "Telecom Server 01",
         "asset_type": "server", "criticality": "HIGH",
         "ip_address": "192.168.1.10", "hostname": "TEL-SRV-01",
         "last_seen": END.isoformat()},
        {"asset_id": "TEL-SRV-02", "cse_id": "CSE-C", "asset_name": "Telecom Server 02",
         "asset_type": "server", "criticality": "MEDIUM",
         "ip_address": "192.168.1.11", "hostname": "TEL-SRV-02",
         "last_seen": END.isoformat()},
        {"asset_id": "TEL-FW-01", "cse_id": "CSE-C", "asset_name": "Telecom Firewall",
         "asset_type": "firewall", "criticality": "HIGH",
         "ip_address": "192.168.1.1", "hostname": "TEL-FW-01",
         "last_seen": END.isoformat()},
        {"asset_id": "TEL-BS-01", "cse_id": "CSE-C", "asset_name": "Base Station Controller",
         "asset_type": "controller", "criticality": "CRITICAL",
         "ip_address": "192.168.20.1", "hostname": "TEL-BS-01",
         "last_seen": END.isoformat()},
        {"asset_id": "TEL-MGT-01", "cse_id": "CSE-C", "asset_name": "Network Management Server",
         "asset_type": "server", "criticality": "MEDIUM",
         "ip_address": "192.168.1.50", "hostname": "TEL-MGT-01",
         "last_seen": END.isoformat()},
    ]


# ── CSE-D: Healthcare — S4 planted ────────────────────────────────────────────
def gen_cse_d_alerts() -> list[dict]:
    rng = random.Random(SEED + 4)
    rows = []

    # S4a: 10 critical alerts never escalated
    assets_d = ["MED-SRV-01", "MED-SRV-02", "MED-DB-01", "MED-WKS-01", "MED-IMG-01"]
    for aid in S4_ALERT_IDS_NEVER_ESC:
        ca = rng_ts(START, END - timedelta(days=5))
        mttr_s = max(300, rng.gauss(7200, 1500))
        cl = ca + timedelta(seconds=mttr_s)
        rows.append(make_alert(
            aid, "CSE-D",
            rng.choice(["Ransomware", "Data Exfiltration", "Privilege Escalation",
                        "Malware Detected", "C2 Communication"]),
            "CRITICAL", ca, cl,
            rng.choice(ANALYSTS_D), rng.choice(assets_d[:3]),
            random_ip(), random_ip(),
            "Alert investigated and closed. No escalation required."
        ))

    # S4b: Alert spike day — 50 alerts in one day
    for i, aid in enumerate(S4_SPIKE_ALERT_IDS):
        spike_t = S4_SPIKE_DAY + timedelta(hours=rng.uniform(0, 23))
        closed_t = spike_t + timedelta(seconds=rng.gauss(1800, 600))
        rows.append(make_alert(
            aid, "CSE-D",
            rng.choice(CATEGORIES),
            rng.choices(SEVERITY_POOL, weights=SEV_WEIGHTS)[0],
            spike_t, closed_t,
            rng.choice(ANALYSTS_D), rng.choice(assets_d),
        ))

    # Normal background
    for _ in range(150):
        cat  = rng.choice(CATEGORIES)
        sev  = rng.choices(SEVERITY_POOL, weights=SEV_WEIGHTS)[0]
        ca   = rng_ts(START, END)
        mttr_s = max(60, rng.gauss(4000, 1200))
        cl   = ca + timedelta(seconds=mttr_s)
        rows.append(make_alert(
            str(uuid.UUID(int=rng.getrandbits(128))), "CSE-D",
            cat, sev, ca, cl,
            rng.choice(ANALYSTS_D), rng.choice(assets_d),
        ))

    return rows


def gen_cse_d_assets() -> list[dict]:
    return [
        {"asset_id": "MED-SRV-01", "cse_id": "CSE-D", "asset_name": "Medical Records Server",
         "asset_type": "server", "criticality": "CRITICAL",
         "ip_address": "10.20.1.10", "hostname": "MED-SRV-01",
         "last_seen": END.isoformat()},
        {"asset_id": "MED-SRV-02", "cse_id": "CSE-D", "asset_name": "Patient Data Server",
         "asset_type": "server", "criticality": "CRITICAL",
         "ip_address": "10.20.1.11", "hostname": "MED-SRV-02",
         "last_seen": END.isoformat()},
        {"asset_id": "MED-DB-01", "cse_id": "CSE-D", "asset_name": "Healthcare Database",
         "asset_type": "database", "criticality": "CRITICAL",
         "ip_address": "10.20.1.50", "hostname": "MED-DB-01",
         "last_seen": END.isoformat()},
        {"asset_id": "MED-WKS-01", "cse_id": "CSE-D", "asset_name": "Clinical Workstation",
         "asset_type": "workstation", "criticality": "MEDIUM",
         "ip_address": "10.20.2.10", "hostname": "MED-WKS-01",
         "last_seen": END.isoformat()},
        {"asset_id": "MED-IMG-01", "cse_id": "CSE-D", "asset_name": "Imaging System",
         "asset_type": "server", "criticality": "HIGH",
         "ip_address": "10.20.3.10", "hostname": "MED-IMG-01",
         "last_seen": END.isoformat()},
    ]


def gen_cse_d_escalations() -> list[dict]:
    """S4: zero escalations even though there are CRITICAL alerts — planted absence."""
    return []   # intentionally empty — no escalations for CSE-D


# ── Writers ───────────────────────────────────────────────────────────────────
def write_csv(rows: list[dict], path: str):
    if not rows:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def write_json(rows: list[dict], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, default=str)


# ── Main ──────────────────────────────────────────────────────────────────────
def generate_all():
    print("[GEN] Starting synthetic data generation...")

    # ── CSE-A ────────────────────────────────────────────────────────────────
    alerts_a = inject_mess(gen_cse_a_alerts())
    write_csv(alerts_a, f"{OUT_DIR}/CSE-A/alerts.csv")
    write_json(alerts_a, f"{OUT_DIR}/CSE-A/alerts.json")

    cases_a = gen_cse_a_cases()
    write_csv(cases_a, f"{OUT_DIR}/CSE-A/cases.csv")
    write_json(cases_a, f"{OUT_DIR}/CSE-A/cases.json")

    inv_a = gen_cse_a_investigations()
    write_csv(inv_a, f"{OUT_DIR}/CSE-A/investigations.csv")
    write_json(inv_a, f"{OUT_DIR}/CSE-A/investigations.json")

    esc_a = gen_cse_a_escalations()
    write_csv(esc_a, f"{OUT_DIR}/CSE-A/escalations.csv")
    write_json(esc_a, f"{OUT_DIR}/CSE-A/escalations.json")

    assets_a = gen_cse_a_assets()
    write_csv(assets_a, f"{OUT_DIR}/CSE-A/assets.csv")
    write_json(assets_a, f"{OUT_DIR}/CSE-A/assets.json")

    # ── CSE-B ────────────────────────────────────────────────────────────────
    alerts_b = inject_mess(gen_cse_b_alerts())
    write_csv(alerts_b, f"{OUT_DIR}/CSE-B/alerts.csv")
    write_json(alerts_b, f"{OUT_DIR}/CSE-B/alerts.json")

    cases_b = gen_cse_b_cases()
    write_csv(cases_b, f"{OUT_DIR}/CSE-B/cases.csv")
    write_json(cases_b, f"{OUT_DIR}/CSE-B/cases.json")

    assets_b = gen_cse_b_assets()
    write_csv(assets_b, f"{OUT_DIR}/CSE-B/assets.csv")
    write_json(assets_b, f"{OUT_DIR}/CSE-B/assets.json")

    # ── CSE-C ────────────────────────────────────────────────────────────────
    alerts_c = inject_mess(gen_cse_c_alerts())
    write_csv(alerts_c, f"{OUT_DIR}/CSE-C/alerts.csv")
    write_json(alerts_c, f"{OUT_DIR}/CSE-C/alerts.json")

    assets_c = gen_cse_c_assets()
    write_csv(assets_c, f"{OUT_DIR}/CSE-C/assets.csv")
    write_json(assets_c, f"{OUT_DIR}/CSE-C/assets.json")

    # ── CSE-D ────────────────────────────────────────────────────────────────
    alerts_d = inject_mess(gen_cse_d_alerts())
    write_csv(alerts_d, f"{OUT_DIR}/CSE-D/alerts.csv")
    write_json(alerts_d, f"{OUT_DIR}/CSE-D/alerts.json")

    esc_d = gen_cse_d_escalations()
    write_csv(esc_d, f"{OUT_DIR}/CSE-D/escalations.csv")
    write_json(esc_d, f"{OUT_DIR}/CSE-D/escalations.json")

    assets_d = gen_cse_d_assets()
    write_csv(assets_d, f"{OUT_DIR}/CSE-D/assets.csv")
    write_json(assets_d, f"{OUT_DIR}/CSE-D/assets.json")

    # ── Summary ──────────────────────────────────────────────────────────────
    summary = {
        "CSE-A": {
            "alerts": len(alerts_a),
            "cases": len(cases_a),
            "investigations": len(inv_a),
            "escalations": len(esc_a),
            "assets": len(assets_a),
        },
        "CSE-B": {
            "alerts": len(alerts_b),
            "cases": len(cases_b),
            "assets": len(assets_b),
        },
        "CSE-C": {
            "alerts": len(alerts_c),
            "assets": len(assets_c),
        },
        "CSE-D": {
            "alerts": len(alerts_d),
            "escalations": len(esc_d),
            "assets": len(assets_d),
        },
    }
    write_json(summary, f"{OUT_DIR}/manifest.json")

    print("[GEN] Done. Files written to:", OUT_DIR)
    for cse, counts in summary.items():
        for dtype, n in counts.items():
            print(f"  {cse}/{dtype}: {n} rows")
    return summary


if __name__ == "__main__":
    generate_all()
