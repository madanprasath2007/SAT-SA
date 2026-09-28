"""
Synthetic Data Seeder
Generates realistic-looking SOC alert data to populate DuckDB for demo purposes.
"""

import uuid
import random
import math
from datetime import datetime, timedelta
from typing import List, Dict, Any

random.seed(42)

CATEGORIES = [
    "Ransomware", "Privilege Escalation", "Lateral Movement",
    "Authentication Failure", "Data Exfiltration", "Malware Detected",
    "Phishing", "Brute Force", "C2 Communication", "Policy Violation",
]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
CSE_IDS = ["CSE-ALPHA", "CSE-BETA", "CSE-GAMMA", "CSE-DELTA"]
ANALYSTS = [f"ANALYST-{i:03d}" for i in range(1, 12)]
ASSETS = [
    {"asset_id": "ASSET-DC01", "asset_name": "Domain Controller 01", "asset_type": "DC", "criticality": "CRITICAL"},
    {"asset_id": "ASSET-FW01", "asset_name": "Perimeter Firewall",  "asset_type": "FW", "criticality": "HIGH"},
    {"asset_id": "ASSET-PAY1", "asset_name": "Payment Gateway",      "asset_type": "APP", "criticality": "CRITICAL"},
    {"asset_id": "ASSET-WEB1", "asset_name": "Web Server 01",        "asset_type": "APP", "criticality": "MEDIUM"},
    {"asset_id": "ASSET-WKS1", "asset_name": "Workstation 1",        "asset_type": "WKS", "criticality": "LOW"},
]

TEMPLATE_NOTES = [
    "Alert investigated. No malicious activity found. Closed as false positive.",
    "Reviewed alert. System behavior is normal. Closing ticket.",
    "Checked and verified. No issues detected. Case closed.",
    "Investigated per SOP. False positive confirmed. Closing.",
    "Alert reviewed. Activity within expected parameters. Closed.",
]

GENUINE_NOTES = [
    "Correlated with ASSET-DC01 authentication logs. Spike at 03:15 UTC matches {src_ip}. Escalated to Tier-2.",
    "Lateral movement detected from {src_ip} to {dst_ip}. Created incident IR-{num}. Notified SOC lead.",
    "Ransomware signature matched CVE-2024-{num}. Endpoint isolated. EDR quarantine applied.",
    "Auth failure storm from {src_ip}. Geo-block applied. 2FA enforcement triggered on account.",
    "C2 beacon detected on port 4444. Firewall rule pushed. Threat intel shared with NCIIPC portal.",
]


def random_ip():
    return f"{random.randint(10,192)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def generate_assets() -> List[Dict[str, Any]]:
    return ASSETS


def generate_alerts(n: int = 500) -> List[Dict[str, Any]]:
    alerts = []
    base_time = datetime.utcnow() - timedelta(days=30)

    # Pick one "lazy" analyst who uses template notes
    lazy_analyst = random.choice(ANALYSTS)

    for i in range(n):
        category   = random.choice(CATEGORIES)
        severity   = random.choices(SEVERITIES, weights=[10, 25, 40, 25])[0]
        cse_id     = random.choice(CSE_IDS)
        analyst_id = random.choice(ANALYSTS)
        asset      = random.choice(ASSETS)

        created_at = base_time + timedelta(
            seconds=random.randint(0, 30 * 24 * 3600)
        )

        # Normal MTTR distribution per category/severity
        base_mttr = {"CRITICAL": 1800, "HIGH": 3600, "MEDIUM": 7200, "LOW": 14400}[severity]
        mttr = max(10, random.gauss(base_mttr, base_mttr * 0.3))

        # Inject gamed MTTR for 5% of CRITICAL alerts
        if severity == "CRITICAL" and random.random() < 0.05:
            mttr = random.uniform(5, 28)   # suspiciously fast

        closed_at = created_at + timedelta(seconds=mttr)

        # Closure notes
        if analyst_id == lazy_analyst or random.random() < 0.15:
            note = random.choice(TEMPLATE_NOTES)
        else:
            template = random.choice(GENUINE_NOTES)
            note = template.format(
                src_ip=random_ip(), dst_ip=random_ip(), num=random.randint(1000, 9999)
            )

        alerts.append({
            "alert_id":      str(uuid.uuid4()),
            "cse_id":        cse_id,
            "category":      category,
            "severity":      severity,
            "created_at":    created_at.isoformat(),
            "closed_at":     closed_at.isoformat(),
            "mttr_seconds":  round(mttr, 2),
            "closure_notes": note,
            "analyst_id":    analyst_id,
            "asset_id":      asset["asset_id"],
            "source_ip":     random_ip(),
            "dest_ip":       random_ip(),
        })
    return alerts


def generate_telemetry_obs() -> List[Dict[str, Any]]:
    """One observation per asset per hour for last 24h."""
    obs = []
    base = datetime.utcnow() - timedelta(hours=24)
    for asset in ASSETS:
        for h in range(24):
            # Inject a blackout for DC01 during business hours
            if asset["asset_id"] == "ASSET-DC01" and 9 <= h <= 11:
                log_count = random.randint(0, 5)   # near-zero — blackout
            else:
                # Normal volume proportional to criticality
                base_vol = {"CRITICAL": 2000, "HIGH": 1200, "MEDIUM": 600, "LOW": 200}[asset["criticality"]]
                log_count = max(0, int(random.gauss(base_vol, base_vol * 0.1)))
            obs.append({
                "asset_id":    asset["asset_id"],
                "cse_id":      random.choice(CSE_IDS),
                "hour_of_day": (base + timedelta(hours=h)).hour,
                "log_count":   log_count,
            })
    return obs


def generate_baselines() -> Dict[str, Dict[int, Dict[str, float]]]:
    """Synthetic baseline μ/σ per asset per hour of day."""
    baselines = {}
    for asset in ASSETS:
        baselines[asset["asset_id"]] = {}
        base_vol = {"CRITICAL": 2000, "HIGH": 1200, "MEDIUM": 600, "LOW": 200}[asset["criticality"]]
        for h in range(24):
            mu = base_vol * (0.5 if h < 6 or h > 22 else 1.0)
            baselines[asset["asset_id"]][h] = {
                "mu": mu, "sigma": mu * 0.1
            }
    return baselines


def generate_cse_alert_counts() -> List[Dict[str, Any]]:
    counts = []
    for cse_id in CSE_IDS:
        for category in CATEGORIES:
            # CSE-DELTA has no Privilege Escalation or Auth Failure alerts — negative space
            if cse_id == "CSE-DELTA" and category in ("Privilege Escalation", "Authentication Failure"):
                count = 0
            else:
                count = random.randint(80, 400)
            counts.append({"cse_id": cse_id, "category": category, "alert_count": count})
    return counts
