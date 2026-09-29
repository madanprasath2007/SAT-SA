"""
Threat Intelligence Importer — Air-Gapped / Offline Import
Validates bundle SHA-256 against manifest before writing to DuckDB.
Rejects any corrupted, unverified, or tampered bundles.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Dict, Optional, Tuple, Union

import duckdb

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_SAMPLE_BUNDLE_DIR = os.path.join(REPO_ROOT, "data", "threat_intel", "sample_bundle")


class ChecksumMismatchError(ValueError):
    """Raised when bundle SHA-256 checksum does not match manifest."""
    pass


def verify_bundle_checksum(bundle_bytes: bytes, manifest_dict: Dict[str, Any]) -> str:
    """Computes SHA-256 of bundle bytes and verifies against manifest."""
    computed_sha = hashlib.sha256(bundle_bytes).hexdigest()
    expected_sha = manifest_dict.get("sha256", "").strip().lower()

    if expected_sha and computed_sha.lower() == expected_sha:
        return computed_sha

    # Try normalizing Windows CRLF to LF
    norm_sha = hashlib.sha256(bundle_bytes.replace(b"\r\n", b"\n")).hexdigest()
    if expected_sha and norm_sha.lower() == expected_sha:
        return norm_sha

    raise ChecksumMismatchError(
        f"Bundle SHA-256 verification failed! Expected '{expected_sha}', computed '{computed_sha}'."
    )


def import_threat_intel_bundle(
    con: duckdb.DuckDBPyConnection,
    bundle_data: Union[bytes, str, Dict],
    manifest_data: Union[bytes, str, Dict],
) -> Dict[str, Any]:
    """
    Imports validated CTI bundle into DuckDB threat_intel_* tables.
    Accepts bytes, JSON string, or pre-parsed dict.
    Strictly verifies checksum first.
    """
    # 1. Parse manifest
    if isinstance(manifest_data, bytes):
        manifest_dict = json.loads(manifest_data.decode("utf-8"))
    elif isinstance(manifest_data, str):
        manifest_dict = json.loads(manifest_data)
    else:
        manifest_dict = manifest_data

    # 2. Get bundle bytes and dict
    if isinstance(bundle_data, bytes):
        bundle_bytes = bundle_data
        bundle_dict = json.loads(bundle_bytes.decode("utf-8"))
    elif isinstance(bundle_data, str):
        bundle_bytes = bundle_data.encode("utf-8")
        bundle_dict = json.loads(bundle_data)
    else:
        # Pre-parsed dict: re-encode canonically
        bundle_dict = bundle_data
        bundle_bytes = json.dumps(bundle_dict, indent=2, sort_keys=True).encode("utf-8")

    # 3. Checksum verification
    verified_sha = verify_bundle_checksum(bundle_bytes, manifest_dict)

    # 4. Insert into database
    bundle_id = bundle_dict.get("bundle_id", f"bundle-{verified_sha[:12]}")
    version = bundle_dict.get("version", manifest_dict.get("version", "1.0.0"))
    iocs = bundle_dict.get("iocs", [])
    cves = bundle_dict.get("cves", [])

    # Record bundle
    con.execute("""
        INSERT OR REPLACE INTO threat_intel_bundles (bundle_id, version, sha256, imported_at, record_count, status)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, 'verified')
    """, [bundle_id, version, verified_sha, len(iocs) + len(cves)])

    # Upsert IOCs
    iocs_imported = 0
    for ioc in iocs:
        con.execute("""
            INSERT OR REPLACE INTO threat_intel_iocs
                (ioc_id, ioc_type, ioc_value, threat_actor, malware_family, description, confidence, mitre_tactics, mitre_techniques, first_seen, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            ioc.get("ioc_id", str(hashlib.md5(f"{ioc['ioc_type']}:{ioc['ioc_value']}".encode()).hexdigest())),
            ioc["ioc_type"],
            ioc["ioc_value"],
            ioc.get("threat_actor"),
            ioc.get("malware_family"),
            ioc.get("description"),
            float(ioc.get("confidence", 0.8)),
            ioc.get("mitre_tactics"),
            ioc.get("mitre_techniques"),
            ioc.get("first_seen", datetime.now(timezone.utc).isoformat()),
            ioc.get("source", "CTI-Bundle"),
        ])
        iocs_imported += 1

    # Upsert CVEs
    cves_imported = 0
    for cve in cves:
        con.execute("""
            INSERT OR REPLACE INTO threat_intel_cves
                (cve_id, description, cvss_score, affected_products, published_date)
            VALUES (?, ?, ?, ?, ?)
        """, [
            cve["cve_id"],
            cve.get("description"),
            float(cve.get("cvss_score", 0.0)),
            cve.get("affected_products"),
            cve.get("published_date", datetime.now(timezone.utc).isoformat()),
        ])
        cves_imported += 1

    return {
        "status": "success",
        "bundle_id": bundle_id,
        "sha256": verified_sha,
        "iocs_imported": iocs_imported,
        "cves_imported": cves_imported,
        "total_records": iocs_imported + cves_imported,
    }


def seed_sample_threat_intel(con: duckdb.DuckDBPyConnection, bundle_dir: Optional[str] = None):
    """Seed threat intelligence from the local sample bundle if not already populated."""
    dir_path = bundle_dir or DEFAULT_SAMPLE_BUNDLE_DIR
    bundle_path = os.path.join(dir_path, "bundle.json")
    manifest_path = os.path.join(dir_path, "manifest.json")

    if not os.path.exists(bundle_path) or not os.path.exists(manifest_path):
        return

    with open(bundle_path, "rb") as f:
        bundle_bytes = f.read()
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_dict = json.load(f)

    try:
        import_threat_intel_bundle(con, bundle_bytes, manifest_dict)
    except Exception as e:
        print(f"[ThreatIntel] Seed error: {e}")
