"""
Threat Intelligence Router (Phase 3)
Allows offline ingestion of CTI bundles with cryptographic SHA-256 verification
and queries the local threat intelligence knowledge base.
"""

import json
from typing import Optional
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from models import get_connection
from threat_intel.importer import (
    ChecksumMismatchError,
    import_threat_intel_bundle,
    seed_sample_threat_intel,
)

router = APIRouter()


@router.post("/import")
async def import_bundle(
    bundle_file: UploadFile = File(..., description="bundle.json file"),
    manifest_file: UploadFile = File(..., description="manifest.json file"),
):
    """
    Import a CTI bundle offline.
    Cryptographically verifies the SHA-256 checksum of the bundle against the manifest.
    Rejects corrupted or tampered files.
    """
    bundle_bytes = await bundle_file.read()
    manifest_bytes = await manifest_file.read()

    con = get_connection()
    try:
        result = import_threat_intel_bundle(con, bundle_bytes, manifest_bytes)
        con.close()
        return result
    except ChecksumMismatchError as cme:
        con.close()
        raise HTTPException(status_code=400, detail=str(cme))
    except Exception as e:
        con.close()
        raise HTTPException(status_code=500, detail=f"Failed to import CTI bundle: {str(e)}")


@router.get("/status")
@router.get("/summary")
def get_cti_status():
    """Return local Threat Intelligence Knowledge Base status and counts."""
    con = get_connection()

    # If empty, seed from default sample bundle
    ioc_cnt = con.execute("SELECT COUNT(*) FROM threat_intel_iocs").fetchone()[0]
    if ioc_cnt == 0:
        seed_sample_threat_intel(con)
        ioc_cnt = con.execute("SELECT COUNT(*) FROM threat_intel_iocs").fetchone()[0]

    cve_cnt = con.execute("SELECT COUNT(*) FROM threat_intel_cves").fetchone()[0]
    bundle_cnt = con.execute("SELECT COUNT(*) FROM threat_intel_bundles").fetchone()[0]

    recent_bundle = con.execute("""
        SELECT bundle_id, version, sha256, imported_at, record_count
        FROM threat_intel_bundles
        ORDER BY imported_at DESC
        LIMIT 1
    """).fetchone()

    con.close()

    return {
        "status": "operational",
        "total_iocs": ioc_cnt,
        "total_cves": cve_cnt,
        "total_bundles": bundle_cnt,
        "latest_bundle": {
            "bundle_id": recent_bundle[0],
            "version": recent_bundle[1],
            "sha256": recent_bundle[2],
            "imported_at": str(recent_bundle[3]),
            "record_count": recent_bundle[4],
        } if recent_bundle else None,
    }


@router.get("/iocs")
def list_iocs(ioc_type: Optional[str] = None, search: Optional[str] = None):
    """List threat intelligence IOCs with optional filtering."""
    con = get_connection()
    query = """
        SELECT ioc_id, ioc_type, ioc_value, threat_actor, malware_family, description,
               confidence, mitre_tactics, mitre_techniques, first_seen, source
        FROM threat_intel_iocs
        WHERE 1=1
    """
    params = []
    if ioc_type:
        query += " AND ioc_type = ?"
        params.append(ioc_type.lower())
    if search:
        query += " AND (ioc_value LIKE ? OR threat_actor LIKE ? OR description LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    query += " ORDER BY confidence DESC, ioc_type LIMIT 100"
    rows = con.execute(query, params).fetchall()
    cols = ["ioc_id", "ioc_type", "ioc_value", "threat_actor", "malware_family", "description",
            "confidence", "mitre_tactics", "mitre_techniques", "first_seen", "source"]
    con.close()

    return {"data": [dict(zip(cols, r)) for r in rows], "count": len(rows)}


@router.get("/cves")
def list_cves(search: Optional[str] = None):
    """List threat intelligence CVEs with optional filtering."""
    con = get_connection()
    query = """
        SELECT cve_id, description, cvss_score, affected_products, published_date
        FROM threat_intel_cves
        WHERE 1=1
    """
    params = []
    if search:
        query += " AND (cve_id LIKE ? OR description LIKE ? OR affected_products LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    query += " ORDER BY cvss_score DESC LIMIT 100"
    rows = con.execute(query, params).fetchall()
    cols = ["cve_id", "description", "cvss_score", "affected_products", "published_date"]
    data = []
    for r in rows:
        row_dict = dict(zip(cols, r))
        if row_dict.get("published_date"):
            row_dict["published_date"] = str(row_dict["published_date"])
        data.append(row_dict)
    con.close()

    return {"data": data, "count": len(data)}

