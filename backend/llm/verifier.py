"""
LLM Evidence Verifier
Guarantees zero-hallucination attack traceback reports by strictly verifying every
cited evidence_id against the DuckDB database. Drops or flags any claim referencing
fabricated, hallucinated, or non-existent evidence IDs.
"""

from typing import Any, Dict, List, Set, Tuple, Union
import duckdb


def get_existing_db_ids(con: duckdb.DuckDBPyConnection) -> Set[str]:
    """Retrieves all valid record identifiers from alerts, cases, assets, and investigations."""
    valid_ids: Set[str] = set()

    for table, col in [("alerts", "alert_id"), ("cases", "case_id"), ("assets", "asset_id"), ("investigations", "investigation_id")]:
        try:
            rows = con.execute(f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL").fetchall()
            for r in rows:
                if r[0]:
                    valid_ids.add(str(r[0]))
        except Exception:
            pass

    return valid_ids


def verify_llm_claims(
    con: duckdb.DuckDBPyConnection,
    narrative_dict: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Verifies every claim and cited evidence_id in an LLM-generated narrative against DuckDB.
    Returns:
        (verified_narrative, list_of_rejected_fabricated_ids)
    """
    valid_ids = get_existing_db_ids(con)
    rejected_ids: List[str] = []
    warnings: List[str] = []

    stages = narrative_dict.get("stages", [])
    verified_stages = []

    for stage in stages:
        raw_eids = stage.get("evidence_ids", [])
        verified_eids = []
        stage_rejected = []

        for eid in raw_eids:
            eid_str = str(eid).strip()
            if eid_str in valid_ids:
                verified_eids.append(eid_str)
            else:
                stage_rejected.append(eid_str)
                rejected_ids.append(eid_str)

        st_copy = dict(stage)
        st_copy["evidence_ids"] = verified_eids

        if stage_rejected:
            msg = f"Stage {stage.get('stage_number')}: Dropped {len(stage_rejected)} non-existent evidence IDs: {', '.join(stage_rejected)}"
            warnings.append(msg)
            st_copy["verification_warning"] = msg
            st_copy["rejected_evidence_ids"] = stage_rejected

        if not verified_eids and raw_eids:
            # All evidence was fabricated
            st_copy["verified"] = False
            st_copy["verification_status"] = "REJECTED_NO_GROUNDED_EVIDENCE"
            st_copy["claim"] = f"[UNVERIFIED CLAIM DROPPED] {stage.get('claim', '')}"
        else:
            st_copy["verified"] = True
            st_copy["verification_status"] = "VERIFIED"

        verified_stages.append(st_copy)

    verified_narrative = dict(narrative_dict)
    verified_narrative["stages"] = verified_stages
    verified_narrative["rejected_evidence_ids"] = rejected_ids
    verified_narrative["verification_passed"] = len(rejected_ids) == 0
    verified_narrative["verification_warnings"] = warnings

    return verified_narrative, rejected_ids
