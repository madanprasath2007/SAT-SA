"""
Attack Traceback Service & Orchestration
Coordinates event graph correlation, MITRE attack path clustering,
offline LLM narrative generation, evidence verification, and report persistence.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid
import duckdb

from .correlate import build_event_graph, graph_to_react_flow, get_threat_intel_lookup
from .path import cluster_candidate_incidents, build_attack_path
from llm.client import get_llm_client
from llm.verifier import verify_llm_claims


def run_attack_traceback(
    con: duckdb.DuckDBPyConnection,
    cse_id: str,
    finding_id: Optional[str] = None,
    llm_backend: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes full attack traceback for a CSE.
    Reconstructs chronological attack chain, calls offline LLM, verifies evidence IDs,
    and returns an explainable supervisory incident report.
    """
    # 1. Cluster alerts into candidate incidents
    candidates = cluster_candidate_incidents(con, cse_id)
    if not candidates:
        return {
            "status": "no_incident",
            "cse_id": cse_id,
            "message": f"No correlated alert clusters found for {cse_id}.",
            "stages": [],
            "confidence_score": 0.0,
        }

    # Select target candidate
    candidate = candidates[0]
    alerts = candidate["alerts"]
    alert_ids = [a["alert_id"] for a in alerts]

    # 2. Reconstruct attack path with MITRE tactics
    attack_path = build_attack_path(candidate)
    stages = attack_path["stages"]
    matched_iocs = attack_path["matched_iocs"]
    entry_point = attack_path["entry_point"]
    confidence = attack_path["overall_confidence"]

    # 3. Build React Flow graph
    G = build_event_graph(con, cse_id=cse_id, alert_ids=alert_ids)
    graph_data = graph_to_react_flow(G)

    # 4. Prepare prompt with ONLY raw evidence records
    evidence_prompt_records = [
        {
            "alert_id": a["alert_id"],
            "timestamp": str(a["created_at"]),
            "category": a.get("category"),
            "severity": a.get("severity"),
            "source_ip": a.get("source_ip"),
            "dest_ip": a.get("dest_ip"),
            "asset_id": a.get("asset_id"),
            "closure_notes": a.get("closure_notes"),
        }
        for a in alerts
    ]

    # Fetch recent supervisor reviewer feedback examples (both Valid and False Positive)
    review_context = ""
    try:
        rev_rows = con.execute("""
            SELECT f.finding_type, r.decision, r.notes
            FROM reviews r
            JOIN findings f ON r.finding_id = f.finding_id
            ORDER BY r.created_at DESC LIMIT 5
        """).fetchall()
        if rev_rows:
            review_context = "\nRECENT SUPERVISOR REVIEW DETERMINATIONS (PRIOR CONTEXT):\n"
            for ftype, dec, notes in rev_rows:
                review_context += f"- Finding '{ftype}': Marked as {dec}. Supervisor note: {notes or 'Confirmed under formal review'}\n"
    except Exception:
        pass

    prompt = f"""
Analyze the following security alert evidence records for {cse_id} and reconstruct how the attack occurred.
Provide a 5-stage chronological attack path matching MITRE ATT&CK tactics:
1. Initial Access
2. Privilege Escalation
3. Lateral Movement
4. Data Access
5. Evidence Tampering
{review_context}
EVIDENCE RECORDS:
{json.dumps(evidence_prompt_records, indent=2)}

You must return ONLY valid JSON matching this schema:
{{
  "incident_title": "String",
  "summary": "String",
  "attacker_entry_point": "String",
  "stages": [
    {{
      "stage_number": 1,
      "stage_name": "Initial Access",
      "tactic": "TA0001",
      "technique": "T1078",
      "claim": "Evidence-grounded claim describing what the attacker did",
      "evidence_ids": ["ALT-ID-1"],
      "attacker_intent": "Strategic intention of adversary in this stage"
    }}
  ]
}}
"""
    system_prompt = "You are a cyber threat intelligence and incident traceback specialist. Rely EXCLUSIVELY on the provided evidence IDs. Do NOT hallucinate any alert IDs."

    # 5. Call LLM (MockLLM or OllamaLLM)
    llm = get_llm_client(llm_backend)
    raw_response = llm.generate(prompt, system_prompt)

    try:
        parsed_llm = json.loads(raw_response)
    except Exception:
        # Fallback to deterministic attack path output
        parsed_llm = {
            "incident_title": f"APT Intrusion Incident — {cse_id}",
            "summary": f"Multi-stage intrusion targeting {cse_id} via {entry_point}.",
            "attacker_entry_point": entry_point,
            "stages": stages,
        }

    # 6. Verify LLM claims — reject any fabricated evidence_ids
    verified_narrative, rejected_eids = verify_llm_claims(con, parsed_llm)

    # 7. Synthesize explainability fields
    ioc_desc = f" Corroborated by CTI match against known malicious IP {matched_iocs[0]['ioc_value']} ({matched_iocs[0].get('threat_actor', 'APT')} - confidence: {matched_iocs[0].get('confidence')})." if matched_iocs else ""
    why_flagged = (
        f"Correlated multi-stage attack detected originating from {entry_point} impacting "
        f"{len(candidate['impacted_assets'])} internal host(s) across {len(alerts)} alerts.{ioc_desc} "
        f"Attack exhibits 5-stage progression with lateral movement and post-compromise log tampering."
    )

    incident_id = f"INC-{cse_id}-{uuid.uuid4().hex[:8].upper()}"
    final_stages = verified_narrative.get("stages", stages)

    report = {
        "incident_id": incident_id,
        "cse_id": cse_id,
        "finding_id": finding_id or (alerts[0]["alert_id"] if alerts else None),
        "title": verified_narrative.get("incident_title", f"Multi-Stage Attack Traceback — {cse_id}"),
        "summary": verified_narrative.get("summary", ""),
        "confidence_score": round(confidence * 100, 1),
        "why_flagged": why_flagged,
        "how_attack_happened": verified_narrative.get("summary", ""),
        "attacker_entry_point": verified_narrative.get("attacker_entry_point", entry_point),
        "stages": final_stages,
        "stages_count": len(final_stages),
        "matched_iocs": matched_iocs,
        "impacted_assets": candidate["impacted_assets"],
        "evidence_ids": [a["alert_id"] for a in alerts],
        "rejected_evidence_ids": rejected_eids,
        "graph": graph_data,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # 8. Persist to traceback_reports table
    try:
        con.execute("""
            INSERT OR REPLACE INTO traceback_reports
                (incident_id, cse_id, finding_id, title, confidence_score, why_flagged,
                 narrative, stages_json, ioc_matches_json, evidence_ids_json, graph_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, [
            incident_id,
            cse_id,
            finding_id or alerts[0]["alert_id"],
            report["title"],
            report["confidence_score"],
            report["why_flagged"],
            report["how_attack_happened"],
            json.dumps(final_stages),
            json.dumps(matched_iocs),
            json.dumps(report["evidence_ids"]),
            json.dumps(graph_data),
        ])
    except Exception as e:
        print(f"[Traceback] Persistence warning: {e}")

    return report
