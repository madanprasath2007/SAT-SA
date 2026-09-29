"""
Attack Path Reconstruction & MITRE ATT&CK Clustering
Clusters alerts into candidate incidents, determines the initial entry point,
maps events to MITRE tactics, detects lateral movement across assets,
and calculates per-stage and overall path confidence scores.
"""

from datetime import datetime
import os
from typing import Any, Dict, List, Optional, Tuple
import duckdb
import networkx as nx
import yaml

from .correlate import build_event_graph, get_threat_intel_lookup

MITRE_MAPPING_FILE = os.path.join(os.path.dirname(__file__), "mitre_mapping.yaml")


def load_mitre_mapping() -> Dict[str, Any]:
    if os.path.exists(MITRE_MAPPING_FILE):
        try:
            with open(MITRE_MAPPING_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("categories", {})
        except Exception as e:
            print(f"[Path] Error loading mitre_mapping.yaml: {e}")
    return {}


def map_category_to_mitre(category: str, mapping: Dict[str, Any]) -> Dict[str, Any]:
    """Map alert category string to MITRE tactic/technique metadata."""
    if category in mapping:
        return mapping[category]

    # Partial match fallback
    c_lower = category.lower()
    for cat_name, info in mapping.items():
        if cat_name.lower() in c_lower or c_lower in cat_name.lower():
            return info

    # Generic fallback
    if "login" in c_lower or "auth" in c_lower:
        return {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1078", "stage_index": 1}
    elif "priv" in c_lower or "elevat" in c_lower:
        return {"tactic_id": "TA0004", "tactic_name": "Privilege Escalation", "technique_id": "T1068", "stage_index": 2}
    elif "lateral" in c_lower or "rdp" in c_lower or "smb" in c_lower:
        return {"tactic_id": "TA0008", "tactic_name": "Lateral Movement", "technique_id": "T1021.001", "stage_index": 3}
    elif "file" in c_lower or "data" in c_lower or "access" in c_lower:
        return {"tactic_id": "TA0009", "tactic_name": "Data Access", "technique_id": "T1005", "stage_index": 4}
    elif "log" in c_lower or "evasion" in c_lower or "tamper" in c_lower or "clear" in c_lower:
        return {"tactic_id": "TA0005", "tactic_name": "Evidence Tampering", "technique_id": "T1070", "stage_index": 5}

    return {"tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1204", "stage_index": 2}


def cluster_candidate_incidents(
    con: duckdb.DuckDBPyConnection, cse_id: str
) -> List[Dict[str, Any]]:
    """
    Groups alerts for a CSE into candidate incidents using connected components
    and external attacker IP pivots.
    """
    ioc_lookup = get_threat_intel_lookup(con)
    G = build_event_graph(con, cse_id=cse_id)

    if G.number_of_nodes() == 0:
        return []

    # Build incident clustering graph excluding static user and asset bridge nodes
    # (Alert-to-alert sequence edges and attacker IP nodes represent true attack links)
    UG = G.to_undirected()
    non_incident_nodes = [
        n for n, d in G.nodes(data=True)
        if d.get("node_type") in ("user", "asset")
    ]
    UG.remove_nodes_from(non_incident_nodes)
    components = list(nx.connected_components(UG))

    candidate_incidents = []
    mitre_map = load_mitre_mapping()

    for idx, comp in enumerate(components):
        alert_nodes = [n for n in comp if n.startswith("alert:")]
        if not alert_nodes:
            continue

        # Extract alert records from DB
        aids = [n.replace("alert:", "") for n in alert_nodes]
        placeholders = ",".join(["?"] * len(aids))
        rows = con.execute(f"""
            SELECT alert_id, category, severity, created_at, closed_at,
                   source_ip, dest_ip, asset_id, analyst_id, mttr_seconds, closure_notes
            FROM alerts
            WHERE alert_id IN ({placeholders})
            ORDER BY created_at ASC
        """, aids).fetchall()

        cols = ["alert_id", "category", "severity", "created_at", "closed_at",
                "source_ip", "dest_ip", "asset_id", "analyst_id", "mttr_seconds", "closure_notes"]
        comp_alerts = [dict(zip(cols, r)) for r in rows]

        # Check for matched IOCs
        matched_iocs = []
        for a in comp_alerts:
            sip = a.get("source_ip")
            dip = a.get("dest_ip")
            if sip and sip in ioc_lookup and ioc_lookup[sip] not in matched_iocs:
                matched_iocs.append(ioc_lookup[sip])
            if dip and dip in ioc_lookup and ioc_lookup[dip] not in matched_iocs:
                matched_iocs.append(ioc_lookup[dip])

        # Distinct impacted assets
        impacted_assets = list({a["asset_id"] for a in comp_alerts if a.get("asset_id")})

        candidate_incidents.append({
            "incident_cluster_id": f"inc-{cse_id}-{idx+1}",
            "cse_id": cse_id,
            "alerts": comp_alerts,
            "matched_iocs": matched_iocs,
            "impacted_assets": impacted_assets,
            "alert_count": len(comp_alerts),
            "start_time": str(comp_alerts[0]["created_at"]),
            "end_time": str(comp_alerts[-1]["created_at"]),
        })

    # Sort candidates by matched IOC count then alert count descending
    candidate_incidents.sort(key=lambda x: (len(x["matched_iocs"]), x["alert_count"]), reverse=True)
    return candidate_incidents


def build_attack_path(
    candidate: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Reconstructs chronological multi-stage attack path from a candidate incident.
    Detects entry point, maps stages to MITRE tactics, flags lateral movement,
    and calculates per-stage and overall confidence.
    """
    alerts = candidate["alerts"]
    matched_iocs = candidate["matched_iocs"]
    mitre_map = load_mitre_mapping()

    # 1. Determine Initial Entry Point
    entry_point = "Unknown External Source"
    initial_alert = alerts[0]
    # Prioritize alert matching confirmed CTI IOC if present
    if matched_iocs:
        ioc_vals = {ioc.get("ioc_value") for ioc in matched_iocs if ioc.get("ioc_value")}
        for a in alerts:
            if a.get("source_ip") in ioc_vals:
                initial_alert = a
                break

    if initial_alert.get("source_ip"):
        entry_point = f"External IP {initial_alert['source_ip']}"
        if initial_alert.get("asset_id"):
            entry_point += f" -> Targeting {initial_alert['asset_id']}"
    elif initial_alert.get("asset_id"):
        entry_point = f"Host {initial_alert['asset_id']}"

    # 2. Stage Grouping & Mapping
    # Standard 5 stages definition
    stage_definitions = [
        {"stage_number": 1, "stage_name": "Initial Access", "tactic_id": "TA0001", "categories": ["Suspicious Login", "Unauthorized Ingress", "Brute Force"]},
        {"stage_number": 2, "stage_name": "Privilege Escalation", "tactic_id": "TA0004", "categories": ["Privilege Escalation", "Exploit"]},
        {"stage_number": 3, "stage_name": "Lateral Movement", "tactic_id": "TA0008", "categories": ["Lateral Movement", "RDP Tunnel", "Remote Execution"]},
        {"stage_number": 4, "stage_name": "Data Access", "tactic_id": "TA0009", "categories": ["File Access", "Sensitive File Access", "Collection", "Data Exfiltration"]},
        {"stage_number": 5, "stage_name": "Evidence Tampering", "tactic_id": "TA0005", "categories": ["Log Tampering", "Defense Evasion", "Log Deletion"]},
    ]

    stages = []
    seen_assets = set()
    lateral_movements = []

    for s_def in stage_definitions:
        s_num = s_def["stage_number"]
        s_name = s_def["stage_name"]
        tactic_id = s_def["tactic_id"]

        # Find alerts matching this stage
        stage_alerts = []
        for a in alerts:
            cat = a.get("category", "")
            mapped = map_category_to_mitre(cat, mitre_map)
            # Match either stage_index, tactic_name, or predefined categories
            if (mapped.get("stage_index") == s_num or
                mapped.get("tactic_name", "").lower() == s_name.lower() or
                any(c.lower() in cat.lower() for c in s_def["categories"])):
                stage_alerts.append(a)

        if not stage_alerts:
            # If S1 has all 5 stages, find closest matching alerts
            continue

        # Detect lateral movement transitions
        for a in stage_alerts:
            aid = a.get("asset_id")
            if aid and seen_assets and aid not in seen_assets:
                lateral_movements.append({
                    "from_assets": list(seen_assets),
                    "to_asset": aid,
                    "alert_id": a["alert_id"],
                    "timestamp": str(a["created_at"]),
                })
            if aid:
                seen_assets.add(aid)

        # Stage confidence calculation
        stage_sev_weights = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.70, "LOW": 0.50}
        avg_sev = sum(stage_sev_weights.get(a.get("severity", "MEDIUM"), 0.7) for a in stage_alerts) / len(stage_alerts)
        has_ioc = any(a.get("source_ip") in [ioc.get("ioc_value") for ioc in matched_iocs] for a in stage_alerts)
        stage_confidence = min(0.98, round(avg_sev * (1.15 if has_ioc else 1.0), 2))

        claims = []
        for a in stage_alerts:
            claims.append(f"{a['category']} on {a.get('asset_id', 'target host')} from {a.get('source_ip', 'internal')}")

        stages.append({
            "stage_number": s_num,
            "stage_name": s_name,
            "tactic": tactic_id,
            "technique": map_category_to_mitre(stage_alerts[0].get("category", ""), mitre_map).get("technique_id", "T1078"),
            "claim": f"{s_name} confirmed via {len(stage_alerts)} alert(s): {', '.join(claims[:2])}.",
            "evidence_ids": [a["alert_id"] for a in stage_alerts],
            "confidence": stage_confidence,
            "start_time": str(stage_alerts[0]["created_at"]),
            "end_time": str(stage_alerts[-1]["created_at"]),
            "attacker_intent": f"Execute {s_name} to advance adversary mission objectives.",
        })

    # Sort stages by stage_number to guarantee strict chronological attack chain
    stages.sort(key=lambda s: s["stage_number"])

    # Overall incident confidence calculation
    if stages:
        base_conf = sum(s["confidence"] for s in stages) / len(stages)
    else:
        base_conf = 0.5

    # Boosters for multi-stage attack and known CTI match
    if matched_iocs:
        base_conf += 0.10
    if len(stages) >= 4:
        base_conf += 0.08
    if len(candidate["impacted_assets"]) >= 2:
        base_conf += 0.05

    overall_confidence = min(0.99, round(base_conf, 2))

    return {
        "candidate_id": candidate["incident_cluster_id"],
        "cse_id": candidate["cse_id"],
        "entry_point": entry_point,
        "stages": stages,
        "stages_count": len(stages),
        "lateral_movements": lateral_movements,
        "impacted_assets": candidate["impacted_assets"],
        "matched_iocs": matched_iocs,
        "overall_confidence": overall_confidence,
    }
