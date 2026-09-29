"""
Traceback Correlation Graph Builder
Constructs a NetworkX multi-directed event graph linking alerts, cases, assets,
IPs, and users. Enriches nodes with threat intelligence IOC/CVE matches.
Provides React Flow format export for interactive UI visualization.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
import duckdb
import networkx as nx


def get_threat_intel_lookup(con: duckdb.DuckDBPyConnection) -> Dict[str, Dict[str, Any]]:
    """Fetches all known IOCs from DuckDB into a dictionary keyed by value."""
    lookup = {}
    try:
        rows = con.execute("""
            SELECT ioc_type, ioc_value, threat_actor, malware_family, description, confidence, mitre_tactics, mitre_techniques
            FROM threat_intel_iocs
        """).fetchall()
        cols = ["ioc_type", "ioc_value", "threat_actor", "malware_family", "description", "confidence", "mitre_tactics", "mitre_techniques"]
        for r in rows:
            d = dict(zip(cols, r))
            lookup[d["ioc_value"]] = d
    except Exception as e:
        print(f"[Correlate] Threat intel lookup notice: {e}")
    return lookup


def build_event_graph(
    con: duckdb.DuckDBPyConnection,
    cse_id: Optional[str] = None,
    alert_ids: Optional[List[str]] = None,
    time_window_hours: float = 12.0,
) -> nx.MultiDiGraph:
    """
    Builds a multi-directed correlation graph linking alerts, assets, IPs, and actors.
    Enriches with CTI IOC matches and chronological sequence links.
    """
    G = nx.MultiDiGraph()
    ioc_lookup = get_threat_intel_lookup(con)

    # 1. Fetch alerts
    query = """
        SELECT alert_id, cse_id, category, severity, created_at, closed_at,
               source_ip, dest_ip, asset_id, analyst_id, mttr_seconds, closure_notes
        FROM alerts
        WHERE 1=1
    """
    params = []
    if cse_id:
        query += " AND cse_id = ?"
        params.append(cse_id)
    if alert_ids:
        placeholders = ",".join(["?"] * len(alert_ids))
        query += f" AND alert_id IN ({placeholders})"
        params.extend(alert_ids)

    query += " ORDER BY created_at ASC"
    rows = con.execute(query, params).fetchall()
    cols = ["alert_id", "cse_id", "category", "severity", "created_at", "closed_at",
            "source_ip", "dest_ip", "asset_id", "analyst_id", "mttr_seconds", "closure_notes"]
    alerts = [dict(zip(cols, r)) for r in rows]

    if not alerts:
        return G

    # 2. Add nodes & entity links
    for a in alerts:
        aid = a["alert_id"]
        a_node = f"alert:{aid}"

        # Alert Node
        G.add_node(
            a_node,
            node_type="alert",
            id=aid,
            label=f"{a['category']} ({aid})",
            category=a["category"],
            severity=a["severity"],
            timestamp=str(a["created_at"]),
            cse_id=a["cse_id"],
            source_ip=a.get("source_ip"),
            dest_ip=a.get("dest_ip"),
            asset_id=a.get("asset_id"),
        )

        # Source IP Node
        sip = a.get("source_ip")
        if sip and sip.strip():
            ip_node = f"ip:{sip}"
            is_ioc = sip in ioc_lookup
            ioc_info = ioc_lookup.get(sip, {})
            if not G.has_node(ip_node):
                G.add_node(
                    ip_node,
                    node_type="ip",
                    id=sip,
                    label=f"IP: {sip}" + (" [CTI MATCH]" if is_ioc else ""),
                    is_ioc=is_ioc,
                    threat_actor=ioc_info.get("threat_actor"),
                    malware_family=ioc_info.get("malware_family"),
                    confidence=ioc_info.get("confidence", 0.0),
                )
            G.add_edge(ip_node, a_node, rel="inbound_traffic", label="origins from")

        # Dest IP Node
        dip = a.get("dest_ip")
        if dip and dip.strip():
            dip_node = f"ip:{dip}"
            is_ioc = dip in ioc_lookup
            ioc_info = ioc_lookup.get(dip, {})
            if not G.has_node(dip_node):
                G.add_node(
                    dip_node,
                    node_type="ip",
                    id=dip,
                    label=f"IP: {dip}",
                    is_ioc=is_ioc,
                    threat_actor=ioc_info.get("threat_actor"),
                )
            G.add_edge(a_node, dip_node, rel="outbound_traffic", label="targets IP")

        # Asset Node
        asset = a.get("asset_id")
        if asset and asset.strip():
            asset_node = f"asset:{asset}"
            if not G.has_node(asset_node):
                G.add_node(
                    asset_node,
                    node_type="asset",
                    id=asset,
                    label=f"Host: {asset}",
                )
            G.add_edge(a_node, asset_node, rel="impacts_asset", label="impacts host")

        # User Node
        analyst = a.get("analyst_id")
        if analyst and analyst.strip():
            user_node = f"user:{analyst}"
            if not G.has_node(user_node):
                G.add_node(
                    user_node,
                    node_type="user",
                    id=analyst,
                    label=f"User/Analyst: {analyst}",
                )
            G.add_edge(a_node, user_node, rel="handled_by", label="triaged by")

    # 3. Add chronological sequence edges between correlated alerts
    # If two alerts share source IP or asset within time_window_hours
    n = len(alerts)
    for i in range(n):
        for j in range(i + 1, n):
            a1 = alerts[i]
            a2 = alerts[j]

            # Check shared context
            same_source_ip = a1.get("source_ip") and a1.get("source_ip") == a2.get("source_ip")
            same_asset = a1.get("asset_id") and a1.get("asset_id") == a2.get("asset_id")
            pivot_asset = (a1.get("dest_ip") and a2.get("source_ip") and a1.get("dest_ip") == a2.get("source_ip"))

            if same_source_ip or same_asset or pivot_asset:
                t1 = datetime.fromisoformat(str(a1["created_at"]).replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(str(a2["created_at"]).replace("Z", "+00:00"))
                diff_sec = (t2 - t1).total_seconds()
                if 0 <= diff_sec <= (time_window_hours * 3600):
                    reason = "attacker pivot" if same_source_ip else "co-located host"
                    G.add_edge(
                        f"alert:{a1['alert_id']}",
                        f"alert:{a2['alert_id']}",
                        rel="sequence",
                        label=f"{reason} (+{int(diff_sec/60)}m)",
                        diff_sec=diff_sec,
                    )

    return G


def graph_to_react_flow(G: nx.MultiDiGraph) -> Dict[str, Any]:
    """
    Serializes NetworkX graph to React Flow format:
    { "nodes": [ { id, type, data, position } ], "edges": [ { id, source, target, label, animated } ] }
    """
    nodes = []
    edges = []

    # Position calculation using a clean tiered horizontal / vertical layout
    pos_x = 50
    pos_y = 50
    stage_counters: Dict[str, int] = {}

    for idx, (node_id, data) in enumerate(G.nodes(data=True)):
        ntype = data.get("node_type", "default")
        col = 0
        if ntype == "ip" and data.get("is_ioc"):
            col = 50
        elif ntype == "ip":
            col = 150
        elif ntype == "alert":
            col = 400
        elif ntype == "asset":
            col = 750
        else:
            col = 950

        row = stage_counters.get(ntype, 0)
        stage_counters[ntype] = row + 1

        x = col
        y = 50 + (row * 90)

        # Style colors
        bg = "#1e293b"
        border = "#475569"
        if data.get("is_ioc"):
            bg = "#450a0a"
            border = "#ef4444"
        elif ntype == "alert":
            sev = data.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                border = "#ef4444"
            elif sev == "HIGH":
                border = "#f97316"
            elif sev == "MEDIUM":
                border = "#eab308"
        elif ntype == "asset":
            border = "#3b82f6"

        nodes.append({
            "id": node_id,
            "type": "default",
            "position": {"x": x, "y": y},
            "data": {
                "label": data.get("label", node_id),
                "node_type": ntype,
                "severity": data.get("severity"),
                "is_ioc": data.get("is_ioc", False),
                "category": data.get("category"),
                "threat_actor": data.get("threat_actor"),
                "timestamp": data.get("timestamp"),
            },
            "style": {
                "background": bg,
                "color": "#f8fafc",
                "border": f"1px solid {border}",
                "borderRadius": "8px",
                "padding": "10px",
                "fontSize": "11px",
                "width": 180,
            }
        })

    edge_count = 0
    for u, v, k, edata in G.edges(data=True, keys=True):
        edge_count += 1
        rel = edata.get("rel", "")
        animated = (rel == "sequence") or ("inbound" in rel)
        edges.append({
            "id": f"e-{u}-{v}-{k}",
            "source": u,
            "target": v,
            "label": edata.get("label", ""),
            "animated": animated,
            "style": {
                "stroke": "#ef4444" if "inbound" in rel else "#3b82f6" if rel == "sequence" else "#64748b",
                "strokeWidth": 2 if rel == "sequence" else 1,
            },
        })

    return {"nodes": nodes, "edges": edges}
