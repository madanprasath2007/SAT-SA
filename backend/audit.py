"""
Audit Logging System (Phase 5)
Provides immutable, tamper-evident recording of supervisory activities:
- Data ingestion batches
- Analytics engine executions
- Threat intelligence imports
- Human reviewer decisions
- Rule modifications and threshold tuning
- PDF/CSV report exports
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import uuid
import duckdb


def log_audit(
    con: duckdb.DuckDBPyConnection,
    action: str,
    user: Dict[str, Any],
    target_entity: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = "127.0.0.1",
) -> str:
    """Records an audit log entry in DuckDB."""
    log_id = f"aud-{uuid.uuid4().hex[:12]}"
    user_id = user.get("user_id", "system")
    username = user.get("username", "system")
    role = user.get("role", "System")
    details_str = json.dumps(details or {})

    try:
        con.execute("""
            INSERT INTO audit_logs (log_id, action, user_id, username, role, target_entity, details_json, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [log_id, action, user_id, username, role, target_entity, details_str, ip_address, datetime.utcnow()])
    except Exception as e:
        print(f"[Audit] Warning: Failed to record audit log: {e}")

    return log_id


def get_audit_logs(
    con: duckdb.DuckDBPyConnection,
    limit: int = 100,
    offset: int = 0,
    action: Optional[str] = None,
    role: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves paginated audit log entries."""
    query = "SELECT log_id, action, user_id, username, role, target_entity, details_json, ip_address, timestamp FROM audit_logs WHERE 1=1"
    params = []
    if action:
        query += " AND action = ?"
        params.append(action)
    if role:
        query += " AND role = ?"
        params.append(role)

    count_q = f"SELECT COUNT(*) FROM ({query}) sub"
    total = con.execute(count_q, params).fetchone()[0]

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = con.execute(query, params).fetchall()
    cols = ["log_id", "action", "user_id", "username", "role", "target_entity", "details", "ip_address", "timestamp"]
    data = []
    for r in rows:
        d = dict(zip(cols, r))
        d["timestamp"] = str(d["timestamp"])
        if d.get("details"):
            try:
                d["details"] = json.loads(d["details"])
            except Exception:
                pass
        data.append(d)

    return {"data": data, "total": total, "limit": limit, "offset": offset}
