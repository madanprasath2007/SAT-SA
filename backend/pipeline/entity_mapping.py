"""
Stage 4 — Entity Mapping
Extracts and links users/systems/IPs across CSEs into the entities table.
An entity is identified by (entity_type, identifier, cse_id).
This runs after normalization so timestamps are already ISO-8601 UTC.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import duckdb
import pandas as pd


def _entity_id(entity_type: str, identifier: str, cse_id: str) -> str:
    """Stable deterministic ID for an entity."""
    key = f"{entity_type}|{identifier.lower().strip()}|{cse_id}"
    return "ENT-" + hashlib.sha1(key.encode()).hexdigest()[:16].upper()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def map_entities(
    df: pd.DataFrame,
    data_type: str,
    cse_id: str,
    con: duckdb.DuckDBPyConnection,
):
    """
    Extract entity records from df and upsert into the entities table.
    Handles: alerts (analyst_id=user, source_ip=ip, asset_id=system),
             assets (asset_id=system, hostname=system, ip_address=ip),
             cases / investigations (analyst_id=user).
    """
    now = _now_iso()
    entities: dict[str, dict[str, Any]] = {}

    def _add(entity_type: str, identifier: str, linked_asset: str = ""):
        if not identifier or identifier.strip() in ("", "nan", "None"):
            return
        eid = _entity_id(entity_type, identifier, cse_id)
        if eid not in entities:
            entities[eid] = {
                "entity_id":       eid,
                "entity_type":     entity_type,
                "identifier":      identifier.strip(),
                "cse_id":          cse_id,
                "first_seen":      now,
                "last_seen":       now,
                "linked_asset_ids": linked_asset,
            }
        else:
            entities[eid]["last_seen"] = now
            if linked_asset and linked_asset not in entities[eid]["linked_asset_ids"]:
                entities[eid]["linked_asset_ids"] += f",{linked_asset}"

    if data_type == "alerts":
        for _, row in df.iterrows():
            _add("user",   str(row.get("analyst_id", "")))
            _add("ip",     str(row.get("source_ip", "")),  str(row.get("asset_id", "")))
            _add("ip",     str(row.get("dest_ip", "")))
            _add("system", str(row.get("asset_id", "")))

    elif data_type == "assets":
        for _, row in df.iterrows():
            _add("system", str(row.get("asset_id", "")))
            if row.get("hostname"):
                _add("system", str(row.get("hostname", "")))
            if row.get("ip_address"):
                _add("ip", str(row.get("ip_address", "")), str(row.get("asset_id", "")))

    elif data_type in ("cases", "investigations"):
        for _, row in df.iterrows():
            _add("user", str(row.get("analyst_id", "")))

    elif data_type == "escalations":
        for _, row in df.iterrows():
            _add("user", str(row.get("escalated_by", "")))
            _add("user", str(row.get("escalated_to", "")))

    # Upsert into DB
    for ent in entities.values():
        con.execute("""
            INSERT INTO entities
                (entity_id, entity_type, identifier, cse_id, first_seen, last_seen, linked_asset_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (entity_id) DO UPDATE SET
                last_seen       = excluded.last_seen,
                linked_asset_ids = excluded.linked_asset_ids
        """, [
            ent["entity_id"], ent["entity_type"], ent["identifier"], ent["cse_id"],
            ent["first_seen"], ent["last_seen"], ent["linked_asset_ids"],
        ])
