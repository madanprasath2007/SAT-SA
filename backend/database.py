"""
database.py — thin shim that imports from models.py for backward compatibility.
All schema and init logic is in models.py (Phase 1).
"""

from models import get_connection, init_db, seed_cses  # noqa: F401

__all__ = ["get_connection", "init_db", "seed_cses"]
