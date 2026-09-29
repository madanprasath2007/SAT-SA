"""
Authentication Router (Phase 5)
Provides JWT login, current user verification, demo user discovery, and rapid role switching.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
import duckdb

from database import get_connection
from auth import (
    create_access_token,
    verify_password,
    get_current_user,
    hash_password,
)
from audit import log_audit, get_audit_logs

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class SwitchRoleRequest(BaseModel):
    role: str


@router.post("/login")
def login(req: LoginRequest, request: Request):
    con = get_connection()
    try:
        row = con.execute("""
            SELECT user_id, username, email, password_hash, role, full_name
            FROM users
            WHERE username = ? OR email = ?
        """, [req.username.strip(), req.username.strip()]).fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
            )

        user_id, username, email, pwd_hash, role, full_name = row
        if not verify_password(req.password, pwd_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
            )

        user_dict = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "full_name": full_name,
        }

        token = create_access_token(data={"sub": user_id, **user_dict})

        # Record audit log
        client_ip = request.client.host if request.client else "127.0.0.1"
        log_audit(
            con,
            action="USER_LOGIN",
            user=user_dict,
            target_entity=user_id,
            details={"email": email, "role": role},
            ip_address=client_ip,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user_dict,
        }
    finally:
        con.close()


@router.get("/me")
def get_me(user: Dict[str, Any] = Depends(get_current_user)):
    return {"user": user}


@router.get("/users")
def list_demo_users():
    con = get_connection()
    try:
        rows = con.execute("""
            SELECT user_id, username, email, role, full_name, created_at
            FROM users
            ORDER BY role ASC, username ASC
        """).fetchall()

        users = []
        for r in rows:
            users.append({
                "user_id": r[0],
                "username": r[1],
                "email": r[2],
                "role": r[3],
                "full_name": r[4],
                "created_at": str(r[5]),
            })
        return {"users": users}
    finally:
        con.close()


@router.post("/switch-role")
def switch_role(req: SwitchRoleRequest, request: Request):
    """
    Convenience method for evaluation & testing:
    Directly returns a signed JWT for the requested role (Admin, Supervisor, or Analyst).
    """
    valid_roles = ["Admin", "Supervisor", "Analyst"]
    target_role = req.role.strip()
    if target_role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role must be one of {valid_roles}.",
        )

    con = get_connection()
    try:
        row = con.execute("""
            SELECT user_id, username, email, role, full_name
            FROM users
            WHERE role = ?
            LIMIT 1
        """, [target_role]).fetchone()

        if row:
            user_id, username, email, role, full_name = row
        else:
            user_id = f"usr-{target_role.lower()}-demo"
            username = target_role.lower()
            email = f"{username}@satsa.gov.in"
            role = target_role
            full_name = f"Demo {target_role}"

        user_dict = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "full_name": full_name,
        }
        token = create_access_token(data={"sub": user_id, **user_dict})

        client_ip = request.client.host if request.client else "127.0.0.1"
        log_audit(
            con,
            action="ROLE_SWITCH",
            user=user_dict,
            target_entity=user_id,
            details={"switched_to_role": role},
            ip_address=client_ip,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user_dict,
        }
    finally:
        con.close()


@router.get("/audit")
def list_audit_trail(
    limit: int = 100,
    offset: int = 0,
    action: Optional[str] = None,
    role: Optional[str] = None,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieves immutable audit trail entries."""
    con = get_connection()
    try:
        res = get_audit_logs(con, limit=limit, offset=offset, action=action, role=role)
        return res
    finally:
        con.close()

