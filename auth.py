"""
FLIX HOST - Authentication & RBAC
"""
from datetime import datetime, timezone
from fastapi import Request, HTTPException
import bcrypt

from db import get_db

# Role -> permission set. "owner" always has everything implicitly.
ROLE_PERMISSIONS = {
    "owner": {"*"},
    "admin": {
        "manage_users", "manage_servers", "manage_plans", "manage_domains",
        "manage_settings", "manage_logs", "manage_bot", "manage_system",
        "manage_backups",
    },
    "moderator": {"manage_users", "manage_servers", "manage_logs"},
    "support": {"manage_logs"},
    "user": set(),
}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def has_permission(role: str, perm: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role, set())
    return "*" in perms or perm in perms


def get_current_user(request: Request) -> dict:
    uid = request.session.get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Authentication required")
    conn = get_db()
    row = conn.execute(
        "SELECT u.*, p.name as plan_name, p.server_limit, p.ram_mb, p.cpu_percent, p.storage_mb, p.features "
        "FROM users u JOIN plans p ON u.plan_id = p.id WHERE u.id = ?",
        (uid,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = dict(row)
    if not user["enabled"]:
        raise HTTPException(status_code=403, detail="Account disabled")
    if user.get("banned"):
        raise HTTPException(status_code=403, detail="Account banned")
    if user["plan_expires_at"]:
        exp = datetime.fromisoformat(user["plan_expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Plan expired")
    force_at = user.get("force_logout_at")
    if force_at:
        session_started = request.session.get("login_at")
        if session_started and session_started < force_at:
            request.session.clear()
            raise HTTPException(status_code=401, detail="Session revoked")
    return user


def require_permission(perm: str):
    def dep(request: Request) -> dict:
        user = get_current_user(request)
        if not has_permission(user["role"], perm):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dep


def require_admin(request: Request) -> dict:
    user = get_current_user(request)
    if user["role"] not in ("owner", "admin", "moderator", "support"):
        raise HTTPException(status_code=403, detail="Admin only")
    return user
