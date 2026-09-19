"""
NEXUS PRO - Plans Engine
Free / Paid / VIP limits live in the database (plans table), never hardcoded
across the codebase. This module is the single place that checks limits
and runs expiration sweeps.
"""
import asyncio
from datetime import datetime, timezone

from db import get_db, now_iso, log_action
from process_manager import stop_server_process, get_directory_size_mb
from db import server_path


def get_plan(plan_id: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_plans() -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM plans ORDER BY price_cents ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def check_can_create_server(user: dict) -> tuple[bool, str]:
    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) c FROM servers WHERE user_id = ? AND status != 'expired'", (user["id"],)
    ).fetchone()["c"]
    conn.close()
    if count >= user["server_limit"]:
        return False, (
            f"Your {user['plan_name']} plan allows up to {user['server_limit']} server(s). "
            f"Upgrade your plan to create more."
        )
    return True, ""


def check_storage_limit(user: dict, sid: int) -> tuple[bool, str]:
    used = get_directory_size_mb(server_path(sid))
    if used > user["storage_mb"]:
        return False, f"Storage limit exceeded ({used}MB / {user['storage_mb']}MB on your {user['plan_name']} plan)."
    return True, ""


async def expiration_sweep():
    """Runs periodically: expires users/servers whose plan or server lifetime ended."""
    while True:
        conn = get_db()
        now = datetime.now(timezone.utc)
        expired_users = conn.execute(
            "SELECT id, username, plan_expires_at FROM users WHERE plan_expires_at IS NOT NULL"
        ).fetchall()
        for u in expired_users:
            exp = datetime.fromisoformat(u["plan_expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= now:
                servers = conn.execute(
                    "SELECT id FROM servers WHERE user_id = ? AND status NOT IN ('stopped','expired')",
                    (u["id"],),
                ).fetchall()
                for s in servers:
                    await stop_server_process(s["id"])
                    conn.execute("UPDATE servers SET status = 'expired' WHERE id = ?", (s["id"],))
                log_action("system", "plan_expired", u["username"])
        conn.commit()
        conn.close()
        await asyncio.sleep(300)  # check every 5 minutes
