"""
FLIX HOST - Lightweight scheduler
Runs periodic platform tasks without external broker.
Safe tasks only: expiration sweep is in plans.py; here we add metric prune + backup retention.
"""
import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path

from db import get_db, now_iso, get_setting, log_action, BACKUPS_DIR


async def prune_old_metrics():
    conn = get_db()
    # keep ~7 days of coarse data: delete older than 7d
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    try:
        conn.execute("DELETE FROM server_metrics WHERE recorded_at < ?", (cutoff,))
        conn.commit()
    except Exception:
        pass
    conn.close()


async def prune_old_backups():
    days = int(get_setting("backup_retention_days", "14") or "14")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn = get_db()
    rows = conn.execute(
        "SELECT id, path FROM backups WHERE created_at < ? AND status = 'ready'",
        (cutoff,),
    ).fetchall()
    for r in rows:
        try:
            if r["path"]:
                Path(r["path"]).unlink(missing_ok=True)
        except Exception:
            pass
        conn.execute("DELETE FROM backups WHERE id = ?", (r["id"],))
    if rows:
        log_action("system", "prune_backups", f"removed {len(rows)}")
    conn.commit()
    conn.close()


async def scheduler_loop():
    """Background loop — never crashes the app."""
    while True:
        try:
            await prune_old_metrics()
            await prune_old_backups()
        except Exception as e:
            print(f"[FLIX scheduler] {e}")
        await asyncio.sleep(3600)  # hourly
