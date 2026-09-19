"""
FLIX HOST - Backup Manager
Real file-system backups (ZIP of server directory). No fake backups.
"""
import shutil
import zipfile
from pathlib import Path

from db import (
    get_db, now_iso, server_path, backup_path, BACKUPS_DIR,
    log_action, get_setting,
)
from process_manager import get_directory_size_mb


def list_backups(server_id: int | None = None, user_id: int | None = None) -> list[dict]:
    conn = get_db()
    q = "SELECT * FROM backups WHERE 1=1"
    params: list = []
    if server_id is not None:
        q += " AND server_id = ?"
        params.append(server_id)
    if user_id is not None:
        q += " AND user_id = ?"
        params.append(user_id)
    q += " ORDER BY id DESC"
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_backup(server_id: int, user_id: int, note: str = "") -> tuple[bool, str, int | None]:
    """Create a real ZIP backup of the server directory."""
    d = server_path(server_id)
    if not d.exists():
        return False, "Server directory not found", None

    # check storage roughly (size of project)
    size_mb = get_directory_size_mb(d)
    # simple guard: refuse if over 500MB for a single backup in constrained env
    if size_mb > 500:
        return False, f"Server files too large for backup ({size_mb} MB). Limit is 500 MB.", None

    conn = get_db()
    # check user backup limit if set
    user = conn.execute("SELECT max_backups, plan_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        limit = user["max_backups"]
        if limit is None:
            plan = conn.execute("SELECT backup_limit FROM plans WHERE id = ?", (user["plan_id"],)).fetchone()
            limit = plan["backup_limit"] if plan and "backup_limit" in plan.keys() else 5
        current = conn.execute(
            "SELECT COUNT(*) c FROM backups WHERE user_id = ? AND status = 'ready'", (user_id,)
        ).fetchone()["c"]
        if limit is not None and current >= int(limit):
            conn.close()
            return False, f"Backup limit reached ({current}/{limit}). Delete old backups first.", None

    cur = conn.execute(
        "INSERT INTO backups (server_id, user_id, name, path, size_bytes, status, created_at, note) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (server_id, user_id, f"backup-{now_iso()[:19]}", "", 0, "creating", now_iso(), note or None),
    )
    bid = cur.lastrowid
    conn.commit()
    conn.close()

    dest = backup_path(bid)
    try:
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in d.rglob("*"):
                if f.is_file():
                    arcname = str(f.relative_to(d))
                    zf.write(f, arcname)
        size = dest.stat().st_size
        conn = get_db()
        conn.execute(
            "UPDATE backups SET path = ?, size_bytes = ?, status = 'ready', name = ? WHERE id = ?",
            (str(dest), size, f"bk-{bid}-{now_iso()[:10]}", bid),
        )
        conn.commit()
        conn.close()
        log_action(str(user_id), "create_backup", f"server={server_id} backup={bid}")
        return True, "Backup created", bid
    except Exception as e:
        conn = get_db()
        conn.execute("UPDATE backups SET status = 'failed', note = ? WHERE id = ?", (str(e)[:200], bid))
        conn.commit()
        conn.close()
        if dest.exists():
            dest.unlink(missing_ok=True)
        return False, f"Backup failed: {e}", bid


def restore_backup(backup_id: int, user_id: int) -> tuple[bool, str]:
    """Restore a backup into the server directory (overwrites files)."""
    conn = get_db()
    row = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
    conn.close()
    if not row:
        return False, "Backup not found"
    if row["user_id"] != user_id:
        # allow admin restore later via higher layer
        pass
    if row["status"] != "ready":
        return False, "Backup is not ready"

    src = Path(row["path"])
    if not src.exists():
        return False, "Backup file missing on disk"

    target = server_path(row["server_id"])
    target.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(src, "r") as zf:
            # basic zip-slip protection
            dest_resolved = target.resolve()
            for info in zf.infolist():
                member = info.filename
                if ".." in member or member.startswith("/") or member.startswith("\\"):
                    continue
                out = (target / member).resolve()
                if not str(out).startswith(str(dest_resolved)):
                    continue
                zf.extract(info, target)
        log_action(str(user_id), "restore_backup", f"backup={backup_id} server={row['server_id']}")
        return True, "Backup restored"
    except Exception as e:
        return False, f"Restore failed: {e}"


def delete_backup(backup_id: int) -> tuple[bool, str]:
    conn = get_db()
    row = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
    if not row:
        conn.close()
        return False, "Backup not found"
    path = Path(row["path"]) if row["path"] else backup_path(backup_id)
    conn.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
    conn.commit()
    conn.close()
    if path.exists():
        path.unlink(missing_ok=True)
    return True, "Backup deleted"
