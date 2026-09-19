"""
FLIX HOST - Deployment Manager
Real deploy cycle: mark version -> install deps -> start -> log stages.
No fake pipeline stages.
"""
import asyncio
from db import get_db, now_iso, log_action, server_path
from process_manager import stop_server_process, start_server_process, install_dependencies, _log, _set_status


def list_deployments(server_id: int | None = None, limit: int = 50) -> list[dict]:
    conn = get_db()
    if server_id:
        rows = conn.execute(
            "SELECT * FROM deployments WHERE server_id = ? ORDER BY id DESC LIMIT ?",
            (server_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM deployments ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _next_version(server_id: int) -> int:
    conn = get_db()
    row = conn.execute(
        "SELECT MAX(version) m FROM deployments WHERE server_id = ?", (server_id,)
    ).fetchone()
    conn.close()
    return int(row["m"] or 0) + 1


async def run_deploy(server_id: int, user_id: int, source: str = "manual", message: str = "") -> tuple[bool, str, int]:
    conn = get_db()
    srv = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not srv:
        conn.close()
        return False, "Server not found", 0
    version = _next_version(server_id)
    cur = conn.execute(
        "INSERT INTO deployments (server_id, user_id, version, status, source, message, started_at, log_text) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (server_id, user_id, version, "running", source, message or "", now_iso(), ""),
    )
    dep_id = cur.lastrowid
    conn.commit()
    conn.close()

    def append_log(line: str):
        _log(server_id, f"[DEPLOY v{version}] {line}")
        c = get_db()
        row = c.execute("SELECT log_text FROM deployments WHERE id = ?", (dep_id,)).fetchone()
        text = (row["log_text"] if row else "") + line + "\n"
        c.execute("UPDATE deployments SET log_text = ? WHERE id = ?", (text, dep_id))
        c.commit()
        c.close()

    try:
        append_log("Stopping current process if any...")
        await stop_server_process(server_id)

        d = server_path(server_id)
        d.mkdir(parents=True, exist_ok=True)
        runtime = srv["runtime"]

        append_log(f"Installing dependencies ({runtime})...")
        ok = await install_dependencies(server_id, d, runtime)
        if not ok:
            c = get_db()
            c.execute(
                "UPDATE deployments SET status = 'failed', finished_at = ?, message = ? WHERE id = ?",
                (now_iso(), "dependency install failed", dep_id),
            )
            c.commit()
            c.close()
            return False, "Dependency installation failed", dep_id

        append_log("Starting application...")
        ok, msg = await start_server_process(server_id)
        status = "success" if ok else "failed"
        append_log(msg)
        c = get_db()
        c.execute(
            "UPDATE deployments SET status = ?, finished_at = ?, message = ? WHERE id = ?",
            (status, now_iso(), msg, dep_id),
        )
        c.commit()
        c.close()
        log_action(str(user_id), "deploy", f"server={server_id} v{version}", "ok" if ok else "failed")
        return ok, msg, dep_id
    except Exception as e:
        c = get_db()
        c.execute(
            "UPDATE deployments SET status = 'failed', finished_at = ?, message = ? WHERE id = ?",
            (now_iso(), str(e)[:300], dep_id),
        )
        c.commit()
        c.close()
        append_log(f"Error: {e}")
        return False, str(e), dep_id
