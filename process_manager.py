"""
NEXUS PRO - Hosting Engine
Real process lifecycle: port allocation, dependency installation,
start/stop/restart, crash detection + optional auto-restart,
and live resource usage via psutil (no fake numbers).

SECURITY NOTE: user-uploaded code is treated as untrusted. Every launched
process gets a stripped-down environment (host secrets like NEXUS_SECRET,
NEXUS_ADMIN_PASSWORD, NEXUS_BOT_API_KEY, BOT_TOKEN are NEVER passed through),
its own working directory, and OS-level resource limits (memory / open files
/ process count) sized from the owner's plan. This is defense-in-depth on a
shared host - it is NOT equivalent to container isolation. See README.md.
"""
import asyncio
import os
import resource
import signal
import socket
from pathlib import Path

import psutil

from db import get_db, now_iso, server_path, get_setting
try:
    from alerts import alert_server_event
except Exception:
    alert_server_event = None

PROCS: dict[int, asyncio.subprocess.Process] = {}
LOGS: dict[int, list[str]] = {}
STARTING: set[int] = set()
MAX_LOG_LINES = 1000

# Only these host env vars are ever visible to user-uploaded code. Secrets
# (NEXUS_SECRET, NEXUS_ADMIN_PASSWORD, NEXUS_BOT_API_KEY, BOT_TOKEN, DB paths)
# are deliberately excluded - user code never gets the platform's own env.
SAFE_ENV_ALLOWLIST = ["PATH", "LANG", "LC_ALL", "HOME", "TMPDIR", "TZ"]


def _build_child_env(user_env_vars: dict, port: int) -> dict:
    env = {k: os.environ[k] for k in SAFE_ENV_ALLOWLIST if k in os.environ}
    env.update({str(k): str(v) for k, v in user_env_vars.items()})
    env["PORT"] = str(port)
    return env


def _make_preexec_fn(ram_mb: int):
    """Runs in the forked child, before exec: applies OS-level resource caps.
    Best-effort - some limits may be refused depending on host permissions,
    in which case they're silently skipped rather than failing the launch."""
    mem_bytes = max(int(ram_mb), 64) * 1024 * 1024

    def _limit():
        for res, val in (
            (resource.RLIMIT_AS, mem_bytes),
            (resource.RLIMIT_NOFILE, 256),
            (resource.RLIMIT_NPROC, 64),
        ):
            try:
                resource.setrlimit(res, (val, val))
            except (ValueError, OSError):
                pass
    return _limit


def _owner_plan_limits(sid: int) -> dict:
    conn = get_db()
    row = conn.execute(
        "SELECT p.ram_mb, p.cpu_percent FROM servers s "
        "JOIN users u ON s.user_id = u.id JOIN plans p ON u.plan_id = p.id WHERE s.id = ?",
        (sid,),
    ).fetchone()
    conn.close()
    return {"ram_mb": row["ram_mb"], "cpu_percent": row["cpu_percent"]} if row else {"ram_mb": 256, "cpu_percent": 25}


def _log(sid: int, text: str):
    log = LOGS.setdefault(sid, [])
    log.append(text)
    if len(log) > MAX_LOG_LINES:
        del log[: -MAX_LOG_LINES]


# ---------------------------------------------------------------------------
# Port manager - avoids collisions by checking DB allocations + OS-level bind
# ---------------------------------------------------------------------------
def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def allocate_port(sid: int) -> int:
    conn = get_db()
    start = int(get_setting("port_range_start", "20000"))
    end = int(get_setting("port_range_end", "29000"))
    used = {r["port"] for r in conn.execute("SELECT port FROM ports").fetchall()}
    port = None
    for candidate in range(start, end):
        if candidate in used:
            continue
        if _port_is_free(candidate):
            port = candidate
            break
    conn.close()
    if port is None:
        raise RuntimeError("No available ports in configured range")
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO ports (port, server_id) VALUES (?, ?)", (port, sid))
    conn.execute("UPDATE servers SET port = ? WHERE id = ?", (port, sid))
    conn.commit()
    conn.close()
    return port


def release_port(sid: int):
    conn = get_db()
    conn.execute("DELETE FROM ports WHERE server_id = ?", (sid,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Dependency installation - real, detected from the uploaded project files
# ---------------------------------------------------------------------------
async def install_dependencies(sid: int, d: Path, runtime: str):
    safe_env = _build_child_env({}, 0)
    limits = _owner_plan_limits(sid)
    if runtime == "python" and (d / "requirements.txt").exists():
        _set_status(sid, "installing")
        _log(sid, "[NEXUS] جاري تثبيت المكتبات من requirements.txt ...")
        proc = await asyncio.create_subprocess_exec(
            "pip", "install", "--no-cache-dir", "-r", "requirements.txt",
            cwd=str(d), env=safe_env, preexec_fn=_make_preexec_fn(limits["ram_mb"]),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        out = await proc.stdout.read()
        for line in out.decode(errors="replace").splitlines():
            _log(sid, line)
        await proc.wait()
        if proc.returncode != 0:
            _log(sid, f"[NEXUS] فشل تثبيت المكتبات (exit {proc.returncode}) - راجع الرسائل أعلاه لمعرفة أي مكتبة ناقصة أو غير متوفرة")
            _set_status(sid, "failed")
            return False
        _log(sid, "[NEXUS] تم تثبيت كل المكتبات بنجاح ✓")
    elif runtime == "node" and (d / "package.json").exists():
        _set_status(sid, "installing")
        _log(sid, "[NEXUS] جاري تثبيت المكتبات من package.json (npm install) ...")
        proc = await asyncio.create_subprocess_exec(
            "npm", "install", cwd=str(d), env=safe_env, preexec_fn=_make_preexec_fn(limits["ram_mb"]),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        out = await proc.stdout.read()
        for line in out.decode(errors="replace").splitlines():
            _log(sid, line)
        await proc.wait()
        if proc.returncode != 0:
            _log(sid, f"[NEXUS] فشل npm install (exit {proc.returncode}) - راجع الرسائل أعلاه لمعرفة أي مكتبة ناقصة")
            _set_status(sid, "failed")
            return False
        _log(sid, "[NEXUS] تم تثبيت كل المكتبات بنجاح ✓")
    return True


def _set_status(sid: int, status: str):
    conn = get_db()
    conn.execute("UPDATE servers SET status = ? WHERE id = ?", (status, sid))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Process lifecycle
# ---------------------------------------------------------------------------
Nexus_SUCCESS_BANNER = r"""
  ______ _      _______   __  _    _  ____   _____ _______
 |  ____| |    |_   _\ \ / / | |  | |/ __ \ / ____|__   __|
 | |__  | |      | |  \ V /  | |__| | |  | | (___    | |
 |  __| | |      | |   > <   |  __  | |  | |\___ \   | |
 | |    | |____ _| |_ / . \  | |  | | |__| |____) |  | |
 |_|    |______|_____/_/ \_\ |_|  |_|\____/|_____/   |_|

  SERVER IS RUNNING SUCCESSFULLY
""".strip("\n")


async def _watch_startup_success(sid: int, proc: asyncio.subprocess.Process):
    """After a short grace period, if the process is still alive (didn't
    crash immediately on a missing import / syntax error / etc.), print a
    clear big success banner so it's obvious at a glance the app is healthy."""
    await asyncio.sleep(2.5)
    if proc.returncode is None and sid in PROCS:
        for line in Nexus_SUCCESS_BANNER.splitlines():
            _log(sid, line)


async def _pump_and_watch(sid: int, proc: asyncio.subprocess.Process):
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            _log(sid, line.decode(errors="replace").rstrip())
    finally:
        code = await proc.wait()
        PROCS.pop(sid, None)
        conn = get_db()
        srv = conn.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        if srv:
            if code != 0 and srv["status"] not in ("stopping", "stopped", "suspended", "expired"):
                attempts = int(srv["restart_attempts"] or 0) + 1
                max_attempts = int(get_setting("max_restart_attempts", "5"))
                cooldown = int(get_setting("restart_cooldown_seconds", "60"))
                delay = int(srv["restart_delay"] or 3)

                conn.execute(
                    "UPDATE servers SET status = 'crashed', last_crash_at = ?, last_error = ?, "
                    "restart_attempts = ? WHERE id = ?",
                    (now_iso(), f"exit code {code}", attempts, sid),
                )
                _log(sid, f"[Nexus] process exited with code {code} - marked as crashed (attempt {attempts}/{max_attempts})")
                if alert_server_event:
                    try:
                        alert_server_event(sid, "Server Crashed", f"Exit code {code} (attempt {attempts}/{max_attempts})", "error")
                    except Exception:
                        pass

                if srv["auto_restart"] and attempts <= max_attempts:
                    _log(sid, f"[Nexus] auto-restart enabled, waiting {delay}s before restart...")
                    conn.commit()
                    conn.close()
                    await asyncio.sleep(max(delay, 1))
                    # simple cooldown check against last crash
                    await start_server_process(sid)
                    return
                elif attempts > max_attempts:
                    _log(sid, f"[Nexus] max restart attempts ({max_attempts}) reached - auto-restart disabled for this cycle")
                    conn.execute("UPDATE servers SET auto_restart = 0 WHERE id = ?", (sid,))
            else:
                conn.execute("UPDATE servers SET status = 'stopped' WHERE id = ?", (sid,))
        conn.commit()
        conn.close()


async def start_server_process(sid: int) -> tuple[bool, str]:
    if sid in PROCS or sid in STARTING:
        return False, "Server is already starting or running"
    STARTING.add(sid)
    try:
        conn = get_db()
        srv = conn.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        conn.close()
        if not srv:
            return False, "Server not found"

        d = server_path(sid)
        d.mkdir(parents=True, exist_ok=True)
        runtime = srv["runtime"]

        if runtime == "static":
            return False, "Static sites do not run as a process - they are served directly"

        ok = await install_dependencies(sid, d, runtime)
        if not ok:
            return False, "Dependency installation failed - check logs"

        port = srv["port"] or allocate_port(sid)
        entry = srv["entry"]
        import json as _json
        env_vars = _json.loads(srv["env_vars"] or "{}")
        env = _build_child_env(env_vars, port)
        limits = _owner_plan_limits(sid)

        if not (d / entry).exists():
            _log(sid, f"[NEXUS] خطأ: الملف \"{entry}\" غير موجود داخل هذا السيرفر.")
            _log(sid, f"[NEXUS] ارفع ملف بهذا الاسم بالضبط من تبويب Files، أو عدّل اسم ملف التشغيل من إعدادات السيرفر.")
            _set_status(sid, "failed")
            return False, f'File "{entry}" not found'

        if srv["start_command"]:
            cmd = srv["start_command"].split()
        elif runtime == "python":
            cmd = ["python", entry]
        elif runtime == "node":
            cmd = ["node", entry]
        else:
            return False, "Unsupported runtime"

        _set_status(sid, "starting")
        _log(sid, f"$ {' '.join(cmd)}  (PORT={port})")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=str(d), env=env,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                start_new_session=True, preexec_fn=_make_preexec_fn(limits["ram_mb"]),
            )
        except FileNotFoundError as e:
            _log(sid, f"[NEXUS] failed to start: {e}")
            _set_status(sid, "failed")
            return False, str(e)

        PROCS[sid] = proc
        LOGS.setdefault(sid, [])
        conn = get_db()
        conn.execute(
            "UPDATE servers SET status = 'running', last_started_at = ?, restart_attempts = 0, "
            "last_error = NULL WHERE id = ?",
            (now_iso(), sid),
        )
        conn.commit()
        conn.close()
        asyncio.create_task(_pump_and_watch(sid, proc))
        asyncio.create_task(_watch_startup_success(sid, proc))
        return True, "Server started"
    finally:
        STARTING.discard(sid)


async def stop_server_process(sid: int) -> tuple[bool, str]:
    proc = PROCS.get(sid)
    _set_status(sid, "stopping")
    if not proc:
        _set_status(sid, "stopped")
        return True, "Server was not running"
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=6)
    except asyncio.TimeoutError:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
    PROCS.pop(sid, None)
    _set_status(sid, "stopped")
    _log(sid, "[NEXUS] process stopped")
    return True, "Server stopped"


async def restart_server_process(sid: int) -> tuple[bool, str]:
    await stop_server_process(sid)
    await asyncio.sleep(0.5)
    return await start_server_process(sid)


async def kill_server_process(sid: int) -> tuple[bool, str]:
    """Force kill (SIGKILL) the process group. Use when stop/timeout fails."""
    proc = PROCS.get(sid)
    _set_status(sid, "stopping")
    if not proc:
        _set_status(sid, "stopped")
        return True, "Server was not running"
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=3)
    except asyncio.TimeoutError:
        pass
    PROCS.pop(sid, None)
    _set_status(sid, "stopped")
    _log(sid, "[Nexus] process killed (SIGKILL)")
    return True, "Server killed"


def record_metric(sid: int, cpu: float, ram: float):
    """Store a real metric sample (best-effort, never blocks startup)."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO server_metrics (server_id, cpu_percent, ram_mb, recorded_at) VALUES (?,?,?,?)",
            (sid, cpu, ram, now_iso()),
        )
        # keep last ~2000 samples per server to avoid unbounded growth
        conn.execute(
            "DELETE FROM server_metrics WHERE server_id = ? AND id NOT IN "
            "(SELECT id FROM server_metrics WHERE server_id = ? ORDER BY id DESC LIMIT 2000)",
            (sid, sid),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Real resource usage (psutil) - never fabricated
# ---------------------------------------------------------------------------
def get_resource_usage(sid: int) -> dict:
    proc = PROCS.get(sid)
    if not proc or proc.returncode is not None:
        return {"cpu_percent": 0.0, "ram_mb": 0.0, "running": False, "pid": None}
    try:
        p = psutil.Process(proc.pid)
        cpu = p.cpu_percent(interval=0.1)
        ram = p.memory_info().rss / (1024 * 1024)
        # record occasionally for history (every call is fine; we prune)
        record_metric(sid, round(cpu, 1), round(ram, 1))
        return {
            "cpu_percent": round(cpu, 1),
            "ram_mb": round(ram, 1),
            "running": True,
            "pid": proc.pid,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"cpu_percent": 0.0, "ram_mb": 0.0, "running": False, "pid": None}


def get_directory_size_mb(d: Path) -> float:
    total = 0
    if d.exists():
        for f in d.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
    return round(total / (1024 * 1024), 2)


def system_health() -> dict:
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "ram_percent": psutil.virtual_memory().percent,
        "ram_used_mb": round(psutil.virtual_memory().used / (1024 * 1024), 1),
        "ram_total_mb": round(psutil.virtual_memory().total / (1024 * 1024), 1),
        "disk_percent": psutil.disk_usage("/").percent,
        "running_servers": len(PROCS),
    }
