import os
import re
import json
import shutil
import zipfile
import secrets
import asyncio
from pathlib import Path
from datetime import datetime, timedelta, timezone

from fastapi import (
    FastAPI, Request, UploadFile, File, Form, HTTPException,
    WebSocket, WebSocketDisconnect, Depends, Header
)
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse, Response
from starlette.middleware.sessions import SessionMiddleware
import httpx

from db import (
    get_db, now_iso, init_db, log_action, get_setting, set_setting,
    server_path, BASE,
)
from auth import (
    hash_password, verify_password, get_current_user, require_admin,
    require_permission, has_permission,
)
from process_manager import (
    PROCS, LOGS, start_server_process, stop_server_process, restart_server_process,
    kill_server_process, get_resource_usage, get_directory_size_mb, system_health, release_port,
)
from plans import list_plans, check_can_create_server, check_storage_limit, expiration_sweep
from scheduler import scheduler_loop
from templates_data import TEMPLATES_META, TEMPLATES_FILES
from deployment_manager import list_deployments, run_deploy
from git_manager import git_clone, git_pull, git_info, git_available
from alerts import alert_server_event, notify_user
from backup_manager import list_backups, create_backup, restore_backup, delete_backup
from db import create_notification

SECRET_KEY = os.getenv("NEXUS_SECRET", secrets.token_hex(48))
ADMIN_USER = os.getenv("NEXUS_ADMIN_USER", "Nexus123@")
ADMIN_PASS = os.getenv("NEXUS_ADMIN_PASSWORD")  # must be set in production, see .env.example
BOT_API_KEY = os.getenv("NEXUS_BOT_API_KEY")     # required for the Telegram bot to call this API

if not ADMIN_PASS:
    # Dev-only fallback so the app still boots locally; production MUST set NEXUS_ADMIN_PASSWORD.
    ADMIN_PASS = secrets.token_urlsafe(12)
    print(f"[NEXUS] WARNING: NEXUS_ADMIN_PASSWORD not set. Generated one-time password: {ADMIN_PASS}")

app = FastAPI(title="Nexus HOST", version="1.0.0", docs_url=None, redoc_url=None)
app.add_middleware(
    SessionMiddleware, secret_key=SECRET_KEY,
    max_age=60 * 60 * 24 * 7, same_site="lax", https_only=False,
)


@app.on_event("startup")
async def on_startup():
    init_db(ADMIN_USER, hash_password(ADMIN_PASS))
    # Prefer env PUBLIC_BASE_URL / Railway domain so proxy links work after deploy
    pub = os.getenv("PUBLIC_BASE_URL") or os.getenv("RAILWAY_PUBLIC_DOMAIN") or ""
    if pub:
        if not pub.startswith("http"):
            pub = "https://" + pub
        set_setting("public_base_url", pub.rstrip("/"))
    asyncio.create_task(expiration_sweep())
    asyncio.create_task(scheduler_loop())


# ---------------------------------------------------------------------------
# Static pages
# ---------------------------------------------------------------------------
def _serve(name: str) -> HTMLResponse:
    return HTMLResponse((BASE / name).read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if request.session.get("uid"):
        return RedirectResponse("/dashboard")
    return _serve("login.html")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    get_current_user(request)
    return _serve("dashboard.html")


@app.get("/editor/{sid}", response_class=HTMLResponse)
async def editor_page(request: Request, sid: int):
    get_current_user(request)
    return _serve("editor.html")


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    require_admin(request)
    return _serve("admin.html")



# ---------------------------------------------------------------------------
# Auth
# Public self-registration is intentionally NOT exposed. Accounts are only
# created by an admin via /api/admin/users (private hosting platform).
# ---------------------------------------------------------------------------


# In-memory login rate limiter (per username + per client IP). Resets on
# process restart - fine for the brute-force-slowdown role it plays here.
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_MAX_ATTEMPTS = 6
LOGIN_WINDOW_SECONDS = 300


def _check_rate_limit(key: str):
    import time
    now = time.time()
    attempts = [t for t in _LOGIN_ATTEMPTS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    _LOGIN_ATTEMPTS[key] = attempts
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(429, "Too many login attempts. Try again in a few minutes.")


def _record_attempt(key: str):
    import time
    _LOGIN_ATTEMPTS.setdefault(key, []).append(time.time())


@app.post("/api/auth/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(f"user:{username}")
    _check_rate_limit(f"ip:{client_ip}")

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    conn.close()
    if not row or not verify_password(password, row["password_hash"]):
        _record_attempt(f"user:{username}")
        _record_attempt(f"ip:{client_ip}")
        log_action(username, "login_failed", result="denied")
        raise HTTPException(401, "Invalid credentials")
    if not row["enabled"]:
        raise HTTPException(403, "Account disabled")
    conn = get_db()
    conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_iso(), row["id"]))
    conn.commit()
    conn.close()
    request.session["uid"] = row["id"]
    log_action(username, "login")
    return {"ok": True, "role": row["role"]}


@app.post("/api/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/auth/me")
async def me(request: Request, user: dict = Depends(get_current_user)):
    safe = {k: v for k, v in user.items() if k != "password_hash"}
    impersonator_uid = request.session.get("impersonator_uid")
    if impersonator_uid:
        conn = get_db()
        real_admin = conn.execute("SELECT username FROM users WHERE id = ?", (impersonator_uid,)).fetchone()
        conn.close()
        safe["impersonating"] = True
        safe["real_admin_username"] = real_admin["username"] if real_admin else "admin"
    else:
        safe["impersonating"] = False
    return safe


@app.post("/api/admin/impersonate/{uid}")
async def start_impersonation(uid: int, request: Request, admin: dict = Depends(require_permission("manage_users"))):
    if request.session.get("impersonator_uid"):
        raise HTTPException(400, "Already impersonating - stop the current session first")
    conn = get_db()
    target = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    if not target:
        raise HTTPException(404, "User not found")
    if target["role"] in ("owner", "admin") and admin["role"] != "owner":
        raise HTTPException(403, "Only an owner can impersonate an admin account")
    request.session["impersonator_uid"] = admin["id"]
    request.session["uid"] = uid
    log_action(admin["username"], "impersonate_start", target["username"])
    return {"ok": True, "username": target["username"]}


@app.post("/api/auth/stop-impersonation")
async def stop_impersonation(request: Request):
    impersonator_uid = request.session.get("impersonator_uid")
    if not impersonator_uid:
        raise HTTPException(400, "Not currently impersonating anyone")
    conn = get_db()
    admin_row = conn.execute("SELECT username FROM users WHERE id = ?", (impersonator_uid,)).fetchone()
    conn.close()
    request.session["uid"] = impersonator_uid
    del request.session["impersonator_uid"]
    log_action(admin_row["username"] if admin_row else "admin", "impersonate_stop")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Servers (user-facing)
# ---------------------------------------------------------------------------
def _server_or_404(request: Request, sid: int) -> tuple[dict, dict]:
    user = get_current_user(request)
    conn = get_db()
    srv = conn.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
    conn.close()
    if not srv:
        raise HTTPException(404, "Server not found")
    srv = dict(srv)
    if user["role"] == "user" and srv["user_id"] != user["id"]:
        raise HTTPException(403, "Forbidden")
    return user, srv


def _public_base(request: Request | None = None) -> str:
    """Public base URL of the platform (Railway / custom domain)."""
    base = get_setting("public_base_url", "").rstrip("/")
    if base:
        return base
    # Railway injects RAILWAY_PUBLIC_DOMAIN or we fall back to request
    railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN") or os.getenv("RAILWAY_STATIC_URL")
    if railway_domain:
        if not railway_domain.startswith("http"):
            railway_domain = "https://" + railway_domain
        return railway_domain.rstrip("/")
    if request is not None:
        return str(request.base_url).rstrip("/")
    return ""


def server_public_url(sid: int, request: Request | None = None, domain: str | None = None) -> str:
    """
    Public URL for a hosted server.
    Priority:
      1. Custom domain saved on the server (user must point DNS themselves)
      2. Platform reverse-proxy path:  {BASE}/p/{sid}/
    """
    if domain:
        if not domain.startswith("http"):
            domain = "https://" + domain
        return domain.rstrip("/")
    base = _public_base(request)
    if not base:
        return f"/p/{sid}/"
    return f"{base}/p/{sid}/"


@app.get("/api/servers")
async def list_servers(request: Request, user: dict = Depends(get_current_user)):
    conn = get_db()
    if has_permission(user["role"], "manage_servers"):
        rows = conn.execute(
            "SELECT s.*, u.username FROM servers s JOIN users u ON s.user_id = u.id ORDER BY s.id DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT s.*, ? as username FROM servers s WHERE s.user_id = ? ORDER BY s.id DESC",
            (user["username"], user["id"]),
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        usage = get_resource_usage(d["id"])
        d.update(usage)
        d["storage_mb"] = get_directory_size_mb(server_path(d["id"]))
        d["public_url"] = server_public_url(d["id"], request, d.get("domain"))
        out.append(d)
    return out


@app.post("/api/servers")
async def create_server(
    request: Request,
    name: str = Form(...), runtime: str = Form(...),
    entry: str = Form(""), start_command: str = Form(""),
    auto_restart: bool = Form(False),
):
    user = get_current_user(request)
    if runtime not in ("python", "node", "static"):
        raise HTTPException(400, "Invalid runtime")
    ok, msg = check_can_create_server(user)
    if not ok:
        raise HTTPException(403, msg)

    name = name.strip()[:64]
    if not name:
        raise HTTPException(400, "Name is required")
    if not entry.strip():
        entry = {"python": "main.py", "node": "index.js", "static": "index.html"}[runtime]

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO servers (user_id, name, runtime, entry, start_command, status, auto_restart, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (user["id"], name, runtime, entry.strip(), start_command.strip() or None,
         "stopped", int(auto_restart), now_iso()),
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()

    d = server_path(sid)
    d.mkdir(parents=True, exist_ok=True)
    default_file = d / entry.strip()
    if not default_file.exists():
        content = {
            "python": 'print("Hello from NEXUS PRO")\n',
            "node": 'console.log("Hello from NEXUS PRO");\n',
            "static": '<!doctype html><html><body><h1>Hello from NEXUS PRO</h1></body></html>\n',
        }[runtime]
        default_file.write_text(content, encoding="utf-8")

    log_action(user["username"], "create_server", name)
    return {"ok": True, "id": sid}


DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


@app.patch("/api/servers/{sid}")
async def edit_server(request: Request, sid: int):
    """Rename a server, change its entry file, or toggle auto-restart. The
    server's own name and its entry filename are deliberately separate
    fields - renaming the server never touches the file it runs."""
    user, srv = _server_or_404(request, sid)
    body = await request.json()
    updates, values = [], []
    if "name" in body:
        name = str(body["name"]).strip()[:64]
        if not name:
            raise HTTPException(400, "Name cannot be empty")
        updates.append("name = ?"); values.append(name)
    if "entry" in body:
        entry = str(body["entry"]).strip()
        if not entry:
            raise HTTPException(400, "Entry filename cannot be empty")
        updates.append("entry = ?"); values.append(entry)
    if "start_command" in body:
        updates.append("start_command = ?"); values.append(str(body["start_command"]).strip() or None)
    if "auto_restart" in body:
        updates.append("auto_restart = ?"); values.append(int(bool(body["auto_restart"])))
    if not updates:
        raise HTTPException(400, "Nothing to update")
    conn = get_db()
    conn.execute(f"UPDATE servers SET {', '.join(updates)} WHERE id = ?", (*values, sid))
    conn.commit()
    conn.close()
    log_action(user["username"], "edit_server", srv["name"])
    return {"ok": True}


@app.put("/api/servers/{sid}/domain")
async def set_domain(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    body = await request.json()
    domain = str(body.get("domain", "")).strip().lower()
    if not domain:
        raise HTTPException(400, "Domain cannot be empty")
    if not DOMAIN_RE.match(domain):
        raise HTTPException(400, "Invalid domain format")
    conn = get_db()
    conn.execute("UPDATE servers SET domain = ? WHERE id = ?", (domain, sid))
    conn.commit()
    conn.close()
    log_action(user["username"], "set_domain", f"{srv['name']}:{domain}")
    return {
        "ok": True, "domain": domain,
        "note": "This only saves the mapping. Point the domain's DNS (CNAME/A record) to your "
                "deployment's real address yourself - NEXUS PRO does not configure DNS or SSL automatically.",
    }


@app.delete("/api/servers/{sid}/domain")
async def remove_domain(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    conn = get_db()
    conn.execute("UPDATE servers SET domain = NULL WHERE id = ?", (sid,))
    conn.commit()
    conn.close()
    log_action(user["username"], "remove_domain", srv["name"])
    return {"ok": True}


@app.delete("/api/servers/{sid}")
async def delete_server(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    await stop_server_process(sid)
    release_port(sid)
    path = server_path(sid)
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    conn = get_db()
    conn.execute("DELETE FROM servers WHERE id = ?", (sid,))
    conn.commit()
    conn.close()
    LOGS.pop(sid, None)
    log_action(user["username"], "delete_server", srv["name"])
    return {"ok": True}


@app.post("/api/servers/{sid}/start")
async def start_server(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    ok, msg = await start_server_process(sid)
    log_action(user["username"], "start_server", srv["name"], "ok" if ok else "failed")
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "message": msg}


@app.post("/api/servers/{sid}/stop")
async def stop_server(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    ok, msg = await stop_server_process(sid)
    log_action(user["username"], "stop_server", srv["name"])
    return {"ok": ok, "message": msg}


@app.post("/api/servers/{sid}/restart")
async def restart_server(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    ok, msg = await restart_server_process(sid)
    log_action(user["username"], "restart_server", srv["name"], "ok" if ok else "failed")
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "message": msg}


@app.post("/api/servers/{sid}/kill")
async def kill_server(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    ok, msg = await kill_server_process(sid)
    log_action(user["username"], "kill_server", srv["name"], "ok" if ok else "failed")
    return {"ok": ok, "message": msg}


# ---------------------------------------------------------------------------
# Backups (real ZIP of server files)
# ---------------------------------------------------------------------------
@app.get("/api/servers/{sid}/backups")
async def server_backups(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    return list_backups(server_id=sid, user_id=user["id"] if user["role"] == "user" else None)


@app.post("/api/servers/{sid}/backups")
async def server_create_backup(request: Request, sid: int, note: str = Form("")):
    user, srv = _server_or_404(request, sid)
    ok, msg, bid = create_backup(sid, user["id"], note=note)
    if not ok:
        raise HTTPException(400, msg)
    create_notification(user["id"], "Backup created", f"Server {srv['name']} backup #{bid}", "success", "backup", sid)
    return {"ok": True, "id": bid, "message": msg}


@app.post("/api/backups/{bid}/restore")
async def server_restore_backup(request: Request, bid: int):
    user = get_current_user(request)
    conn = get_db()
    row = conn.execute("SELECT * FROM backups WHERE id = ?", (bid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Backup not found")
    if user["role"] == "user" and row["user_id"] != user["id"]:
        raise HTTPException(403, "Forbidden")
    # stop server before restore
    await stop_server_process(row["server_id"])
    ok, msg = restore_backup(bid, user["id"])
    log_action(user["username"], "restore_backup", str(bid), "ok" if ok else "failed")
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "message": msg}


@app.delete("/api/backups/{bid}")
async def server_delete_backup(request: Request, bid: int):
    user = get_current_user(request)
    conn = get_db()
    row = conn.execute("SELECT * FROM backups WHERE id = ?", (bid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Backup not found")
    if user["role"] == "user" and row["user_id"] != user["id"]:
        raise HTTPException(403, "Forbidden")
    ok, msg = delete_backup(bid)
    log_action(user["username"], "delete_backup", str(bid))
    return {"ok": ok, "message": msg}


@app.get("/api/backups/{bid}/download")
async def download_backup(request: Request, bid: int):
    user = get_current_user(request)
    conn = get_db()
    row = conn.execute("SELECT * FROM backups WHERE id = ?", (bid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Backup not found")
    if user["role"] == "user" and row["user_id"] != user["id"]:
        raise HTTPException(403, "Forbidden")
    path = Path(row["path"])
    if not path.exists():
        raise HTTPException(404, "Backup file missing")
    return FileResponse(path, filename=path.name, media_type="application/zip")


@app.get("/api/servers/{sid}")
async def get_server(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    usage = get_resource_usage(sid)
    srv.update(usage)
    srv["storage_mb"] = get_directory_size_mb(server_path(sid))
    srv["public_url"] = server_public_url(sid, request, srv.get("domain"))
    # parse env for client
    try:
        srv["env"] = json.loads(srv.get("env_vars") or "{}")
    except Exception:
        srv["env"] = {}
    return srv


@app.get("/api/servers/{sid}/logs")
async def get_logs(request: Request, sid: int):
    _server_or_404(request, sid)
    return {"lines": LOGS.get(sid, [])[-500:]}


@app.delete("/api/servers/{sid}/logs")
async def clear_logs(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    LOGS[sid] = []
    log_action(user["username"], "clear_logs", srv["name"])
    return {"ok": True}


@app.get("/api/servers/{sid}/env")
async def get_env_vars(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    try:
        env = json.loads(srv.get("env_vars") or "{}")
    except Exception:
        env = {}
    return {"env": env}


@app.put("/api/servers/{sid}/env")
async def set_env_vars(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    body = await request.json()
    env = body.get("env", {})
    if not isinstance(env, dict):
        raise HTTPException(400, "env must be an object")
    # sanitize keys
    clean = {str(k).strip(): str(v) for k, v in env.items() if str(k).strip()}
    conn = get_db()
    conn.execute("UPDATE servers SET env_vars = ? WHERE id = ?", (json.dumps(clean), sid))
    conn.commit()
    conn.close()
    log_action(user["username"], "update_env", srv["name"])
    return {"ok": True, "env": clean}


@app.get("/api/servers/{sid}/diagnostics")
async def server_diagnostics(request: Request, sid: int):
    """Real health checks — no fake results."""
    user, srv = _server_or_404(request, sid)
    d = server_path(sid)
    checks = []

    def add(name, status, detail=""):
        checks.append({"name": name, "status": status, "detail": detail})

    # entry file
    entry = srv.get("entry") or ""
    entry_path = d / entry if entry else None
    if entry_path and entry_path.is_file():
        add("Entry file", "passed", f"Found: {entry}")
    else:
        add("Entry file", "failed", f"Missing: {entry or '(not set)'}")

    # runtime binary
    runtime = srv.get("runtime")
    if runtime == "python":
        import shutil as _sh
        py = _sh.which("python3") or _sh.which("python")
        add("Python runtime", "passed" if py else "failed", py or "python not found on host")
        req = d / "requirements.txt"
        add("requirements.txt", "passed" if req.exists() else "warning",
            "Present" if req.exists() else "No requirements.txt (optional)")
    elif runtime == "node":
        import shutil as _sh
        node = _sh.which("node")
        npm = _sh.which("npm")
        add("Node runtime", "passed" if node else "failed", node or "node not found")
        add("npm", "passed" if npm else "warning", npm or "npm not found")
        pkg = d / "package.json"
        add("package.json", "passed" if pkg.exists() else "warning",
            "Present" if pkg.exists() else "No package.json")
    elif runtime == "static":
        add("Static runtime", "passed", "Files served directly via proxy")
    else:
        add("Runtime", "failed", f"Unknown runtime: {runtime}")

    # port
    port = srv.get("port")
    if port:
        add("Port assigned", "passed", str(port))
    else:
        add("Port assigned", "warning", "No port allocated yet (assigned on first start)")

    # process
    usage = get_resource_usage(sid)
    if usage.get("running"):
        add("Process", "passed", f"PID {usage.get('pid')} · CPU {usage.get('cpu_percent')}% · RAM {usage.get('ram_mb')} MB")
    else:
        st = srv.get("status") or "stopped"
        if st in ("crashed", "failed", "error"):
            add("Process", "failed", f"Status: {st}" + (f" — {srv.get('last_error')}" if srv.get("last_error") else ""))
        else:
            add("Process", "warning", f"Not running (status: {st})")

    # storage
    storage = get_directory_size_mb(d)
    limit = user.get("storage_mb") or 0
    if limit and storage > limit:
        add("Storage", "failed", f"{storage} MB used / {limit} MB limit")
    elif limit and storage > limit * 0.85:
        add("Storage", "warning", f"{storage} MB used / {limit} MB limit")
    else:
        add("Storage", "passed", f"{storage} MB used" + (f" / {limit} MB limit" if limit else ""))

    # directory exists
    add("Server directory", "passed" if d.exists() else "failed", str(d))

    # public url
    pub = server_public_url(sid, request, srv.get("domain"))
    add("Public URL", "passed", pub)

    passed = sum(1 for c in checks if c["status"] == "passed")
    warnings = sum(1 for c in checks if c["status"] == "warning")
    failed = sum(1 for c in checks if c["status"] == "failed")
    overall = "failed" if failed else ("warning" if warnings else "passed")

    return {
        "server_id": sid,
        "overall": overall,
        "summary": {"passed": passed, "warning": warnings, "failed": failed},
        "checks": checks,
    }


# ---------------------------------------------------------------------------
# File manager - path traversal is blocked via safe_path()
# ---------------------------------------------------------------------------
def safe_path(base: Path, rel: str) -> Path:
    rel = (rel or "").replace("\\", "/").lstrip("/")
    target = (base / rel).resolve()
    if not str(target).startswith(str(base.resolve())):
        raise HTTPException(400, "Invalid path")
    return target


@app.get("/api/servers/{sid}/files")
async def list_files(request: Request, sid: int, path: str = ""):
    _server_or_404(request, sid)
    base = server_path(sid)
    target = safe_path(base, path)
    if not target.exists() or not target.is_dir():
        raise HTTPException(404, "Directory not found")
    items = []
    for p in sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        items.append({"name": p.name, "type": "dir" if p.is_dir() else "file",
                       "size": p.stat().st_size if p.is_file() else 0})
    return items


@app.get("/api/servers/{sid}/file")
async def read_file(request: Request, sid: int, path: str):
    _server_or_404(request, sid)
    target = safe_path(server_path(sid), path)
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "File not found")
    if target.stat().st_size > 2_000_000:
        raise HTTPException(400, "File too large to edit here (2MB limit)")
    try:
        content = target.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        content = target.read_text(encoding="latin-1")
    return {"path": path, "content": content}


@app.put("/api/servers/{sid}/file")
async def write_file(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    body = await request.json()
    path, content = body.get("path", ""), body.get("content", "")
    target = safe_path(server_path(sid), path)
    ok, msg = check_storage_limit(user, sid)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    if not ok:
        log_action(user["username"], "storage_warning", srv["name"], "over_limit")
    return {"ok": True}


MAX_UPLOAD_BYTES = 50 * 1024 * 1024        # 50MB per uploaded file
MAX_ZIP_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # zip-bomb guard
MAX_ZIP_MEMBERS = 5000


@app.post("/api/servers/{sid}/upload")
async def upload_file(request: Request, sid: int, file: UploadFile = File(...), path: str = Form("")):
    user, srv = _server_or_404(request, sid)
    ok, msg = check_storage_limit(user, sid)
    if not ok:
        raise HTTPException(403, msg)
    dest_dir = safe_path(server_path(sid), path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(file.filename or "upload").name
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (limit {MAX_UPLOAD_BYTES // (1024*1024)}MB)")

    if filename.lower().endswith(".zip"):
        tmp = dest_dir / ("_tmp_" + filename)
        tmp.write_bytes(content)
        try:
            with zipfile.ZipFile(tmp, "r") as zf:
                infos = zf.infolist()
                if len(infos) > MAX_ZIP_MEMBERS:
                    raise HTTPException(400, "Archive has too many files")
                total_uncompressed = sum(i.file_size for i in infos)
                if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise HTTPException(400, "Archive is too large when extracted (possible zip bomb)")

                dest_resolved = dest_dir.resolve()
                for info in infos:
                    member = info.filename
                    if ".." in member or member.startswith("/") or member.startswith("\\"):
                        continue  # reject traversal attempts
                    target = (dest_dir / member).resolve()
                    if not str(target).startswith(str(dest_resolved)):
                        continue  # reject anything that resolves outside the server's directory
                    zf.extract(info, dest_dir)
        finally:
            tmp.unlink(missing_ok=True)
    else:
        (dest_dir / filename).write_bytes(content)
    log_action(user["username"], "upload_file", f"{srv['name']}:{filename}")
    return {"ok": True}


@app.delete("/api/servers/{sid}/file")
async def delete_file(request: Request, sid: int, path: str):
    user, srv = _server_or_404(request, sid)
    target = safe_path(server_path(sid), path)
    if not target.exists():
        raise HTTPException(404, "Not found")
    shutil.rmtree(target) if target.is_dir() else target.unlink()
    log_action(user["username"], "delete_file", f"{srv['name']}:{path}")
    return {"ok": True}


@app.post("/api/servers/{sid}/file/rename")
async def rename_file(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    body = await request.json()
    old_path, new_name = body.get("path", ""), str(body.get("new_name", "")).strip()
    if not new_name or "/" in new_name or "\\" in new_name:
        raise HTTPException(400, "Invalid new file name")
    old_target = safe_path(server_path(sid), old_path)
    if not old_target.exists():
        raise HTTPException(404, "File not found")
    new_target = safe_path(server_path(sid), str(Path(old_path).parent / new_name))
    if new_target.exists():
        raise HTTPException(409, "A file with that name already exists")
    old_target.rename(new_target)
    log_action(user["username"], "rename_file", f"{srv['name']}:{old_path}->{new_name}")
    return {"ok": True}


@app.get("/api/servers/{sid}/file/download")
async def download_file(request: Request, sid: int, path: str):
    _server_or_404(request, sid)
    target = safe_path(server_path(sid), path)
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "File not found")
    return FileResponse(target, filename=target.name, media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Public reverse proxy — makes user servers reachable on Railway / any host
# URL form:  https://your-app.up.railway.app/p/{server_id}/...
# or custom domain if the user pointed DNS to this deployment.
# ---------------------------------------------------------------------------
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


@app.api_route("/p/{sid}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.api_route("/p/{sid}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def public_proxy(request: Request, sid: int, path: str = ""):
    """Forward public traffic to the internal process port of a running server."""
    conn = get_db()
    srv = conn.execute("SELECT id, port, status, runtime FROM servers WHERE id = ?", (sid,)).fetchone()
    conn.close()
    if not srv:
        return HTMLResponse("<h1>404</h1><p>Server not found</p>", status_code=404)
    if srv["runtime"] == "static":
        # serve static files directly from the server directory
        base = server_path(sid)
        rel = path or "index.html"
        target = safe_path(base, rel)
        if target.is_dir():
            target = target / "index.html"
        if not target.exists() or not target.is_file():
            return HTMLResponse("<h1>404</h1><p>File not found</p>", status_code=404)
        return FileResponse(target)
    if not srv["port"] or srv["status"] not in ("running", "starting"):
        return HTMLResponse(
            "<h1>Server Offline</h1><p>This application is not running right now.</p>",
            status_code=503,
        )
    upstream = f"http://127.0.0.1:{srv['port']}/{path}"
    if request.url.query:
        upstream += "?" + request.url.query

    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
    headers["x-forwarded-for"] = request.client.host if request.client else ""
    headers["x-forwarded-proto"] = request.url.scheme
    headers["x-forwarded-host"] = request.headers.get("host", "")

    body = await request.body()
    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
            upstream_resp = await client.request(
                request.method, upstream, headers=headers, content=body,
            )
    except httpx.ConnectError:
        return HTMLResponse(
            "<h1>Connection Failed</h1><p>Could not reach the application process.</p>",
            status_code=502,
        )
    except Exception as e:
        return HTMLResponse(f"<h1>Proxy Error</h1><p>{e}</p>", status_code=502)

    resp_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in HOP_BY_HOP
    }
    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# Live console over WebSocket (real log tail, not simulated)
# ---------------------------------------------------------------------------
@app.websocket("/ws/servers/{sid}")
async def ws_console(websocket: WebSocket, sid: int):
    await websocket.accept()
    last_len = 0
    try:
        while True:
            lines = LOGS.get(sid, [])
            if len(lines) != last_len:
                await websocket.send_json({"lines": lines[-300:]})
                last_len = len(lines)
            await websocket.send_json({"usage": get_resource_usage(sid)})
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass


# ---------------------------------------------------------------------------
# Admin: users
# ---------------------------------------------------------------------------
@app.get("/api/admin/users")
async def admin_list_users(admin: dict = Depends(require_permission("manage_users"))):
    conn = get_db()
    rows = conn.execute(
        "SELECT u.id,u.username,u.role,u.enabled,u.plan_id,u.plan_expires_at,u.created_at,u.last_login,"
        "p.name as plan_name FROM users u JOIN plans p ON u.plan_id = p.id ORDER BY u.id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/admin/users")
async def admin_create_user(
    admin: dict = Depends(require_permission("manage_users")),
    username: str = Form(...), password: str = Form(...),
    role: str = Form("user"), plan_id: int = Form(1),
):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, plan_id, created_at) VALUES (?,?,?,?,?)",
            (username.strip(), hash_password(password), role, plan_id, now_iso()),
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(409, "Username already exists")
    conn.close()
    log_action(admin["username"], "admin_create_user", username)
    return {"ok": True}


@app.post("/api/admin/users/trial")
async def admin_create_trial_user(
    admin: dict = Depends(require_permission("manage_users")),
    username: str = Form(...), password: str = Form(...),
    plan_id: int = Form(...), hours: int = Form(...),
):
    """Creates an account that is only open (enabled) for a set number of
    hours - the expiration sweep already running in plans.py will stop its
    servers and mark it expired automatically when the time is up."""
    if hours <= 0:
        raise HTTPException(400, "hours must be a positive number")
    expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, plan_id, plan_expires_at, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (username.strip(), hash_password(password), "user", plan_id, expires, now_iso()),
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(409, "Username already exists")
    conn.close()
    log_action(admin["username"], "admin_create_trial_user", f"{username} ({hours}h)")
    return {"ok": True, "expires_at": expires}


@app.patch("/api/admin/users/{uid}")
async def admin_update_user(
    uid: int, admin: dict = Depends(require_permission("manage_users")),
    enabled: int | None = Form(None), plan_id: int | None = Form(None),
    plan_days: int | None = Form(None), role: str | None = Form(None),
):
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(404, "User not found")
    if target["role"] == "owner" and admin["role"] != "owner":
        conn.close()
        raise HTTPException(403, "Only an owner can modify another owner")

    if enabled is not None:
        conn.execute("UPDATE users SET enabled = ? WHERE id = ?", (enabled, uid))
    if plan_id is not None:
        conn.execute("UPDATE users SET plan_id = ? WHERE id = ?", (plan_id, uid))
    if plan_days is not None:
        exp = (datetime.now(timezone.utc) + timedelta(days=plan_days)).isoformat() if plan_days > 0 else None
        conn.execute("UPDATE users SET plan_expires_at = ? WHERE id = ?", (exp, uid))
    if role is not None and admin["role"] == "owner":
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
    conn.commit()
    conn.close()
    log_action(admin["username"], "admin_update_user", target["username"])
    return {"ok": True}


@app.delete("/api/admin/users/{uid}")
async def admin_delete_user(uid: int, admin: dict = Depends(require_permission("manage_users"))):
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(404, "User not found")
    if target["role"] in ("owner", "admin"):
        conn.close()
        raise HTTPException(400, "Cannot delete an admin/owner account here")
    servers = conn.execute("SELECT id FROM servers WHERE user_id = ?", (uid,)).fetchall()
    conn.close()
    for s in servers:
        await stop_server_process(s["id"])
        release_port(s["id"])
        shutil.rmtree(server_path(s["id"]), ignore_errors=True)
    conn = get_db()
    conn.execute("DELETE FROM servers WHERE user_id = ?", (uid,))
    conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    log_action(admin["username"], "admin_delete_user", target["username"])
    return {"ok": True}


# ---------------------------------------------------------------------------
# Admin: plans
# ---------------------------------------------------------------------------
@app.get("/api/admin/plans")
async def admin_list_plans(admin: dict = Depends(require_permission("manage_plans"))):
    return list_plans()


@app.patch("/api/admin/plans/{pid}")
async def admin_update_plan(
    pid: int, admin: dict = Depends(require_permission("manage_plans")),
    server_limit: int = Form(...), ram_mb: int = Form(...),
    cpu_percent: int = Form(...), storage_mb: int = Form(...),
    price_cents: int = Form(...), duration_days: int = Form(...),
):
    conn = get_db()
    conn.execute(
        "UPDATE plans SET server_limit=?, ram_mb=?, cpu_percent=?, storage_mb=?, price_cents=?, duration_days=? "
        "WHERE id=?",
        (server_limit, ram_mb, cpu_percent, storage_mb, price_cents, duration_days, pid),
    )
    conn.commit()
    conn.close()
    log_action(admin["username"], "admin_update_plan", str(pid))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Admin: servers (global control)
# ---------------------------------------------------------------------------
@app.post("/api/admin/servers/{sid}/suspend")
async def admin_suspend_server(sid: int, admin: dict = Depends(require_permission("manage_servers"))):
    await stop_server_process(sid)
    conn = get_db()
    conn.execute("UPDATE servers SET status = 'suspended' WHERE id = ?", (sid,))
    conn.commit()
    conn.close()
    log_action(admin["username"], "admin_suspend_server", str(sid))
    return {"ok": True}


@app.post("/api/admin/servers/{sid}/unsuspend")
async def admin_unsuspend_server(sid: int, admin: dict = Depends(require_permission("manage_servers"))):
    conn = get_db()
    conn.execute("UPDATE servers SET status = 'stopped' WHERE id = ?", (sid,))
    conn.commit()
    conn.close()
    log_action(admin["username"], "admin_unsuspend_server", str(sid))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Admin: settings / system / audit log
# ---------------------------------------------------------------------------
@app.get("/api/admin/settings")
async def admin_get_settings(admin: dict = Depends(require_permission("manage_settings"))):
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


@app.post("/api/admin/settings")
async def admin_set_settings(request: Request, admin: dict = Depends(require_permission("manage_settings"))):
    body = await request.json()
    for k, v in body.items():
        set_setting(k, str(v))
    log_action(admin["username"], "admin_update_settings")
    return {"ok": True}


@app.get("/api/admin/system")
async def admin_system(admin: dict = Depends(require_permission("manage_system"))):
    return system_health()


@app.get("/api/admin/audit")
async def admin_audit(admin: dict = Depends(require_permission("manage_logs"))):
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/admin/broadcast")
async def admin_broadcast(
    request: Request, admin: dict = Depends(require_permission("manage_users")), message: str = Form(...),
):
    set_setting("broadcast_message", message)
    set_setting("broadcast_at", now_iso())
    log_action(admin["username"], "broadcast", message[:80])
    return {"ok": True}


@app.get("/api/broadcast")
async def get_broadcast():
    msg = get_setting("broadcast_message", "")
    return {"message": msg, "at": get_setting("broadcast_at", "")}


# ---------------------------------------------------------------------------
# Bot API - separate token auth so the Telegram bot talks to the SAME engine
# instead of a second, disconnected database.
# ---------------------------------------------------------------------------
def require_bot_token(x_bot_token: str = Header(None)):
    if not BOT_API_KEY or x_bot_token != BOT_API_KEY:
        raise HTTPException(401, "Invalid bot token")
    return True


@app.get("/api/bot/overview")
async def bot_overview(_: bool = Depends(require_bot_token)):
    conn = get_db()
    users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    servers = conn.execute("SELECT COUNT(*) c FROM servers").fetchone()["c"]
    running = conn.execute("SELECT COUNT(*) c FROM servers WHERE status='running'").fetchone()["c"]
    conn.close()
    health = system_health()
    return {"users": users, "servers": servers, "running": running, **health}


@app.get("/api/bot/users")
async def bot_users(_: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute(
        "SELECT u.id,u.username,u.role,u.enabled,p.name as plan_name FROM users u "
        "JOIN plans p ON u.plan_id = p.id ORDER BY u.id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/bot/servers")
async def bot_servers(_: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute(
        "SELECT s.id,s.name,s.runtime,s.status,s.port,u.username FROM servers s "
        "JOIN users u ON s.user_id = u.id ORDER BY s.id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/bot/servers/{sid}/{action}")
async def bot_server_action(sid: int, action: str, _: bool = Depends(require_bot_token)):
    if action == "start":
        ok, msg = await start_server_process(sid)
    elif action == "stop":
        ok, msg = await stop_server_process(sid)
    elif action == "restart":
        ok, msg = await restart_server_process(sid)
    else:
        raise HTTPException(400, "Unknown action")
    log_action("telegram-bot", f"bot_{action}_server", str(sid), "ok" if ok else "failed")
    return {"ok": ok, "message": msg}


@app.post("/api/bot/users/{uid}/setplan")
async def bot_set_plan(uid: int, plan_id: int = Form(...), days: int = Form(30), _: bool = Depends(require_bot_token)):
    conn = get_db()
    exp = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat() if days > 0 else None
    conn.execute("UPDATE users SET plan_id = ?, plan_expires_at = ? WHERE id = ?", (plan_id, exp, uid))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_set_plan", f"user={uid} plan={plan_id}")
    return {"ok": True}


@app.post("/api/bot/users/{uid}/suspend")
async def bot_suspend_user(uid: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    conn.execute("UPDATE users SET enabled = 0 WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_suspend_user", str(uid))
    return {"ok": True}


@app.post("/api/bot/users/{uid}/enable")
async def bot_enable_user(uid: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    conn.execute("UPDATE users SET enabled = 1 WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_enable_user", str(uid))
    return {"ok": True}


@app.get("/api/bot/users/{uid}")
async def bot_user_info(uid: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    row = conn.execute(
        "SELECT u.id,u.username,u.role,u.enabled,u.plan_expires_at,u.created_at,u.last_login,"
        "p.name as plan_name,p.server_limit,p.ram_mb,p.cpu_percent,p.storage_mb "
        "FROM users u JOIN plans p ON u.plan_id = p.id WHERE u.id = ?", (uid,),
    ).fetchone()
    server_count = conn.execute("SELECT COUNT(*) c FROM servers WHERE user_id = ?", (uid,)).fetchone()["c"]
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")
    out = dict(row)
    out["server_count"] = server_count
    return out


@app.post("/api/bot/users")
async def bot_create_user(
    username: str = Form(...), password: str = Form(...),
    role: str = Form("user"), plan_id: int = Form(1),
    _: bool = Depends(require_bot_token),
):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, plan_id, created_at) VALUES (?,?,?,?,?)",
            (username.strip(), hash_password(password), role, plan_id, now_iso()),
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(409, "Username already exists")
    conn.close()
    log_action("telegram-bot", "bot_create_user", username)
    return {"ok": True}


@app.post("/api/bot/users/trial")
async def bot_create_trial_user(
    username: str = Form(...), password: str = Form(...),
    plan_id: int = Form(...), hours: int = Form(...),
    _: bool = Depends(require_bot_token),
):
    if hours <= 0:
        raise HTTPException(400, "hours must be a positive number")
    expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, plan_id, plan_expires_at, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (username.strip(), hash_password(password), "user", plan_id, expires, now_iso()),
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(409, "Username already exists")
    conn.close()
    log_action("telegram-bot", "bot_create_trial_user", f"{username} ({hours}h)")
    return {"ok": True, "expires_at": expires}


@app.get("/api/bot/servers/{sid}/files")
async def bot_list_files(sid: int, path: str = "", _: bool = Depends(require_bot_token)):
    base = server_path(sid)
    target = safe_path(base, path)
    if not target.exists() or not target.is_dir():
        raise HTTPException(404, "Directory not found")
    items = []
    for p in sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        items.append({"name": p.name, "type": "dir" if p.is_dir() else "file",
                       "size": p.stat().st_size if p.is_file() else 0})
    return items


@app.get("/api/bot/servers/{sid}/file")
async def bot_read_file(sid: int, path: str, _: bool = Depends(require_bot_token)):
    target = safe_path(server_path(sid), path)
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "File not found")
    if target.stat().st_size > 200_000:
        raise HTTPException(400, "File too large to preview here (200KB limit)")
    try:
        content = target.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        content = target.read_text(encoding="latin-1")
    return {"path": path, "content": content}


@app.put("/api/bot/servers/{sid}/domain")
async def bot_set_domain(sid: int, domain: str = Form(...), _: bool = Depends(require_bot_token)):
    if not DOMAIN_RE.match(domain.strip().lower()):
        raise HTTPException(400, "Invalid domain format")
    conn = get_db()
    conn.execute("UPDATE servers SET domain = ? WHERE id = ?", (domain.strip().lower(), sid))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_set_domain", f"{sid}:{domain}")
    return {"ok": True}


@app.get("/api/bot/users/search")
async def bot_search_users(q: str, _: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, role, enabled FROM users WHERE username LIKE ? LIMIT 15", (f"%{q}%",)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/bot/servers/search")
async def bot_search_servers(q: str, _: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute(
        "SELECT s.id, s.name, s.status, u.username FROM servers s JOIN users u ON s.user_id = u.id "
        "WHERE s.name LIKE ? LIMIT 15", (f"%{q}%",)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.delete("/api/bot/users/{uid}")
async def bot_delete_user(uid: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(404, "User not found")
    if target["role"] in ("owner", "admin"):
        conn.close()
        raise HTTPException(400, "Cannot delete an admin/owner account here")
    servers = conn.execute("SELECT id FROM servers WHERE user_id = ?", (uid,)).fetchall()
    conn.close()
    for s in servers:
        await stop_server_process(s["id"])
        release_port(s["id"])
        shutil.rmtree(server_path(s["id"]), ignore_errors=True)
    conn = get_db()
    conn.execute("DELETE FROM servers WHERE user_id = ?", (uid,))
    conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_delete_user", target["username"])
    return {"ok": True}


@app.post("/api/bot/users/{uid}/role")
async def bot_set_role(uid: int, role: str = Form(...), _: bool = Depends(require_bot_token)):
    if role not in ("user", "support", "moderator", "admin", "owner"):
        raise HTTPException(400, "Invalid role")
    conn = get_db()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_set_role", f"user={uid} role={role}")
    return {"ok": True}


@app.post("/api/bot/users/{uid}/resetpassword")
async def bot_reset_password(uid: int, password: str = Form(...), _: bool = Depends(require_bot_token)):
    if len(password) < 6:
        raise HTTPException(400, "Password must be 6+ characters")
    conn = get_db()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), uid))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_reset_password", str(uid))
    return {"ok": True}


@app.get("/api/bot/users/recent")
async def bot_recent_users(_: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---- Bot: servers ----
@app.post("/api/bot/servers")
async def bot_create_server(
    owner_id: int = Form(...), name: str = Form(...), runtime: str = Form(...),
    entry: str = Form(""), _: bool = Depends(require_bot_token),
):
    if runtime not in ("python", "node", "static"):
        raise HTTPException(400, "Invalid runtime")
    if not entry.strip():
        entry = {"python": "main.py", "node": "index.js", "static": "index.html"}[runtime]
    conn = get_db()
    owner = conn.execute("SELECT id FROM users WHERE id = ?", (owner_id,)).fetchone()
    if not owner:
        conn.close()
        raise HTTPException(404, "Owner not found")
    cur = conn.execute(
        "INSERT INTO servers (user_id, name, runtime, entry, status, auto_restart, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (owner_id, name.strip()[:64], runtime, entry.strip(), "stopped", 0, now_iso()),
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    d = server_path(sid)
    d.mkdir(parents=True, exist_ok=True)
    content = {
        "python": 'print("Hello from NEXUS PRO")\n',
        "node": 'console.log("Hello from NEXUS PRO");\n',
        "static": '<!doctype html><html><body><h1>Hello from NEXUS PRO</h1></body></html>\n',
    }[runtime]
    (d / entry.strip()).write_text(content, encoding="utf-8")
    log_action("telegram-bot", "bot_create_server", name)
    return {"ok": True, "id": sid}


@app.delete("/api/bot/servers/{sid}")
async def bot_delete_server(sid: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    srv = conn.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
    conn.close()
    if not srv:
        raise HTTPException(404, "Server not found")
    await stop_server_process(sid)
    release_port(sid)
    shutil.rmtree(server_path(sid), ignore_errors=True)
    conn = get_db()
    conn.execute("DELETE FROM servers WHERE id = ?", (sid,))
    conn.commit()
    conn.close()
    LOGS.pop(sid, None)
    log_action("telegram-bot", "bot_delete_server", srv["name"])
    return {"ok": True}


@app.get("/api/bot/servers/{sid}")
async def bot_server_info(sid: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    row = conn.execute(
        "SELECT s.*, u.username FROM servers s JOIN users u ON s.user_id = u.id WHERE s.id = ?", (sid,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Server not found")
    out = dict(row)
    out.update(get_resource_usage(sid))
    out["storage_mb"] = get_directory_size_mb(server_path(sid))
    return out


@app.get("/api/bot/servers/{sid}/logs")
async def bot_server_logs(sid: int, _: bool = Depends(require_bot_token)):
    return {"lines": LOGS.get(sid, [])[-60:]}


@app.post("/api/bot/servers/{sid}/suspend")
async def bot_suspend_server(sid: int, _: bool = Depends(require_bot_token)):
    await stop_server_process(sid)
    conn = get_db()
    conn.execute("UPDATE servers SET status = 'suspended' WHERE id = ?", (sid,))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_suspend_server", str(sid))
    return {"ok": True}


@app.post("/api/bot/servers/{sid}/unsuspend")
async def bot_unsuspend_server(sid: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    conn.execute("UPDATE servers SET status = 'stopped' WHERE id = ?", (sid,))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_unsuspend_server", str(sid))
    return {"ok": True}


@app.put("/api/bot/servers/{sid}/env")
async def bot_set_env_var(sid: int, key: str = Form(...), value: str = Form(...), _: bool = Depends(require_bot_token)):
    conn = get_db()
    row = conn.execute("SELECT env_vars FROM servers WHERE id = ?", (sid,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Server not found")
    env = json.loads(row["env_vars"] or "{}")
    env[key] = value
    conn.execute("UPDATE servers SET env_vars = ? WHERE id = ?", (json.dumps(env), sid))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_set_env", f"{sid}:{key}")
    return {"ok": True}


@app.post("/api/bot/servers/{sid}/edit")
async def bot_edit_server(
    sid: int, name: str = Form(None), entry: str = Form(None),
    auto_restart: int = Form(None), _: bool = Depends(require_bot_token),
):
    conn = get_db()
    srv = conn.execute("SELECT id FROM servers WHERE id = ?", (sid,)).fetchone()
    if not srv:
        conn.close()
        raise HTTPException(404, "Server not found")
    updates, values = [], []
    if name is not None:
        updates.append("name = ?"); values.append(name.strip()[:64])
    if entry is not None:
        updates.append("entry = ?"); values.append(entry.strip())
    if auto_restart is not None:
        updates.append("auto_restart = ?"); values.append(int(bool(auto_restart)))
    if not updates:
        conn.close()
        raise HTTPException(400, "Nothing to update")
    conn.execute(f"UPDATE servers SET {', '.join(updates)} WHERE id = ?", (*values, sid))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_edit_server", str(sid))
    return {"ok": True}


@app.get("/api/bot/servers/recent")
async def bot_recent_servers(_: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute(
        "SELECT s.id, s.name, s.runtime, s.status, u.username FROM servers s "
        "JOIN users u ON s.user_id = u.id ORDER BY s.id DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/bot/servers/killall")
async def bot_killall(_: bool = Depends(require_bot_token)):
    conn = get_db()
    running = conn.execute("SELECT id FROM servers WHERE status = 'running'").fetchall()
    conn.close()
    for s in running:
        await stop_server_process(s["id"])
    log_action("telegram-bot", "bot_killall", f"{len(running)} servers")
    return {"ok": True, "stopped": len(running)}


@app.get("/api/bot/ports")
async def bot_ports(_: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute(
        "SELECT p.port, p.server_id, s.name FROM ports p JOIN servers s ON p.server_id = s.id ORDER BY p.port"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---- Bot: plans ----
@app.get("/api/bot/plans")
async def bot_list_plans(_: bool = Depends(require_bot_token)):
    return list_plans()


@app.get("/api/bot/plans/{pid}")
async def bot_plan_info(pid: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    row = conn.execute("SELECT * FROM plans WHERE id = ?", (pid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Plan not found")
    return dict(row)


@app.post("/api/bot/plans/{pid}/edit")
async def bot_edit_plan(pid: int, field: str = Form(...), value: str = Form(...), _: bool = Depends(require_bot_token)):
    allowed = {"server_limit", "ram_mb", "cpu_percent", "storage_mb", "duration_days", "price_cents"}
    if field not in allowed:
        raise HTTPException(400, f"Field must be one of: {', '.join(sorted(allowed))}")
    try:
        int_value = int(value)
    except ValueError:
        raise HTTPException(400, "Value must be an integer")
    conn = get_db()
    conn.execute(f"UPDATE plans SET {field} = ? WHERE id = ?", (int_value, pid))
    conn.commit()
    conn.close()
    log_action("telegram-bot", "bot_edit_plan", f"{pid}:{field}={int_value}")
    return {"ok": True}


# ---- Bot: system / settings / audit / maintenance ----
@app.get("/api/bot/system")
async def bot_system(_: bool = Depends(require_bot_token)):
    return system_health()


@app.get("/api/bot/audit")
async def bot_audit(_: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 15").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/bot/settings")
async def bot_get_settings(_: bool = Depends(require_bot_token)):
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


@app.post("/api/bot/settings")
async def bot_set_setting(key: str = Form(...), value: str = Form(...), _: bool = Depends(require_bot_token)):
    set_setting(key, value)
    log_action("telegram-bot", "bot_set_setting", f"{key}={value}")
    return {"ok": True}


@app.post("/api/bot/maintenance/{state}")
async def bot_maintenance(state: str, _: bool = Depends(require_bot_token)):
    if state not in ("on", "off"):
        raise HTTPException(400, "state must be 'on' or 'off'")
    set_setting("maintenance_mode", "1" if state == "on" else "0")
    log_action("telegram-bot", "bot_maintenance", state)
    return {"ok": True}


@app.get("/api/bot/ping")
async def bot_ping(_: bool = Depends(require_bot_token)):
    return {"ok": True, "version": "8.0.0"}


@app.post("/api/bot/broadcast")
async def bot_broadcast(message: str = Form(...), _: bool = Depends(require_bot_token)):
    set_setting("broadcast_message", message)
    set_setting("broadcast_at", now_iso())
    log_action("telegram-bot", "broadcast", message[:80])
    return {"ok": True}



# ---------------------------------------------------------------------------
# Templates + Clone (real file copies, no fake scaffolds)
# ---------------------------------------------------------------------------
TEMPLATES = TEMPLATES_META


@app.get("/api/templates")
async def list_templates(user: dict = Depends(get_current_user)):
    out = []
    for key, meta in TEMPLATES.items():
        out.append({"id": key, **meta})
    return out


@app.post("/api/servers/from-template")
async def create_from_template(
    request: Request,
    template_id: str = Form(...),
    name: str = Form(...),
):
    user = get_current_user(request)
    if template_id not in TEMPLATES:
        raise HTTPException(400, "Unknown template")
    ok, msg = check_can_create_server(user)
    if not ok:
        raise HTTPException(403, msg)
    meta = TEMPLATES[template_id]
    name = name.strip()[:64]
    if not name:
        raise HTTPException(400, "Name required")

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO servers (user_id, name, runtime, entry, status, auto_restart, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (user["id"], name, meta["runtime"], meta["entry"], "stopped", 0, now_iso()),
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()

    dst = server_path(sid)
    dst.mkdir(parents=True, exist_ok=True)
    files = TEMPLATES_FILES.get(template_id) or {}
    if files:
        for rel, content in files.items():
            if content is None:
                continue
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    else:
        (dst / meta["entry"]).write_text("# template missing\n", encoding="utf-8")

    log_action(user["username"], "create_from_template", f"{name}:{template_id}")
    return {"ok": True, "id": sid}


@app.post("/api/servers/{sid}/clone")
async def clone_server(request: Request, sid: int, name: str = Form("")):
    """Clone files + settings. Does not copy secrets (env cleared)."""
    user, srv = _server_or_404(request, sid)
    ok, msg = check_can_create_server(user)
    if not ok:
        raise HTTPException(403, msg)
    new_name = (name or (srv["name"] + "-clone")).strip()[:64]

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO servers (user_id, name, runtime, entry, start_command, status, auto_restart, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (user["id"], new_name, srv["runtime"], srv["entry"], srv.get("start_command"),
         "stopped", 0, now_iso()),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    src = server_path(sid)
    dst = server_path(new_id)
    if src.exists():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        dst.mkdir(parents=True, exist_ok=True)

    log_action(user["username"], "clone_server", f"{sid}->{new_id}")
    return {"ok": True, "id": new_id}


@app.get("/api/servers/{sid}/metrics")
async def server_metrics_history(request: Request, sid: int, limit: int = 60):
    _server_or_404(request, sid)
    limit = max(1, min(limit, 500))
    conn = get_db()
    rows = conn.execute(
        "SELECT cpu_percent, ram_mb, recorded_at FROM server_metrics "
        "WHERE server_id = ? ORDER BY id DESC LIMIT ?",
        (sid, limit),
    ).fetchall()
    conn.close()
    data = [dict(r) for r in rows]
    data.reverse()
    return {"points": data}



@app.post("/api/admin/users/{uid}/force-logout")
async def admin_force_logout(uid: int, admin: dict = Depends(require_permission("manage_users"))):
    conn = get_db()
    target = conn.execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(404, "User not found")
    conn.execute("UPDATE users SET force_logout_at = ? WHERE id = ?", (now_iso(), uid))
    conn.commit()
    conn.close()
    log_action(admin["username"], "force_logout", target["username"])
    return {"ok": True}


@app.post("/api/admin/users/{uid}/ban")
async def admin_ban_user(uid: int, admin: dict = Depends(require_permission("manage_users")), banned: int = Form(1)):
    conn = get_db()
    target = conn.execute("SELECT username, role FROM users WHERE id = ?", (uid,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(404, "User not found")
    if target["role"] in ("owner", "admin") and admin["role"] != "owner":
        conn.close()
        raise HTTPException(403, "Cannot ban admin")
    conn.execute("UPDATE users SET banned = ?, enabled = ? WHERE id = ?", (int(banned), 0 if banned else 1, uid))
    conn.commit()
    conn.close()
    log_action(admin["username"], "ban_user" if banned else "unban_user", target["username"])
    return {"ok": True}


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------
@app.get("/api/servers/{sid}/deployments")
async def get_deployments(request: Request, sid: int):
    _server_or_404(request, sid)
    return list_deployments(server_id=sid)


@app.post("/api/servers/{sid}/deploy")
async def deploy_server(request: Request, sid: int, message: str = Form("")):
    user, srv = _server_or_404(request, sid)
    ok, msg, dep_id = await run_deploy(sid, user["id"], source="manual", message=message)
    if not ok:
        raise HTTPException(400, msg)
    create_notification(user["id"], "Deployment success", f"{srv['name']} deployed", "success", "deploy", sid)
    return {"ok": True, "deployment_id": dep_id, "message": msg}


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------
@app.get("/api/api-keys")
async def list_api_keys(user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, key_prefix, scopes, expires_at, last_used_at, created_at, revoked "
        "FROM api_keys WHERE user_id = ? ORDER BY id DESC",
        (user["id"],),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/api-keys")
async def create_api_key(
    user: dict = Depends(get_current_user),
    name: str = Form(...),
    scopes: str = Form("servers:read,servers:write"),
):
    raw = secrets.token_urlsafe(32)
    prefix = raw[:8]
    key_hash = hash_password(raw)
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO api_keys (user_id, name, key_hash, key_prefix, scopes, created_at) VALUES (?,?,?,?,?,?)",
        (user["id"], name.strip()[:64], key_hash, prefix, scopes, now_iso()),
    )
    kid = cur.lastrowid
    conn.commit()
    conn.close()
    log_action(user["username"], "create_api_key", name)
    # raw key shown only once
    return {"ok": True, "id": kid, "key": f"Nexus_{raw}", "prefix": prefix}


@app.delete("/api/api-keys/{kid}")
async def revoke_api_key(kid: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM api_keys WHERE id = ? AND user_id = ?", (kid, user["id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Key not found")
    conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (kid,))
    conn.commit()
    conn.close()
    log_action(user["username"], "revoke_api_key", str(kid))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Maintenance mode (public read for UI)
# ---------------------------------------------------------------------------
@app.get("/api/system/status")
async def system_status():
    maint = get_setting("maintenance_mode", "0") == "1"
    h = system_health()
    return {
        "maintenance": maint,
        "site_name": get_setting("site_name", "Nexus HOST"),
        **h,
    }


@app.post("/api/admin/maintenance")
async def set_maintenance(
    admin: dict = Depends(require_permission("manage_system")),
    enabled: int = Form(...),
):
    set_setting("maintenance_mode", "1" if enabled else "0")
    log_action(admin["username"], "maintenance", "on" if enabled else "off")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------
@app.get("/api/servers/{sid}/git")
async def server_git_info(request: Request, sid: int):
    _server_or_404(request, sid)
    info = await git_info(sid)
    conn = get_db()
    row = conn.execute("SELECT git_url, git_branch FROM servers WHERE id = ?", (sid,)).fetchone()
    conn.close()
    info["git_url"] = row["git_url"] if row else None
    info["git_branch"] = row["git_branch"] if row else None
    info["host_has_git"] = git_available()
    return info


@app.post("/api/servers/{sid}/git/clone")
async def server_git_clone(request: Request, sid: int, url: str = Form(...), branch: str = Form("main")):
    user, srv = _server_or_404(request, sid)
    ok, msg = await git_clone(sid, url, branch)
    log_action(user["username"], "git_clone", f"{sid}:{url}", "ok" if ok else "failed")
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "message": msg}


@app.post("/api/servers/{sid}/git/pull")
async def server_git_pull(request: Request, sid: int):
    user, srv = _server_or_404(request, sid)
    ok, msg = await git_pull(sid)
    log_action(user["username"], "git_pull", str(sid), "ok" if ok else "failed")
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "message": msg}


@app.post("/api/servers/{sid}/rollback")
async def server_rollback(request: Request, sid: int):
    """Rollback = restore latest ready backup then optional restart."""
    user, srv = _server_or_404(request, sid)
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM backups WHERE server_id = ? AND status = 'ready' ORDER BY id DESC LIMIT 1",
        (sid,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(400, "No backup available to rollback to. Create a backup first.")
    await stop_server_process(sid)
    ok, msg = restore_backup(row["id"], user["id"])
    log_action(user["username"], "rollback", f"server={sid} backup={row['id']}", "ok" if ok else "failed")
    if not ok:
        raise HTTPException(400, msg)
    notify_user(user["id"], "Rollback completed", f"Server {srv['name']} restored from backup #{row['id']}", "info", "backup", sid)
    return {"ok": True, "backup_id": row["id"], "message": msg}


# ---------------------------------------------------------------------------
# Global search
# ---------------------------------------------------------------------------
@app.get("/api/search")
async def global_search(request: Request, q: str = "", user: dict = Depends(get_current_user)):
    q = (q or "").strip()
    if len(q) < 1:
        return {"servers": [], "users": []}
    like = f"%{q}%"
    conn = get_db()
    if has_permission(user["role"], "manage_servers"):
        servers = conn.execute(
            "SELECT id, name, status, runtime FROM servers WHERE name LIKE ? LIMIT 20", (like,)
        ).fetchall()
    else:
        servers = conn.execute(
            "SELECT id, name, status, runtime FROM servers WHERE user_id = ? AND name LIKE ? LIMIT 20",
            (user["id"], like),
        ).fetchall()
    users = []
    if has_permission(user["role"], "manage_users"):
        users = conn.execute(
            "SELECT id, username, role, enabled FROM users WHERE username LIKE ? LIMIT 20", (like,)
        ).fetchall()
    conn.close()
    return {"servers": [dict(r) for r in servers], "users": [dict(r) for r in users]}


# ---------------------------------------------------------------------------
# Telegram account linking
# ---------------------------------------------------------------------------
@app.post("/api/bot/telegram/link")
async def bot_link_telegram(telegram_id: int = Form(...), username: str = Form(...), _: bool = Depends(require_bot_token)):
    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "User not found")
    conn.execute(
        "INSERT INTO telegram_links (telegram_id, user_id, linked_at) VALUES (?,?,?) "
        "ON CONFLICT(telegram_id) DO UPDATE SET user_id = excluded.user_id, linked_at = excluded.linked_at",
        (telegram_id, user["id"], now_iso()),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/bot/telegram/link/{telegram_id}")
async def bot_get_link(telegram_id: int, _: bool = Depends(require_bot_token)):
    conn = get_db()
    row = conn.execute(
        "SELECT t.telegram_id, t.user_id, u.username, u.role FROM telegram_links t "
        "JOIN users u ON u.id = t.user_id WHERE t.telegram_id = ?",
        (telegram_id,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Not linked")
    return dict(row)

@app.get("/api/notifications")
async def get_notifications(request: Request, user: dict = Depends(get_current_user)):
    conn = get_db()
    if has_permission(user["role"], "manage_system"):
        rows = conn.execute(
            "SELECT * FROM notifications ORDER BY id DESC LIMIT 100"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE user_id = ? OR user_id IS NULL ORDER BY id DESC LIMIT 50",
            (user["id"],),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/notifications/{nid}/read")
async def mark_notification_read(nid: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    conn.execute(
        "UPDATE notifications SET is_read = 1 WHERE id = ? AND (user_id = ? OR user_id IS NULL)",
        (nid, user["id"]),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/health")
async def health():
    try:
        conn = get_db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False
    h = system_health()
    return {
        "status": "ok" if db_ok else "degraded",
        "version": "8.0.0",
        "database": "ok" if db_ok else "error",
        "running_servers": h.get("running_servers", 0),
        "cpu_percent": h.get("cpu_percent"),
        "ram_percent": h.get("ram_percent"),
    }
