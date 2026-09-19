"""
NEXUS / FLIX HOST - Database Layer
All schema + low level DB helpers live here so both the web app (app.py)
and the Telegram bot (bot.py) can share the exact same data definitions.

Schema is evolved via safe migrations (ADD COLUMN IF NOT EXISTS style)
so existing installations keep their data.
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
SERVERS_DIR = BASE / "servers"
BACKUPS_DIR = BASE / "backups"
DATA.mkdir(exist_ok=True)
SERVERS_DIR.mkdir(exist_ok=True)
BACKUPS_DIR.mkdir(exist_ok=True)
DB_PATH = DATA / "nexus.db"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


DEFAULT_PLANS = [
    # name, price_cents, duration_days(0=unlimited), server_limit, ram_mb, cpu_percent, storage_mb, features(json), color
    ("Free", 0, 0, 1, 256, 25, 250, json.dumps(["1 server", "Community support"]), "#7d8590"),
    ("Paid", 999, 30, 5, 1024, 60, 2048, json.dumps(["5 servers", "Priority support", "Custom domains"]), "#3b82f6"),
    ("VIP", 2999, 30, 15, 4096, 100, 10240,
     json.dumps(["15 servers", "Dedicated support", "Custom domains", "Highest resources", "Auto restart"]), "#a855f7"),
]

# Core schema (CREATE IF NOT EXISTS) — original tables + new ones
SCHEMA = """
CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    price_cents INTEGER NOT NULL DEFAULT 0,
    duration_days INTEGER NOT NULL DEFAULT 0,
    server_limit INTEGER NOT NULL DEFAULT 1,
    ram_mb INTEGER NOT NULL DEFAULT 256,
    cpu_percent INTEGER NOT NULL DEFAULT 25,
    storage_mb INTEGER NOT NULL DEFAULT 250,
    features TEXT NOT NULL DEFAULT '[]',
    color TEXT NOT NULL DEFAULT '#3b82f6',
    is_default INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    enabled INTEGER NOT NULL DEFAULT 1,
    plan_id INTEGER NOT NULL DEFAULT 1,
    plan_expires_at TEXT,
    created_at TEXT NOT NULL,
    last_login TEXT,
    FOREIGN KEY (plan_id) REFERENCES plans(id)
);

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    runtime TEXT NOT NULL,
    entry TEXT NOT NULL,
    start_command TEXT,
    port INTEGER,
    status TEXT NOT NULL DEFAULT 'stopped',
    auto_restart INTEGER NOT NULL DEFAULT 0,
    env_vars TEXT NOT NULL DEFAULT '{}',
    domain TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    last_started_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    result TEXT NOT NULL DEFAULT 'ok',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    port INTEGER PRIMARY KEY,
    server_id INTEGER NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- New tables (v7+)
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ready',
    created_at TEXT NOT NULL,
    note TEXT,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    category TEXT NOT NULL DEFAULT 'system',
    related_server_id INTEGER,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    cpu_percent REAL NOT NULL DEFAULT 0,
    ram_mb REAL NOT NULL DEFAULT 0,
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    expires_at TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',
    source TEXT NOT NULL DEFAULT 'manual',
    message TEXT,
    started_at TEXT,
    finished_at TEXT,
    log_text TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS telegram_links (
    telegram_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    linked_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""

DEFAULT_SETTINGS = {
    "site_name": "FLIX HOST",
    "site_description": "Infrastructure Control Center",
    "primary_accent": "#ef4444",
    "maintenance_mode": "0",
    "port_range_start": "20000",
    "port_range_end": "29000",
    "base_domain": "",
    "public_base_url": "",
    "max_restart_attempts": "5",
    "restart_cooldown_seconds": "60",
    "backup_retention_days": "14",
}


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == column for r in rows)


def _safe_add_column(conn: sqlite3.Connection, table: str, column: str, definition: str):
    if not _column_exists(conn, table, column):
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError:
            pass


def migrate(conn: sqlite3.Connection):
    """Safe additive migrations. Never drops or renames columns."""
    # users expansions
    _safe_add_column(conn, "users", "email", "TEXT")
    _safe_add_column(conn, "users", "banned", "INTEGER NOT NULL DEFAULT 0")
    _safe_add_column(conn, "users", "last_ip", "TEXT")
    _safe_add_column(conn, "users", "force_logout_at", "TEXT")
    _safe_add_column(conn, "users", "max_ports", "INTEGER")
    _safe_add_column(conn, "users", "max_backups", "INTEGER")
    _safe_add_column(conn, "users", "notes", "TEXT")

    # servers expansions
    _safe_add_column(conn, "servers", "install_command", "TEXT")
    _safe_add_column(conn, "servers", "runtime_version", "TEXT")
    _safe_add_column(conn, "servers", "restart_delay", "INTEGER NOT NULL DEFAULT 3")
    _safe_add_column(conn, "servers", "restart_attempts", "INTEGER NOT NULL DEFAULT 0")
    _safe_add_column(conn, "servers", "last_crash_at", "TEXT")
    _safe_add_column(conn, "servers", "last_error", "TEXT")
    _safe_add_column(conn, "servers", "auto_start", "INTEGER NOT NULL DEFAULT 0")
    _safe_add_column(conn, "servers", "project_id", "INTEGER")
    _safe_add_column(conn, "servers", "environment", "TEXT DEFAULT 'production'")
    _safe_add_column(conn, "servers", "git_url", "TEXT")
    _safe_add_column(conn, "servers", "git_branch", "TEXT DEFAULT 'main'")

    # audit_log expansions
    _safe_add_column(conn, "audit_log", "ip", "TEXT")
    _safe_add_column(conn, "audit_log", "details", "TEXT")

    # plans expansions
    _safe_add_column(conn, "plans", "port_limit", "INTEGER NOT NULL DEFAULT 2")
    _safe_add_column(conn, "plans", "backup_limit", "INTEGER NOT NULL DEFAULT 3")

    conn.commit()


def init_db(admin_user: str, admin_pass_hash: str):
    conn = get_db()
    conn.executescript(SCHEMA)
    migrate(conn)

    existing_plans = conn.execute("SELECT COUNT(*) c FROM plans").fetchone()["c"]
    if existing_plans == 0:
        for i, (name, price, dur, slim, ram, cpu, storage, feats, color) in enumerate(DEFAULT_PLANS):
            conn.execute(
                "INSERT INTO plans (name, price_cents, duration_days, server_limit, ram_mb, cpu_percent, "
                "storage_mb, features, color, is_default) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (name, price, dur, slim, ram, cpu, storage, feats, color, 1 if i == 0 else 0),
            )

    for k, v in DEFAULT_SETTINGS.items():
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    # update branding if still old default
    row = conn.execute("SELECT value FROM settings WHERE key = 'site_name'").fetchone()
    if row and row["value"] == "NEXUS PRO":
        conn.execute("UPDATE settings SET value = ? WHERE key = 'site_name'", ("FLIX HOST",))
        conn.execute("UPDATE settings SET value = ? WHERE key = 'site_description'",
                     ("Infrastructure Control Center",))
        conn.execute("UPDATE settings SET value = ? WHERE key = 'primary_accent'", ("#ef4444",))

    admin = conn.execute("SELECT id FROM users WHERE role IN ('admin','owner') LIMIT 1").fetchone()
    if not admin:
        vip_plan = conn.execute("SELECT id FROM plans ORDER BY server_limit DESC LIMIT 1").fetchone()
        conn.execute(
            "INSERT INTO users (username, password_hash, role, plan_id, created_at) VALUES (?,?,?,?,?)",
            (admin_user, admin_pass_hash, "owner", vip_plan["id"], now_iso()),
        )
    conn.commit()
    conn.close()


def log_action(actor: str, action: str, target: str = "", result: str = "ok",
               ip: str = "", details: str = ""):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO audit_log (actor, action, target, result, created_at, ip, details) "
            "VALUES (?,?,?,?,?,?,?)",
            (actor, action, target, result, now_iso(), ip or None, details or None),
        )
    except sqlite3.OperationalError:
        # fallback for very old schema without new columns
        conn.execute(
            "INSERT INTO audit_log (actor, action, target, result, created_at) VALUES (?,?,?,?,?)",
            (actor, action, target, result, now_iso()),
        )
    conn.commit()
    conn.close()


def get_setting(key: str, default: str = "") -> str:
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()


def server_path(sid: int) -> Path:
    return SERVERS_DIR / f"srv_{sid:06d}"


def backup_path(backup_id: int) -> Path:
    return BACKUPS_DIR / f"bk_{backup_id:08d}.zip"


def create_notification(user_id: int | None, title: str, body: str,
                        level: str = "info", category: str = "system",
                        related_server_id: int | None = None):
    conn = get_db()
    conn.execute(
        "INSERT INTO notifications (user_id, title, body, level, category, related_server_id, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (user_id, title, body, level, category, related_server_id, now_iso()),
    )
    conn.commit()
    conn.close()
