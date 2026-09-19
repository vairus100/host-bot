"""
FLIX HOST - Telegram Control Center
Same backend API as the web panel (X-Bot-Token). No separate database.

Env: BOT_TOKEN, NEXUS_API_URL, NEXUS_BOT_API_KEY, TELEGRAM_ADMIN_IDS
Run: python bot.py
"""
from __future__ import annotations

import os
import logging
import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("flix-bot")

BOT_TOKEN = os.environ["BOT_TOKEN"]
API_URL = os.getenv("NEXUS_API_URL", "http://127.0.9.0.1:8000").rstrip("/")
API_KEY = os.environ["NEXUS_BOT_API_KEY"]
HEADERS = {"X-Bot-Token": API_KEY}

ADMIN_IDS: set[int] = {
    int(x) for x in os.getenv("TELEGRAM_ADMIN_IDS", "").split(",") if x.strip()
}

PAGE_SIZE = 6


# ---------------------------------------------------------------------------
# API helper
# ---------------------------------------------------------------------------
async def api(method: str, path: str, **kwargs):
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.request(method, f"{API_URL}{path}", headers=HEADERS, **kwargs)
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise RuntimeError(f"{r.status_code}: {detail}")
        if r.status_code == 204 or not r.content:
            return {}
        return r.json()


def load_admins():
    try:
        r = httpx.get(f"{API_URL}/api/bot/settings", headers=HEADERS, timeout=10)
        r.raise_for_status()
        saved = r.json().get("telegram_admin_ids", "")
        for x in saved.split(","):
            if x.strip():
                ADMIN_IDS.add(int(x.strip()))
    except Exception as e:
        log.warning("admin list load failed: %s", e)


def persist_admins():
    try:
        httpx.post(
            f"{API_URL}/api/bot/settings",
            headers=HEADERS,
            timeout=10,
            data={"key": "telegram_admin_ids", "value": ",".join(str(i) for i in ADMIN_IDS)},
        )
    except Exception as e:
        log.warning("admin list persist failed: %s", e)


def is_allowed(uid: int | None) -> bool:
    if not ADMIN_IDS:
        return True  # open if no list configured (dev only)
    return uid is not None and uid in ADMIN_IDS


# ---------------------------------------------------------------------------
# Keyboards
# ---------------------------------------------------------------------------
def kb_main() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Dashboard", callback_data="menu:dash"),
            InlineKeyboardButton("Servers", callback_data="menu:servers:0"),
        ],
        [
            InlineKeyboardButton("Users", callback_data="menu:users:0"),
            InlineKeyboardButton("System", callback_data="menu:system"),
        ],
        [
            InlineKeyboardButton("Audit", callback_data="menu:audit"),
            InlineKeyboardButton("Maintenance", callback_data="menu:maint"),
        ],
        [InlineKeyboardButton("Refresh", callback_data="menu:home")],
    ])


def kb_server(sid: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Start", callback_data=f"srv:{sid}:start"),
            InlineKeyboardButton("Stop", callback_data=f"srv:{sid}:stop"),
            InlineKeyboardButton("Restart", callback_data=f"srv:{sid}:restart"),
        ],
        [
            InlineKeyboardButton("Console", callback_data=f"srv:{sid}:console"),
            InlineKeyboardButton("Logs", callback_data=f"srv:{sid}:logs"),
            InlineKeyboardButton("Status", callback_data=f"srv:{sid}:info"),
        ],
        [
            InlineKeyboardButton("Deploy", callback_data=f"srv:{sid}:deploy"),
            InlineKeyboardButton("Backup", callback_data=f"srv:{sid}:backup"),
            InlineKeyboardButton("Diagnostics", callback_data=f"srv:{sid}:diag"),
        ],
        [
            InlineKeyboardButton("Kill", callback_data=f"confirm:kill:{sid}"),
            InlineKeyboardButton("Delete", callback_data=f"confirm:delete:{sid}"),
        ],
        [InlineKeyboardButton("Back", callback_data="menu:servers:0")],
    ])


def kb_confirm(action: str, sid: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Confirm", callback_data=f"do:{action}:{sid}"),
            InlineKeyboardButton("Cancel", callback_data=f"srv:{sid}:info"),
        ]
    ])


def kb_back_home() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("Home", callback_data="menu:home")]])


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------
async def deny(update: Update):
    target = update.callback_query.message if update.callback_query else update.effective_message
    if target:
        await target.reply_text("Access denied. Your Telegram ID is not authorized.")


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------
async def screen_home(update: Update, context: ContextTypes.DEFAULT_TYPE, edit: bool = False):
    text = (
        "FLIX HOST\n"
        "Infrastructure Control Center\n\n"
        "Use the buttons below. All actions hit the same backend as the web panel."
    )
    await send(update, text, kb_main(), edit)


async def screen_dashboard(update: Update, edit: bool = True):
    try:
        data = await api("GET", "/api/bot/overview")
    except Exception as e:
        await send(update, f"API error: {e}", kb_back_home(), edit)
        return
    text = (
        "SYSTEM STATUS\n\n"
        f"CPU: {data.get('cpu_percent', '—')}%\n"
        f"RAM: {data.get('ram_used_mb', '—')} / {data.get('ram_total_mb', '—')} MB "
        f"({data.get('ram_percent', '—')}%)\n"
        f"Disk: {data.get('disk_percent', '—')}%\n\n"
        f"Users: {data.get('users', '—')}\n"
        f"Servers: {data.get('servers', '—')}\n"
        f"Running: {data.get('running', data.get('running_servers', '—'))}\n"
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("Refresh", callback_data="menu:dash")],
        [InlineKeyboardButton("Home", callback_data="menu:home")],
    ])
    await send(update, text, kb, edit)


async def screen_servers(update: Update, page: int = 0, edit: bool = True):
    try:
        rows = await api("GET", "/api/bot/servers")
    except Exception as e:
        await send(update, f"API error: {e}", kb_back_home(), edit)
        return
    if not isinstance(rows, list):
        rows = []
    total = len(rows)
    start = page * PAGE_SIZE
    chunk = rows[start : start + PAGE_SIZE]
    lines = ["SERVERS\n"]
    buttons = []
    for s in chunk:
        lines.append(
            f"#{s.get('id')}  {s.get('name')}  [{s.get('status')}]  "
            f"{s.get('runtime')}  port {s.get('port') or '—'}"
        )
        buttons.append([
            InlineKeyboardButton(
                f"#{s.get('id')} {s.get('name')}"[:40],
                callback_data=f"srv:{s.get('id')}:info",
            )
        ])
    if not chunk:
        lines.append("No servers.")
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("Prev", callback_data=f"menu:servers:{page-1}"))
    if start + PAGE_SIZE < total:
        nav.append(InlineKeyboardButton("Next", callback_data=f"menu:servers:{page+1}"))
    if nav:
        buttons.append(nav)
    buttons.append([InlineKeyboardButton("Home", callback_data="menu:home")])
    await send(update, "\n".join(lines), InlineKeyboardMarkup(buttons), edit)


async def screen_server_info(update: Update, sid: int, edit: bool = True):
    try:
        s = await api("GET", f"/api/bot/servers/{sid}")
    except Exception as e:
        await send(update, f"API error: {e}", kb_back_home(), edit)
        return
    text = (
        f"SERVER #{s.get('id')}\n\n"
        f"Name: {s.get('name')}\n"
        f"Owner: {s.get('username')}\n"
        f"Runtime: {s.get('runtime')}\n"
        f"Status: {s.get('status')}\n"
        f"Port: {s.get('port') or '—'}\n"
        f"CPU: {s.get('cpu_percent', 0)}%\n"
        f"RAM: {s.get('ram_mb', 0)} MB\n"
        f"Storage: {s.get('storage_mb', 0)} MB\n"
        f"Entry: {s.get('entry')}\n"
        f"Domain: {s.get('domain') or '—'}\n"
    )
    await send(update, text, kb_server(sid), edit)


async def screen_console(update: Update, sid: int, edit: bool = True):
    try:
        data = await api("GET", f"/api/bot/servers/{sid}/logs")
        lines = data.get("lines") or []
    except Exception as e:
        await send(update, f"API error: {e}", kb_server(sid), edit)
        return
    tail = lines[-25:] if lines else ["(no logs)"]
    body = "\n".join(str(x)[:200] for x in tail)
    if len(body) > 3500:
        body = body[-3500:]
    text = f"CONSOLE #{sid}\n\n{body}"
    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Refresh", callback_data=f"srv:{sid}:console"),
            InlineKeyboardButton("Back", callback_data=f"srv:{sid}:info"),
        ]
    ])
    await send(update, text, kb, edit)


async def screen_users(update: Update, page: int = 0, edit: bool = True):
    try:
        rows = await api("GET", "/api/bot/users")
    except Exception as e:
        await send(update, f"API error: {e}", kb_back_home(), edit)
        return
    if not isinstance(rows, list):
        rows = []
    start = page * PAGE_SIZE
    chunk = rows[start : start + PAGE_SIZE]
    lines = ["USERS\n"]
    buttons = []
    for u in chunk:
        st = "on" if u.get("enabled") else "off"
        lines.append(f"#{u.get('id')}  {u.get('username')}  [{u.get('role')}]  {st}  {u.get('plan_name')}")
        buttons.append([
            InlineKeyboardButton(
                f"#{u.get('id')} {u.get('username')}"[:40],
                callback_data=f"user:{u.get('id')}",
            )
        ])
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("Prev", callback_data=f"menu:users:{page-1}"))
    if start + PAGE_SIZE < len(rows):
        nav.append(InlineKeyboardButton("Next", callback_data=f"menu:users:{page+1}"))
    if nav:
        buttons.append(nav)
    buttons.append([InlineKeyboardButton("Home", callback_data="menu:home")])
    await send(update, "\n".join(lines) if chunk else "USERS\n\nNo users.", InlineKeyboardMarkup(buttons), edit)


async def screen_user(update: Update, uid: int, edit: bool = True):
    try:
        u = await api("GET", f"/api/bot/users/{uid}")
    except Exception as e:
        await send(update, f"API error: {e}", kb_back_home(), edit)
        return
    text = (
        f"USER #{u.get('id')}\n\n"
        f"Username: {u.get('username')}\n"
        f"Role: {u.get('role')}\n"
        f"Plan: {u.get('plan_name')}\n"
        f"Enabled: {u.get('enabled')}\n"
        f"Servers: {u.get('server_count')}\n"
        f"Last login: {u.get('last_login') or '—'}\n"
        f"Expires: {u.get('plan_expires_at') or 'never'}\n"
    )
    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Enable", callback_data=f"useract:{uid}:enable"),
            InlineKeyboardButton("Disable", callback_data=f"useract:{uid}:disable"),
        ],
        [InlineKeyboardButton("Back", callback_data="menu:users:0")],
    ])
    await send(update, text, kb, edit)


async def screen_system(update: Update, edit: bool = True):
    try:
        data = await api("GET", "/api/bot/system")
        ping = await api("GET", "/api/bot/ping")
    except Exception as e:
        await send(update, f"API error: {e}", kb_back_home(), edit)
        return
    text = (
        "SYSTEM\n\n"
        f"Version: {ping.get('version', '—')}\n"
        f"CPU: {data.get('cpu_percent')}%\n"
        f"RAM: {data.get('ram_percent')}% "
        f"({data.get('ram_used_mb')} / {data.get('ram_total_mb')} MB)\n"
        f"Disk: {data.get('disk_percent')}%\n"
        f"Running processes: {data.get('running_servers')}\n"
    )
    await send(update, text, InlineKeyboardMarkup([
        [InlineKeyboardButton("Refresh", callback_data="menu:system")],
        [InlineKeyboardButton("Home", callback_data="menu:home")],
    ]), edit)


async def screen_audit(update: Update, edit: bool = True):
    try:
        rows = await api("GET", "/api/bot/audit")
    except Exception as e:
        await send(update, f"API error: {e}", kb_back_home(), edit)
        return
    lines = ["AUDIT LOG\n"]
    for r in (rows or [])[:15]:
        lines.append(
            f"{str(r.get('created_at', ''))[:19]}  {r.get('actor')}  "
            f"{r.get('action')}  {r.get('target') or ''}  [{r.get('result')}]"
        )
    await send(update, "\n".join(lines), kb_back_home(), edit)


async def screen_maint(update: Update, edit: bool = True):
    try:
        settings = await api("GET", "/api/bot/settings")
        on = str(settings.get("maintenance_mode", "0")) == "1"
    except Exception as e:
        await send(update, f"API error: {e}", kb_back_home(), edit)
        return
    text = f"MAINTENANCE MODE\n\nCurrently: {'ON' if on else 'OFF'}"
    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Turn ON", callback_data="maint:on"),
            InlineKeyboardButton("Turn OFF", callback_data="maint:off"),
        ],
        [InlineKeyboardButton("Home", callback_data="menu:home")],
    ])
    await send(update, text, kb, edit)


# ---------------------------------------------------------------------------
# Send helper (edit or reply)
# ---------------------------------------------------------------------------
async def send(update: Update, text: str, keyboard: InlineKeyboardMarkup, edit: bool):
    if len(text) > 4000:
        text = text[:4000] + "\n…"
    if edit and update.callback_query:
        try:
            await update.callback_query.edit_message_text(text, reply_markup=keyboard)
            return
        except Exception:
            pass
    msg = update.effective_message
    if msg:
        await msg.reply_text(text, reply_markup=keyboard)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id if update.effective_user else None
    if not is_allowed(uid):
        await deny(update)
        return
    await screen_home(update, context, edit=False)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    text = (
        "COMMANDS\n\n"
        "/start  /panel  /help\n"
        "/dashboard\n"
        "/servers\n"
        "/server <id>\n"
        "/status\n"
        "/startserver <id>\n"
        "/stopserver <id>\n"
        "/restartserver <id>\n"
        "/console <id>\n"
        "/logs <id>\n"
        "/users\n"
        "/system\n"
        "/audit\n/link <username>\n/search <query>\n\n"
        "Buttons are preferred. Sensitive actions require confirmation."
    )
    await update.effective_message.reply_text(text, reply_markup=kb_main())


async def cmd_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    await screen_dashboard(update, edit=False)


async def cmd_servers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    await screen_servers(update, 0, edit=False)


async def cmd_server(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    if not context.args:
        await update.effective_message.reply_text("Usage: /server <id>")
        return
    try:
        sid = int(context.args[0])
    except ValueError:
        await update.effective_message.reply_text("Invalid id")
        return
    await screen_server_info(update, sid, edit=False)


async def cmd_action(update: Update, context: ContextTypes.DEFAULT_TYPE, action: str):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    if not context.args:
        await update.effective_message.reply_text(f"Usage: /{action}server <id>")
        return
    try:
        sid = int(context.args[0])
    except ValueError:
        await update.effective_message.reply_text("Invalid id")
        return
    try:
        r = await api("POST", f"/api/bot/servers/{sid}/{action}")
        await update.effective_message.reply_text(f"{action}: {r.get('message', 'ok')}")
    except Exception as e:
        await update.effective_message.reply_text(str(e))


async def cmd_console(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    if not context.args:
        await update.effective_message.reply_text("Usage: /console <id>")
        return
    await screen_console(update, int(context.args[0]), edit=False)


async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    await screen_users(update, 0, edit=False)


async def cmd_system(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    await screen_system(update, edit=False)


async def cmd_audit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    await screen_audit(update, edit=False)


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if not q:
        return
    await q.answer()
    uid = update.effective_user.id if update.effective_user else None
    if not is_allowed(uid):
        await deny(update)
        return

    data = q.data or ""
    parts = data.split(":")

    if data in ("menu:home", "menu:panel"):
        await screen_home(update, context, edit=True)
        return
    if data == "menu:dash":
        await screen_dashboard(update, edit=True)
        return
    if parts[0] == "menu" and parts[1] == "servers":
        page = int(parts[2]) if len(parts) > 2 else 0
        await screen_servers(update, page, edit=True)
        return
    if parts[0] == "menu" and parts[1] == "users":
        page = int(parts[2]) if len(parts) > 2 else 0
        await screen_users(update, page, edit=True)
        return
    if data == "menu:system":
        await screen_system(update, edit=True)
        return
    if data == "menu:audit":
        await screen_audit(update, edit=True)
        return
    if data == "menu:maint":
        await screen_maint(update, edit=True)
        return

    if parts[0] == "maint" and len(parts) == 2:
        state = parts[1]
        try:
            await api("POST", f"/api/bot/maintenance/{state}")
            await screen_maint(update, edit=True)
        except Exception as e:
            await send(update, str(e), kb_back_home(), True)
        return

    if parts[0] == "user" and len(parts) == 2:
        await screen_user(update, int(parts[1]), edit=True)
        return

    if parts[0] == "useract" and len(parts) == 3:
        uid_t, act = int(parts[1]), parts[2]
        try:
            if act == "enable":
                await api("POST", f"/api/bot/users/{uid_t}/enable")
            else:
                await api("POST", f"/api/bot/users/{uid_t}/suspend")
            await screen_user(update, uid_t, edit=True)
        except Exception as e:
            await send(update, str(e), kb_back_home(), True)
        return

    if parts[0] == "confirm" and len(parts) == 3:
        action, sid = parts[1], int(parts[2])
        await send(
            update,
            f"CONFIRM ACTION\n\nServer: #{sid}\nAction: {action}\n\nThis cannot be undone easily.",
            kb_confirm(action, sid),
            True,
        )
        return

    if parts[0] == "do" and len(parts) == 3:
        action, sid = parts[1], int(parts[2])
        try:
            if action == "kill":
                # web kill endpoint requires session; use stop via bot API
                await api("POST", f"/api/bot/servers/{sid}/stop")
                msg = "Stop/kill requested"
            elif action == "delete":
                await api("DELETE", f"/api/bot/servers/{sid}")
                msg = "Server deleted"
                await send(update, msg, InlineKeyboardMarkup([[InlineKeyboardButton("Servers", callback_data="menu:servers:0")]]), True)
                return
            else:
                msg = "Unknown"
            await send(update, msg, kb_server(sid), True)
        except Exception as e:
            await send(update, str(e), kb_server(sid), True)
        return

    if parts[0] == "srv" and len(parts) >= 3:
        sid = int(parts[1])
        action = parts[2]
        if action == "info":
            await screen_server_info(update, sid, edit=True)
            return
        if action == "console" or action == "logs":
            await screen_console(update, sid, edit=True)
            return
        if action in ("start", "stop", "restart"):
            try:
                r = await api("POST", f"/api/bot/servers/{sid}/{action}")
                await send(update, f"{action}: {r.get('message', 'ok')}", kb_server(sid), True)
            except Exception as e:
                await send(update, str(e), kb_server(sid), True)
            return
        if action == "deploy":
            try:
                # use web-compatible path via bot if available; fallback message
                await api("POST", f"/api/bot/servers/{sid}/restart")
                await send(update, "Deploy approximated: dependencies reinstall on next start + restart issued.", kb_server(sid), True)
            except Exception as e:
                await send(update, str(e), kb_server(sid), True)
            return
        if action == "backup":
            await send(update, "Create backup from the web panel (Files are large for Telegram).", kb_server(sid), True)
            return
        if action == "diag":
            try:
                s = await api("GET", f"/api/bot/servers/{sid}")
                text = (
                    f"DIAGNOSTICS #{sid}\n\n"
                    f"Status: {s.get('status')}\n"
                    f"Runtime: {s.get('runtime')}\n"
                    f"Port: {s.get('port')}\n"
                    f"CPU: {s.get('cpu_percent')}%\n"
                    f"RAM: {s.get('ram_mb')} MB\n"
                    f"Storage: {s.get('storage_mb')} MB\n"
                )
                await send(update, text, kb_server(sid), True)
            except Exception as e:
                await send(update, str(e), kb_server(sid), True)
            return



async def cmd_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Link this Telegram account to a hosting username: /link <username>"""
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    if not context.args:
        await update.effective_message.reply_text("Usage: /link <hosting_username>")
        return
    username = context.args[0]
    tid = update.effective_user.id
    try:
        from telegram import constants
        await api("POST", "/api/bot/telegram/link", data={"telegram_id": tid, "username": username})
        await update.effective_message.reply_text(f"Linked Telegram {tid} to user {username}")
    except Exception as e:
        await update.effective_message.reply_text(str(e))


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id if update.effective_user else None):
        await deny(update)
        return
    q = " ".join(context.args) if context.args else ""
    if not q:
        await update.effective_message.reply_text("Usage: /search <query>")
        return
    try:
        servers = await api("GET", "/api/bot/servers/search", params={"q": q})
        users = await api("GET", "/api/bot/users/search", params={"q": q})
        lines = ["SEARCH\n"]
        lines.append("Servers:")
        for s in (servers or [])[:10]:
            lines.append(f"  #{s.get('id')} {s.get('name')} [{s.get('status')}]")
        lines.append("Users:")
        for u in (users or [])[:10]:
            lines.append(f"  #{u.get('id')} {u.get('username')}")
        await update.effective_message.reply_text("\n".join(lines))
    except Exception as e:
        await update.effective_message.reply_text(str(e))


def main():
    load_admins()
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("panel", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("dashboard", cmd_dashboard))
    app.add_handler(CommandHandler("servers", cmd_servers))
    app.add_handler(CommandHandler("server", cmd_server))
    app.add_handler(CommandHandler("status", cmd_dashboard))
    app.add_handler(CommandHandler("users", cmd_users))
    app.add_handler(CommandHandler("system", cmd_system))
    app.add_handler(CommandHandler("audit", cmd_audit))
    app.add_handler(CommandHandler("link", cmd_link))
    app.add_handler(CommandHandler("search", cmd_search))
    app.add_handler(CommandHandler("console", cmd_console))
    app.add_handler(CommandHandler("logs", cmd_console))
    app.add_handler(CommandHandler("startserver", lambda u, c: cmd_action(u, c, "start")))
    app.add_handler(CommandHandler("stopserver", lambda u, c: cmd_action(u, c, "stop")))
    app.add_handler(CommandHandler("restartserver", lambda u, c: cmd_action(u, c, "restart")))
    app.add_handler(CallbackQueryHandler(on_callback))

    log.info("FLIX HOST Telegram Control Center starting")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
