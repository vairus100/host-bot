"""
Nexus HOST - Alert helpers
Push notifications to DB + optional Telegram for authorized admins.
"""
import os
import httpx
from db import create_notification, get_db, get_setting


def notify_user(user_id: int | None, title: str, body: str, level: str = "warning",
                category: str = "system", server_id: int | None = None):
    create_notification(user_id, title, body, level, category, server_id)


def telegram_admin_ids() -> list[int]:
    ids = set()
    for x in os.getenv("TELEGRAM_ADMIN_IDS", "").split(","):
        if x.strip():
            ids.add(int(x.strip()))
    try:
        saved = get_setting("telegram_admin_ids", "")
        for x in saved.split(","):
            if x.strip():
                ids.add(int(x.strip()))
    except Exception:
        pass
    return list(ids)


def push_telegram_alert(text: str):
    token = os.getenv("BOT_TOKEN")
    if not token:
        return
    for chat_id in telegram_admin_ids():
        try:
            httpx.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text[:3500]},
                timeout=10,
            )
        except Exception:
            pass


def alert_server_event(server_id: int, title: str, body: str, level: str = "warning"):
    conn = get_db()
    row = conn.execute("SELECT user_id, name FROM servers WHERE id = ?", (server_id,)).fetchone()
    conn.close()
    uid = row["user_id"] if row else None
    name = row["name"] if row else str(server_id)
    notify_user(uid, title, f"{name}: {body}", level, "server", server_id)
    push_telegram_alert(f"Nexus HOST ALERT\n{title}\nServer: {name} (#{server_id})\n{body}")
