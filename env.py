# ==== FLIX HOST / NEXUS — Environment Variables ====
# Copy to .env for local, or set in Railway Variables tab.
# NEVER commit a real .env with secrets.

# Session signing key - generate with:
#   python -c "import secrets; print(secrets.token_hex(48))"
NEXUS_SECRET=

# Initial admin (created on first boot)
NEXUS_ADMIN_USER=flix123@
NEXUS_ADMIN_PASSWORD=nexus@flix@200xx

# Optional: Telegram bot
BOT_TOKEN=
NEXUS_API_URL=http://127.0.9.0.1:8000
NEXUS_BOT_API_KEY=
TELEGRAM_ADMIN_IDS=

# Public base URL of this deployment (important for Railway + proxy links)
# Example after deploy: https://your-project.up.railway.app
# Or your custom domain: https://host.yourdomain.com
PUBLIC_BASE_URL=

# Railway injects PORT automatically — do not set in production
PORT=8000
