# Deploy FLIX HOST on Railway

## 1. Create project
- New Project → Deploy from GitHub (or upload ZIP / empty + CLI)

## 2. Required Variables (Railway → Variables)
```
NEXUS_SECRET=<run: python -c "import secrets; print(secrets.token_hex(48))">
NEXUS_ADMIN_USER=your_admin_username
NEXUS_ADMIN_PASSWORD=strong_password_here
PUBLIC_BASE_URL=https://YOUR-PROJECT.up.railway.app
```

Optional Telegram:
```
BOT_TOKEN=...
NEXUS_BOT_API_KEY=<random secret>
NEXUS_API_URL=https://YOUR-PROJECT.up.railway.app
TELEGRAM_ADMIN_IDS=123456789
```

## 3. Start command
Already in `railway.json` / `Procfile`:
```
uvicorn app:app --host 0.0.0.0 --port $PORT
```

## 4. Public URLs for user apps
After a server is **Running**, it is reachable at:

```
https://YOUR-PROJECT.up.railway.app/p/{SERVER_ID}/
```

Example: server id `3` → `https://xxx.up.railway.app/p/3/`

Custom domain (optional):
1. Add custom domain in Railway dashboard
2. Set `PUBLIC_BASE_URL=https://yourdomain.com`
3. Users can also set a per-server domain (DNS must point to Railway)

## 5. Notes
- Only the main service port is public; internal process ports are proxied via `/p/{id}/`
- SQLite + local files work on a single Railway service (data lives in the container filesystem — use a Volume if you need persistence across redeploys)
- Node.js + Python runtimes are installed in the Dockerfile

## 6. First login
Open the Railway URL → login with `NEXUS_ADMIN_USER` / `NEXUS_ADMIN_PASSWORD`
