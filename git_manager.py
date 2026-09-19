"""
FLIX HOST - Git helper
Best-effort git clone/pull when `git` binary exists on the host.
Never fakes success.
"""
import asyncio
import shutil
from pathlib import Path

from db import get_db, now_iso, server_path, log_action


def git_available() -> bool:
    return shutil.which("git") is not None


async def _run(cmd: list[str], cwd: str | None = None) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    return proc.returncode or 0, (out or b"").decode(errors="replace")


async def git_clone(server_id: int, url: str, branch: str = "main") -> tuple[bool, str]:
    if not git_available():
        return False, "git binary not available on this host"
    url = (url or "").strip()
    if not url.startswith(("https://", "git@")):
        return False, "Only https:// or git@ URLs allowed"
    d = server_path(server_id)
    d.mkdir(parents=True, exist_ok=True)
    # if already a git repo, pull instead
    if (d / ".git").exists():
        return await git_pull(server_id, branch)
    code, out = await _run(["git", "clone", "--depth", "1", "--branch", branch or "main", url, str(d)])
    if code != 0:
        # empty dir clone into .
        if any(d.iterdir()):
            return False, out[-1500:] or f"git clone failed ({code})"
        code, out = await _run(["git", "clone", "--depth", "1", "--branch", branch or "main", url, "."], cwd=str(d))
    if code != 0:
        return False, out[-1500:] or f"git clone failed ({code})"
    conn = get_db()
    conn.execute(
        "UPDATE servers SET git_url = ?, git_branch = ? WHERE id = ?",
        (url, branch or "main", server_id),
    )
    conn.commit()
    conn.close()
    return True, "cloned"


async def git_pull(server_id: int, branch: str | None = None) -> tuple[bool, str]:
    if not git_available():
        return False, "git binary not available on this host"
    d = server_path(server_id)
    if not (d / ".git").exists():
        return False, "Not a git repository"
    br = branch
    if not br:
        conn = get_db()
        row = conn.execute("SELECT git_branch FROM servers WHERE id = ?", (server_id,)).fetchone()
        conn.close()
        br = (row["git_branch"] if row else None) or "main"
    code, out = await _run(["git", "fetch", "--depth", "1", "origin", br], cwd=str(d))
    if code != 0:
        return False, out[-1500:]
    code2, out2 = await _run(["git", "reset", "--hard", f"origin/{br}"], cwd=str(d))
    if code2 != 0:
        return False, out2[-1500:]
    return True, "pulled"


async def git_info(server_id: int) -> dict:
    d = server_path(server_id)
    info = {"available": git_available(), "is_repo": (d / ".git").exists(), "commit": None, "branch": None}
    if not info["is_repo"] or not info["available"]:
        return info
    c1, o1 = await _run(["git", "rev-parse", "--short", "HEAD"], cwd=str(d))
    c2, o2 = await _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(d))
    if c1 == 0:
        info["commit"] = o1.strip()
    if c2 == 0:
        info["branch"] = o2.strip()
    return info
