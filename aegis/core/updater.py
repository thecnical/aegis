from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from aegis.core.ui import console
from aegis.core.utils import ensure_dir, run_command, which


def update_nuclei_templates(nuclei_cmd: str) -> Dict[str, str]:
    if not which(nuclei_cmd):
        return {"status": "missing", "tool": nuclei_cmd}
    code, out, err = run_command([nuclei_cmd, "-update-templates"])
    if code != 0:
        return {"status": "failed", "error": err or out}
    return {"status": "ok", "detail": out or "updated"}


def update_wordlists(repo_url: str, dest_path: str) -> Dict[str, str]:
    if not which("git"):
        return {"status": "missing", "tool": "git"}

    dest = Path(dest_path)
    ensure_dir(dest.parent.as_posix())

    if not dest.exists():
        code, out, err = run_command(["git", "clone", repo_url, str(dest)])
        if code != 0:
            return {"status": "failed", "error": err or out}
        _write_wordlist_version(dest, repo_url)
        return {"status": "ok", "detail": "cloned"}

    code, out, err = run_command(["git", "-C", str(dest), "pull"])
    if code != 0:
        return {"status": "failed", "error": err or out}
    _write_wordlist_version(dest, repo_url)
    return {"status": "ok", "detail": "updated"}


def _write_wordlist_version(dest: Path, repo_url: str) -> None:
    code, out, _ = run_command(["git", "-C", str(dest), "rev-parse", "HEAD"])
    commit = out.strip() if code == 0 else "unknown"
    version_path = dest / ".aegis.json"
    payload = {
        "repo": repo_url,
        "commit": commit,
    }
    version_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def print_update_summary(results: Dict[str, Dict[str, str]]) -> None:
    for key, result in results.items():
        status = result.get("status", "unknown")
        if status == "ok":
            console.print(f"[primary]{key}[/primary]: {result.get('detail', 'ok')}")
        elif status == "missing":
            console.print(f"[warning]{key} missing tool:[/warning] {result.get('tool')}")
        else:
            console.print(f"[error]{key} failed:[/error] {result.get('error')}")


def get_wordlist_status(dest_path: str) -> Dict[str, str]:
    dest = Path(dest_path)
    version_path = dest / ".aegis.json"
    if not version_path.exists():
        return {"status": "unknown"}
    try:
        data = json.loads(version_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "unknown"}
    data["status"] = "ok"
    return data
