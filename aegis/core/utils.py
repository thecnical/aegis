from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

from aegis.core.ui import console
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from aegis.core.parsers import parse_nmap_xml



def ensure_url(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme:
        return target
    return f"https://{target}"


def which(tool: str) -> Optional[str]:
    from shutil import which as _which

    return _which(tool)


def run_command(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"
    except OSError as exc:
        return 1, "", str(exc)


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def parse_json_lines(raw: str) -> List[Dict[str, object]]:
    items: List[Dict[str, object]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            items.append(data)
    return items


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def emit_json(data: "Mapping[str, object]", output_path: Optional[str] = None) -> None:
    payload = json.dumps(data, indent=2)
    if output_path:
        Path(output_path).write_text(payload, encoding="utf-8")
    else:
        console.print_json(payload)


def get_http_session(retries: int = 3, backoff: float = 0.3) -> Session:
    session = Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


__all__ = [
    "ensure_url",
    "which",
    "run_command",
    "resolve_host",
    "parse_nmap_xml",
    "parse_json_lines",
    "ensure_dir",
    "emit_json",
    "get_http_session",
]
