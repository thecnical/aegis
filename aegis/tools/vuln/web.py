"""Web vulnerability scanning with HTTP evidence capture."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import click
import httpx
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aegis.core.parsers import parse_nuclei_json_lines
from aegis.core.ui import console
from aegis.core.utils import emit_json, parse_json_lines, run_command, which


def _get_timeout(config: object, profile: str) -> int:
    from aegis.core.config_manager import ConfigManager
    cfg = config if isinstance(config, ConfigManager) else None
    if cfg is None:
        return 30
    val = cfg.get(f"profiles.{profile}.timeout", cfg.get("general.default_timeout", 30))
    return int(val) if val is not None else 30


def _get_ferox_depth(config: object, profile: str) -> int:
    from aegis.core.config_manager import ConfigManager
    cfg = config if isinstance(config, ConfigManager) else None
    if cfg is None:
        return 2
    val = cfg.get(f"profiles.{profile}.ferox_depth", 2)
    return int(val) if val is not None else 2


def _get_nuclei_rate(config: object, profile: str) -> int:
    from aegis.core.config_manager import ConfigManager
    cfg = config if isinstance(config, ConfigManager) else None
    if cfg is None:
        return 150
    val = cfg.get(f"profiles.{profile}.nuclei_rate", 150)
    return int(val) if val is not None else 150


def _capture_http_evidence(
    url: str,
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Make an HTTP request and capture full request/response as evidence."""
    evidence: Dict[str, Any] = {
        "request": "",
        "response_status": 0,
        "response_headers": {},
        "response_body_snippet": "",
        "error": None,
    }
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,  # noqa: S501
            headers=headers or {},
            cookies=cookies or {},
        ) as client:
            resp = client.get(url, params=params or {})

        # Build request string
        req_headers = "\r\n".join(
            f"{k}: {v}" for k, v in resp.request.headers.items()
        )
        evidence["request"] = (
            f"GET {resp.request.url} HTTP/1.1\r\n"
            f"{req_headers}\r\n\r\n"
        )
        evidence["response_status"] = resp.status_code
        evidence["response_headers"] = dict(resp.headers)
        evidence["response_body_snippet"] = resp.text[:1000]
    except Exception as exc:
        evidence["error"] = str(exc)
    return evidence


def _run_nuclei_with_evidence(
    url: str,
    nuclei_cmd: str,
    rate: int,
    timeout: int,
    cookies: Optional[str],
    headers: Optional[List[str]],
    tags: Optional[str],
) -> List[Dict[str, Any]]:
    """Run nuclei and return findings with HTTP evidence."""
    cmd = [nuclei_cmd, "-u", url, "-json", "-silent", "-rate-limit", str(rate)]

    if cookies:
        cmd += ["-H", f"Cookie: {cookies}"]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    if tags:
        cmd += ["-tags", tags]

    code, out, err = run_command(cmd, timeout=timeout)
    findings = parse_nuclei_json_lines(out)

    # Enrich each finding with HTTP evidence
    enriched: List[Dict[str, Any]] = []
    for f in findings:
        target_url = str(f.get("target") or url)
        evidence = _capture_http_evidence(target_url, timeout=10)
        enriched.append({**f, "http_evidence": evidence})

    return enriched


@click.command("web")
@click.argument("url")
@click.option("--no-dir-scan", is_flag=True, help="Skip directory scan.")
@click.option("--no-nuclei", is_flag=True, help="Skip nuclei scan.")
@click.option("--cookies", default=None, help="Session cookies (e.g. 'session=abc123').")
@click.option("--header", "extra_headers", multiple=True,
              help="Extra headers (e.g. 'Authorization: Bearer token'). Repeatable.")
@click.option("--tags", default=None, help="Nuclei template tags to run (e.g. 'cve,sqli').")
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    url: str,
    no_dir_scan: bool,
    no_nuclei: bool,
    cookies: Optional[str],
    extra_headers: tuple,
    tags: Optional[str],
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Web vulnerability scanning with HTTP evidence capture."""
    context = ctx.obj
    config = context.config
    db = context.db
    profile = context.profile
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)
    target_id = db.upsert_target(url)

    ferox_cmd = config.get("external_tools.feroxbuster", "feroxbuster")
    nuclei_cmd = config.get("external_tools.nuclei", "nuclei")
    timeout = _get_timeout(config, profile)

    dir_findings: List[str] = []
    nuclei_findings: List[Dict[str, Any]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        # ── Directory scan ────────────────────────────────────────────────────
        if not no_dir_scan:
            task = progress.add_task("feroxbuster directory scan", total=None)
            if not which(ferox_cmd):
                console.print(f"[yellow]feroxbuster not found: {ferox_cmd}[/yellow]")
            else:
                depth = _get_ferox_depth(config, profile)
                cmd = [ferox_cmd, "-u", url, "-q", "--json", "--depth", str(depth)]
                if cookies:
                    cmd += ["-b", cookies]
                for h in extra_headers:
                    cmd += ["-H", h]

                code, out, err = run_command(cmd, timeout=timeout)
                if code not in (0, 1):
                    console.print(f"[yellow]feroxbuster exited {code}[/yellow]")
                else:
                    for item in parse_json_lines(out):
                        path = item.get("url") or item.get("target")
                        status = int(item.get("status", 0))
                        if path and status in (200, 201, 204, 301, 302, 403, 405):
                            dir_findings.append(str(path))
                            # Capture HTTP evidence for interesting paths
                            if status in (200, 201):
                                ev = _capture_http_evidence(str(path), timeout=5)
                                fid = db.add_finding(
                                    target_id=target_id, host_id=None, port_id=None,
                                    title=f"Discovered: {path}",
                                    severity="info",
                                    category="recon",
                                    description=f"Status: {status}  Length: {item.get('length', '?')}",
                                    source="feroxbuster",
                                )
                                if fid:
                                    db.add_evidence(fid, "request", ev["request"][:500])
                                    db.add_evidence(fid, "response_status", str(status))
                                    if ev["response_body_snippet"]:
                                        db.add_evidence(
                                            fid, "response_snippet",
                                            ev["response_body_snippet"][:300]
                                        )
            progress.remove_task(task)

        # ── Nuclei scan ───────────────────────────────────────────────────────
        if not no_nuclei:
            task = progress.add_task("nuclei vulnerability scan", total=None)
            if not which(nuclei_cmd):
                console.print(f"[yellow]nuclei not found: {nuclei_cmd}[/yellow]")
            else:
                rate = _get_nuclei_rate(config, profile)
                nuclei_findings = _run_nuclei_with_evidence(
                    url, nuclei_cmd, rate, timeout,
                    cookies, list(extra_headers), tags,
                )
            progress.remove_task(task)

    # ── Store nuclei findings with evidence ───────────────────────────────────
    for finding in nuclei_findings:
        name = str(finding.get("name") or "Nuclei finding")
        severity = str(finding.get("severity") or "info").lower()
        target = str(finding.get("target") or url)
        template_id = str(finding.get("template_id") or "")
        refs = finding.get("references")
        http_ev = finding.get("http_evidence", {})

        fid = db.add_finding(
            target_id=target_id, host_id=None, port_id=None,
            title=name,
            severity=severity,
            category="vuln",
            description=f"Template: {template_id}\nTarget: {target}",
            source="nuclei",
        )
        if fid:
            db.add_evidence(fid, "target", target)
            if refs:
                db.add_evidence(fid, "references", str(refs))
            # Store HTTP evidence
            if http_ev.get("request"):
                db.add_evidence(fid, "http_request", http_ev["request"][:1000])
            if http_ev.get("response_status"):
                db.add_evidence(fid, "http_response_status", str(http_ev["response_status"]))
            if http_ev.get("response_body_snippet"):
                db.add_evidence(fid, "http_response_snippet", http_ev["response_body_snippet"][:500])

    # ── Output ────────────────────────────────────────────────────────────────
    json_results: Dict[str, Any] = {
        "url": url,
        "dir_findings": sorted(set(dir_findings)),
        "nuclei_findings": [
            {k: v for k, v in f.items() if k != "http_evidence"}
            for f in nuclei_findings
        ],
    }

    if json_out:
        emit_json(json_results, json_output)
        return

    if dir_findings:
        t = Table(title=f"Directory Scan ({len(dir_findings)} paths)")
        t.add_column("Path", style="cyan")
        for path_str in sorted(set(dir_findings))[:100]:
            t.add_row(path_str)
        console.print(t)

    if nuclei_findings:
        t = Table(title=f"Nuclei Findings ({len(nuclei_findings)})")
        t.add_column("Name", style="green")
        t.add_column("Severity", style="magenta")
        t.add_column("Target", style="cyan")
        t.add_column("Evidence", style="dim")
        for f in nuclei_findings:
            ev = f.get("http_evidence", {})
            ev_str = f"HTTP {ev.get('response_status', '?')}" if ev.get("response_status") else ""
            t.add_row(
                str(f.get("name", "")),
                str(f.get("severity", "")),
                str(f.get("target", ""))[:60],
                ev_str,
            )
        console.print(t)

    if not dir_findings and not nuclei_findings:
        console.print("[yellow]No findings.[/yellow]")

    console.print(
        f"[primary]Web scan complete.[/primary] "
        f"{len(dir_findings)} paths, {len(nuclei_findings)} vuln(s)"
    )
