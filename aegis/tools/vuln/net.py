"""Network vulnerability scanning: Hydra brute-force + SMB + WAF detection."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import click
import httpx
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json, run_command, which


# ── Default credential lists ──────────────────────────────────────────────────

DEFAULT_CREDS: Dict[str, List[str]] = {
    "ftp":      ["anonymous:", "admin:admin", "root:root", "ftp:ftp"],
    "ssh":      ["root:root", "root:toor", "admin:admin", "admin:password", "user:password"],
    "telnet":   ["admin:admin", "root:root", "admin:"],
    "mysql":    ["root:root", "root:", "admin:admin"],
    "postgres": ["postgres:postgres", "postgres:", "admin:admin"],
    "rdp":      ["administrator:password", "admin:admin"],
    "smb":      ["administrator:password", "admin:admin", "guest:"],
    "http-get": ["admin:admin", "admin:password", "root:root"],
}

# ── WAF fingerprints ──────────────────────────────────────────────────────────

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":       ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF":          ["awswaf", "x-amzn-requestid"],
    "Akamai":           ["akamai", "akamaighost"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP ASM":    ["ts=", "f5-trafficshield"],
    "Sucuri":           ["sucuri", "x-sucuri-id"],
    "ModSecurity":      ["mod_security", "modsecurity", "NOYB"],
    "Barracuda":        ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
    "Fortinet":         ["fortigate", "fortiweb"],
    "Nginx WAF":        ["nginx", "x-nginx"],
}


def _detect_waf(url: str, timeout: int) -> Optional[str]:
    """Detect WAF by sending a probe request and analysing headers/body."""
    try:
        # Send a benign request first
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:  # noqa: S501
            resp = client.get(url)

        headers_str = " ".join(
            f"{k.lower()}:{v.lower()}" for k, v in resp.headers.items()
        )
        body_lower = resp.text[:2000].lower()
        combined = headers_str + " " + body_lower

        for waf_name, signatures in WAF_SIGNATURES.items():
            if any(sig.lower() in combined for sig in signatures):
                return waf_name

        # Send a malicious-looking probe to trigger WAF
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:  # noqa: S501
            probe = client.get(url, params={"q": "' OR 1=1--"})

        if probe.status_code in (403, 406, 429, 503):
            probe_headers = " ".join(
                f"{k.lower()}:{v.lower()}" for k, v in probe.headers.items()
            )
            probe_body = probe.text[:2000].lower()
            probe_combined = probe_headers + " " + probe_body
            for waf_name, signatures in WAF_SIGNATURES.items():
                if any(sig.lower() in probe_combined for sig in signatures):
                    return waf_name
            # Generic WAF detection by status code change
            if probe.status_code != resp.status_code and probe.status_code in (403, 406):
                return "Unknown WAF (blocked probe)"

    except Exception:
        pass
    return None


def _parse_smb_shares(output: str) -> List[str]:
    shares: List[str] = []
    for line in output.splitlines():
        if "Disk" in line:
            parts = line.split()
            if parts:
                shares.append(parts[0])
    return shares


def _parse_hydra_output(output: str) -> List[Dict[str, str]]:
    """Parse hydra output for found credentials."""
    found: List[Dict[str, str]] = []
    # Hydra success lines: [port][service] host: X login: Y password: Z
    pattern = re.compile(
        r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            found.append({
                "port": match.group(1),
                "service": match.group(2),
                "host": match.group(3),
                "login": match.group(4),
                "password": match.group(5),
            })
    return found


def _get_timeout(config: object, profile: str) -> int:
    from aegis.core.config_manager import ConfigManager
    cfg = config if isinstance(config, ConfigManager) else None
    if cfg is None:
        return 30
    val = cfg.get(f"profiles.{profile}.timeout", cfg.get("general.default_timeout", 30))
    return int(val) if val is not None else 30


@click.command("net")
@click.argument("target_ip")
@click.option("--no-brute", is_flag=True, help="Skip Hydra brute-force.")
@click.option("--no-smb", is_flag=True, help="Skip SMB enumeration.")
@click.option("--no-waf", is_flag=True, help="Skip WAF detection.")
@click.option("--service", default="ssh", show_default=True,
              type=click.Choice(list(DEFAULT_CREDS.keys()) + ["all"]),
              help="Service to brute-force.")
@click.option("--userlist", default=None, help="Custom username list file.")
@click.option("--passlist", default=None, help="Custom password list file.")
@click.option("--url", "target_url", default=None,
              help="HTTP URL for WAF detection (e.g. http://target).")
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.option("--force", is_flag=True, help="Bypass safe-mode check.")
@click.pass_context
def cli(
    ctx: click.Context,
    target_ip: str,
    no_brute: bool,
    no_smb: bool,
    no_waf: bool,
    service: str,
    userlist: Optional[str],
    passlist: Optional[str],
    target_url: Optional[str],
    json_out: bool,
    json_output: Optional[str],
    force: bool,
) -> None:
    """Network vulnerability scanning: brute-force, SMB enum, WAF detection."""
    context = ctx.obj
    config = context.config
    db = context.db
    profile = context.profile
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)
    target_id = db.upsert_target(target_ip)

    if config.get("general.safe_mode", True) and not force:
        console.print(
            "[yellow]Safe mode is on. Brute-force requires [cyan]--force[/cyan].[/yellow]"
        )
        no_brute = True

    hydra_cmd = config.get("external_tools.hydra", "hydra")
    smb_cmd = config.get("external_tools.smbclient", "smbclient")
    timeout = _get_timeout(config, profile)

    results: Dict[str, object] = {
        "target": target_ip,
        "waf": None,
        "smb_shares": [],
        "credentials_found": [],
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        # ── WAF Detection ─────────────────────────────────────────────────────
        if not no_waf:
            url_to_probe = target_url or f"http://{target_ip}"
            task = progress.add_task(f"WAF detection on {url_to_probe}", total=None)
            waf = _detect_waf(url_to_probe, timeout=10)
            progress.remove_task(task)

            results["waf"] = waf
            if waf:
                console.print(f"[bold red]WAF detected:[/bold red] {waf}")
                fid = db.add_finding(
                    target_id=target_id, host_id=None, port_id=None,
                    title=f"WAF detected: {waf}",
                    severity="info",
                    category="network",
                    description=f"WAF '{waf}' detected on {url_to_probe}. Adjust payloads accordingly.",
                    source="waf-detect",
                )
                if fid:
                    db.add_evidence(fid, "waf_name", waf)
                    db.add_evidence(fid, "url", url_to_probe)
            else:
                console.print("[green]No WAF detected.[/green]")

        # ── SMB Enumeration ───────────────────────────────────────────────────
        if not no_smb:
            task = progress.add_task("SMB share enumeration", total=None)
            shares: List[str] = []
            if not which(smb_cmd):
                console.print(f"[yellow]smbclient not found: {smb_cmd}[/yellow]")
            else:
                code, out, err = run_command(
                    [smb_cmd, "-L", f"//{target_ip}", "-N"], timeout=timeout
                )
                if code == 0:
                    shares = _parse_smb_shares(out)
            progress.remove_task(task)

            results["smb_shares"] = shares
            if shares:
                t = Table(title="SMB Shares")
                t.add_column("Share", style="green")
                for share in shares:
                    t.add_row(share)
                console.print(t)
                host_id = db.upsert_host(target_ip)
                fid = db.add_finding(
                    target_id=target_id, host_id=host_id, port_id=None,
                    title="SMB shares accessible",
                    severity="medium",
                    category="network",
                    description=f"Shares: {', '.join(shares)}",
                    source="smbclient",
                )
                if fid:
                    db.add_evidence(fid, "shares", ", ".join(shares))
            else:
                console.print("[dim]No SMB shares found.[/dim]")

        # ── Hydra Brute-Force ─────────────────────────────────────────────────
        if not no_brute:
            if not which(hydra_cmd):
                console.print(f"[yellow]hydra not found: {hydra_cmd}[/yellow]")
            else:
                services_to_test = (
                    list(DEFAULT_CREDS.keys()) if service == "all" else [service]
                )

                all_creds: List[Dict[str, str]] = []

                for svc in services_to_test:
                    task = progress.add_task(
                        f"Hydra brute-force: {svc} on {target_ip}", total=None
                    )

                    # Build command
                    cmd = [hydra_cmd, "-t", "4", "-f"]

                    if userlist:
                        cmd += ["-L", userlist]
                    else:
                        # Write default usernames to temp file
                        import tempfile
                        cred_pairs = DEFAULT_CREDS.get(svc, ["admin:admin"])
                        users = list({c.split(":")[0] for c in cred_pairs})
                        passwords = list({c.split(":")[1] for c in cred_pairs if ":" in c})

                        with tempfile.NamedTemporaryFile(
                            mode="w", suffix=".txt", delete=False
                        ) as uf:
                            uf.write("\n".join(users))
                            user_tmp = uf.name
                        cmd += ["-L", user_tmp]

                    if passlist:
                        cmd += ["-P", passlist]
                    else:
                        with tempfile.NamedTemporaryFile(
                            mode="w", suffix=".txt", delete=False
                        ) as pf:
                            pf.write("\n".join(passwords))
                            pass_tmp = pf.name
                        cmd += ["-P", pass_tmp]

                    cmd += [target_ip, svc]

                    code, out, err = run_command(cmd, timeout=timeout)
                    progress.remove_task(task)

                    # Clean up temp files
                    import os
                    for tmp in [user_tmp, pass_tmp]:
                        try:
                            os.unlink(tmp)
                        except Exception:
                            pass

                    creds = _parse_hydra_output(out)
                    all_creds.extend(creds)

                    if creds:
                        for cred in creds:
                            console.print(
                                f"[bold red]CREDENTIAL FOUND:[/bold red] "
                                f"{cred['service']}://{cred['login']}:{cred['password']}@{target_ip}"
                            )
                            host_id = db.upsert_host(target_ip)
                            fid = db.add_finding(
                                target_id=target_id, host_id=host_id, port_id=None,
                                title=f"Credential found: {svc} on {target_ip}",
                                severity="high",
                                category="network",
                                description=(
                                    f"Service: {svc}\n"
                                    f"Login: {cred['login']}\n"
                                    f"Password: {cred['password']}"
                                ),
                                source="hydra",
                            )
                            if fid:
                                db.add_evidence(
                                    fid, "credential",
                                    f"{cred['login']}:{cred['password']}"
                                )

                results["credentials_found"] = all_creds

                if not all_creds:
                    console.print("[dim]No credentials found.[/dim]")

    if json_out:
        emit_json(results, json_output)
        return

    # Summary
    waf_val = results.get("waf")
    creds_val = results.get("credentials_found", [])
    shares_val = results.get("smb_shares", [])
    console.print(
        f"\n[primary]Network scan complete.[/primary] "
        f"WAF: {waf_val or 'none'}  "
        f"Shares: {len(shares_val)}  "  # type: ignore[arg-type]
        f"Credentials: {len(creds_val)}"  # type: ignore[arg-type]
    )
