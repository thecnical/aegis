"""OSINT collection using theHarvester with structured output parsing."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List

import click
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json, which


def _run_harvester(target: str, sources: str, timeout: int) -> Dict[str, List[str]]:
    """Run theHarvester and return structured results."""
    harvester = which("theHarvester") or which("theharvester")
    if not harvester:
        console.print(
            "[yellow]theHarvester not found.[/yellow] "
            "Install: [cyan]sudo apt install theharvester[/cyan]"
        )
        return {}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        tmp_path = f.name

    cmd = [
        harvester, "-d", target, "-b", sources,
        "-l", "200", "-f", tmp_path,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        console.print("[yellow]theHarvester timed out.[/yellow]")
        return {}
    except OSError as exc:
        console.print(f"[error]theHarvester failed: {exc}[/error]")
        return {}

    # Try JSON output first
    json_file = Path(tmp_path + ".json")
    if json_file.exists():
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            json_file.unlink(missing_ok=True)
            Path(tmp_path).unlink(missing_ok=True)
            return {
                "emails": list(data.get("emails", [])),
                "hosts": list(data.get("hosts", [])),
                "ips": list(data.get("ips", [])),
                "urls": list(data.get("urls", [])),
            }
        except (json.JSONDecodeError, OSError):
            pass

    Path(tmp_path).unlink(missing_ok=True)

    # Fall back to text parsing
    return _parse_harvester_text(output)


def _parse_harvester_text(output: str) -> Dict[str, List[str]]:
    """Parse theHarvester text output into structured data."""
    results: Dict[str, List[str]] = {
        "emails": [],
        "hosts": [],
        "ips": [],
        "urls": [],
        "linkedin": [],
    }

    email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_re = re.compile(r"https?://[^\s]+")
    linkedin_re = re.compile(r"linkedin\.com/in/[^\s]+", re.IGNORECASE)

    section = None
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Section headers
        if "Emails found" in line or "[*] Emails" in line:
            section = "emails"
            continue
        elif "Hosts found" in line or "[*] Hosts" in line:
            section = "hosts"
            continue
        elif "IPs found" in line or "[*] IPs" in line:
            section = "ips"
            continue
        elif "URLs" in line:
            section = "urls"
            continue
        elif "LinkedIn" in line:
            section = "linkedin"
            continue
        elif line.startswith("[*]") or line.startswith("[-]"):
            section = None

        # Extract by section
        if section == "emails" or not section:
            for email in email_re.findall(line):
                if email not in results["emails"]:
                    results["emails"].append(email)

        if section == "hosts" or not section:
            # Hostname lines often look like: subdomain.example.com:1.2.3.4
            if "." in line and not line.startswith("["):
                host = line.split(":")[0].strip()
                if host and host not in results["hosts"]:
                    results["hosts"].append(host)

        if section == "ips" or not section:
            for ip in ip_re.findall(line):
                if ip not in results["ips"]:
                    results["ips"].append(ip)

        for url in url_re.findall(line):
            if url not in results["urls"]:
                results["urls"].append(url)

        for li in linkedin_re.findall(line):
            full = f"https://{li}" if not li.startswith("http") else li
            if full not in results["linkedin"]:
                results["linkedin"].append(full)

    return results


def _github_dork(target: str, timeout: int) -> List[str]:
    """Search GitHub for exposed secrets/code using gh CLI or curl."""
    results: List[str] = []
    dorks = [
        f'"{target}" password',
        f'"{target}" api_key',
        f'"{target}" secret',
        f'"{target}" token',
    ]

    # Try gh CLI first
    gh = which("gh")
    if gh:
        for dork in dorks[:2]:  # limit to avoid rate limiting
            try:
                result = subprocess.run(
                    [gh, "search", "code", dork, "--limit", "5", "--json", "path,repository"],
                    capture_output=True, text=True, timeout=timeout,
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for item in data:
                        repo = item.get("repository", {}).get("fullName", "")
                        path = item.get("path", "")
                        if repo:
                            results.append(f"https://github.com/{repo}/blob/main/{path}")
            except Exception:
                continue
    else:
        # Fallback: just report the dorks to run manually
        for dork in dorks:
            results.append(f"Manual GitHub dork: site:github.com {dork}")

    return results


@click.command("osint")
@click.argument("target")
@click.option("--emails", is_flag=True, help="Collect email addresses.")
@click.option("--github-dorks", "github_dorks", is_flag=True, help="Run GitHub dork searches.")
@click.option("--linkedin", is_flag=True, help="Collect LinkedIn profiles.")
@click.option("--sources", default="google,bing,crtsh,dnsdumpster", show_default=True)
@click.option("--timeout", default=120, show_default=True, type=int)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    target: str,
    emails: bool,
    github_dorks: bool,
    linkedin: bool,
    sources: str,
    timeout: int,
    json_out: bool,
    json_output: str | None,
) -> None:
    """OSINT collection: emails, subdomains, IPs, GitHub dorks."""
    context = ctx.obj
    db = context.db if context else None
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    console.print(f"[accent]OSINT collection for:[/accent] {target}")

    all_results: Dict[str, List[str]] = {
        "emails": [], "hosts": [], "ips": [], "urls": [], "linkedin": [], "github": []
    }

    # Run theHarvester
    harvester_results = _run_harvester(target, sources, timeout)
    for key in ("emails", "hosts", "ips", "urls", "linkedin"):
        all_results[key].extend(harvester_results.get(key, []))

    # GitHub dorks
    if github_dorks:
        console.print("[dim]Running GitHub dork searches...[/dim]")
        all_results["github"] = _github_dork(target, timeout)

    # Store findings in DB
    if db:
        # Emails
        for email in all_results["emails"]:
            db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"Email address: {email}",
                severity="info",
                category="recon",
                description=f"Email found for {target}: {email}",
                source="theHarvester",
            )

        # Hosts
        for host in all_results["hosts"]:
            db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"Host discovered: {host}",
                severity="info",
                category="recon",
                description=f"Host found for {target}: {host}",
                source="theHarvester",
            )

        # GitHub findings
        for item in all_results["github"]:
            db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"GitHub exposure: {target}",
                severity="medium",
                category="recon",
                description=item,
                source="github-dork",
            )

        # LinkedIn
        for profile in all_results["linkedin"]:
            db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"LinkedIn profile: {profile}",
                severity="info",
                category="recon",
                description=f"LinkedIn profile found for {target}: {profile}",
                source="theHarvester",
            )

    if json_out:
        emit_json({"target": target, "results": all_results}, json_output)
        return

    # Display results
    if all_results["emails"] and (emails or not any([emails, github_dorks, linkedin])):
        t = Table(title=f"Emails ({len(all_results['emails'])})")
        t.add_column("Email", style="cyan")
        for e in all_results["emails"][:50]:
            t.add_row(e)
        console.print(t)

    if all_results["hosts"]:
        t = Table(title=f"Hosts ({len(all_results['hosts'])})")
        t.add_column("Host", style="green")
        for h in all_results["hosts"][:50]:
            t.add_row(h)
        console.print(t)

    if all_results["ips"]:
        t = Table(title=f"IPs ({len(all_results['ips'])})")
        t.add_column("IP", style="magenta")
        for ip in all_results["ips"][:50]:
            t.add_row(ip)
        console.print(t)

    if all_results["github"] and github_dorks:
        t = Table(title=f"GitHub Results ({len(all_results['github'])})")
        t.add_column("Result", style="yellow")
        for item in all_results["github"]:
            t.add_row(item)
        console.print(t)

    if all_results["linkedin"] and linkedin:
        t = Table(title=f"LinkedIn Profiles ({len(all_results['linkedin'])})")
        t.add_column("Profile", style="blue")
        for p in all_results["linkedin"]:
            t.add_row(p)
        console.print(t)

    total = sum(len(v) for v in all_results.values())
    console.print(f"[primary]OSINT complete. {total} item(s) found and stored.[/primary]")
