"""Active Directory enumeration using BloodHound, ldapdomaindump, and CrackMapExec.

Enumerates AD users, groups, computers, GPOs, ACLs, and attack paths.
All tools are free and open source.

Install:
  pip install bloodhound ldapdomaindump impacket
  sudo apt install crackmapexec
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

import click
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json, run_command, which


def _run_ldapdomaindump(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    out_dir: str,
    timeout: int,
) -> Dict[str, Any]:
    """Run ldapdomaindump to enumerate AD objects."""
    lddd = which("ldapdomaindump")
    if not lddd:
        # Try python module
        try:
            result = subprocess.run(
                ["python3", "-m", "ldapdomaindump", "--help"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                lddd = "python3 -m ldapdomaindump"
        except Exception:
            pass

    if not lddd:
        return {"status": "skipped", "reason": "ldapdomaindump not found. Install: pip install ldapdomaindump"}

    Path(out_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        "ldapdomaindump",
        "-u", f"{domain}\\{username}",
        "-p", password,
        "--no-html",
        "-o", out_dir,
        dc_ip,
    ]

    code, out, err = run_command(cmd, timeout=timeout)

    if code != 0:
        return {"status": "error", "error": err[:500]}

    # Parse output files
    results: Dict[str, Any] = {"status": "ok", "files": [], "summary": {}}
    out_path = Path(out_dir)

    for json_file in out_path.glob("*.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            count = len(data) if isinstance(data, list) else 1
            results["files"].append({"file": json_file.name, "count": count})
            results["summary"][json_file.stem] = count
        except Exception:
            pass

    return results


def _run_crackmapexec(
    target: str,
    domain: str,
    username: str,
    password: str,
    timeout: int,
) -> Dict[str, Any]:
    """Run CrackMapExec for SMB/LDAP enumeration."""
    cme = which("crackmapexec") or which("cme")
    if not cme:
        return {"status": "skipped", "reason": "crackmapexec not found. Install: sudo apt install crackmapexec"}

    results: Dict[str, Any] = {"status": "ok", "findings": []}

    # SMB enumeration
    smb_tests = [
        (["smb", target, "-u", username, "-p", password, "--shares"], "shares"),
        (["smb", target, "-u", username, "-p", password, "--users"], "users"),
        (["smb", target, "-u", username, "-p", password, "--groups"], "groups"),
        (["smb", target, "-u", username, "-p", password, "--pass-pol"], "password_policy"),
    ]

    for args, label in smb_tests:
        code, out, err = run_command([cme] + args, timeout=timeout)
        if code == 0 and out:
            results["findings"].append({"type": label, "output": out[:1000]})

    return results


def _run_bloodhound_python(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    out_dir: str,
    timeout: int,
) -> Dict[str, Any]:
    """Run bloodhound-python to collect AD data for BloodHound analysis."""
    bh = which("bloodhound-python")
    if not bh:
        return {
            "status": "skipped",
            "reason": "bloodhound-python not found. Install: pip install bloodhound",
        }

    Path(out_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        bh,
        "-u", username,
        "-p", password,
        "-d", domain,
        "-dc", dc_ip,
        "-c", "All",  # Collect all: Users, Groups, Computers, Trusts, ACL, GPO
        "--zip",
        "-o", out_dir,
    ]

    code, out, err = run_command(cmd, timeout=timeout)

    if code != 0:
        return {"status": "error", "error": err[:500]}

    # Find output zip
    zip_files = list(Path(out_dir).glob("*.zip"))
    return {
        "status": "ok",
        "output_dir": out_dir,
        "zip_files": [str(z) for z in zip_files],
        "note": "Import the zip file into BloodHound for attack path analysis",
    }


def _enumerate_anonymous(dc_ip: str, domain: str, timeout: int) -> Dict[str, Any]:
    """Try anonymous LDAP enumeration (no credentials required)."""
    results: Dict[str, Any] = {"users": [], "domain_info": {}}

    # Try rpcclient anonymous
    rpcclient = which("rpcclient")
    if rpcclient:
        code, out, err = run_command(
            [rpcclient, "-U", "", "-N", dc_ip, "-c", "enumdomusers"],
            timeout=timeout,
        )
        if code == 0:
            for line in out.splitlines():
                if "user:[" in line:
                    match = line.split("user:[")[1].split("]")[0] if "user:[" in line else ""
                    if match:
                        results["users"].append(match)

    # Try enum4linux
    enum4linux = which("enum4linux") or which("enum4linux-ng")
    if enum4linux:
        code, out, err = run_command(
            [enum4linux, "-a", dc_ip],
            timeout=timeout,
        )
        if code == 0:
            results["enum4linux_output"] = out[:2000]

    return results


@click.command("ad")
@click.argument("dc_ip")
@click.option("--domain", required=True, help="AD domain name (e.g. corp.local).")
@click.option("--username", default="", help="AD username (leave empty for anonymous).")
@click.option("--password", default="", help="AD password.")
@click.option("--no-bloodhound", is_flag=True, help="Skip BloodHound collection.")
@click.option("--no-ldap", is_flag=True, help="Skip ldapdomaindump.")
@click.option("--no-cme", is_flag=True, help="Skip CrackMapExec.")
@click.option("--out-dir", default="data/ad", show_default=True)
@click.option("--timeout", default=120, show_default=True, type=int)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    no_bloodhound: bool,
    no_ldap: bool,
    no_cme: bool,
    out_dir: str,
    timeout: int,
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Active Directory enumeration: BloodHound, ldapdomaindump, CrackMapExec."""
    context = ctx.obj
    db = context.db if context else None
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    # Scope check
    if context and hasattr(context, "scope") and context.scope:
        context.scope.validate_or_abort(dc_ip)

    console.print(f"[accent]Active Directory enumeration:[/accent] {domain} @ {dc_ip}")

    all_results: Dict[str, Any] = {
        "dc_ip": dc_ip,
        "domain": domain,
        "anonymous": {},
        "ldapdomaindump": {},
        "bloodhound": {},
        "crackmapexec": {},
    }

    # ── Anonymous enumeration (no creds needed) ───────────────────────────────
    console.print("[dim]  Trying anonymous enumeration...[/dim]")
    anon = _enumerate_anonymous(dc_ip, domain, timeout)
    all_results["anonymous"] = anon

    if anon.get("users"):
        console.print(f"  [yellow]Anonymous users found: {len(anon['users'])}[/yellow]")
        if db:
            fid = db.add_finding(
                target_id=None, host_id=db.upsert_host(dc_ip), port_id=None,
                title=f"AD anonymous enumeration: {len(anon['users'])} users on {domain}",
                severity="high",
                category="recon",
                description=f"Domain: {domain}\nUsers: {', '.join(anon['users'][:20])}",
                source="rpcclient",
            )
            if fid:
                db.add_evidence(fid, "users", "\n".join(anon["users"]))

    # ── ldapdomaindump ────────────────────────────────────────────────────────
    if not no_ldap and username:
        console.print("[dim]  Running ldapdomaindump...[/dim]")
        ldap_result = _run_ldapdomaindump(
            dc_ip, domain, username, password,
            f"{out_dir}/ldap", timeout,
        )
        all_results["ldapdomaindump"] = ldap_result

        if ldap_result.get("status") == "ok":
            summary = ldap_result.get("summary", {})
            console.print(f"  [green]ldapdomaindump complete:[/green] {summary}")
            if db:
                fid = db.add_finding(
                    target_id=None, host_id=db.upsert_host(dc_ip), port_id=None,
                    title=f"AD LDAP dump: {domain}",
                    severity="high",
                    category="recon",
                    description=f"Domain: {domain}\nObjects: {json.dumps(summary)}",
                    source="ldapdomaindump",
                )
                if fid:
                    db.add_evidence(fid, "output_dir", f"{out_dir}/ldap")
        elif ldap_result.get("status") == "skipped":
            console.print(f"  [yellow]{ldap_result['reason']}[/yellow]")

    # ── BloodHound ────────────────────────────────────────────────────────────
    if not no_bloodhound and username:
        console.print("[dim]  Running bloodhound-python...[/dim]")
        bh_result = _run_bloodhound_python(
            dc_ip, domain, username, password,
            f"{out_dir}/bloodhound", timeout,
        )
        all_results["bloodhound"] = bh_result

        if bh_result.get("status") == "ok":
            zips = bh_result.get("zip_files", [])
            console.print(f"  [green]BloodHound data collected:[/green] {zips}")
            console.print("  [cyan]Import the zip into BloodHound GUI for attack path analysis[/cyan]")
            if db:
                fid = db.add_finding(
                    target_id=None, host_id=db.upsert_host(dc_ip), port_id=None,
                    title=f"BloodHound AD data collected: {domain}",
                    severity="high",
                    category="recon",
                    description=(
                        f"Domain: {domain}\n"
                        f"Output: {bh_result.get('output_dir')}\n"
                        f"Zip files: {', '.join(zips)}\n"
                        "Import into BloodHound for attack path analysis."
                    ),
                    source="bloodhound",
                )
                if fid and zips:
                    db.add_evidence(fid, "zip_path", zips[0])
        elif bh_result.get("status") == "skipped":
            console.print(f"  [yellow]{bh_result['reason']}[/yellow]")

    # ── CrackMapExec ──────────────────────────────────────────────────────────
    if not no_cme and username:
        console.print("[dim]  Running CrackMapExec...[/dim]")
        cme_result = _run_crackmapexec(dc_ip, domain, username, password, timeout)
        all_results["crackmapexec"] = cme_result

        if cme_result.get("status") == "ok":
            findings = cme_result.get("findings", [])
            console.print(f"  [green]CME complete:[/green] {len(findings)} result(s)")
            for f in findings:
                if db:
                    db.add_finding(
                        target_id=None, host_id=db.upsert_host(dc_ip), port_id=None,
                        title=f"AD CME {f['type']}: {domain}",
                        severity="medium",
                        category="recon",
                        description=f"Type: {f['type']}\n{f['output'][:500]}",
                        source="crackmapexec",
                    )

    if json_out:
        emit_json(all_results, json_output)
        return

    # Summary table
    t = Table(title=f"AD Enumeration: {domain}")
    t.add_column("Tool", style="cyan")
    t.add_column("Status", style="green")
    t.add_column("Result", style="white")

    t.add_row(
        "Anonymous",
        "ok" if anon.get("users") else "no results",
        f"{len(anon.get('users', []))} users found",
    )
    t.add_row(
        "ldapdomaindump",
        all_results["ldapdomaindump"].get("status", "skipped"),
        str(all_results["ldapdomaindump"].get("summary", "")),
    )
    t.add_row(
        "BloodHound",
        all_results["bloodhound"].get("status", "skipped"),
        str(all_results["bloodhound"].get("zip_files", "")),
    )
    t.add_row(
        "CrackMapExec",
        all_results["crackmapexec"].get("status", "skipped"),
        f"{len(all_results['crackmapexec'].get('findings', []))} results",
    )
    console.print(t)

    if all_results["bloodhound"].get("zip_files"):
        console.print(
            "\n[bold cyan]Next step:[/bold cyan] Import BloodHound zip into the BloodHound GUI\n"
            "  1. Start BloodHound: [cyan]bloodhound[/cyan]\n"
            "  2. Upload data: drag the zip file into the interface\n"
            "  3. Run query: 'Find Shortest Paths to Domain Admins'"
        )
