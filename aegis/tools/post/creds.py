"""Credential collection: SMB share enumeration + file extraction."""
from __future__ import annotations

import re
from typing import Dict, List

import click
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json, run_command, which


# Common credential file patterns to look for on SMB shares
CRED_FILE_PATTERNS = [
    "*.txt", "*.cfg", "*.conf", "*.ini", "*.xml",
    "*.json", "*.yaml", "*.yml", "*.env",
    "password*", "passwd*", "cred*", "secret*", "key*",
]

# Regex patterns to detect credentials in file content
CRED_PATTERNS = [
    re.compile(r"password\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"passwd\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"secret\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"token\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"aws_access_key_id\s*[=:]\s*\S+", re.IGNORECASE),
]


def _list_smb_shares(target: str, timeout: int) -> List[str]:
    """List SMB shares on target. Returns list of share names."""
    smbclient = which("smbclient")
    if not smbclient:
        return []

    code, out, err = run_command([smbclient, "-L", f"//{target}", "-N"], timeout=timeout)
    shares: List[str] = []
    for line in out.splitlines():
        # Lines look like: "  sharename  Disk  Description"
        parts = line.split()
        if len(parts) >= 2 and "Disk" in line:
            shares.append(parts[0].strip())
    return shares


def _list_share_files(target: str, share: str, timeout: int) -> List[str]:
    """List files in an SMB share. Returns list of file paths."""
    smbclient = which("smbclient")
    if not smbclient:
        return []

    code, out, err = run_command(
        [smbclient, f"//{target}/{share}", "-N", "-c", "ls"],
        timeout=timeout,
    )
    files: List[str] = []
    for line in out.splitlines():
        parts = line.split()
        if parts and not parts[0].startswith("."):
            files.append(parts[0])
    return files


def _get_smb_file(target: str, share: str, filename: str, timeout: int) -> str:
    """Download and return content of a file from SMB share."""
    smbclient = which("smbclient")
    if not smbclient:
        return ""

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as f:
        tmp_path = f.name

    try:
        code, out, err = run_command(
            [smbclient, f"//{target}/{share}", "-N", "-c", f"get {filename} {tmp_path}"],
            timeout=timeout,
        )
        if code == 0:
            from pathlib import Path
            content = Path(tmp_path).read_text(encoding="utf-8", errors="replace")
            Path(tmp_path).unlink(missing_ok=True)
            return content
    except Exception:
        pass
    return ""


def _scan_for_creds(content: str) -> List[str]:
    """Scan file content for credential patterns."""
    found: List[str] = []
    for pattern in CRED_PATTERNS:
        for match in pattern.findall(content):
            found.append(match.strip())
    return found


@click.command("creds")
@click.option("--target", required=True, help="Target host for credential collection.")
@click.option("--deep", is_flag=True, help="Download and scan files for credentials.")
@click.option("--timeout", default=30, show_default=True, type=int)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    target: str,
    deep: bool,
    timeout: int,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Credential collection via SMB share enumeration and file scanning."""
    context = ctx.obj
    db = context.db if context else None
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    # Scope check
    if context and hasattr(context, "scope") and context.scope:
        context.scope.validate_or_abort(target)

    if not which("smbclient"):
        console.print("[yellow]smbclient not found. Install: sudo apt install smbclient[/yellow]")
        return

    console.print(f"[accent]Enumerating SMB shares on {target}...[/accent]")

    results: Dict[str, object] = {"target": target, "shares": [], "credentials": []}
    all_creds: List[Dict[str, str]] = []

    # Step 1: List shares
    shares = _list_smb_shares(target, timeout)
    results["shares"] = shares

    if not shares:
        console.print("[yellow]No accessible SMB shares found.[/yellow]")
        if json_out:
            emit_json(results, json_output)
        return

    # Display shares
    t = Table(title=f"SMB Shares on {target}")
    t.add_column("Share", style="cyan")
    for share in shares:
        t.add_row(share)
    console.print(t)

    if db:
        host_id = db.upsert_host(target)
        fid = db.add_finding(
            target_id=None, host_id=host_id, port_id=None,
            title=f"SMB shares accessible on {target}",
            severity="medium",
            category="post",
            description=f"Shares: {', '.join(shares)}",
            source="smbclient",
        )
        if fid:
            db.add_evidence(fid, "shares", ", ".join(shares))

    # Step 2: Deep scan — list files and look for credentials
    if deep:
        console.print("[dim]Deep scanning shares for credential files...[/dim]")
        for share in shares:
            files = _list_share_files(target, share, timeout)
            for filename in files:
                # Check if filename matches credential patterns
                fname_lower = filename.lower()
                is_interesting = any(
                    kw in fname_lower
                    for kw in ["password", "passwd", "cred", "secret", "key", "token", "config", ".env"]
                )
                if not is_interesting:
                    continue

                console.print(f"[dim]  Checking {share}/{filename}...[/dim]")
                content = _get_smb_file(target, share, filename, timeout)
                if not content:
                    continue

                creds = _scan_for_creds(content)
                for cred in creds:
                    entry = {"share": share, "file": filename, "credential": cred}
                    all_creds.append(entry)
                    console.print(f"[red]  CREDENTIAL FOUND in {share}/{filename}: {cred[:80]}[/red]")

                    if db:
                        fid = db.add_finding(
                            target_id=None, host_id=db.upsert_host(target), port_id=None,
                            title=f"Credential in SMB file: {share}/{filename}",
                            severity="high",
                            category="post",
                            description=f"File: //{target}/{share}/{filename}\nCredential: {cred[:200]}",
                            source="smbclient-creds",
                        )
                        if fid:
                            db.add_evidence(fid, "credential", cred[:500])
                            db.add_evidence(fid, "file_path", f"//{target}/{share}/{filename}")

    results["credentials"] = all_creds

    if json_out:
        emit_json(results, json_output)
        return

    if all_creds:
        t = Table(title=f"Credentials Found ({len(all_creds)})")
        t.add_column("Share", style="cyan")
        t.add_column("File", style="magenta")
        t.add_column("Credential", style="red")
        for c in all_creds:
            t.add_row(c["share"], c["file"], c["credential"][:60])
        console.print(t)
    elif deep:
        console.print("[green]No credentials found in scanned files.[/green]")

    console.print(
        f"[primary]Credential collection complete.[/primary] "
        f"{len(shares)} share(s), {len(all_creds)} credential(s) found."
    )
