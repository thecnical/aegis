from __future__ import annotations

from typing import Dict, List

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aegis.core.utils import emit_json, run_command, which
from aegis.core.ui import console


DEFAULT_CREDS: Dict[str, List[str]] = {
    "ftp": ["anonymous:", "admin:admin", "root:root"],
    "ssh": ["root:root", "admin:admin", "user:password"],
    "telnet": ["admin:admin", "root:root"],
    "mysql": ["root:root", "root:"],
    "postgres": ["postgres:postgres"],
}


def _parse_smb_shares(output: str) -> List[str]:
    shares: List[str] = []
    for line in output.splitlines():
        if "Disk" in line:
            parts = line.split()
            if parts:
                shares.append(parts[0])
    return shares


def _get_timeout(config, profile: str) -> int:
    return int(
        config.get(f"profiles.{profile}.timeout", config.get("general.default_timeout", 30))
    )


@click.command("net")
@click.argument("target_ip")
@click.option("--no-defaults", is_flag=True, help="Skip default credential guidance.")
@click.option("--no-smb", is_flag=True, help="Skip SMB enumeration.")
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    target_ip: str,
    no_defaults: bool,
    no_smb: bool,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Network vulnerability scanning."""
    context = ctx.obj
    config = context.config
    db = context.db
    profile = context.profile
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)
    target_id = db.upsert_target(target_ip)

    smb_cmd = config.get("external_tools.smbclient", "smbclient")
    timeout = _get_timeout(config, profile)

    default_creds = DEFAULT_CREDS.copy()
    shares: List[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        if not no_defaults:
            task = progress.add_task("Checking default credentials", total=None)
            if not json_out:
                table = Table(title="Default Credential Checklist")
                table.add_column("Service", style="cyan")
                table.add_column("Common Defaults", style="magenta")
                for service, creds in DEFAULT_CREDS.items():
                    table.add_row(service, ", ".join(creds))
                console.print(table)
            progress.remove_task(task)

        if not no_smb:
            task = progress.add_task("Enumerating SMB shares", total=None)
            if not which(smb_cmd):
                console.print(f"[bold yellow]smbclient not found:[/bold yellow] {smb_cmd}")
            else:
                code, out, err = run_command(
                    [smb_cmd, "-L", f"//{target_ip}", "-N"], timeout=timeout
                )
                if code != 0:
                    console.print(f"[bold red]smbclient failed:[/bold red] {err}")
                else:
                    shares = _parse_smb_shares(out)
                    if shares and not json_out:
                        table = Table(title="SMB Shares")
                        table.add_column("Share", style="green")
                        for share in shares:
                            table.add_row(share)
                        console.print(table)
                        host_id = db.upsert_host(target_ip)
                        db.add_vulnerability(
                            host_id=host_id,
                            port_id=None,
                            name="SMB Shares Exposed",
                            severity="info",
                            description=", ".join(shares),
                            source="smbclient",
                        )
                        finding_id = db.add_finding(
                            target_id=target_id,
                            host_id=host_id,
                            port_id=None,
                            title="SMB Shares Exposed",
                            severity="info",
                            category="network",
                            description=", ".join(shares),
                            source="smbclient",
                        )
                        if finding_id:
                            db.add_evidence(
                                finding_id=finding_id,
                                kind="shares",
                                payload=", ".join(shares),
                            )
                    elif not shares and not json_out:
                        console.print("[bold yellow]No shares found.[/bold yellow]")
            progress.remove_task(task)

    results = {
        "target": target_ip,
        "default_creds": default_creds if not no_defaults else {},
        "smb_shares": shares,
    }

    if json_out:
        emit_json(results, json_output)
