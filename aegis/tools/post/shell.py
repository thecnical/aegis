from __future__ import annotations

from pathlib import Path
from typing import List

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aegis.core.utils import emit_json, run_command, which
from aegis.core.ui import console



def _parse_peas_findings(output: str) -> List[str]:
    findings: List[str] = []
    for line in output.splitlines():
        if "[!]" in line or "CVE-" in line:
            findings.append(line.strip())
    return findings[:50]


def _get_timeout(config, profile: str) -> int:
    return int(
        config.get(f"profiles.{profile}.timeout", config.get("general.default_timeout", 30))
    )


@click.command("shell")
@click.argument("target_ip")
@click.option("--no-enum", is_flag=True, help="Skip local enumeration.")
@click.option("--no-privesc", is_flag=True, help="Skip priv-esc checks.")
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    target_ip: str,
    no_enum: bool,
    no_privesc: bool,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Post-exploitation helpers for a compromised host."""
    context = ctx.obj
    config = context.config
    db = context.db
    profile = context.profile
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    linpeas_cmd = config.get("external_tools.linpeas", "linpeas.sh")
    winpeas_cmd = config.get("external_tools.winpeas", "winpeas.exe")
    timeout = _get_timeout(config, profile)

    findings: List[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        if not no_enum:
            task = progress.add_task("Running local enumeration", total=None)
            script = linpeas_cmd if which(linpeas_cmd) else winpeas_cmd
            if not which(script) and not Path(script).exists():
                console.print(
                    "[bold yellow]LinPEAS/WinPEAS not found. Configure external_tools.linpeas or winpeas.[/bold yellow]"
                )
            else:
                code, out, err = run_command([script], timeout=timeout)
                if code != 0:
                    console.print(f"[bold red]Enumeration failed:[/bold red] {err}")
                else:
                    findings = _parse_peas_findings(out)
                    if findings and not json_out:
                        table = Table(title="Enumeration Highlights")
                        table.add_column("Finding", style="green")
                        for item in findings:
                            table.add_row(item)
                        console.print(table)
            progress.remove_task(task)

        if not no_privesc:
            task = progress.add_task("Checking privilege escalation hints", total=None)
            host_id = db.upsert_host(target_ip)
            db.add_vulnerability(
                host_id=host_id,
                port_id=None,
                name="PrivEsc Review Required",
                severity="medium",
                description="Review LinPEAS/WinPEAS output for escalation paths.",
                source="privesc_check",
            )
            db.add_finding(
                target_id=db.upsert_target(target_ip),
                host_id=host_id,
                port_id=None,
                title="PrivEsc Review Required",
                severity="medium",
                category="post",
                description="Review LinPEAS/WinPEAS output for escalation paths.",
                source="privesc_check",
            )
            if not json_out:
                console.print(
                    "[bold yellow]PrivEsc checklist added to report. Review local enumeration output.[/bold yellow]"
                )
            progress.remove_task(task)

    results = {
        "target": target_ip,
        "findings": findings,
        "privesc_check": not no_privesc,
    }

    if json_out:
        emit_json(results, json_output)
