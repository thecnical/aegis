from __future__ import annotations

from typing import List

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aegis.core.parsers import parse_nuclei_json_lines
from aegis.core.utils import emit_json, parse_json_lines, run_command, which
from aegis.core.ui import console



def _get_timeout(config, profile: str) -> int:
    return int(
        config.get(f"profiles.{profile}.timeout", config.get("general.default_timeout", 30))
    )


def _get_ferox_depth(config, profile: str) -> int:
    return int(config.get(f"profiles.{profile}.ferox_depth", 2))


def _get_nuclei_rate(config, profile: str) -> int:
    return int(config.get(f"profiles.{profile}.nuclei_rate", 150))


@click.command("web")
@click.argument("url")
@click.option("--no-dir-scan", is_flag=True, help="Skip directory scan.")
@click.option("--no-nuclei", is_flag=True, help="Skip nuclei scan.")
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    url: str,
    no_dir_scan: bool,
    no_nuclei: bool,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Web vulnerability scanning."""
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
    nuclei_findings: List[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        if not no_dir_scan:
            task = progress.add_task("Running feroxbuster", total=None)
            if not which(ferox_cmd):
                console.print(f"[bold yellow]feroxbuster not found:[/bold yellow] {ferox_cmd}")
            else:
                depth = _get_ferox_depth(config, profile)
                code, out, err = run_command(
                    [ferox_cmd, "-u", url, "-q", "--json", "--depth", str(depth)],
                    timeout=timeout,
                )
                if code != 0:
                    console.print(f"[bold red]feroxbuster failed:[/bold red] {err}")
                else:
                    for item in parse_json_lines(out):
                        target = item.get("url") or item.get("target")
                        if target:
                            dir_findings.append(str(target))
            progress.remove_task(task)

        if not no_nuclei:
            task = progress.add_task("Running nuclei", total=None)
            if not which(nuclei_cmd):
                console.print(f"[bold yellow]nuclei not found:[/bold yellow] {nuclei_cmd}")
            else:
                rate = _get_nuclei_rate(config, profile)
                code, out, err = run_command(
                    [nuclei_cmd, "-u", url, "-json", "-rate-limit", str(rate)],
                    timeout=timeout,
                )
                if code != 0:
                    console.print(f"[bold red]nuclei failed:[/bold red] {err}")
                else:
                    nuclei_findings = parse_nuclei_json_lines(out)
            progress.remove_task(task)

    results = {
        "url": url,
        "dir_findings": sorted(set(dir_findings)),
        "nuclei_findings": nuclei_findings,
    }

    if json_out:
        emit_json(results, json_output)
        return

    if dir_findings:
        table = Table(title="Directory Scan Results")
        table.add_column("Path", style="cyan")
        for item in sorted(set(dir_findings)):
            table.add_row(item)
        console.print(table)

    if nuclei_findings:
        table = Table(title="Nuclei Findings")
        table.add_column("Name", style="green")
        table.add_column("Severity", style="magenta")
        table.add_column("Target", style="cyan")
        for finding in nuclei_findings:
            name = finding.get("name")
            severity = finding.get("severity")
            target = finding.get("target")
            references = finding.get("references")
            if name and target:
                table.add_row(str(name), str(severity), str(target))
                db.add_vulnerability(
                    host_id=None,
                    port_id=None,
                    name=str(name),
                    severity=str(severity),
                    description=str(finding.get("template_id", "")),
                    source="nuclei",
                )
                finding_id = db.add_finding(
                    target_id=target_id,
                    host_id=None,
                    port_id=None,
                    title=str(name),
                    severity=str(severity),
                    category="web",
                    description=str(finding.get("template_id", "")),
                    source="nuclei",
                )
                if finding_id:
                    db.add_evidence(
                        finding_id=finding_id,
                        kind="target",
                        payload=str(target),
                    )
                    if references:
                        db.add_evidence(
                            finding_id=finding_id,
                            kind="references",
                            payload=str(references),
                        )
        console.print(table)

    if not dir_findings and not nuclei_findings:
        console.print("[bold yellow]No results to display.[/bold yellow]")
