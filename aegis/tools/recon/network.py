from __future__ import annotations

from typing import Dict, List

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aegis.core.utils import emit_json, parse_nmap_xml, run_command, which
from aegis.core.ui import console



def _get_timeout(config, profile: str) -> int:
    return int(
        config.get(f"profiles.{profile}.timeout", config.get("general.default_timeout", 30))
    )


def _get_nmap_args(config, profile: str) -> List[str]:
    args = config.get(f"profiles.{profile}.nmap_args", "-sC -sV")
    if isinstance(args, str):
        return args.split()
    if isinstance(args, list):
        return [str(item) for item in args]
    return ["-sC", "-sV"]


@click.command("network")
@click.argument("cidr_range")
@click.option(
    "--ping-only",
    is_flag=True,
    help="Only perform ping sweep (no port scan).",
)
@click.option(
    "--port-scan",
    is_flag=True,
    help="Run full active port scan on discovered hosts.",
)
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    cidr_range: str,
    ping_only: bool,
    port_scan: bool,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Active network reconnaissance for a CIDR range."""
    context = ctx.obj
    config = context.config
    db = context.db
    profile = context.profile
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    nmap_cmd = config.get("external_tools.nmap", "nmap")
    if not which(nmap_cmd):
        console.print(f"[bold red]nmap not found:[/bold red] {nmap_cmd}")
        return

    timeout = _get_timeout(config, profile)
    discovered: List[str] = []
    port_results: Dict[str, List[Dict[str, object]]] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Running ping sweep", total=None)
        code, out, err = run_command(
            [nmap_cmd, "-sn", cidr_range, "-oX", "-"], timeout=timeout
        )
        progress.remove_task(task)
        if code != 0:
            console.print(f"[bold red]nmap ping sweep failed:[/bold red] {err}")
            return
        parsed = parse_nmap_xml(out)
        for host in parsed.get("hosts", []):
            ip = host.get("ip")
            if ip:
                discovered.append(ip)
                db.upsert_host(ip)

        if not json_out:
            table = Table(title="Ping Sweep Results")
            table.add_column("Host", style="cyan")
            for ip in discovered:
                table.add_row(ip)
            console.print(table)

        if ping_only or not discovered:
            results = {"cidr": cidr_range, "hosts": discovered, "ports": port_results}
            if json_out:
                emit_json(results, json_output)
            return

        if port_scan:
            scan_task = progress.add_task("Running active port scans", total=None)
            for ip in discovered:
                nmap_args = _get_nmap_args(config, profile)
                code, out, err = run_command(
                    [nmap_cmd, "-p-"] + nmap_args + [ip, "-oX", "-"], timeout=timeout
                )
                if code != 0:
                    console.print(
                        f"[bold red]nmap port scan failed for {ip}:[/bold red] {err}"
                    )
                    continue
                parsed = parse_nmap_xml(out)
                for host in parsed.get("hosts", []):
                    host_id = db.upsert_host(host.get("ip"))
                    for port in host.get("ports", []):
                        port_id = db.add_port(
                            host_id,
                            port.get("port"),
                            port.get("protocol"),
                            port.get("state"),
                        )
                        service = port.get("service", {})
                        if service.get("name"):
                            db.add_service(
                                port_id,
                                service.get("name"),
                                service.get("product") or "",
                                service.get("version") or "",
                            )
                        port_results.setdefault(ip, []).append(port)
            progress.remove_task(scan_task)

    results = {"cidr": cidr_range, "hosts": discovered, "ports": port_results}
    if json_out:
        emit_json(results, json_output)
        return

    console.print("[bold green]Network reconnaissance complete.[/bold green]")
