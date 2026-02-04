from __future__ import annotations

import json
import requests
from typing import Dict, List

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aegis.core.utils import (
    emit_json,
    ensure_url,
    get_http_session,
    resolve_host,
    run_command,
    which,
)
from aegis.core.ui import console



def _parse_subfinder_output(output: str) -> List[str]:
    hosts = [line.strip() for line in output.splitlines() if line.strip()]
    return sorted(set(hosts))


def _shodan_host_lookup(session, api_key: str, ip: str, timeout: int) -> Dict[str, object]:
    url = f"https://api.shodan.io/shodan/host/{ip}"
    response = session.get(url, params={"key": api_key}, timeout=timeout)
    response.raise_for_status()
    return response.json()


def _parse_wappalyzer_output(raw: str) -> List[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [raw]
    if isinstance(data, dict) and "technologies" in data:
        techs = data.get("technologies", [])
        names = [t.get("name") for t in techs if isinstance(t, dict)]
        return [name for name in names if name]
    if isinstance(data, list):
        names = [t.get("name") for t in data if isinstance(t, dict)]
        return [name for name in names if name]
    return [raw]


def _get_timeout(config, profile: str) -> int:
    return int(
        config.get(f"profiles.{profile}.timeout", config.get("general.default_timeout", 30))
    )


@click.command("domain")
@click.argument("domain_name")
@click.option("--no-subdomains", is_flag=True, help="Skip subdomain enumeration.")
@click.option("--no-shodan", is_flag=True, help="Skip Shodan passive port scan.")
@click.option("--no-wappalyzer", is_flag=True, help="Skip Wappalyzer tech detection.")
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    domain_name: str,
    no_subdomains: bool,
    no_shodan: bool,
    no_wappalyzer: bool,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Passive reconnaissance for a domain."""
    context = ctx.obj
    config = context.config
    db = context.db
    profile = context.profile
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    subfinder_cmd = config.get("external_tools.subfinder", "subfinder")
    wappalyzer_cmd = config.get("external_tools.wappalyzer", "wappalyzer")
    shodan_key = config.get("api_keys.shodan", "")
    timeout = _get_timeout(config, profile)
    http_timeout = int(config.get("general.http_timeout", 15))
    http_retries = int(config.get("general.http_retries", 3))
    http_backoff = float(config.get("general.http_backoff", 0.3))
    session = get_http_session(http_retries, http_backoff)

    subdomains: List[str] = []
    shodan_ports: Dict[str, List[int]] = {}
    techs: List[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        if not no_subdomains:
            task = progress.add_task("Enumerating subdomains", total=None)
            if not which(subfinder_cmd):
                console.print(
                    f"[bold yellow]subfinder not found:[/bold yellow] {subfinder_cmd}"
                )
            else:
                code, out, err = run_command(
                    [subfinder_cmd, "-silent", "-d", domain_name], timeout=timeout
                )
                if code != 0:
                    console.print(
                        f"[bold red]subfinder failed:[/bold red] {err or 'unknown error'}"
                    )
                else:
                    subdomains = _parse_subfinder_output(out)
            progress.remove_task(task)

        if not no_shodan:
            task = progress.add_task("Querying Shodan", total=None)
            if not shodan_key or shodan_key == "CHANGE_ME":
                console.print("[bold yellow]Shodan API key not configured.[/bold yellow]")
            else:
                root_ip = resolve_host(domain_name)
                if not root_ip:
                    console.print(
                        f"[bold yellow]Could not resolve domain:[/bold yellow] {domain_name}"
                    )
                else:
                    try:
                        data = _shodan_host_lookup(session, shodan_key, root_ip, http_timeout)
                        ports = data.get("ports", []) if isinstance(data, dict) else []
                        if isinstance(ports, list):
                            shodan_ports[root_ip] = [int(p) for p in ports if isinstance(p, int)]
                    except requests.RequestException as exc:
                        console.print(f"[bold red]Shodan query failed:[/bold red] {exc}")
            progress.remove_task(task)

        if not no_wappalyzer:
            task = progress.add_task("Detecting technologies", total=None)
            if not which(wappalyzer_cmd):
                console.print(
                    f"[bold yellow]wappalyzer not found:[/bold yellow] {wappalyzer_cmd}"
                )
            else:
                target_url = ensure_url(domain_name)
                code, out, err = run_command(
                    [wappalyzer_cmd, target_url, "--pretty"], timeout=timeout
                )
                if code != 0:
                    console.print(
                        f"[bold red]wappalyzer failed:[/bold red] {err or 'unknown error'}"
                    )
                else:
                    techs = _parse_wappalyzer_output(out)
            progress.remove_task(task)

    results = {
        "domain": domain_name,
        "subdomains": subdomains,
        "shodan_ports": shodan_ports,
        "technologies": techs,
    }

    if json_out:
        emit_json(results, json_output)
        return

    if subdomains:
        table = Table(title="Discovered Subdomains")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP", style="green")
        for host in subdomains:
            ip = resolve_host(host)
            table.add_row(host, ip or "-")
            if ip:
                host_id = db.upsert_host(ip, hostname=host)
                if ip in shodan_ports:
                    for port in shodan_ports[ip]:
                        db.add_port(host_id, port, "tcp", "open")
        console.print(table)

    if shodan_ports:
        table = Table(title="Shodan Passive Ports")
        table.add_column("IP", style="cyan")
        table.add_column("Ports", style="magenta")
        for ip, ports in shodan_ports.items():
            table.add_row(ip, ", ".join(str(p) for p in ports))
        console.print(table)

    if techs:
        table = Table(title="Detected Technologies")
        table.add_column("Technology", style="green")
        for tech in techs:
            table.add_row(tech)
        console.print(table)

    if not subdomains and not shodan_ports and not techs:
        console.print("[bold yellow]No results to display.[/bold yellow]")
