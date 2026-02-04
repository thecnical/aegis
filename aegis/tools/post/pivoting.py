from __future__ import annotations

import subprocess

import click
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from aegis.core.utils import emit_json, which
from aegis.core.ui import console



@click.command("pivoting")
@click.argument("network")
@click.option("--ssh", "ssh_target", help="SSH target in user@host format.")
@click.option("--port", "local_port", default=1080, show_default=True)
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    network: str,
    ssh_target: str,
    local_port: int,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Pivoting helpers for internal networks."""
    _ = network
    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    status = "not_started"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Setting up SOCKS proxy", total=None)
        if not ssh_target:
            if not json_out:
                console.print("[bold yellow]Provide --ssh user@host to create a SOCKS proxy.[/bold yellow]")
            status = "missing_ssh_target"
        else:
            if not which("ssh"):
                if not json_out:
                    console.print("[bold red]ssh not found on PATH.[/bold red]")
                status = "ssh_missing"
            else:
                if not json_out:
                    console.print(
                        f"[bold green]Starting SOCKS proxy on 127.0.0.1:{local_port} via {ssh_target}[/bold green]"
                    )
                status = "started"
                try:
                    subprocess.run(["ssh", "-N", "-D", str(local_port), ssh_target], check=False)
                except OSError as exc:
                    if not json_out:
                        console.print(f"[bold red]SSH failed:[/bold red] {exc}")
                    status = "failed"
        progress.remove_task(task)

    results = {
        "network": network,
        "ssh_target": ssh_target,
        "local_port": local_port,
        "status": status,
    }

    if json_out:
        emit_json(results, json_output)
