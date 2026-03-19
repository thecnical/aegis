from __future__ import annotations

import subprocess

import click

from aegis.core.ui import console
from aegis.core.utils import which


@click.command("osint")
@click.argument("target")
@click.option("--emails", is_flag=True, help="Collect email addresses.")
@click.option("--github-dorks", is_flag=True, help="Run GitHub dork searches.")
@click.option("--linkedin", is_flag=True, help="Collect LinkedIn profiles.")
@click.pass_context
def cli(ctx: click.Context, target: str, emails: bool, github_dorks: bool, linkedin: bool) -> None:
    """OSINT collection using theHarvester."""
    context = ctx.obj
    db = context.db if context else None

    harvester = which("theHarvester")
    if not harvester:
        console.print("[warning]theHarvester not found on PATH. Install it to use OSINT collection.[/warning]")
        return

    sources = "google,bing,crtsh"
    cmd = [harvester, "-d", target, "-b", sources, "-l", "100"]

    console.print(f"[accent]Running OSINT collection for {target}...[/accent]")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        console.print(output[:3000])
        if db:
            db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"OSINT results for {target}",
                severity="info",
                category="recon",
                description=output[:1000],
                source="theHarvester",
            )
    except subprocess.TimeoutExpired:
        console.print("[warning]theHarvester timed out.[/warning]")
    except Exception as exc:
        console.print(f"[error]OSINT collection failed: {exc}[/error]")
