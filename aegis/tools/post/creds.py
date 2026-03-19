from __future__ import annotations

import subprocess

import click

from aegis.core.ui import console
from aegis.core.utils import which


@click.command("creds")
@click.option("--target", default=None, help="Target host for credential collection.")
@click.pass_context
def cli(ctx: click.Context, target: str | None) -> None:
    """Credential collection via SMB share enumeration."""
    context = ctx.obj
    db = context.db if context else None

    if not target:
        console.print("[warning]No --target specified.[/warning]")
        return

    # Scope check
    if context and hasattr(context, "scope") and context.scope:
        context.scope.validate_or_abort(target)

    smbclient = which("smbclient")
    if not smbclient:
        console.print("[warning]smbclient not found on PATH. Install it for credential collection.[/warning]")
        return

    console.print(f"[accent]Enumerating SMB shares on {target}...[/accent]")
    cmd = [smbclient, "-L", target, "-N"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        console.print(output[:2000])
        if output and db:
            db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"SMB shares enumerated on {target}",
                severity="medium",
                category="post",
                description=output[:1000],
                source="smbclient",
            )
    except subprocess.TimeoutExpired:
        console.print("[warning]smbclient timed out.[/warning]")
    except Exception as exc:
        console.print(f"[error]Credential collection failed: {exc}[/error]")
