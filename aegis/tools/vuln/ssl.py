from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import click

from aegis.core.ui import console
from aegis.core.utils import which


@click.command("ssl")
@click.argument("host")
@click.option("--port", default=443, show_default=True, type=int)
@click.pass_context
def cli(ctx: click.Context, host: str, port: int) -> None:
    """SSL/TLS analysis using testssl.sh."""
    context = ctx.obj
    db = context.db if context else None

    # Scope check
    if context and hasattr(context, "scope") and context.scope:
        context.scope.validate_or_abort(host)

    testssl = which("testssl.sh") or which("testssl")
    if not testssl:
        console.print("[warning]testssl.sh not found on PATH. Install it to use SSL analysis.[/warning]")
        return

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    cmd = [testssl, "--jsonfile", tmp_path, "--quiet", f"{host}:{port}"]
    console.print(f"[accent]Running SSL analysis on {host}:{port}...[/accent]")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        results = json.loads(Path(tmp_path).read_text(encoding="utf-8"))
        findings_count = 0
        for item in results if isinstance(results, list) else []:
            severity = str(item.get("severity", "info")).lower()
            if severity in ("critical", "high", "medium", "low"):
                if db:
                    db.add_finding(
                        target_id=None, host_id=None, port_id=None,
                        title=str(item.get("id", "SSL issue")),
                        severity=severity,
                        category="vuln",
                        description=str(item.get("finding", "")),
                        source="testssl",
                    )
                findings_count += 1
        console.print(f"[primary]SSL analysis complete. {findings_count} finding(s) stored.[/primary]")
    except subprocess.TimeoutExpired:
        console.print("[warning]testssl.sh timed out.[/warning]")
    except Exception as exc:
        console.print(f"[error]SSL analysis failed: {exc}[/error]")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
