"""Web screenshot capture using gowitness (free, open source).

Install: go install github.com/sensepost/gowitness@latest
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import List

import click
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json, ensure_dir, which


def _run_gowitness_single(url: str, out_dir: str, timeout: int) -> bool:
    binary = which("gowitness")
    if not binary:
        return False
    try:
        result = subprocess.run(
            [binary, "single", "--url", url, "--screenshot-path", out_dir],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _run_gowitness_file(hosts_file: str, out_dir: str, timeout: int) -> bool:
    binary = which("gowitness")
    if not binary:
        return False
    try:
        result = subprocess.run(
            [binary, "scan", "file", "-f", hosts_file, "--screenshot-path", out_dir],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


@click.command("screenshot")
@click.argument("target")
@click.option(
    "--from-db",
    "from_db",
    is_flag=True,
    help="Screenshot all hosts already discovered in the workspace DB.",
)
@click.option("--out-dir", default="data/screenshots", show_default=True)
@click.option("--timeout", default=60, show_default=True, type=int)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    target: str,
    from_db: bool,
    out_dir: str,
    timeout: int,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Capture screenshots of web services using gowitness."""
    context = ctx.obj
    db = context.db
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    if not which("gowitness"):
        console.print(
            "[bold yellow]gowitness not found.[/bold yellow] "
            "Install: [cyan]go install github.com/sensepost/gowitness@latest[/cyan]"
        )
        return

    ensure_dir(out_dir)
    screenshots: List[dict] = []

    if from_db:
        # Pull all hosts from DB and screenshot them
        conn = db.connect()
        hosts = [dict(r) for r in conn.execute("SELECT ip, hostname FROM hosts").fetchall()]
        urls = []
        for h in hosts:
            ip = h.get("ip") or ""
            hostname = h.get("hostname") or ""
            urls.append(f"https://{hostname or ip}")
            urls.append(f"http://{hostname or ip}")

        if not urls:
            console.print("[warning]No hosts in database. Run recon first.[/warning]")
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            tmp_path = f.name

        console.print(f"[accent]Screenshotting {len(urls)} URLs from DB...[/accent]")
        ok = _run_gowitness_file(tmp_path, out_dir, timeout)
        Path(tmp_path).unlink(missing_ok=True)
    else:
        # Single target
        from aegis.core.utils import ensure_url
        url = ensure_url(target)
        console.print(f"[accent]Screenshotting:[/accent] {url}")
        ok = _run_gowitness_single(url, out_dir, timeout)

    # Collect generated screenshots
    shot_dir = Path(out_dir)
    for img in sorted(shot_dir.glob("*.png")):
        screenshots.append({"file": str(img), "size_kb": round(img.stat().st_size / 1024, 1)})
        # Store as finding in DB
        db.add_finding(
            target_id=None, host_id=None, port_id=None,
            title=f"Screenshot: {img.stem}",
            severity="info",
            category="screenshot",
            description=str(img),
            source="gowitness",
        )

    if json_out:
        emit_json({"target": target, "screenshots": screenshots}, json_output)
        return

    if not screenshots:
        console.print("[warning]No screenshots captured.[/warning]")
        return

    table = Table(title=f"Screenshots ({len(screenshots)})")
    table.add_column("File", style="cyan")
    table.add_column("Size (KB)", style="green")
    for s in screenshots:
        table.add_row(s["file"], str(s["size_kb"]))
    console.print(table)
    console.print(f"[primary]Screenshots saved to:[/primary] {out_dir}")
