from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import click

from aegis.core.ui import console
from aegis.core.utils import which


@click.command("api")
@click.argument("url")
@click.option("--wordlist", default=None, help="Path to wordlist file.")
@click.pass_context
def cli(ctx: click.Context, url: str, wordlist: str | None) -> None:
    """API endpoint fuzzing using ffuf."""
    from urllib.parse import urlparse
    context = ctx.obj
    db = context.db if context else None

    # Scope check
    if context and hasattr(context, "scope") and context.scope:
        parsed = urlparse(url)
        context.scope.validate_or_abort(parsed.netloc or url)

    ffuf = which("ffuf")
    if not ffuf:
        console.print("[warning]ffuf not found on PATH. Install it to use API fuzzing.[/warning]")
        return

    if not wordlist:
        console.print("[warning]No wordlist provided. Use --wordlist <path>.[/warning]")
        return

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    fuzz_url = url.rstrip("/") + "/FUZZ"
    cmd = [ffuf, "-w", wordlist, "-u", fuzz_url, "-o", tmp_path, "-of", "json", "-mc", "200,201,204,301,302,403"]
    console.print(f"[accent]Fuzzing API endpoints at {url}...[/accent]")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        data = json.loads(Path(tmp_path).read_text(encoding="utf-8"))
        results = data.get("results", [])
        for item in results:
            endpoint = str(item.get("url", ""))
            status = str(item.get("status", ""))
            if db:
                db.add_finding(
                    target_id=None, host_id=None, port_id=None,
                    title=f"API endpoint discovered: {endpoint}",
                    severity="info",
                    category="vuln",
                    description=f"Status: {status}  Length: {item.get('length', '?')}",
                    source="ffuf",
                )
        console.print(f"[primary]API fuzzing complete. {len(results)} endpoint(s) found.[/primary]")
    except subprocess.TimeoutExpired:
        console.print("[warning]ffuf timed out.[/warning]")
    except Exception as exc:
        console.print(f"[error]API fuzzing failed: {exc}[/error]")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
