"""JS & Git secret extraction using trufflehog (free, open source).

Install: go install github.com/trufflesecurity/trufflehog/v3@latest
"""
from __future__ import annotations

import json
import subprocess
from typing import List

import click
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import ensure_dir, which


def _run_trufflehog(target: str, mode: str, timeout: int) -> List[dict]:
    """Run trufflehog and return parsed findings."""
    binary = which("trufflehog")
    if not binary:
        console.print(
            "[bold yellow]trufflehog not found.[/bold yellow] "
            "Install: [cyan]go install github.com/trufflesecurity/trufflehog/v3@latest[/cyan]"
        )
        return []

    if mode == "git":
        cmd = [binary, "git", target, "--json", "--no-update"]
    else:
        cmd = [binary, "filesystem", target, "--json", "--no-update"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        console.print("[warning]trufflehog timed out.[/warning]")
        return []
    except OSError as exc:
        console.print(f"[error]trufflehog failed: {exc}[/error]")
        return []

    findings: List[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                findings.append(data)
        except json.JSONDecodeError:
            continue
    return findings


@click.command("secrets")
@click.argument("target")
@click.option(
    "--mode",
    type=click.Choice(["filesystem", "git"]),
    default="filesystem",
    show_default=True,
    help="Scan a local filesystem path or a git repo URL.",
)
@click.option("--timeout", default=120, show_default=True, type=int)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    target: str,
    mode: str,
    timeout: int,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Extract secrets and API keys from JS files or git repos using trufflehog."""
    from aegis.core.utils import emit_json

    context = ctx.obj
    db = context.db
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    ensure_dir("data/secrets")
    console.print(f"[accent]Scanning for secrets in:[/accent] {target} (mode={mode})")

    raw_findings = _run_trufflehog(target, mode, timeout)

    stored: List[dict] = []
    for item in raw_findings:
        detector = item.get("DetectorName") or item.get("detector_name") or "unknown"
        raw_val = item.get("Raw") or item.get("raw") or ""
        source_meta = item.get("SourceMetadata") or {}
        file_path = ""
        line_num = ""
        if isinstance(source_meta, dict):
            data_block = source_meta.get("Data") or {}
            if isinstance(data_block, dict):
                for sub in data_block.values():
                    if isinstance(sub, dict):
                        file_path = str(sub.get("file") or sub.get("filename") or "")
                        line_num = str(sub.get("line") or "")
                        break

        finding_id = db.add_finding(
            target_id=None,
            host_id=None,
            port_id=None,
            title=f"Secret detected: {detector}",
            severity="high",
            category="secrets",
            description=f"Detector: {detector}\nFile: {file_path}:{line_num}\nRaw: {raw_val[:200]}",
            source="trufflehog",
        )
        stored.append({
            "id": finding_id,
            "detector": detector,
            "file": file_path,
            "line": line_num,
            "raw_preview": raw_val[:80],
        })

    if json_out:
        emit_json({"target": target, "secrets": stored}, json_output)
        return

    if not stored:
        console.print("[green]No secrets found.[/green]")
        return

    table = Table(title=f"Secrets Found ({len(stored)})")
    table.add_column("Detector", style="red")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta")
    table.add_column("Preview", style="yellow")
    for s in stored:
        table.add_row(s["detector"], s["file"], s["line"], s["raw_preview"])
    console.print(table)
    console.print(f"[primary]Stored {len(stored)} secret findings in database.[/primary]")
