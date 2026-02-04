from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List

import click
from rich.table import Table

from aegis.core.utils import emit_json, ensure_dir
from aegis.core.ui import console



def _fetch_table(conn, table: str) -> List[dict]:
    cursor = conn.cursor()
    return [dict(row) for row in cursor.execute(f"SELECT * FROM {table}").fetchall()]


@click.command("export")
@click.argument("format")
@click.option(
    "--table",
    "table_name",
    default="ports",
    show_default=True,
    help="Table to export (hosts, ports, services, vulnerabilities, findings, evidence).",
)
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    format: str,
    table_name: str,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Export data to CSV or JSON."""
    context = ctx.obj
    db = context.db
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    format = format.lower()
    if format not in {"csv", "json"}:
        console.print("[bold red]Format must be csv or json.[/bold red]")
        return

    conn = db.connect()
    data = _fetch_table(conn, table_name)

    ensure_dir("data/exports")
    output_path = Path("data/exports") / f"{table_name}.{format}"

    if format == "json":
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        if not data:
            output_path.write_text("", encoding="utf-8")
        else:
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(data[0].keys()))
                writer.writeheader()
                writer.writerows(data)

    results = {"table": table_name, "format": format, "output_path": str(output_path)}
    if json_out:
        emit_json(results, json_output)
        return

    table = Table(title="Export Complete")
    table.add_column("Path", style="green")
    table.add_row(str(output_path))
    console.print(table)
