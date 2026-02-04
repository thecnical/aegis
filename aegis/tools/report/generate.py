from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import click
from rich.table import Table

from aegis.core.reporting import render_report, render_report_html
from aegis.core.utils import emit_json, ensure_dir
from aegis.core.ui import console



def _fetch_all(conn) -> Dict[str, List[dict]]:
    results: Dict[str, List[dict]] = {
        "hosts": [],
        "ports": [],
        "services": [],
        "vulns": [],
        "findings": [],
        "evidence": [],
    }
    cursor = conn.cursor()
    results["hosts"] = [dict(row) for row in cursor.execute("SELECT * FROM hosts").fetchall()]
    results["ports"] = [dict(row) for row in cursor.execute("SELECT * FROM ports").fetchall()]
    results["services"] = [dict(row) for row in cursor.execute("SELECT * FROM services").fetchall()]
    results["vulns"] = [dict(row) for row in cursor.execute("SELECT * FROM vulnerabilities").fetchall()]
    results["findings"] = [dict(row) for row in cursor.execute("SELECT * FROM findings").fetchall()]
    results["evidence"] = [dict(row) for row in cursor.execute("SELECT * FROM evidence").fetchall()]
    return results


@click.command("generate")
@click.argument("target")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["md", "html"], case_sensitive=False),
    default="md",
    show_default=True,
)
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    target: str,
    report_format: str,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Generate a Markdown report from the database."""
    context = ctx.obj
    db = context.db
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    conn = db.connect()
    data = _fetch_all(conn)

    ensure_dir("data/reports")
    ensure_dir("data/evidence")
    report_path = Path("data/reports") / f"{target}.{report_format}"

    evidence_map: Dict[int, List[dict]] = {}
    evidence_paths: Dict[int, List[str]] = {}
    for ev in data["evidence"]:
        evidence_map.setdefault(int(ev.get("finding_id", 0)), []).append(ev)

    for finding_id, ev_list in evidence_map.items():
        for ev in ev_list:
            ev_path = Path("data/evidence") / f"evidence_{ev.get('id')}_{ev.get('kind')}.txt"
            ev_path.write_text(str(ev.get("payload", "")), encoding="utf-8")
            evidence_paths.setdefault(finding_id, []).append(str(ev_path))

    template_path = context.config.get("general.report_template", "")
    template_path_html = context.config.get("general.report_template_html", "")
    brand = context.config.get("general.brand", "Aegis")
    custom_sections = context.config.get("general.report_custom_sections", []) or []
    if report_format == "html":
        report_text = render_report_html(
            target=target,
            data=data,
            evidence_paths=evidence_paths,
            template_path=template_path_html or None,
            brand=brand,
            custom_sections=custom_sections,
        )
    else:
        report_text = render_report(
            target=target,
            data=data,
            evidence_paths=evidence_paths,
            template_path=template_path or None,
            brand=brand,
            custom_sections=custom_sections,
        )
    report_path.write_text(report_text, encoding="utf-8")

    results = {"target": target, "report_path": str(report_path)}

    if json_out:
        emit_json(results, json_output)
        return

    table = Table(title="Report Generated")
    table.add_column("Path", style="green")
    table.add_row(str(report_path))
    console.print(table)
