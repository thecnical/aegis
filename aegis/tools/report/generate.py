from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

import click
from rich.table import Table

from aegis.core.reporting import render_report, render_report_html, render_report_pdf
from aegis.core.utils import emit_json, ensure_dir
from aegis.core.ui import console


def _fetch_all(conn) -> Dict[str, List[dict]]:
    results: Dict[str, List[dict]] = {
        "hosts": [], "ports": [], "services": [], "vulns": [], "findings": [], "evidence": [],
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
    "--format", "report_format",
    type=click.Choice(["md", "html", "pdf"], case_sensitive=False),
    default="md", show_default=True,
)
@click.option("--min-severity", default=None, help="Minimum severity to include (info/low/medium/high/critical).")
@click.option("--template", "template_name", default=None, help="Template name or path (e.g. professional, minimal).")
@click.option("--brand", "brand_override", default=None, help="Brand/company name for the report.")
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    target: str,
    report_format: str,
    min_severity: Optional[str],
    template_name: Optional[str],
    brand_override: Optional[str],
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Generate a report from the database."""
    context = ctx.obj
    db = context.db
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    conn = db.connect()
    data = _fetch_all(conn)

    ensure_dir("data/reports")
    ensure_dir("data/evidence")

    ext = "pdf" if report_format == "pdf" else report_format
    report_path = Path("data/reports") / f"{target}.{ext}"

    evidence_map: Dict[int, List[dict]] = {}
    evidence_paths: Dict[int, List[str]] = {}
    for ev in data["evidence"]:
        evidence_map.setdefault(int(ev.get("finding_id", 0)), []).append(ev)
    for finding_id, ev_list in evidence_map.items():
        for ev in ev_list:
            ev_path = Path("data/evidence") / f"evidence_{ev.get('id')}_{ev.get('kind')}.txt"
            ev_path.write_text(str(ev.get("payload", "")), encoding="utf-8")
            evidence_paths.setdefault(finding_id, []).append(str(ev_path))

    # Resolve template path
    resolved_template_path: Optional[str] = None
    resolved_template_html: Optional[str] = None

    if template_name:
        from aegis.core.template_manager import TemplateManager
        tm = TemplateManager()
        try:
            tpath = tm.get_template_path(template_name)
            if tpath.endswith(".html"):
                resolved_template_html = tpath
            else:
                resolved_template_path = tpath
        except FileNotFoundError:
            console.print(f"[warning]Template '{template_name}' not found, using default.[/warning]")
    else:
        resolved_template_path = context.config.get("general.report_template", "") or None
        resolved_template_html = context.config.get("general.report_template_html", "") or None

    brand = brand_override or str(context.config.get("general.brand", "Aegis") or "Aegis")
    custom_sections = context.config.get("general.report_custom_sections", []) or []

    if report_format == "pdf":
        html_text = render_report_html(
            target=target, data=data, evidence_paths=evidence_paths,
            template_path=resolved_template_html or None, brand=brand,
            custom_sections=custom_sections, min_severity=min_severity,
        )
        pdf_bytes = render_report_pdf(html_text)
        report_path.write_bytes(pdf_bytes)
    elif report_format == "html":
        report_text = render_report_html(
            target=target, data=data, evidence_paths=evidence_paths,
            template_path=resolved_template_html or None, brand=brand,
            custom_sections=custom_sections, min_severity=min_severity,
        )
        report_path.write_text(report_text, encoding="utf-8")
    else:
        report_text = render_report(
            target=target, data=data, evidence_paths=evidence_paths,
            template_path=resolved_template_path or None, brand=brand,
            custom_sections=custom_sections, min_severity=min_severity,
        )
        report_path.write_text(report_text, encoding="utf-8")

    results: dict[str, object] = {"target": target, "report_path": str(report_path)}
    if json_out:
        emit_json(results, json_output)
        return

    table = Table(title="Report Generated")
    table.add_column("Path", style="green")
    table.add_row(str(report_path))
    console.print(table)
