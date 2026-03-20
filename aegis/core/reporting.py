from __future__ import annotations

import json
from datetime import datetime
from html import escape
from importlib import resources
from pathlib import Path
from string import Template
from typing import Dict, List, Optional

SEVERITY_RANK: Dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4
}


def _build_attack_graph(
    hosts: List[dict],
    findings: List[dict],
    vulns: List[dict],
) -> str:
    """Build a D3-compatible JSON graph from hosts and findings."""
    nodes: List[dict] = []
    links: List[dict] = []
    seen_ids: set[str] = set()

    for h in hosts:
        nid = f"host-{h.get('id', h.get('ip', 'unknown'))}"
        if nid not in seen_ids:
            nodes.append({"id": nid, "label": h.get("hostname") or h.get("ip") or "host", "type": "host"})
            seen_ids.add(nid)

    for f in findings:
        nid = f"finding-{f.get('id', id(f))}"
        sev = str(f.get("severity") or "info").lower()
        label = str(f.get("title") or "finding")[:40]
        if nid not in seen_ids:
            nodes.append({"id": nid, "label": label, "type": "finding", "severity": sev})
            seen_ids.add(nid)
        # Link to host if host_id is set
        host_id = f.get("host_id")
        if host_id:
            src = f"host-{host_id}"
            if src in seen_ids:
                links.append({"source": src, "target": nid})
        elif nodes:
            # Link to first host as fallback
            links.append({"source": nodes[0]["id"], "target": nid})

    for v in vulns:
        nid = f"vuln-{v.get('id', id(v))}"
        sev = str(v.get("severity") or "medium").lower()
        label = str(v.get("name") or "vuln")[:40]
        if nid not in seen_ids:
            nodes.append({"id": nid, "label": label, "type": "finding", "severity": sev})
            seen_ids.add(nid)
        host_id = v.get("host_id")
        if host_id:
            src = f"host-{host_id}"
            if src in seen_ids:
                links.append({"source": src, "target": nid})
        elif nodes:
            links.append({"source": nodes[0]["id"], "target": nid})

    return json.dumps({"nodes": nodes, "links": links})


def _filter_by_severity(items: List[dict], min_severity: Optional[str]) -> List[dict]:
    """Return items at or above min_severity threshold."""
    if not min_severity:
        return items
    threshold = SEVERITY_RANK.get(min_severity.lower(), 0)
    return [i for i in items if SEVERITY_RANK.get(str(i.get("severity", "info")).lower(), 0) >= threshold]


def render_report_pdf(html: str) -> bytes:
    """Convert HTML string to PDF bytes using weasyprint."""
    try:
        from weasyprint import HTML  # type: ignore[import]
        return HTML(string=html).write_pdf()
    except ImportError as exc:
        raise RuntimeError("weasyprint is required for PDF export: pip install weasyprint") from exc


def _format_section(title: str, items: List[str]) -> str:
    lines = [f"## {title}"]
    if not items:
        lines.append("- None")
    else:
        lines.extend([f"- {item}" for item in items])
    return "\n".join(lines)


def _load_template(template_path: str | None) -> str:
    if template_path:
        path = Path(template_path)
        if path.exists():
            return path.read_text(encoding="utf-8")
    template_file = resources.files("aegis.templates").joinpath("report.md")
    return template_file.read_text(encoding="utf-8")


def _load_html_template(template_path: str | None) -> str:
    if template_path:
        path = Path(template_path)
        if path.exists():
            return path.read_text(encoding="utf-8")
    template_file = resources.files("aegis.templates").joinpath("report.html")
    return template_file.read_text(encoding="utf-8")


def render_report(
    target: str,
    data: Dict[str, List[dict]],
    evidence_paths: Dict[int, List[str]],
    template_path: str | None,
    brand: str,
    custom_sections: List[dict] | None = None,
    min_severity: Optional[str] = None,
    company_name: str = "",
    company_logo: str = "",
    classification: str = "Confidential",
    assessor_name: str = "",
    executive_summary: str = "",
) -> str:
    ff = _filter_by_severity(data["findings"], min_severity)
    fv = _filter_by_severity(data["vulns"], min_severity)
    hosts = [f"{h.get('ip')} ({h.get('hostname') or 'unknown'})" for h in data["hosts"]]
    ports = [
        f"Host {p.get('host_id')}: {p.get('port')}/{p.get('protocol')} ({p.get('state')})"
        for p in data["ports"]
    ]
    services = [
        f"Port {s.get('port_id')}: {s.get('name')} {s.get('product')} {s.get('version')}"
        for s in data["services"]
    ]
    vulns = [
        f"{v.get('name')} ({v.get('severity')}) [{v.get('source')}]: {v.get('description')}"
        for v in fv
    ]
    findings: List[str] = []
    for f in ff:
        findings.append(f"{f.get('title')} ({f.get('severity')}) [{f.get('source')}]: {f.get('description')}")
        for ev_path in evidence_paths.get(int(f.get("id", 0)), []):
            findings.append(f"Evidence: {ev_path}")

    severity_counts: Dict[str, int] = {}
    for item in ff + fv:
        sev = str(item.get("severity") or "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    risk_summary = [f"{sev}: {count}" for sev, count in sorted(severity_counts.items())]

    criticals: List[str] = []
    for f in ff:
        if str(f.get("severity") or "").lower() in {"critical", "high"}:
            criticals.append(f"Finding: {f.get('title')} - {f.get('description')}")
    for v in fv:
        if str(v.get("severity") or "").lower() in {"critical", "high"}:
            criticals.append(f"Vuln: {v.get('name')} - {v.get('description')}")

    custom_blocks: List[str] = []
    for section in custom_sections or []:
        title = str(section.get("title", "Notes"))
        body = str(section.get("body", ""))
        custom_blocks.append(_format_section(title, [body] if body else []))

    template_text = _load_template(template_path)
    tmpl = Template(template_text)
    return tmpl.safe_substitute(
        title=f"Aegis Report: {target}",
        generated_at=datetime.utcnow().isoformat(),
        brand=brand,
        company_name=company_name or brand,
        company_logo=company_logo,
        classification=classification,
        assessor_name=assessor_name or brand,
        executive_summary=executive_summary,
        summary=_format_section("Summary", [f"Target: {target}"]),
        hosts=_format_section("Hosts", hosts),
        ports=_format_section("Open Ports", ports),
        services=_format_section("Services", services),
        vulns=_format_section("Vulnerabilities", vulns),
        findings=_format_section("Findings", findings),
        risk_summary=_format_section("Risk Summary", risk_summary),
        top_criticals=_format_section("Top Criticals", criticals[:10]),
        custom_sections="\n\n".join(custom_blocks),
    )


def _format_html_section(title: str, items: List[str]) -> str:
    if not items:
        return f"<h2>{escape(title)}</h2><ul><li>None</li></ul>"
    items_html = "".join([f"<li>{escape(item)}</li>" for item in items])
    return f"<h2>{escape(title)}</h2><ul>{items_html}</ul>"


def render_report_html(
    target: str,
    data: Dict[str, List[dict]],
    evidence_paths: Dict[int, List[str]],
    template_path: str | None,
    brand: str,
    custom_sections: List[dict] | None = None,
    min_severity: Optional[str] = None,
    company_name: str = "",
    company_logo: str = "",
    classification: str = "Confidential",
    assessor_name: str = "",
    executive_summary: str = "",
) -> str:
    ff = _filter_by_severity(data["findings"], min_severity)
    fv = _filter_by_severity(data["vulns"], min_severity)
    hosts = [f"{h.get('ip')} ({h.get('hostname') or 'unknown'})" for h in data["hosts"]]
    ports = [
        f"Host {p.get('host_id')}: {p.get('port')}/{p.get('protocol')} ({p.get('state')})"
        for p in data["ports"]
    ]
    services = [
        f"Port {s.get('port_id')}: {s.get('name')} {s.get('product')} {s.get('version')}"
        for s in data["services"]
    ]
    vulns = [
        f"{v.get('name')} ({v.get('severity')}) [{v.get('source')}]: {v.get('description')}"
        for v in fv
    ]
    findings: List[str] = []
    for f in ff:
        findings.append(f"{f.get('title')} ({f.get('severity')}) [{f.get('source')}]: {f.get('description')}")
        for ev_path in evidence_paths.get(int(f.get("id", 0)), []):
            findings.append(f"Evidence: {ev_path}")

    severity_counts: Dict[str, int] = {}
    for item in ff + fv:
        sev = str(item.get("severity") or "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    risk_summary = [f"{sev}: {count}" for sev, count in sorted(severity_counts.items())]

    criticals: List[str] = []
    for f in ff:
        if str(f.get("severity") or "").lower() in {"critical", "high"}:
            criticals.append(f"Finding: {f.get('title')} - {f.get('description')}")
    for v in fv:
        if str(v.get("severity") or "").lower() in {"critical", "high"}:
            criticals.append(f"Vuln: {v.get('name')} - {v.get('description')}")

    custom_blocks: List[str] = []
    for section in custom_sections or []:
        title = str(section.get("title", "Notes"))
        body = str(section.get("body", ""))
        custom_blocks.append(_format_html_section(title, [body] if body else []))

    template_text = _load_html_template(template_path)
    tmpl = Template(template_text)
    attack_graph = _build_attack_graph(data["hosts"], ff, fv)
    return tmpl.safe_substitute(
        title=f"Aegis Report: {target}",
        generated_at=datetime.utcnow().isoformat(),
        brand=brand,
        company_name=company_name or brand,
        company_logo=company_logo,
        classification=classification,
        assessor_name=assessor_name or brand,
        executive_summary=executive_summary,
        summary=_format_html_section("Summary", [f"Target: {target}"]),
        hosts=_format_html_section("Hosts", hosts),
        ports=_format_html_section("Open Ports", ports),
        services=_format_html_section("Services", services),
        vulns=_format_html_section("Vulnerabilities", vulns),
        findings=_format_html_section("Findings", findings),
        risk_summary=_format_html_section("Risk Summary", risk_summary),
        top_criticals=_format_html_section("Top Criticals", criticals[:10]),
        custom_sections="\n".join(custom_blocks),
        attack_graph_json=attack_graph,
    )
