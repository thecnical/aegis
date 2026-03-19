"""Burp Suite XML export importer for Aegis."""
from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

from aegis.core.db_manager import DatabaseManager


@dataclass
class BurpIssue:
    name: str
    host: str
    host_ip: str
    path: str
    location: str
    severity: str          # normalized to info/low/medium/high/critical
    confidence: str
    issue_background: str
    remediation_background: str
    issue_detail: str
    request: Optional[str]   # decoded from base64
    response: Optional[str]  # decoded from base64


def _normalize_severity(burp_severity: str) -> str:
    """Map Burp severity to Aegis severity."""
    mapping: dict[str, str] = {
        "information": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return mapping.get(burp_severity.lower().strip(), "info")


def _decode_b64(value: Optional[str]) -> Optional[str]:
    """Decode a base64-encoded string, returning None on failure."""
    if not value:
        return None
    try:
        return base64.b64decode(value.strip()).decode("utf-8", errors="replace")
    except Exception:
        return value  # return as-is if not valid base64


def _strip_doctype(xml_text: str) -> str:
    """Remove DOCTYPE declaration which can cause ElementTree to fail."""
    # Remove <!DOCTYPE ...> blocks (possibly multi-line)
    cleaned = re.sub(r"<!DOCTYPE[^>]*(?:\[.*?\])?>", "", xml_text, flags=re.DOTALL)
    return cleaned


def _text(element: Optional[ET.Element]) -> str:
    """Safely extract text from an XML element."""
    if element is None:
        return ""
    return (element.text or "").strip()


def parse_burp_xml(xml_path: str) -> list[BurpIssue]:
    """Parse a Burp Suite XML export file. Returns list of BurpIssue."""
    with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()

    cleaned = _strip_doctype(raw)

    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse Burp XML: {exc}") from exc

    issues: list[BurpIssue] = []

    for issue_el in root.findall("issue"):
        host_el = issue_el.find("host")
        host_text = _text(host_el)
        host_ip = host_el.get("ip", "") if host_el is not None else ""

        # Decode request/response (may be base64-encoded)
        req_el = issue_el.find("requestresponse/request")
        resp_el = issue_el.find("requestresponse/response")

        req_b64 = req_el is not None and req_el.get("base64", "false").lower() == "true"
        resp_b64 = resp_el is not None and resp_el.get("base64", "false").lower() == "true"

        req_raw = _text(req_el) if req_el is not None else None
        resp_raw = _text(resp_el) if resp_el is not None else None

        request = _decode_b64(req_raw) if req_b64 else req_raw
        response = _decode_b64(resp_raw) if resp_b64 else resp_raw

        issues.append(
            BurpIssue(
                name=_text(issue_el.find("name")),
                host=host_text,
                host_ip=host_ip,
                path=_text(issue_el.find("path")),
                location=_text(issue_el.find("location")),
                severity=_normalize_severity(_text(issue_el.find("severity"))),
                confidence=_text(issue_el.find("confidence")),
                issue_background=_text(issue_el.find("issueBackground")),
                remediation_background=_text(issue_el.find("remediationBackground")),
                issue_detail=_text(issue_el.find("issueDetail")),
                request=request,
                response=response,
            )
        )

    return issues


def import_burp_xml(
    xml_path: str,
    db: DatabaseManager,
    dry_run: bool = False,
) -> dict[str, int]:
    """Import Burp XML findings into the database.

    Returns {"imported": N, "skipped": N, "errors": N}
    """
    counts: dict[str, int] = {"imported": 0, "skipped": 0, "errors": 0}

    try:
        issues = parse_burp_xml(xml_path)
    except (ValueError, OSError) as exc:
        counts["errors"] += 1
        return counts

    for issue in issues:
        try:
            if dry_run:
                counts["imported"] += 1
                continue

            # Upsert host — use IP if available, else hostname from URL
            host_identifier = issue.host_ip if issue.host_ip else issue.host
            # Strip scheme from host for storage
            clean_host = re.sub(r"^https?://", "", issue.host).rstrip("/")
            host_id = db.upsert_host(
                ip=host_identifier or clean_host,
                hostname=clean_host if host_identifier else None,
            )

            # Build description from issue_detail + issue_background
            description_parts = []
            if issue.issue_detail:
                description_parts.append(issue.issue_detail)
            if issue.issue_background:
                description_parts.append(f"\n\nBackground:\n{issue.issue_background}")
            if issue.remediation_background:
                description_parts.append(f"\n\nRemediation:\n{issue.remediation_background}")
            description = "".join(description_parts)

            finding_id = db.add_finding(
                target_id=None,
                host_id=host_id,
                port_id=None,
                title=issue.name,
                severity=issue.severity,
                category="burp",
                description=description,
                source="burp",
            )

            # Store request/response as evidence
            if issue.request:
                db.add_evidence(finding_id, "request", issue.request[:10000])
            if issue.response:
                db.add_evidence(finding_id, "response", issue.response[:10000])

            # Store location as evidence
            if issue.location:
                db.add_evidence(finding_id, "location", issue.location)

            counts["imported"] += 1

        except Exception:
            counts["errors"] += 1

    return counts
