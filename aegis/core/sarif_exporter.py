"""SARIF v2.1.0 exporter for GitHub Code Scanning integration."""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Optional

from aegis.core.db_manager import DatabaseManager

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _severity_to_sarif_level(severity: str) -> str:
    """Map Aegis severity to SARIF notification level."""
    mapping: dict[str, str] = {
        "info": "note",
        "low": "note",
        "medium": "warning",
        "high": "error",
        "critical": "error",
    }
    return mapping.get(severity.lower(), "warning")


def _severity_to_security_severity(severity: str) -> str:
    """Map to GitHub security-severity score string."""
    mapping: dict[str, str] = {
        "info": "0.0",
        "low": "3.9",
        "medium": "6.9",
        "high": "8.9",
        "critical": "10.0",
    }
    return mapping.get(severity.lower(), "5.0")


def _title_to_rule_id(title: str, index: int) -> str:
    """Convert a finding title to a SARIF rule ID like AEGIS-001."""
    return f"AEGIS-{index:03d}"


def _title_to_rule_name(title: str) -> str:
    """Convert a finding title to a CamelCase rule name."""
    # Remove non-alphanumeric, title-case each word, join
    words = re.sub(r"[^\w\s]", " ", title).split()
    return "".join(w.capitalize() for w in words if w) or "UnknownFinding"


def _owasp_uri(title: str) -> str:
    """Best-effort OWASP reference URI based on title keywords."""
    title_lower = title.lower()
    if "sql" in title_lower and "inject" in title_lower:
        return "https://owasp.org/www-community/attacks/SQL_Injection"
    if "xss" in title_lower or "cross-site scripting" in title_lower or "cross site scripting" in title_lower:
        return "https://owasp.org/www-community/attacks/xss/"
    if "csrf" in title_lower or "cross-site request" in title_lower:
        return "https://owasp.org/www-community/attacks/csrf"
    if "ssrf" in title_lower:
        return "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
    if "lfi" in title_lower or "local file" in title_lower:
        return "https://owasp.org/www-project-web-security-testing-guide/"
    if "rce" in title_lower or "remote code" in title_lower:
        return "https://owasp.org/www-community/attacks/Code_Injection"
    if "xxe" in title_lower:
        return "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
    if "open redirect" in title_lower:
        return "https://owasp.org/www-project-web-security-testing-guide/"
    return "https://owasp.org/www-project-top-ten/"


def export_sarif(
    db: DatabaseManager,
    session_id: Optional[int] = None,
    tool_name: str = "Aegis",
    tool_version: str = "2.0.0",
) -> dict:
    """Generate a SARIF v2.1.0 document from findings.

    Returns the SARIF dict (call json.dumps() to serialize).
    """
    if session_id is not None:
        findings = db.get_session_findings(session_id)
    else:
        findings = db.get_all_findings(limit=1000)

    # Build unique rules from finding titles
    title_to_rule: dict[str, dict] = {}
    rule_index = 1
    for finding in findings:
        title = str(finding.get("title", "Unknown"))
        if title not in title_to_rule:
            rule_id = _title_to_rule_id(title, rule_index)
            severity = str(finding.get("severity", "info"))
            description = str(finding.get("description", ""))[:500]
            title_to_rule[title] = {
                "id": rule_id,
                "name": _title_to_rule_name(title),
                "shortDescription": {"text": title},
                "fullDescription": {"text": description or title},
                "helpUri": _owasp_uri(title),
                "properties": {
                    "security-severity": _severity_to_security_severity(severity),
                    "tags": ["security", _title_to_rule_name(title).lower()],
                },
            }
            rule_index += 1

    rules = list(title_to_rule.values())

    # Build results
    results: list[dict] = []
    for finding in findings:
        title = str(finding.get("title", "Unknown"))
        rule = title_to_rule.get(title, {})
        rule_id = rule.get("id", "AEGIS-000")
        severity = str(finding.get("severity", "info"))
        description = str(finding.get("description", ""))
        source = str(finding.get("source", "aegis"))

        # Build location URI from host or description
        host_id = finding.get("host_id")
        location_uri = "unknown"
        if host_id:
            try:
                conn = db.connect()
                cursor = conn.cursor()
                cursor.execute("SELECT ip, hostname FROM hosts WHERE id = ?", (host_id,))
                row = cursor.fetchone()
                if row:
                    location_uri = row["hostname"] or row["ip"] or "unknown"
            except Exception:
                pass

        path_val = finding.get("path") or finding.get("category") or ""
        if path_val:
            location_uri = f"{location_uri}/{path_val}".lstrip("/")

        result: dict = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(severity),
            "message": {
                "text": f"{title} found at {location_uri}" if location_uri != "unknown" else title
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location_uri,
                        },
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "severity": severity,
                "source": source,
                "finding_id": finding.get("id"),
            },
        }
        results.append(result)

    sarif_doc: dict = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/thecnical/aegis",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
            }
        ],
    }

    return sarif_doc


def export_sarif_file(
    db: DatabaseManager,
    output_path: str,
    session_id: Optional[int] = None,
) -> str:
    """Export SARIF to a file. Returns the file path."""
    sarif_doc = export_sarif(db, session_id=session_id)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sarif_doc, fh, indent=2)
    return output_path
