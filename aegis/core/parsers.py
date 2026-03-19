from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

import defusedxml.ElementTree as DefusedET  # safe XML parsing (prevents XXE)


SQLMAP_VULN_RE = re.compile(r"is vulnerable|sql injection", re.IGNORECASE)
SQLMAP_PAYLOAD_RE = re.compile(r"payload\s*:\s*(.+)", re.IGNORECASE)


def parse_nmap_xml(xml_output: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {"hosts": []}
    try:
        root = DefusedET.fromstring(xml_output)
    except ET.ParseError:
        return results

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = host.find("address")
        ip = address.get("addr") if address is not None else None
        hostnames = [
            hn.get("name")
            for hn in host.findall("hostnames/hostname")
            if hn.get("name")
        ]
        ports_data = []
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            port_id = int(port.get("portid", 0))
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            service = {
                "name": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
            }
            scripts = []
            for script in port.findall("script"):
                script_id = script.get("id")
                output = script.get("output")
                if script_id or output:
                    scripts.append({"id": script_id, "output": output})
            ports_data.append(
                {
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "scripts": scripts,
                }
            )
        results["hosts"].append(
            {
                "ip": ip,
                "hostnames": hostnames,
                "ports": ports_data,
            }
        )
    return results


def parse_nuclei_json_lines(raw: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        references = info.get("reference") or info.get("references")
        findings.append(
            {
                "name": info.get("name"),
                "severity": info.get("severity"),
                "template_id": data.get("template-id"),
                "target": data.get("host") or data.get("matched-at"),
                "references": references,
                "raw": data,
            }
        )
    return findings


def parse_sqlmap_output(raw: str) -> Dict[str, object]:
    dbms = None
    payloads: List[str] = []
    for line in raw.splitlines():
        if "back-end DBMS" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                dbms = parts[1].strip()
        match = SQLMAP_PAYLOAD_RE.search(line)
        if match:
            payloads.append(match.group(1).strip())
    return {
        "vulnerable": bool(SQLMAP_VULN_RE.search(raw)),
        "dbms": dbms,
        "payloads": payloads,
    }
