"""AI Autonomous Mode orchestrator for Aegis.

Real agentic loop:
  1. Run nmap → parse structured hosts/ports/services
  2. Feed services to AI → get specific tool recommendations
  3. Run recommended tools → parse structured findings
  4. Feed findings back to AI → get next actions
  5. Execute payloads against real endpoints
  6. Generate final report
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from aegis.core.ai_client import AIClient
from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.parsers import parse_nmap_xml, parse_nuclei_json_lines, parse_sqlmap_output
from aegis.core.scope_manager import ScopeManager
from aegis.core.ui import console
from aegis.core.utils import run_command


# ── Phase tool registry ───────────────────────────────────────────────────────

PHASE_TOOLS: dict[str, list[tuple[str, list[str]]]] = {
    "recon": [
        ("nmap-discovery", ["nmap", "-sn", "{target}", "-oX", "-"]),
        ("nmap-services",  ["nmap", "-sC", "-sV", "-p-", "--open", "{target}", "-oX", "-"]),
        ("subfinder",      ["subfinder", "-d", "{target}", "-silent"]),
    ],
    "vuln": [
        ("nuclei",         ["nuclei", "-u", "{target}", "-json", "-silent"]),
        ("nuclei-cves",    ["nuclei", "-u", "{target}", "-json", "-silent", "-tags", "cve"]),
        ("feroxbuster",    ["feroxbuster", "-u", "{target}", "-q", "--json", "--depth", "2"]),
    ],
    "exploit": [
        ("sqlmap",         ["sqlmap", "-u", "{target}", "--batch", "--level=2", "--risk=1"]),
    ],
    "post": [
        ("smbclient",      ["smbclient", "-L", "{target}", "-N"]),
    ],
    "reporting": [],
}

ALL_PHASES = ["recon", "vuln", "exploit", "post", "reporting"]
DEFAULT_PHASES = ["recon", "vuln"]


class AIOrchestrator:
    """Real agentic pentest orchestrator with structured output parsing."""

    def __init__(
        self,
        target: str,
        config: ConfigManager,
        db: DatabaseManager,
        scope: ScopeManager,
        full: bool = False,
        dry_run: bool = False,
        report_format: str = "md",
        min_severity: Optional[str] = None,
    ) -> None:
        self.target = target
        self.config = config
        self.db = db
        self.scope = scope
        self.full = full
        self.dry_run = dry_run
        self.report_format = report_format
        self.min_severity = min_severity
        self._ai = AIClient(config, db)
        self._session_id: Optional[int] = None
        self._findings: List[Dict[str, Any]] = []
        self._hosts: List[Dict[str, Any]] = []
        self._services: List[Dict[str, Any]] = []
        self._phase_summaries: Dict[str, List[Dict[str, Any]]] = {}

    # ── Scope & session ───────────────────────────────────────────────────────

    def _check_scope(self) -> None:
        if bool(self.config.get("general.safe_mode", True)):
            self.scope.validate_or_abort(self.target)

    def _start_session(self) -> int:
        label = f"auto:{self.target}:{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
        sid = self.db.add_scan_session(workspace_id=None, label=label)
        self._session_id = sid
        return sid

    def _finish_session(self) -> None:
        if self._session_id is None:
            return
        summary = json.dumps({
            phase: len(findings)
            for phase, findings in self._phase_summaries.items()
        })
        self.db.finish_scan_session(self._session_id, summary)

    # ── AI decision layer ─────────────────────────────────────────────────────

    def _ai_select_tools(self, phase: str) -> List[Tuple[str, List[str]]]:
        """Ask AI to select and prioritise tools based on discovered services."""
        default_tools = PHASE_TOOLS.get(phase, [])
        if not default_tools or not self._services:
            return default_tools

        try:
            services_summary = "\n".join(
                f"- {s.get('host')}:{s.get('port')} {s.get('name')} {s.get('product')} {s.get('version')}"
                for s in self._services[:20]
            )
            findings_summary = "\n".join(
                f"- [{f.get('severity','?')}] {f.get('title','?')}"
                for f in self._findings[-15:]
            ) or "No findings yet."

            prompt = (
                f"Target: {self.target}\n\n"
                f"Discovered services:\n{services_summary}\n\n"
                f"Current findings:\n{findings_summary}\n\n"
                f"Phase: {phase}\n"
                f"Available tools: {[t[0] for t in default_tools]}\n\n"
                "Which tools should I run and in what order? "
                "Reply with a JSON array of tool names: [\"tool1\", \"tool2\"]"
            )
            response = self._ai.complete(prompt, "suggest")
            start = response.find("[")
            end = response.rfind("]") + 1
            if start >= 0 and end > start:
                names = json.loads(response[start:end])
                ordered = [t for n in names for t in default_tools if t[0] == n]
                remaining = [t for t in default_tools if t not in ordered]
                return ordered + remaining
        except Exception:
            pass
        return default_tools

    def _ai_next_action(self, phase: str) -> Optional[str]:
        """Ask AI what to do next based on all findings so far."""
        if not self._findings:
            return None
        try:
            findings_summary = "\n".join(
                f"- [{f.get('severity','?')}] {f.get('title','?')}: {str(f.get('description',''))[:100]}"
                for f in self._findings[-20:]
            )
            services_summary = "\n".join(
                f"- {s.get('host')}:{s.get('port')} {s.get('name')} {s.get('product')} {s.get('version')}"
                for s in self._services[:10]
            ) or "No services discovered yet."

            prompt = (
                f"Penetration test target: {self.target}\n\n"
                f"Services found:\n{services_summary}\n\n"
                f"Findings so far:\n{findings_summary}\n\n"
                f"Current phase: {phase}\n\n"
                "Based on these findings, what is the single most important next action? "
                "Be specific: name the exact tool, command, or technique. "
                "Keep your answer to 2-3 sentences."
            )
            return self._ai.complete(prompt, "suggest")
        except Exception:
            return None

    # ── Tool execution ────────────────────────────────────────────────────────

    def _run_tool(self, tool_name: str, cmd_template: List[str]) -> Optional[str]:
        """Execute a tool. Returns stdout or None."""
        cmd = [part.replace("{target}", self.target) for part in cmd_template]
        binary = cmd[0]

        if not shutil.which(binary):
            console.print(f"[yellow]  skip {tool_name}: '{binary}' not found[/yellow]")
            return None

        if self.dry_run:
            console.print(f"[dim]  DRY-RUN [{tool_name}] {' '.join(cmd)}[/dim]")
            return None

        timeout_val = self.config.get("profiles.default.timeout", 120)
        timeout = int(timeout_val) if timeout_val is not None else 120
        code, out, err = run_command(cmd, timeout=timeout)
        if code not in (0, 1):  # many tools return 1 on findings
            console.print(f"[yellow]  {tool_name} exited {code}[/yellow]")
        return out if out.strip() else None

    # ── Structured output parsing ─────────────────────────────────────────────

    def _parse_and_store(self, phase: str, tool_name: str, raw_output: str) -> int:
        """Parse tool output into structured findings. Returns count stored."""
        if not raw_output or not raw_output.strip():
            return 0

        count = 0

        # ── Nmap XML ──────────────────────────────────────────────────────────
        if tool_name.startswith("nmap"):
            parsed = parse_nmap_xml(raw_output)
            for host in parsed.get("hosts", []):
                ip = host.get("ip") or ""
                hostnames = host.get("hostnames", [])
                hostname = hostnames[0] if hostnames else None
                host_id = self.db.upsert_host(ip, hostname=hostname)
                self._hosts.append({"ip": ip, "hostname": hostname, "id": host_id})

                for port_data in host.get("ports", []):
                    if port_data.get("state") != "open":
                        continue
                    port_id = self.db.add_port(
                        host_id,
                        port_data["port"],
                        port_data.get("protocol", "tcp"),
                        port_data["state"],
                    )
                    svc = port_data.get("service", {})
                    if svc.get("name"):
                        self.db.add_service(
                            port_id,
                            svc.get("name", ""),
                            svc.get("product", ""),
                            svc.get("version", ""),
                        )
                        self._services.append({
                            "host": ip,
                            "port": port_data["port"],
                            "name": svc.get("name", ""),
                            "product": svc.get("product", ""),
                            "version": svc.get("version", ""),
                        })

                    # Store NSE script findings
                    for script in port_data.get("scripts", []):
                        script_output = script.get("output", "")
                        if script_output and len(script_output) > 10:
                            severity = "medium" if any(
                                kw in script_output.lower()
                                for kw in ["vuln", "cve-", "exploit", "vulnerable"]
                            ) else "info"
                            fid = self._store_finding(
                                title=f"Nmap script: {script.get('id', 'unknown')} on {ip}:{port_data['port']}",
                                severity=severity,
                                category="recon",
                                description=script_output[:1000],
                                source="nmap",
                                host_id=host_id,
                                port_id=port_id,
                            )
                            if fid:
                                count += 1

                # Store open port as finding
                open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
                if open_ports:
                    port_list = ", ".join(
                        f"{p['port']}/{p.get('protocol','tcp')} ({p.get('service',{}).get('name','')})"
                        for p in open_ports
                    )
                    fid = self._store_finding(
                        title=f"Open ports on {ip}",
                        severity="info",
                        category="recon",
                        description=f"Open ports: {port_list}",
                        source="nmap",
                        host_id=host_id,
                    )
                    if fid:
                        count += 1
            return count

        # ── Nuclei JSON lines ─────────────────────────────────────────────────
        if tool_name.startswith("nuclei"):
            findings = parse_nuclei_json_lines(raw_output)
            for f in findings:
                name = str(f.get("name") or "Nuclei finding")
                severity = str(f.get("severity") or "info").lower()
                target = str(f.get("target") or self.target)
                template_id = str(f.get("template_id") or "")
                refs = f.get("references")
                refs_str = str(refs) if refs else ""

                fid = self._store_finding(
                    title=name,
                    severity=severity,
                    category="vuln",
                    description=f"Template: {template_id}\nTarget: {target}",
                    source="nuclei",
                )
                if fid:
                    self.db.add_evidence(fid, "target", target)
                    if refs_str:
                        self.db.add_evidence(fid, "references", refs_str)
                    count += 1
            return count

        # ── Feroxbuster JSON lines ────────────────────────────────────────────
        if tool_name == "feroxbuster":
            for line in raw_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    url = str(item.get("url") or item.get("target") or "")
                    status = int(item.get("status", 0))
                    if url and status in (200, 201, 204, 301, 302, 403, 405):
                        fid = self._store_finding(
                            title=f"Discovered path: {url}",
                            severity="info",
                            category="recon",
                            description=f"Status: {status}  Length: {item.get('length', '?')}",
                            source="feroxbuster",
                        )
                        if fid:
                            count += 1
                except (json.JSONDecodeError, ValueError):
                    continue
            return count

        # ── SQLmap ────────────────────────────────────────────────────────────
        if tool_name == "sqlmap":
            parsed = parse_sqlmap_output(raw_output)
            if parsed.get("vulnerable"):
                payloads = parsed.get("payloads", [])
                dbms = parsed.get("dbms", "")
                fid = self._store_finding(
                    title=f"SQL Injection confirmed on {self.target}",
                    severity="high",
                    category="exploit",
                    description=f"DBMS: {dbms}\nPayloads: {'; '.join(str(p) for p in payloads[:5])}",
                    source="sqlmap",
                )
                if fid:
                    if dbms:
                        self.db.add_evidence(fid, "dbms", str(dbms))
                    if payloads:
                        self.db.add_evidence(fid, "payloads", "; ".join(str(p) for p in payloads))
                    count += 1
            return count

        # ── Subfinder ─────────────────────────────────────────────────────────
        if tool_name == "subfinder":
            subdomains = [line.strip() for line in raw_output.splitlines() if line.strip()]
            for sub in subdomains:
                fid = self._store_finding(
                    title=f"Subdomain: {sub}",
                    severity="info",
                    category="recon",
                    description=f"Subdomain discovered: {sub}",
                    source="subfinder",
                )
                if fid:
                    count += 1
            return count

        # ── Smbclient ─────────────────────────────────────────────────────────
        if tool_name == "smbclient":
            shares = [
                line.split()[0]
                for line in raw_output.splitlines()
                if "Disk" in line and line.split()
            ]
            if shares:
                fid = self._store_finding(
                    title=f"SMB shares exposed on {self.target}",
                    severity="medium",
                    category="post",
                    description=f"Shares: {', '.join(shares)}",
                    source="smbclient",
                )
                if fid:
                    self.db.add_evidence(fid, "shares", ", ".join(shares))
                    count += 1
            return count

        # ── Generic fallback ──────────────────────────────────────────────────
        fid = self._store_finding(
            title=f"[{phase}] {tool_name} output",
            severity="info",
            category=phase,
            description=raw_output[:2000],
            source=tool_name,
        )
        return 1 if fid else 0

    def _store_finding(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        source: str,
        host_id: Optional[int] = None,
        port_id: Optional[int] = None,
    ) -> Optional[int]:
        """Store a finding and tag it with the current session."""
        fid = self.db.add_finding(
            target_id=None,
            host_id=host_id,
            port_id=port_id,
            title=title,
            severity=severity,
            category=category,
            description=description,
            source=source,
        )
        if fid and self._session_id is not None:
            conn = self.db.connect()
            conn.execute(
                "UPDATE findings SET session_id = ? WHERE id = ?",
                (self._session_id, fid),
            )
            conn.commit()
        finding = {
            "id": fid,
            "title": title,
            "severity": severity,
            "category": category,
            "source": source,
            "description": description,
        }
        self._findings.append(finding)
        return fid

    # ── AI payload execution ──────────────────────────────────────────────────

    def _execute_ai_payloads(self) -> None:
        """Generate and ACTUALLY TEST payloads against discovered endpoints."""
        if not self._services:
            return

        # Find web services
        web_services = [
            s for s in self._services
            if s.get("name", "").lower() in ("http", "https", "http-alt", "http-proxy")
            or str(s.get("port", "")) in ("80", "443", "8080", "8443", "8000", "3000")
        ]
        if not web_services:
            return

        # Get AI-generated payloads
        stack_str = ", ".join(
            f"{s.get('name')} {s.get('product')} {s.get('version')}"
            for s in self._services[:10]
        )
        try:
            prompt = (
                f"Target: {self.target}\n"
                f"Tech stack: {stack_str}\n\n"
                "Generate 5 targeted attack payloads. For each include:\n"
                "- type: sqli|xss|lfi|ssrf|rce\n"
                "- payload: the exact string to inject\n"
                "- param: URL parameter name to test\n"
                "- path: URL path to test (e.g. /search, /login)\n\n"
                'Reply as JSON array: [{"type":"...","payload":"...","param":"...","path":"..."}]'
            )
            response = self._ai.complete(prompt, "suggest")
            start = response.find("[")
            end = response.rfind("]") + 1
            if start < 0 or end <= start:
                return
            payloads = json.loads(response[start:end])
        except Exception:
            return

        # Actually test each payload
        for svc in web_services[:3]:
            scheme = "https" if str(svc.get("port")) in ("443", "8443") else "http"
            base_url = f"{scheme}://{svc.get('host')}:{svc.get('port')}"

            for p in payloads:
                if not isinstance(p, dict):
                    continue
                ptype = str(p.get("type", "unknown"))
                payload_str = str(p.get("payload", ""))
                param = str(p.get("param", "q"))
                path = str(p.get("path", "/"))
                test_url = f"{base_url}{path}"

                try:
                    with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:  # noqa: S501
                        resp = client.get(test_url, params={param: payload_str})
                    body = resp.text

                    # Check for indicators of success
                    confirmed = False
                    if ptype == "xss" and payload_str in body:
                        confirmed = True
                    elif ptype == "lfi" and any(
                        ind in body for ind in ["root:x:", "daemon:", "bin/bash"]
                    ):
                        confirmed = True
                    elif ptype == "sqli" and any(
                        ind in body.lower()
                        for ind in ["sql syntax", "mysql_fetch", "ora-", "sqlite_", "pg_query"]
                    ):
                        confirmed = True

                    severity = "high" if confirmed else "medium"
                    title = (
                        f"CONFIRMED {ptype.upper()} on {test_url}?{param}="
                        if confirmed
                        else f"Potential {ptype.upper()} test: {test_url}"
                    )

                    fid = self._store_finding(
                        title=title,
                        severity=severity,
                        category="exploit",
                        description=(
                            f"URL: {test_url}\n"
                            f"Param: {param}\n"
                            f"Payload: {payload_str}\n"
                            f"Status: {resp.status_code}\n"
                            f"Confirmed: {confirmed}"
                        ),
                        source="ai-payload",
                    )
                    if fid:
                        self.db.add_evidence(fid, "request", f"GET {test_url}?{param}={payload_str}")
                        self.db.add_evidence(fid, "response_status", str(resp.status_code))
                        if confirmed:
                            self.db.add_evidence(fid, "response_snippet", body[:500])

                except Exception:
                    continue

    # ── Phase runner ──────────────────────────────────────────────────────────

    def _run_phase(self, phase: str, progress: Progress) -> None:
        if phase == "reporting":
            return

        tools = self._ai_select_tools(phase)
        phase_count = 0

        for tool_name, cmd_template in tools:
            task_id = progress.add_task(f"  [{phase}] {tool_name}", total=None)
            output = self._run_tool(tool_name, cmd_template)
            progress.remove_task(task_id)

            if output:
                count = self._parse_and_store(phase, tool_name, output)
                phase_count += count
                if count > 0:
                    console.print(f"  [green]✓[/green] {tool_name}: {count} finding(s)")

        self._phase_summaries[phase] = [
            f for f in self._findings
            if f.get("category") == phase or f.get("source") in [t[0] for t in tools]
        ]

        # After recon: ask AI what to do next
        if phase == "recon" and self._services:
            next_action = self._ai_next_action(phase)
            if next_action:
                console.print(f"\n[cyan]AI recommendation:[/cyan] {next_action}\n")
            # Execute AI-generated payloads against discovered web services
            self._execute_ai_payloads()

        console.print(
            f"[accent]Phase {phase} complete:[/accent] "
            f"{phase_count} finding(s), "
            f"{len(self._services)} service(s) known"
        )

    # ── Report generation ─────────────────────────────────────────────────────

    def _generate_report(self) -> str:
        from aegis.core.reporting import (
            SEVERITY_RANK,
            render_report,
            render_report_html,
            render_report_pdf,
        )

        safe_target = self.target.replace("/", "_").replace(":", "_")
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        reports_dir = Path("data/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        findings = list(self._findings)
        if self.min_severity:
            min_rank = SEVERITY_RANK.get(self.min_severity.lower(), 0)
            findings = [
                f for f in findings
                if SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 0) >= min_rank
            ]

        # Get AI executive summary
        exec_summary = ""
        if findings:
            try:
                crit = sum(1 for f in findings if f.get("severity") in ("critical", "high"))
                prompt = (
                    f"Write a 3-sentence executive summary for a pentest of {self.target}. "
                    f"Found {len(findings)} total findings, {crit} critical/high severity. "
                    f"Top findings: {', '.join(f.get('title','') for f in findings[:5])}"
                )
                exec_summary = self._ai.complete(prompt, "report")
            except Exception:
                exec_summary = f"Automated pentest of {self.target} found {len(findings)} findings."

        data: Dict[str, Any] = {
            "findings": findings,
            "vulns": [],
            "hosts": self._hosts,
            "ports": [],
            "services": self._services,
            "evidence": [],
        }
        evidence_paths: Dict[int, List[str]] = {}
        brand = str(self.config.get("general.brand", "Aegis") or "Aegis")

        if self.report_format == "html":
            content = render_report_html(
                target=self.target, data=data, evidence_paths=evidence_paths,
                template_path=None, brand=brand, min_severity=self.min_severity,
                executive_summary=exec_summary,
            )
            out_path = reports_dir / f"{safe_target}_{timestamp}.html"
            out_path.write_text(content, encoding="utf-8")
        elif self.report_format == "pdf":
            html = render_report_html(
                target=self.target, data=data, evidence_paths=evidence_paths,
                template_path=None, brand=brand, min_severity=self.min_severity,
                executive_summary=exec_summary,
            )
            pdf_bytes = render_report_pdf(html)
            out_path = reports_dir / f"{safe_target}_{timestamp}.pdf"
            out_path.write_bytes(pdf_bytes)
        else:
            content = render_report(
                target=self.target, data=data, evidence_paths=evidence_paths,
                template_path=None, brand=brand, min_severity=self.min_severity,
                executive_summary=exec_summary,
            )
            out_path = reports_dir / f"{safe_target}_{timestamp}.md"
            out_path.write_text(content, encoding="utf-8")

        return str(out_path)

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self) -> str:
        """Execute the full autonomous pentest. Returns report file path."""
        self._check_scope()
        self._start_session()

        phases = ALL_PHASES if self.full else DEFAULT_PHASES + ["reporting"]

        console.print("\n[bold green]Aegis Autonomous Pentest[/bold green]")
        console.print(f"[dim]Target: {self.target}  Phases: {[p for p in phases if p != 'reporting']}[/dim]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            for phase in phases:
                if phase == "reporting":
                    continue
                console.print(f"\n[bold cyan]── Phase: {phase} ──[/bold cyan]")
                self._run_phase(phase, progress)

        console.print(f"\n[bold green]Generating report ({self.report_format})...[/bold green]")
        report_path = self._generate_report()
        self._finish_session()

        # Final AI summary
        try:
            crit = sum(1 for f in self._findings if f.get("severity") in ("critical", "high"))
            console.print(
                f"\n[bold]Run complete:[/bold] {len(self._findings)} findings "
                f"({crit} critical/high), {len(self._services)} services discovered"
            )
        except Exception:
            pass

        return report_path
