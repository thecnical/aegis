"""AI Autonomous Mode orchestrator for Aegis.

Drives the full pentest lifecycle end-to-end from a single target input,
using AIClient to select tools per phase and storing all findings in a
named Session.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from aegis.core.ai_client import AIClient
from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.scope_manager import ScopeManager
from aegis.core.ui import console
from aegis.core.utils import run_command

# Phase definitions: name → list of (tool_name, cmd_template)
# cmd_template uses {target} as placeholder
PHASE_TOOLS: dict[str, list[tuple[str, list[str]]]] = {
    "recon": [
        ("nmap-ping", ["nmap", "-sn", "{target}", "-oX", "-"]),
        ("subfinder", ["subfinder", "-d", "{target}", "-silent"]),
    ],
    "vuln": [
        ("nmap-vuln", ["nmap", "-sC", "-sV", "{target}", "-oX", "-"]),
        ("nuclei", ["nuclei", "-u", "{target}", "-json"]),
    ],
    "exploit": [
        ("sqlmap", ["sqlmap", "-u", "{target}", "--batch", "--level=1"]),
    ],
    "post": [
        ("smbclient", ["smbclient", "-L", "{target}", "-N"]),
    ],
    "reporting": [],  # handled separately
}

ALL_PHASES = ["recon", "vuln", "exploit", "post", "reporting"]
DEFAULT_PHASES = ["recon", "vuln"]


class AIOrchestrator:
    """Orchestrates autonomous pentest phases using AI-guided tool selection."""

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
        self._findings: list[dict[str, Any]] = []
        self._phase_summaries: dict[str, list[dict[str, Any]]] = {}

    def _check_scope(self) -> None:
        """Abort if target is out of scope and safe_mode is enabled."""
        safe_mode = bool(self.config.get("general.safe_mode", True))
        if safe_mode:
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

    def _ai_tool_list(self, phase: str) -> list[tuple[str, list[str]]]:
        """Ask AI to prioritise tools for this phase given accumulated findings."""
        default_tools = PHASE_TOOLS.get(phase, [])
        if not default_tools:
            return default_tools
        try:
            findings_summary = "\n".join(
                f"- [{f.get('severity','?')}] {f.get('title','?')}" for f in self._findings[-20:]
            ) or "No findings yet."
            prompt = (
                f"Given these findings so far:\n{findings_summary}\n\n"
                f"For the '{phase}' phase against target '{self.target}', "
                f"list the most important tools to run from: "
                f"{[t[0] for t in default_tools]}. "
                "Reply with a JSON array of tool names in priority order."
            )
            response = self._ai.complete(prompt, "suggest")
            # Try to parse JSON array from response
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

    def _run_tool(self, tool_name: str, cmd_template: list[str]) -> Optional[str]:
        """Execute a single tool command. Returns stdout or None on skip/error."""
        cmd = [part.replace("{target}", self.target) for part in cmd_template]
        binary = cmd[0]

        if not shutil.which(binary):
            console.print(f"[bold yellow]Skipping {tool_name}:[/bold yellow] '{binary}' not on PATH")
            return None

        if self.dry_run:
            console.print(f"[primary]DRY-RUN[/primary] [{tool_name}] {' '.join(cmd)}")
            return None

        timeout_val = self.config.get("profiles.default.timeout", 60)
        timeout = int(timeout_val) if timeout_val is not None else 60
        code, out, err = run_command(cmd, timeout=timeout)
        if code != 0:
            console.print(f"[warning]{tool_name} exited {code}: {err[:200]}[/warning]")
        return out

    def _store_findings(self, phase: str, raw_output: str, tool_name: str) -> None:
        """Parse raw output and store findings in DB."""
        if not raw_output or not raw_output.strip():
            return
        # Simple heuristic: store as a single finding per tool run
        finding_id = self.db.add_finding(
            target_id=None,
            host_id=None,
            port_id=None,
            title=f"[{phase}] {tool_name} output",
            severity="info",
            category=phase,
            description=raw_output[:2000],
            source=tool_name,
        )
        if self._session_id is not None:
            # Tag finding with session_id via direct update
            conn = self.db.connect()
            conn.execute(
                "UPDATE findings SET session_id = ? WHERE id = ?",
                (self._session_id, finding_id),
            )
            conn.commit()
        finding = {
            "id": finding_id,
            "title": f"[{phase}] {tool_name} output",
            "severity": "info",
            "category": phase,
            "source": tool_name,
        }
        self._findings.append(finding)
        self._phase_summaries.setdefault(phase, []).append(finding)

    def _run_phase(self, phase: str, progress: Progress) -> None:
        """Execute all tools for a phase."""
        if phase == "reporting":
            return  # handled after all phases
        tools = self._ai_tool_list(phase)
        for tool_name, cmd_template in tools:
            task_id = progress.add_task(f"[{phase}] {tool_name}", total=None)
            output = self._run_tool(tool_name, cmd_template)
            progress.remove_task(task_id)
            if output:
                self._store_findings(phase, output, tool_name)

    def _generate_report(self) -> str:
        """Generate final report and return file path."""
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

        data: dict[str, Any] = {
            "findings": findings,
            "vulns": [],
            "hosts": [],
            "ports": [],
            "services": [],
            "evidence": [],
        }
        evidence_paths: dict[int, list[str]] = {}
        brand = str(self.config.get("general.brand", "Aegis") or "Aegis")

        if self.report_format == "html":
            content = render_report_html(
                target=self.target,
                data=data,
                evidence_paths=evidence_paths,
                template_path=None,
                brand=brand,
                min_severity=self.min_severity,
            )
            out_path = reports_dir / f"{safe_target}_{timestamp}.html"
            out_path.write_text(content, encoding="utf-8")
        elif self.report_format == "pdf":
            html = render_report_html(
                target=self.target,
                data=data,
                evidence_paths=evidence_paths,
                template_path=None,
                brand=brand,
                min_severity=self.min_severity,
            )
            pdf_bytes = render_report_pdf(html)
            out_path = reports_dir / f"{safe_target}_{timestamp}.pdf"
            out_path.write_bytes(pdf_bytes)
        else:
            content = render_report(
                target=self.target,
                data=data,
                evidence_paths=evidence_paths,
                template_path=None,
                brand=brand,
                min_severity=self.min_severity,
            )
            out_path = reports_dir / f"{safe_target}_{timestamp}.md"
            out_path.write_text(content, encoding="utf-8")

        return str(out_path)

    def run(self) -> str:
        """Execute the autonomous pentest run. Returns report file path."""
        self._check_scope()
        self._start_session()

        phases = ALL_PHASES if self.full else DEFAULT_PHASES + ["reporting"]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            for phase in phases:
                if phase == "reporting":
                    continue
                console.print(f"[accent]Phase: {phase}[/accent]")
                self._run_phase(phase, progress)

        report_path = self._generate_report()
        self._finish_session()
        return report_path
