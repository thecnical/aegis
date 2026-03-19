"""Parallel multi-target campaign runner using asyncio."""
from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.scope_manager import ScopeManager
from aegis.core.ui import console


@dataclass
class CampaignTarget:
    target: str
    kind: str  # domain, ip, cidr, url


@dataclass
class CampaignResult:
    target: str
    session_id: int
    findings_count: int
    duration_seconds: float
    error: Optional[str] = None


@dataclass
class CampaignRun:
    campaign_name: str
    targets: list[CampaignTarget]
    results: list[CampaignResult] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: Optional[str] = None
    total_findings: int = 0


class CampaignRunner:
    """Runs scans against multiple targets in parallel."""

    def __init__(
        self,
        config: ConfigManager,
        db: DatabaseManager,
        scope: ScopeManager,
        max_parallel: int = 3,
        phases: Optional[list[str]] = None,
        dry_run: bool = False,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.config = config
        self.db = db
        self.scope = scope
        self.max_parallel = max_parallel
        self.phases = phases or ["recon", "vuln"]
        self.dry_run = dry_run
        self.progress_callback = progress_callback

    def _notify(self, target: str, status: str) -> None:
        if self.progress_callback:
            self.progress_callback(target, status)
        else:
            console.print(f"[dim][campaign] {target}: {status}[/dim]")

    async def run_target(self, target: CampaignTarget) -> CampaignResult:
        """Run a full scan against a single target. Returns CampaignResult."""
        start_time = time.monotonic()
        self._notify(target.target, "starting")

        # Create a scan session for this target
        label = f"campaign:{target.target}:{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
        session_id = self.db.add_scan_session(workspace_id=None, label=label)

        findings_count = 0

        try:
            if self.dry_run:
                self._notify(target.target, "dry-run — skipping actual scan")
                # Simulate a brief delay
                await asyncio.sleep(0.1)
                duration = time.monotonic() - start_time
                self.db.finish_scan_session(session_id, '{"dry_run": true}')
                return CampaignResult(
                    target=target.target,
                    session_id=session_id,
                    findings_count=0,
                    duration_seconds=round(duration, 2),
                )

            # Run each phase
            for phase in self.phases:
                self._notify(target.target, f"phase:{phase}")
                phase_findings = await self._run_phase_async(
                    target.target, phase, session_id
                )
                findings_count += phase_findings

            duration = time.monotonic() - start_time
            self.db.finish_scan_session(
                session_id,
                f'{{"findings": {findings_count}, "phases": {self.phases}}}',
            )
            self._notify(target.target, f"done — {findings_count} findings in {duration:.1f}s")
            return CampaignResult(
                target=target.target,
                session_id=session_id,
                findings_count=findings_count,
                duration_seconds=round(duration, 2),
            )

        except Exception as exc:
            duration = time.monotonic() - start_time
            error_msg = str(exc)
            self._notify(target.target, f"error: {error_msg}")
            try:
                self.db.finish_scan_session(session_id, f'{{"error": "{error_msg[:200]}"}}')
            except Exception:
                pass
            return CampaignResult(
                target=target.target,
                session_id=session_id,
                findings_count=findings_count,
                duration_seconds=round(duration, 2),
                error=error_msg,
            )

    async def _run_phase_async(
        self, target: str, phase: str, session_id: int
    ) -> int:
        """Run a single phase against a target asynchronously. Returns finding count."""
        from aegis.core.ai_orchestrator import PHASE_TOOLS

        tools = PHASE_TOOLS.get(phase, [])
        findings_count = 0

        for tool_name, cmd_template in tools:
            binary = cmd_template[0] if cmd_template else ""
            if not binary or not shutil.which(binary):
                continue

            cmd = [part.replace("{target}", target) for part in cmd_template]
            timeout_val = self.config.get("profiles.default.timeout", 60)
            timeout = int(timeout_val) if timeout_val is not None else 60

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    raw_stdout, raw_stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout
                    )
                    output = raw_stdout.decode("utf-8", errors="replace").strip()
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.communicate()
                    output = ""

                if output:
                    finding_id = self.db.add_finding(
                        target_id=None,
                        host_id=None,
                        port_id=None,
                        title=f"[{phase}] {tool_name} output",
                        severity="info",
                        category=phase,
                        description=output[:2000],
                        source=tool_name,
                    )
                    conn = self.db.connect()
                    conn.execute(
                        "UPDATE findings SET session_id = ? WHERE id = ?",
                        (session_id, finding_id),
                    )
                    conn.commit()
                    findings_count += 1

            except Exception:
                continue

        return findings_count

    async def run_campaign(
        self, campaign_name: str, targets: list[CampaignTarget]
    ) -> CampaignRun:
        """Run scans against all targets with max_parallel concurrency."""
        run = CampaignRun(campaign_name=campaign_name, targets=targets)
        semaphore = asyncio.Semaphore(self.max_parallel)

        async def bounded_run(t: CampaignTarget) -> CampaignResult:
            async with semaphore:
                return await self.run_target(t)

        tasks = [bounded_run(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, CampaignResult):
                run.results.append(result)
                run.total_findings += result.findings_count
            elif isinstance(result, BaseException):
                # Unexpected error — create a failed result placeholder
                run.results.append(
                    CampaignResult(
                        target="unknown",
                        session_id=0,
                        findings_count=0,
                        duration_seconds=0.0,
                        error=str(result),
                    )
                )

        run.finished_at = datetime.utcnow().isoformat()
        return run

    def run(
        self, campaign_name: str, targets: list[CampaignTarget]
    ) -> CampaignRun:
        """Synchronous wrapper for run_campaign."""
        return asyncio.run(self.run_campaign(campaign_name, targets))
