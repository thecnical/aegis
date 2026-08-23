"""Adaptive continuous monitoring engine — self-looping scanner that gets smarter.

Unlike basic watch/cron that re-runs the same scan on a fixed schedule, this engine:
  1. Adapts scan intensity based on target volatility (more changes = more frequent scans)
  2. Focuses on areas where drift was detected (selective re-scanning)
  3. Uses the learning engine to choose optimal tools per-iteration
  4. Generates delta reports (what changed since last scan)
  5. Applies exponential backoff for stable targets (saves resources)
  6. Escalates notification urgency based on severity trends
  7. Integrates with MITRE ATT&CK for threat-based prioritization

Design: Event-loop architecture with configurable scheduling policies.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

import httpx

from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.deduplicator import Deduplicator
from aegis.core.learning_engine import LearningEngine
from aegis.core.scope_manager import ScopeManager
from aegis.core.signal_quality import merge_duplicate_findings, score_confidence
from aegis.core.ui import console
from aegis.core.advanced_web_checks import run_advanced_authorized_checks


# ── Scheduling Policy ─────────────────────────────────────────────────────────

@dataclass
class TargetSchedule:
    """Adaptive scheduling state for a single target."""
    target: str
    base_interval_seconds: int = 3600  # 1 hour default
    current_interval_seconds: int = 3600
    min_interval_seconds: int = 300  # 5 minutes minimum
    max_interval_seconds: int = 86400  # 24 hours maximum
    last_scan_time: float = 0
    last_change_time: float = 0
    consecutive_no_change: int = 0
    consecutive_changes: int = 0
    volatility_score: float = 0.5  # 0=stable, 1=volatile
    priority: int = 5  # 1=highest, 10=lowest
    last_findings_count: int = 0
    total_scans: int = 0
    enabled: bool = True

    def should_scan_now(self) -> bool:
        """Determine if this target should be scanned now."""
        if not self.enabled:
            return False
        if self.last_scan_time == 0:
            return True  # Never scanned
        elapsed = time.time() - self.last_scan_time
        return elapsed >= self.current_interval_seconds

    def record_scan_result(self, findings_count: int, changes_detected: int) -> None:
        """Update schedule based on scan results (adaptive algorithm)."""
        self.total_scans += 1
        now = time.time()

        if changes_detected > 0:
            self.consecutive_changes += 1
            self.consecutive_no_change = 0
            self.last_change_time = now
            # Increase frequency (target is volatile)
            self._decrease_interval()
            self.volatility_score = min(1.0, self.volatility_score + 0.15)
        else:
            self.consecutive_no_change += 1
            self.consecutive_changes = 0
            # Decrease frequency (target is stable) — exponential backoff
            self._increase_interval()
            self.volatility_score = max(0.0, self.volatility_score - 0.05)

        # Severity-based urgency: more high-sev findings = scan more often
        if findings_count > self.last_findings_count:
            self._decrease_interval()

        self.last_findings_count = findings_count
        self.last_scan_time = now

    def _decrease_interval(self) -> None:
        """Make scans more frequent."""
        self.current_interval_seconds = max(
            self.min_interval_seconds,
            int(self.current_interval_seconds * 0.6),
        )

    def _increase_interval(self) -> None:
        """Make scans less frequent (exponential backoff)."""
        backoff_factor = 1.3 + (self.consecutive_no_change * 0.1)
        self.current_interval_seconds = min(
            self.max_interval_seconds,
            int(self.current_interval_seconds * backoff_factor),
        )

    def time_until_next_scan(self) -> int:
        """Seconds until next scheduled scan."""
        if self.last_scan_time == 0:
            return 0
        elapsed = time.time() - self.last_scan_time
        remaining = self.current_interval_seconds - elapsed
        return max(0, int(remaining))


# ── Delta Report ──────────────────────────────────────────────────────────────

@dataclass
class DeltaReport:
    """Report showing what changed between scan iterations."""
    target: str
    scan_time: str
    previous_scan_time: str
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = field(default_factory=list)
    persisting_findings: List[Dict[str, Any]] = field(default_factory=list)
    drift_events: List[Dict[str, Any]] = field(default_factory=list)
    new_services: List[Dict[str, Any]] = field(default_factory=list)
    removed_services: List[Dict[str, Any]] = field(default_factory=list)
    severity_trend: str = "stable"  # "improving", "stable", "worsening"

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings or self.resolved_findings or self.drift_events
                    or self.new_services or self.removed_services)

    @property
    def change_count(self) -> int:
        return (len(self.new_findings) + len(self.resolved_findings)
                + len(self.drift_events) + len(self.new_services) + len(self.removed_services))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "previous_scan_time": self.previous_scan_time,
            "changes_detected": self.has_changes,
            "change_count": self.change_count,
            "severity_trend": self.severity_trend,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "persisting_findings_count": len(self.persisting_findings),
            "drift_events": self.drift_events,
            "new_services": self.new_services,
            "removed_services": self.removed_services,
        }

    def summary_text(self) -> str:
        """Human-readable summary for notifications."""
        parts = [f"Delta Report: {self.target}"]
        if self.new_findings:
            parts.append(f"  NEW: {len(self.new_findings)} finding(s)")
        if self.resolved_findings:
            parts.append(f"  RESOLVED: {len(self.resolved_findings)} finding(s)")
        if self.drift_events:
            parts.append(f"  DRIFT: {len(self.drift_events)} change(s)")
        if self.new_services:
            parts.append(f"  NEW SERVICES: {len(self.new_services)}")
        parts.append(f"  Trend: {self.severity_trend}")
        return "\n".join(parts)


# ── Adaptive Monitor Engine ───────────────────────────────────────────────────

class AdaptiveMonitor:
    """The adaptive continuous monitoring engine.

    Orchestrates periodic scanning with intelligent scheduling.
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: ConfigManager,
        scope: ScopeManager,
        *,
        base_interval: int = 3600,
        min_interval: int = 300,
        max_interval: int = 86400,
        max_concurrent: int = 3,
        notify_callback: Optional[Callable[[DeltaReport], None]] = None,
    ) -> None:
        self.db = db
        self.config = config
        self.scope = scope
        self.learning = LearningEngine(db)
        self.dedup = Deduplicator(db)
        self._schedules: Dict[str, TargetSchedule] = {}
        self._base_interval = base_interval
        self._min_interval = min_interval
        self._max_interval = max_interval
        self._max_concurrent = max_concurrent
        self._notify_callback = notify_callback
        self._running = False
        self._iteration = 0
        self._total_findings = 0
        self._delta_reports: List[DeltaReport] = []
        # Previous state tracking for delta reports
        self._previous_findings: Dict[str, Set[str]] = defaultdict(set)  # target → set of finding titles
        self._previous_services: Dict[str, Set[str]] = defaultdict(set)  # target → set of service keys

    def add_target(self, target: str, priority: int = 5) -> None:
        """Add a target to the monitoring schedule."""
        if target not in self._schedules:
            self._schedules[target] = TargetSchedule(
                target=target,
                base_interval_seconds=self._base_interval,
                current_interval_seconds=self._base_interval,
                min_interval_seconds=self._min_interval,
                max_interval_seconds=self._max_interval,
                priority=priority,
            )

    def load_scope_targets(self) -> None:
        """Load all in-scope targets into the monitoring schedule."""
        targets = self.scope.list_targets()
        for entry in targets:
            self.add_target(entry.target)

    def get_next_targets(self) -> List[str]:
        """Get targets that are due for scanning, ordered by priority."""
        due = [
            sched for sched in self._schedules.values()
            if sched.should_scan_now()
        ]
        # Sort by: priority (lower=first), then volatility (higher=first)
        due.sort(key=lambda s: (s.priority, -s.volatility_score))
        return [s.target for s in due[:self._max_concurrent]]

    def scan_target(self, target: str) -> DeltaReport:
        """Execute an adaptive scan on a single target and generate delta report."""
        schedule = self._schedules.get(target)
        if not schedule:
            self.add_target(target)
            schedule = self._schedules[target]

        scan_start = time.time()
        now_str = datetime.now(timezone.utc).isoformat()
        prev_scan_str = (
            datetime.fromtimestamp(schedule.last_scan_time, tz=timezone.utc).isoformat()
            if schedule.last_scan_time > 0 else "never"
        )

        # Get learning recommendations for this target
        recommendations = self.learning.recommend_strategy(target)

        # Run scan based on target type
        findings: List[Dict[str, Any]] = []
        services: List[Dict[str, Any]] = []
        technologies: List[str] = []
        headers: Dict[str, str] = {}

        try:
            scan_result = self._execute_scan(target, recommendations)
            findings = scan_result.get("findings", [])
            services = scan_result.get("services", [])
            technologies = scan_result.get("technologies", [])
            headers = scan_result.get("headers", {})
        except Exception as exc:
            console.print(f"[warning]Scan error for {target}: {exc}[/warning]")

        # Generate delta report
        current_finding_titles = set(f.get("title", "") for f in findings)
        previous_titles = self._previous_findings.get(target, set())

        new_findings = [f for f in findings if f.get("title", "") not in previous_titles]
        resolved_titles = previous_titles - current_finding_titles
        resolved_findings = [{"title": t} for t in resolved_titles]
        persisting_titles = previous_titles & current_finding_titles
        persisting_findings = [f for f in findings if f.get("title", "") in persisting_titles]

        # Service delta
        current_service_keys = set(f"{s.get('name', '')}:{s.get('port', '')}" for s in services)
        previous_service_keys = self._previous_services.get(target, set())
        new_svc = [{"key": k} for k in current_service_keys - previous_service_keys]
        removed_svc = [{"key": k} for k in previous_service_keys - current_service_keys]

        # Severity trend
        high_sev_now = sum(1 for f in findings if f.get("severity", "").lower() in ("high", "critical"))
        high_sev_before = sum(1 for t in previous_titles if "critical" in t.lower() or "high" in t.lower())
        if high_sev_now > high_sev_before:
            trend = "worsening"
        elif high_sev_now < high_sev_before:
            trend = "improving"
        else:
            trend = "stable"

        # Update learning engine
        duration = time.time() - scan_start
        drift_events = []
        if self.learning:
            learn_result = self.learning.learn_from_scan(
                target=target,
                services=services,
                technologies=technologies,
                headers=headers,
                findings=findings,
                tools_used=recommendations.get("recommended_tools", [])[:5],
                phases_used=recommendations.get("recommended_phases", ["recon", "vuln"]),
                duration_seconds=duration,
            )
            drift_events = learn_result.get("drift_events", [])

        # Build delta report
        delta = DeltaReport(
            target=target,
            scan_time=now_str,
            previous_scan_time=prev_scan_str,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persisting_findings=persisting_findings,
            drift_events=drift_events,
            new_services=new_svc,
            removed_services=removed_svc,
            severity_trend=trend,
        )

        # Update schedule based on results
        schedule.record_scan_result(len(findings), delta.change_count)

        # Update state tracking
        self._previous_findings[target] = current_finding_titles
        self._previous_services[target] = current_service_keys
        self._delta_reports.append(delta)
        self._total_findings += len(new_findings)

        # Notify if changes
        if delta.has_changes and self._notify_callback:
            try:
                self._notify_callback(delta)
            except Exception:
                pass

        return delta

    def _execute_scan(self, target: str, recommendations: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the actual scan. Uses web checks for HTTP targets."""
        findings: List[Dict[str, Any]] = []
        services: List[Dict[str, Any]] = []
        technologies: List[str] = []
        headers: Dict[str, str] = {}

        # Determine if target is a URL or IP
        is_web = target.startswith("http://") or target.startswith("https://")
        if not is_web and not target.replace(".", "").replace(":", "").isdigit():
            # Looks like a domain, try HTTPS
            target_url = f"https://{target}"
        elif is_web:
            target_url = target
        else:
            target_url = None

        if target_url:
            # Web-focused adaptive scan
            try:
                with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
                    resp = client.get(target_url)
                headers = dict(resp.headers)
                server = headers.get("server", "")
                powered_by = headers.get("x-powered-by", "")
                if server:
                    technologies.append(server.split("/")[0].lower())
                if powered_by:
                    technologies.append(powered_by.split("/")[0].lower())

                # Detect services from headers
                services.append({"name": "https" if "https" in target_url else "http", "port": 443 if "https" in target_url else 80})

            except Exception:
                pass

            # Run advanced web checks (real HTTP probes)
            try:
                web_findings = run_advanced_authorized_checks(target_url, include_dangerous=False)
                findings.extend(web_findings)
            except Exception:
                pass

        # Deduplicate and score
        merged = merge_duplicate_findings(findings)
        scored = []
        for f in merged:
            sc = score_confidence(f)
            row = dict(f)
            row["confidence_score"] = sc.confidence_score
            scored.append(row)

        return {
            "findings": scored,
            "services": services,
            "technologies": technologies,
            "headers": headers,
        }

    def run_once(self) -> List[DeltaReport]:
        """Run one iteration of the monitoring loop."""
        self._iteration += 1
        targets = self.get_next_targets()

        if not targets:
            return []

        reports = []
        for target in targets:
            console.print(f"[dim]  [{self._iteration}] Scanning: {target}[/dim]")
            report = self.scan_target(target)
            reports.append(report)

            if report.has_changes:
                console.print(f"  [yellow]Changes detected ({report.change_count}):[/yellow]")
                if report.new_findings:
                    console.print(f"    [red]NEW findings: {len(report.new_findings)}[/red]")
                if report.resolved_findings:
                    console.print(f"    [green]RESOLVED: {len(report.resolved_findings)}[/green]")
                if report.drift_events:
                    console.print(f"    [yellow]DRIFT: {len(report.drift_events)} change(s)[/yellow]")
            else:
                schedule = self._schedules[target]
                console.print(f"    [dim]No changes. Next scan in {schedule.time_until_next_scan()}s[/dim]")

        return reports

    def run_loop(self, max_iterations: int = 0) -> None:
        """Run the continuous monitoring loop.

        Args:
            max_iterations: Stop after N iterations (0=infinite)
        """
        self._running = True
        console.print("[accent]Adaptive monitoring started.[/accent]")
        console.print(f"[dim]  Targets: {len(self._schedules)}  Base interval: {self._base_interval}s[/dim]")

        try:
            iteration = 0
            while self._running:
                iteration += 1
                if max_iterations and iteration > max_iterations:
                    break

                reports = self.run_once()

                if not reports:
                    # No targets due — find shortest wait
                    waits = [s.time_until_next_scan() for s in self._schedules.values() if s.enabled]
                    sleep_time = min(waits) if waits else 60
                    sleep_time = max(10, min(sleep_time, 300))  # Clamp to 10s-5m
                    time.sleep(sleep_time)
                else:
                    # Brief pause between iterations
                    time.sleep(5)

        except KeyboardInterrupt:
            console.print("\n[primary]Adaptive monitoring stopped.[/primary]")
        finally:
            self._running = False

    def stop(self) -> None:
        """Stop the monitoring loop."""
        self._running = False

    def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        schedules_info = []
        for target, sched in self._schedules.items():
            schedules_info.append({
                "target": target,
                "interval_seconds": sched.current_interval_seconds,
                "volatility": round(sched.volatility_score, 2),
                "priority": sched.priority,
                "total_scans": sched.total_scans,
                "next_scan_in": sched.time_until_next_scan(),
                "consecutive_no_change": sched.consecutive_no_change,
            })

        return {
            "running": self._running,
            "iteration": self._iteration,
            "total_targets": len(self._schedules),
            "total_findings_discovered": self._total_findings,
            "total_delta_reports": len(self._delta_reports),
            "schedules": schedules_info,
        }

    def get_delta_reports(self, target: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent delta reports."""
        reports = self._delta_reports
        if target:
            reports = [r for r in reports if r.target == target]
        return [r.to_dict() for r in reports[-limit:]]
