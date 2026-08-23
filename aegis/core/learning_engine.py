"""Self-learning feedback engine — persistent knowledge base that evolves with every scan.

This is the brain of Aegis. Unlike traditional scanners that start fresh every time,
this engine:
  1. Builds persistent target profiles (technologies, services, behaviors)
  2. Tracks tool effectiveness (which tools found vulns for which tech stacks)
  3. Learns scan strategies (what works for what, eliminating wasted effort)
  4. Detects drift (changes between scans — new ports, new services, patched vulns)
  5. Correlates patterns across targets (if target A had vuln X, similar target B might too)
  6. Provides intelligent recommendations based on accumulated knowledge

Storage: SQLite (same DB as aegis) with dedicated learning tables.
No external ML libraries needed — pure statistical learning + pattern matching.
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aegis.core.db_manager import DatabaseManager


# ── Database schema for learning tables ───────────────────────────────────────

LEARNING_SCHEMA = """
-- Target profiles: what we know about each target
CREATE TABLE IF NOT EXISTS learning_target_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    target_hash TEXT NOT NULL,
    profile_data TEXT NOT NULL DEFAULT '{}',
    technologies TEXT NOT NULL DEFAULT '[]',
    services TEXT NOT NULL DEFAULT '[]',
    behaviors TEXT NOT NULL DEFAULT '[]',
    scan_count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_fingerprint TEXT NOT NULL DEFAULT '',
    UNIQUE(target_hash)
);

-- Tool effectiveness: which tools found findings for which tech/service
CREATE TABLE IF NOT EXISTS learning_tool_effectiveness (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    technology TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    port INTEGER DEFAULT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    high_sev_count INTEGER NOT NULL DEFAULT 0,
    false_positive_count INTEGER NOT NULL DEFAULT 0,
    avg_runtime_seconds REAL NOT NULL DEFAULT 0,
    last_used TEXT NOT NULL,
    effectiveness_score REAL NOT NULL DEFAULT 0.5,
    UNIQUE(tool_name, technology, service)
);

-- Scan history: what was run, what was found
CREATE TABLE IF NOT EXISTS learning_scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_hash TEXT NOT NULL,
    scan_timestamp TEXT NOT NULL,
    tools_used TEXT NOT NULL DEFAULT '[]',
    findings_count INTEGER NOT NULL DEFAULT 0,
    high_sev_count INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL NOT NULL DEFAULT 0,
    profile_snapshot TEXT NOT NULL DEFAULT '{}',
    strategy_used TEXT NOT NULL DEFAULT ''
);

-- Drift detection: changes between scans
CREATE TABLE IF NOT EXISTS learning_drift_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_hash TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    drift_type TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    old_value TEXT NOT NULL DEFAULT '',
    new_value TEXT NOT NULL DEFAULT '',
    acknowledged INTEGER NOT NULL DEFAULT 0
);

-- Pattern correlations: cross-target intelligence
CREATE TABLE IF NOT EXISTS learning_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_hash TEXT NOT NULL UNIQUE,
    pattern_type TEXT NOT NULL,
    pattern_data TEXT NOT NULL DEFAULT '{}',
    confidence REAL NOT NULL DEFAULT 0.5,
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_matched TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Strategy recommendations: learned optimal scan strategies
CREATE TABLE IF NOT EXISTS learning_strategies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tech_fingerprint TEXT NOT NULL,
    recommended_tools TEXT NOT NULL DEFAULT '[]',
    recommended_phases TEXT NOT NULL DEFAULT '[]',
    avg_findings REAL NOT NULL DEFAULT 0,
    success_rate REAL NOT NULL DEFAULT 0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    last_updated TEXT NOT NULL,
    UNIQUE(tech_fingerprint)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:32]


# ── Target Profile ────────────────────────────────────────────────────────────

class TargetProfile:
    """Represents accumulated knowledge about a single target."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.target_hash = _hash(target)
        self.technologies: List[str] = []
        self.services: List[Dict] = []
        self.behaviors: List[str] = []
        self.scan_count: int = 0
        self.first_seen: str = _now()
        self.last_seen: str = _now()
        self.last_fingerprint: str = ""
        self.profile_data: Dict[str, Any] = {
            "headers": {},
            "open_ports": [],
            "server_software": "",
            "frameworks": [],
            "cms": "",
            "waf_detected": "",
            "cloud_provider": "",
            "cdn": "",
            "historical_vulns": [],
            "patch_history": [],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_hash": self.target_hash,
            "technologies": self.technologies,
            "services": self.services,
            "behaviors": self.behaviors,
            "scan_count": self.scan_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_fingerprint": self.last_fingerprint,
            "profile_data": self.profile_data,
        }

    @classmethod
    def from_db_row(cls, row: Dict) -> "TargetProfile":
        profile = cls(row["target"])
        profile.target_hash = row["target_hash"]
        profile.technologies = json.loads(row.get("technologies", "[]"))
        profile.services = json.loads(row.get("services", "[]"))
        profile.behaviors = json.loads(row.get("behaviors", "[]"))
        profile.scan_count = row.get("scan_count", 0)
        profile.first_seen = row.get("first_seen", _now())
        profile.last_seen = row.get("last_seen", _now())
        profile.last_fingerprint = row.get("last_fingerprint", "")
        profile.profile_data = json.loads(row.get("profile_data", "{}"))
        return profile

    def fingerprint(self) -> str:
        """Generate a fingerprint of the current profile state for drift detection."""
        data = json.dumps({
            "technologies": sorted(self.technologies),
            "services": sorted([json.dumps(s, sort_keys=True) for s in self.services]),
            "open_ports": sorted(self.profile_data.get("open_ports", [])),
        }, sort_keys=True)
        return _hash(data)

    def update_from_scan(
        self,
        services: List[Dict],
        technologies: List[str],
        headers: Dict[str, str],
        findings: List[Dict],
    ) -> List[Dict]:
        """Update profile with new scan data. Returns drift events."""
        drifts = []
        self.scan_count += 1
        self.last_seen = _now()

        # Detect technology changes
        old_tech = set(self.technologies)
        new_tech = set(technologies)
        added_tech = new_tech - old_tech
        removed_tech = old_tech - new_tech

        if added_tech:
            drifts.append({
                "drift_type": "technology_added",
                "description": f"New technologies detected: {', '.join(added_tech)}",
                "severity": "info",
                "old_value": json.dumps(sorted(old_tech)),
                "new_value": json.dumps(sorted(new_tech)),
            })
        if removed_tech:
            drifts.append({
                "drift_type": "technology_removed",
                "description": f"Technologies no longer detected: {', '.join(removed_tech)}",
                "severity": "low",
                "old_value": json.dumps(sorted(old_tech)),
                "new_value": json.dumps(sorted(new_tech)),
            })

        # Detect service changes
        old_ports: set = set(self.profile_data.get("open_ports", []))
        new_ports: set = set(s.get("port") for s in services if s.get("port"))
        added_ports = new_ports - old_ports
        removed_ports = old_ports - new_ports

        if added_ports:
            drifts.append({
                "drift_type": "port_opened",
                "description": f"New open ports: {', '.join(str(p) for p in sorted(added_ports))}",
                "severity": "medium",
                "old_value": json.dumps(sorted(old_ports)),
                "new_value": json.dumps(sorted(new_ports)),
            })
        if removed_ports:
            drifts.append({
                "drift_type": "port_closed",
                "description": f"Ports no longer open: {', '.join(str(p) for p in sorted(removed_ports))}",
                "severity": "low",
                "old_value": json.dumps(sorted(old_ports)),
                "new_value": json.dumps(sorted(new_ports)),
            })

        # Detect server software changes
        old_server = self.profile_data.get("server_software", "")
        new_server = headers.get("server", "")
        if new_server and old_server and new_server != old_server:
            drifts.append({
                "drift_type": "server_changed",
                "description": f"Server software changed: {old_server} → {new_server}",
                "severity": "medium",
                "old_value": old_server,
                "new_value": new_server,
            })

        # Detect patched vulnerabilities
        old_vuln_titles = set(self.profile_data.get("historical_vulns", []))
        new_vuln_titles = set(f.get("title", "") for f in findings)
        patched = old_vuln_titles - new_vuln_titles
        if patched and self.scan_count > 1:
            for title in patched:
                drifts.append({
                    "drift_type": "vulnerability_patched",
                    "description": f"Previously found vulnerability no longer detected: {title}",
                    "severity": "info",
                    "old_value": title,
                    "new_value": "",
                })
                self.profile_data.setdefault("patch_history", []).append({
                    "title": title,
                    "patched_at": _now(),
                })

        # New vulnerabilities
        new_vulns = new_vuln_titles - old_vuln_titles
        if new_vulns and self.scan_count > 1:
            for title in list(new_vulns)[:10]:
                drifts.append({
                    "drift_type": "new_vulnerability",
                    "description": f"New vulnerability detected: {title}",
                    "severity": "high",
                    "old_value": "",
                    "new_value": title,
                })

        # Update profile
        self.technologies = sorted(new_tech)
        self.services = services
        self.profile_data["open_ports"] = sorted(new_ports)
        self.profile_data["server_software"] = new_server or old_server
        self.profile_data["headers"] = headers
        self.profile_data["historical_vulns"] = sorted(new_vuln_titles | old_vuln_titles)

        new_fp = self.fingerprint()
        if self.last_fingerprint and self.last_fingerprint != new_fp:
            drifts.append({
                "drift_type": "profile_changed",
                "description": "Target profile fingerprint changed (overall drift detected)",
                "severity": "info",
                "old_value": self.last_fingerprint,
                "new_value": new_fp,
            })
        self.last_fingerprint = new_fp

        return drifts


# ── Learning Engine ───────────────────────────────────────────────────────────

class LearningEngine:
    """Core self-learning engine. Persists knowledge in SQLite."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db
        self._init_schema()

    def _init_schema(self) -> None:
        """Create learning tables if they don't exist."""
        conn = self._db.connect()
        for statement in LEARNING_SCHEMA.split(";"):
            statement = statement.strip()
            if statement:
                try:
                    conn.execute(statement)
                except Exception:
                    pass
        conn.commit()

    # ── Target Profile Management ─────────────────────────────────────────────

    def get_target_profile(self, target: str) -> Optional[TargetProfile]:
        """Retrieve the learned profile for a target."""
        conn = self._db.connect()
        row = conn.execute(
            "SELECT * FROM learning_target_profiles WHERE target_hash = ?",
            (_hash(target),),
        ).fetchone()
        if row:
            return TargetProfile.from_db_row(dict(row))
        return None

    def save_target_profile(self, profile: TargetProfile) -> None:
        """Persist a target profile to the database."""
        conn = self._db.connect()
        conn.execute("""
            INSERT INTO learning_target_profiles
                (target, target_hash, profile_data, technologies, services,
                 behaviors, scan_count, first_seen, last_seen, last_fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target_hash) DO UPDATE SET
                profile_data = excluded.profile_data,
                technologies = excluded.technologies,
                services = excluded.services,
                behaviors = excluded.behaviors,
                scan_count = excluded.scan_count,
                last_seen = excluded.last_seen,
                last_fingerprint = excluded.last_fingerprint
        """, (
            profile.target,
            profile.target_hash,
            json.dumps(profile.profile_data),
            json.dumps(profile.technologies),
            json.dumps(profile.services),
            json.dumps(profile.behaviors),
            profile.scan_count,
            profile.first_seen,
            profile.last_seen,
            profile.last_fingerprint,
        ))
        conn.commit()

    def get_all_profiles(self, limit: int = 50) -> List[TargetProfile]:
        """Get all known target profiles."""
        conn = self._db.connect()
        rows = conn.execute(
            "SELECT * FROM learning_target_profiles ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [TargetProfile.from_db_row(dict(r)) for r in rows]

    # ── Tool Effectiveness Tracking ───────────────────────────────────────────

    def record_tool_result(
        self,
        tool_name: str,
        technology: str,
        service: str,
        port: Optional[int],
        findings_count: int,
        high_sev_count: int,
        runtime_seconds: float,
    ) -> None:
        """Record the outcome of running a tool. Updates effectiveness score."""
        conn = self._db.connect()

        # Get existing record
        row = conn.execute(
            "SELECT * FROM learning_tool_effectiveness WHERE tool_name=? AND technology=? AND service=?",
            (tool_name, technology, service),
        ).fetchone()

        if row:
            existing = dict(row)
            total_findings = existing["findings_count"] + findings_count
            total_high = existing["high_sev_count"] + high_sev_count
            # Exponential moving average for runtime
            alpha = 0.3
            new_avg_runtime = (alpha * runtime_seconds) + ((1 - alpha) * existing["avg_runtime_seconds"])
            # Effectiveness score: weighted combination
            new_score = self._calculate_effectiveness(
                total_findings, total_high, existing["false_positive_count"], new_avg_runtime
            )
            conn.execute("""
                UPDATE learning_tool_effectiveness SET
                    findings_count = ?,
                    high_sev_count = ?,
                    avg_runtime_seconds = ?,
                    effectiveness_score = ?,
                    last_used = ?
                WHERE tool_name = ? AND technology = ? AND service = ?
            """, (
                total_findings, total_high, new_avg_runtime, new_score, _now(),
                tool_name, technology, service,
            ))
        else:
            score = self._calculate_effectiveness(findings_count, high_sev_count, 0, runtime_seconds)
            conn.execute("""
                INSERT INTO learning_tool_effectiveness
                    (tool_name, technology, service, port, findings_count,
                     high_sev_count, false_positive_count, avg_runtime_seconds,
                     last_used, effectiveness_score)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            """, (
                tool_name, technology, service, port, findings_count,
                high_sev_count, runtime_seconds, _now(), score,
            ))
        conn.commit()

    def record_false_positive(self, tool_name: str, technology: str, service: str) -> None:
        """Record a false positive to decrease tool effectiveness."""
        conn = self._db.connect()
        conn.execute("""
            UPDATE learning_tool_effectiveness SET
                false_positive_count = false_positive_count + 1,
                effectiveness_score = MAX(0, effectiveness_score - 0.05)
            WHERE tool_name = ? AND technology = ? AND service = ?
        """, (tool_name, technology, service))
        conn.commit()

    def get_best_tools(
        self,
        technology: str = "",
        service: str = "",
        top_n: int = 5,
    ) -> List[Dict]:
        """Get the most effective tools for a given tech/service combination."""
        conn = self._db.connect()
        conditions = []
        params: list = []

        if technology:
            conditions.append("technology = ?")
            params.append(technology)
        if service:
            conditions.append("service = ?")
            params.append(service)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        rows = conn.execute(f"""
            SELECT * FROM learning_tool_effectiveness
            {where_clause}
            ORDER BY effectiveness_score DESC
            LIMIT ?
        """, params + [top_n]).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _calculate_effectiveness(
        findings: int,
        high_sev: int,
        false_positives: int,
        avg_runtime: float,
    ) -> float:
        """Calculate tool effectiveness score (0.0 - 1.0)."""
        if findings == 0 and high_sev == 0:
            return 0.1  # Tool ran but found nothing

        # Base score from findings
        finding_score = min(1.0, math.log2(findings + 1) / 5)

        # Bonus for high severity (critical findings matter more)
        severity_bonus = min(0.3, high_sev * 0.1)

        # Penalty for false positives
        fp_penalty = min(0.4, false_positives * 0.05)

        # Speed bonus (faster = better, but not the main factor)
        speed_bonus = max(0, 0.1 - (avg_runtime / 600) * 0.1)

        score = finding_score + severity_bonus - fp_penalty + speed_bonus
        return max(0.0, min(1.0, score))

    # ── Scan History & Drift ──────────────────────────────────────────────────

    def record_scan(
        self,
        target: str,
        tools_used: List[str],
        findings_count: int,
        high_sev_count: int,
        duration_seconds: float,
        strategy: str = "",
    ) -> None:
        """Record a completed scan in the history."""
        conn = self._db.connect()
        profile = self.get_target_profile(target)
        snapshot = profile.to_dict() if profile else {}

        conn.execute("""
            INSERT INTO learning_scan_history
                (target_hash, scan_timestamp, tools_used, findings_count,
                 high_sev_count, duration_seconds, profile_snapshot, strategy_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            _hash(target), _now(), json.dumps(tools_used),
            findings_count, high_sev_count, duration_seconds,
            json.dumps(snapshot, default=str), strategy,
        ))
        conn.commit()

    def record_drift(self, target: str, drift_events: List[Dict]) -> None:
        """Store drift events for a target."""
        if not drift_events:
            return
        conn = self._db.connect()
        for event in drift_events:
            conn.execute("""
                INSERT INTO learning_drift_events
                    (target_hash, detected_at, drift_type, description,
                     severity, old_value, new_value)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                _hash(target), _now(),
                event["drift_type"], event["description"],
                event.get("severity", "info"),
                event.get("old_value", ""),
                event.get("new_value", ""),
            ))
        conn.commit()

    def get_drift_history(self, target: str, limit: int = 50) -> List[Dict]:
        """Get drift events for a target."""
        conn = self._db.connect()
        rows = conn.execute("""
            SELECT * FROM learning_drift_events
            WHERE target_hash = ?
            ORDER BY detected_at DESC
            LIMIT ?
        """, (_hash(target), limit)).fetchall()
        return [dict(r) for r in rows]

    def get_unacknowledged_drifts(self, target: Optional[str] = None) -> List[Dict]:
        """Get drift events that haven't been acknowledged."""
        conn = self._db.connect()
        if target:
            rows = conn.execute("""
                SELECT * FROM learning_drift_events
                WHERE target_hash = ? AND acknowledged = 0
                ORDER BY detected_at DESC
            """, (_hash(target),)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM learning_drift_events
                WHERE acknowledged = 0
                ORDER BY detected_at DESC
            """).fetchall()
        return [dict(r) for r in rows]

    # ── Pattern Correlation ───────────────────────────────────────────────────

    def record_pattern(
        self,
        pattern_type: str,
        pattern_data: Dict,
        confidence: float = 0.5,
    ) -> None:
        """Record a discovered pattern for cross-target intelligence."""
        pattern_str = json.dumps(pattern_data, sort_keys=True)
        pattern_hash = _hash(pattern_str)
        conn = self._db.connect()

        existing = conn.execute(
            "SELECT * FROM learning_patterns WHERE pattern_hash = ?",
            (pattern_hash,),
        ).fetchone()

        if existing:
            # Increase confidence with repeated observation
            new_confidence = min(1.0, dict(existing)["confidence"] + 0.1)
            conn.execute("""
                UPDATE learning_patterns SET
                    confidence = ?,
                    hit_count = hit_count + 1,
                    last_matched = ?
                WHERE pattern_hash = ?
            """, (new_confidence, _now(), pattern_hash))
        else:
            conn.execute("""
                INSERT INTO learning_patterns
                    (pattern_hash, pattern_type, pattern_data, confidence,
                     hit_count, last_matched, created_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (
                pattern_hash, pattern_type, json.dumps(pattern_data),
                confidence, _now(), _now(),
            ))
        conn.commit()

    def find_similar_targets(self, target: str) -> List[Dict]:
        """Find targets with similar profiles (for cross-target intelligence)."""
        profile = self.get_target_profile(target)
        if not profile:
            return []

        all_profiles = self.get_all_profiles(limit=100)
        similarities = []

        for other in all_profiles:
            if other.target_hash == profile.target_hash:
                continue
            score = self._similarity_score(profile, other)
            if score > 0.3:
                similarities.append({
                    "target": other.target,
                    "similarity_score": round(score, 3),
                    "shared_technologies": list(
                        set(profile.technologies) & set(other.technologies)
                    ),
                    "their_vulns": other.profile_data.get("historical_vulns", [])[:5],
                })

        similarities.sort(key=lambda x: x["similarity_score"], reverse=True)
        return similarities[:10]

    @staticmethod
    def _similarity_score(a: TargetProfile, b: TargetProfile) -> float:
        """Calculate Jaccard similarity between two target profiles."""
        tech_a = set(a.technologies)
        tech_b = set(b.technologies)
        if not tech_a and not tech_b:
            return 0.0
        tech_intersection = tech_a & tech_b
        tech_union = tech_a | tech_b
        tech_sim = len(tech_intersection) / len(tech_union) if tech_union else 0

        ports_a = set(a.profile_data.get("open_ports", []))
        ports_b = set(b.profile_data.get("open_ports", []))
        if not ports_a and not ports_b:
            port_sim = 0.0
        else:
            port_union = ports_a | ports_b
            port_sim = len(ports_a & ports_b) / len(port_union) if port_union else 0

        # Weighted combination
        return (tech_sim * 0.6) + (port_sim * 0.4)

    # ── Strategy Recommendations ──────────────────────────────────────────────

    def update_strategy(
        self,
        technologies: List[str],
        tools_used: List[str],
        phases_used: List[str],
        findings_count: int,
    ) -> None:
        """Update learned strategy based on scan results."""
        tech_fp = _hash(",".join(sorted(technologies)))
        conn = self._db.connect()

        existing = conn.execute(
            "SELECT * FROM learning_strategies WHERE tech_fingerprint = ?",
            (tech_fp,),
        ).fetchone()

        if existing:
            row = dict(existing)
            old_tools = json.loads(row["recommended_tools"])
            old_avg = row["avg_findings"]
            sample_count = row["sample_count"]

            # Update with exponential moving average
            new_avg = ((old_avg * sample_count) + findings_count) / (sample_count + 1)

            # Merge tools (keep tools that produce results)
            if findings_count > 0:
                merged_tools = list(set(old_tools + tools_used))
            else:
                merged_tools = old_tools

            success_rate = row["success_rate"]
            if findings_count > 0:
                success_rate = ((success_rate * sample_count) + 1.0) / (sample_count + 1)
            else:
                success_rate = ((success_rate * sample_count) + 0.0) / (sample_count + 1)

            conn.execute("""
                UPDATE learning_strategies SET
                    recommended_tools = ?,
                    recommended_phases = ?,
                    avg_findings = ?,
                    success_rate = ?,
                    sample_count = sample_count + 1,
                    last_updated = ?
                WHERE tech_fingerprint = ?
            """, (
                json.dumps(merged_tools), json.dumps(phases_used),
                new_avg, success_rate, _now(), tech_fp,
            ))
        else:
            conn.execute("""
                INSERT INTO learning_strategies
                    (tech_fingerprint, recommended_tools, recommended_phases,
                     avg_findings, success_rate, sample_count, last_updated)
                VALUES (?, ?, ?, ?, ?, 1, ?)
            """, (
                tech_fp, json.dumps(tools_used), json.dumps(phases_used),
                float(findings_count), 1.0 if findings_count > 0 else 0.0, _now(),
            ))
        conn.commit()

    def recommend_strategy(self, target: str) -> Dict[str, Any]:
        """Get intelligent scan recommendations based on learned knowledge.

        This is the key differentiator: the engine uses everything it has learned
        to suggest the optimal scanning approach for a target.
        """
        profile = self.get_target_profile(target)
        recommendations: Dict[str, Any] = {
            "target": target,
            "confidence": "low",
            "recommended_tools": [],
            "recommended_phases": ["recon", "vuln"],
            "skip_tools": [],
            "focus_areas": [],
            "similar_targets": [],
            "drift_alerts": [],
            "reasoning": [],
        }

        if not profile:
            recommendations["reasoning"].append("No prior knowledge of this target. Running default strategy.")
            return recommendations

        recommendations["confidence"] = "medium" if profile.scan_count >= 2 else "low"
        if profile.scan_count >= 5:
            recommendations["confidence"] = "high"

        # 1. Get best tools for detected technologies
        for tech in profile.technologies:
            best = self.get_best_tools(technology=tech, top_n=3)
            for tool in best:
                if tool["effectiveness_score"] > 0.4:
                    recommendations["recommended_tools"].append(tool["tool_name"])
                    recommendations["reasoning"].append(
                        f"Tool '{tool['tool_name']}' highly effective for {tech} "
                        f"(score={tool['effectiveness_score']:.2f})"
                    )

        # 2. Get best tools for detected services
        for svc in profile.services:
            svc_name = svc.get("name", "")
            if svc_name:
                best = self.get_best_tools(service=svc_name, top_n=2)
                for tool in best:
                    if tool["effectiveness_score"] > 0.3:
                        recommendations["recommended_tools"].append(tool["tool_name"])

        # 3. Strategy from tech fingerprint
        tech_fp = _hash(",".join(sorted(profile.technologies)))
        conn = self._db.connect()
        strategy_row = conn.execute(
            "SELECT * FROM learning_strategies WHERE tech_fingerprint = ?",
            (tech_fp,),
        ).fetchone()
        if strategy_row:
            strategy = dict(strategy_row)
            if strategy["success_rate"] > 0.5:
                recommendations["recommended_phases"] = json.loads(strategy["recommended_phases"])
                recommendations["reasoning"].append(
                    f"Strategy success rate: {strategy['success_rate']:.0%} "
                    f"(from {strategy['sample_count']} previous scans)"
                )

        # 4. Cross-target intelligence
        similar = self.find_similar_targets(target)
        if similar:
            recommendations["similar_targets"] = similar[:3]
            for sim in similar[:3]:
                their_vulns = sim.get("their_vulns", [])
                if their_vulns:
                    recommendations["focus_areas"].extend(their_vulns[:3])
                    recommendations["reasoning"].append(
                        f"Similar target '{sim['target']}' had vulns: "
                        f"{', '.join(their_vulns[:3])}"
                    )

        # 5. Drift alerts
        drifts = self.get_unacknowledged_drifts(target)
        if drifts:
            recommendations["drift_alerts"] = drifts[:5]
            recommendations["reasoning"].append(
                f"{len(drifts)} unacknowledged changes detected since last scan"
            )

        # 6. Tools to skip (low effectiveness)
        conn = self._db.connect()
        low_eff = conn.execute("""
            SELECT tool_name, effectiveness_score FROM learning_tool_effectiveness
            WHERE effectiveness_score < 0.15
            ORDER BY effectiveness_score ASC
            LIMIT 5
        """).fetchall()
        for row in low_eff:
            r = dict(row)
            recommendations["skip_tools"].append(r["tool_name"])
            recommendations["reasoning"].append(
                f"Skipping '{r['tool_name']}' — low effectiveness ({r['effectiveness_score']:.2f})"
            )

        # Deduplicate
        recommendations["recommended_tools"] = list(set(recommendations["recommended_tools"]))
        recommendations["focus_areas"] = list(set(recommendations["focus_areas"]))

        return recommendations

    # ── Learning Integration Point ────────────────────────────────────────────

    def learn_from_scan(
        self,
        target: str,
        services: List[Dict],
        technologies: List[str],
        headers: Dict[str, str],
        findings: List[Dict],
        tools_used: List[str],
        phases_used: List[str],
        duration_seconds: float,
    ) -> Dict[str, Any]:
        """Main integration point: call after every scan to learn from results.

        Returns a summary of what was learned and any drift detected.
        """
        # Get or create profile
        profile = self.get_target_profile(target)
        if not profile:
            profile = TargetProfile(target)

        # Update profile and detect drift
        drift_events = profile.update_from_scan(services, technologies, headers, findings)

        # Save profile
        self.save_target_profile(profile)

        # Record drift
        if drift_events:
            self.record_drift(target, drift_events)

        # Record scan history
        high_sev = sum(
            1 for f in findings
            if str(f.get("severity", "")).lower() in ("high", "critical")
        )
        self.record_scan(
            target, tools_used, len(findings), high_sev, duration_seconds,
            strategy=",".join(phases_used),
        )

        # Record tool effectiveness per technology
        for tool in tools_used:
            tool_findings = [f for f in findings if f.get("source", "") == tool]
            tool_high = sum(
                1 for f in tool_findings
                if str(f.get("severity", "")).lower() in ("high", "critical")
            )
            for tech in technologies:
                self.record_tool_result(
                    tool, tech, "", None,
                    len(tool_findings), tool_high, duration_seconds / max(1, len(tools_used)),
                )

        # Update strategy
        self.update_strategy(technologies, tools_used, phases_used, len(findings))

        # Pattern correlation
        if technologies and findings:
            self.record_pattern(
                "tech_vuln_correlation",
                {"technologies": sorted(technologies), "vuln_types": sorted(set(
                    f.get("category", "") for f in findings
                ))},
                confidence=0.5,
            )

        return {
            "profile_updated": True,
            "scan_count": profile.scan_count,
            "drift_events": drift_events,
            "drift_count": len(drift_events),
            "tools_tracked": len(tools_used),
            "findings_learned": len(findings),
        }

    # ── Statistics & Reporting ────────────────────────────────────────────────

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall learning engine statistics."""
        conn = self._db.connect()

        try:
            profiles_count = conn.execute("SELECT COUNT(*) FROM learning_target_profiles").fetchone()[0]
        except Exception:
            profiles_count = 0
        try:
            tools_count = conn.execute("SELECT COUNT(*) FROM learning_tool_effectiveness").fetchone()[0]
        except Exception:
            tools_count = 0
        try:
            scans_count = conn.execute("SELECT COUNT(*) FROM learning_scan_history").fetchone()[0]
        except Exception:
            scans_count = 0
        try:
            drift_count = conn.execute("SELECT COUNT(*) FROM learning_drift_events").fetchone()[0]
        except Exception:
            drift_count = 0
        try:
            patterns_count = conn.execute("SELECT COUNT(*) FROM learning_patterns").fetchone()[0]
        except Exception:
            patterns_count = 0
        try:
            strategies_count = conn.execute("SELECT COUNT(*) FROM learning_strategies").fetchone()[0]
        except Exception:
            strategies_count = 0

        # Top performing tools
        try:
            top_tools = conn.execute("""
                SELECT tool_name, AVG(effectiveness_score) as avg_score,
                       SUM(findings_count) as total_findings
                FROM learning_tool_effectiveness
                GROUP BY tool_name
                ORDER BY avg_score DESC
                LIMIT 10
            """).fetchall()
        except Exception:
            top_tools = []

        return {
            "knowledge_base": {
                "target_profiles": profiles_count,
                "tool_effectiveness_records": tools_count,
                "scan_history_entries": scans_count,
                "drift_events": drift_count,
                "patterns_discovered": patterns_count,
                "strategies_learned": strategies_count,
            },
            "top_tools": [
                {"name": dict(t)["tool_name"], "avg_score": round(dict(t)["avg_score"], 3),
                 "total_findings": dict(t)["total_findings"]}
                for t in top_tools
            ],
        }
