from __future__ import annotations

import hashlib
from aegis.core.db_manager import DatabaseManager


class Deduplicator:
    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def fingerprint(self, finding: dict) -> str:
        """SHA-256 of (title + target + severity + source) concatenated."""
        title = finding.get("title", "")
        target = finding.get("target", finding.get("url", ""))
        severity = finding.get("severity", "")
        source = finding.get("source", "")
        raw = title + target + severity + source
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_duplicate(self, finding: dict) -> bool:
        """Return True if the fingerprint already exists in finding_hashes."""
        fp = self.fingerprint(finding)
        conn = self.db.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM finding_hashes WHERE fingerprint = ?", (fp,)
        )
        return cursor.fetchone() is not None

    def register(self, finding: dict, finding_id: int | None = None) -> None:
        """Insert fingerprint into finding_hashes; silently ignores duplicates."""
        fp = self.fingerprint(finding)
        conn = self.db.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO finding_hashes (fingerprint, finding_id) VALUES (?, ?)",
            (fp, finding_id),
        )
        conn.commit()

    def filter_new(self, findings: list[dict]) -> list[dict]:
        """Return only findings not yet seen, registering each new one."""
        result: list[dict] = []
        for finding in findings:
            if not self.is_duplicate(finding):
                result.append(finding)
                self.register(finding)
        return result
