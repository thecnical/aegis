from __future__ import annotations

from dataclasses import dataclass

try:
    from cvss import CVSS3
    _CVSS_AVAILABLE = True
except ImportError:
    _CVSS_AVAILABLE = False


@dataclass
class CVSSResult:
    score: float
    vector: str
    severity: str


# Heuristic CVSS v3.1 vectors keyed by nuclei severity
_SEVERITY_VECTORS: dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "medium":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
    "low":      "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

_FALLBACK_SCORES: dict[str, float] = {
    "critical": 9.8,
    "high":     8.1,
    "medium":   5.3,
    "low":      2.1,
    "info":     0.0,
}


class CVSSScorer:
    def score(self, finding: dict) -> CVSSResult:
        """Return a CVSSResult for the given finding dict."""
        severity = str(finding.get("severity", "info")).lower()
        vector = _SEVERITY_VECTORS.get(severity, _SEVERITY_VECTORS["info"])

        if _CVSS_AVAILABLE:
            try:
                c = CVSS3(vector)
                numeric = float(c.base_score)
            except Exception:
                numeric = _FALLBACK_SCORES.get(severity, 0.0)
        else:
            numeric = _FALLBACK_SCORES.get(severity, 0.0)

        # Clamp to [0.0, 10.0] for safety
        numeric = max(0.0, min(10.0, numeric))
        return CVSSResult(score=numeric, vector=vector, severity=self.severity_from_score(numeric))

    def severity_from_score(self, score: float) -> str:
        """Map a CVSS v3.1 numeric score to a severity label (no gaps)."""
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "info"
