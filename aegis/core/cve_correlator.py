"""CVE correlation via NVD API v2 for Aegis."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional

from aegis.core.db_manager import DatabaseManager
from aegis.core.utils import get_http_session

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Common words to strip when building search keywords
_STOP_WORDS = frozenset(
    {
        "vulnerability", "vulnerabilities", "injection", "attack", "exploit",
        "remote", "local", "code", "execution", "arbitrary", "bypass",
        "disclosure", "information", "cross", "site", "scripting", "request",
        "forgery", "overflow", "buffer", "heap", "stack", "use", "after",
        "free", "null", "pointer", "dereference", "the", "and", "or", "in",
        "of", "a", "an", "to", "via", "with", "for", "on", "at", "by",
        "reflected", "stored", "blind", "based", "error", "time",
    }
)


@dataclass
class CVEMatch:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    published: str
    severity: str
    url: str


def _extract_keywords(text: str) -> str:
    """Extract meaningful keywords from a finding title/description."""
    # Lowercase, remove punctuation, split
    words = re.sub(r"[^\w\s]", " ", text.lower()).split()
    keywords = [w for w in words if w not in _STOP_WORDS and len(w) > 2]
    # Take first 3 meaningful keywords to keep query focused
    return " ".join(keywords[:3])


def _parse_cvss_v31(metrics: dict) -> tuple[Optional[float], Optional[str]]:
    """Extract CVSS v3.1 score and vector from NVD metrics dict."""
    v31_list = metrics.get("cvssMetricV31", [])
    if v31_list:
        cvss_data = v31_list[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")
        return (float(score) if score is not None else None, vector)
    # Fall back to v3.0
    v30_list = metrics.get("cvssMetricV30", [])
    if v30_list:
        cvss_data = v30_list[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")
        return (float(score) if score is not None else None, vector)
    # Fall back to v2
    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list:
        cvss_data = v2_list[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        return (float(score) if score is not None else None, None)
    return None, None


def _score_to_severity(score: Optional[float]) -> str:
    """Convert CVSS score to Aegis severity label."""
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def search_cve(
    keyword: str,
    max_results: int = 5,
    api_key: Optional[str] = None,
) -> list[CVEMatch]:
    """Search NVD for CVEs matching keyword.

    Rate-limited to 1 req/6s without API key, 0.6s with key.
    """
    session = get_http_session(retries=2, backoff=1.0)
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    params: dict[str, str | int] = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 20),
    }

    try:
        resp = session.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        if resp.status_code == 429:
            # Rate limited — wait and retry once
            wait = 6.0 if not api_key else 0.6
            time.sleep(wait)
            resp = session.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    matches: list[CVEMatch] = []
    for vuln_entry in data.get("vulnerabilities", [])[:max_results]:
        cve = vuln_entry.get("cve", {})
        cve_id = cve.get("id", "")

        # Get English description
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_score, cvss_vector = _parse_cvss_v31(metrics)
        severity = _score_to_severity(cvss_score)
        published = cve.get("published", "")
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        matches.append(
            CVEMatch(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published=published,
                severity=severity,
                url=url,
            )
        )

    return matches


def correlate_finding(
    finding: dict,
    db: DatabaseManager,
    api_key: Optional[str] = None,
) -> list[CVEMatch]:
    """Find CVEs matching a finding's title/description. Returns top matches."""
    title = str(finding.get("title", ""))
    description = str(finding.get("description", ""))

    # Build keyword from title first, fall back to description
    keyword = _extract_keywords(title)
    if not keyword:
        keyword = _extract_keywords(description[:200])
    if not keyword:
        return []

    matches = search_cve(keyword, max_results=5, api_key=api_key)

    # Store matches in DB
    finding_id = int(finding.get("id", 0))
    if finding_id and matches:
        for match in matches:
            try:
                db.add_cve_correlation(
                    finding_id=finding_id,
                    cve_id=match.cve_id,
                    description=match.description,
                    cvss_score=match.cvss_score,
                    cvss_vector=match.cvss_vector,
                    severity=match.severity,
                    published=match.published,
                    url=match.url,
                )
            except Exception:
                pass  # Duplicate or DB error — skip

    return matches


def correlate_all_findings(
    db: DatabaseManager,
    session_id: Optional[int] = None,
    api_key: Optional[str] = None,
) -> dict[int, list[CVEMatch]]:
    """Correlate all findings (or session findings) with CVEs.

    Returns finding_id -> CVEs mapping.
    """
    if session_id is not None:
        findings = db.get_session_findings(session_id)
    else:
        findings = db.get_all_findings(limit=200)

    rate_delay = 0.6 if api_key else 6.0
    results: dict[int, list[CVEMatch]] = {}

    for i, finding in enumerate(findings):
        finding_id = int(finding.get("id", 0))
        if not finding_id:
            continue

        matches = correlate_finding(finding, db, api_key=api_key)
        results[finding_id] = matches

        # Rate limiting between requests (skip delay after last item)
        if i < len(findings) - 1:
            time.sleep(rate_delay)

    return results
