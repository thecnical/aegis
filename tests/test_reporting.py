"""Unit tests for reporting module."""
from __future__ import annotations


from aegis.core.reporting import render_report, render_report_html, SEVERITY_RANK, _filter_by_severity


def _make_data(findings=None, vulns=None):
    return {
        "hosts": [], "ports": [], "services": [],
        "findings": findings or [],
        "vulns": vulns or [],
    }


def test_filter_by_severity_none_returns_all() -> None:
    items = [{"severity": "info"}, {"severity": "critical"}]
    assert _filter_by_severity(items, None) == items


def test_filter_by_severity_medium() -> None:
    items = [
        {"severity": "info"},
        {"severity": "low"},
        {"severity": "medium"},
        {"severity": "high"},
        {"severity": "critical"},
    ]
    result = _filter_by_severity(items, "medium")
    severities = [i["severity"] for i in result]
    assert "info" not in severities
    assert "low" not in severities
    assert "medium" in severities
    assert "critical" in severities


def test_render_report_min_severity_filters(tmp_path) -> None:
    findings = [
        {"id": 1, "title": "Info finding", "severity": "info", "source": "test", "description": "d", "category": "web"},
        {"id": 2, "title": "Critical finding", "severity": "critical", "source": "test", "description": "d", "category": "web"},
    ]
    data = _make_data(findings=findings)
    report = render_report("target", data, {}, None, "Aegis", min_severity="high")
    assert "Critical finding" in report
    assert "Info finding" not in report


def test_render_report_html_min_severity_filters() -> None:
    findings = [
        {"id": 1, "title": "Low finding", "severity": "low", "source": "test", "description": "d", "category": "web"},
        {"id": 2, "title": "High finding", "severity": "high", "source": "test", "description": "d", "category": "web"},
    ]
    data = _make_data(findings=findings)
    html = render_report_html("target", data, {}, None, "Aegis", min_severity="high")
    assert "High finding" in html
    assert "Low finding" not in html


def test_severity_rank_coverage() -> None:
    for sev in ("info", "low", "medium", "high", "critical"):
        assert sev in SEVERITY_RANK
