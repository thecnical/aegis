"""Unit tests for CVSSScorer."""
from __future__ import annotations

import pytest

from aegis.core.cvss_scorer import CVSSScorer


@pytest.fixture()
def scorer() -> CVSSScorer:
    return CVSSScorer()


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_score_range(scorer: CVSSScorer, severity: str) -> None:
    result = scorer.score({"severity": severity})
    assert 0.0 <= result.score <= 10.0


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_score_returns_vector(scorer: CVSSScorer, severity: str) -> None:
    result = scorer.score({"severity": severity})
    assert result.vector.startswith("CVSS:3.1/")


@pytest.mark.parametrize("score,expected", [
    (0.0, "info"),
    (0.1, "low"),
    (3.9, "low"),
    (4.0, "medium"),
    (6.9, "medium"),
    (7.0, "high"),
    (8.9, "high"),
    (9.0, "critical"),
    (10.0, "critical"),
])
def test_severity_from_score(scorer: CVSSScorer, score: float, expected: str) -> None:
    assert scorer.severity_from_score(score) == expected


def test_unknown_severity_defaults_to_info(scorer: CVSSScorer) -> None:
    result = scorer.score({"severity": "unknown_xyz"})
    assert 0.0 <= result.score <= 10.0
