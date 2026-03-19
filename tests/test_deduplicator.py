"""Unit tests for Deduplicator."""
from __future__ import annotations

from aegis.core.deduplicator import Deduplicator
from aegis.core.db_manager import DatabaseManager


def _finding(title: str = "Test", target: str = "10.0.0.1", severity: str = "high", source: str = "test") -> dict:
    return {"title": title, "target": target, "severity": severity, "source": source}


def test_fingerprint_deterministic(db: DatabaseManager) -> None:
    d = Deduplicator(db)
    f = _finding()
    assert d.fingerprint(f) == d.fingerprint(f)


def test_fingerprint_differs_on_different_input(db: DatabaseManager) -> None:
    d = Deduplicator(db)
    assert d.fingerprint(_finding(title="A")) != d.fingerprint(_finding(title="B"))


def test_is_duplicate_false_initially(db: DatabaseManager) -> None:
    d = Deduplicator(db)
    assert d.is_duplicate(_finding()) is False


def test_register_then_is_duplicate(db: DatabaseManager) -> None:
    d = Deduplicator(db)
    f = _finding()
    d.register(f)
    assert d.is_duplicate(f) is True


def test_filter_new_returns_new_only(db: DatabaseManager) -> None:
    d = Deduplicator(db)
    findings = [_finding("A"), _finding("B"), _finding("C")]
    result = d.filter_new(findings)
    assert len(result) == 3


def test_filter_new_idempotent(db: DatabaseManager) -> None:
    d = Deduplicator(db)
    findings = [_finding("X"), _finding("Y")]
    first = d.filter_new(findings)
    second = d.filter_new(findings)
    assert len(first) == 2
    assert len(second) == 0  # all already registered


def test_filter_new_suppresses_duplicates(db: DatabaseManager) -> None:
    d = Deduplicator(db)
    f = _finding()
    d.filter_new([f])
    result = d.filter_new([f])
    assert result == []
