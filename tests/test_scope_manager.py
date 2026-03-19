"""Unit tests for ScopeManager."""
from __future__ import annotations

import pytest
import click

from aegis.core.scope_manager import ScopeManager
from aegis.core.db_manager import DatabaseManager


def test_empty_scope_is_open(db: DatabaseManager) -> None:
    sm = ScopeManager(db, safe_mode=True)
    assert sm.is_in_scope("192.168.1.1") is True


def test_exact_ip_match(db: DatabaseManager) -> None:
    sm = ScopeManager(db, safe_mode=True)
    sm.add_target("10.0.0.1", "ip")
    assert sm.is_in_scope("10.0.0.1") is True
    assert sm.is_in_scope("10.0.0.2") is False


def test_cidr_containment(db: DatabaseManager) -> None:
    sm = ScopeManager(db, safe_mode=True)
    sm.add_target("192.168.1.0/24", "cidr")
    assert sm.is_in_scope("192.168.1.100") is True
    assert sm.is_in_scope("192.168.2.1") is False


def test_domain_suffix_match(db: DatabaseManager) -> None:
    sm = ScopeManager(db, safe_mode=True)
    sm.add_target("example.com", "domain")
    assert sm.is_in_scope("sub.example.com") is True
    assert sm.is_in_scope("example.com") is True
    assert sm.is_in_scope("notexample.com") is False


def test_safe_mode_false_bypasses_scope(db: DatabaseManager) -> None:
    sm = ScopeManager(db, safe_mode=False)
    sm.add_target("10.0.0.1", "ip")
    # Should not raise even for out-of-scope target
    sm.validate_or_abort("99.99.99.99")


def test_validate_or_abort_raises_when_out_of_scope(db: DatabaseManager) -> None:
    sm = ScopeManager(db, safe_mode=True)
    sm.add_target("10.0.0.1", "ip")
    with pytest.raises(click.Abort):
        sm.validate_or_abort("99.99.99.99")


def test_remove_target(db: DatabaseManager) -> None:
    sm = ScopeManager(db, safe_mode=True)
    tid = sm.add_target("10.0.0.5", "ip")
    sm.remove_target(tid)
    # After removal, scope is empty → open scope
    assert sm.is_in_scope("10.0.0.5") is True


def test_list_targets(db: DatabaseManager) -> None:
    sm = ScopeManager(db, safe_mode=True)
    sm.add_target("example.com", "domain")
    sm.add_target("10.0.0.0/8", "cidr")
    entries = sm.list_targets()
    assert len(entries) == 2
