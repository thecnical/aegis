"""Property-based tests for Aegis (hypothesis).

**Property 12: Note and Tag Non-Destructiveness**
**Validates: Requirements 8.6**
"""
from __future__ import annotations

import sqlite3

from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.core.db_manager import DatabaseManager


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

def _make_db() -> DatabaseManager:
    """Return a fresh in-memory DatabaseManager."""
    mgr = DatabaseManager(":memory:")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    mgr._conn = conn
    mgr.init_db()
    return mgr


def _insert_finding(db: DatabaseManager) -> int:
    return db.add_finding(
        target_id=None,
        host_id=None,
        port_id=None,
        title="prop-test finding",
        severity="high",
        category="web",
        description="description",
        source="hypothesis",
    )


def _snapshot(db: DatabaseManager, finding_id: int) -> dict:
    cursor = db._conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    return dict(cursor.fetchone())


# ---------------------------------------------------------------------------
# Property 12: Note and Tag Non-Destructiveness
# For any non-empty note body or tag label, adding a note/tag to a finding
# must leave every column of that finding row unchanged.
# ---------------------------------------------------------------------------

@given(body=st.text(min_size=1, max_size=500))
@settings(max_examples=100)
def test_property_add_note_non_destructive(body: str) -> None:
    """Adding a note never mutates the linked findings row."""
    db = _make_db()
    fid = _insert_finding(db)
    before = _snapshot(db, fid)

    db.add_note(fid, body)

    after = _snapshot(db, fid)
    assert before == after, (
        f"add_note(body={body!r}) mutated findings row: {before} -> {after}"
    )


@given(label=st.text(min_size=1, max_size=100))
@settings(max_examples=100)
def test_property_add_tag_non_destructive(label: str) -> None:
    """Adding a tag never mutates the linked findings row."""
    db = _make_db()
    fid = _insert_finding(db)
    before = _snapshot(db, fid)

    db.add_tag(fid, label)

    after = _snapshot(db, fid)
    assert before == after, (
        f"add_tag(label={label!r}) mutated findings row: {before} -> {after}"
    )


@given(
    body=st.text(min_size=1, max_size=500),
    label=st.text(min_size=1, max_size=100),
)
@settings(max_examples=100)
def test_property_add_note_and_tag_non_destructive(body: str, label: str) -> None:
    """Adding both a note and a tag never mutates the linked findings row."""
    db = _make_db()
    fid = _insert_finding(db)
    before = _snapshot(db, fid)

    db.add_note(fid, body)
    db.add_tag(fid, label)

    after = _snapshot(db, fid)
    assert before == after, (
        f"add_note+add_tag mutated findings row: {before} -> {after}"
    )
