"""Unit tests for DatabaseManager schema migrations (Task 1.1)."""
from __future__ import annotations

import sqlite3

import pytest

from aegis.core.db_manager import DatabaseManager


@pytest.fixture()
def db() -> DatabaseManager:
    """Return a DatabaseManager backed by an in-memory SQLite database."""
    mgr = DatabaseManager(":memory:")
    # Override connect so it uses a shared in-memory connection
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    mgr._conn = conn
    mgr.init_db()
    return mgr


# ---------------------------------------------------------------------------
# 1. All seven new tables are created on a fresh in-memory DB
# ---------------------------------------------------------------------------

NEW_TABLES = [
    "workspaces",
    "scope",
    "notes",
    "tags",
    "finding_hashes",
    "ai_results",
    "scan_sessions",
]


@pytest.mark.parametrize("table", NEW_TABLES)
def test_new_tables_exist(db: DatabaseManager, table: str) -> None:
    cursor = db._conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    )
    assert cursor.fetchone() is not None, f"Table '{table}' was not created"


# ---------------------------------------------------------------------------
# 2. ALTER TABLE migrations are idempotent (run init_db() twice, no error)
# ---------------------------------------------------------------------------

def test_init_db_idempotent(db: DatabaseManager) -> None:
    """Calling init_db() a second time must not raise."""
    db.init_db()  # second call — should be a no-op


# ---------------------------------------------------------------------------
# 3. New findings columns are present after migration
# ---------------------------------------------------------------------------

NEW_FINDINGS_COLUMNS = ["cvss_score", "cvss_vector", "deduplicated", "session_id"]


@pytest.mark.parametrize("col", NEW_FINDINGS_COLUMNS)
def test_findings_new_columns_exist(db: DatabaseManager, col: str) -> None:
    cursor = db._conn.cursor()
    cursor.execute("PRAGMA table_info(findings)")
    columns = {row["name"] for row in cursor.fetchall()}
    assert col in columns, f"Column 'findings.{col}' is missing"


# ---------------------------------------------------------------------------
# 4. add_note / add_tag do NOT mutate the findings row
# ---------------------------------------------------------------------------

def _insert_finding(db: DatabaseManager) -> int:
    return db.add_finding(
        target_id=None,
        host_id=None,
        port_id=None,
        title="Test finding",
        severity="medium",
        category="web",
        description="desc",
        source="test",
    )


def test_add_note_does_not_mutate_finding(db: DatabaseManager) -> None:
    fid = _insert_finding(db)
    cursor = db._conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (fid,))
    before = dict(cursor.fetchone())

    db.add_note(fid, "some note body")

    cursor.execute("SELECT * FROM findings WHERE id = ?", (fid,))
    after = dict(cursor.fetchone())
    assert before == after, "add_note mutated the findings row"


def test_add_tag_does_not_mutate_finding(db: DatabaseManager) -> None:
    fid = _insert_finding(db)
    cursor = db._conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (fid,))
    before = dict(cursor.fetchone())

    db.add_tag(fid, "confirmed")

    cursor.execute("SELECT * FROM findings WHERE id = ?", (fid,))
    after = dict(cursor.fetchone())
    assert before == after, "add_tag mutated the findings row"


# ---------------------------------------------------------------------------
# 5. add_note / get_notes round-trip
# ---------------------------------------------------------------------------

def test_add_and_get_notes(db: DatabaseManager) -> None:
    fid = _insert_finding(db)
    nid = db.add_note(fid, "first note")
    assert isinstance(nid, int) and nid > 0
    notes = db.get_notes(fid)
    assert len(notes) == 1
    assert notes[0]["body"] == "first note"
    assert notes[0]["finding_id"] == fid


# ---------------------------------------------------------------------------
# 6. add_tag / get_tags / remove_tag round-trip
# ---------------------------------------------------------------------------

def test_add_get_remove_tags(db: DatabaseManager) -> None:
    fid = _insert_finding(db)
    tid = db.add_tag(fid, "false-positive")
    assert isinstance(tid, int) and tid > 0

    tags = db.get_tags(fid)
    assert any(t["label"] == "false-positive" for t in tags)

    db.remove_tag(fid, "false-positive")
    tags_after = db.get_tags(fid)
    assert not any(t["label"] == "false-positive" for t in tags_after)


# ---------------------------------------------------------------------------
# 7. add_ai_result persists a row
# ---------------------------------------------------------------------------

def test_add_ai_result(db: DatabaseManager) -> None:
    fid = _insert_finding(db)
    rid = db.add_ai_result(fid, None, "triage", "gpt-4", "prompt text", "response text")
    assert isinstance(rid, int) and rid > 0
    cursor = db._conn.cursor()
    cursor.execute("SELECT * FROM ai_results WHERE id = ?", (rid,))
    row = dict(cursor.fetchone())
    assert row["task"] == "triage"
    assert row["finding_id"] == fid


# ---------------------------------------------------------------------------
# 8. scan_sessions lifecycle
# ---------------------------------------------------------------------------

def test_scan_session_lifecycle(db: DatabaseManager) -> None:
    sid = db.add_scan_session(None, "test-session")
    assert isinstance(sid, int) and sid > 0

    db.finish_scan_session(sid, '{"findings": 3}')

    sessions = db.get_scan_sessions()
    assert any(s["id"] == sid for s in sessions)
    match = next(s for s in sessions if s["id"] == sid)
    assert match["summary"] == '{"findings": 3}'
    assert match["finished_at"] is not None


# ---------------------------------------------------------------------------
# 9. get_session_findings returns findings linked to a session
# ---------------------------------------------------------------------------

def test_get_session_findings(db: DatabaseManager) -> None:
    sid = db.add_scan_session(None, "scan-1")
    # Insert a finding and manually set session_id
    fid = _insert_finding(db)
    db._conn.execute("UPDATE findings SET session_id = ? WHERE id = ?", (sid, fid))
    db._conn.commit()

    results = db.get_session_findings(sid)
    assert len(results) == 1
    assert results[0]["id"] == fid
