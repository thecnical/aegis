from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, List, Optional


def _is_postgres_url(db_path: str) -> bool:
    return db_path.startswith("postgresql://") or db_path.startswith("postgres://")


class DatabaseManager:
    """
    Database manager for Aegis.

    Supports both SQLite (default) and PostgreSQL.

    SQLite:   db_path = "data/aegis.db"
    Postgres: db_path = "postgresql://user:pass@host:5432/aegis"
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._use_postgres = _is_postgres_url(db_path)
        self._conn: Any = None  # sqlite3.Connection or psycopg2 connection

    def connect(self) -> Any:
        if self._conn is not None:
            return self._conn

        if self._use_postgres:
            try:
                import psycopg2  # type: ignore[import]
                import psycopg2.extras  # type: ignore[import]
                self._conn = psycopg2.connect(self.db_path)
                self._conn.autocommit = False
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL support requires psycopg2: pip install psycopg2-binary"
                ) from exc
        else:
            path = Path(self.db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(path))
            self._conn.row_factory = sqlite3.Row

        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _cursor(self) -> Any:
        return self.connect().cursor()

    def _commit(self) -> None:
        self._conn.commit()

    def _placeholder(self) -> str:
        """Return the correct SQL placeholder for the current backend."""
        return "%s" if self._use_postgres else "?"

    def _last_id(self, cursor: Any) -> int:
        """Return the last inserted row ID."""
        if self._use_postgres:
            row = cursor.fetchone()
            if row is None:
                raise RuntimeError("INSERT did not return a row ID")
            return int(row[0])
        rowid = cursor.lastrowid
        if rowid is None:
            raise RuntimeError("INSERT did not produce a rowid")
        return int(rowid)

    def _row_to_dict(self, cursor: Any, row: Any) -> dict:
        """Convert a row to a dict regardless of backend."""
        if self._use_postgres:
            cols = [desc[0] for desc in cursor.description]
            return dict(zip(cols, row))
        return dict(row)

    def _fetchall_dicts(self, cursor: Any) -> List[dict]:
        rows = cursor.fetchall()
        if self._use_postgres:
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, row)) for row in rows]
        return [dict(row) for row in rows]

    def _execute(self, cursor: Any, sql: str, params: tuple = ()) -> Any:
        """Execute SQL with correct placeholder style."""
        if self._use_postgres:
            sql = sql.replace("?", "%s")
            # Add RETURNING id for INSERT statements
            if sql.strip().upper().startswith("INSERT") and "RETURNING" not in sql.upper():
                sql = sql.rstrip().rstrip(";") + " RETURNING id"
        cursor.execute(sql, params)
        return cursor

    def init_db(self) -> None:
        conn = self.connect()
        cursor = conn.cursor()

        # Use IF NOT EXISTS for all tables — works on both SQLite and Postgres
        _tables = [
            """CREATE TABLE IF NOT EXISTS targets (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS hosts (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                hostname TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS ports (
                id SERIAL PRIMARY KEY,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS services (
                id SERIAL PRIMARY KEY,
                port_id INTEGER NOT NULL,
                name TEXT,
                product TEXT,
                version TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS vulnerabilities (
                id SERIAL PRIMARY KEY,
                host_id INTEGER,
                port_id INTEGER,
                name TEXT NOT NULL,
                severity TEXT,
                description TEXT,
                source TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS findings (
                id SERIAL PRIMARY KEY,
                target_id INTEGER,
                host_id INTEGER,
                port_id INTEGER,
                title TEXT NOT NULL,
                severity TEXT,
                category TEXT,
                description TEXT,
                source TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                deduplicated INTEGER DEFAULT 0,
                session_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS evidence (
                id SERIAL PRIMARY KEY,
                finding_id INTEGER NOT NULL,
                kind TEXT,
                payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS workspaces (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                db_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS scope (
                id SERIAL PRIMARY KEY,
                workspace_id INTEGER,
                target TEXT NOT NULL,
                kind TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                finding_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS tags (
                id SERIAL PRIMARY KEY,
                finding_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS finding_hashes (
                id SERIAL PRIMARY KEY,
                fingerprint TEXT UNIQUE NOT NULL,
                finding_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS ai_results (
                id SERIAL PRIMARY KEY,
                finding_id INTEGER,
                session_id INTEGER,
                task TEXT NOT NULL,
                model TEXT,
                prompt TEXT,
                response TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS scan_sessions (
                id SERIAL PRIMARY KEY,
                workspace_id INTEGER,
                label TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished_at TIMESTAMP,
                summary TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS cve_correlations (
                id SERIAL PRIMARY KEY,
                finding_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                severity TEXT,
                published TEXT,
                url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS campaign_targets (
                id SERIAL PRIMARY KEY,
                campaign_name TEXT NOT NULL,
                target TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'domain',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS api_tokens (
                id SERIAL PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )""",
        ]

        # SQLite uses AUTOINCREMENT syntax; replace SERIAL for SQLite
        for ddl in _tables:
            if not self._use_postgres:
                ddl = ddl.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                ddl = ddl.replace("TIMESTAMP", "DATETIME")
            cursor.execute(ddl)

        # SQLite-only: idempotent column migrations (Postgres has them in CREATE TABLE)
        if not self._use_postgres:
            for col_def in ["cvss_score REAL", "cvss_vector TEXT",
                            "deduplicated INTEGER DEFAULT 0", "session_id INTEGER"]:
                self._add_column_if_missing(cursor, "findings", col_def)

        conn.commit()

    def upsert_target(self, name: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        self._execute(cursor, "SELECT id FROM targets WHERE name = ?", (name,))
        row = cursor.fetchone()
        if row:
            return int(row[0] if self._use_postgres else row["id"])
        self._execute(cursor, "INSERT INTO targets (name) VALUES (?)", (name,))
        self._commit()
        return self._last_id(cursor)

    def upsert_host(self, ip: str, hostname: Optional[str] = None) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        self._execute(cursor, "SELECT id FROM hosts WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            rid = int(row[0] if self._use_postgres else row["id"])
            if hostname:
                self._execute(cursor, "UPDATE hosts SET hostname = ? WHERE id = ?", (hostname, rid))
                self._commit()
            return rid
        self._execute(cursor, "INSERT INTO hosts (ip, hostname) VALUES (?, ?)", (ip, hostname))
        self._commit()
        return self._last_id(cursor)

    def add_port(self, host_id: int, port: int, protocol: str, state: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        self._execute(
            cursor,
            "SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, port, protocol),
        )
        row = cursor.fetchone()
        if row:
            rid = int(row[0] if self._use_postgres else row["id"])
            self._execute(cursor, "UPDATE ports SET state = ? WHERE id = ?", (state, rid))
            self._commit()
            return rid
        self._execute(
            cursor,
            "INSERT INTO ports (host_id, port, protocol, state) VALUES (?, ?, ?, ?)",
            (host_id, port, protocol, state),
        )
        self._commit()
        return self._last_id(cursor)

    def add_service(self, port_id: int, name: str, product: str, version: str) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO services (port_id, name, product, version) VALUES (?, ?, ?, ?)",
            (port_id, name, product, version),
        )
        self._commit()
        return self._last_id(cursor)

    def add_vulnerability(
        self,
        host_id: Optional[int],
        port_id: Optional[int],
        name: str,
        severity: str,
        description: str,
        source: str,
    ) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO vulnerabilities (host_id, port_id, name, severity, description, source) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (host_id, port_id, name, severity, description, source),
        )
        self._commit()
        return self._last_id(cursor)

    def add_finding(
        self,
        target_id: Optional[int],
        host_id: Optional[int],
        port_id: Optional[int],
        title: str,
        severity: str,
        category: str,
        description: str,
        source: str,
    ) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO findings "
            "(target_id, host_id, port_id, title, severity, category, description, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (target_id, host_id, port_id, title, severity, category, description, source),
        )
        self._commit()
        return self._last_id(cursor)

    def add_evidence(self, finding_id: int, kind: str, payload: str) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO evidence (finding_id, kind, payload) VALUES (?, ?, ?)",
            (finding_id, kind, payload),
        )
        self._commit()
        return self._last_id(cursor)

    # ── Migration helper ──────────────────────────────────────────────────────

    def _add_column_if_missing(self, cursor: Any, table: str, col_def: str) -> None:
        """Idempotently add a column (SQLite only)."""
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
        except Exception:
            pass

    # ── Notes ─────────────────────────────────────────────────────────────────

    def add_note(self, finding_id: int, body: str) -> int:
        cursor = self._cursor()
        self._execute(cursor, "INSERT INTO notes (finding_id, body) VALUES (?, ?)", (finding_id, body))
        self._commit()
        return self._last_id(cursor)

    def get_notes(self, finding_id: int) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM notes WHERE finding_id = ? ORDER BY created_at ASC", (finding_id,))
        return self._fetchall_dicts(cursor)

    # ── Tags ──────────────────────────────────────────────────────────────────

    def add_tag(self, finding_id: int, label: str) -> int:
        cursor = self._cursor()
        self._execute(cursor, "INSERT INTO tags (finding_id, label) VALUES (?, ?)", (finding_id, label))
        self._commit()
        return self._last_id(cursor)

    def remove_tag(self, finding_id: int, label: str) -> None:
        cursor = self._cursor()
        self._execute(cursor, "DELETE FROM tags WHERE finding_id = ? AND label = ?", (finding_id, label))
        self._commit()

    def get_tags(self, finding_id: int) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM tags WHERE finding_id = ? ORDER BY created_at ASC", (finding_id,))
        return self._fetchall_dicts(cursor)

    # ── AI results ────────────────────────────────────────────────────────────

    def add_ai_result(
        self,
        finding_id: Optional[int],
        session_id: Optional[int],
        task: str,
        model: str,
        prompt: str,
        response: str,
    ) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO ai_results (finding_id, session_id, task, model, prompt, response) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (finding_id, session_id, task, model, prompt, response),
        )
        self._commit()
        return self._last_id(cursor)

    # ── Scan sessions ─────────────────────────────────────────────────────────

    def add_scan_session(self, workspace_id: Optional[int], label: str) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO scan_sessions (workspace_id, label) VALUES (?, ?)",
            (workspace_id, label),
        )
        self._commit()
        return self._last_id(cursor)

    def finish_scan_session(self, session_id: int, summary: str) -> None:
        cursor = self._cursor()
        self._execute(
            cursor,
            "UPDATE scan_sessions SET finished_at = CURRENT_TIMESTAMP, summary = ? WHERE id = ?",
            (summary, session_id),
        )
        self._commit()

    def get_scan_sessions(self, limit: int = 50) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?", (limit,))
        return self._fetchall_dicts(cursor)

    def get_session_findings(self, session_id: int) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at ASC", (session_id,))
        return self._fetchall_dicts(cursor)

    def get_all_findings(self, limit: int = 500, offset: int = 0) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM findings ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
        return self._fetchall_dicts(cursor)

    def get_finding(self, finding_id: int) -> Optional[dict]:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_dict(cursor, row)

    def get_evidence(self, finding_id: int) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM evidence WHERE finding_id = ? ORDER BY created_at ASC", (finding_id,))
        return self._fetchall_dicts(cursor)

    # ── CVE correlations ──────────────────────────────────────────────────────

    def add_cve_correlation(
        self,
        finding_id: int,
        cve_id: str,
        description: str,
        cvss_score: Optional[float],
        cvss_vector: Optional[str],
        severity: str,
        published: str,
        url: str,
    ) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO cve_correlations "
            "(finding_id, cve_id, description, cvss_score, cvss_vector, severity, published, url) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (finding_id, cve_id, description, cvss_score, cvss_vector, severity, published, url),
        )
        self._commit()
        return self._last_id(cursor)

    def get_cve_correlations(self, finding_id: int) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM cve_correlations WHERE finding_id = ? ORDER BY cvss_score DESC", (finding_id,))
        return self._fetchall_dicts(cursor)

    # ── Campaign targets ──────────────────────────────────────────────────────

    def add_campaign_target(self, campaign_name: str, target: str, kind: str) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO campaign_targets (campaign_name, target, kind) VALUES (?, ?, ?)",
            (campaign_name, target, kind),
        )
        self._commit()
        return self._last_id(cursor)

    def get_campaign_targets(self, campaign_name: str) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM campaign_targets WHERE campaign_name = ? ORDER BY id ASC", (campaign_name,))
        return self._fetchall_dicts(cursor)

    # ── Scope ─────────────────────────────────────────────────────────────────

    def get_scope_entries(self) -> list:
        cursor = self._cursor()
        self._execute(cursor, "SELECT * FROM scope ORDER BY id ASC", ())
        return self._fetchall_dicts(cursor)

    def remove_scope_entry(self, entry_id: int) -> None:
        cursor = self._cursor()
        self._execute(cursor, "DELETE FROM scope WHERE id = ?", (entry_id,))
        self._commit()

    def add_scope_entry(self, target: str, kind: str) -> int:
        cursor = self._cursor()
        self._execute(
            cursor,
            "INSERT INTO scope (target, kind, workspace_id) VALUES (?, ?, ?)",
            (target, kind, None),
        )
        self._commit()
        return self._last_id(cursor)
