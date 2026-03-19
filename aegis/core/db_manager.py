from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional




class DatabaseManager:
    """SQLite manager for Aegis."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def init_db(self) -> None:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                hostname TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id INTEGER NOT NULL,
                name TEXT,
                product TEXT,
                version TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (port_id) REFERENCES ports (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port_id INTEGER,
                name TEXT NOT NULL,
                severity TEXT,
                description TEXT,
                source TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts (id),
                FOREIGN KEY (port_id) REFERENCES ports (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                host_id INTEGER,
                port_id INTEGER,
                title TEXT NOT NULL,
                severity TEXT,
                category TEXT,
                description TEXT,
                source TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets (id),
                FOREIGN KEY (host_id) REFERENCES hosts (id),
                FOREIGN KEY (port_id) REFERENCES ports (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                kind TEXT,
                payload TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                db_path TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scope (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER,
                target TEXT NOT NULL,
                kind TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (workspace_id) REFERENCES workspaces (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                finding_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER,
                session_id INTEGER,
                task TEXT NOT NULL,
                model TEXT,
                prompt TEXT,
                response TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings (id)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER,
                label TEXT,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                finished_at DATETIME,
                summary TEXT
            );
            """
        )
        # Idempotent ALTER TABLE migrations for findings columns
        for col_def in [
            "cvss_score REAL",
            "cvss_vector TEXT",
            "deduplicated INTEGER DEFAULT 0",
            "session_id INTEGER",
        ]:
            self._add_column_if_missing(cursor, "findings", col_def)

        # CVE correlations table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                severity TEXT,
                published TEXT,
                url TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            );
            """
        )

        # Campaign targets table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS campaign_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_name TEXT NOT NULL,
                target TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'domain',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # API tokens table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME
            );
            """
        )

        conn.commit()

    def upsert_target(self, name: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM targets WHERE name = ?", (name,))
        row = cursor.fetchone()
        if row:
            return int(row["id"])
        cursor.execute("INSERT INTO targets (name) VALUES (?)", (name,))
        conn.commit()
        return self._last_insert_id(cursor)

    def upsert_host(self, ip: str, hostname: Optional[str] = None) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            if hostname:
                cursor.execute(
                    "UPDATE hosts SET hostname = ? WHERE id = ?",
                    (hostname, row["id"]),
                )
                conn.commit()
            return int(row["id"])
        cursor.execute(
            "INSERT INTO hosts (ip, hostname) VALUES (?, ?)",
            (ip, hostname),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def add_port(self, host_id: int, port: int, protocol: str, state: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, port, protocol),
        )
        row = cursor.fetchone()
        if row:
            cursor.execute(
                "UPDATE ports SET state = ? WHERE id = ?",
                (state, row["id"]),
            )
            conn.commit()
            return int(row["id"])
        cursor.execute(
            "INSERT INTO ports (host_id, port, protocol, state) VALUES (?, ?, ?, ?)",
            (host_id, port, protocol, state),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def add_service(
        self, port_id: int, name: str, product: str, version: str
    ) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO services (port_id, name, product, version) VALUES (?, ?, ?, ?)",
            (port_id, name, product, version),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def add_vulnerability(
        self,
        host_id: Optional[int],
        port_id: Optional[int],
        name: str,
        severity: str,
        description: str,
        source: str,
    ) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vulnerabilities (host_id, port_id, name, severity, description, source)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (host_id, port_id, name, severity, description, source),
        )
        conn.commit()
        return self._last_insert_id(cursor)

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
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO findings (target_id, host_id, port_id, title, severity, category, description, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (target_id, host_id, port_id, title, severity, category, description, source),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def add_evidence(self, finding_id: int, kind: str, payload: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO evidence (finding_id, kind, payload) VALUES (?, ?, ?)",
            (finding_id, kind, payload),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    # ------------------------------------------------------------------
    # Migration helper
    # ------------------------------------------------------------------

    def _add_column_if_missing(
        self, cursor: sqlite3.Cursor, table: str, col_def: str
    ) -> None:
        """Idempotently add a column to *table*; silently skips if it exists."""
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
        except sqlite3.OperationalError:
            # Column already exists — nothing to do.
            pass

    @staticmethod
    def _last_insert_id(cursor: sqlite3.Cursor) -> int:
        """Return cursor.lastrowid as int, raising if None."""
        rowid = cursor.lastrowid
        if rowid is None:
            raise RuntimeError("INSERT did not produce a rowid")
        return int(rowid)

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------

    def add_note(self, finding_id: int, body: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notes (finding_id, body) VALUES (?, ?)",
            (finding_id, body),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def get_notes(self, finding_id: int) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM notes WHERE finding_id = ? ORDER BY created_at ASC",
            (finding_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------

    def add_tag(self, finding_id: int, label: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO tags (finding_id, label) VALUES (?, ?)",
            (finding_id, label),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def remove_tag(self, finding_id: int, label: str) -> None:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM tags WHERE finding_id = ? AND label = ?",
            (finding_id, label),
        )
        conn.commit()

    def get_tags(self, finding_id: int) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM tags WHERE finding_id = ? ORDER BY created_at ASC",
            (finding_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # AI results
    # ------------------------------------------------------------------

    def add_ai_result(
        self,
        finding_id: Optional[int],
        session_id: Optional[int],
        task: str,
        model: str,
        prompt: str,
        response: str,
    ) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO ai_results (finding_id, session_id, task, model, prompt, response)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (finding_id, session_id, task, model, prompt, response),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    # ------------------------------------------------------------------
    # Scan sessions
    # ------------------------------------------------------------------

    def add_scan_session(self, workspace_id: Optional[int], label: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scan_sessions (workspace_id, label) VALUES (?, ?)",
            (workspace_id, label),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def finish_scan_session(self, session_id: int, summary: str) -> None:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE scan_sessions
            SET finished_at = CURRENT_TIMESTAMP, summary = ?
            WHERE id = ?
            """,
            (summary, session_id),
        )
        conn.commit()

    def get_scan_sessions(self, limit: int = 50) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_session_findings(self, session_id: int) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at ASC",
            (session_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_all_findings(self, limit: int = 500, offset: int = 0) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_finding(self, finding_id: int) -> Optional[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_evidence(self, finding_id: int) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY created_at ASC",
            (finding_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # CVE correlations
    # ------------------------------------------------------------------

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
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO cve_correlations
                (finding_id, cve_id, description, cvss_score, cvss_vector, severity, published, url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (finding_id, cve_id, description, cvss_score, cvss_vector, severity, published, url),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def get_cve_correlations(self, finding_id: int) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM cve_correlations WHERE finding_id = ? ORDER BY cvss_score DESC",
            (finding_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Campaign targets
    # ------------------------------------------------------------------

    def add_campaign_target(self, campaign_name: str, target: str, kind: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO campaign_targets (campaign_name, target, kind) VALUES (?, ?, ?)",
            (campaign_name, target, kind),
        )
        conn.commit()
        return self._last_insert_id(cursor)

    def get_campaign_targets(self, campaign_name: str) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM campaign_targets WHERE campaign_name = ? ORDER BY id ASC",
            (campaign_name,),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Scope helpers (for REST API)
    # ------------------------------------------------------------------

    def get_scope_entries(self) -> list[dict]:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scope ORDER BY id ASC")
        return [dict(row) for row in cursor.fetchall()]

    def remove_scope_entry(self, entry_id: int) -> None:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scope WHERE id = ?", (entry_id,))
        conn.commit()

    def add_scope_entry(self, target: str, kind: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scope (target, kind, workspace_id) VALUES (?, ?, ?)",
            (target, kind, None),
        )
        conn.commit()
        return self._last_insert_id(cursor)
