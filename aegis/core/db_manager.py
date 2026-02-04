from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from aegis.core.ui import console



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
        return int(cursor.lastrowid)

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
        return int(cursor.lastrowid)

    def add_port(self, host_id: int, port: int, protocol: str, state: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO ports (host_id, port, protocol, state) VALUES (?, ?, ?, ?)",
            (host_id, port, protocol, state),
        )
        conn.commit()
        return int(cursor.lastrowid)

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
        return int(cursor.lastrowid)

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
        return int(cursor.lastrowid)

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
        return int(cursor.lastrowid)

    def add_evidence(self, finding_id: int, kind: str, payload: str) -> int:
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO evidence (finding_id, kind, payload) VALUES (?, ?, ?)",
            (finding_id, kind, payload),
        )
        conn.commit()
        return int(cursor.lastrowid)
