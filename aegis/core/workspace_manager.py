from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

import click

from aegis.core.db_manager import DatabaseManager
from aegis.core.ui import console


@dataclass
class Workspace:
    name: str
    db_path: str
    reports_path: str


class WorkspaceManager:
    ACTIVE_FILE = Path("data/.active_workspace")
    BASE_DIR = Path("data/workspaces")

    def __init__(self, root_db: DatabaseManager) -> None:
        self._root_db = root_db

    def create(self, name: str) -> Workspace:
        ws_dir = self.BASE_DIR / name
        db_path = ws_dir / "aegis.db"
        reports_path = ws_dir / "reports"

        db_path.parent.mkdir(parents=True, exist_ok=True)
        reports_path.mkdir(parents=True, exist_ok=True)

        conn = self._root_db.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO workspaces (name, db_path) VALUES (?, ?)",
            (name, str(db_path)),
        )
        conn.commit()

        return Workspace(
            name=name,
            db_path=str(db_path),
            reports_path=str(reports_path),
        )

    def switch(self, name: str) -> Workspace:
        ws = self._get_from_db(name)
        if ws is None:
            console.print(f"[error]Workspace '{name}' not found.[/error]")
            raise click.Abort()

        self.ACTIVE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.ACTIVE_FILE.write_text(name)
        return ws

    def list_workspaces(self) -> list[Workspace]:
        conn = self._root_db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT name, db_path FROM workspaces ORDER BY name")
        rows = cursor.fetchall()
        return [
            Workspace(
                name=row["name"],
                db_path=row["db_path"],
                reports_path=str(self.BASE_DIR / row["name"] / "reports"),
            )
            for row in rows
        ]

    def current(self) -> Workspace:
        if self.ACTIVE_FILE.exists():
            name = self.ACTIVE_FILE.read_text().strip()
        else:
            name = "default"

        ws = self._get_from_db(name)
        if ws is not None:
            return ws

        # Auto-create "default" workspace if it doesn't exist yet
        if name == "default":
            return self.create("default")

        console.print(f"[error]Workspace '{name}' not found.[/error]")
        raise click.Abort()

    def delete(self, name: str) -> None:
        ws = self._get_from_db(name)
        if ws is None:
            console.print(f"[error]Workspace '{name}' not found.[/error]")
            raise click.Abort()

        conn = self._root_db.connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM workspaces WHERE name = ?", (name,))
        conn.commit()

        ws_dir = self.BASE_DIR / name
        if ws_dir.exists():
            shutil.rmtree(ws_dir)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_from_db(self, name: str) -> Workspace | None:
        conn = self._root_db.connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name, db_path FROM workspaces WHERE name = ?", (name,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return Workspace(
            name=row["name"],
            db_path=row["db_path"],
            reports_path=str(self.BASE_DIR / row["name"] / "reports"),
        )
