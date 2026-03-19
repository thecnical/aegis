from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

import click

from aegis.core.db_manager import DatabaseManager
from aegis.core.ui import console


@dataclass
class ScopeEntry:
    id: int
    target: str
    kind: str  # 'ip' | 'cidr' | 'domain' | 'url'
    workspace_id: Optional[int]


class ScopeManager:
    def __init__(self, db: DatabaseManager, safe_mode: bool = True) -> None:
        self._db = db
        self._safe_mode = safe_mode

    def add_target(self, target: str, kind: str) -> int:
        conn = self._db.connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scope (target, kind, workspace_id) VALUES (?, ?, ?)",
            (target, kind, None),
        )
        conn.commit()
        rowid = cursor.lastrowid
        return int(rowid) if rowid is not None else 0

    def remove_target(self, target_id: int) -> None:
        conn = self._db.connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scope WHERE id = ?", (target_id,))
        conn.commit()

    def list_targets(self) -> list[ScopeEntry]:
        conn = self._db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT id, target, kind, workspace_id FROM scope ORDER BY id ASC")
        return [
            ScopeEntry(
                id=row["id"],
                target=row["target"],
                kind=row["kind"],
                workspace_id=row["workspace_id"],
            )
            for row in cursor.fetchall()
        ]

    def is_in_scope(self, target: str) -> bool:
        entries = self.list_targets()
        # Empty scope table means open scope — everything is in scope
        if not entries:
            return True

        for entry in entries:
            if entry.kind == "cidr":
                try:
                    network = ipaddress.ip_network(entry.target, strict=False)
                    addr = ipaddress.ip_address(target)
                    if addr in network:
                        return True
                except ValueError:
                    continue
            elif entry.kind == "domain":
                # Suffix match: target ends with the domain entry
                if target == entry.target or target.endswith("." + entry.target):
                    return True
            else:
                # 'ip' or 'url': exact match
                if target == entry.target:
                    return True

        return False

    def validate_or_abort(self, target: str) -> None:
        if not self._safe_mode:
            return
        if not self.is_in_scope(target):
            console.print(
                f"[error]Target '[bold]{target}[/bold]' is not in scope. "
                "Add it with [bold]aegis scope add[/bold] or disable safe mode.[/error]"
            )
            raise click.Abort()
