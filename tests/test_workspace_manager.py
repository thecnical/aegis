"""Unit tests for WorkspaceManager."""
from __future__ import annotations

import pytest
import click

from aegis.core.workspace_manager import WorkspaceManager
from aegis.core.db_manager import DatabaseManager


def test_create_workspace(db: DatabaseManager, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.BASE_DIR", tmp_path / "workspaces")
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.ACTIVE_FILE", tmp_path / ".active_workspace")
    wm = WorkspaceManager(db)
    ws = wm.create("test-ws")
    assert ws.name == "test-ws"
    assert "test-ws" in ws.db_path


def test_list_workspaces(db: DatabaseManager, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.BASE_DIR", tmp_path / "workspaces")
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.ACTIVE_FILE", tmp_path / ".active_workspace")
    wm = WorkspaceManager(db)
    wm.create("ws1")
    wm.create("ws2")
    workspaces = wm.list_workspaces()
    names = [w.name for w in workspaces]
    assert "ws1" in names
    assert "ws2" in names


def test_switch_nonexistent_raises(db: DatabaseManager, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.BASE_DIR", tmp_path / "workspaces")
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.ACTIVE_FILE", tmp_path / ".active_workspace")
    wm = WorkspaceManager(db)
    with pytest.raises(click.Abort):
        wm.switch("nonexistent")


def test_delete_workspace(db: DatabaseManager, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.BASE_DIR", tmp_path / "workspaces")
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.ACTIVE_FILE", tmp_path / ".active_workspace")
    wm = WorkspaceManager(db)
    wm.create("to-delete")
    wm.delete("to-delete")
    names = [w.name for w in wm.list_workspaces()]
    assert "to-delete" not in names


def test_delete_nonexistent_raises(db: DatabaseManager, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.BASE_DIR", tmp_path / "workspaces")
    monkeypatch.setattr("aegis.core.workspace_manager.WorkspaceManager.ACTIVE_FILE", tmp_path / ".active_workspace")
    wm = WorkspaceManager(db)
    with pytest.raises(click.Abort):
        wm.delete("ghost")
