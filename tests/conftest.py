"""Shared pytest fixtures for Aegis test suite."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegis.core.db_manager import DatabaseManager
from aegis.core.config_manager import ConfigManager


@pytest.fixture()
def db() -> DatabaseManager:
    """In-memory DatabaseManager with schema initialized."""
    mgr = DatabaseManager(":memory:")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    mgr._conn = conn
    mgr.init_db()
    return mgr


@pytest.fixture()
def config(tmp_path: Path) -> ConfigManager:
    """ConfigManager backed by a minimal temp config file."""
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "general:\n  safe_mode: true\napi_keys:\n  bytez: CHANGE_ME\n  openrouter: CHANGE_ME\nnotifications:\n  slack_webhook: ''\n  discord_webhook: ''\n",
        encoding="utf-8",
    )
    mgr = ConfigManager(str(cfg_path))
    mgr.load()
    return mgr


@pytest.fixture()
def mock_http_response() -> MagicMock:
    """A mock httpx response returning a simple AI completion."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "choices": [{"message": {"content": "AI response text"}}]
    }
    resp.raise_for_status = MagicMock()
    return resp
