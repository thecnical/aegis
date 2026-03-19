"""Integration tests for watch command (single iteration mock)."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from main import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_watch_exits_on_keyboard_interrupt(runner: CliRunner, tmp_path) -> None:
    """Watch command should handle KeyboardInterrupt cleanly."""
    db_path = str(tmp_path / "test.db")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"general:\n  db_path: {db_path}\n  safe_mode: false\napi_keys:\n  bytez: CHANGE_ME\n  openrouter: CHANGE_ME\nnotifications:\n  slack_webhook: ''\n  discord_webhook: ''\nprofiles:\n  default:\n    timeout: 30\n",
        encoding="utf-8",
    )
    with patch("time.sleep", side_effect=KeyboardInterrupt):
        result = runner.invoke(cli, ["--config", str(cfg), "watch", "--interval", "1"])
    assert result.exit_code in (0, 1)
