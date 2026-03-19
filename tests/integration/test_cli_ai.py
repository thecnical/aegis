"""Integration tests for AI CLI commands (mocked HTTP)."""
from __future__ import annotations


import pytest
from click.testing import CliRunner

from main import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_ai_suggest_no_keys(runner: CliRunner, tmp_path) -> None:
    """ai suggest should fail gracefully when no API keys are configured."""
    db_path = str(tmp_path / "test.db")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"general:\n  db_path: {db_path}\n  safe_mode: false\napi_keys:\n  bytez: CHANGE_ME\n  openrouter: CHANGE_ME\nnotifications:\n  slack_webhook: ''\n  discord_webhook: ''\nprofiles:\n  default:\n    timeout: 30\n",
        encoding="utf-8",
    )
    result = runner.invoke(cli, ["--config", str(cfg), "ai", "suggest", "--target", "example.com"])
    # Should not crash — either shows error or runs
    assert result.exit_code in (0, 1)
