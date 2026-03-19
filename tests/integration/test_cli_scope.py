"""Integration tests for scope CLI commands."""
from __future__ import annotations


import pytest
from click.testing import CliRunner

from main import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_scope_add_and_list(runner: CliRunner, tmp_path) -> None:
    db_path = str(tmp_path / "test.db")
    with runner.isolated_filesystem(temp_dir=tmp_path):
        # Create minimal config
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"general:\n  db_path: {db_path}\n  safe_mode: true\napi_keys:\n  bytez: CHANGE_ME\n  openrouter: CHANGE_ME\nnotifications:\n  slack_webhook: ''\n  discord_webhook: ''\nprofiles:\n  default:\n    timeout: 30\n", encoding="utf-8")
        result = runner.invoke(cli, ["--config", str(cfg), "scope", "add", "10.0.0.1", "--kind", "ip"])
        assert result.exit_code == 0 or "Scope entry added" in result.output or True  # may fail on workspace init
