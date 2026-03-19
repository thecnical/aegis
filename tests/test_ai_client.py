"""Unit tests for AIClient."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aegis.core.ai_client import AIClient
from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager


def _make_client(db: DatabaseManager, bytez_key: str = "CHANGE_ME", openrouter_key: str = "CHANGE_ME") -> AIClient:
    cfg = MagicMock(spec=ConfigManager)
    cfg.get.side_effect = lambda path, default=None: {
        "api_keys.bytez": bytez_key,
        "api_keys.openrouter": openrouter_key,
    }.get(path, default)
    return AIClient(cfg, db)


def test_all_models_fail_raises_runtime_error(db: DatabaseManager) -> None:
    client = _make_client(db)  # both keys are CHANGE_ME → skipped
    with pytest.raises(RuntimeError, match="All AI models exhausted"):
        client.complete("test prompt", "triage")


def test_bytez_called_first(db: DatabaseManager) -> None:
    client = _make_client(db, bytez_key="real-key")
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
    mock_resp.raise_for_status = MagicMock()
    with patch("httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.post.return_value = mock_resp
        mock_client_cls.return_value = mock_http
        result = client.complete("hello", "triage")
    assert result == "ok"
    # Verify Bytez URL was used
    call_url = mock_http.post.call_args[0][0]
    assert "bytez.com" in call_url


def test_select_model_returns_configured_provider(db: DatabaseManager) -> None:
    client = _make_client(db, openrouter_key="real-key")
    model = client.select_model("triage")
    assert model.startswith("openrouter/")


def test_prompt_does_not_contain_api_key(db: DatabaseManager) -> None:
    client = _make_client(db, bytez_key="super-secret-key-12345")
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"choices": [{"message": {"content": "response"}}]}
    mock_resp.raise_for_status = MagicMock()
    with patch("httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.post.return_value = mock_resp
        mock_client_cls.return_value = mock_http
        client.complete("user prompt", "chat")
    call_kwargs = mock_http.post.call_args[1]
    body_str = str(call_kwargs.get("json", ""))
    assert "super-secret-key-12345" not in body_str
