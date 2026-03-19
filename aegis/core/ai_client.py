from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.ui import console

MODEL_PREFERENCES: dict[str, list[str]] = {
    "triage":    ["bytez/mistral-7b-instruct",  "openrouter/mistralai/mistral-7b-instruct:free"],
    "summarize": ["bytez/llama-3-8b-instruct",   "openrouter/meta-llama/llama-3-8b-instruct:free"],
    "suggest":   ["bytez/mistral-7b-instruct",   "openrouter/mistralai/mistral-7b-instruct:free"],
    "report":    ["bytez/llama-3-8b-instruct",   "openrouter/meta-llama/llama-3-8b-instruct:free"],
    "chat":      ["bytez/mistral-7b-instruct",   "openrouter/mistralai/mistral-7b-instruct:free"],
}


@dataclass
class AITriageResult:
    finding_id: int
    model: str
    remediation: str
    risk_narrative: str
    cvss_suggestion: str


class AIClient:
    BYTEZ_BASE = "https://api.bytez.com/models/v2"
    OPENROUTER_BASE = "https://openrouter.ai/api/v1"

    def __init__(self, config: ConfigManager, db: DatabaseManager) -> None:
        self._config = config
        self._db = db

    def _bytez_key(self) -> Optional[str]:
        key = self._config.get("api_keys.bytez")
        if not key or key == "CHANGE_ME":
            return None
        return key

    def _openrouter_key(self) -> Optional[str]:
        key = self._config.get("api_keys.openrouter")
        if not key or key == "CHANGE_ME":
            return None
        return key

    def select_model(self, task: str) -> str:
        """Return the first model in MODEL_PREFERENCES[task] whose provider key is configured."""
        for model in MODEL_PREFERENCES[task]:
            provider, _ = model.split("/", 1)
            if provider == "bytez" and self._bytez_key():
                return model
            if provider == "openrouter" and self._openrouter_key():
                return model
        raise RuntimeError(f"No configured AI provider available for task '{task}'")

    def complete(self, prompt: str, task: str) -> str:
        """Try each model in MODEL_PREFERENCES[task] in order; return first successful response."""
        for model in MODEL_PREFERENCES[task]:
            provider, model_name = model.split("/", 1)
            try:
                if provider == "bytez":
                    key = self._bytez_key()
                    if not key:
                        continue
                    response = self._call_bytez(model_name, prompt)
                elif provider == "openrouter":
                    key = self._openrouter_key()
                    if not key:
                        continue
                    response = self._call_openrouter(model_name, prompt)
                else:
                    console.print(f"[warning]Unknown provider '{provider}', skipping.[/warning]")
                    continue
            except Exception as exc:
                console.print(f"[warning]Model {model} failed: {exc}[/warning]")
                continue

            self._db.add_ai_result(
                finding_id=None,
                session_id=None,
                task=task,
                model=model,
                prompt=prompt,
                response=response,
            )
            return response

        raise RuntimeError("All AI models exhausted")

    def _call_bytez(self, model: str, prompt: str) -> str:
        """POST to Bytez chat completions endpoint and return the response text."""
        api_key = self._bytez_key()
        url = f"{self.BYTEZ_BASE}/{model}/chat/completions"
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                url,
                headers={"Authorization": f"Key {api_key}"},
                json={
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1024,
                },
            )
            resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def _call_openrouter(self, model: str, prompt: str) -> str:
        """POST to OpenRouter chat completions endpoint and return the response text."""
        api_key = self._openrouter_key()
        url = f"{self.OPENROUTER_BASE}/chat/completions"
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1024,
                },
            )
            resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
