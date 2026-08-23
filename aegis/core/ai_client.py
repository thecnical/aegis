"""Multi-provider AI client with automatic fallback.

Supported providers (all free tiers, no credit card required):
  groq        — 750-900 tokens/sec via LPU hardware (fastest inference)
  nvidia      — 100+ models via NVIDIA NIM / build.nvidia.com (free tier)
  llm7        — No-registration free endpoint, OpenAI-compatible
  cloudflare  — Workers AI, global edge inference (free tier)
  opencode    — OpenCode Zen curated models (free tier available)
  bytez       — Free tier LLMs
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.ui import console

# ── Model preferences per task ────────────────────────────────────────────────
# Each list is tried in order; first provider with a configured key wins.
# groq is first — fastest inference (750-900 tokens/sec on LPU hardware).
# nvidia is second — 100+ models free, no CC required.
# llm7 is third — no registration needed, truly zero-friction.
# cloudflare is fourth — global edge, free tier.
# opencode is fifth — OpenCode Zen gateway, free models available.
# bytez is last fallback.
MODEL_PREFERENCES: dict[str, list[str]] = {
    "triage": [
        "groq/llama-3.3-70b-versatile",
        "nvidia/meta/llama-3.3-70b-instruct",
        "llm7/llama-3.3-70b-instruct:turbo",
        "cloudflare/@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        "opencode/big-pickle",
        "bytez/mistral-7b-instruct",
    ],
    "summarize": [
        "groq/llama-3.1-8b-instant",
        "nvidia/meta/llama-3.1-8b-instruct",
        "llm7/llama-3.1-8b-instruct:turbo",
        "cloudflare/@cf/meta/llama-3.1-8b-instruct",
        "opencode/big-pickle",
        "bytez/llama-3-8b-instruct",
    ],
    "suggest": [
        "groq/llama-3.3-70b-versatile",
        "nvidia/qwen/qwen2.5-72b-instruct",
        "llm7/qwen2.5-72b-instruct:turbo",
        "cloudflare/@cf/qwen/qwen2.5-72b-instruct",
        "opencode/big-pickle",
        "bytez/mistral-7b-instruct",
    ],
    "report": [
        "groq/llama-3.3-70b-versatile",
        "nvidia/meta/llama-3.3-70b-instruct",
        "llm7/llama-3.3-70b-instruct:turbo",
        "cloudflare/@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        "opencode/big-pickle",
        "bytez/llama-3-8b-instruct",
    ],
    "chat": [
        "groq/llama-3.3-70b-versatile",
        "nvidia/meta/llama-3.1-70b-instruct",
        "llm7/llama-3.1-70b-instruct:turbo",
        "cloudflare/@cf/meta/llama-3.1-70b-instruct",
        "opencode/big-pickle",
        "bytez/mistral-7b-instruct",
    ],
    # Forensics-specific tasks
    "forensics_analyze": [
        "groq/llama-3.3-70b-versatile",
        "nvidia/nvidia/llama-3.1-nemotron-70b-instruct",
        "llm7/llama-3.3-70b-instruct:turbo",
        "cloudflare/@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        "opencode/big-pickle",
        "bytez/llama-3-8b-instruct",
    ],
    "forensics_redteam": [
        "groq/llama-3.3-70b-versatile",
        "nvidia/nvidia/llama-3.1-nemotron-70b-instruct",
        "llm7/qwen2.5-72b-instruct:turbo",
        "cloudflare/@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        "opencode/big-pickle",
        "bytez/mistral-7b-instruct",
    ],
    "forensics_timeline": [
        "groq/llama-3.1-8b-instant",
        "nvidia/meta/llama-3.1-8b-instruct",
        "llm7/llama-3.1-8b-instruct:turbo",
        "cloudflare/@cf/meta/llama-3.1-8b-instruct",
        "opencode/big-pickle",
        "bytez/llama-3-8b-instruct",
    ],
}


@dataclass
class AITriageResult:
    finding_id: int
    model: str
    remediation: str
    risk_narrative: str
    cvss_suggestion: str


class AIClient:
    # ── Provider base URLs ────────────────────────────────────────────────────
    GROQ_BASE = "https://api.groq.com/openai/v1"
    NVIDIA_BASE = "https://integrate.api.nvidia.com/v1"
    LLM7_BASE = "https://api.llm7.io/v1"
    CLOUDFLARE_BASE = "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1"
    BYTEZ_BASE = "https://api.bytez.com/models/v2"
    OPENCODE_ZEN_BASE = "https://opencode.ai/zen/v1"

    def __init__(self, config: ConfigManager, db: DatabaseManager) -> None:
        self._config = config
        self._db = db

    # ── Key accessors ─────────────────────────────────────────────────────────

    def _key(self, name: str) -> Optional[str]:
        val = self._config.get(f"api_keys.{name}")
        if not val or str(val).strip() in ("CHANGE_ME", "", "null", "None"):
            return None
        return str(val).strip()

    def _groq_key(self) -> Optional[str]:
        return self._key("groq")

    def _nvidia_key(self) -> Optional[str]:
        return self._key("nvidia")

    def _llm7_key(self) -> Optional[str]:
        # llm7 works WITHOUT any key (anonymous), but key gives higher limits
        key = self._key("llm7")
        return key  # None is also valid for llm7

    def _cloudflare_key(self) -> Optional[str]:
        return self._key("cloudflare")

    def _cloudflare_account(self) -> Optional[str]:
        return self._key("cloudflare_account_id")

    def _bytez_key(self) -> Optional[str]:
        return self._key("bytez")

    def _opencode_zen_key(self) -> Optional[str]:
        return self._key("opencode_zen")

    # ── Provider availability ─────────────────────────────────────────────────

    def _provider_available(self, provider: str) -> bool:
        if provider == "groq":
            return bool(self._groq_key())
        if provider == "nvidia":
            return bool(self._nvidia_key())
        if provider == "llm7":
            return True  # works without key
        if provider == "cloudflare":
            return bool(self._cloudflare_key() and self._cloudflare_account())
        if provider == "bytez":
            return bool(self._bytez_key())
        if provider == "openrouter" or provider == "opencode":
            return bool(self._opencode_zen_key())
        return False

    def select_model(self, task: str) -> str:
        for model in MODEL_PREFERENCES.get(task, []):
            provider = model.split("/")[0]
            if self._provider_available(provider):
                return model
        raise RuntimeError(f"No configured AI provider available for task '{task}'")

    # ── Main completion entry point ───────────────────────────────────────────

    def complete(self, prompt: str, task: str) -> str:
        models = MODEL_PREFERENCES.get(task, MODEL_PREFERENCES["chat"])
        for model in models:
            provider = model.split("/")[0]
            model_name = "/".join(model.split("/")[1:])
            if not self._provider_available(provider):
                continue
            try:
                response = self._dispatch(provider, model_name, prompt)
            except Exception as exc:
                console.print(f"[warning]Model {model} failed: {exc}[/warning]")
                continue

            try:
                self._db.add_ai_result(
                    finding_id=None,
                    session_id=None,
                    task=task,
                    model=model,
                    prompt=prompt,
                    response=response,
                )
            except Exception:
                pass  # non-fatal
            return response

        raise RuntimeError(
            "All AI models exhausted. Run 'aegis configure-keys --interactive' to add free API keys."
        )

    def _dispatch(self, provider: str, model_name: str, prompt: str) -> str:
        if provider == "groq":
            return self._call_openai_compat(
                self.GROQ_BASE, model_name, prompt,
                bearer=self._groq_key(),
            )
        if provider == "nvidia":
            return self._call_openai_compat(
                self.NVIDIA_BASE, model_name, prompt,
                bearer=self._nvidia_key(),
            )
        if provider == "llm7":
            return self._call_openai_compat(
                self.LLM7_BASE, model_name, prompt,
                bearer=self._llm7_key(),  # may be None → no Authorization header
            )
        if provider == "cloudflare":
            return self._call_cloudflare(model_name, prompt)
        if provider == "bytez":
            return self._call_bytez(model_name, prompt)
        if provider == "openrouter" or provider == "opencode":
            return self._call_openai_compat(
                self.OPENCODE_ZEN_BASE, model_name, prompt,
                bearer=self._opencode_zen_key(),
            )
        raise RuntimeError(f"Unknown provider: {provider}")

    # ── Generic OpenAI-compatible call ────────────────────────────────────────

    def _call_openai_compat(
        self,
        base_url: str,
        model: str,
        prompt: str,
        bearer: Optional[str] = None,
        max_tokens: int = 2048,
        timeout: int = 60,
    ) -> str:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                    "temperature": 0.2,
                },
            )
            resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    # ── Cloudflare Workers AI ─────────────────────────────────────────────────

    def _call_cloudflare(self, model: str, prompt: str, max_tokens: int = 2048) -> str:
        account_id = self._cloudflare_account()
        api_key = self._cloudflare_key()
        url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{model}"
        with httpx.Client(timeout=60) as client:
            resp = client.post(
                url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                },
            )
            resp.raise_for_status()
        data = resp.json()
        return data["result"]["response"]

    # ── Bytez ─────────────────────────────────────────────────────────────────

    def _call_bytez(self, model: str, prompt: str, max_tokens: int = 1024) -> str:
        api_key = self._bytez_key()
        url = f"{self.BYTEZ_BASE}/{model}/chat/completions"
        with httpx.Client(timeout=60) as client:
            resp = client.post(
                url,
                headers={"Authorization": f"Key {api_key}"},
                json={
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                },
            )
            resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    # ── Provider status check (used by 'aegis ai doctor') ────────────────────

    def provider_status(self) -> dict[str, dict[str, object]]:
        """Return availability status of every configured provider."""
        providers = {
            "groq": {
                "key_set": bool(self._groq_key()),
                "url": "https://console.groq.com/keys",
                "free": True,
                "speed": "750-900 tokens/sec",
                "note": "Fastest inference via LPU hardware",
            },
            "nvidia": {
                "key_set": bool(self._nvidia_key()),
                "url": "https://build.nvidia.com",
                "free": True,
                "speed": "Fast GPU inference",
                "note": "100+ models, no CC required",
            },
            "llm7": {
                "key_set": True,  # works without key
                "url": "https://llm7.io",
                "free": True,
                "speed": "Fast",
                "note": "No registration required",
            },
            "cloudflare": {
                "key_set": bool(self._cloudflare_key() and self._cloudflare_account()),
                "url": "https://dash.cloudflare.com",
                "free": True,
                "speed": "Global edge",
                "note": "Free tier via Workers AI",
            },
            "bytez": {
                "key_set": bool(self._bytez_key()),
                "url": "https://bytez.com",
                "free": True,
                "speed": "Moderate",
                "note": "Free tier",
            },
        }
        return providers
