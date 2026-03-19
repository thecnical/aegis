from __future__ import annotations

from typing import Optional

import httpx

from aegis.core.config_manager import ConfigManager
from aegis.core.ui import console

_SEVERITY_RANK: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4
}


class Notifier:
    def __init__(self, config: ConfigManager) -> None:
        self._config = config

    def send_findings(
        self,
        findings: list[dict],
        channel: str = "both",
        min_severity: Optional[str] = None,
    ) -> None:
        """Send findings to Slack and/or Discord, filtered by min_severity."""
        filtered = self._filter(findings, min_severity)
        if not filtered:
            return
        if channel in ("slack", "both"):
            self._post_slack(self._build_slack_payload(filtered))
        if channel in ("discord", "both"):
            self._post_discord(self._build_discord_payload(filtered))

    def _filter(self, findings: list[dict], min_severity: Optional[str]) -> list[dict]:
        if not min_severity:
            return findings
        threshold = _SEVERITY_RANK.get(min_severity.lower(), 0)
        return [f for f in findings if _SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 0) >= threshold]

    def _build_slack_payload(self, findings: list[dict]) -> dict:
        blocks: list[dict] = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🔴 Aegis: {len(findings)} New Finding(s)"}},
        ]
        for f in findings[:10]:  # Slack has block limits
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*[{f.get('severity','?').upper()}]* {f.get('title','?')}\n_{f.get('description','')[:200]}_",
                },
            })
        return {"blocks": blocks}

    def _build_discord_payload(self, findings: list[dict]) -> dict:
        embeds = []
        for f in findings[:10]:
            severity = str(f.get("severity", "info")).lower()
            color = {"critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFAA00, "low": 0xFFFF00, "info": 0x00AAFF}.get(severity, 0xAAAAAA)
            embeds.append({
                "title": f"[{severity.upper()}] {f.get('title', '?')}",
                "description": str(f.get("description", ""))[:2000],
                "color": color,
            })
        return {"embeds": embeds, "username": "Aegis"}

    def _post_slack(self, payload: dict) -> None:
        url = self._config.get("notifications.slack_webhook", "")
        if not url:
            return
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
        except Exception as exc:
            console.print(f"[warning]Slack notification failed: {exc}[/warning]")

    def _post_discord(self, payload: dict) -> None:
        url = self._config.get("notifications.discord_webhook", "")
        if not url:
            return
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
        except Exception as exc:
            console.print(f"[warning]Discord notification failed: {exc}[/warning]")
