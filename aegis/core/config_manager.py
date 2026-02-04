from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml
from aegis.core.ui import console



class ConfigManager:
    """Loads and stores YAML configuration."""

    def __init__(self, config_path: str) -> None:
        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}

    def load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            console.print(
                f"[bold red]Config not found:[/bold red] {self.config_path}"
            )
            self._config = {}
            return self._config
        try:
            with self.config_path.open("r", encoding="utf-8") as handle:
                self._config = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError) as exc:
            console.print(f"[bold red]Failed to load config:[/bold red] {exc}")
            self._config = {}
        return self._config

    def get(self, path: str, default: Any = None) -> Any:
        if not self._config:
            self.load()
        current: Any = self._config
        for key in path.split("."):
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def save(self, data: Dict[str, Any] | None = None) -> None:
        payload = data if data is not None else self._config
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with self.config_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(payload, handle, sort_keys=False)
