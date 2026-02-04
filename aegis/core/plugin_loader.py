from __future__ import annotations

import importlib
import json
import pkgutil
from pathlib import Path
from typing import Dict, List

import click

from aegis.core.ui import console


def discover_tools() -> Dict[str, List[click.Command]]:
    """Discover tool modules under aegis.tools and return grouped commands."""
    tools: Dict[str, List[click.Command]] = {}
    import aegis.tools

    for module_info in pkgutil.iter_modules(aegis.tools.__path__):
        category = module_info.name
        category_package = f"aegis.tools.{category}"
        try:
            category_mod = importlib.import_module(category_package)
        except Exception as exc:
            console.print(
                f"[yellow]Skipping category {category}:[/yellow] {exc}"
            )
            continue

        for tool_info in pkgutil.iter_modules(category_mod.__path__):
            module_name = f"{category_package}.{tool_info.name}"
            try:
                mod = importlib.import_module(module_name)
            except Exception as exc:
                console.print(
                    f"[yellow]Skipping tool {module_name}:[/yellow] {exc}"
                )
                continue
            command = getattr(mod, "cli", None)
            if isinstance(command, click.Command):
                tools.setdefault(category, []).append(command)
    return tools


def discover_manifests() -> Dict[str, List[dict]]:
    """Discover tool manifest metadata under aegis.tools."""
    metadata: Dict[str, List[dict]] = {}
    import aegis.tools

    for module_info in pkgutil.iter_modules(aegis.tools.__path__):
        category = module_info.name
        category_package = f"aegis.tools.{category}"
        try:
            category_mod = importlib.import_module(category_package)
        except Exception as exc:
            console.print(
                f"[yellow]Skipping category {category}:[/yellow] {exc}"
            )
            continue

        for tool_info in pkgutil.iter_modules(category_mod.__path__):
            module_name = f"{category_package}.{tool_info.name}"
            try:
                mod = importlib.import_module(module_name)
            except Exception:
                continue
            module_path = Path(getattr(mod, "__file__", ""))
            if not module_path.exists():
                continue
            manifest_path = module_path.with_suffix(".manifest.json")
            if not manifest_path.exists():
                continue
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            data["category"] = category
            data["module"] = module_name
            metadata.setdefault(category, []).append(data)
    return metadata
