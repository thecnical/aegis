from __future__ import annotations

from shutil import which
from typing import Dict, Tuple


def detect_external_tools(tools: Dict[str, str], force: bool = False) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Detect external tools on PATH and return (updated_tools, detected_paths)."""
    updated = dict(tools)
    detected: Dict[str, str] = {}

    for name, current in tools.items():
        path = which(str(current)) or which(str(name))
        if path:
            detected[name] = path
            if force or not current or str(current) == name:
                updated[name] = path
    return updated, detected
