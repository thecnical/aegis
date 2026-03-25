from __future__ import annotations

import os
from pathlib import Path
from shutil import which as _shutil_which
from typing import Dict, List, Optional, Tuple


# ── Extra search paths beyond $PATH ──────────────────────────────────────────
# These are checked in order when a tool is not found on $PATH.

def _extra_search_paths() -> List[Path]:
    """Return candidate directories where tools may live outside $PATH."""
    home = Path.home()
    paths: List[Path] = [
        # Go tools (go install)
        home / "go" / "bin",
        Path("/usr/local/go/bin"),
        Path("/usr/bin"),
        # Cargo tools (cargo install)
        home / ".cargo" / "bin",
        # Project venv (pip install inside .venv)
        Path.cwd() / ".venv" / "bin",
        Path("/opt/aegis-venv/bin"),
        # Downloaded scripts (linpeas, winpeas, testssl)
        Path.cwd() / "data" / "tools",
        home / "data" / "tools",
        # System locations
        Path("/usr/local/bin"),
        Path("/usr/local/sbin"),
    ]
    return paths


def _find_tool(name: str) -> Optional[str]:
    """
    Find a tool by name.
    1. Try shutil.which (respects $PATH)
    2. Try extra search paths
    3. Try common alternative names / extensions
    """
    # 1. Standard PATH lookup
    found = _shutil_which(name)
    if found:
        return found

    # 2. Extra directories
    for directory in _extra_search_paths():
        candidate = directory / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)

    # 3. Alternative names for known tools
    _aliases: Dict[str, List[str]] = {
        "testssl":      ["testssl.sh", "testssl"],
        "testssl.sh":   ["testssl.sh", "testssl"],
        "linpeas":      ["linpeas.sh", "linpeas"],
        "linpeas.sh":   ["linpeas.sh", "linpeas"],
        "winpeas":      ["winpeas.exe", "winpeas", "winPEASx64.exe"],
        "winpeas.exe":  ["winpeas.exe", "winpeas", "winPEASx64.exe"],
        "msfconsole":   ["msfconsole"],
        "webtech":      ["webtech"],
        "trufflehog":   ["trufflehog"],
        "gowitness":    ["gowitness"],
        "feroxbuster":  ["feroxbuster"],
        "subfinder":    ["subfinder"],
        "nuclei":       ["nuclei"],
        "amass":        ["amass"],
        "theHarvester": ["theHarvester", "theharvester"],
    }

    for alt in _aliases.get(name, []):
        found = _shutil_which(alt)
        if found:
            return found
        for directory in _extra_search_paths():
            candidate = directory / alt
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)

    return None


def detect_external_tools(
    tools: Dict[str, str],
    force: bool = False,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Detect external tools and return (updated_config, detected_paths).

    Searches PATH, Go bin, Cargo bin, project venv, data/tools/, and
    common system locations — not just $PATH.

    Args:
        tools:  Current external_tools dict from config.
        force:  If True, overwrite existing paths even if already set.

    Returns:
        updated:   Config dict with resolved absolute paths where found.
        detected:  Dict of name → resolved path for every tool found.
    """
    updated = dict(tools)
    detected: Dict[str, str] = {}

    for name, current in tools.items():
        # Try the configured command/path first
        path = _find_tool(str(current))
        # If not found by configured name, try the key name directly
        if not path:
            path = _find_tool(str(name))

        if path:
            detected[name] = path
            # Update config if forced or if current value is just the bare name
            if force or not current or str(current) == name or str(current) == str(name) + ".sh":
                updated[name] = path

    return updated, detected


def tool_status(tools: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """
    Return a rich status dict for every tool in the config.

    Each entry: {"path": str|"", "status": "ok"|"missing", "resolved": str}
    """
    status: Dict[str, Dict[str, str]] = {}
    for name, configured in tools.items():
        path = _find_tool(str(configured)) or _find_tool(str(name))
        status[name] = {
            "configured": str(configured),
            "path": path or "",
            "status": "ok" if path else "missing",
        }
    return status
