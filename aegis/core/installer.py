from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Tuple

from aegis.core.ui import console
from aegis.core.utils import ensure_dir, run_command, which


def _is_linux() -> bool:
    return os.name == "posix"


def _os_release() -> Dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    data: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def _is_debian_like() -> bool:
    info = _os_release()
    ids = {info.get("ID", ""), info.get("ID_LIKE", "")}
    blob = " ".join(ids).lower()
    return any(x in blob for x in ["debian", "ubuntu", "kali"])


def build_install_plan(include_peas: bool = False) -> List[Tuple[str, List[str]]]:
    plan: List[Tuple[str, List[str]]] = []
    plan.append(("apt-update", ["sudo", "apt", "update"]))
    plan.append(
        (
            "apt-core",
            [
                "sudo",
                "apt",
                "install",
                "-y",
                "nmap",
                "smbclient",
                "netcat-openbsd",
                "hydra",
                "sqlmap",
                "git",
                "golang",
                "cargo",
                "npm",
                "curl",
            ],
        )
    )
    plan.append(
        (
            "subfinder",
            ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
        )
    )
    plan.append(
        (
            "nuclei",
            ["go", "install", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"],
        )
    )
    plan.append(("feroxbuster", ["cargo", "install", "feroxbuster"]))
    plan.append(("wappalyzer", ["npm", "install", "-g", "wappalyzer"]))
    if include_peas:
        ensure_dir("data/tools")
        plan.append(
            (
                "linpeas",
                [
                    "curl",
                    "-L",
                    "-o",
                    "data/tools/linpeas.sh",
                    "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
                ],
            )
        )
        plan.append(
            (
                "winpeas",
                [
                    "curl",
                    "-L",
                    "-o",
                    "data/tools/winpeas.exe",
                    "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe",
                ],
            )
        )
    return plan


def run_install_plan(plan: List[Tuple[str, List[str]]], dry_run: bool = False) -> Dict[str, str]:
    results: Dict[str, str] = {}
    for name, cmd in plan:
        if dry_run:
            console.print(f"[primary]DRY-RUN[/primary] {name}: {' '.join(cmd)}")
            results[name] = "dry-run"
            continue
        if not which(cmd[0]):
            console.print(f"[warning]Skipping {name}, missing tool:[/warning] {cmd[0]}")
            results[name] = "missing"
            continue
        code, out, err = run_command(cmd, timeout=None)
        if code != 0:
            console.print(f"[error]Failed {name}:[/error] {err or out}")
            results[name] = "failed"
        else:
            console.print(f"[primary]{name}[/primary]: ok")
            results[name] = "ok"
    return results


def validate_environment() -> Tuple[bool, str]:
    if not _is_linux():
        return False, "installer supports Linux only"
    if not _is_debian_like():
        return False, "installer supports Debian/Ubuntu/Kali only"
    return True, ""


# Prerequisite binaries required per tool name
_PREREQS: Dict[str, str] = {
    "subfinder": "go",
    "nuclei": "go",
    "feroxbuster": "cargo",
    "wappalyzer": "npm",
}


def run_install_plan_interactive(
    plan: List[Tuple[str, List[str]]],
    assume_yes: bool = False,
    dry_run: bool = False,
) -> Dict[str, str]:
    """Run install plan with per-tool interactive prompts.

    Returns a dict mapping tool name → outcome string.
    """
    import sys

    if not _is_linux():
        console.print("[error]install-tools supports Linux only.[/error]")
        sys.exit(1)

    results: Dict[str, str] = {}

    for name, cmd in plan:
        # Check prerequisite binary
        prereq = _PREREQS.get(name)
        if prereq and not which(prereq):
            console.print(
                f"[bold yellow]Skipping {name}:[/bold yellow] prerequisite '{prereq}' not on PATH"
            )
            results[name] = "skipped"
            continue

        if dry_run:
            console.print(f"[primary]DRY-RUN[/primary] {name}: {' '.join(cmd)}")
            results[name] = "dry-run"
            continue

        if not assume_yes:
            try:
                answer = input(f"Install {name} ({' '.join(cmd)})? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[warning]Aborted.[/warning]")
                break
            if answer not in ("y", "yes"):
                console.print(f"[dim]Skipped {name}.[/dim]")
                results[name] = "skipped"
                continue

        if not which(cmd[0]):
            console.print(f"[warning]Skipping {name}, missing tool:[/warning] {cmd[0]}")
            results[name] = "skipped"
            continue

        code, out, err = run_command(cmd, timeout=None)
        if code != 0:
            console.print(f"[error]Failed {name}:[/error] {err or out}")
            results[name] = "failed"
        else:
            console.print(f"[primary]{name}[/primary]: ok")
            results[name] = "ok"

    return results
