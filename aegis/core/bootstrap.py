"""Full one-command bootstrap for Aegis on Debian/Ubuntu/Kali Linux.

Installs every dependency in the correct order:
  1. System packages via apt (with root/sudo) — includes apt upgrade
  2. Go toolchain (if missing)
  3. Rust/Cargo toolchain (if missing)
  4. Go-based tools: subfinder, nuclei, trufflehog, gowitness, amass
  5. Cargo-based tools: feroxbuster
  6. Python venv at /opt/aegis-venv (avoids Kali PEP 668 restriction)
  7. Creates required directories
  8. Fixes PATH so Go/Cargo bins are always found
  9. Validates everything
"""
from __future__ import annotations

import os
import pwd
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from aegis.core.ui import console
from aegis.core.utils import ensure_dir, which

# ── Constants ─────────────────────────────────────────────────────────────────

GO_VERSION = "1.22.4"
GO_TARBALL = f"go{GO_VERSION}.linux-amd64.tar.gz"
GO_URL = f"https://go.dev/dl/{GO_TARBALL}"
GO_INSTALL_DIR = "/usr/local"

VENV_DIR = "/opt/aegis-venv"

# Resolve the real user's home (works correctly under sudo)
def _real_user() -> Tuple[str, str]:
    """Return (username, home_dir) of the invoking user, not root."""
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user:
        try:
            pw = pwd.getpwnam(sudo_user)
            return sudo_user, pw.pw_dir
        except KeyError:
            pass
    return os.environ.get("USER", "root"), str(Path.home())

_REAL_USER, _REAL_HOME = _real_user()
GOPATH_BIN = str(Path(_REAL_HOME) / "go" / "bin")
CARGO_BIN = str(Path(_REAL_HOME) / ".cargo" / "bin")

APT_PACKAGES = [
    # Core pentest tools
    "nmap", "smbclient", "netcat-openbsd", "hydra", "sqlmap",
    "nikto", "whatweb", "ffuf", "curl", "wget", "git",
    # Build tools needed for Go/Rust
    "build-essential", "pkg-config",
    # WeasyPrint native deps (PDF reports)
    "libpango-1.0-0", "libpangoft2-1.0-0", "libpangocairo-1.0-0",
    "libcairo2", "libffi-dev", "libgdk-pixbuf-2.0-0",
    # Python (venv support)
    "python3", "python3-pip", "python3-venv", "python3-full",
    # System Go (fallback)
    "golang-go",
]

GO_TOOLS: List[Tuple[str, str]] = [
    ("subfinder",   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("nuclei",      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("trufflehog",  "github.com/trufflesecurity/trufflehog/v3@latest"),
    ("gowitness",   "github.com/sensepost/gowitness@latest"),
    ("amass",       "github.com/owasp-amass/amass/v4/...@master"),
]

CARGO_TOOLS: List[Tuple[str, str]] = [
    ("feroxbuster", "feroxbuster"),
]

PIP_TOOLS: List[Tuple[str, str]] = [
    ("webtech",  "webtech"),
    ("mcp",      "mcp"),
]

DATA_DIRS = [
    "data", "data/logs", "data/reports", "data/screenshots",
    "data/wordlists", "data/tools", "data/secrets",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_root() -> bool:
    return os.geteuid() == 0


def _run(cmd: List[str], env: Optional[Dict[str, str]] = None, timeout: int = 600) -> Tuple[int, str, str]:
    """Run a command, streaming output to console in real time."""
    merged_env = {**os.environ}
    if env:
        merged_env.update(env)
    # Ensure Go and Cargo bins are always on PATH
    merged_env["PATH"] = (
        f"{GOPATH_BIN}:{CARGO_BIN}:{merged_env.get('PATH', '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')}"
    )
    merged_env["GOPATH"] = str(Path.home() / "go")
    merged_env["HOME"] = str(Path.home())

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=merged_env,
        )
        output_lines: List[str] = []
        if proc.stdout:
            for line in proc.stdout:
                line = line.rstrip()
                output_lines.append(line)
                console.print(f"[dim]  {line}[/dim]")
        proc.wait(timeout=timeout)
        return proc.returncode, "\n".join(output_lines), ""
    except subprocess.TimeoutExpired:
        proc.kill()
        return 124, "", "timed out"
    except OSError as exc:
        return 1, "", str(exc)


def _step(label: str) -> None:
    console.print(f"\n[bold cyan]▶ {label}[/bold cyan]")


def _ok(label: str) -> None:
    console.print(f"[bold green]  ✓ {label}[/bold green]")


def _warn(label: str) -> None:
    console.print(f"[bold yellow]  ⚠ {label}[/bold yellow]")


def _fail(label: str) -> None:
    console.print(f"[bold red]  ✗ {label}[/bold red]")


# ── Step implementations ───────────────────────────────────────────────────────

def step_apt(dry_run: bool) -> Dict[str, str]:
    _step("Updating system packages (apt update + upgrade + install)")
    results: Dict[str, str] = {}

    if dry_run:
        console.print(f"[dim]  DRY-RUN: apt update && apt upgrade && apt install -y {' '.join(APT_PACKAGES)}[/dim]")
        return {p: "dry-run" for p in APT_PACKAGES}

    # Update package lists
    code, _, err = _run(["apt-get", "update", "-y"])
    if code != 0:
        _warn(f"apt update returned {code}: {err[:100]}")

    # Upgrade existing packages
    code, _, err = _run(["apt-get", "upgrade", "-y"])
    if code != 0:
        _warn(f"apt upgrade returned {code}: {err[:100]}")

    # Install required packages
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    code, _, err = _run(
        ["apt-get", "install", "-y", "--no-install-recommends"] + APT_PACKAGES,
        env=env,
    )
    if code != 0:
        _warn(f"Some apt packages may have failed: {err[:200]}")
        results["apt"] = "partial"
    else:
        _ok("System packages installed")
        results["apt"] = "ok"
    return results


def step_go(dry_run: bool) -> str:
    _step("Checking Go toolchain")

    go_bin = which("go")
    if go_bin:
        code, ver, _ = _run(["go", "version"])
        _ok(f"Go already installed: {ver.strip()}")
        return "ok"

    _warn("Go not found — installing from go.dev")
    if dry_run:
        console.print(f"[dim]  DRY-RUN: download {GO_URL} → {GO_INSTALL_DIR}[/dim]")
        return "dry-run"

    tarball = f"/tmp/{GO_TARBALL}"
    code, _, err = _run(["curl", "-fsSL", "-o", tarball, GO_URL])
    if code != 0:
        _fail(f"Failed to download Go: {err}")
        return "failed"

    # Remove old Go installation if present
    _run(["rm", "-rf", f"{GO_INSTALL_DIR}/go"])
    code, _, err = _run(["tar", "-C", GO_INSTALL_DIR, "-xzf", tarball])
    if code != 0:
        _fail(f"Failed to extract Go: {err}")
        return "failed"

    # Symlink go binary to /usr/local/bin
    go_binary = f"{GO_INSTALL_DIR}/go/bin/go"
    _run(["ln", "-sf", go_binary, "/usr/local/bin/go"])
    _run(["ln", "-sf", f"{GO_INSTALL_DIR}/go/bin/gofmt", "/usr/local/bin/gofmt"])
    _run(["rm", "-f", tarball])
    _ok(f"Go {GO_VERSION} installed")
    return "ok"


def step_rust(dry_run: bool) -> str:
    _step("Checking Rust/Cargo toolchain")

    cargo_bin = which("cargo") or which(str(Path(CARGO_BIN) / "cargo"))
    if cargo_bin:
        code, ver, _ = _run(["cargo", "--version"])
        _ok(f"Cargo already installed: {ver.strip()}")
        return "ok"

    _warn("Cargo not found — installing via rustup")
    if dry_run:
        console.print("[dim]  DRY-RUN: curl https://sh.rustup.rs | sh -s -- -y[/dim]")
        return "dry-run"

    code, _, err = _run(
        ["sh", "-c", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path"],
        timeout=300,
    )
    if code != 0:
        _fail(f"rustup install failed: {err}")
        return "failed"

    _ok("Rust/Cargo installed")
    return "ok"


def step_go_tools(dry_run: bool) -> Dict[str, str]:
    _step("Installing Go-based tools")
    results: Dict[str, str] = {}

    # Find go binary
    go_bin = which("go") or "/usr/local/go/bin/go"

    for binary, pkg in GO_TOOLS:
        if which(binary) or Path(GOPATH_BIN, binary).exists():
            _ok(f"{binary}: already installed")
            results[binary] = "ok"
            continue
        if dry_run:
            console.print(f"[dim]  DRY-RUN: go install {pkg}[/dim]")
            results[binary] = "dry-run"
            continue
        console.print(f"[accent]  Installing {binary}...[/accent]")
        # Run as the real user so GOPATH lands in their home, not /root
        cmd = (
            f"export GOPATH='{GOPATH_BIN}/../'; "
            f"export GOBIN='{GOPATH_BIN}'; "
            f"export PATH='/usr/local/go/bin:{GOPATH_BIN}:$PATH'; "
            f"'{go_bin}' install '{pkg}'"
        )
        code, _, err = _run(["su", "-l", _REAL_USER, "-c", cmd], timeout=300)
        if code != 0:
            _fail(f"{binary}: {err[:150]}")
            results[binary] = "failed"
        else:
            _ok(binary)
            results[binary] = "ok"
    return results


def step_cargo_tools(dry_run: bool) -> Dict[str, str]:
    _step("Installing Cargo-based tools")
    results: Dict[str, str] = {}

    cargo = which("cargo") or str(Path(CARGO_BIN) / "cargo")

    for binary, crate in CARGO_TOOLS:
        if which(binary) or Path(CARGO_BIN, binary).exists():
            _ok(f"{binary}: already installed")
            results[binary] = "ok"
            continue
        if dry_run:
            console.print(f"[dim]  DRY-RUN: cargo install {crate}[/dim]")
            results[binary] = "dry-run"
            continue
        if not Path(cargo).exists() and not which("cargo"):
            _warn(f"{binary}: cargo not found — skipping")
            results[binary] = "skipped"
            continue
        console.print(f"[accent]  Installing {binary}...[/accent]")
        # Run as the real user so cargo uses their home
        cmd = f"export PATH='{CARGO_BIN}:$PATH'; '{cargo}' install '{crate}'"
        code, _, err = _run(["su", "-l", _REAL_USER, "-c", cmd], timeout=600)
        if code != 0:
            _fail(f"{binary}: {err[:150]}")
            results[binary] = "failed"
        else:
            _ok(binary)
            results[binary] = "ok"
    return results


def step_pip_tools(dry_run: bool) -> Dict[str, str]:
    """Install Python tools into /opt/aegis-venv to avoid Kali PEP 668 restriction."""
    _step(f"Setting up Python venv at {VENV_DIR}")
    results: Dict[str, str] = {}

    if dry_run:
        console.print(f"[dim]  DRY-RUN: python3 -m venv {VENV_DIR}[/dim]")
        for binary, pkg in PIP_TOOLS:
            console.print(f"[dim]  DRY-RUN: {VENV_DIR}/bin/pip install {pkg}[/dim]")
            results[binary] = "dry-run"
        return results

    venv_pip = str(Path(VENV_DIR) / "bin" / "pip")
    venv_python = str(Path(VENV_DIR) / "bin" / "python")

    # Create venv if it doesn't exist
    if not Path(venv_python).exists():
        code, _, err = _run([sys.executable, "-m", "venv", VENV_DIR])
        if code != 0:
            _fail(f"Failed to create venv: {err}")
            return {"venv": "failed"}
        _ok(f"Venv created at {VENV_DIR}")
    else:
        _ok(f"Venv already exists at {VENV_DIR}")

    # Upgrade pip inside venv
    _run([venv_pip, "install", "--upgrade", "pip", "--quiet"])

    # Install each tool
    for binary, pkg in PIP_TOOLS:
        venv_bin = str(Path(VENV_DIR) / "bin" / binary)
        if Path(venv_bin).exists():
            _ok(f"{binary}: already installed in venv")
            results[binary] = "ok"
            continue
        console.print(f"[accent]  Installing {pkg}...[/accent]")
        code, _, err = _run([venv_pip, "install", "--quiet", pkg])
        if code != 0:
            _fail(f"{pkg}: {err[:150]}")
            results[binary] = "failed"
        else:
            _ok(pkg)
            results[binary] = "ok"

    return results


def step_directories() -> None:
    _step("Creating data directories")
    for d in DATA_DIRS:
        ensure_dir(d)
    _ok("Directories ready")


def step_path_profile() -> None:
    """Append Go/Cargo PATH exports to ~/.bashrc and ~/.zshrc if not already present."""
    _step("Fixing PATH for Go and Cargo binaries")

    exports = (
        "\n# Aegis — Go and Cargo tool paths\n"
        f'export PATH="$PATH:{GOPATH_BIN}:{CARGO_BIN}"\n'
        f'export GOPATH="$HOME/go"\n'
    )

    for rc_file in [Path.home() / ".bashrc", Path.home() / ".zshrc"]:
        if not rc_file.exists():
            continue
        content = rc_file.read_text(encoding="utf-8")
        if GOPATH_BIN in content:
            _ok(f"{rc_file.name}: PATH already configured")
            continue
        rc_file.write_text(content + exports, encoding="utf-8")
        _ok(f"{rc_file.name}: PATH updated")

    # Also export for the current process so subsequent steps work
    os.environ["PATH"] = f"{GOPATH_BIN}:{CARGO_BIN}:{os.environ.get('PATH', '')}"
    os.environ["GOPATH"] = str(Path.home() / "go")


def step_nuclei_templates(dry_run: bool) -> str:
    """Update Nuclei templates after install."""
    _step("Updating Nuclei templates")
    nuclei = which("nuclei") or str(Path(GOPATH_BIN) / "nuclei")
    if not Path(nuclei).exists() and not which("nuclei"):
        _warn("nuclei not found — skipping template update")
        return "skipped"
    if dry_run:
        console.print("[dim]  DRY-RUN: nuclei -update-templates[/dim]")
        return "dry-run"
    code, _, err = _run([nuclei, "-update-templates"], timeout=120)
    if code != 0:
        _warn(f"Template update failed (non-fatal): {err[:100]}")
        return "warn"
    _ok("Nuclei templates updated")
    return "ok"


def step_validate() -> Dict[str, str]:
    """Check every tool is reachable and report status."""
    _step("Validating installation")
    all_tools = (
        [b for b, _ in GO_TOOLS]
        + [b for b, _ in CARGO_TOOLS]
        + [b for b, _ in PIP_TOOLS]
        + ["nmap", "sqlmap", "whatweb", "nikto", "ffuf", "curl", "git"]
    )
    results: Dict[str, str] = {}
    for tool in all_tools:
        found = (
            which(tool)
            or Path(GOPATH_BIN, tool).exists()
            or Path(CARGO_BIN, tool).exists()
        )
        if found:
            _ok(tool)
            results[tool] = "ok"
        else:
            _warn(f"{tool}: not found on PATH (may need to open a new terminal)")
            results[tool] = "missing"
    return results


# ── Main bootstrap entry point ────────────────────────────────────────────────

def run_bootstrap(dry_run: bool = False, skip_rust: bool = False) -> Dict[str, object]:
    """Run the full bootstrap sequence. Returns a summary dict."""
    console.print("\n[bold green]╔══════════════════════════════════════╗[/bold green]")
    console.print("[bold green]║   Aegis Full Bootstrap — Starting    ║[/bold green]")
    console.print("[bold green]╚══════════════════════════════════════╝[/bold green]\n")

    if not _is_root() and not dry_run:
        console.print(
            "[bold red]Bootstrap requires root privileges.[/bold red]\n"
            "Run with: [cyan]sudo aegis bootstrap --yes[/cyan]\n"
            "Or:       [cyan]sudo python -m aegis bootstrap --yes[/cyan]"
        )
        sys.exit(1)

    summary: Dict[str, object] = {}

    summary["apt"]         = step_apt(dry_run)
    summary["go"]          = step_go(dry_run)
    if not skip_rust:
        summary["rust"]    = step_rust(dry_run)
    step_path_profile()
    summary["go_tools"]    = step_go_tools(dry_run)
    if not skip_rust:
        summary["cargo_tools"] = step_cargo_tools(dry_run)
    summary["pip_tools"]   = step_pip_tools(dry_run)
    step_directories()
    summary["nuclei_templates"] = step_nuclei_templates(dry_run)
    summary["validation"]  = step_validate()

    # Final summary table
    console.print("\n[bold green]╔══════════════════════════════════════╗[/bold green]")
    console.print("[bold green]║         Bootstrap Complete           ║[/bold green]")
    console.print("[bold green]╚══════════════════════════════════════╝[/bold green]")
    console.print(
        "\n[primary]Next steps:[/primary]\n"
        "  1. Open a new terminal (or run: [cyan]source ~/.bashrc[/cyan])\n"
        "  2. Edit [cyan]config/config.yaml[/cyan] — add your free API keys\n"
        "  3. Run [cyan]aegis doctor[/cyan] to verify everything\n"
        "  4. Run [cyan]aegis ai auto --target <host>[/cyan] to start a pentest\n"
    )
    return summary
