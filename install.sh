#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Aegis — One-Command Full Installer
# Supports: Kali Linux, Debian, Ubuntu (any version with apt)
# Usage:
#   sudo bash install.sh          # full install
#   sudo bash install.sh --dry-run  # preview only
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
  [[ "$arg" == "--dry-run" ]] && DRY_RUN=1
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
fail() { echo -e "${RED}  ✗ $*${RESET}"; }
step() { echo -e "\n${CYAN}${BOLD}▶ $*${RESET}"; }
run()  {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN:${RESET} $*"
  else
    "$@"
  fi
}

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]] && [[ $DRY_RUN -eq 0 ]]; then
  fail "This script must be run as root: sudo bash install.sh"
  exit 1
fi

echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║   Aegis — Full Installer                 ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}\n"

# ── Detect home dir (works under sudo) ───────────────────────────────────────
REAL_HOME="${SUDO_HOME:-$HOME}"
REAL_USER="${SUDO_USER:-$(whoami)}"
GOPATH_BIN="$REAL_HOME/go/bin"
CARGO_BIN="$REAL_HOME/.cargo/bin"
export PATH="$GOPATH_BIN:$CARGO_BIN:/usr/local/go/bin:$PATH"
export GOPATH="$REAL_HOME/go"
export HOME="$REAL_HOME"

# ── Step 1: apt packages ──────────────────────────────────────────────────────
step "Installing system packages"
run apt-get update -qq
run apt-get install -y --no-install-recommends \
  nmap smbclient netcat-openbsd hydra sqlmap nikto whatweb ffuf curl wget git \
  build-essential pkg-config python3-pip python3-venv \
  libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
  libcairo2 libffi-dev libgdk-pixbuf-2.0-0
ok "System packages installed"

# ── Step 2: Go toolchain ──────────────────────────────────────────────────────
step "Checking Go toolchain"
GO_VERSION="1.22.4"
if command -v go &>/dev/null; then
  ok "Go already installed: $(go version)"
else
  warn "Installing Go $GO_VERSION..."
  TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
  run curl -fsSL -o "/tmp/$TARBALL" "https://go.dev/dl/$TARBALL"
  run rm -rf /usr/local/go
  run tar -C /usr/local -xzf "/tmp/$TARBALL"
  run ln -sf /usr/local/go/bin/go /usr/local/bin/go
  run ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  run rm -f "/tmp/$TARBALL"
  ok "Go $GO_VERSION installed"
fi

# ── Step 3: Rust/Cargo ────────────────────────────────────────────────────────
step "Checking Rust/Cargo"
if command -v cargo &>/dev/null || [[ -f "$CARGO_BIN/cargo" ]]; then
  ok "Cargo already installed"
else
  warn "Installing Rust via rustup..."
  run su -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path' "$REAL_USER"
  ok "Rust installed"
fi
export PATH="$CARGO_BIN:$PATH"

# ── Step 4: Go tools ──────────────────────────────────────────────────────────
step "Installing Go-based tools"
GO_TOOLS=(
  "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "trufflehog:github.com/trufflesecurity/trufflehog/v3@latest"
  "gowitness:github.com/sensepost/gowitness@latest"
  "amass:github.com/owasp-amass/amass/v4/...@master"
)
for entry in "${GO_TOOLS[@]}"; do
  binary="${entry%%:*}"
  pkg="${entry#*:}"
  if command -v "$binary" &>/dev/null || [[ -f "$GOPATH_BIN/$binary" ]]; then
    ok "$binary: already installed"
  else
    echo "  Installing $binary..."
    run su -c "GOPATH=$GOPATH_BIN/../ GOBIN=$GOPATH_BIN /usr/local/go/bin/go install $pkg" "$REAL_USER" || warn "$binary install failed (non-fatal)"
    ok "$binary"
  fi
done

# ── Step 5: Cargo tools ───────────────────────────────────────────────────────
step "Installing Cargo-based tools"
if command -v feroxbuster &>/dev/null || [[ -f "$CARGO_BIN/feroxbuster" ]]; then
  ok "feroxbuster: already installed"
else
  echo "  Installing feroxbuster (this takes a few minutes)..."
  run su -c "$CARGO_BIN/cargo install feroxbuster" "$REAL_USER" || warn "feroxbuster install failed (non-fatal)"
  ok "feroxbuster"
fi

# ── Step 6: Python tools ──────────────────────────────────────────────────────
step "Installing Python tools"
run pip3 install --quiet webtech mcp
ok "webtech, mcp installed"

# ── Step 7: Aegis itself ──────────────────────────────────────────────────────
step "Installing Aegis"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
  run pip3 install -e "$SCRIPT_DIR"
  ok "Aegis installed from source"
else
  run pip3 install aegis-cli
  ok "Aegis installed from PyPI"
fi

# ── Step 8: Data directories ──────────────────────────────────────────────────
step "Creating data directories"
for d in data data/logs data/reports data/screenshots data/wordlists data/tools data/secrets; do
  run mkdir -p "$SCRIPT_DIR/$d"
done
ok "Directories ready"

# ── Step 9: Nuclei templates ──────────────────────────────────────────────────
step "Updating Nuclei templates"
NUCLEI_BIN="$GOPATH_BIN/nuclei"
if [[ -f "$NUCLEI_BIN" ]] || command -v nuclei &>/dev/null; then
  run su -c "nuclei -update-templates -silent" "$REAL_USER" || warn "Template update failed (non-fatal)"
  ok "Nuclei templates updated"
else
  warn "nuclei not found — skipping template update"
fi

# ── Step 10: Fix PATH in shell profiles ───────────────────────────────────────
step "Updating shell PATH"
PATH_EXPORT="
# Aegis — Go and Cargo tool paths
export PATH=\"\$PATH:$GOPATH_BIN:$CARGO_BIN\"
export GOPATH=\"$REAL_HOME/go\"
"
for rc in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
  if [[ -f "$rc" ]] && ! grep -q "$GOPATH_BIN" "$rc"; then
    echo "$PATH_EXPORT" >> "$rc"
    ok "Updated $rc"
  fi
done

# ── Final validation ──────────────────────────────────────────────────────────
step "Validating installation"
ALL_TOOLS=(nmap sqlmap whatweb nikto ffuf subfinder nuclei trufflehog gowitness feroxbuster webtech)
MISSING=()
for t in "${ALL_TOOLS[@]}"; do
  if command -v "$t" &>/dev/null || [[ -f "$GOPATH_BIN/$t" ]] || [[ -f "$CARGO_BIN/$t" ]]; then
    ok "$t"
  else
    warn "$t: not found (may need new terminal)"
    MISSING+=("$t")
  fi
done

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║   Installation Complete!                 ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${CYAN}Next steps:${RESET}"
echo "  1. Open a new terminal (or run: source ~/.bashrc)"
echo "  2. Edit config/config.yaml — add your free API keys"
echo "  3. Run: aegis doctor"
echo "  4. Run: aegis ai auto --target <host>"
echo ""
if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "Some tools not on PATH yet: ${MISSING[*]}"
  echo "  → Open a new terminal and run: aegis doctor"
fi
