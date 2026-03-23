#!/usr/bin/env bash
# =============================================================================
# Aegis — One-Command Full Installer
# Supports: Kali Linux, Debian, Ubuntu
# Usage:
#   sudo bash install.sh            # full install
#   sudo bash install.sh --dry-run  # preview only
# =============================================================================
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

run() {
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
echo -e "${BOLD}${GREEN}║        Aegis — Full Installer            ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}\n"

# ── Detect real user home (correct under sudo) ────────────────────────────────
# When running as sudo, SUDO_USER is the original user, HOME may be /root
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Go and Cargo paths for the real user
GO_INSTALL_DIR="/usr/local"
GO_BIN="$GO_INSTALL_DIR/go/bin/go"
GOPATH_DIR="$REAL_HOME/go"
GOPATH_BIN="$GOPATH_DIR/bin"
CARGO_BIN="$REAL_HOME/.cargo/bin"

# Make sure Go and Cargo bins are on PATH for this script session
export PATH="/usr/local/go/bin:$GOPATH_BIN:$CARGO_BIN:$PATH"
export GOPATH="$GOPATH_DIR"

echo -e "  Installing as user: ${CYAN}${REAL_USER}${RESET}  (home: ${CYAN}${REAL_HOME}${RESET})"

# ── Step 1: apt update + upgrade + packages ───────────────────────────────────
step "Updating system packages (apt update && apt upgrade)"
if [[ $DRY_RUN -eq 0 ]]; then
  apt-get update -y
  apt-get upgrade -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nmap smbclient netcat-openbsd hydra sqlmap nikto whatweb ffuf \
    curl wget git build-essential pkg-config \
    python3 python3-pip python3-venv python3-full \
    golang-go \
    libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
    libcairo2 libffi-dev libgdk-pixbuf-2.0-0
else
  echo -e "  ${YELLOW}DRY-RUN:${RESET} apt-get update && apt-get upgrade && apt-get install ..."
fi
ok "System packages installed"

# ── Step 2: Go toolchain ──────────────────────────────────────────────────────
step "Checking Go toolchain"
GO_VERSION="1.22.4"

# Prefer system Go if available and recent enough, otherwise install manually
if command -v go &>/dev/null; then
  ok "Go already installed: $(go version)"
  GO_BIN="$(command -v go)"
else
  warn "Go not found — installing Go $GO_VERSION from go.dev"
  if [[ $DRY_RUN -eq 0 ]]; then
    TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
    curl -fsSL -o "/tmp/$TARBALL" "https://go.dev/dl/$TARBALL"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/$TARBALL"
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    rm -f "/tmp/$TARBALL"
    export PATH="/usr/local/go/bin:$PATH"
    GO_BIN="/usr/local/go/bin/go"
  else
    echo -e "  ${YELLOW}DRY-RUN:${RESET} install Go $GO_VERSION to /usr/local/go"
    GO_BIN="/usr/local/go/bin/go"
  fi
  ok "Go $GO_VERSION installed"
fi

# ── Step 3: Rust/Cargo ────────────────────────────────────────────────────────
step "Checking Rust/Cargo"
CARGO_CMD="$CARGO_BIN/cargo"

if command -v cargo &>/dev/null || [[ -f "$CARGO_CMD" ]]; then
  ok "Cargo already installed"
  CARGO_CMD="$(command -v cargo 2>/dev/null || echo "$CARGO_CMD")"
else
  warn "Cargo not found — installing via rustup"
  if [[ $DRY_RUN -eq 0 ]]; then
    # Install as the real user, not root
    su -l "$REAL_USER" -c \
      'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path' \
      || warn "rustup install failed (non-fatal — feroxbuster will be skipped)"
  else
    echo -e "  ${YELLOW}DRY-RUN:${RESET} rustup install for $REAL_USER"
  fi
  ok "Rust/Cargo installed"
fi

# ── Step 4: Go-based tools ────────────────────────────────────────────────────
step "Installing Go-based tools"

# Helper: run go install as the real user with correct env
go_install() {
  local pkg="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN:${RESET} go install $pkg"
    return 0
  fi
  su -l "$REAL_USER" -c \
    "export GOPATH='$GOPATH_DIR'; export GOBIN='$GOPATH_BIN'; export PATH='/usr/local/go/bin:$GOPATH_BIN:$PATH'; go install '$pkg'" \
    2>&1 || return 1
}

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
    echo -e "  Installing ${CYAN}$binary${RESET}..."
    if go_install "$pkg"; then
      ok "$binary"
    else
      warn "$binary install failed (non-fatal)"
    fi
  fi
done

# ── Step 5: Cargo-based tools ─────────────────────────────────────────────────
step "Installing Cargo-based tools"

cargo_install() {
  local crate="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN:${RESET} cargo install $crate"
    return 0
  fi
  su -l "$REAL_USER" -c \
    "export PATH='$CARGO_BIN:$PATH'; '$CARGO_BIN/cargo' install '$crate'" \
    2>&1 || return 1
}

if command -v feroxbuster &>/dev/null || [[ -f "$CARGO_BIN/feroxbuster" ]]; then
  ok "feroxbuster: already installed"
elif [[ ! -f "$CARGO_BIN/cargo" ]] && ! command -v cargo &>/dev/null; then
  warn "feroxbuster skipped — cargo not available"
else
  echo -e "  Installing ${CYAN}feroxbuster${RESET} (this takes a few minutes)..."
  if cargo_install "feroxbuster"; then
    ok "feroxbuster"
  else
    warn "feroxbuster install failed (non-fatal)"
  fi
fi

# ── Step 6: Python venv + pip tools ──────────────────────────────────────────
# Kali Linux uses an externally-managed Python (PEP 668).
# We install into a dedicated venv at /opt/aegis-venv so pip works cleanly.
step "Setting up Python virtual environment"

VENV_DIR="/opt/aegis-venv"

if [[ $DRY_RUN -eq 0 ]]; then
  python3 -m venv "$VENV_DIR"
  # Install pip tools into the venv
  "$VENV_DIR/bin/pip" install --upgrade pip --quiet
  "$VENV_DIR/bin/pip" install webtech mcp --quiet
  ok "Python venv created at $VENV_DIR"

  # Install Aegis itself into the venv
  step "Installing Aegis"
  if [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
    "$VENV_DIR/bin/pip" install -e "$SCRIPT_DIR" --quiet
    ok "Aegis installed from source into venv"
  else
    "$VENV_DIR/bin/pip" install aegis-cli --quiet
    ok "Aegis installed from PyPI into venv"
  fi

  # Create wrapper scripts in /usr/local/bin so 'aegis' works system-wide
  cat > /usr/local/bin/aegis <<WRAPPER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/aegis" "\$@"
WRAPPER
  chmod +x /usr/local/bin/aegis

  cat > /usr/local/bin/aegis-mcp <<WRAPPER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/aegis-mcp" "\$@"
WRAPPER
  chmod +x /usr/local/bin/aegis-mcp

  ok "Wrapper scripts created: /usr/local/bin/aegis and /usr/local/bin/aegis-mcp"
else
  echo -e "  ${YELLOW}DRY-RUN:${RESET} python3 -m venv $VENV_DIR"
  echo -e "  ${YELLOW}DRY-RUN:${RESET} pip install webtech mcp aegis-cli"
  echo -e "  ${YELLOW}DRY-RUN:${RESET} create /usr/local/bin/aegis wrapper"
fi

# ── Step 7: Data directories ──────────────────────────────────────────────────
step "Creating data directories"
for d in data data/logs data/reports data/screenshots data/wordlists data/tools data/secrets; do
  run mkdir -p "$SCRIPT_DIR/$d"
done
# Fix ownership so the real user can write to them
if [[ $DRY_RUN -eq 0 ]]; then
  chown -R "$REAL_USER:$REAL_USER" "$SCRIPT_DIR/data" 2>/dev/null || true
fi
ok "Directories ready"

# ── Step 8: Nuclei templates ──────────────────────────────────────────────────
step "Updating Nuclei templates"
if [[ $DRY_RUN -eq 0 ]]; then
  NUCLEI_BIN=""
  if command -v nuclei &>/dev/null; then
    NUCLEI_BIN="$(command -v nuclei)"
  elif [[ -f "$GOPATH_BIN/nuclei" ]]; then
    NUCLEI_BIN="$GOPATH_BIN/nuclei"
  fi

  if [[ -n "$NUCLEI_BIN" ]]; then
    su -l "$REAL_USER" -c \
      "export PATH='$GOPATH_BIN:$PATH'; '$NUCLEI_BIN' -update-templates -silent" \
      || warn "Template update failed (non-fatal)"
    ok "Nuclei templates updated"
  else
    warn "nuclei not found — skipping template update"
  fi
else
  echo -e "  ${YELLOW}DRY-RUN:${RESET} nuclei -update-templates"
fi

# ── Step 9: Fix PATH in shell profiles ───────────────────────────────────────
step "Updating shell PATH for $REAL_USER"

PATH_BLOCK="
# Aegis — Go and Cargo tool paths (added by install.sh)
export GOPATH=\"$GOPATH_DIR\"
export PATH=\"\$PATH:$GOPATH_BIN:$CARGO_BIN\"
"

for rc in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
  if [[ -f "$rc" ]] && ! grep -q "Aegis — Go and Cargo" "$rc"; then
    echo "$PATH_BLOCK" >> "$rc"
    chown "$REAL_USER:$REAL_USER" "$rc" 2>/dev/null || true
    ok "Updated $rc"
  elif [[ -f "$rc" ]]; then
    ok "$rc: PATH already configured"
  fi
done

# ── Final validation ──────────────────────────────────────────────────────────
step "Validating installation"

ALL_TOOLS=(nmap sqlmap whatweb nikto ffuf subfinder nuclei trufflehog gowitness feroxbuster)
MISSING=()

for t in "${ALL_TOOLS[@]}"; do
  if command -v "$t" &>/dev/null \
    || [[ -f "$GOPATH_BIN/$t" ]] \
    || [[ -f "$CARGO_BIN/$t" ]]; then
    ok "$t"
  else
    warn "$t: not found (may need new terminal)"
    MISSING+=("$t")
  fi
done

# Check aegis itself
if command -v aegis &>/dev/null || [[ -f "/usr/local/bin/aegis" ]]; then
  ok "aegis"
else
  warn "aegis: not found"
  MISSING+=("aegis")
fi

# Check Python tools inside venv
for pt in webtech; do
  if [[ -f "$VENV_DIR/bin/$pt" ]] || command -v "$pt" &>/dev/null; then
    ok "$pt (venv)"
  else
    warn "$pt: not found in venv"
    MISSING+=("$pt")
  fi
done

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║        Installation Complete!            ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${CYAN}Next steps:${RESET}"
echo "  1. Open a new terminal (or run: source ~/.zshrc)"
echo "  2. Edit $SCRIPT_DIR/config/config.yaml — add your free API keys"
echo "  3. Run: aegis doctor"
echo "  4. Run: aegis ai auto --target <host>"
echo ""

if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "Some tools not on PATH yet: ${MISSING[*]}"
  echo "  → Open a new terminal and run: aegis doctor"
  echo "  → Go tools are in: $GOPATH_BIN"
  echo "  → Cargo tools are in: $CARGO_BIN"
fi
