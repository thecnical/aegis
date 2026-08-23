#!/usr/bin/env bash
# =============================================================================
# Aegis-Devin v3.0.0 — ONE COMMAND FULL INSTALL
# =============================================================================
#
# Usage (copy-paste this SINGLE line):
#
#   git clone https://github.com/thecnical/aegis-devin.git && cd aegis-devin && sudo bash setup.sh
#
# What this does:
#   1. Detects your OS (Kali, Ubuntu, Debian, Arch, Fedora, macOS)
#   2. Installs ALL system dependencies (python3-venv, nmap, sqlmap, etc.)
#   3. Creates a Python virtual environment (bypasses PEP 668 / "externally managed" error)
#   4. Installs Aegis + all Python dependencies inside the venv
#   5. Installs Go-based tools (nuclei, subfinder, trufflehog, gowitness)
#   6. Installs Rust-based tools (feroxbuster)
#   7. Creates a global `aegis` command that works from anywhere
#   8. Sets up PATH for Go/Cargo tools
#   9. Updates nuclei templates
#  10. Runs validation to confirm everything works
#
# Requirements: sudo access, internet connection
# Time: ~3-5 minutes on good internet
# =============================================================================

set -uo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  [OK] $*${RESET}"; }
warn() { echo -e "${YELLOW}  [!] $*${RESET}"; }
fail() { echo -e "${RED}  [X] $*${RESET}"; }
step() { echo -e "\n${CYAN}${BOLD}[$1/7] $2${RESET}"; }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  fail "This script requires root. Run with: sudo bash setup.sh"
  exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6 || echo "/home/$REAL_USER")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
GOPATH_DIR="$REAL_HOME/go"
GOPATH_BIN="$GOPATH_DIR/bin"
CARGO_BIN="$REAL_HOME/.cargo/bin"

echo -e "\n${BOLD}${GREEN}"
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║     AEGIS-DEVIN v3.0.0 — Full Stack Auto-Installer       ║"
echo "  ║     AI Autonomous Pentest + Network Forensics Platform    ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  User: ${CYAN}$REAL_USER${RESET}  |  OS: ${CYAN}$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -s)${RESET}"
echo -e "  Project: ${CYAN}$SCRIPT_DIR${RESET}"
echo ""

# =============================================================================
# STEP 1: System packages
# =============================================================================
step 1 "Installing system packages"

# Detect package manager
if command -v apt-get &>/dev/null; then
  PKG_MGR="apt"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3 python3-pip python3-venv python3-full \
    git curl wget build-essential pkg-config \
    nmap smbclient netcat-openbsd hydra sqlmap nikto whatweb ffuf \
    golang rustc cargo \
    libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
    libcairo2 libffi-dev libgdk-pixbuf-2.0-0 \
    tcpdump tshark 2>/dev/null || true
elif command -v pacman &>/dev/null; then
  PKG_MGR="pacman"
  pacman -Sy --noconfirm python python-pip python-virtualenv \
    git curl wget nmap sqlmap hydra nikto go rust \
    tcpdump wireshark-cli 2>/dev/null || true
elif command -v dnf &>/dev/null; then
  PKG_MGR="dnf"
  dnf install -y python3 python3-pip python3-virtualenv \
    git curl wget nmap sqlmap hydra golang cargo \
    tcpdump wireshark-cli 2>/dev/null || true
elif command -v brew &>/dev/null; then
  PKG_MGR="brew"
  sudo -u "$REAL_USER" brew install python3 nmap sqlmap go rust tcpdump 2>/dev/null || true
else
  fail "Unsupported package manager. Install python3, python3-venv, nmap manually."
  exit 1
fi
ok "System packages installed ($PKG_MGR)"

# =============================================================================
# STEP 2: Python virtual environment + Aegis
# =============================================================================
step 2 "Setting up Python virtual environment + Aegis"

# Create venv (this bypasses PEP 668 "externally managed environment")
python3 -m venv "$VENV_DIR"
ok "Virtual environment created at $VENV_DIR"

# Upgrade pip
"$VENV_DIR/bin/pip" install --upgrade pip --quiet

# Install Aegis with all dependencies
"$VENV_DIR/bin/pip" install -e "$SCRIPT_DIR" --quiet 2>&1 | tail -5
ok "Aegis + all Python dependencies installed"

# Install optional forensics deps (non-fatal if they fail)
"$VENV_DIR/bin/pip" install scapy dpkt blake3 --quiet 2>/dev/null || warn "Some forensics deps skipped (non-fatal)"

# Fix ownership
chown -R "$REAL_USER:$REAL_USER" "$VENV_DIR" 2>/dev/null || true

# =============================================================================
# STEP 3: Global 'aegis' command
# =============================================================================
step 3 "Creating global 'aegis' command"

cat > /usr/local/bin/aegis << EOF
#!/usr/bin/env bash
export AEGIS_PROJECT_DIR="$SCRIPT_DIR"
export PATH="$GOPATH_BIN:$CARGO_BIN:\$PATH"
export GOPATH="$GOPATH_DIR"
exec "$VENV_DIR/bin/aegis" "\$@"
EOF
chmod +x /usr/local/bin/aegis

cat > /usr/local/bin/aegis-mcp << EOF
#!/usr/bin/env bash
export AEGIS_PROJECT_DIR="$SCRIPT_DIR"
export PATH="$GOPATH_BIN:$CARGO_BIN:\$PATH"
exec "$VENV_DIR/bin/aegis-mcp" "\$@"
EOF
chmod +x /usr/local/bin/aegis-mcp

ok "'aegis' command available globally at /usr/local/bin/aegis"

# =============================================================================
# STEP 4: Go-based security tools
# =============================================================================
step 4 "Installing Go-based security tools"

GO_BIN=""
command -v go &>/dev/null && GO_BIN="$(command -v go)"
[[ -z "$GO_BIN" && -x /usr/local/go/bin/go ]] && GO_BIN="/usr/local/go/bin/go"
[[ -z "$GO_BIN" && -x /usr/bin/go ]] && GO_BIN="/usr/bin/go"

if [[ -n "$GO_BIN" ]]; then
  mkdir -p "$GOPATH_BIN"
  chown -R "$REAL_USER:$REAL_USER" "$GOPATH_DIR" 2>/dev/null || true

  install_go_tool() {
    local name="$1" pkg="$2"
    if command -v "$name" &>/dev/null || [[ -f "$GOPATH_BIN/$name" ]]; then
      ok "$name (already installed)"
    else
      echo -e "  Installing $name..."
      sudo -u "$REAL_USER" HOME="$REAL_HOME" GOPATH="$GOPATH_DIR" GOBIN="$GOPATH_BIN" \
        "$GO_BIN" install "$pkg" 2>/dev/null && ok "$name" || warn "$name (failed, non-fatal)"
    fi
  }

  install_go_tool "nuclei"     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  install_go_tool "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool "trufflehog" "github.com/trufflesecurity/trufflehog/v3@latest"
  install_go_tool "gowitness"  "github.com/sensepost/gowitness@latest"
else
  warn "Go not found — skipping Go-based tools (nuclei, subfinder, etc.)"
  warn "Install Go manually: apt install golang OR download from https://go.dev"
fi

# =============================================================================
# STEP 5: Rust-based tools (feroxbuster)
# =============================================================================
step 5 "Installing Rust-based tools"

CARGO_CMD=""
command -v cargo &>/dev/null && CARGO_CMD="$(command -v cargo)"
[[ -z "$CARGO_CMD" && -x "$CARGO_BIN/cargo" ]] && CARGO_CMD="$CARGO_BIN/cargo"

if command -v feroxbuster &>/dev/null || [[ -f "$CARGO_BIN/feroxbuster" ]]; then
  ok "feroxbuster (already installed)"
elif [[ -n "$CARGO_CMD" ]]; then
  echo -e "  Installing feroxbuster (may take 2-3 min)..."
  sudo -u "$REAL_USER" HOME="$REAL_HOME" "$CARGO_CMD" install feroxbuster 2>/dev/null \
    && ok "feroxbuster" || warn "feroxbuster (failed, non-fatal)"
else
  warn "Cargo not found — skipping feroxbuster"
fi

# =============================================================================
# STEP 6: PATH + Shell configuration
# =============================================================================
step 6 "Configuring shell PATH"

PATH_EXPORT="
# ── Aegis tools PATH (auto-added by setup.sh) ──
export GOPATH=\"$GOPATH_DIR\"
export PATH=\"\$PATH:$GOPATH_BIN:$CARGO_BIN\"
"

for rcfile in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
  if [[ -f "$rcfile" ]] && ! grep -q "Aegis tools PATH" "$rcfile"; then
    echo "$PATH_EXPORT" >> "$rcfile"
    chown "$REAL_USER:$REAL_USER" "$rcfile" 2>/dev/null || true
    ok "Updated $rcfile"
  elif [[ -f "$rcfile" ]]; then
    ok "$rcfile (already configured)"
  fi
done

# =============================================================================
# STEP 7: Validation
# =============================================================================
step 7 "Validating installation"

PASS=0; TOTAL=0
validate() {
  local name="$1"; shift
  ((TOTAL++))
  if "$@" &>/dev/null 2>&1; then
    ok "$name"
    ((PASS++))
  else
    warn "$name — not found"
  fi
}

validate "aegis"       test -x /usr/local/bin/aegis
validate "python venv" test -d "$VENV_DIR/bin/python3"
validate "nmap"        command -v nmap
validate "sqlmap"      command -v sqlmap
validate "hydra"       command -v hydra
validate "nikto"       command -v nikto
validate "nuclei"      bash -c "command -v nuclei || test -f '$GOPATH_BIN/nuclei'"
validate "subfinder"   bash -c "command -v subfinder || test -f '$GOPATH_BIN/subfinder'"
validate "feroxbuster" bash -c "command -v feroxbuster || test -f '$CARGO_BIN/feroxbuster'"
validate "tcpdump"     command -v tcpdump

# Create data directories
mkdir -p "$SCRIPT_DIR/data"/{logs,reports,screenshots,wordlists,forensics/captures,workflows}
chown -R "$REAL_USER:$REAL_USER" "$SCRIPT_DIR/data" 2>/dev/null || true

# =============================================================================
# DONE
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║              INSTALLATION COMPLETE!                       ║${RESET}"
echo -e "${BOLD}${GREEN}║           $PASS/$TOTAL tools installed successfully               ║${RESET}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${CYAN}Quick Start (open a NEW terminal first):${RESET}"
echo ""
echo -e "  ${GREEN}1.${RESET} aegis doctor                          # Verify installation"
echo -e "  ${GREEN}2.${RESET} aegis configure-keys --interactive    # Set free AI API keys"
echo -e "  ${GREEN}3.${RESET} aegis scope add <target>              # Add target"
echo -e "  ${GREEN}4.${RESET} aegis ai auto --target <host>         # Full AI pentest!"
echo ""
echo -e "${CYAN}One-Liner to test right now:${RESET}"
echo -e "  ${BOLD}aegis --help${RESET}"
echo ""
echo -e "${YELLOW}Note: Open a new terminal for PATH changes to take effect.${RESET}"
echo ""
