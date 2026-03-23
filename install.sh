#!/usr/bin/env bash
# =============================================================================
# Aegis — Bulletproof One-Command Installer
# Supports: Kali Linux, Debian, Ubuntu
#
# Usage:
#   sudo bash install.sh            # full install
#   sudo bash install.sh --dry-run  # preview only
# =============================================================================
set -uo pipefail   # NOTE: no -e so we handle errors ourselves

DRY_RUN=0
for arg in "$@"; do [[ "$arg" == "--dry-run" ]] && DRY_RUN=1; done

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
fail() { echo -e "${RED}  ✗ $*${RESET}"; }
step() { echo -e "\n${CYAN}${BOLD}▶ $*${RESET}"; }
info() { echo -e "  ${CYAN}$*${RESET}"; }

dryrun() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN:${RESET} $*"; return 0
  fi
  "$@"
}

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 && $DRY_RUN -eq 0 ]]; then
  fail "Run as root:  sudo bash install.sh"
  exit 1
fi

echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║        Aegis — Full Installer            ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}\n"

# ── Resolve real user (works correctly under sudo) ────────────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[[ -z "$REAL_HOME" ]] && REAL_HOME="/home/$REAL_USER"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info "User  : $REAL_USER"
info "Home  : $REAL_HOME"
info "Script: $SCRIPT_DIR"

# ── Path constants ────────────────────────────────────────────────────────────
GOPATH_DIR="$REAL_HOME/go"
GOPATH_BIN="$GOPATH_DIR/bin"
CARGO_BIN="$REAL_HOME/.cargo/bin"
VENV_DIR="$SCRIPT_DIR/.venv"          # project-local venv (not /opt)
PIP_CACHE="$REAL_HOME/.cache/pip"

# ── Helper: run a command as the real user ────────────────────────────────────
# Uses sudo -u instead of su -l to avoid login-shell PATH resets
as_user() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN (as $REAL_USER):${RESET} $*"; return 0
  fi
  sudo -u "$REAL_USER" \
    HOME="$REAL_HOME" \
    GOPATH="$GOPATH_DIR" \
    GOBIN="$GOPATH_BIN" \
    PATH="/usr/local/go/bin:$GOPATH_BIN:$CARGO_BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    bash -c "$*"
}

# =============================================================================
# STEP 1 — apt update + upgrade + install all system packages
# =============================================================================
step "System packages (apt update + upgrade + install)"

if [[ $DRY_RUN -eq 0 ]]; then
  apt-get update -y
  apt-get upgrade -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget git build-essential pkg-config \
    golang rustc cargo \
    python3 python3-pip python3-venv python3-full \
    nmap smbclient netcat-openbsd hydra sqlmap nikto whatweb ffuf \
    libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
    libcairo2 libffi-dev libgdk-pixbuf-2.0-0
else
  echo -e "  ${YELLOW}DRY-RUN:${RESET} apt-get update && apt-get upgrade && apt-get install ..."
fi
ok "System packages ready"

# =============================================================================
# STEP 2 — Go toolchain
# =============================================================================
step "Go toolchain"

GO_VERSION="1.22.4"
GO_BIN=""

# Check system Go first (apt installed golang)
for candidate in /usr/bin/go /usr/local/go/bin/go; do
  if [[ -x "$candidate" ]]; then
    GO_BIN="$candidate"
    break
  fi
done
command -v go &>/dev/null && GO_BIN="$(command -v go)"

if [[ -n "$GO_BIN" ]]; then
  ok "Go already installed: $($GO_BIN version 2>/dev/null || echo 'unknown')"
else
  warn "Go not found via apt — downloading Go $GO_VERSION from go.dev"
  if [[ $DRY_RUN -eq 0 ]]; then
    TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
    curl -fsSL -o "/tmp/$TARBALL" "https://go.dev/dl/$TARBALL"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/$TARBALL"
    ln -sf /usr/local/go/bin/go   /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    rm -f "/tmp/$TARBALL"
    GO_BIN="/usr/local/go/bin/go"
    export PATH="/usr/local/go/bin:$PATH"
    ok "Go $GO_VERSION installed to /usr/local/go"
  else
    echo -e "  ${YELLOW}DRY-RUN:${RESET} download + install Go $GO_VERSION"
    GO_BIN="/usr/local/go/bin/go"
  fi
fi

# =============================================================================
# STEP 3 — Rust / Cargo
# =============================================================================
step "Rust / Cargo"

CARGO_CMD=""
for candidate in /usr/bin/cargo "$CARGO_BIN/cargo"; do
  [[ -x "$candidate" ]] && CARGO_CMD="$candidate" && break
done
command -v cargo &>/dev/null && CARGO_CMD="$(command -v cargo)"

if [[ -n "$CARGO_CMD" ]]; then
  ok "Cargo already installed: $($CARGO_CMD --version 2>/dev/null || echo 'unknown')"
else
  warn "Cargo not found via apt — installing via rustup as $REAL_USER"
  if [[ $DRY_RUN -eq 0 ]]; then
    as_user 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path' \
      && CARGO_CMD="$CARGO_BIN/cargo" \
      || warn "rustup failed — feroxbuster will be skipped (non-fatal)"
    ok "Rust/Cargo installed"
  else
    echo -e "  ${YELLOW}DRY-RUN:${RESET} rustup install for $REAL_USER"
  fi
fi

# =============================================================================
# STEP 4 — Go-based tools
# =============================================================================
step "Go-based tools"

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
    continue
  fi

  if [[ -z "$GO_BIN" ]]; then
    warn "$binary: skipped (go not found)"
    continue
  fi

  info "Installing $binary ..."
  if [[ $DRY_RUN -eq 0 ]]; then
    as_user "'$GO_BIN' install '$pkg'" \
      && ok "$binary" \
      || warn "$binary install failed (non-fatal)"
  else
    echo -e "  ${YELLOW}DRY-RUN:${RESET} go install $pkg"
  fi
done

# =============================================================================
# STEP 5 — Cargo-based tools
# =============================================================================
step "Cargo-based tools"

if command -v feroxbuster &>/dev/null || [[ -f "$CARGO_BIN/feroxbuster" ]]; then
  ok "feroxbuster: already installed"
elif [[ -z "$CARGO_CMD" ]]; then
  warn "feroxbuster: skipped (cargo not available)"
else
  info "Installing feroxbuster (this takes a few minutes) ..."
  if [[ $DRY_RUN -eq 0 ]]; then
    as_user "'$CARGO_CMD' install feroxbuster" \
      && ok "feroxbuster" \
      || warn "feroxbuster install failed (non-fatal)"
  else
    echo -e "  ${YELLOW}DRY-RUN:${RESET} cargo install feroxbuster"
  fi
fi

# =============================================================================
# STEP 6 — Python venv (bypasses Kali PEP 668 restriction)
# =============================================================================
step "Python virtual environment + Aegis"

# Fix pip cache ownership so pip doesn't complain about permissions
if [[ $DRY_RUN -eq 0 ]]; then
  mkdir -p "$PIP_CACHE"
  chown -R "$REAL_USER:$REAL_USER" "$PIP_CACHE" 2>/dev/null || true
fi

if [[ $DRY_RUN -eq 0 ]]; then
  # Create venv as root (it lives inside the project dir)
  python3 -m venv "$VENV_DIR"

  # Upgrade pip inside venv
  "$VENV_DIR/bin/pip" install --upgrade pip --quiet

  # Install Python dependencies
  "$VENV_DIR/bin/pip" install webtech mcp --quiet
  ok "webtech, mcp installed into venv"

  # Install Aegis itself
  if [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
    "$VENV_DIR/bin/pip" install -e "$SCRIPT_DIR" --quiet
    ok "Aegis installed from source"
  else
    "$VENV_DIR/bin/pip" install aegis-cli --quiet
    ok "Aegis installed from PyPI"
  fi

  # Fix venv ownership so the real user can use it
  chown -R "$REAL_USER:$REAL_USER" "$VENV_DIR" 2>/dev/null || true

  # Create system-wide wrapper scripts
  cat > /usr/local/bin/aegis << 'WRAPPER'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
VENV="$(dirname "$(dirname "$0")")"
# Find the project venv
for candidate in \
  "$HOME/Desktop/aegis/.venv/bin/aegis" \
  "/opt/aegis/.venv/bin/aegis" \
  "$(pwd)/.venv/bin/aegis"; do
  [[ -x "$candidate" ]] && exec "$candidate" "$@"
done
# Fallback: search common locations
find /home /root /opt -name "aegis" -path "*/.venv/bin/aegis" 2>/dev/null | head -1 | xargs -I{} exec {} "$@"
echo "aegis not found. Run: sudo bash install.sh" >&2; exit 1
WRAPPER
  chmod +x /usr/local/bin/aegis

  # Smarter wrapper that finds the venv relative to the script location
  AEGIS_BIN="$VENV_DIR/bin/aegis"
  cat > /usr/local/bin/aegis << WRAPPER
#!/usr/bin/env bash
exec "$AEGIS_BIN" "\$@"
WRAPPER
  chmod +x /usr/local/bin/aegis

  AEGIS_MCP_BIN="$VENV_DIR/bin/aegis-mcp"
  cat > /usr/local/bin/aegis-mcp << WRAPPER
#!/usr/bin/env bash
exec "$AEGIS_MCP_BIN" "\$@"
WRAPPER
  chmod +x /usr/local/bin/aegis-mcp

  ok "Wrappers created: /usr/local/bin/aegis  /usr/local/bin/aegis-mcp"
else
  echo -e "  ${YELLOW}DRY-RUN:${RESET} python3 -m venv $VENV_DIR"
  echo -e "  ${YELLOW}DRY-RUN:${RESET} pip install webtech mcp aegis-cli"
  echo -e "  ${YELLOW}DRY-RUN:${RESET} create /usr/local/bin/aegis wrapper"
fi

# =============================================================================
# STEP 7 — Data directories + ownership
# =============================================================================
step "Data directories"

for d in data data/logs data/reports data/screenshots data/wordlists data/tools data/secrets; do
  dryrun mkdir -p "$SCRIPT_DIR/$d"
done

if [[ $DRY_RUN -eq 0 ]]; then
  chown -R "$REAL_USER:$REAL_USER" "$SCRIPT_DIR/data" 2>/dev/null || true
fi
ok "Directories ready"

# =============================================================================
# STEP 8 — Nuclei templates
# =============================================================================
step "Nuclei templates"

if [[ $DRY_RUN -eq 0 ]]; then
  NUCLEI_BIN=""
  command -v nuclei &>/dev/null && NUCLEI_BIN="$(command -v nuclei)"
  [[ -z "$NUCLEI_BIN" && -f "$GOPATH_BIN/nuclei" ]] && NUCLEI_BIN="$GOPATH_BIN/nuclei"

  if [[ -n "$NUCLEI_BIN" ]]; then
    as_user "'$NUCLEI_BIN' -update-templates -silent" \
      && ok "Nuclei templates updated" \
      || warn "Template update failed (non-fatal)"
  else
    warn "nuclei not found — skipping template update"
  fi
else
  echo -e "  ${YELLOW}DRY-RUN:${RESET} nuclei -update-templates"
fi

# =============================================================================
# STEP 9 — Shell PATH
# =============================================================================
step "Shell PATH for $REAL_USER"

PATH_BLOCK="
# ── Aegis tool paths ──────────────────────────────────────────────────────────
export GOPATH=\"$GOPATH_DIR\"
export PATH=\"\$PATH:$GOPATH_BIN:$CARGO_BIN\"
# ─────────────────────────────────────────────────────────────────────────────
"

for rc in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
  if [[ -f "$rc" ]] && ! grep -q "Aegis tool paths" "$rc"; then
    echo "$PATH_BLOCK" >> "$rc"
    chown "$REAL_USER:$REAL_USER" "$rc" 2>/dev/null || true
    ok "Updated $rc"
  elif [[ -f "$rc" ]]; then
    ok "$rc: already configured"
  fi
done

# =============================================================================
# FINAL — Validation
# =============================================================================
step "Validation"

PASS=0; FAIL=0
check() {
  local name="$1"; shift
  if "$@" &>/dev/null 2>&1; then
    ok "$name"
    ((PASS++)) || true
  else
    warn "$name: not found (may need new terminal)"
    ((FAIL++)) || true
  fi
}

check "nmap"         command -v nmap
check "sqlmap"       command -v sqlmap
check "whatweb"      command -v whatweb
check "nikto"        command -v nikto
check "ffuf"         command -v ffuf
check "go"           bash -c "command -v go || [[ -x /usr/local/go/bin/go ]]"
check "cargo"        bash -c "command -v cargo || [[ -x '$CARGO_BIN/cargo' ]]"
check "subfinder"    bash -c "command -v subfinder || [[ -f '$GOPATH_BIN/subfinder' ]]"
check "nuclei"       bash -c "command -v nuclei    || [[ -f '$GOPATH_BIN/nuclei' ]]"
check "trufflehog"   bash -c "command -v trufflehog || [[ -f '$GOPATH_BIN/trufflehog' ]]"
check "gowitness"    bash -c "command -v gowitness  || [[ -f '$GOPATH_BIN/gowitness' ]]"
check "feroxbuster"  bash -c "command -v feroxbuster || [[ -f '$CARGO_BIN/feroxbuster' ]]"
check "webtech"      test -f "$VENV_DIR/bin/webtech"
check "aegis"        test -f "/usr/local/bin/aegis"
check "python venv"  test -d "$VENV_DIR"

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║        Installation Complete!            ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${GREEN}Passed: $PASS${RESET}   ${YELLOW}Warnings: $FAIL${RESET}"
echo ""
echo -e "${CYAN}Next steps:${RESET}"
echo "  1. Open a new terminal  (or: source ~/.zshrc)"
echo "  2. Edit: $SCRIPT_DIR/config/config.yaml"
echo "  3. Run:  aegis doctor"
echo "  4. Run:  aegis ai auto --target <host>"
echo ""
if [[ $FAIL -gt 0 ]]; then
  warn "$FAIL tool(s) not on PATH yet — open a new terminal and run: aegis doctor"
  echo "  Go tools  → $GOPATH_BIN"
  echo "  Cargo     → $CARGO_BIN"
  echo "  Python    → $VENV_DIR/bin/"
fi
