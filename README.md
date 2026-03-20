<div align="center">

```
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

**Aegis — AI-Augmented Offensive Security Platform**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![CI](https://github.com/thecnical/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/thecnical/aegis/actions)
[![mypy](https://img.shields.io/badge/type--checked-mypy-blue?style=flat-square)](https://mypy-lang.org)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-orange?style=flat-square)](https://github.com/astral-sh/ruff)
[![PyPI](https://img.shields.io/badge/PyPI-aegis--cli-blue?style=flat-square&logo=pypi)](https://pypi.org/project/aegis-cli/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow?style=flat-square)](https://github.com/PyCQA/bandit)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=flat-square&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

*One command. Every phase. AI-driven.*

> **Legal Notice:** Aegis is for authorized penetration testing and security research only.
> Using it against systems you do not own or have explicit written permission to test is illegal.

</div>

---

## What is Aegis?

**Aegis** (`aegis-cli` on PyPI) is a modular, AI-augmented command-line platform that unifies the complete penetration testing lifecycle into a single consistent tool. Instead of juggling a dozen separate tools with different output formats and workflows, Aegis wraps them all — Nmap, Nuclei, ffuf, testssl.sh, theHarvester, sqlmap, and more — behind one CLI with a shared database, scope enforcement, and AI-driven orchestration.

Every finding from every tool lands in the same SQLite database. Every scan runs inside a named workspace. Every result can be exported as a PDF report, a SARIF file for GitHub Code Scanning, or a JSON feed for your CI/CD pipeline.

**The headline feature:** `aegis ai auto --target <host>` — give it a target, walk away, come back to a full penetration test report.

### Who is it for?

- **Penetration testers** who want a unified workflow instead of scattered terminal windows
- **Bug bounty hunters** who need fast recon-to-report pipelines
- **Red teams** running parallel campaigns across many targets
- **Security engineers** integrating vulnerability scanning into CI/CD pipelines
- **CTF players** who want AI-assisted attack surface analysis

---

## Architecture Overview

Aegis is built around four layers that work together:

```
┌─────────────────────────────────────────────────────────────────┐
│  CLI Layer  (Click commands — main.py)                          │
│  Every command group: recon, vuln, exploit, ai, burp, cve ...   │
├─────────────────────────────────────────────────────────────────┤
│  Core Layer  (aegis/core/)                                      │
│  DatabaseManager · AIOrchestrator · CampaignRunner              │
│  BurpImporter · CVECorrelator · SARIFExporter · TemplateManager │
├─────────────────────────────────────────────────────────────────┤
│  Tools Layer  (aegis/tools/)                                    │
│  recon/ · vuln/ · exploit/ · post/ · report/                    │
│  Each tool is a Click command that writes findings to the DB    │
├─────────────────────────────────────────────────────────────────┤
│  Storage Layer  (SQLite per workspace)                          │
│  targets · hosts · ports · findings · evidence · cve_correlations│
│  scan_sessions · campaign_targets · api_tokens · scope          │
└─────────────────────────────────────────────────────────────────┘
```

**Data flow:** A tool runs → parses output → calls `db.add_finding()` → finding stored with `session_id` → AI triage reads findings → report generated → SARIF exported → CI/CD notified.

---

## Feature Matrix

| Feature | How it works |
|---|---|
| **AI Autonomous Mode** | `AIOrchestrator` runs all phases sequentially, uses the AI client to select tools per phase based on accumulated findings, generates a final report |
| **Burp Suite Import** | Parses Burp XML exports with defusedxml (XXE-safe), decodes base64 request/response bodies, stores findings + HTTP evidence in the DB |
| **CVE Correlation** | Extracts keywords from finding titles, queries NVD API v2, stores CVSS v3.1 scores and vectors per finding, respects rate limits |
| **SARIF Export** | Generates SARIF v2.1.0 with per-finding rule IDs, OWASP reference URIs, and GitHub security-severity scores |
| **Parallel Campaigns** | `asyncio.Semaphore`-based runner — each target gets its own scan session, results aggregated into a `CampaignRun` |
| **REST API** | FastAPI app with async scan jobs, paginated findings, Burp import, CVE lookup, SARIF download, scope management |
| **Workspace Isolation** | Each workspace has its own SQLite database — no cross-engagement data leakage |
| **Scope Enforcement** | `ScopeManager` checks every target before scanning; `safe_mode: true` aborts out-of-scope requests |
| **Deduplication** | SHA-256 fingerprint of `title+host+category` — duplicate findings are silently dropped |
| **CVSS Scoring** | `cvss` library computes v3.1 base scores from vectors found in tool output |
| **Notifications** | Slack and Discord webhook delivery with severity filtering |
| **Watch Mode** | Continuous polling loop — only new findings (post-dedup) trigger notifications |
| **Custom Templates** | HTML/Markdown templates with `$title`, `$generated_at`, `$findings` placeholders |
| **PDF Reports** | WeasyPrint renders HTML templates to PDF with severity filtering |

---

## Installation

### Requirements

- Python 3.10 or newer
- pip
- Git

### Kali Linux — step-by-step

**Step 1 — System dependencies**

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv git \
  libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
  libcairo2 libffi-dev libgdk-pixbuf-2.0-0
```

> Note: the correct package name on modern Kali is `libgdk-pixbuf-2.0-0` (not `libgdk-pixbuf2.0-0`).

**Step 2 — Clone and set up a virtual environment**

```bash
git clone https://github.com/thecnical/aegis.git
cd aegis
python3 -m venv .venv
source .venv/bin/activate
```

**Step 3 — Install Aegis**

```bash
pip install -e .
```

**Step 4 — Set up config and verify**

```bash
mkdir -p data/logs
# Edit config/config.yaml and add your API keys
nano config/config.yaml
aegis doctor
```

**Step 5 — Install external tools (optional)**

```bash
# Interactive — pick which tools to install
aegis install-tools

# Or install everything at once
aegis install-tools --yes
```

### From PyPI

```bash
pip install aegis-cli
```

### With development dependencies

```bash
pip install -e ".[dev]"
```

### First-time setup

```bash
# Edit config/config.yaml — add your API keys
aegis doctor
```

`aegis doctor` checks which external tools are installed and which API keys are configured. Run `aegis doctor --fix` to auto-detect tool paths and write them to config.

---

## Configuration

All settings live in `config/config.yaml`. Aegis never reads environment variables for secrets — everything is explicit in the config file.

```yaml
general:
  db_path: data/aegis.db        # root database path
  safe_mode: true               # abort if target is out of scope
  wordlists_path: data/wordlists

api_keys:
  shodan: CHANGE_ME             # https://shodan.io
  openrouter: CHANGE_ME         # https://openrouter.ai (free tier available)
  bytez: CHANGE_ME              # https://bytez.com (free tier available)
  nvd: CHANGE_ME                # https://nvd.nist.gov/developers/request-an-api-key

api:
  key: ""                       # REST API bearer token (empty = open access)

notifications:
  slack_webhook: ""             # https://api.slack.com/messaging/webhooks
  discord_webhook: ""           # Discord channel webhook URL

external_tools:
  nmap: nmap
  nuclei: nuclei
  subfinder: subfinder
  ffuf: ffuf

profiles:
  default:
    timeout: 30
    nmap_args: "-sC -sV"
    nuclei_rate: 150
  stealth:
    timeout: 120
    nmap_args: "-sS -T2 --randomize-hosts"
    nuclei_rate: 20
  aggressive:
    timeout: 10
    nmap_args: "-sS -T4"
    nuclei_rate: 300
```

**Scan profiles** let you switch between stealth and aggressive modes with `--profile stealth`. The profile controls timeouts, Nmap flags, and Nuclei rate limits.

**Global CLI flags** apply to every command:

| Flag | Default | Description |
|---|---|---|
| `--config PATH` | `config/config.yaml` | Path to config file |
| `--profile NAME` | `default` | Scan profile to use |
| `--workspace NAME` | active workspace | Override the active workspace |
| `--json` | off | Print all output as JSON |
| `--json-output FILE` | — | Write JSON output to a file |
| `--debug` | off | Enable debug logging |

---

## Workspaces

Workspaces give each engagement its own isolated SQLite database. There is no shared state between workspaces — findings, sessions, scope, and notes are all per-workspace.

**How it works internally:** The root database (`data/aegis.db`) stores a `workspaces` table with the name and path of each workspace database. When you run any command, Aegis resolves the active workspace, opens its database, and all reads/writes go there.

```bash
# Create a workspace for a new engagement
aegis workspace create client-acme

# Switch to it — all subsequent commands use this workspace
aegis workspace switch client-acme

# List all workspaces
aegis workspace list

# Delete a workspace (removes the DB entry, not the file)
aegis workspace delete old-engagement
```

You can also override the workspace for a single command without switching:

```bash
aegis --workspace client-acme recon domain acme.com
```

---

## Scope Management

Scope enforcement is one of Aegis's most important safety features. Before any tool runs against a target, `ScopeManager` checks whether the target falls within the defined scope entries.

**How it works:** Scope entries are stored in the `scope` table of the active workspace database. Each entry has a `target` (IP, CIDR, domain, or URL) and a `kind`. When `safe_mode: true` is set in config, any scan against an out-of-scope target raises an error and aborts — no tool is invoked.

```bash
# Add scope entries
aegis scope add acme.com --kind domain
aegis scope add 10.10.0.0/16 --kind cidr
aegis scope add https://api.acme.com --kind url
aegis scope add 192.168.1.5 --kind ip

# View current scope
aegis scope list

# Remove an entry by ID
aegis scope remove 3
```

With `safe_mode: true`, running `aegis recon domain evil.com` when `evil.com` is not in scope will abort with an error before any network request is made.

---

## Recon

Reconnaissance commands gather information about targets without active exploitation. All findings are stored in the active workspace database under the current scan session.

```bash
# Enumerate subdomains, DNS records, and run Nmap on discovered hosts
aegis recon domain example.com

# Scan a CIDR range with Nmap — discovers hosts, open ports, services
aegis recon network 192.168.1.0/24 --port-scan

# Query specific DNS record types
aegis recon dns example.com --types A,MX,TXT,NS,AAAA

# OSINT gathering — emails, GitHub dorks, Shodan lookups
aegis recon osint example.com --emails --github-dorks
```

**What happens under the hood:** Each recon command invokes the relevant external tool (subfinder, nmap, theHarvester), parses the output using `aegis/core/parsers.py`, and writes structured findings to the database. If a tool is not installed, the command logs a warning and continues — it never crashes.

---

## Technology Detection

`aegis recon domain` automatically detects web technologies on the target. Aegis uses **free, open-source tools** — no paid API key required.

| Tool | How to install | Notes |
|---|---|---|
| **webtech** | `pip install webtech` | Python-based, fingerprints via headers/HTML/cookies |
| **whatweb** | `sudo apt install whatweb` | Pre-installed on Kali Linux |

Aegis tries `webtech` first, then falls back to `whatweb` automatically. If neither is installed, it prints a hint and continues without crashing.

```bash
# Tech detection runs automatically with domain recon
aegis recon domain example.com

# Skip tech detection if you don't need it
aegis recon domain example.com --no-techdetect
```

To install both tools at once:

```bash
pip install webtech
sudo apt install whatweb   # already on Kali
```

> Wappalyzer was removed — its CLI requires a paid subscription. `webtech` and `whatweb` are fully free and cover the same use case.

---

## Vulnerability Scanning

Vulnerability scanning commands actively probe targets for weaknesses. They build on recon data already in the database.

```bash
# Web vulnerability scan using Nuclei templates
aegis vuln web https://example.com

# Network vulnerability scan using Nmap NSE scripts
aegis vuln net 192.168.1.1

# SSL/TLS configuration analysis using testssl.sh
aegis vuln ssl example.com --port 443

# API endpoint fuzzing using ffuf
aegis vuln api https://api.example.com --wordlist data/wordlists/api.txt
```

**Nuclei integration:** `aegis vuln web` runs Nuclei with the configured rate limit and parses its JSON-lines output. Each finding includes the template ID, severity, and matched URL, stored directly in the workspace database.

---

## Uninstalling Aegis

```bash
# Preview what will be removed (safe — makes no changes)
aegis uninstall --dry-run

# Remove Aegis and its installed tools
aegis uninstall --yes

# Also delete databases, reports, and logs
aegis uninstall --yes --remove-data

# Full clean — remove everything including config
aegis uninstall --yes --remove-data --remove-config
```

What `aegis uninstall` removes:
- The `aegis-cli` Python package
- `webtech` pip package
- Go-installed binaries (`subfinder`, `nuclei`) from `~/go/bin/`
- `feroxbuster` via `cargo uninstall`

It does **not** remove system packages installed via `apt` (nmap, sqlmap, etc.) — those are managed by your system package manager.

---

## Roadmap — What's Coming Next

These are the planned upgrades to make Aegis more powerful, based on current offensive security research trends:

### Near-term
- **LLM-assisted payload generation** — use the AI client to generate context-aware SQLi, XSS, and SSRF payloads based on discovered tech stack
- **Passive JS analysis** — extract endpoints, secrets, and API keys from JavaScript files during recon (using `trufflehog` / `gitleaks` integration)
- **Screenshot capture** — auto-screenshot discovered web services with `gowitness` and embed thumbnails in HTML reports
- **HTTP request smuggling detection** — integrate `smuggler` or `h2csmuggler` as a vuln module
- **Cloud asset discovery** — enumerate S3 buckets, Azure blobs, and GCP storage for a target domain

### Medium-term
- **Graph-based attack path visualization** — render a D3.js attack graph from findings (host → port → vuln → exploit chain)
- **Autonomous exploit chaining** — AI orchestrator selects and chains exploits based on confirmed vulnerabilities, not just suggestions
- **MCP (Model Context Protocol) server** — expose Aegis as an MCP tool so AI agents (Claude, Cursor, etc.) can drive pentests natively
- **Team collaboration mode** — shared workspace over PostgreSQL instead of per-user SQLite
- **Custom nuclei template generation** — AI writes Nuclei YAML templates for newly discovered endpoints

### Research-grade
- **Fuzzing integration** — `ffuf` + `boofuzz` for protocol-level fuzzing with finding correlation
- **Binary analysis hooks** — connect to `radare2` / `ghidra` for post-exploitation binary triage
- **Adversarial ML detection bypass** — test WAF/IDS evasion using AI-generated obfuscated payloads
- **CVE-to-PoC auto-mapping** — correlate NVD CVEs with public PoC repos (ExploitDB, GitHub) and auto-stage them

---

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

```bash
# Set up dev environment
git clone https://github.com/thecnical/aegis.git
cd aegis
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest --tb=short

# Lint and type check
ruff check .
mypy aegis/
```

---

## Support the Project

If Aegis saves you time on an engagement or helps you learn offensive security, consider buying me a coffee — it keeps the project going.

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

---

## License

MIT — see [LICENSE](LICENSE) for details.
