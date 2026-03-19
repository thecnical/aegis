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

### From source (recommended)

```bash
git clone https://github.com/thecnical/aegis.git
cd aegis
pip install -e .
```

This installs the `aegis` command globally. The `-e` flag means edits to the source are reflected immediately without reinstalling.

### From PyPI

```bash
pip install aegis-cli
```

### With development dependencies

```bash
pip install -e ".[dev]"
```

This adds pytest, hypothesis, ruff, mypy, and type stubs for local development and testing.

### First-time setup

```bash
cp config/config.yaml.example config/config.yaml
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

**Nuclei integration:** `aegis vuln web` runs Nuclei with the configured rate limit and parses its JSON-lines output. Each finding includes the template ID, severity