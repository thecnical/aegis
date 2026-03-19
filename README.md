<div align="center">

<img src="https://img.shields.io/badge/AEGIS-Offensive%20Security%20Platform-red?style=for-the-badge&logo=shield&logoColor=white" alt="Aegis"/>

```
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

**A modular, AI-augmented offensive security platform for penetration testers.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CI](https://github.com/thecnical/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/thecnical/aegis/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)](Dockerfile)
[![Security](https://img.shields.io/badge/Topic-Offensive%20Security-critical?style=flat-square)](https://github.com/thecnical/aegis)

> **Legal Disclaimer:** Aegis is intended for authorized penetration testing and security research only.
> Use against systems you do not own or have explicit written permission to test is illegal.
> The author assumes no liability for misuse.

</div>

---

## Overview

Aegis is a command-line offensive security platform that unifies the full penetration testing lifecycle — from initial reconnaissance through exploitation, post-exploitation, and professional report delivery. It wraps industry-standard tools (Nmap, Nuclei, ffuf, testssl.sh, theHarvester, and more) behind a consistent CLI with workspace isolation, scope enforcement, AI-assisted triage, and real-time webhook notifications.

**Key design principles:**
- Every scan respects a defined scope — no accidental out-of-scope testing
- Each engagement runs in an isolated workspace with its own database
- Findings are deduplicated across runs using SHA-256 fingerprinting
- All subprocess calls use list form — no `shell=True`, no injection risk
- AI prompts contain only finding metadata — never credentials or PII

---

## Capabilities

| Domain | Tools & Features |
|---|---|
| **Recon** | Domain enumeration, network scanning, subdomain brute-force, DNS records, OSINT, web screenshots |
| **Vulnerability** | Web scanning (Nuclei), network (Nmap NSE), SSL/TLS analysis (testssl.sh), API fuzzing (ffuf) |
| **Exploitation** | Local File Inclusion (LFI), Server-Side Request Forgery (SSRF) |
| **Post-Exploitation** | SMB credential harvesting |
| **AI Triage** | Finding triage, session summarization, attack surface suggestions, narrative report generation, interactive chat |
| **Reporting** | Markdown, HTML, PDF export with severity filtering |
| **Notifications** | Slack and Discord webhooks with per-severity filtering |
| **Monitoring** | Continuous watch mode with deduplication — only new findings trigger alerts |
| **Workspaces** | Isolated SQLite database per engagement |
| **Scope Enforcement** | IP, CIDR, domain, and URL scope with safe-mode abort |
| **Web UI** | FastAPI + htmx dashboard for findings review and report download |
| **Terminal UI** | Full Textual-based interactive TUI |
| **CVSS Scoring** | Automatic CVSS v3.1 base score assignment |


---

## Installation

### Requirements

- Python 3.10 or higher
- pip
- Git

### Install from source

```bash
git clone https://github.com/thecnical/aegis.git
cd aegis
pip install -e .
```

### Verify

```bash
aegis --help
aegis doctor
```

### Install with development dependencies

```bash
pip install -e ".[dev]"
```

---

## Configuration

All settings live in `config/config.yaml`. The file ships with safe placeholder values — replace them with your own.

```yaml
general:
  db_path: data/aegis.db
  safe_mode: true        # Abort scans targeting out-of-scope hosts

api_keys:
  shodan: CHANGE_ME
  openrouter: CHANGE_ME
  bytez: CHANGE_ME

notifications:
  slack_webhook: ""
  discord_webhook: ""

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
    nmap_args: "-sS"
    nuclei_rate: 300

external_tools:
  nmap: nmap
  nuclei: nuclei
  subfinder: subfinder
  amass: amass
  ffuf: ffuf
  testssl: testssl.sh
  gowitness: gowitness
  theHarvester: theHarvester
  feroxbuster: feroxbuster
  nikto: nikto
  smbclient: smbclient
```

**Global CLI flags** (available on every command):

| Flag | Default | Description |
|---|---|---|
| `--config PATH` | `config/config.yaml` | Config file path |
| `--profile NAME` | `default` | Scan profile |
| `--workspace NAME` | active workspace | Override workspace for this invocation |
| `--log-file PATH` | `data/logs/aegis.log` | Log output path |
| `--debug` | off | Enable debug logging |
| `--json` | off | Output results as JSON |
| `--json-output PATH` | — | Write JSON output to file |

---

## External Tools

Install these tools to unlock full functionality. Aegis degrades gracefully when a tool is missing — it prints a warning and skips that step.

| Tool | Purpose | Install |
|---|---|---|
| [nmap](https://nmap.org) | Network/port scanning | `apt install nmap` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Web vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [amass](https://github.com/owasp-amass/amass) | Subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
| [ffuf](https://github.com/ffuf/ffuf) | Web/API fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| [testssl.sh](https://testssl.sh) | SSL/TLS analysis | `git clone https://github.com/drwetter/testssl.sh` |
| [gowitness](https://github.com/sensepost/gowitness) | Web screenshots | `go install github.com/sensepost/gowitness@latest` |
| [theHarvester](https://github.com/laramies/theHarvester) | OSINT collection | `pip install theHarvester` |
| [feroxbuster](https://github.com/epi052/feroxbuster) | Directory brute-force | `cargo install feroxbuster` |
| [nikto](https://github.com/sullo/nikto) | Web server scanning | `apt install nikto` |
| [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) | SMB enumeration | `apt install smbclient` |

After installing, run `aegis setup --yes` or `aegis doctor --fix` to auto-detect paths.


---

## Command Reference

### `aegis doctor`

Validate your environment — checks external tool paths and API key configuration.

```bash
aegis doctor                 # Show status of all tools and keys
aegis doctor --fix           # Auto-detect tool paths and update config
aegis doctor --fix --force   # Force re-detection of all tools
```

---

### `aegis setup`

Install external tool dependencies.

```bash
aegis setup                  # Interactive install
aegis setup --yes            # Non-interactive
aegis setup --dry-run        # Preview only
aegis setup --peas           # Include PEAS privilege escalation scripts
aegis setup --fix-config     # Update config paths after install
```

---

### `aegis install-tools`

Interactive per-tool installer. Prompts yes/no for each external tool before installing.

```bash
aegis install-tools                  # Interactive: prompt for each tool
aegis install-tools --yes            # Non-interactive: install all without prompts
aegis install-tools --dry-run        # Preview install commands without executing
aegis install-tools --peas           # Include PEAS privilege escalation scripts
```

| Flag | Description |
|---|---|
| `--yes` | Skip all prompts and install all tools non-interactively |
| `--dry-run` | Print each tool's install command without executing; marks outcome as `dry-run` |
| `--peas` | Include linpeas/winpeas in the install plan |

If the host OS is not Linux, the command prints an error and exits. If a tool's prerequisite binary (`go`, `cargo`, `npm`) is not on PATH, that tool is skipped with a warning.

---

### `aegis update`

Update Nuclei templates and wordlists.

```bash
aegis update --nuclei        # Update Nuclei templates
aegis update --wordlists     # Update wordlists
aegis update --all           # Update everything
aegis update --status        # Show current wordlist status
```

---

### `aegis workspace`

Manage isolated engagement workspaces. Each workspace has its own SQLite database at `data/workspaces/<name>/aegis.db`.

```bash
aegis workspace create NAME  # Create a new workspace
aegis workspace switch NAME  # Set the active workspace
aegis workspace list         # List all workspaces
aegis workspace delete NAME  # Delete a workspace and all its data
```

---

### `aegis scope`

Define the engagement scope. With `safe_mode: true`, any command targeting an out-of-scope host aborts immediately.

```bash
aegis scope add TARGET --kind KIND   # Add a scope entry
aegis scope remove ID                # Remove by ID
aegis scope list                     # List all entries
```

Supported kinds: `ip`, `cidr`, `domain`, `url`

```bash
aegis scope add 10.0.0.0/8 --kind cidr
aegis scope add example.com --kind domain
aegis scope add 192.168.1.5 --kind ip
aegis scope list
aegis scope remove 3
```

---

### `aegis run`

Execute a full recon + vuln pipeline in one command.

```bash
aegis run --domain example.com
aegis run --cidr 192.168.1.0/24
aegis run --url https://example.com
aegis run --target-ip 10.0.0.1
aegis run --domain example.com --full              # Include report generation
aegis run --domain example.com --full --report-target example
```

---

### `aegis recon`

Information gathering.

```bash
# Domain enumeration (Subfinder + Amass + Shodan)
aegis recon domain example.com

# Network scan (Nmap)
aegis recon network 192.168.1.0/24

# Subdomain brute-force
aegis recon subdomain example.com

# DNS records (dnspython — no external tool required)
aegis recon dns example.com
aegis recon dns example.com --types A,MX,TXT,NS,CNAME

# OSINT (theHarvester)
aegis recon osint example.com
aegis recon osint example.com --emails --github-dorks

# Web screenshots (gowitness)
aegis recon screenshots https://example.com
```

---

### `aegis vuln`

Vulnerability scanning.

```bash
# Web vulnerabilities (Nuclei)
aegis vuln web https://example.com

# Network vulnerabilities (Nmap NSE)
aegis vuln net 192.168.1.1

# SSL/TLS analysis (testssl.sh)
aegis vuln ssl example.com
aegis vuln ssl example.com --port 8443

# API endpoint fuzzing (ffuf)
aegis vuln api https://api.example.com --wordlist data/wordlists/api.txt
```

---

### `aegis exploit`

Exploitation modules. All commands validate scope before executing.

```bash
# Local File Inclusion
aegis exploit lfi "https://example.com/page" --param file

# Server-Side Request Forgery
aegis exploit ssrf "https://example.com/fetch" --callback https://your-collaborator.net
```

---

### `aegis post`

Post-exploitation. All commands validate scope before executing.

```bash
# SMB credential harvesting
aegis post creds --target 192.168.1.10
```

---

### `aegis report`

Generate and export findings reports.

```bash
aegis report generate example.com                          # Markdown (default)
aegis report generate example.com --format html
aegis report generate example.com --format pdf
aegis report generate example.com --format pdf --min-severity high

aegis report export --format csv
aegis report export --format json --output data/exports/findings.json
```

Severity levels: `info` → `low` → `medium` → `high` → `critical`

---

### `aegis notes`

Annotate findings with free-text notes.

```bash
aegis notes add 42 "Confirmed exploitable — needs immediate patch"
aegis notes list 42
```

---

### `aegis tag`

Tag findings for triage workflow.

```bash
aegis tag add 42 confirmed
aegis tag add 43 false-positive
aegis tag add 42 needs-retest
aegis tag list 42
aegis tag remove 42 needs-retest
```

---

### `aegis ai`

AI-assisted analysis. Requires an API key configured in `config/config.yaml`.

```bash
aegis ai triage                          # Triage all findings with remediation advice
aegis ai triage --session 3              # Triage a specific session
aegis ai summarize --session 3           # Summarize a session
aegis ai suggest --target example.com   # Attack surface suggestions
aegis ai report --target example.com    # Generate narrative report section
aegis ai chat                            # Interactive chat about findings
```

#### `aegis ai auto` — Autonomous Mode

Run a fully automated pentest from a single target. Aegis selects tools per phase using AI, stores all findings in a named session, and generates a final report.

```bash
aegis ai auto --target example.com                          # Recon + vuln phases
aegis ai auto --target example.com --full                   # All 5 phases
aegis ai auto --target example.com --format html            # HTML report
aegis ai auto --target example.com --min-severity medium    # Filter report by severity
aegis ai auto --target example.com --dry-run                # Preview tool invocations
```

| Flag | Description |
|---|---|
| `--target TARGET` | Target host, IP, or CIDR (required) |
| `--full` | Run all 5 phases: recon, vuln scanning, exploitation, post-exploitation, reporting |
| `--format md\|html\|pdf` | Report output format (default: `md`) |
| `--min-severity LEVEL` | Include only findings at or above this severity in the final report |
| `--dry-run` | Print planned tool invocations per phase without executing |

Phases run in order: **recon → vuln scanning → exploitation → post-exploitation → reporting**. Without `--full`, only recon and vuln scanning run. All findings are stored in a named session in the database. The final report file path is printed on completion.

---

### `aegis notify`

Send findings to Slack and/or Discord.

```bash
aegis notify test                                          # Test both channels
aegis notify test --channel slack
aegis notify send --session 1 --min-severity high
aegis notify send --session 1 --channel slack --min-severity critical
```

Configure webhooks in `config/config.yaml`:

```yaml
notifications:
  slack_webhook: https://hooks.slack.com/services/...
  discord_webhook: https://discord.com/api/webhooks/...
```

---

### `aegis watch`

Continuous monitoring — re-scans in-scope targets on a schedule and alerts only on new findings.

```bash
aegis watch                                          # Default: 1 hour interval
aegis watch --interval 1800 --min-severity medium
aegis watch --interval 3600 --notify slack
aegis watch --interval 3600 --notify both --min-severity high
```

Stop with `Ctrl+C`.

---

### `aegis timeline`

View scan session history.

```bash
aegis timeline
aegis timeline --limit 20
```

---

### `aegis compare`

Diff findings between two scan sessions.

```bash
aegis compare 1 2
```

Output shows: `NEW` / `RESOLVED` / `PERSISTING` findings.

---

### `aegis campaign`

Manage multi-run scan campaigns for tracking remediation over time.

```bash
aegis campaign create acme-q4 --domain acme.com
aegis campaign list
aegis campaign run acme-q4 --full
aegis campaign diff acme-q4
aegis campaign report acme-q4
```

---

### `aegis serve`

Launch the web-based findings dashboard.

```bash
aegis serve                              # http://127.0.0.1:8080
aegis serve --host 0.0.0.0 --port 9090
```

| Route | Description |
|---|---|
| `GET /` | Dashboard — finding counts by severity |
| `GET /findings` | Paginated findings table |
| `GET /findings/{id}` | Finding detail with notes and tags |
| `GET /sessions` | Scan session timeline |
| `POST /findings/{id}/notes` | Add a note |
| `GET /report/{target}` | Download report |

> Binds to `127.0.0.1` by default. Use `--host 0.0.0.0` only when remote access is required.

---

### `aegis interactive`

Launch the full terminal UI.

```bash
aegis interactive
```

Keybindings: `↑↓` navigate · `Enter` view detail · `R` refresh · `Q` quit

---

### `aegis plugins`

List all auto-discovered tool plugins.

```bash
aegis plugins
```


---

## Typical Engagement Workflow

```bash
# 1. Create an isolated workspace for the engagement
aegis workspace create client-acme
aegis workspace switch client-acme

# 2. Define scope
aegis scope add acme.com --kind domain
aegis scope add 10.10.0.0/16 --kind cidr

# 3. Reconnaissance
aegis recon domain acme.com
aegis recon dns acme.com
aegis recon osint acme.com --emails

# 4. Vulnerability scanning
aegis vuln web https://acme.com
aegis vuln ssl acme.com
aegis vuln api https://api.acme.com --wordlist data/wordlists/api.txt

# 5. AI-assisted triage
aegis ai triage
aegis ai suggest --target acme.com

# 6. Annotate findings
aegis tag add 1 confirmed
aegis notes add 1 "Exploitable via unauthenticated endpoint — CVE-XXXX-XXXX"

# 7. Generate deliverable
aegis report generate acme.com --format pdf --min-severity medium

# 8. Notify the team
aegis notify send --session 1 --min-severity high --channel slack

# 9. Track remediation across re-tests
aegis compare 1 2
```

---

## Docker

```bash
# Build
docker build -t aegis .

# Run a scan
docker run --rm -it \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  aegis recon domain example.com

# Run the web UI
docker run --rm -it \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  aegis serve --host 0.0.0.0 --port 8080
```

---

## Testing

```bash
# Run the full test suite
pytest

# With coverage report
pytest --cov=aegis --cov-report=term-missing

# Unit tests only
pytest tests/ --ignore=tests/integration

# Specific module
pytest tests/test_scope_manager.py -v
```

The test suite includes unit tests, property-based tests (Hypothesis), and CLI integration tests.

---

## Security

- API keys and webhook URLs are stored in `config/config.yaml` only — never logged or transmitted in AI prompts
- `safe_mode: true` prevents accidental scanning of out-of-scope targets
- All external tool invocations use list-form subprocess calls — no `shell=True`
- The web UI binds to `127.0.0.1` by default
- AI prompts contain only finding metadata (title, severity, description) — never raw credentials or session data

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

Built by **[Chandan Pandey](https://github.com/thecnical)**

If this tool saves you time on an engagement, consider buying me a coffee.

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/chandanpandit)

</div>
