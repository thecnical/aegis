<div align="center">

```
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

### AI-Augmented Offensive Security Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![CI](https://github.com/thecnical/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/thecnical/aegis/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![mypy](https://img.shields.io/badge/type--checked-mypy-blue?style=flat-square)](https://mypy-lang.org)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-orange?style=flat-square)](https://github.com/astral-sh/ruff)

*One command. Every phase. AI-driven.*

> **Legal Notice:** For authorized penetration testing and security research only.
> Use against systems you do not own or have explicit written permission to test is illegal.

</div>

---

## What is Aegis?

Aegis is a modular CLI platform that unifies the full penetration testing lifecycle — recon, vulnerability scanning, exploitation, post-exploitation, and reporting — behind a single consistent interface. It wraps industry-standard tools (Nmap, Nuclei, ffuf, testssl.sh, theHarvester, and more) and adds AI-driven orchestration, workspace isolation, scope enforcement, deduplication, and real-time notifications.

**The headline feature:** `aegis ai auto --target <host>` — give it a target, walk away, come back to a full report.

---

## Feature Highlights

```
┌─────────────────────────────────────────────────────────────────┐
│  🤖  AI Autonomous Mode   — full pentest from one command       │
│  🗂️  Workspace Isolation  — separate DB per engagement          │
│  🎯  Scope Enforcement    — safe-mode abort for out-of-scope    │
│  🔁  Deduplication        — SHA-256 fingerprinting, no noise    │
│  📊  CVSS v3.1 Scoring    — automatic severity assignment       │
│  🌐  Web UI               — FastAPI + htmx findings dashboard   │
│  🖥️  Terminal UI          — full Textual TUI                    │
│  🔔  Notifications        — Slack & Discord webhooks            │
│  👁️  Watch Mode           — continuous monitoring, new-only     │
│  📄  PDF Reports          — Markdown / HTML / PDF export        │
└─────────────────────────────────────────────────────────────────┘
```

| Domain | Capabilities |
|---|---|
| **Recon** | Domain enum, network scan, subdomain brute-force, DNS records, OSINT, screenshots |
| **Vuln** | Web (Nuclei), network (Nmap NSE), SSL/TLS (testssl.sh), API fuzzing (ffuf) |
| **Exploit** | LFI, SSRF |
| **Post** | SMB credential harvesting |
| **AI** | Triage, summarize, suggest, report, chat, **autonomous orchestration** |
| **Reporting** | Markdown, HTML, PDF with severity filtering |

---

## Quick Start

```bash
git clone https://github.com/thecnical/aegis.git
cd aegis
pip install -e .
cp config/config.yaml.example config/config.yaml   # add your API keys
aegis doctor
```

### Install external tools interactively

```bash
aegis install-tools          # prompts yes/no for each tool
aegis install-tools --yes    # install all without prompts
aegis install-tools --dry-run
```

### Run your first scan

```bash
# Scoped recon
aegis workspace create client-acme
aegis scope add acme.com --kind domain
aegis recon domain acme.com

# Full autonomous pentest (AI picks the tools)
aegis ai auto --target acme.com --full --format pdf
```

---

## AI Autonomous Mode

The most powerful feature in Aegis. Provide a target — the AI orchestrates every phase.

```bash
aegis ai auto --target example.com                       # recon + vuln
aegis ai auto --target example.com --full                # all 5 phases
aegis ai auto --target example.com --full --format pdf   # PDF report
aegis ai auto --target example.com --min-severity high   # filter report
aegis ai auto --target example.com --dry-run             # preview only
```

**How it works:**

```
Target ──► Scope Check ──► Recon ──► Vuln Scan ──► Exploit ──► Post ──► Report
                              ▲           ▲
                         AI selects   AI selects
                          tools        tools
                         based on     based on
                         target        findings
```

- AI selects which tools to run per phase based on accumulated findings
- All findings stored in a named session in SQLite
- Final report generated in Markdown, HTML, or PDF
- Scope enforcement — aborts if target is out of scope and `safe_mode: true`
- Missing tools are skipped gracefully with a warning

Configure AI providers in `config/config.yaml`:

```yaml
api_keys:
  openrouter: YOUR_KEY   # https://openrouter.ai (free tier available)
  bytez: YOUR_KEY        # https://bytez.com (free tier available)
```

---

## Installation

### Requirements

- Python 3.10+
- pip
- Git
- Linux (for `aegis install-tools` — other OS works for everything else)

### From source

```bash
git clone https://github.com/thecnical/aegis.git
cd aegis
pip install -e .
```

### With dev dependencies

```bash
pip install -e ".[dev]"
```

### Docker

```bash
docker build -t aegis .

# Run a scan
docker run --rm -it \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  aegis recon domain example.com

# Web UI
docker run --rm -it -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  aegis serve --host 0.0.0.0
```

---

## Configuration

`config/config.yaml` — all settings in one place.

```yaml
general:
  db_path: data/aegis.db
  safe_mode: true          # abort scans on out-of-scope targets

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
```

**Global flags** (every command):

| Flag | Default | Description |
|---|---|---|
| `--config PATH` | `config/config.yaml` | Config file |
| `--profile NAME` | `default` | Scan profile |
| `--workspace NAME` | active | Override workspace |
| `--json` | off | JSON output |
| `--debug` | off | Debug logging |

---

## External Tools

Aegis degrades gracefully — missing tools are skipped with a warning.

| Tool | Purpose | Install |
|---|---|---|
| [nmap](https://nmap.org) | Port scanning | `apt install nmap` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Web vuln scanning | `go install ...nuclei@latest` |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enum | `go install ...subfinder@latest` |
| [ffuf](https://github.com/ffuf/ffuf) | API/web fuzzing | `go install ...ffuf@latest` |
| [testssl.sh](https://testssl.sh) | SSL/TLS analysis | `git clone ...testssl.sh` |
| [theHarvester](https://github.com/laramies/theHarvester) | OSINT | `pip install theHarvester` |
| [feroxbuster](https://github.com/epi052/feroxbuster) | Dir brute-force | `cargo install feroxbuster` |
| [gowitness](https://github.com/sensepost/gowitness) | Screenshots | `go install ...gowitness@latest` |
| [smbclient](https://www.samba.org) | SMB enum | `apt install smbclient` |
| [sqlmap](https://sqlmap.org) | SQL injection | `apt install sqlmap` |
| [hydra](https://github.com/vanhauser-thc/thc-hydra) | Brute-force | `apt install hydra` |

```bash
aegis install-tools          # interactive installer
aegis doctor --fix           # auto-detect installed tools
```

---

## Command Reference

### Workspace & Scope

```bash
aegis workspace create NAME
aegis workspace switch NAME
aegis workspace list
aegis workspace delete NAME

aegis scope add 10.0.0.0/8 --kind cidr
aegis scope add example.com --kind domain
aegis scope list
aegis scope remove 3
```

### Recon

```bash
aegis recon domain example.com
aegis recon network 192.168.1.0/24 --port-scan
aegis recon dns example.com --types A,MX,TXT,NS
aegis recon osint example.com --emails --github-dorks
```

### Vulnerability Scanning

```bash
aegis vuln web https://example.com
aegis vuln net 192.168.1.1
aegis vuln ssl example.com --port 443
aegis vuln api https://api.example.com --wordlist data/wordlists/api.txt
```

### Exploitation

```bash
aegis exploit lfi "https://example.com/page" --param file
aegis exploit ssrf "https://example.com/fetch" --callback https://collab.net
```

### AI

```bash
aegis ai auto --target example.com --full --format pdf
aegis ai triage --session 3
aegis ai summarize --session 3
aegis ai suggest --target example.com
aegis ai report --target example.com --format html
aegis ai chat
```

### Reporting & Export

```bash
aegis report generate example.com --format pdf --min-severity medium
aegis report export json --table findings
```

### Findings Management

```bash
aegis notes add 42 "Confirmed exploitable"
aegis tag add 42 confirmed
aegis tag add 43 false-positive
aegis timeline --limit 20
aegis compare 1 2
```

### Monitoring & Notifications

```bash
aegis watch --interval 1800 --min-severity medium --notify slack
aegis notify send --session 1 --min-severity high
aegis notify test --channel discord
```

### UI

```bash
aegis serve                  # web UI at http://127.0.0.1:8080
aegis interactive            # Textual TUI
```

---

## Typical Engagement Workflow

```bash
# 1. Workspace + scope
aegis workspace create client-acme
aegis workspace switch client-acme
aegis scope add acme.com --kind domain
aegis scope add 10.10.0.0/16 --kind cidr

# 2. Recon
aegis recon domain acme.com
aegis recon dns acme.com
aegis recon osint acme.com --emails

# 3. Vuln scanning
aegis vuln web https://acme.com
aegis vuln ssl acme.com

# 4. AI triage
aegis ai triage
aegis ai suggest --target acme.com

# 5. Annotate
aegis tag add 1 confirmed
aegis notes add 1 "Exploitable via unauthenticated endpoint"

# 6. Report
aegis report generate acme.com --format pdf --min-severity medium

# 7. Notify
aegis notify send --session 1 --min-severity high --channel slack

# 8. Re-test diff
aegis compare 1 2
```

Or skip all of that:

```bash
aegis ai auto --target acme.com --full --format pdf
```

---

## Testing

```bash
pytest                                          # full suite
pytest --cov=aegis --cov-report=term-missing   # with coverage
pytest tests/ --ignore=tests/integration       # unit only
pytest tests/test_properties.py -v             # property-based tests
```

The suite includes unit tests, property-based tests (Hypothesis), and CLI integration tests.

---

## Roadmap

Things that would make Aegis even better — contributions welcome:

- [ ] **Burp Suite integration** — import findings from Burp XML exports
- [ ] **Metasploit bridge** — trigger MSF modules from the CLI
- [ ] **CVE correlation** — auto-link findings to CVE database
- [ ] **Multi-target campaigns** — parallel scans across target lists
- [ ] **Report templates** — custom branded PDF templates
- [ ] **Plugin marketplace** — community tool wrappers
- [ ] **REST API** — headless operation for CI/CD pipelines
- [ ] **SARIF export** — integrate with GitHub Code Scanning
- [ ] **Scheduled scans** — cron-based watch mode
- [ ] **Team collaboration** — shared workspace over network DB

---

## Security

- API keys stored in `config/config.yaml` only — never logged or sent in AI prompts
- `safe_mode: true` prevents accidental out-of-scope scanning
- All subprocess calls use list form — no `shell=True`, no injection risk
- Web UI binds to `127.0.0.1` by default
- AI prompts contain only finding metadata — never credentials or raw session data
- Full mypy type checking — zero type errors across 51 source files

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

Built by **[Chandan Pandey](https://github.com/thecnical)**

[![GitHub stars](https://img.shields.io/github/stars/thecnical/aegis?style=social)](https://github.com/thecnical/aegis/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/thecnical/aegis?style=social)](https://github.com/thecnical/aegis/network/members)

If Aegis saves you time on an engagement, a ⭐ goes a long way.

</div>
