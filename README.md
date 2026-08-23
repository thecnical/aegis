# ⚔ AEGIS-DEVIN v3.0.0

### AI-Driven Autonomous Penetration Testing & Network Forensics Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0-brightgreen.svg)]()

> **One CLI. Every phase. Real AI. Self-Learning. Zero Cost.**

Aegis-Devin is a modular offensive security platform that combines autonomous scanning, AI-powered decision making, network forensics, self-learning intelligence, and exploit chain analysis into a single CLI tool. All AI features run on **free API providers** — no credit card required.

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [AI Integration](#ai-integration)
- [Command Reference](#command-reference)
  - [Scope Management](#scope-management)
  - [Reconnaissance](#reconnaissance)
  - [Vulnerability Scanning](#vulnerability-scanning)
  - [Exploitation](#exploitation)
  - [AI Commands](#ai-commands)
  - [MITRE ATT&CK](#mitre-attck)
  - [Exploit Chain Analysis](#exploit-chain-analysis)
  - [Network Forensics](#network-forensics)
  - [Self-Learning Engine](#self-learning-engine)
  - [Adaptive Monitoring](#adaptive-monitoring)
  - [Reporting](#reporting)
  - [CVE Correlation](#cve-correlation)
  - [Campaign Management](#campaign-management)
  - [REST API](#rest-api)
  - [Workspace Management](#workspace-management)
  - [Configuration](#configuration)
- [Scan Profiles](#scan-profiles)
- [External Tools](#external-tools)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Author](#author)

---

## Key Features

| Feature | Description |
|---------|-------------|
| **AI Autonomous Pentest** | One command runs full recon → vuln → exploit → report cycle with AI decision-making |
| **Self-Learning Engine** | Remembers targets, builds profiles, tracks tool effectiveness, detects drift between scans |
| **Exploit Chain Analysis** | Automatically connects individual vulnerabilities into multi-step attack paths |
| **MITRE ATT&CK Mapping** | Maps all findings to 82 ATT&CK techniques across 14 tactics with kill chain visualization |
| **Network Forensics** | Deep PCAP analysis with C2 beacon detection, DNS tunneling, exfiltration heuristics |
| **Anomaly Detection** | Statistical baseline modeling with Z-score deviation, port scan detection, ARP spoofing |
| **Passive OSINT** | Certificate Transparency, Wayback Machine, favicon hashing, JS endpoint extraction |
| **Adaptive Monitoring** | Self-tuning continuous scanner that adapts frequency based on target volatility |
| **Multi-Provider AI** | Automatic fallback across Groq, NVIDIA NIM, LLM7, Cloudflare, Bytez, OpenRouter |
| **REST API** | FastAPI server for CI/CD integration with rate limiting and auth |
| **SARIF Export** | GitHub Code Scanning integration |
| **Evidence Chain** | SHA-256 + BLAKE3 tamper-evident hash chain for forensic captures |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AEGIS CLI (Click)                         │
├──────────┬──────────┬──────────┬──────────┬─────────┬──────────┤
│  Recon   │   Vuln   │ Exploit  │   Post   │   AI    │Forensics │
│          │          │          │          │         │          │
│ dns      │ web      │ web      │ shell    │ auto    │ capture  │
│ network  │ ssl      │ lfi      │ creds    │ triage  │ analyze  │
│ domain   │ api      │ ssrf     │ pivoting │ suggest │ dns      │
│ cloud    │ smuggling│ oob      │          │ report  │ anomalies│
│ osint    │ net      │ msf      │          │ chat    │ sessions │
│ ad       │          │ net      │          │ doctor  │ creds    │
│ secrets  │          │          │          │         │ verify   │
│ screenshot│         │          │          │         │          │
├──────────┴──────────┴──────────┴──────────┴─────────┴──────────┤
│                        CORE ENGINE                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ AI Client│ │ Learning │ │ Workflow │ │ Exploit Chains   │   │
│  │ (6 LLMs) │ │ Engine   │ │ Engine   │ │ (13 templates)   │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ MITRE    │ │ Adaptive │ │ Signal   │ │ CVE Correlator   │   │
│  │ ATT&CK   │ │ Monitor  │ │ Quality  │ │ (NVD API v2)     │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  Database (SQLite/PostgreSQL) │ Config (YAML) │ Reports (MD/HTML/PDF)│
└─────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Requirements

- Python 3.10 or higher
- pip package manager
- Linux, macOS, or Windows (WSL recommended for full tool support)

### Install from Source

```bash
git clone https://github.com/thecnical/aegis-devin.git
cd aegis-devin
pip install -e .
```

### Install from PyPI

```bash
pip install aegis-devin
```

### Install with Forensics Support

```bash
pip install aegis-devin[forensics]
```

### Verify Installation

```bash
aegis --help
aegis doctor
```

---

## Quick Start

### 1. Configure AI Keys (Free — No Credit Card)

```bash
aegis configure-keys --interactive
```

Or set individual keys:

```bash
aegis configure-keys \
  --openrouter YOUR_OPENROUTER_KEY \
  --bytez YOUR_BYTEZ_KEY
```

**Free API Key Sources:**

| Provider | URL | Speed | Registration |
|----------|-----|-------|--------------|
| Groq | https://console.groq.com | 750 tok/s | Email signup |
| NVIDIA NIM | https://build.nvidia.com | 100+ models | Email signup |
| LLM7 | https://llm7.io | Good | **No registration needed** |
| OpenRouter | https://openrouter.ai/keys | Many models | Email signup |
| Bytez | https://bytez.com | Good | Email signup |

> LLM7 works without any API key. Aegis automatically falls back through providers.

### 2. Validate Setup

```bash
aegis ai doctor --strict
```

### 3. Add Target and Scan

```bash
aegis scope add example.com
aegis ai auto --target example.com
```

---

## AI Integration

### How AI Works in Aegis

Aegis uses Large Language Models (LLMs) via free API providers for intelligent decision-making. The AI does NOT do the scanning — external tools (nmap, nuclei, sqlmap) do the actual work. The AI helps with:

| Function | What AI Does | Example |
|----------|-------------|---------|
| **Tool Selection** | Analyzes discovered services, recommends which tools to run | "I see Apache 2.4.49 — run nuclei with CVE-2021-41773 template" |
| **Next-Action Planning** | Based on findings so far, suggests what to try next | "SQL injection found — try to extract credentials" |
| **Payload Generation** | Writes targeted attack payloads for discovered endpoints | Generates XSS/SQLi/SSRF payloads tailored to the target |
| **Finding Triage** | Prioritizes vulnerabilities, explains risk in plain English | "This SQLi is critical because it leads to full DB access" |
| **Executive Summary** | Writes professional pentest report narrative | Full paragraph-style executive summary |
| **Interactive Chat** | Answers questions about scan results | "Which findings should I fix first?" |

### Provider Fallback Chain

```
Request → Groq (fastest) → NVIDIA NIM → LLM7 (no key) → Cloudflare → Bytez → OpenRouter
           ↓ if fails        ↓ if fails     ↓ if fails      ↓ if fails    ↓ if fails
         (next provider)   (next provider) (next provider) (next provider) (error)
```

### Task-Specific Model Selection

Different tasks use different models optimized for that purpose:

- **Triage/Suggest:** Llama 3.3 70B (needs reasoning)
- **Summarize:** Llama 3.1 8B (fast, simple task)
- **Report:** Llama 3.3 70B (needs quality writing)
- **Chat:** Llama 3.3 70B (conversational)
- **Forensics:** Nemotron 70B (analytical reasoning)

### Using AI Without External Tools

Even without nmap/nuclei installed, the AI commands still work:

```bash
# These only need AI keys, no external tools
aegis ai suggest --target example.com
aegis ai chat
aegis ai triage --session 1
aegis ai summarize --session 1
```

---

## Command Reference

### Global Options

Every command accepts these flags:

```bash
aegis --config PATH      # Config file path (default: config/config.yaml)
aegis --profile NAME     # Scan profile (default, fast, deep, stealth, web-fast, web-deep, api-deep)
aegis --workspace NAME   # Override active workspace
aegis --json             # Output all results as JSON
aegis --json-output FILE # Write JSON to file
aegis --debug            # Enable verbose debug logging
```

---

### Scope Management

Manage which targets are authorized for scanning.

```bash
# Add targets
aegis scope add example.com
aegis scope add 192.168.1.0/24
aegis scope add https://app.example.com

# List current scope
aegis scope list

# Remove target
aegis scope remove 1   # by ID from list
```

> When `safe_mode: true` in config, all scan commands validate targets against scope before executing.

---

### Reconnaissance

#### DNS Enumeration

```bash
aegis recon dns example.com
```

Resolves A, MX, TXT, NS, CNAME records using dnspython. No external tools needed.

**Output:** Table with record types and values.

#### Network Scan

```bash
aegis recon network 192.168.1.0/24
aegis recon network 10.0.0.1 --profile deep
```

Runs nmap ping sweep + port scan. Parses XML output into structured findings.

**Requires:** nmap

**Output:** Hosts, open ports, services, OS detection.

#### Domain Recon

```bash
aegis recon domain example.com
```

Combines subdomain enumeration (subfinder), technology detection (webtech), and Shodan lookup.

**Requires:** subfinder, webtech (optional: shodan CLI)

#### Cloud Asset Discovery

```bash
aegis recon cloud example.com
```

Discovers exposed S3 buckets, Azure Blob containers, and GCP Storage via DNS + HTTP probing. No API keys required.

**Output:** Found buckets with access level (public listing, access denied, not found).

#### OSINT Passive Reconnaissance

```bash
aegis recon osint example.com
aegis recon osint example.com --no-wayback
aegis recon osint example.com --js-url https://example.com/app.js
```

**100% passive — makes NO requests to the target.** Queries third-party databases:

| Source | What It Finds |
|--------|--------------|
| **Certificate Transparency** (crt.sh) | All subdomains from SSL certificates |
| **Wayback Machine** (web.archive.org) | Historical URLs categorized: APIs, admin panels, config files, backups |
| **Favicon Hash** | MurmurHash3 for Shodan infrastructure discovery |
| **Passive DNS** (HackerTarget) | Associated hosts and IPs |
| **JavaScript Analysis** | API endpoints, hardcoded secrets, emails, IPs, cloud URLs |

**Options:**
- `--no-wayback` — Skip Wayback Machine query
- `--no-crt` — Skip Certificate Transparency
- `--no-favicon` — Skip favicon hash
- `--no-dns` — Skip passive DNS
- `--js-url URL` — Analyze a JavaScript file for endpoints/secrets
- `--timeout INT` — Request timeout (default: 30s)

#### Active Directory Enumeration

```bash
aegis recon ad 10.0.0.1 --domain corp.local --username admin --password Pass123
aegis recon ad 10.0.0.1 --domain corp.local  # anonymous enumeration
```

Runs BloodHound, ldapdomaindump, and CrackMapExec for AD enumeration.

**Requires:** bloodhound-python, ldapdomaindump, crackmapexec (all optional — skips if not found)

#### Secret Scanning

```bash
aegis recon secrets /path/to/repo
aegis recon secrets https://github.com/org/repo
```

**Requires:** trufflehog

#### Screenshot

```bash
aegis recon screenshot https://example.com
```

**Requires:** gowitness

---

### Vulnerability Scanning

#### Web Vulnerability Scan

```bash
aegis vuln web https://target.com
aegis vuln web https://target.com --profile web-deep
```

Runs nuclei templates + feroxbuster directory bruting. Captures HTTP evidence for each finding.

**Requires:** nuclei, feroxbuster

**Output:** Findings table with severity, template ID, evidence.

#### SSL/TLS Analysis

```bash
aegis vuln ssl example.com
```

**Requires:** testssl.sh

#### API Fuzzing

```bash
aegis vuln api https://target.com/api
```

**Requires:** ffuf

#### HTTP Smuggling

```bash
aegis vuln smuggling https://target.com
```

Tests CL.TE, TE.CL, and TE.TE request smuggling.

---

### Exploitation

#### Web Exploitation

```bash
aegis exploit web https://target.com/search?q=test
```

Runs sqlmap (SQL injection) + reflected XSS testing.

**Requires:** sqlmap

#### Local File Inclusion

```bash
aegis exploit lfi https://target.com/page?file=about
```

Tests 9 LFI payloads (../../etc/passwd, php://filter, etc.).

#### SSRF Testing

```bash
aegis exploit ssrf https://target.com/fetch?url=
```

Tests common SSRF parameters with internal IP targets.

#### Out-of-Band Detection

```bash
aegis exploit oob https://target.com
```

SSRF/XXE detection via DNS callback (interactsh).

---

### AI Commands

#### Full Autonomous Pentest

```bash
aegis ai auto --target example.com
aegis ai auto --target example.com --full          # All phases including exploit
aegis ai auto --target example.com --dry-run       # Show plan without executing
aegis ai auto --target example.com --min-severity high  # Only report high+
```

**What happens:**
1. Runs nmap → discovers hosts, ports, services
2. AI analyzes services → selects best tools
3. Runs recommended tools → parses structured output
4. AI reviews findings → suggests next actions
5. AI generates payloads → tests them against real endpoints
6. Generates report with AI executive summary

**Duration:** 2-10 minutes depending on target size and tools installed.

#### AI Triage

```bash
aegis ai triage --session 1
aegis ai triage --target example.com
```

AI prioritizes findings with remediation advice, risk narrative, and CVSS suggestions.

#### AI Summary

```bash
aegis ai summarize --session 1
```

Generates executive summary of a scan session.

#### AI Suggestions

```bash
aegis ai suggest --target example.com
```

AI analyzes the target and suggests attack surface areas and testing approaches.

#### AI Report

```bash
aegis ai report --target example.com
```

AI writes a full pentest report narrative from findings.

#### AI Chat

```bash
aegis ai chat
```

Interactive conversation about your findings. Ask questions like:
- "Which vulnerabilities should I fix first?"
- "How can the attacker chain these findings?"
- "Write a remediation plan for the critical findings"

#### AI Doctor

```bash
aegis ai doctor
aegis ai doctor --strict   # Exit non-zero if AI not ready
```

Validates AI configuration, tests provider connectivity, shows which models are available.

---

### MITRE ATT&CK

#### Map Findings to ATT&CK

```bash
aegis mitre map
aegis mitre map --session 3
aegis mitre map --severity high
aegis mitre map --json
```

Maps all findings to MITRE ATT&CK Enterprise techniques. Shows:
- Finding → technique(s) mapping with confidence scores
- Kill chain coverage visualization (which tactics are covered)
- Coverage gaps (tactics with no observations)

**Output example:**
```
Kill Chain Coverage:
  ██████████ Reconnaissance        (4 techniques)
  ░░░░░░░░░░ Resource Development  (0 techniques)  ← GAP
  ████████░░ Initial Access        (3 techniques)
  ████░░░░░░ Execution             (1 technique)
  ...
```

#### Generate Attack Narrative

```bash
aegis mitre narrative
aegis mitre narrative --session 2
```

Generates a structured attack story organized by kill chain phase.

#### Browse Techniques

```bash
aegis mitre techniques
aegis mitre techniques --tactic "Credential Access"
aegis mitre techniques --search "brute"
```

Lists known ATT&CK techniques. 82 techniques across 14 tactics in the database.

---

### Exploit Chain Analysis

#### Discover Chains

```bash
aegis chains analyze
aegis chains analyze --session 3
aegis chains analyze --min-confidence 0.6
aegis chains analyze --json
```

Automatically connects individual vulnerabilities into multi-step attack paths. The engine:
1. Classifies findings by vulnerability type (17 types: sqli, xss, rce, lfi, ssrf, etc.)
2. Matches against 13 chain templates (known attack patterns)
3. Discovers implicit chains via capability graph traversal
4. Scores confidence and provides mitigations

**Example output:**
```
━━━ Chain 1: SSRF to Cloud Compromise ━━━
  Impact: CRITICAL | Confidence: 90%
  Description: SSRF allows reading cloud metadata → IAM credentials → full compromise
  Steps:
    1. [HIGH] SSRF on image proxy
       → Gains: internal_access, cloud_metadata, port_scanning
  Final Impact: Full cloud account compromise via metadata service
  Mitigations:
    • Block metadata IP in egress rules
    • Use IMDSv2 (requires token)
    • WAF SSRF rules
```

#### Generate Chain Report

```bash
aegis chains report
aegis chains report --session 2
```

Generates detailed Markdown report of all discovered exploit chains.

---

### Network Forensics

#### Deep PCAP Analysis

```bash
aegis forensics analyze capture.pcap
aegis forensics analyze capture.pcap --timeline-output timeline.json
aegis forensics analyze capture.pcap --json
```

Comprehensive analysis including:
- C2 beacon detection (scoring based on interval regularity, jitter, payload consistency)
- DNS tunneling detection (entropy analysis, subdomain length, query frequency)
- DGA domain detection (high entropy + unusual length)
- Fast-flux network detection (single domain → many IPs)
- Data exfiltration heuristics (volume, unusual ports, DNS payload sizes)
- Session reconstruction (TCP streams, HTTP conversations)
- Timeline building for incident response

#### DNS Analysis

```bash
aegis forensics dns capture.pcap
aegis forensics dns capture.pcap --json
```

DNS-focused deep analysis:
- **Tunneling:** Detects encoded data in subdomain labels
- **DGA:** Identifies algorithmically generated domains
- **Fast-flux:** Finds domains resolving to many IPs
- **Statistics:** Top queried domains, query patterns

#### Anomaly Detection

```bash
aegis forensics anomalies capture.pcap
aegis forensics anomalies capture.pcap --z-threshold 2.5
aegis forensics anomalies capture.pcap --port-scan-threshold 15
aegis forensics anomalies capture.pcap --severity high
```

Statistical anomaly detection using Welford's online algorithm (O(1) memory):

| Detection | Method |
|-----------|--------|
| Volume spike | Z-score on payload sizes per source |
| Rate spike | Z-score on packets-per-second per source |
| Port scan | Track unique dst_ports per (src, dst) pair in time window |
| Horizontal scan | Track unique dst_hosts per (src, port) pair |
| High-entropy payload | Shannon entropy > 7.5 (encrypted C2) |
| ICMP flood | Rate > 100 pps from single source |
| ICMP tunnel | ICMP payload > 128 bytes (normal ping is 32-64) |
| ARP spoofing | MAC address change for known IP |
| TTL anomaly | Significant TTL deviation (possible MITM) |
| Slowloris | Many long-lived HTTP connections from one source |

**Options:**
- `--z-threshold FLOAT` — Z-score threshold (default: 3.0, lower = more sensitive)
- `--port-scan-threshold INT` — Ports to trigger alert (default: 20)
- `--severity CHOICE` — Filter results by severity

#### Session Extraction

```bash
aegis forensics sessions capture.pcap --protocol http
aegis forensics sessions capture.pcap --protocol dns
aegis forensics sessions capture.pcap --protocol tls
aegis forensics sessions capture.pcap --protocol all
```

Extracts and displays protocol sessions (HTTP request/response, DNS queries, TLS handshakes).

#### Credential Extraction

```bash
aegis forensics credentials capture.pcap
```

Extracts cleartext credentials from FTP, HTTP Basic Auth, and Telnet traffic.

#### Live Capture

```bash
sudo aegis forensics capture --interface eth0 --duration 300
sudo aegis forensics capture -i wlan0 -d 60 --filter "port 80 or port 443"
```

Starts live packet capture with:
- Automatic file rotation
- SHA-256 + BLAKE3 evidence chain (court-admissible integrity)
- Configurable BPF filters

**Options:**
- `--interface / -i` — Network interface (default: eth0)
- `--duration / -d` — Capture duration in seconds (default: 60)
- `--filter TEXT` — BPF filter expression
- `--output-dir PATH` — Output directory
- `--rotation INT` — File rotation interval in seconds

**Requires:** tcpdump (capture), dpkt or tshark (analysis)

#### Evidence Verification

```bash
aegis forensics verify data/forensics/captures/evidence_chain.json
```

Verifies the integrity of an evidence hash chain. Detects if any PCAP file was tampered with after capture.

---

### Self-Learning Engine

The learning engine makes Aegis smarter with every scan. It maintains a persistent knowledge base in SQLite.

#### View Status

```bash
aegis learn status
```

Shows knowledge base size: target profiles, tool effectiveness records, scan history, drift events, patterns, strategies.

#### Target Profile

```bash
aegis learn profile example.com
```

Shows everything Aegis has learned about a target:
- Technologies detected (nginx, php, wordpress, etc.)
- Open ports and services
- Server software and version
- Historical vulnerabilities (all vulns ever found)
- Patch history (vulns that were fixed between scans)
- Scan count and frequency

#### Intelligent Recommendations

```bash
aegis learn recommend example.com
```

Uses accumulated knowledge to suggest the optimal scan strategy:
- **Recommended tools:** Based on what worked for this technology stack
- **Skip tools:** Tools with low effectiveness score
- **Focus areas:** Vulns found on similar targets that this target might have
- **Drift alerts:** Unacknowledged changes since last scan
- **Confidence:** low/medium/high based on data quantity

#### Drift Detection

```bash
aegis learn drift                        # All unacknowledged drifts
aegis learn drift example.com            # Specific target
aegis learn drift example.com --all      # Full history
```

Shows changes detected between scans:
- New ports opened / ports closed
- Technologies added / removed
- Server software version changes
- New vulnerabilities discovered
- Previously found vulnerabilities now patched

#### List Known Targets

```bash
aegis learn targets
```

Lists all targets in the knowledge base with scan count, technologies, and last seen date.

---

### Adaptive Monitoring

#### Start Monitoring

```bash
aegis watch
aegis watch --interval 1800                    # 30-minute base interval
aegis watch --min-interval 120 --max-interval 43200  # 2min to 12hrs range
aegis watch --notify slack                     # With Slack notifications
aegis watch --notify discord                   # With Discord notifications
aegis watch --max-iterations 10                # Stop after 10 cycles
```

**How adaptive scheduling works:**
- Target has changes? → Scan interval decreases (more frequent)
- Target is stable? → Exponential backoff (less frequent)
- Minimum interval prevents overwhelming the target
- Maximum interval ensures nothing is missed

**Example behavior:**
```
Initial: scan every 60 minutes
Scan 1: 3 changes detected → interval drops to 36 minutes
Scan 2: 2 more changes → drops to 21 minutes
Scan 3: no changes → increases to 30 minutes
Scan 4: no changes → increases to 45 minutes
Scan 5: no changes → increases to 72 minutes
...eventually backs off to max (24 hours if no changes)
```

**Delta Reports:** After each scan, generates a report showing:
- New findings (vulnerabilities discovered since last scan)
- Resolved findings (previously found vulns no longer detected)
- Service changes (new/removed ports)
- Drift events (technology/config changes)
- Severity trend (improving/stable/worsening)

---

### Reporting

#### Generate Reports

```bash
aegis report generate --target example.com --format md
aegis report generate --target example.com --format html
aegis report generate --target example.com --format pdf
aegis report generate --target example.com --format html --min-severity medium
```

Reports include:
- Executive summary
- Findings table with severity and evidence
- Attack graph (D3.js interactive visualization in HTML)
- Remediation recommendations
- Custom sections (configurable in config.yaml)

#### SARIF Export (GitHub Code Scanning)

```bash
aegis sarif export --session 1
aegis sarif export --session 1 --output results.sarif
```

Exports findings in SARIF format for GitHub Code Scanning integration.

#### Timeline

```bash
aegis timeline
aegis timeline --limit 20
```

Shows scan session history with timestamps.

#### Compare Sessions

```bash
aegis compare 1 2
```

Compares findings between two scan sessions. Shows new, resolved, and persisting vulnerabilities.

---

### CVE Correlation

```bash
aegis cve correlate --session 1
aegis cve lookup CVE-2024-1234
```

Correlates findings with the NVD (National Vulnerability Database) API v2. Fetches CVSS scores, descriptions, and references.

**Requires:** NVD API key (free: https://nvd.nist.gov/developers/request-an-api-key)

---

### Campaign Management

```bash
aegis campaign create "Bug Bounty Q1" --domain target.com --url https://app.target.com
aegis campaign list
aegis campaign run "Bug Bounty Q1"
aegis campaign report "Bug Bounty Q1"
```

Manages multi-target scan campaigns with parallel execution, progress tracking, and aggregated reporting.

---

### REST API

#### Start Server

```bash
aegis api start
aegis api start --port 9000 --host 0.0.0.0
```

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/findings` | List findings (paginated) |
| GET | `/api/v1/findings/{id}` | Get finding details + notes + CVEs |
| POST | `/api/v1/findings/{id}/notes` | Add note to finding |
| GET | `/api/v1/sessions` | List scan sessions |
| GET | `/api/v1/sessions/{id}/findings` | Session findings |
| POST | `/api/v1/scan` | Trigger async scan job |
| GET | `/api/v1/scan/{job_id}` | Get scan job status |
| GET | `/api/v1/report/{target}` | Download report |
| POST | `/api/v1/burp/import` | Import Burp XML |
| GET | `/api/v1/sarif/{session_id}` | SARIF export |
| GET | `/api/v1/scope` | List scope |
| POST | `/api/v1/scope` | Add scope entry |
| DELETE | `/api/v1/scope/{id}` | Remove scope entry |

#### Authentication

Set `api.key` in config.yaml or use token-based auth:

```bash
aegis token create --name "CI Pipeline"
# Returns: aegis_tok_xxxxxxxxxxxx

# Use in requests:
curl -H "X-API-Key: aegis_tok_xxxxxxxxxxxx" http://localhost:8000/api/v1/findings
```

#### Security

- Rate limiting: 100 requests/minute/IP
- CORS: Configurable via `AEGIS_CORS_ORIGINS` environment variable
- Input validation on all target parameters

---

### Workspace Management

```bash
aegis workspace create pentest-client-a
aegis workspace switch pentest-client-a
aegis workspace list
aegis workspace delete old-workspace
```

Each workspace has its own database, findings, and scan history.

---

### Configuration

#### Interactive Key Setup

```bash
aegis configure-keys --interactive
```

#### Config File

Located at `config/config.yaml`. Key sections:

```yaml
general:
  safe_mode: true          # Require scope for all scans
  default_timeout: 30      # Command timeout in seconds

api_keys:
  groq: YOUR_KEY           # Fastest AI provider
  nvidia: YOUR_KEY         # 100+ models
  openrouter: YOUR_KEY     # Many model options
  bytez: YOUR_KEY          # Free fallback
  shodan: YOUR_KEY         # Shodan integration
  nvd: YOUR_KEY            # CVE correlation

notifications:
  slack_webhook: URL       # Slack alerts
  discord_webhook: URL     # Discord alerts

workflow:
  workers: 4               # Parallel threads
  rate_limit_per_sec: 5    # HTTP rate limiting
```

---

## Scan Profiles

| Profile | Use Case | Speed |
|---------|----------|-------|
| `default` | Balanced scan | Medium |
| `fast` | Quick results | Fast |
| `deep` | Thorough with OS detection | Slow |
| `stealth` | Low detection risk | Very slow |
| `web-fast` | Quick web scan | Fast |
| `web-deep` | Thorough web assessment | Slow |
| `api-deep` | API-focused testing | Medium |

```bash
aegis vuln web https://target.com --profile web-deep
aegis ai auto --target example.com --profile stealth
```

---

## External Tools

Aegis wraps these open-source tools (install what you need):

| Tool | Purpose | Install |
|------|---------|---------|
| nmap | Port scanning, service detection | `apt install nmap` |
| nuclei | Vulnerability scanning (10K+ templates) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| feroxbuster | Directory bruting | `apt install feroxbuster` |
| sqlmap | SQL injection | `apt install sqlmap` |
| subfinder | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| hydra | Brute force | `apt install hydra` |
| testssl.sh | SSL/TLS analysis | `apt install testssl.sh` |
| trufflehog | Secret scanning | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| gowitness | Screenshots | `go install github.com/sensepost/gowitness@latest` |
| crackmapexec | AD/SMB enumeration | `apt install crackmapexec` |
| bloodhound-python | AD attack paths | `pip install bloodhound` |
| tcpdump | Packet capture | `apt install tcpdump` |
| tshark | PCAP analysis | `apt install tshark` |

> Aegis gracefully skips any tool that's not installed — it never crashes, just reports "tool not found".

---

## Security Considerations

- **Authorization Required:** Always get written permission before scanning targets
- **Safe Mode:** Enable `safe_mode: true` in config to enforce scope checking
- **API Security:** CORS restricted to configured origins, rate limiting enabled
- **Evidence Chain:** Forensic captures use SHA-256 + BLAKE3 integrity verification
- **No Secrets in Output:** API keys are masked in logs and CLI output
- **TLS Verification:** Disabled only for target-facing requests (expected for pentest tools), NOT for AI API calls

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests: `pytest`
4. Run linter: `ruff check .`
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## Author

**Chandan Pandey**

- GitHub: [@thecnical](https://github.com/thecnical)
- Project: [aegis-devin](https://github.com/thecnical/aegis-devin)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>One command. Every phase. Real AI. Self-Learning.</b><br>
  <code>aegis ai auto --target YOUR_TARGET --full</code>
</p>
