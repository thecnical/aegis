# Aegis Help Guide

Created by Chandan Pandey.

## What Is Aegis

Aegis is a modular offensive security CLI framework that helps security professionals run reconnaissance, vulnerability checks, exploitation helpers, post-exploitation tasks, and reporting from a single, consistent interface.

## How It Helps You

- Centralizes common security tooling in one CLI.
- Stores results in a local database for reporting and comparisons.
- Produces consistent reports and JSON output for automation.
- Adds profiles (fast, default, deep) to control scan intensity.
- Provides a pipeline command to chain recon → vuln → report.

## Core Workflow

1. Recon (discover hosts and services)
2. Vulnerability checks
3. Exploit helpers (optional, safe-mode protected)
4. Report generation

Example:

```bash
aegis run --domain example.com --url https://example.com --full
```

Generate HTML report:

```bash
aegis report generate example.com --format html
```

Update signatures and wordlists:

```bash
aegis update --all
```

Check wordlist version status:

```bash
aegis update --status
```

Wordlist metadata is stored in `data/wordlists/.aegis.json`.

Manage campaigns:

```bash
aegis campaign create myscan --domain example.com --url https://example.com
aegis campaign run myscan --full
aegis campaign diff myscan
aegis campaign report myscan
```

Campaign reports are saved to `data/reports/campaign_<name>.md`.

## External Tools (Required for Full Functionality)

Aegis wraps external tools. If a tool is missing, Aegis will warn you and skip that step.

Recommended tools:

- `nmap`
- `nuclei`
- `subfinder`
- `feroxbuster`
- `sqlmap`
- `hydra`
- `wappalyzer`
- `smbclient`
- `netcat`
- `linpeas`
- `winpeas`

Suggested installs:

```bash
sudo apt install -y cargo npm
cargo install feroxbuster
npm install -g wappalyzer
```

You can publish Aegis without bundling these tools, but users must install them to unlock all features. Aegis still runs with partial functionality if some tools are missing.

## API Keys

### Shodan

1. Create a Shodan account.
2. Copy your API key from your account dashboard.
3. Update `config/config.yaml`:

```
api_keys:
  shodan: "YOUR_KEY"
```

If the key is missing, Shodan-related checks are skipped.

## Profiles

Profiles tune timeouts and tool intensity:

- `default`: balanced
- `fast`: quick scans
- `deep`: comprehensive scans

Example:

```bash
aegis --profile deep recon network 10.0.0.0/24
```

## Report Theming

Customize reports by editing `aegis/templates/report.md` or setting `general.report_template`
in `config/config.yaml`. Add extra sections using `general.report_custom_sections`.
For HTML, set `general.report_template_html` or edit `aegis/templates/report.html`.

## Safety Notes

- Exploit helpers require `--force` when safe-mode is enabled.
- Always test only on systems you are authorized to assess.

## Troubleshooting

Check dependencies and configuration:

```bash
aegis doctor
```

Auto-detect tool paths and update config:

```bash
aegis doctor --fix
aegis doctor --fix --force
```

Automatic tool installer (Kali/Debian only):

```bash
aegis setup
aegis setup --yes --peas --fix-config
```

List plugins:

```bash
aegis plugins
```


Generate changelog:

```bash
python scripts/generate_changelog.py
```

Changelog supports Conventional Commits and auto-links PRs/issues when a GitHub remote is set.
