# Aegis - Modular Offensive Security CLI Framework

![CI](https://github.com/YOUR_GITHUB_USER/YOUR_REPO/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/aegis-cli)

Replace `YOUR_GITHUB_USER/YOUR_REPO` with your real repository.

Aegis is a modular and extensible offensive security CLI that centralizes recon, vulnerability analysis, exploitation helpers, post-exploitation workflows, and reporting.

## Installation

1. Create a virtual environment and install dependencies:

```bash
python --version  # Requires Python 3.10+
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

2. Install Aegis as a CLI tool:

```bash
pip install .
```

Created by Chandan Pandey.

## Configuration

Copy and edit `config/config.yaml`:

- `api_keys.shodan`: Shodan API key for passive port data
- `external_tools.*`: Paths or command names for external dependencies
- `general.db_path`: SQLite database path
- `general.safe_mode`: Prevents exploit helpers without `--force`
- `general.http_timeout`: HTTP timeout in seconds
- `general.http_retries`: HTTP retry count
- `general.http_backoff`: HTTP retry backoff
- `general.report_template`: Path to custom report template
- `general.report_custom_sections`: Custom report sections
- `general.report_template_html`: Path to custom HTML report template
- `general.brand`: Branding text for reports
- `general.wordlists_path`: Where wordlists are stored
- `general.wordlists_repo`: Wordlists repo URL
- `profiles.*`: Timeout presets (use `--profile`)

How to get Shodan API key:
Create an account on Shodan, open your account dashboard, and copy the API key into `config/config.yaml`.

Do I need all external tools before release:
You can publish Aegis without bundling tools, but users must install them to unlock each feature. Aegis runs with partial functionality if a tool is missing.

## External Dependencies (Kali Linux)

Install core tools:

```bash
sudo apt update
sudo apt install -y nmap smbclient netcat-openbsd hydra sqlmap git
```

ProjectDiscovery tools (subfinder, nuclei) and others are often installed from upstream:

```bash
sudo apt install -y golang
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

Make sure Go tools are on PATH:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Additional tools:

- `feroxbuster` (Rust)
- `wappalyzer` CLI
- `linpeas` / `winpeas`

Suggested installs:

```bash
sudo apt install -y cargo npm
cargo install feroxbuster
npm install -g wappalyzer
```

LinPEAS / WinPEAS (manual download):

```bash
mkdir -p data/tools
cd data/tools
# Place linpeas.sh and winpeas.exe here, or update config paths.
```

After installing, ensure they are in your PATH or set exact paths in `config/config.yaml`.

## Usage

Global usage:

```bash
aegis --help
aegis --config config/config.yaml
```

Read the full help guide:

```bash
type HELP.md   # Windows
cat HELP.md    # Linux
```

Check dependencies:

```bash
aegis doctor
```

Auto-detect tool paths and update config:

```bash
aegis doctor --fix
aegis doctor --fix --force
```

Install external tools and verify:

```bash
aegis doctor
```

Automatic tool installer (Kali/Debian only):

```bash
aegis setup
aegis setup --yes --peas --fix-config
```

Note: this uses `sudo` and requires internet access.

List installed plugins:

```bash
aegis plugins
```

Use a profile preset:

```bash
aegis --profile fast recon network 10.0.0.0/24
```

Enable debug logging and custom log file:

```bash
aegis --debug --log-file data/logs/aegis.log recon domain example.com
```

Run a quick pipeline:

```bash
aegis run --domain example.com --url https://example.com
```

Run a full pipeline with report:

```bash
aegis run --domain example.com --url https://example.com --full
```

Manage campaigns:

```bash
aegis campaign create myscan --domain example.com --url https://example.com
aegis campaign run myscan --full
aegis campaign diff myscan
aegis campaign report myscan
```

Campaign reports are saved to `data/reports/campaign_<name>.md`.

Update signatures and wordlists:

```bash
aegis update --all
```

Check wordlist version status:

```bash
aegis update --status
```

### Recon

```bash
# Passive domain recon

aegis recon domain example.com

aegis recon domain example.com --no-wappalyzer

aegis recon domain example.com --no-subdomains --no-shodan
```

```bash
# Active network recon

aegis recon network 10.0.0.0/24

aegis recon network 10.0.0.0/24 --port-scan
```

### Vulnerability

```bash
# Web scanning

aegis vuln web https://example.com

aegis vuln web https://example.com --no-nuclei
```

```bash
# Network scanning

aegis vuln net 10.0.0.10

aegis vuln net 10.0.0.10 --no-smb
```

### Exploit

```bash
# Web helpers

aegis exploit web https://example.com --force

aegis exploit web https://example.com --no-xss --no-sqlmap --force
```

```bash
# Network helpers

aegis exploit net 10.0.0.10 --service ssh --user root --passlist passwords.txt --force

aegis exploit net 10.0.0.10 --listen --lport 4444 --force
```

### Post-Exploitation

```bash
# Local enumeration helpers

aegis post shell 10.0.0.10

aegis post shell 10.0.0.10 --no-privesc
```

```bash
# Pivoting

aegis post pivoting 10.0.1.0/24 --ssh user@10.0.0.10 --port 1080
```

### Reporting

```bash
# Generate markdown report

aegis report generate example.com

# Generate HTML report

aegis report generate example.com --format html

# Export data

aegis report export csv --table ports

aegis report export json --table vulnerabilities
```

Evidence files are exported to `data/evidence/` during report generation.
Wordlist update metadata is saved to `data/wordlists/.aegis.json`.

### JSON Output

Every command supports JSON output:

```bash
aegis recon domain example.com --json

aegis vuln web https://example.com --json --json-output data/vuln.json
```

Global JSON output:

```bash
aegis --json recon domain example.com
```

## Advanced Profiles

Profiles can tune tool behavior:

- `profiles.*.nmap_args`: Nmap scan flags
- `profiles.*.nuclei_rate`: Nuclei rate limit
- `profiles.*.ferox_depth`: Feroxbuster recursion depth

## Report Theming

Set `general.report_template` in `config/config.yaml` to use a custom report template.
You can also edit `aegis/templates/report.md` and `general.report_custom_sections` for custom sections.
For HTML, set `general.report_template_html` or edit `aegis/templates/report.html`.

## 💰 You can help me by Donating
  [![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)
More donation options coming soon.

## Deployment on Kali

Recommended:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install .
```

Alternative (pipx):

```bash
pip install pipx
pipx install .
```

System-wide install (not recommended):

```bash
sudo python -m pip install .
```

## Configuration Checklist

1. Add Shodan API key in `config/config.yaml` under `api_keys.shodan`.
2. Run `aegis doctor` to verify tools are detected.
3. Run `aegis run --domain <target> --url <target> --full` for a complete pipeline.

## Database

Aegis stores scan results in a local SQLite database, `data/aegis.db`. This enables reporting and export across multiple runs.

## Notes

Aegis wraps external tools and assumes you have authorization for any targets you scan.

## Community

- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SECURITY.md`
