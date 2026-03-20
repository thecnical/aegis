# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Yes    |
| < 2.0   | ❌ No     |

## Reporting a Vulnerability

If you discover a security vulnerability in Aegis, please **do not open a public GitHub issue**.

Instead, report it privately:

- **GitHub:** Use [GitHub Private Vulnerability Reporting](https://github.com/thecnical/aegis/security/advisories/new)
- **Email:** Open a GitHub issue with the title `[SECURITY]` and we will follow up privately

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You can expect an acknowledgement within 48 hours and a fix or mitigation within 14 days for confirmed issues.

## Scope

This policy covers the `aegis-cli` Python package and the code in this repository. It does **not** cover third-party tools that Aegis wraps (nmap, nuclei, sqlmap, etc.) — report those to their respective projects.
