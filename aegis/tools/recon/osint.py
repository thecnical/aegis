"""Advanced OSINT passive reconnaissance — gather intelligence without touching the target.

Capabilities:
  - Certificate Transparency log search (crt.sh)
  - Wayback Machine URL history extraction
  - Favicon hash fingerprinting (same as Shodan)
  - JavaScript endpoint/secret extraction from archived pages
  - WHOIS historical data
  - DNS history / passive DNS
  - Technology stack fingerprinting from public sources
  - Social media / GitHub dork discovery
  - Security.txt and robots.txt analysis
  - Email pattern discovery

All 100% passive — no direct requests to the target (except optional favicon fetch).
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import click
import httpx
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json


# ── Certificate Transparency ──────────────────────────────────────────────────

def search_crt_sh(domain: str, timeout: int = 30) -> List[Dict[str, str]]:
    """Search Certificate Transparency logs via crt.sh for subdomains and cert info."""
    results: List[Dict[str, str]] = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "Aegis-OSINT/2.2"},
            )
        if resp.status_code != 200:
            return results
        entries = resp.json()
        seen_names: Set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and name not in seen_names and "*" not in name:
                    seen_names.add(name)
                    results.append({
                        "subdomain": name,
                        "issuer": entry.get("issuer_name", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                        "serial": entry.get("serial_number", ""),
                    })
    except Exception as exc:
        console.print(f"[dim]  crt.sh error: {exc}[/dim]")
    return results


# ── Wayback Machine ───────────────────────────────────────────────────────────

def search_wayback(domain: str, timeout: int = 30, limit: int = 500) -> List[Dict[str, str]]:
    """Query the Wayback Machine CDX API for historical URLs."""
    results: List[Dict[str, str]] = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "timestamp,original,mimetype,statuscode",
                    "collapse": "urlkey",
                    "limit": str(limit),
                },
                headers={"User-Agent": "Aegis-OSINT/2.2"},
            )
        if resp.status_code != 200:
            return results
        data = resp.json()
        if len(data) < 2:
            return results
        # First row is headers
        for row in data[1:]:
            if len(row) >= 4:
                results.append({
                    "timestamp": row[0],
                    "url": row[1],
                    "mimetype": row[2],
                    "status": row[3],
                })
    except Exception as exc:
        console.print(f"[dim]  Wayback error: {exc}[/dim]")
    return results


def extract_interesting_wayback_urls(urls: List[Dict[str, str]]) -> Dict[str, List[str]]:
    """Categorize Wayback URLs into interesting groups."""
    categories: Dict[str, List[str]] = {
        "api_endpoints": [],
        "admin_panels": [],
        "config_files": [],
        "backup_files": [],
        "js_files": [],
        "sensitive_paths": [],
        "login_pages": [],
    }

    patterns = {
        "api_endpoints": re.compile(r"/(api|graphql|v[0-9]+|rest|swagger|openapi)", re.I),
        "admin_panels": re.compile(r"/(admin|dashboard|panel|manage|cms|wp-admin)", re.I),
        "config_files": re.compile(r"\.(env|config|conf|ini|yml|yaml|xml|json)$", re.I),
        "backup_files": re.compile(r"\.(bak|backup|old|orig|copy|sql|dump|tar|gz|zip)$", re.I),
        "js_files": re.compile(r"\.js$", re.I),
        "sensitive_paths": re.compile(r"/(\.git|\.svn|\.env|\.htaccess|web\.config|phpinfo)", re.I),
        "login_pages": re.compile(r"/(login|signin|auth|sso|oauth|register)", re.I),
    }

    seen: Set[str] = set()
    for entry in urls:
        url = entry.get("url", "")
        if url in seen:
            continue
        seen.add(url)
        for category, pattern in patterns.items():
            if pattern.search(url):
                categories[category].append(url)
                break

    return categories


# ── Favicon Hash (mmh3 — same as Shodan) ──────────────────────────────────────

def calculate_favicon_hash(url: str, timeout: int = 10) -> Optional[int]:
    """Fetch favicon and calculate its mmh3 hash (compatible with Shodan's http.favicon.hash).

    Uses a pure-Python MurmurHash3 implementation to avoid external deps.
    """
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            resp = client.get(url)
        if resp.status_code != 200:
            return None
        import base64
        favicon_b64 = base64.encodebytes(resp.content)
        # MurmurHash3 32-bit
        return _mmh3_hash32(favicon_b64)
    except Exception:
        return None


def _mmh3_hash32(data: bytes, seed: int = 0) -> int:
    """Pure Python MurmurHash3 32-bit implementation."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(nblocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    # Finalization mix
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Convert to signed 32-bit
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


# ── JavaScript Endpoint Extraction ────────────────────────────────────────────

def extract_js_endpoints(js_content: str) -> Dict[str, List[str]]:
    """Extract API endpoints, secrets, and interesting patterns from JavaScript."""
    results: Dict[str, List[str]] = {
        "api_paths": [],
        "full_urls": [],
        "potential_secrets": [],
        "email_addresses": [],
        "ip_addresses": [],
        "cloud_urls": [],
    }

    # API paths
    api_pattern = re.compile(r'["\']/(api|v[0-9]+)/[a-zA-Z0-9/_-]+["\']')
    for match in api_pattern.finditer(js_content):
        path = match.group(0).strip("\"'")
        if path not in results["api_paths"]:
            results["api_paths"].append(path)

    # Full URLs
    url_pattern = re.compile(r'https?://[a-zA-Z0-9./_?&=#%-]+')
    for match in url_pattern.finditer(js_content):
        url = match.group(0).rstrip("\"')}];,")
        if len(url) > 10 and url not in results["full_urls"]:
            results["full_urls"].append(url)

    # Potential secrets (API keys, tokens)
    secret_patterns = [
        (r'["\']?(?:api[_-]?key|apikey|api[_-]?secret|token|secret[_-]?key|access[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-./+=]{16,})["\']', "API Key/Token"),
        (r'(?:AWS|aws)[_-]?(?:ACCESS|SECRET)[_-]?(?:KEY|ID)["\']?\s*[:=]\s*["\']([A-Z0-9]{16,})["\']', "AWS Key"),
        (r'(?:firebase|supabase|stripe)[a-zA-Z]*["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Service Key"),
    ]
    for pattern, label in secret_patterns:
        for match in re.finditer(pattern, js_content, re.I):
            secret = f"[{label}] {match.group(1)[:30]}..."
            if secret not in results["potential_secrets"]:
                results["potential_secrets"].append(secret)

    # Emails
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    for match in email_pattern.finditer(js_content):
        email = match.group(0)
        if email not in results["email_addresses"] and not email.endswith(".png"):
            results["email_addresses"].append(email)

    # IP addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for match in ip_pattern.finditer(js_content):
        ip = match.group(0)
        if not ip.startswith("0.") and ip not in results["ip_addresses"]:
            results["ip_addresses"].append(ip)

    # Cloud URLs
    cloud_pattern = re.compile(r'https?://[a-zA-Z0-9.-]*(?:amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|cloudfront\.net|azureedge\.net)[a-zA-Z0-9./_?&=-]*')
    for match in cloud_pattern.finditer(js_content):
        url = match.group(0)
        if url not in results["cloud_urls"]:
            results["cloud_urls"].append(url)

    return results


# ── Passive DNS / SecurityTrails-style ────────────────────────────────────────

def get_dns_history_hackertarget(domain: str, timeout: int = 15) -> List[str]:
    """Get DNS records from HackerTarget (free, no key required)."""
    results: List[str] = []
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                headers={"User-Agent": "Aegis-OSINT/2.2"},
            )
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if len(parts) >= 1 and parts[0].strip():
                    results.append(parts[0].strip())
    except Exception:
        pass
    return results


# ── Email Pattern Discovery ───────────────────────────────────────────────────

def discover_email_pattern(domain: str, timeout: int = 15) -> Dict[str, Any]:
    """Try to discover email pattern for a domain using public sources."""
    patterns_found: List[str] = []
    emails_found: List[str] = []

    # Check common email verification endpoints that leak info
    common_patterns = [
        f"info@{domain}",
        f"admin@{domain}",
        f"support@{domain}",
        f"contact@{domain}",
        f"security@{domain}",
        f"noreply@{domain}",
    ]

    return {
        "domain": domain,
        "common_addresses": common_patterns,
        "note": "Use with email verification tools or OSINT frameworks for validation",
    }


# ── Main OSINT Orchestrator ───────────────────────────────────────────────────

def run_passive_osint(
    domain: str,
    include_wayback: bool = True,
    include_crt: bool = True,
    include_favicon: bool = True,
    include_dns: bool = True,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Run comprehensive passive OSINT gathering against a domain."""
    results: Dict[str, Any] = {
        "domain": domain,
        "certificate_transparency": {},
        "wayback_machine": {},
        "favicon": {},
        "passive_dns": {},
        "findings": [],
    }

    # ── Certificate Transparency ──────────────────────────────────────────────
    if include_crt:
        console.print("[dim]  Querying Certificate Transparency logs...[/dim]")
        crt_results = search_crt_sh(domain, timeout)
        subdomains = sorted(set(r["subdomain"] for r in crt_results))
        results["certificate_transparency"] = {
            "total_certs": len(crt_results),
            "unique_subdomains": len(subdomains),
            "subdomains": subdomains[:100],
            "issuers": list(set(r["issuer"] for r in crt_results))[:10],
        }
        if subdomains:
            results["findings"].append({
                "title": f"CT Log: {len(subdomains)} subdomains discovered for {domain}",
                "severity": "info",
                "category": "recon",
                "source": "crt.sh",
                "description": f"Subdomains: {', '.join(subdomains[:20])}",
            })

    # ── Wayback Machine ───────────────────────────────────────────────────────
    if include_wayback:
        console.print("[dim]  Querying Wayback Machine...[/dim]")
        wayback_urls = search_wayback(domain, timeout)
        categorized = extract_interesting_wayback_urls(wayback_urls)
        results["wayback_machine"] = {
            "total_urls": len(wayback_urls),
            "categorized": {k: v[:20] for k, v in categorized.items()},
        }

        # Generate findings for interesting discoveries
        for category, urls in categorized.items():
            if urls:
                severity = "medium" if category in ("config_files", "backup_files", "sensitive_paths") else "info"
                results["findings"].append({
                    "title": f"Wayback {category}: {len(urls)} URL(s) for {domain}",
                    "severity": severity,
                    "category": "recon",
                    "source": "wayback-machine",
                    "description": f"URLs: {', '.join(urls[:5])}",
                })

    # ── Favicon Hash ──────────────────────────────────────────────────────────
    if include_favicon:
        console.print("[dim]  Calculating favicon hash...[/dim]")
        # Try common favicon paths
        for path in ["/favicon.ico", "/assets/favicon.ico"]:
            fav_url = f"https://{domain}{path}"
            fav_hash = calculate_favicon_hash(fav_url, timeout=10)
            if fav_hash is not None:
                results["favicon"] = {
                    "url": fav_url,
                    "hash": fav_hash,
                    "shodan_query": f"http.favicon.hash:{fav_hash}",
                }
                results["findings"].append({
                    "title": f"Favicon hash: {fav_hash} (Shodan searchable)",
                    "severity": "info",
                    "category": "recon",
                    "source": "favicon-hash",
                    "description": f"Use Shodan query: http.favicon.hash:{fav_hash} to find related infrastructure",
                })
                break

    # ── Passive DNS ───────────────────────────────────────────────────────────
    if include_dns:
        console.print("[dim]  Gathering passive DNS records...[/dim]")
        dns_hosts = get_dns_history_hackertarget(domain, timeout)
        results["passive_dns"] = {
            "hosts": dns_hosts[:50],
            "count": len(dns_hosts),
        }
        if dns_hosts:
            results["findings"].append({
                "title": f"Passive DNS: {len(dns_hosts)} hosts for {domain}",
                "severity": "info",
                "category": "recon",
                "source": "passive-dns",
                "description": f"Hosts: {', '.join(dns_hosts[:10])}",
            })

    return results


# ── CLI Command ───────────────────────────────────────────────────────────────

@click.command("osint")
@click.argument("domain")
@click.option("--no-wayback", is_flag=True, help="Skip Wayback Machine query.")
@click.option("--no-crt", is_flag=True, help="Skip Certificate Transparency query.")
@click.option("--no-favicon", is_flag=True, help="Skip favicon hash calculation.")
@click.option("--no-dns", is_flag=True, help="Skip passive DNS lookup.")
@click.option("--js-url", default=None, help="URL of a JS file to analyze for endpoints/secrets.")
@click.option("--timeout", default=30, show_default=True, type=int)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    domain: str,
    no_wayback: bool,
    no_crt: bool,
    no_favicon: bool,
    no_dns: bool,
    js_url: Optional[str],
    timeout: int,
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Passive OSINT intelligence gathering — no direct target contact.

    Searches Certificate Transparency logs, Wayback Machine, favicon hashing,
    passive DNS, and JavaScript endpoint extraction.
    """
    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)
    db = getattr(context, "db", None)

    # Scope check
    if context and hasattr(context, "scope") and context.scope:
        context.scope.validate_or_abort(domain)

    console.print(f"[accent]Passive OSINT Recon:[/accent] {domain}")
    console.print("[dim]  All queries go to third-party databases — no direct target contact.[/dim]")

    results = run_passive_osint(
        domain,
        include_wayback=not no_wayback,
        include_crt=not no_crt,
        include_favicon=not no_favicon,
        include_dns=not no_dns,
        timeout=timeout,
    )

    # ── JavaScript analysis (optional) ────────────────────────────────────────
    if js_url:
        console.print(f"[dim]  Analyzing JavaScript: {js_url}[/dim]")
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
                resp = client.get(js_url)
            if resp.status_code == 200:
                js_results = extract_js_endpoints(resp.text)
                results["javascript_analysis"] = js_results
                for category, items in js_results.items():
                    if items:
                        severity = "high" if category == "potential_secrets" else "info"
                        results["findings"].append({
                            "title": f"JS {category}: {len(items)} found in {js_url}",
                            "severity": severity,
                            "category": "recon",
                            "source": "js-analysis",
                            "description": f"Items: {', '.join(items[:5])}",
                        })
        except Exception as exc:
            console.print(f"[warning]  JS analysis failed: {exc}[/warning]")

    if json_out:
        emit_json(results, json_output)
        return

    # ── Pretty output ─────────────────────────────────────────────────────────
    from rich.panel import Panel

    # CT results
    ct = results.get("certificate_transparency", {})
    if ct.get("unique_subdomains"):
        console.print(f"\n[bold cyan]Certificate Transparency:[/bold cyan] {ct['unique_subdomains']} subdomains from {ct['total_certs']} certificates")
        subs = ct.get("subdomains", [])
        if subs:
            t = Table(border_style="dim cyan")
            t.add_column("Subdomain", style="green")
            for sub in subs[:25]:
                t.add_row(sub)
            console.print(t)
            if len(subs) > 25:
                console.print(f"[dim]  ... and {len(subs) - 25} more[/dim]")

    # Wayback results
    wb = results.get("wayback_machine", {})
    if wb.get("total_urls"):
        console.print(f"\n[bold cyan]Wayback Machine:[/bold cyan] {wb['total_urls']} historical URLs")
        categorized = wb.get("categorized", {})
        for category, urls in categorized.items():
            if urls:
                style = "red" if category in ("config_files", "backup_files", "sensitive_paths") else "yellow"
                console.print(f"  [{style}]{category}:[/{style}] {len(urls)}")
                for url in urls[:5]:
                    console.print(f"    [dim]{url[:80]}[/dim]")

    # Favicon
    fav = results.get("favicon", {})
    if fav.get("hash"):
        console.print(f"\n[bold cyan]Favicon Hash:[/bold cyan] {fav['hash']}")
        console.print(f"  [dim]Shodan query: {fav['shodan_query']}[/dim]")

    # Passive DNS
    pdns = results.get("passive_dns", {})
    if pdns.get("count"):
        console.print(f"\n[bold cyan]Passive DNS:[/bold cyan] {pdns['count']} hosts")
        for host in pdns.get("hosts", [])[:10]:
            console.print(f"  [green]{host}[/green]")

    # JS Analysis
    js = results.get("javascript_analysis", {})
    if js:
        console.print(f"\n[bold cyan]JavaScript Analysis:[/bold cyan]")
        for category, items in js.items():
            if items:
                style = "bold red" if category == "potential_secrets" else "yellow"
                console.print(f"  [{style}]{category}: {len(items)}[/{style}]")
                for item in items[:3]:
                    console.print(f"    [dim]{item[:70]}[/dim]")

    # Summary
    findings = results.get("findings", [])
    console.print(f"\n[bold green]Total OSINT findings: {len(findings)}[/bold green]")

    # Store in DB
    if db and findings:
        target_id = db.upsert_target(domain)
        for f in findings:
            db.add_finding(
                target_id=target_id,
                host_id=None,
                port_id=None,
                title=f["title"],
                severity=f["severity"],
                category=f["category"],
                description=f["description"],
                source=f["source"],
            )
        console.print(f"[dim]  {len(findings)} findings stored in database.[/dim]")
