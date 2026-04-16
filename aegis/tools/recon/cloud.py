"""Cloud asset discovery — S3, Azure Blob, GCP Storage, CloudFront, etc.

Discovers exposed cloud storage buckets and assets for a target domain.
Uses DNS resolution, HTTP probing, and permutation wordlists.
100% free — no cloud API keys required.
"""
from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional

import click
import httpx
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json


# ── Bucket name permutations ──────────────────────────────────────────────────

BUCKET_PREFIXES = [
    "", "dev-", "staging-", "prod-", "production-", "test-", "backup-",
    "data-", "static-", "assets-", "media-", "files-", "uploads-",
    "logs-", "archive-", "public-", "private-", "internal-", "api-",
    "cdn-", "images-", "img-", "docs-", "downloads-", "releases-",
]

BUCKET_SUFFIXES = [
    "", "-dev", "-staging", "-prod", "-production", "-test", "-backup",
    "-data", "-static", "-assets", "-media", "-files", "-uploads",
    "-logs", "-archive", "-public", "-private", "-internal", "-api",
    "-cdn", "-images", "-docs", "-downloads", "-releases", "-bucket",
    "-storage", "-store", "-s3", "-blob",
]


def _generate_bucket_names(domain: str) -> List[str]:
    """Generate candidate bucket names from a domain."""
    # Extract company name from domain
    parts = domain.split(".")
    company = parts[0] if parts else domain
    # Also try without common TLD parts
    names = set()
    for prefix in BUCKET_PREFIXES[:10]:  # limit to avoid too many requests
        for suffix in BUCKET_SUFFIXES[:10]:
            names.add(f"{prefix}{company}{suffix}")
    return sorted(names)


# ── AWS S3 ────────────────────────────────────────────────────────────────────

def _check_s3_bucket(name: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Check if an S3 bucket exists and is publicly accessible."""
    urls = [
        f"https://{name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{name}",
        f"https://{name}.s3.us-east-1.amazonaws.com",
    ]
    for url in urls:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as client:  # noqa: S501
                resp = client.get(url)

            if resp.status_code == 200:
                # Check if it's a bucket listing
                is_listing = "<ListBucketResult" in resp.text or "<Contents>" in resp.text
                return {
                    "provider": "AWS S3",
                    "name": name,
                    "url": url,
                    "status": resp.status_code,
                    "public_listing": is_listing,
                    "severity": "critical" if is_listing else "high",
                    "size_hint": resp.headers.get("content-length", "?"),
                }
            elif resp.status_code == 403:
                # Bucket exists but access denied — still a finding
                return {
                    "provider": "AWS S3",
                    "name": name,
                    "url": url,
                    "status": 403,
                    "public_listing": False,
                    "severity": "medium",
                    "note": "Bucket exists but access denied",
                }
            elif resp.status_code == 301:
                # Redirect to correct region
                location = resp.headers.get("location", "")
                if "amazonaws.com" in location:
                    return {
                        "provider": "AWS S3",
                        "name": name,
                        "url": location,
                        "status": 301,
                        "public_listing": False,
                        "severity": "medium",
                        "note": f"Redirected to {location}",
                    }
        except Exception:
            continue
    return None


# ── Azure Blob Storage ────────────────────────────────────────────────────────

def _check_azure_blob(name: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Check if an Azure Blob Storage container is publicly accessible."""
    urls = [
        f"https://{name}.blob.core.windows.net",
        f"https://{name}.blob.core.windows.net/?comp=list",
    ]
    for url in urls:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as client:  # noqa: S501
                resp = client.get(url)

            if resp.status_code == 200:
                is_listing = "<EnumerationResults" in resp.text or "<Blobs>" in resp.text
                return {
                    "provider": "Azure Blob",
                    "name": name,
                    "url": url,
                    "status": resp.status_code,
                    "public_listing": is_listing,
                    "severity": "critical" if is_listing else "high",
                }
            elif resp.status_code == 403:
                return {
                    "provider": "Azure Blob",
                    "name": name,
                    "url": url,
                    "status": 403,
                    "public_listing": False,
                    "severity": "medium",
                    "note": "Container exists but access denied",
                }
        except Exception:
            continue
    return None


# ── GCP Cloud Storage ─────────────────────────────────────────────────────────

def _check_gcp_bucket(name: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Check if a GCP Cloud Storage bucket is publicly accessible."""
    urls = [
        f"https://storage.googleapis.com/{name}",
        f"https://{name}.storage.googleapis.com",
        f"https://storage.googleapis.com/{name}?prefix=",
    ]
    for url in urls:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as client:  # noqa: S501
                resp = client.get(url)

            if resp.status_code == 200:
                is_listing = "<ListBucketResult" in resp.text or '"items"' in resp.text
                return {
                    "provider": "GCP Storage",
                    "name": name,
                    "url": url,
                    "status": resp.status_code,
                    "public_listing": is_listing,
                    "severity": "critical" if is_listing else "high",
                }
            elif resp.status_code == 403:
                return {
                    "provider": "GCP Storage",
                    "name": name,
                    "url": url,
                    "status": 403,
                    "public_listing": False,
                    "severity": "medium",
                    "note": "Bucket exists but access denied",
                }
        except Exception:
            continue
    return None


# ── CloudFront / CDN ──────────────────────────────────────────────────────────

def _check_cloudfront(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Check if domain uses CloudFront and if it's misconfigured."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:  # noqa: S501
            resp = client.get(f"https://{domain}")

        headers = {k.lower(): v for k, v in resp.headers.items()}
        if "cloudfront" in headers.get("via", "").lower() or \
           "x-amz-cf-id" in headers or \
           "x-amz-cf-pop" in headers:

            # Check for CloudFront misconfiguration (403 with CF error)
            if resp.status_code == 403 and "cloudfront" in resp.text.lower():
                return {
                    "provider": "AWS CloudFront",
                    "domain": domain,
                    "url": f"https://{domain}",
                    "status": 403,
                    "severity": "info",
                    "note": "CloudFront distribution detected",
                    "cf_id": headers.get("x-amz-cf-id", ""),
                }
    except Exception:
        pass
    return None


# ── DNS-based cloud detection ─────────────────────────────────────────────────

def _dns_cloud_detect(domain: str) -> List[Dict[str, str]]:
    """Detect cloud services via DNS CNAME records."""
    findings: List[Dict[str, str]] = []
    cloud_patterns = {
        "amazonaws.com": "AWS",
        "cloudfront.net": "AWS CloudFront",
        "blob.core.windows.net": "Azure Blob",
        "azurewebsites.net": "Azure App Service",
        "storage.googleapis.com": "GCP Storage",
        "appspot.com": "GCP App Engine",
        "herokuapp.com": "Heroku",
        "netlify.app": "Netlify",
        "vercel.app": "Vercel",
        "pages.github.io": "GitHub Pages",
        "fastly.net": "Fastly CDN",
        "akamaiedge.net": "Akamai CDN",
    }

    try:
        import dns.resolver  # type: ignore[import]
        for rtype in ("CNAME", "A"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    val = str(rdata).rstrip(".")
                    for pattern, provider in cloud_patterns.items():
                        if pattern in val:
                            findings.append({
                                "domain": domain,
                                "record_type": rtype,
                                "value": val,
                                "provider": provider,
                            })
            except Exception:
                continue
    except ImportError:
        # Fallback: socket-based
        try:
            ip = socket.gethostbyname(domain)
            findings.append({"domain": domain, "record_type": "A", "value": ip, "provider": "unknown"})
        except Exception:
            pass

    return findings


@click.command("cloud")
@click.argument("domain")
@click.option("--no-s3", is_flag=True, help="Skip AWS S3 checks.")
@click.option("--no-azure", is_flag=True, help="Skip Azure Blob checks.")
@click.option("--no-gcp", is_flag=True, help="Skip GCP Storage checks.")
@click.option("--wordlist", default=None, help="Custom bucket name wordlist file.")
@click.option("--timeout", default=8, show_default=True, type=int)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    domain: str,
    no_s3: bool,
    no_azure: bool,
    no_gcp: bool,
    wordlist: Optional[str],
    timeout: int,
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Discover exposed cloud storage: S3, Azure Blob, GCP Storage."""
    context = ctx.obj
    db = context.db if context else None
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    # Scope check
    if context and hasattr(context, "scope") and context.scope:
        context.scope.validate_or_abort(domain)

    console.print(f"[accent]Cloud asset discovery for:[/accent] {domain}")

    all_findings: List[Dict[str, Any]] = []

    # ── DNS-based detection ───────────────────────────────────────────────────
    console.print("[dim]  Checking DNS records for cloud services...[/dim]")
    dns_findings = _dns_cloud_detect(domain)
    for df in dns_findings:
        console.print(f"  [cyan]{df['provider']}[/cyan] detected via {df['record_type']}: {df['value']}")

    # ── Generate bucket names ─────────────────────────────────────────────────
    if wordlist:
        from pathlib import Path
        names = [n.strip() for n in Path(wordlist).read_text().splitlines() if n.strip()]
    else:
        names = _generate_bucket_names(domain)

    console.print(f"[dim]  Testing {len(names)} bucket name permutations...[/dim]")

    # ── S3 ────────────────────────────────────────────────────────────────────
    if not no_s3:
        console.print("[dim]  Checking AWS S3...[/dim]")
        for name in names:
            result = _check_s3_bucket(name, timeout)
            if result:
                all_findings.append(result)
                severity_color = "red" if result["severity"] == "critical" else "yellow"
                console.print(
                    f"  [{severity_color}]S3 FOUND:[/{severity_color}] "
                    f"{result['url']} (listing={result['public_listing']})"
                )

    # ── Azure ─────────────────────────────────────────────────────────────────
    if not no_azure:
        console.print("[dim]  Checking Azure Blob Storage...[/dim]")
        for name in names:
            result = _check_azure_blob(name, timeout)
            if result:
                all_findings.append(result)
                console.print(f"  [yellow]Azure FOUND:[/yellow] {result['url']}")

    # ── GCP ───────────────────────────────────────────────────────────────────
    if not no_gcp:
        console.print("[dim]  Checking GCP Cloud Storage...[/dim]")
        for name in names:
            result = _check_gcp_bucket(name, timeout)
            if result:
                all_findings.append(result)
                console.print(f"  [yellow]GCP FOUND:[/yellow] {result['url']}")

    # ── CloudFront ────────────────────────────────────────────────────────────
    cf_result = _check_cloudfront(domain, timeout)
    if cf_result:
        all_findings.append(cf_result)

    # ── Store findings ────────────────────────────────────────────────────────
    if db:
        for f in all_findings:
            provider = f.get("provider", "cloud")
            url = f.get("url", "")
            severity = f.get("severity", "medium")
            listing = f.get("public_listing", False)

            fid = db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"{'PUBLIC BUCKET LISTING' if listing else 'Cloud asset'}: {f.get('name', url)} ({provider})",
                severity=severity,
                category="recon",
                description=(
                    f"Provider: {provider}\n"
                    f"URL: {url}\n"
                    f"Public listing: {listing}\n"
                    f"HTTP status: {f.get('status', '?')}\n"
                    f"Note: {f.get('note', '')}"
                ),
                source="cloud-discovery",
            )
            if fid:
                db.add_evidence(fid, "url", url)
                db.add_evidence(fid, "provider", provider)

    if json_out:
        emit_json({"domain": domain, "dns": dns_findings, "buckets": all_findings}, json_output)
        return

    if not all_findings:
        console.print("[green]No exposed cloud assets found.[/green]")
    else:
        t = Table(title=f"Cloud Assets Found ({len(all_findings)})")
        t.add_column("Provider", style="cyan")
        t.add_column("Name/URL", style="green")
        t.add_column("Public Listing", style="red")
        t.add_column("Severity", style="magenta")
        t.add_column("Status", style="dim")

        for f in all_findings:
            listing_str = "[red]YES[/red]" if f.get("public_listing") else "no"
            t.add_row(
                f.get("provider", "?"),
                str(f.get("url", f.get("name", "")))[:60],
                listing_str,
                f.get("severity", "?"),
                str(f.get("status", "?")),
            )
        console.print(t)

    console.print(
        f"[primary]Cloud discovery complete.[/primary] "
        f"{len(all_findings)} asset(s) found."
    )
