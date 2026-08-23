"""Forensics CLI commands — exposed as `aegis forensics <subcommand>`."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import click

from aegis.core.ui import console
from aegis.core.utils import emit_json


@click.group("forensics")
def forensics_group() -> None:
    """Network forensics: capture, analyze, detect threats."""


@forensics_group.command("capture")
@click.option("--interface", "-i", default="eth0", show_default=True, help="Network interface.")
@click.option("--duration", "-d", default=60, show_default=True, type=int, help="Capture duration in seconds.")
@click.option("--filter", "bpf_filter", default="", help="BPF filter expression.")
@click.option("--output-dir", default="data/forensics/captures", show_default=True)
@click.option("--rotation", default=300, show_default=True, type=int, help="File rotation interval (seconds).")
@click.pass_context
def capture_cmd(
    ctx: click.Context,
    interface: str,
    duration: int,
    bpf_filter: str,
    output_dir: str,
    rotation: int,
) -> None:
    """Start live network capture with evidence chain integrity."""
    from aegis.forensics.capture import LiveCapture

    console.print(f"[accent]Starting capture:[/accent] interface={interface} duration={duration}s")
    console.print(f"[dim]  Output: {output_dir}[/dim]")
    if bpf_filter:
        console.print(f"[dim]  Filter: {bpf_filter}[/dim]")

    capture = LiveCapture(
        interface=interface,
        output_dir=output_dir,
        bpf_filter=bpf_filter,
        rotation_seconds=min(rotation, duration),
    )

    capture.start()
    console.print(f"[green]Capture running for {duration}s... Press Ctrl+C to stop early.[/green]")

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture interrupted by user.[/yellow]")

    last_file = capture.stop()
    console.print(f"[green]Capture stopped.[/green] Last file: {last_file}")

    # Show evidence chain status
    chain = capture.chain
    entries = chain.export()
    if entries:
        console.print(f"\n[accent]Evidence chain:[/accent] {len(entries)} file(s) recorded")
        for entry in entries[-3:]:  # Show last 3
            console.print(
                f"  [dim]#{entry['index']}[/dim] {Path(entry['file']).name} "
                f"sha256={entry['sha256'][:16]}... "
                f"size={entry['size_bytes']} bytes"
            )
        if chain.verify():
            console.print("  [green]Chain integrity: VERIFIED[/green]")
        else:
            console.print("  [red]Chain integrity: BROKEN — possible tampering![/red]")


@forensics_group.command("analyze")
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("--json", "json_out", is_flag=True, help="Output as JSON.")
@click.option("--json-output", default=None, help="Write JSON to file.")
@click.option("--timeline-output", default=None, help="Export timeline to JSON file.")
@click.pass_context
def analyze_cmd(
    ctx: click.Context,
    pcap_path: str,
    json_out: bool,
    json_output: Optional[str],
    timeline_output: Optional[str],
) -> None:
    """Deep analysis of a PCAP file — detect beacons, tunneling, exfiltration."""
    from aegis.forensics.analyzer import ForensicsAnalyzer

    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    console.print(f"[accent]Analyzing PCAP:[/accent] {pcap_path}")

    analyzer = ForensicsAnalyzer()
    results = analyzer.analyze_pcap(pcap_path)

    if timeline_output:
        analyzer.timeline.to_json(timeline_output)
        console.print(f"[green]Timeline exported:[/green] {timeline_output}")

    if json_out:
        emit_json(results, json_output)
        return

    # Pretty print results
    from rich.panel import Panel
    from rich.table import Table

    # Summary
    summary = results["summary"]
    console.print(Panel(
        f"Packets: {summary['total_packets']}  |  "
        f"Streams: {summary['streams']['total_streams']}  |  "
        f"HTTP convos: {summary['streams']['http_conversations']}",
        title="[bold]Analysis Summary[/bold]",
        border_style="green",
    ))

    # Protocol distribution
    if summary["protocol_distribution"]:
        t = Table(title="Protocol Distribution", border_style="dim")
        t.add_column("Protocol", style="cyan")
        t.add_column("Packets", style="white", justify="right")
        for proto, count in sorted(summary["protocol_distribution"].items(), key=lambda x: -x[1]):
            t.add_row(proto.upper(), str(count))
        console.print(t)

    # Threats
    threats = results["threats"]

    # Beacons
    beacons = threats.get("beacons", [])
    if beacons:
        console.print(f"\n[bold red]C2 Beacons Detected: {len(beacons)}[/bold red]")
        t = Table(border_style="red")
        t.add_column("Score", style="bold red", justify="center")
        t.add_column("Source", style="cyan")
        t.add_column("Destination", style="yellow")
        t.add_column("Interval", style="white")
        t.add_column("Jitter", style="white")
        t.add_column("Connections", justify="right")
        for b in beacons[:10]:
            t.add_row(
                str(b["beacon_score"]),
                b["src_ip"],
                b["dst"],
                f"{b['mean_interval_seconds']}s",
                f"{b['jitter']:.2%}",
                str(b["connection_count"]),
            )
        console.print(t)

    # DNS analysis
    dns = threats.get("dns_analysis", {})
    tunneling = dns.get("tunneling", [])
    dga = dns.get("dga_domains", [])
    fast_flux = dns.get("fast_flux", [])

    if tunneling:
        console.print(f"\n[bold red]DNS Tunneling Detected: {len(tunneling)}[/bold red]")
        for t_finding in tunneling[:5]:
            console.print(f"  [red]●[/red] {t_finding['domain']} — {', '.join(t_finding['indicators'])}")

    if dga:
        console.print(f"\n[bold yellow]DGA Domains Detected: {len(dga)}[/bold yellow]")
        for d in dga[:10]:
            console.print(f"  [yellow]●[/yellow] {d['domain']} (entropy={d['entropy']})")

    if fast_flux:
        console.print(f"\n[bold yellow]Fast-Flux Networks: {len(fast_flux)}[/bold yellow]")
        for ff in fast_flux[:5]:
            console.print(f"  [yellow]●[/yellow] {ff['domain']} → {ff['ip_count']} IPs")

    # Exfiltration
    exfil = threats.get("exfiltration", [])
    if exfil:
        console.print(f"\n[bold red]Exfiltration Indicators: {len(exfil)}[/bold red]")
        for e in exfil[:10]:
            console.print(f"  [{e['severity']}]●[/{e['severity']}] {e['description']}")

    if not beacons and not tunneling and not dga and not fast_flux and not exfil:
        console.print("\n[green]No threats detected in this capture.[/green]")

    # Store findings in DB if context available
    db = getattr(context, "db", None) if context else None
    if db:
        all_threats = beacons + tunneling + dga + fast_flux + exfil
        for threat in all_threats:
            db.add_finding(
                target_id=None,
                host_id=None,
                port_id=None,
                title=f"[Forensics] {threat.get('type', 'unknown')}: {threat.get('description', '')[:80]}",
                severity=threat.get("severity", "info"),
                category="forensics",
                description=threat.get("description", ""),
                source="forensics-analyzer",
            )
        if all_threats:
            console.print(f"\n[dim]{len(all_threats)} findings stored in database.[/dim]")


@forensics_group.command("verify")
@click.argument("chain_file", type=click.Path(exists=True))
@click.pass_context
def verify_cmd(ctx: click.Context, chain_file: str) -> None:
    """Verify integrity of an evidence chain (tamper detection)."""
    from aegis.forensics.capture import EvidenceChain

    chain = EvidenceChain(chain_file)
    entries = chain.export()

    console.print(f"[accent]Evidence Chain:[/accent] {chain_file}")
    console.print(f"  Entries: {len(entries)}")

    if not entries:
        console.print("  [yellow]Empty chain — nothing to verify.[/yellow]")
        return

    # Show entries
    from rich.table import Table
    t = Table(title="Chain Entries", border_style="dim")
    t.add_column("#", style="dim", justify="right")
    t.add_column("File", style="cyan")
    t.add_column("SHA-256", style="dim")
    t.add_column("Size", justify="right")
    t.add_column("Timestamp")

    for entry in entries:
        t.add_row(
            str(entry["index"]),
            Path(entry["file"]).name,
            entry["sha256"][:24] + "...",
            f"{entry['size_bytes']:,} B",
            entry["timestamp"][:19],
        )
    console.print(t)

    # Verify
    if chain.verify():
        console.print("\n  [bold green]✓ INTEGRITY VERIFIED[/bold green] — Chain is intact, no tampering detected.")
    else:
        console.print("\n  [bold red]✗ INTEGRITY BROKEN[/bold red] — Chain has been tampered with!")
        # Find break point
        for i, entry in enumerate(entries):
            if i == 0:
                continue
            if entry["prev_sha256"] != entries[i - 1]["sha256"]:
                console.print(f"  [red]Break at entry #{i}: prev_sha256 mismatch[/red]")
                console.print(f"    Expected: {entries[i-1]['sha256'][:32]}...")
                console.print(f"    Got:      {entry['prev_sha256'][:32]}...")
                break


@forensics_group.command("dns")
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def dns_cmd(ctx: click.Context, pcap_path: str, json_out: bool, json_output: Optional[str]) -> None:
    """DNS-focused analysis: tunneling, DGA, fast-flux detection."""
    from aegis.forensics.analyzer import DNSAnalyzer, ForensicsAnalyzer
    from aegis.forensics.capture import PcapReader

    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    console.print(f"[accent]DNS Analysis:[/accent] {pcap_path}")

    reader = PcapReader(pcap_path)
    dns_analyzer = DNSAnalyzer()

    for record in reader.extract_dns_queries():
        dns_analyzer.add_query(record)

    results = dns_analyzer.full_analysis()

    if json_out:
        emit_json(results, json_output)
        return

    stats = results["stats"]
    console.print(f"  Total queries: {stats['total_queries']}")
    console.print(f"  Unique domains: {stats['unique_domains']}")

    if stats["top_queried"]:
        console.print("\n  [bold]Top queried domains:[/bold]")
        for domain, count in stats["top_queried"][:10]:
            console.print(f"    {count:>5}x  {domain}")

    for category, findings in [
        ("DNS Tunneling", results["tunneling"]),
        ("DGA Domains", results["dga_domains"]),
        ("Fast-Flux", results["fast_flux"]),
    ]:
        if findings:
            console.print(f"\n  [bold red]{category}: {len(findings)}[/bold red]")
            for f in findings[:5]:
                console.print(f"    [red]●[/red] {f['description']}")


@forensics_group.command("sessions")
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("--protocol", default="http", type=click.Choice(["http", "dns", "tls", "all"]))
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def sessions_cmd(
    ctx: click.Context,
    pcap_path: str,
    protocol: str,
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Extract and display protocol sessions from PCAP."""
    from aegis.forensics.capture import PcapReader

    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    console.print(f"[accent]Session extraction:[/accent] {pcap_path} (protocol={protocol})")

    reader = PcapReader(pcap_path)
    results: dict = {}

    if protocol in ("http", "all"):
        results["http"] = reader.extract_http_sessions()
    if protocol in ("dns", "all"):
        results["dns"] = reader.extract_dns_queries()
    if protocol in ("tls", "all"):
        results["tls"] = reader.extract_tls_info()

    if json_out:
        emit_json(results, json_output)
        return

    from rich.table import Table

    for proto, sessions in results.items():
        if not sessions:
            console.print(f"  [dim]No {proto.upper()} sessions found.[/dim]")
            continue

        console.print(f"\n[bold]{proto.upper()} Sessions: {len(sessions)}[/bold]")
        t = Table(border_style="dim")

        if proto == "http":
            t.add_column("Method", style="cyan")
            t.add_column("Host", style="green")
            t.add_column("URI", style="white")
            t.add_column("Status", justify="center")
            for s in sessions[:30]:
                t.add_row(s.get("method"), s.get("host"), s.get("uri", "")[:60], s.get("response_code"))
        elif proto == "dns":
            t.add_column("Query", style="cyan")
            t.add_column("Type", style="green")
            t.add_column("Answer", style="white")
            for s in sessions[:30]:
                t.add_row(s.get("query_name"), s.get("query_type"), s.get("answers", "")[:40])
        elif proto == "tls":
            t.add_column("SNI", style="cyan")
            t.add_column("Version", style="green")
            t.add_column("Cipher", style="white")
            for s in sessions[:30]:
                t.add_row(s.get("sni"), s.get("version"), s.get("cipher", "")[:30])

        console.print(t)


@forensics_group.command("credentials")
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def credentials_cmd(
    ctx: click.Context,
    pcap_path: str,
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Extract cleartext credentials from PCAP (FTP, HTTP Basic, Telnet)."""
    from aegis.forensics.capture import PcapReader

    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    console.print(f"[accent]Credential extraction:[/accent] {pcap_path}")

    reader = PcapReader(pcap_path)
    creds = reader.extract_credentials()

    if json_out:
        emit_json(creds, json_output)
        return

    if not creds:
        console.print("  [green]No cleartext credentials found.[/green]")
        return

    console.print(f"  [bold red]Cleartext credentials found: {len(creds)}[/bold red]")
    from rich.table import Table
    t = Table(border_style="red")
    t.add_column("Protocol", style="cyan")
    t.add_column("Data", style="red")
    for c in creds[:20]:
        data_str = str(c.get("data", ""))[:80]
        t.add_row(c.get("protocol", "?"), data_str)
    console.print(t)

    # Store in DB
    db = getattr(context, "db", None) if context else None
    if db:
        for c in creds:
            db.add_finding(
                target_id=None,
                host_id=None,
                port_id=None,
                title=f"Cleartext credential ({c.get('protocol', '?')})",
                severity="critical",
                category="forensics",
                description=f"Protocol: {c.get('protocol')}\nData: {str(c.get('data', ''))[:200]}",
                source="forensics-credentials",
            )
        console.print(f"  [dim]{len(creds)} credential findings stored.[/dim]")


@forensics_group.command("anomalies")
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("--z-threshold", default=3.0, show_default=True, type=float, help="Z-score threshold for anomaly detection.")
@click.option("--port-scan-threshold", default=20, show_default=True, type=int, help="Ports touched to trigger port scan alert.")
@click.option("--severity", default=None, type=click.Choice(["info", "low", "medium", "high", "critical"]))
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def anomalies_cmd(
    ctx: click.Context,
    pcap_path: str,
    z_threshold: float,
    port_scan_threshold: int,
    severity: Optional[str],
    json_out: bool,
    json_output: Optional[str],
) -> None:
    """Statistical anomaly detection on PCAP — port scans, floods, tunneling, spoofing."""
    from aegis.forensics.anomaly_detector import analyze_pcap_anomalies

    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    console.print(f"[accent]Anomaly Detection:[/accent] {pcap_path}")
    console.print(f"[dim]  Z-threshold={z_threshold}  Port-scan-threshold={port_scan_threshold}[/dim]")

    results = analyze_pcap_anomalies(pcap_path, z_threshold, port_scan_threshold)
    anomalies = results["anomalies"]
    status = results["status"]

    if severity:
        anomalies = [a for a in anomalies if a.get("severity") == severity]

    if json_out:
        emit_json(results, json_output)
        return

    from rich.panel import Panel
    from rich.table import Table

    # Status summary
    console.print(Panel(
        f"Packets processed: {status['total_packets_processed']:,}\n"
        f"Total bytes: {status['total_bytes_processed']:,}\n"
        f"Anomalies detected: {status['total_anomalies_detected']}\n"
        f"Tracked sources: {status['tracked_sources']}\n"
        f"Baseline metrics: {status['baseline_metrics']}",
        title="[bold]Engine Status[/bold]",
        border_style="green",
    ))

    # Severity distribution
    sev_dist = status.get("severity_distribution", {})
    if sev_dist:
        console.print("\n[bold]Severity Distribution:[/bold]")
        for sev_level in ["critical", "high", "medium", "low", "info"]:
            count = sev_dist.get(sev_level, 0)
            if count:
                style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "dim white"}.get(sev_level, "white")
                console.print(f"  [{style}]{sev_level.upper():>10}: {count}[/{style}]")

    # Anomaly type breakdown
    type_dist = status.get("anomaly_types", {})
    if type_dist:
        console.print("\n[bold]Anomaly Types:[/bold]")
        for atype, count in sorted(type_dist.items(), key=lambda x: -x[1]):
            console.print(f"  [cyan]{atype:<25}[/cyan] {count}")

    # Detailed anomalies table
    if anomalies:
        console.print(f"\n[bold]Anomalies ({len(anomalies)}):[/bold]")
        t = Table(border_style="red")
        t.add_column("Score", style="bold", justify="center", width=5)
        t.add_column("Type", style="cyan", width=20)
        t.add_column("Severity", justify="center", width=8)
        t.add_column("Source", style="green", width=15)
        t.add_column("Description", width=50)

        for a in anomalies[:40]:
            sev = a.get("severity", "info")
            sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "dim"}.get(sev, "white")
            t.add_row(
                f"{a.get('score', 0):.0f}",
                a.get("type", ""),
                f"[{sev_style}]{sev}[/{sev_style}]",
                a.get("source_ip", "")[:15],
                a.get("description", "")[:50],
            )
        console.print(t)
    else:
        console.print("\n[green]No anomalies detected.[/green]")

    # Store findings in DB
    db = getattr(context, "db", None) if context else None
    if db and anomalies:
        for a in anomalies:
            db.add_finding(
                target_id=None, host_id=None, port_id=None,
                title=f"[Anomaly] {a.get('type', 'unknown')}",
                severity=a.get("severity", "info"),
                category="anomaly-detection",
                description=a.get("description", ""),
                source="anomaly-detector",
            )
        console.print(f"\n[dim]{len(anomalies)} anomaly findings stored in database.[/dim]")
