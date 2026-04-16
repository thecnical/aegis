"""Pivoting helpers: SOCKS proxy, port forwarding, internal network enumeration."""
from __future__ import annotations

import subprocess
import time
from typing import Dict, List, Optional

import click
from rich.table import Table

from aegis.core.ui import console
from aegis.core.utils import emit_json, run_command, which


def _start_socks_proxy(ssh_target: str, local_port: int) -> Optional[subprocess.Popen]:  # type: ignore[type-arg]
    """Start SSH SOCKS5 proxy in background. Returns process handle."""
    ssh = which("ssh")
    if not ssh:
        console.print("[red]ssh not found on PATH.[/red]")
        return None

    cmd = [
        ssh,
        "-N",                          # no remote command
        "-D", str(local_port),         # SOCKS5 dynamic port forwarding
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=30",
        ssh_target,
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Give it a moment to connect
        time.sleep(2)
        if proc.poll() is not None:
            _, err = proc.communicate()
            console.print(f"[red]SSH tunnel failed: {err.decode()[:200]}[/red]")
            return None
        return proc
    except OSError as exc:
        console.print(f"[red]SSH failed: {exc}[/red]")
        return None


def _port_forward(ssh_target: str, local_port: int, remote_host: str, remote_port: int) -> Optional[subprocess.Popen]:  # type: ignore[type-arg]
    """Set up SSH local port forward: localhost:local_port → remote_host:remote_port."""
    ssh = which("ssh")
    if not ssh:
        return None

    cmd = [
        ssh,
        "-N",
        "-L", f"{local_port}:{remote_host}:{remote_port}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        ssh_target,
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        if proc.poll() is not None:
            return None
        return proc
    except OSError:
        return None


def _scan_through_proxy(
    network: str,
    proxy_port: int,
    timeout: int,
) -> List[Dict[str, str]]:
    """Scan internal network through SOCKS proxy using nmap with proxychains."""
    results: List[Dict[str, str]] = []

    # Try proxychains4 or proxychains
    proxychains = which("proxychains4") or which("proxychains")
    nmap = which("nmap")

    if not proxychains or not nmap:
        console.print(
            "[yellow]proxychains/nmap not found. "
            "Install: sudo apt install proxychains4 nmap[/yellow]"
        )
        # Fall back to reporting the proxy is ready
        results.append({
            "type": "proxy_ready",
            "detail": f"SOCKS5 proxy on 127.0.0.1:{proxy_port}. "
                      f"Configure proxychains or your browser to use it.",
        })
        return results

    # Write a temporary proxychains config
    import tempfile
    config_content = (
        "strict_chain\n"
        "proxy_dns\n"
        "[ProxyList]\n"
        f"socks5 127.0.0.1 {proxy_port}\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False
    ) as f:
        f.write(config_content)
        conf_path = f.name

    try:
        code, out, err = run_command(
            [proxychains, "-f", conf_path, nmap, "-sT", "-Pn", "--open",
             "-p", "22,80,443,445,3389,8080,8443", network, "-oX", "-"],
            timeout=timeout,
        )
        if code == 0 and out:
            from aegis.core.parsers import parse_nmap_xml
            parsed = parse_nmap_xml(out)
            for host in parsed.get("hosts", []):
                ip = host.get("ip", "")
                for port_data in host.get("ports", []):
                    if port_data.get("state") == "open":
                        results.append({
                            "type": "open_port",
                            "host": ip,
                            "port": str(port_data.get("port", "")),
                            "service": port_data.get("service", {}).get("name", ""),
                        })
    except Exception as exc:
        console.print(f"[yellow]Proxy scan failed: {exc}[/yellow]")
    finally:
        from pathlib import Path
        Path(conf_path).unlink(missing_ok=True)

    return results


@click.command("pivoting")
@click.argument("network", default="10.0.0.0/24")
@click.option("--ssh", "ssh_target", required=True, help="SSH jump host: user@host")
@click.option("--port", "local_port", default=1080, show_default=True, type=int,
              help="Local SOCKS5 proxy port.")
@click.option("--forward", "forward_spec", default=None,
              help="Port forward: local_port:remote_host:remote_port")
@click.option("--scan", "do_scan", is_flag=True,
              help="Scan internal network through proxy after setup.")
@click.option("--timeout", default=60, show_default=True, type=int)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def cli(
    ctx: click.Context,
    network: str,
    ssh_target: str,
    local_port: int,
    forward_spec: Optional[str],
    do_scan: bool,
    timeout: int,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Pivoting: SOCKS5 proxy + port forwarding + internal network scan."""
    context = ctx.obj
    db = context.db if context else None
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)

    results: Dict[str, object] = {
        "network": network,
        "ssh_target": ssh_target,
        "proxy_port": local_port,
        "status": "not_started",
        "internal_hosts": [],
    }

    # Start SOCKS proxy
    console.print(f"[accent]Starting SOCKS5 proxy via {ssh_target} on 127.0.0.1:{local_port}...[/accent]")
    proxy_proc = _start_socks_proxy(ssh_target, local_port)

    if proxy_proc is None:
        results["status"] = "proxy_failed"
        if json_out:
            emit_json(results, json_output)
        return

    console.print(f"[green]✓ SOCKS5 proxy running on 127.0.0.1:{local_port}[/green]")
    results["status"] = "proxy_running"

    # Optional port forward
    forward_proc = None
    if forward_spec:
        parts = forward_spec.split(":")
        if len(parts) == 3:
            try:
                lp = int(parts[0])
                rh = parts[1]
                rp = int(parts[2])
                console.print(f"[accent]Setting up port forward: localhost:{lp} → {rh}:{rp}...[/accent]")
                forward_proc = _port_forward(ssh_target, lp, rh, rp)
                if forward_proc:
                    console.print(f"[green]✓ Port forward active: localhost:{lp} → {rh}:{rp}[/green]")
                    results["port_forward"] = f"localhost:{lp} → {rh}:{rp}"
            except ValueError:
                console.print("[yellow]Invalid --forward format. Use: local_port:remote_host:remote_port[/yellow]")

    # Store proxy setup as finding
    if db:
        db.add_finding(
            target_id=None, host_id=None, port_id=None,
            title=f"SOCKS5 pivot via {ssh_target}",
            severity="info",
            category="post",
            description=(
                f"SOCKS5 proxy: 127.0.0.1:{local_port}\n"
                f"Jump host: {ssh_target}\n"
                f"Target network: {network}"
            ),
            source="pivoting",
        )

    # Scan internal network through proxy
    internal_hosts: List[Dict[str, str]] = []
    if do_scan:
        console.print(f"[accent]Scanning {network} through proxy...[/accent]")
        internal_hosts = _scan_through_proxy(network, local_port, timeout)
        results["internal_hosts"] = internal_hosts

        if internal_hosts and db:
            for item in internal_hosts:
                if item.get("type") == "open_port":
                    host_id = db.upsert_host(item["host"])
                    db.add_finding(
                        target_id=None, host_id=host_id, port_id=None,
                        title=f"Internal host: {item['host']}:{item['port']} ({item.get('service','')})",
                        severity="info",
                        category="post",
                        description=f"Discovered via pivot through {ssh_target}",
                        source="pivoting",
                    )

    if json_out:
        # Terminate proxy before returning
        if proxy_proc:
            proxy_proc.terminate()
        if forward_proc:
            forward_proc.terminate()
        emit_json(results, json_output)
        return

    # Display results
    console.print("\n[bold]Pivot Summary[/bold]")
    console.print(f"  SOCKS5 proxy: [cyan]127.0.0.1:{local_port}[/cyan]")
    console.print(f"  Jump host:    [cyan]{ssh_target}[/cyan]")
    console.print(f"  Network:      [cyan]{network}[/cyan]")

    if internal_hosts:
        t = Table(title=f"Internal Hosts ({len(internal_hosts)})")
        t.add_column("Host", style="cyan")
        t.add_column("Port", style="magenta")
        t.add_column("Service", style="green")
        for item in internal_hosts:
            if item.get("type") == "open_port":
                t.add_row(item.get("host", ""), item.get("port", ""), item.get("service", ""))
            else:
                t.add_row("—", "—", item.get("detail", ""))
        console.print(t)

    console.print(
        "\n[yellow]Proxy is running. Press Ctrl+C to stop.[/yellow]\n"
        f"Configure tools to use SOCKS5 proxy at 127.0.0.1:{local_port}"
    )

    try:
        # Keep proxy alive until interrupted
        while proxy_proc.poll() is None:
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        if proxy_proc:
            proxy_proc.terminate()
            console.print("[dim]Proxy stopped.[/dim]")
        if forward_proc:
            forward_proc.terminate()
