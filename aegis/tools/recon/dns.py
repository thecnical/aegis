from __future__ import annotations

import click
from rich.table import Table

from aegis.core.ui import console


@click.command("dns")
@click.argument("domain")
@click.option("--types", default="A,MX,TXT,NS,CNAME", show_default=True, help="Comma-separated DNS record types.")
@click.pass_context
def cli(ctx: click.Context, domain: str, types: str) -> None:
    """DNS enumeration for a domain."""
    try:
        import dns.resolver  # type: ignore[import]
    except ImportError:
        console.print("[error]dnspython not installed. Run: pip install dnspython[/error]")
        return

    context = ctx.obj
    db = context.db if context else None
    record_types = [t.strip().upper() for t in types.split(",") if t.strip()]

    table = Table(title=f"DNS Records: {domain}")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="green")

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                value = str(rdata)
                table.add_row(rtype, value)
                if db:
                    db.add_finding(
                        target_id=None, host_id=None, port_id=None,
                        title=f"DNS {rtype} record",
                        severity="info",
                        category="recon",
                        description=f"{domain} {rtype} -> {value}",
                        source="dns",
                    )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as exc:
            console.print(f"[warning]DNS {rtype} query failed: {exc}[/warning]")

    console.print(table)
