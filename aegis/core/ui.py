from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

THEME = Theme(
    {
        "primary":   "bold bright_green",
        "accent":    "bold bright_cyan",
        "warning":   "bold yellow",
        "error":     "bold red",
        "dim_green": "dim green",
        "gold":      "bold yellow",
        "muted":     "dim white",
    }
)

console = Console(theme=THEME)

VERSION = "2.0.0"

# ── ASCII art ─────────────────────────────────────────────────────────────────

_BANNER_ART = """\
[bold bright_green]
 ░█████╗░███████╗░██████╗░██╗░██████╗
 ██╔══██╗██╔════╝██╔════╝░██║██╔════╝
 ███████║█████╗░░██║░░██╗░██║╚█████╗░
 ██╔══██║██╔══╝░░██║░░╚██╗██║░╚═══██╗
 ██║░░██║███████╗╚██████╔╝██║██████╔╝
 ╚═╝░░╚═╝╚══════╝░╚═════╝░╚═╝╚═════╝[/bold bright_green]"""

_SUBTITLE = (
    "\n"
    "[bold bright_cyan]  ╔══════════════════════════════════════════════════════════════╗[/bold bright_cyan]\n"
    "[bold bright_cyan]  ║[/bold bright_cyan]  [bold white]AI-Driven Autonomous Penetration Testing Platform[/bold white]          [bold bright_cyan]║[/bold bright_cyan]\n"
    "[bold bright_cyan]  ║[/bold bright_cyan]  [dim white]One command. Every phase. Real agentic intelligence.[/dim white]         [bold bright_cyan]║[/bold bright_cyan]\n"
    "[bold bright_cyan]  ╚══════════════════════════════════════════════════════════════╝[/bold bright_cyan]"
)

_STATS = (
    "\n"
    "[dim white]  ┌─ [bold bright_green]15+[/bold bright_green] Attack Modules  "
    "·  [bold bright_green]10+[/bold bright_green] WAF Vendors Detected  "
    "·  [bold bright_green]100%[/bold bright_green] Free & Open Source ─┐[/dim white]\n"
    "[dim white]  │  [bold bright_cyan]Recon[/bold bright_cyan] → [bold bright_cyan]Vuln[/bold bright_cyan] → "
    "[bold bright_cyan]Exploit[/bold bright_cyan] → [bold bright_cyan]Post[/bold bright_cyan] → "
    "[bold bright_cyan]Report[/bold bright_cyan]  │  "
    "[bold yellow]AI selects tools. AI reads output. AI decides next.[/bold yellow]  │[/dim white]\n"
    "[dim white]  └──────────────────────────────────────────────────────────────────┘[/dim white]"
)

_MODULES_HEADER = "\n[dim white]  ── Commands ──────────────────────────────────────────────────────[/dim white]"

_MODULES = (
    "\n"
    "  [bold bright_green]recon[/bold bright_green]    [dim white]domain · network · dns · osint · cloud · secrets · screenshot · ad[/dim white]\n"
    "  [bold bright_green]vuln[/bold bright_green]     [dim white]web · net · ssl · api · smuggling[/dim white]\n"
    "  [bold bright_green]exploit[/bold bright_green]  [dim white]web · net · lfi · ssrf · oob · msf[/dim white]\n"
    "  [bold bright_green]post[/bold bright_green]     [dim white]shell · creds · pivoting[/dim white]\n"
    "  [bold bright_green]ai[/bold bright_green]       [dim white]auto · triage · summarize · suggest · report · chat[/dim white]\n"
    "  [bold bright_green]report[/bold bright_green]   [dim white]generate · export  (md · html · pdf · sarif)[/dim white]"
)

_QUICKSTART = (
    "\n"
    "[dim white]  ── Quick Start ────────────────────────────────────────────────────[/dim white]\n"
    "  [dim white]$[/dim white] [bold bright_cyan]aegis scope add example.com --kind domain[/bold bright_cyan]\n"
    "  [dim white]$[/dim white] [bold bright_cyan]aegis ai auto --target example.com --full --format html[/bold bright_cyan]\n"
    "  [dim white]$[/dim white] [bold bright_cyan]aegis doctor[/bold bright_cyan]  [dim white]← verify all tools are installed[/dim white]"
)

_FOOTER = (
    "\n"
    "[dim white]  ── Info ───────────────────────────────────────────────────────────[/dim white]\n"
    "  [dim white]Author :[/dim white] [bold bright_green]Chandan Pandey[/bold bright_green]"
    "  [dim white]│  Version :[/dim white] [bold bright_cyan]v{ver}[/bold bright_cyan]"
    "  [dim white]│  License :[/dim white] [bold white]MIT[/bold white]\n"
    "  [dim white]GitHub :[/dim white] [bright_cyan]https://github.com/thecnical/aegis[/bright_cyan]\n"
    "  [dim white]Support:[/dim white] [bright_yellow]https://buymeacoffee.com/chandanpandit[/bright_yellow]\n"
    "\n"
    "  [dim white]⚠  For authorized penetration testing only. Unauthorized use is illegal.[/dim white]"
)


def show_banner(enabled: bool = True) -> None:
    if not enabled:
        return

    content = (
        _BANNER_ART
        + _SUBTITLE
        + _STATS
        + _MODULES_HEADER
        + _MODULES
        + _QUICKSTART
        + _FOOTER.format(ver=VERSION)
        + "\n"
    )

    console.print(
        Panel(
            content,
            border_style="bright_green",
            padding=(0, 1),
            expand=False,
            title="[bold bright_green] ⚔  AEGIS  ⚔ [/bold bright_green]",
            title_align="center",
            subtitle="[dim green] AI-Powered Offensive Security [/dim green]",
            subtitle_align="center",
        )
    )
