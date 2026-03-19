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

VERSION = "1.0.0"

_BANNER_ART = """\
[bold bright_green]
   ▄████████    ▄████████  ▄██████▄   ▄█     ▄████████
  ███    ███   ███    ███ ███    ███ ███    ███    ███
  ███    ███   ███    █▀  ███    █▀  ███▌   ███    █▀
  ███    ███  ▄███▄▄▄     ███        ███▌   ███
▀███████████ ▀▀███▀▀▀     ███  █▄    ███▌ ▀███████████
  ███    ███   ███    █▄  ███    ███  ███           ███
  ███    ███   ███    ███ ███    ███  ███     ▄█    ███
  ███    █▀    ██████████  ▀██████▀   █▀    ▄████████▀
[/bold bright_green]"""

_TAGLINE   = "[bold bright_cyan]  ⚔  Modular Offensive Security Platform  ⚔[/bold bright_cyan]"
_AUTHOR    = "[dim white]  Created by [bold bright_green]Chandan Pandey[/bold bright_green]  •  v{ver}  •  [bright_cyan]github.com/chandanpandey/aegis[/bright_cyan][/dim white]"
_SEPARATOR = "[dim green]  ─────────────────────────────────────────────────────────────────[/dim green]"
_MODULES   = (
    "[dim white]  Modules:[/dim white] "
    "[bright_cyan]recon[/bright_cyan] · "
    "[bright_cyan]vuln[/bright_cyan] · "
    "[bright_cyan]exploit[/bright_cyan] · "
    "[bright_cyan]post[/bright_cyan] · "
    "[bright_cyan]report[/bright_cyan] · "
    "[bright_cyan]ai[/bright_cyan] · "
    "[bright_cyan]scope[/bright_cyan] · "
    "[bright_cyan]workspace[/bright_cyan] · "
    "[bright_cyan]watch[/bright_cyan] · "
    "[bright_cyan]serve[/bright_cyan]"
)
_HINT = "[dim white]  Run [bold]aegis --help[/bold] to see all commands  •  [bold]aegis doctor[/bold] to check dependencies[/dim white]"


def show_banner(enabled: bool = True) -> None:
    if not enabled:
        return

    content = (
        _BANNER_ART
        + "\n"
        + _TAGLINE
        + "\n"
        + _AUTHOR.format(ver=VERSION)
        + "\n"
        + _SEPARATOR
        + "\n"
        + _MODULES
        + "\n"
        + _HINT
        + "\n"
    )

    console.print(
        Panel(
            content,
            border_style="bright_green",
            padding=(0, 2),
            expand=False,
        )
    )
