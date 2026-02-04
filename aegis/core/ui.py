from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

THEME = Theme(
    {
        "primary": "bold green",
        "accent": "bright_cyan",
        "warning": "bold yellow",
        "error": "bold red",
    }
)

console = Console(theme=THEME)


def show_banner(enabled: bool = True) -> None:
    if not enabled:
        return
    banner = (
        "[primary] █████╗ ███████╗ ██████╗ ██╗███████╗[/primary]\n"
        "[primary]██╔══██╗██╔════╝██╔════╝ ██║██╔════╝[/primary]\n"
        "[primary]███████║█████╗  ██║  ███╗██║███████╗[/primary]\n"
        "[primary]██╔══██║██╔══╝  ██║   ██║██║╚════██║[/primary]\n"
        "[primary]██║  ██║███████╗╚██████╔╝██║███████║[/primary]\n"
        "[primary]╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝[/primary]\n"
        "[accent]Offensive Security CLI[/accent]\n"
        "[green]Created by Chandan Pandey[/green]"
    )
    console.print(Panel.fit(banner, border_style="green"))
