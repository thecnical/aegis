"""First-run interactive setup wizard — auto-triggers on first use.

Guides the user through API key configuration with clickable links,
validation, and a nice terminal UI.
"""
from __future__ import annotations


from aegis.core.config_manager import ConfigManager
from aegis.core.ui import console


# ── API Key Providers ─────────────────────────────────────────────────────────

PROVIDERS = [
    {
        "name": "OpenCode Zen",
        "key_name": "opencode_zen",
        "url": "https://opencode.ai/zen",
        "description": "Free AI gateway with curated models for coding/security tasks",
        "instructions": "Sign up → Dashboard → Copy API key",
        "required": False,
        "priority": 1,
    },
    {
        "name": "NVIDIA NIM",
        "key_name": "nvidia",
        "url": "https://build.nvidia.com",
        "description": "100+ models, fastest inference, free tier available",
        "instructions": "Sign up → API Catalog → Get API Key",
        "required": False,
        "priority": 2,
    },
    {
        "name": "Groq",
        "key_name": "groq",
        "url": "https://console.groq.com/keys",
        "description": "750 tokens/sec LPU inference (fastest provider)",
        "instructions": "Sign up → API Keys → Create key",
        "required": False,
        "priority": 3,
    },
    {
        "name": "Shodan",
        "key_name": "shodan",
        "url": "https://account.shodan.io",
        "description": "Internet-wide scanning data (for recon enrichment)",
        "instructions": "Sign up → Account → API Key (free tier available)",
        "required": False,
        "priority": 4,
    },
    {
        "name": "NVD (CVE Database)",
        "key_name": "nvd",
        "url": "https://nvd.nist.gov/developers/request-an-api-key",
        "description": "National Vulnerability Database for CVE correlation",
        "instructions": "Fill form → Check email → Activate key",
        "required": False,
        "priority": 5,
    },
]


def _is_configured(config: ConfigManager, key_name: str) -> bool:
    """Check if a key is already configured."""
    val = config.get(f"api_keys.{key_name}")
    return bool(val and str(val).strip() not in ("CHANGE_ME", "", "null", "None"))


def needs_first_run(config: ConfigManager) -> bool:
    """Check if first-run setup is needed (no AI keys configured)."""
    # If at least one AI provider is configured, skip
    ai_keys = ["opencode_zen", "nvidia", "groq", "cloudflare", "bytez"]
    return not any(_is_configured(config, k) for k in ai_keys)


def run_first_time_setup(config: ConfigManager) -> None:
    """Run the interactive first-time setup wizard."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm

    console.print()
    console.print(Panel(
        "[bold]Welcome to Aegis-Devin![/bold]\n\n"
        "This is your first run. Let's configure AI API keys.\n"
        "All providers have [green]FREE tiers[/green] — no credit card required.\n\n"
        "[dim]You can skip any key by pressing Enter (empty).\n"
        "At least ONE AI key is needed for AI features to work.\n"
        "You can always reconfigure later with: aegis configure-keys -i[/dim]",
        title="[bold cyan]First-Time Setup Wizard[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    # Show provider table
    t = Table(title="Available AI Providers (All Free)", border_style="cyan")
    t.add_column("#", style="bold", justify="center", width=3)
    t.add_column("Provider", style="cyan", width=15)
    t.add_column("Description", width=45)
    t.add_column("Get Key", style="green", width=35)

    for i, p in enumerate(PROVIDERS, 1):
        t.add_row(str(i), str(p["name"]), str(p["description"]), str(p["url"]))
    console.print(t)
    console.print()

    # Ask for each key
    configured_count = 0
    config_data = config.load()
    api_keys = config_data.get("api_keys", {}) or {}

    for provider in PROVIDERS:
        name = str(provider["name"])
        key_name = str(provider["key_name"])
        url = str(provider["url"])

        if _is_configured(config, key_name):
            console.print(f"  [green]✓[/green] {name}: already configured")
            configured_count += 1
            continue

        console.print(f"\n  [bold cyan]{name}[/bold cyan]")
        console.print(f"  [dim]{provider['description']}[/dim]")
        console.print(f"  [green]Get key →[/green] [link={url}]{url}[/link]")
        console.print(f"  [dim]{provider['instructions']}[/dim]")

        try:
            key_input = Prompt.ask(
                f"  Paste {name} API key (or Enter to skip)",
                default="",
            )
        except (EOFError, KeyboardInterrupt):
            console.print("\n  [yellow]Setup interrupted. Run 'aegis configure-keys -i' later.[/yellow]")
            break

        if key_input.strip():
            api_keys[key_name] = key_input.strip()
            configured_count += 1
            console.print(f"  [green]✓ {name} key saved![/green]")
        else:
            console.print("  [dim]  Skipped[/dim]")

    # Save config
    config_data["api_keys"] = api_keys
    config.save(config_data)

    # Notifications setup
    console.print()
    try:
        setup_notif = Confirm.ask("  Set up Slack/Discord notifications?", default=False)
    except (EOFError, KeyboardInterrupt):
        setup_notif = False

    if setup_notif:
        notifications = config_data.get("notifications", {}) or {}
        try:
            slack = Prompt.ask("  Slack webhook URL (or Enter to skip)", default="")
            if slack.strip():
                notifications["slack_webhook"] = slack.strip()
                console.print("  [green]✓ Slack configured[/green]")

            discord = Prompt.ask("  Discord webhook URL (or Enter to skip)", default="")
            if discord.strip():
                notifications["discord_webhook"] = discord.strip()
                console.print("  [green]✓ Discord configured[/green]")

            config_data["notifications"] = notifications
            config.save(config_data)
        except (EOFError, KeyboardInterrupt):
            pass

    # Summary
    console.print()
    if configured_count > 0:
        console.print(Panel(
            f"[green]Setup complete![/green] {configured_count} API key(s) configured.\n\n"
            "[bold]Ready to go:[/bold]\n"
            "  aegis ai doctor          # Verify AI providers\n"
            "  aegis scope add <target> # Add target\n"
            "  aegis ai auto --target <host>  # Full AI pentest!",
            title="[bold green]Setup Complete[/bold green]",
            border_style="green",
        ))
    else:
        console.print(Panel(
            "[yellow]No API keys configured.[/yellow]\n\n"
            "AI features won't work without at least one key.\n"
            "LLM7 works without a key but has rate limits.\n\n"
            "Run later: [cyan]aegis configure-keys --interactive[/cyan]",
            title="[yellow]Setup Skipped[/yellow]",
            border_style="yellow",
        ))
