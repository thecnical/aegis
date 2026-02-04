from __future__ import annotations

from pathlib import Path

import click
from rich.table import Table

from aegis.core.campaigns import (
    add_run,
    create_campaign,
    diff_runs,
    generate_campaign_report,
    get_runs,
    list_campaigns,
    summarize_db,
)
from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.installer import build_install_plan, run_install_plan, validate_environment
from aegis.core.logger import setup_logging
from aegis.core.plugin_loader import discover_manifests, discover_tools
from aegis.core.updater import (
    get_wordlist_status,
    print_update_summary,
    update_nuclei_templates,
    update_wordlists,
)
from aegis.core.tooling import detect_external_tools
from aegis.core.utils import emit_json, which
from aegis.core.ui import console, show_banner



class AegisContext:
    """Shared context for CLI commands."""

    def __init__(
        self,
        config: ConfigManager,
        db: DatabaseManager,
        profile: str,
        json_out: bool,
        json_output: str | None,
    ) -> None:
        self.config = config
        self.db = db
        self.profile = profile
        self.json_out = json_out
        self.json_output = json_output


pass_context = click.make_pass_decorator(AegisContext)


@click.group()
@click.option(
    "--config",
    "config_path",
    default="config/config.yaml",
    show_default=True,
    help="Path to config file.",
)
@click.option("--profile", default="default", show_default=True)
@click.option("--log-file", default="data/logs/aegis.log", show_default=True)
@click.option("--debug", is_flag=True, help="Enable debug logging.")
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
@click.option("--json-output", default=None, help="Write JSON to a file.")
@click.pass_context
def cli(
    ctx: click.Context,
    config_path: str,
    profile: str,
    log_file: str,
    debug: bool,
    json_out: bool,
    json_output: str | None,
) -> None:
    """Aegis - Modular Offensive Security CLI."""
    setup_logging(log_file, debug)
    config = ConfigManager(config_path)
    config.load()
    db_path = config.get("general.db_path", "data/aegis.db")
    db = DatabaseManager(db_path)
    db.init_db()

    profiles = config.get("profiles", {}) or {}
    if profile not in profiles:
        console.print(
            f"[bold yellow]Profile '{profile}' not found. Using defaults.[/bold yellow]"
        )
    ctx.obj = AegisContext(
        config=config,
        db=db,
        profile=profile,
        json_out=json_out,
        json_output=json_output,
    )
    show_banner(not json_out)


@cli.result_callback()
@click.pass_context
def cleanup(ctx: click.Context, *_: object, **__: object) -> None:
    context: AegisContext = ctx.obj
    if context and context.db:
        context.db.close()


@cli.command("doctor")
@pass_context
@click.option("--fix", "fix_tools", is_flag=True, help="Auto-detect tools and update config.")
@click.option("--force", "force_fix", is_flag=True, help="Overwrite configured tool paths.")
def doctor(ctx: AegisContext, fix_tools: bool, force_fix: bool) -> None:
    """Check configuration and external dependencies."""
    config = ctx.config
    api_keys = config.get("api_keys", {}) or {}
    tools = config.get("external_tools", {}) or {}

    if fix_tools:
        updated, detected = detect_external_tools(tools, force=force_fix)
        config_data = config.load()
        config_data["external_tools"] = updated
        config.save(config_data)
        tools = updated
        if ctx.json_out:
            emit_json({"updated": updated, "detected": detected}, ctx.json_output)
            return
        console.print("[primary]Updated external tool paths in config.[/primary]")

    table = Table(title="External Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Command", style="magenta")
    table.add_column("Status", style="green")
    for name, cmd in tools.items():
        found = which(str(cmd))
        status = "ok" if found else "missing"
        table.add_row(str(name), str(cmd), status)
    console.print(table)

    key_table = Table(title="API Keys")
    key_table.add_column("Service", style="cyan")
    key_table.add_column("Configured", style="green")
    for name, value in api_keys.items():
        configured = bool(value) and value != "CHANGE_ME"
        key_table.add_row(str(name), "yes" if configured else "no")
    console.print(key_table)

    config_path = Path(config.get("general.db_path", "data/aegis.db"))
    if not config_path.parent.exists():
        console.print(
            f"[bold yellow]Database directory does not exist:[/bold yellow] {config_path.parent}"
        )


@cli.command("plugins")
def plugins() -> None:
    """List discovered plugins and metadata."""
    metadata = discover_manifests()
    table = Table(title="Discovered Plugins")
    table.add_column("Category", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Command", style="magenta")
    table.add_column("Description", style="white")
    for category, entries in metadata.items():
        for entry in entries:
            table.add_row(
                str(category),
                str(entry.get("name", "")),
                str(entry.get("command", "")),
                str(entry.get("description", "")),
            )
    console.print(table)


@cli.command("run")
@click.option("--domain", default=None, help="Run recon domain against a target.")
@click.option("--cidr", default=None, help="Run recon network against a CIDR range.")
@click.option("--url", default=None, help="Run vuln web against a target URL.")
@click.option("--target-ip", default=None, help="Run vuln net against a target IP.")
@click.option("--full", "full_run", is_flag=True, help="Run recon, vuln, and report.")
@click.option("--report-target", default=None, help="Override report target name.")
@click.pass_context
def run_pipeline(
    ctx: click.Context,
    domain: str | None,
    cidr: str | None,
    url: str | None,
    target_ip: str | None,
    full_run: bool,
    report_target: str | None,
) -> None:
    """Run a basic pipeline across recon and vuln stages."""
    if domain:
        ctx.invoke(recon.get_command(ctx, "domain"), domain_name=domain)
    if cidr:
        ctx.invoke(recon.get_command(ctx, "network"), cidr_range=cidr)
    if url:
        ctx.invoke(vuln.get_command(ctx, "web"), url=url)
    if target_ip:
        ctx.invoke(vuln.get_command(ctx, "net"), target_ip=target_ip)
    if full_run:
        target_name = report_target or domain or url or target_ip or cidr or "report"
        ctx.invoke(report.get_command(ctx, "generate"), target=target_name)


@cli.command("setup")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation prompt.")
@click.option("--dry-run", is_flag=True, help="Print commands without running.")
@click.option("--peas", "include_peas", is_flag=True, help="Download LinPEAS/WinPEAS.")
@click.option("--fix-config", is_flag=True, help="Auto-update tool paths after install.")
@pass_context
def setup_tools(
    ctx: AegisContext, assume_yes: bool, dry_run: bool, include_peas: bool, fix_config: bool
) -> None:
    """Install external dependencies on Kali/Debian-based systems."""
    ok, reason = validate_environment()
    if not ok:
        console.print(f"[error]Setup not supported:[/error] {reason}")
        return

    if not assume_yes:
        proceed = click.confirm("Install external tools now?", default=False)
        if not proceed:
            console.print("[warning]Setup cancelled by user.[/warning]")
            return

    plan = build_install_plan(include_peas=include_peas)
    results = run_install_plan(plan, dry_run=dry_run)

    if fix_config and not dry_run:
        tools = ctx.config.get("external_tools", {}) or {}
        updated, _ = detect_external_tools(tools, force=True)
        config_data = ctx.config.load()
        config_data["external_tools"] = updated
        ctx.config.save(config_data)
        console.print("[primary]Config updated with detected tool paths.[/primary]")

    if ctx.json_out:
        emit_json({"setup": results}, ctx.json_output)


@cli.command("update")
@click.option("--nuclei", "nuclei_update", is_flag=True, help="Update Nuclei templates.")
@click.option("--wordlists", is_flag=True, help="Update wordlists repository.")
@click.option("--all", "update_all", is_flag=True, help="Update all signatures.")
@click.option("--status", "show_status", is_flag=True, help="Show wordlist status.")
@pass_context
def update_signatures(
    ctx: AegisContext,
    nuclei_update: bool,
    wordlists: bool,
    update_all: bool,
    show_status: bool,
) -> None:
    """Update templates and wordlists."""
    config = ctx.config
    if update_all:
        nuclei_update = True
        wordlists = True
    if show_status:
        dest = config.get("general.wordlists_path", "data/wordlists")
        status = get_wordlist_status(str(dest))
        if ctx.json_out:
            emit_json({"wordlists": status}, ctx.json_output)
            return
        console.print(f"[primary]Wordlists status:[/primary] {status}")
        return
    if not nuclei_update and not wordlists:
        console.print("[warning]Select --nuclei, --wordlists, or --all.[/warning]")
        return
    results = {}
    if nuclei_update:
        nuclei_cmd = config.get("external_tools.nuclei", "nuclei")
        results["nuclei"] = update_nuclei_templates(str(nuclei_cmd))
    if wordlists:
        repo = config.get("general.wordlists_repo", "")
        dest = config.get("general.wordlists_path", "data/wordlists")
        if not repo:
            results["wordlists"] = {"status": "failed", "error": "wordlists_repo not set"}
        else:
            results["wordlists"] = update_wordlists(str(repo), str(dest))
    if ctx.json_out:
        emit_json({"updates": results}, ctx.json_output)
        return
    print_update_summary(results)


@cli.group("campaign")
def campaign_group() -> None:
    """Manage scan campaigns."""


@campaign_group.command("create")
@click.argument("name")
@click.option("--domain", default=None)
@click.option("--cidr", default=None)
@click.option("--url", default=None)
@click.option("--target-ip", default=None)
def campaign_create(name: str, domain: str | None, cidr: str | None, url: str | None, target_ip: str | None) -> None:
    targets = {"domain": domain, "cidr": cidr, "url": url, "target_ip": target_ip}
    if not any(targets.values()):
        console.print("[warning]Provide at least one target option.[/warning]")
        return
    create_campaign(name, targets)
    console.print(f"[primary]Campaign created:[/primary] {name}")


@campaign_group.command("list")
def campaign_list() -> None:
    campaigns = list_campaigns()
    table = Table(title="Campaigns")
    table.add_column("Name", style="cyan")
    table.add_column("Targets", style="magenta")
    table.add_column("Runs", style="green")
    for item in campaigns:
        table.add_row(
            str(item.get("name")),
            str(item.get("targets")),
            str(item.get("runs")),
        )
    console.print(table)


@campaign_group.command("run")
@click.argument("name")
@click.option("--full", "full_run", is_flag=True, help="Run recon, vuln, and report.")
@click.option("--report-target", default=None)
@click.pass_context
def campaign_run(
    ctx: click.Context, name: str, full_run: bool, report_target: str | None
) -> None:
    data = list_campaigns()
    campaign = next((c for c in data if c["name"] == name), None)
    if not campaign:
        console.print(f"[error]Campaign not found:[/error] {name}")
        return
    targets = campaign.get("targets", {})
    run_pipeline(
        ctx,
        domain=targets.get("domain"),
        cidr=targets.get("cidr"),
        url=targets.get("url"),
        target_ip=targets.get("target_ip"),
        full_run=full_run,
        report_target=report_target,
    )
    summary = summarize_db(ctx.obj.db)
    add_run(name, summary)


@campaign_group.command("diff")
@click.argument("name")
def campaign_diff(name: str) -> None:
    runs = get_runs(name)
    if len(runs) < 2:
        console.print("[warning]Need at least two runs to diff.[/warning]")
        return
    delta = diff_runs(runs[-2], runs[-1])
    table = Table(title=f"Campaign Diff: {name}")
    table.add_column("Metric", style="cyan")
    table.add_column("Delta", style="magenta")
    for key, value in delta.items():
        table.add_row(str(key), str(value))
    console.print(table)


@campaign_group.command("report")
@click.argument("name")
def campaign_report(name: str) -> None:
    report_path = generate_campaign_report(name)
    if report_path:
        console.print(f"[primary]Campaign report saved:[/primary] {report_path}")


@cli.group()
def recon() -> None:
    """Information gathering tools."""


@cli.group()
def vuln() -> None:
    """Vulnerability analysis tools."""


@cli.group()
def exploit() -> None:
    """Exploitation tools."""


@cli.group()
def post() -> None:
    """Post-exploitation tools."""


@cli.group()
def report() -> None:
    """Reporting and export tools."""


def register_tools() -> None:
    tools = discover_tools()
    groups = {
        "recon": recon,
        "vuln": vuln,
        "exploit": exploit,
        "post": post,
        "report": report,
    }
    for category, commands in tools.items():
        group = groups.get(category)
        if not group:
            continue
        for command in commands:
            group.add_command(command)


register_tools()


if __name__ == "__main__":
    cli()
