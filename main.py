from __future__ import annotations

import time
from typing import Optional

import click
from rich.table import Table

from aegis.core.campaigns import (
    add_run, create_campaign, diff_runs,
    generate_campaign_report, get_runs, list_campaigns, summarize_db,
)
from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.installer import (
    build_install_plan,
    run_install_plan,
    run_install_plan_interactive,
    validate_environment,
    _is_linux as _is_linux_check,
)
from aegis.core.logger import setup_logging
from aegis.core.plugin_loader import discover_manifests, discover_tools
from aegis.core.updater import (
    get_wordlist_status, print_update_summary,
    update_nuclei_templates, update_wordlists,
)
from aegis.core.tooling import detect_external_tools
from aegis.core.utils import emit_json
from aegis.core.ui import console, show_banner
from aegis.core.scope_manager import ScopeManager
from aegis.core.workspace_manager import WorkspaceManager
from aegis.core.ai_client import AIClient
from aegis.core.notifier import Notifier
from aegis.core.deduplicator import Deduplicator


class AegisContext:
    """Shared context for CLI commands."""

    def __init__(
        self,
        config: ConfigManager,
        db: DatabaseManager,
        profile: str,
        json_out: bool,
        json_output: Optional[str],
        scope: Optional[ScopeManager] = None,
        workspace_name: str = "default",
    ) -> None:
        self.config = config
        self.db = db
        self.profile = profile
        self.json_out = json_out
        self.json_output = json_output
        self.scope = scope or ScopeManager(db, safe_mode=bool(config.get("general.safe_mode", True)))
        self.workspace_name = workspace_name


pass_context = click.make_pass_decorator(AegisContext)


@click.group()
@click.option("--config", "config_path", default="config/config.yaml", show_default=True)
@click.option("--profile", default="default", show_default=True)
@click.option("--log-file", default="data/logs/aegis.log", show_default=True)
@click.option("--debug", is_flag=True)
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.option("--workspace", "workspace_name", default=None, help="Override active workspace.")
@click.pass_context
def cli(
    ctx: click.Context,
    config_path: str,
    profile: str,
    log_file: str,
    debug: bool,
    json_out: bool,
    json_output: Optional[str],
    workspace_name: Optional[str],
) -> None:
    """Aegis - Modular Offensive Security Platform."""
    setup_logging(log_file, debug)
    config = ConfigManager(config_path)
    config.load()

    # Resolve workspace
    root_db_path = config.get("general.db_path", "data/aegis.db")
    root_db = DatabaseManager(root_db_path)
    root_db.init_db()
    ws_mgr = WorkspaceManager(root_db)

    if workspace_name:
        ws = ws_mgr.switch(workspace_name)
    else:
        ws = ws_mgr.current()

    db = DatabaseManager(ws.db_path)
    db.init_db()

    profiles = config.get("profiles", {}) or {}
    if profile not in profiles:
        console.print(f"[warning]Profile '{profile}' not found. Using defaults.[/warning]")

    ctx.obj = AegisContext(
        config=config,
        db=db,
        profile=profile,
        json_out=json_out,
        json_output=json_output,
        workspace_name=ws.name,
    )
    show_banner(not json_out)


@cli.result_callback()
@click.pass_context
def cleanup(ctx: click.Context, *_: object, **__: object) -> None:
    context: Optional[AegisContext] = ctx.find_object(AegisContext)
    if context and context.db:
        context.db.close()


# ─── scope ────────────────────────────────────────────────────────────────────

@cli.group("scope")
def scope_group() -> None:
    """Manage in-scope targets."""


@scope_group.command("add")
@click.argument("target")
@click.option("--kind", default="ip", type=click.Choice(["ip", "cidr", "domain", "url"]), show_default=True)
@pass_context
def scope_add(ctx: AegisContext, target: str, kind: str) -> None:
    """Add a target to scope."""
    tid = ctx.scope.add_target(target, kind)
    console.print(f"[primary]Scope entry added:[/primary] id={tid}  {kind}:{target}")


@scope_group.command("remove")
@click.argument("target_id", type=int)
@pass_context
def scope_remove(ctx: AegisContext, target_id: int) -> None:
    """Remove a scope entry by id."""
    ctx.scope.remove_target(target_id)
    console.print(f"[primary]Scope entry {target_id} removed.[/primary]")


@scope_group.command("list")
@pass_context
def scope_list(ctx: AegisContext) -> None:
    """List all scope entries."""
    entries = ctx.scope.list_targets()
    table = Table(title="Scope")
    table.add_column("ID", style="cyan")
    table.add_column("Kind", style="magenta")
    table.add_column("Target", style="green")
    for e in entries:
        table.add_row(str(e.id), e.kind, e.target)
    console.print(table)


# ─── workspace ────────────────────────────────────────────────────────────────

@cli.group("workspace")
@click.pass_context
def workspace_group(ctx: click.Context) -> None:
    """Manage workspaces."""


@workspace_group.command("create")
@click.argument("name")
@click.pass_context
def workspace_create(ctx: click.Context, name: str) -> None:
    """Create a new workspace."""
    aegis_ctx: Optional[AegisContext] = ctx.find_object(AegisContext)
    if aegis_ctx is None:
        return
    root_db = DatabaseManager(aegis_ctx.config.get("general.db_path", "data/aegis.db"))
    root_db.init_db()
    ws = WorkspaceManager(root_db).create(name)
    console.print(f"[primary]Workspace created:[/primary] {ws.name}  db={ws.db_path}")


@workspace_group.command("switch")
@click.argument("name")
@click.pass_context
def workspace_switch(ctx: click.Context, name: str) -> None:
    """Switch active workspace."""
    aegis_ctx: Optional[AegisContext] = ctx.find_object(AegisContext)
    if aegis_ctx is None:
        return
    root_db = DatabaseManager(aegis_ctx.config.get("general.db_path", "data/aegis.db"))
    root_db.init_db()
    ws = WorkspaceManager(root_db).switch(name)
    console.print(f"[primary]Active workspace:[/primary] {ws.name}")


@workspace_group.command("list")
@click.pass_context
def workspace_list(ctx: click.Context) -> None:
    """List all workspaces."""
    aegis_ctx: Optional[AegisContext] = ctx.find_object(AegisContext)
    if aegis_ctx is None:
        return
    root_db = DatabaseManager(aegis_ctx.config.get("general.db_path", "data/aegis.db"))
    root_db.init_db()
    workspaces = WorkspaceManager(root_db).list_workspaces()
    table = Table(title="Workspaces")
    table.add_column("Name", style="cyan")
    table.add_column("DB Path", style="magenta")
    for ws in workspaces:
        table.add_row(ws.name, ws.db_path)
    console.print(table)


@workspace_group.command("delete")
@click.argument("name")
@click.pass_context
def workspace_delete(ctx: click.Context, name: str) -> None:
    """Delete a workspace."""
    aegis_ctx: Optional[AegisContext] = ctx.find_object(AegisContext)
    if aegis_ctx is None:
        return
    root_db = DatabaseManager(aegis_ctx.config.get("general.db_path", "data/aegis.db"))
    root_db.init_db()
    WorkspaceManager(root_db).delete(name)
    console.print(f"[primary]Workspace deleted:[/primary] {name}")


# ─── notes ────────────────────────────────────────────────────────────────────

@cli.group("notes")
def notes_group() -> None:
    """Annotate findings with notes."""


@notes_group.command("add")
@click.argument("finding_id", type=int)
@click.argument("text")
@pass_context
def notes_add(ctx: AegisContext, finding_id: int, text: str) -> None:
    """Add a note to a finding."""
    nid = ctx.db.add_note(finding_id, text)
    console.print(f"[primary]Note added:[/primary] id={nid}")


@notes_group.command("list")
@click.argument("finding_id", type=int)
@pass_context
def notes_list(ctx: AegisContext, finding_id: int) -> None:
    """List notes for a finding."""
    notes = ctx.db.get_notes(finding_id)
    table = Table(title=f"Notes for finding {finding_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Body", style="white")
    table.add_column("Created", style="dim")
    for n in notes:
        table.add_row(str(n["id"]), n["body"], str(n.get("created_at", "")))
    console.print(table)


# ─── tag ──────────────────────────────────────────────────────────────────────

@cli.group("tag")
def tag_group() -> None:
    """Tag findings for triage."""


@tag_group.command("add")
@click.argument("finding_id", type=int)
@click.argument("label")
@pass_context
def tag_add(ctx: AegisContext, finding_id: int, label: str) -> None:
    """Add a tag to a finding."""
    tid = ctx.db.add_tag(finding_id, label)
    console.print(f"[primary]Tag added:[/primary] id={tid}  label={label}")


@tag_group.command("remove")
@click.argument("finding_id", type=int)
@click.argument("label")
@pass_context
def tag_remove(ctx: AegisContext, finding_id: int, label: str) -> None:
    """Remove a tag from a finding."""
    ctx.db.remove_tag(finding_id, label)
    console.print(f"[primary]Tag '{label}' removed from finding {finding_id}.[/primary]")


@tag_group.command("list")
@click.argument("finding_id", type=int)
@pass_context
def tag_list(ctx: AegisContext, finding_id: int) -> None:
    """List tags for a finding."""
    tags = ctx.db.get_tags(finding_id)
    table = Table(title=f"Tags for finding {finding_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Label", style="magenta")
    for t in tags:
        table.add_row(str(t["id"]), t["label"])
    console.print(table)


# ─── ai ───────────────────────────────────────────────────────────────────────

@cli.group("ai")
def ai_group() -> None:
    """AI-powered triage and analysis."""


def _get_ai(ctx: AegisContext) -> AIClient:
    return AIClient(ctx.config, ctx.db)


@ai_group.command("triage")
@click.option("--session", "session_id", default=None, type=int)
@click.option("--finding", "finding_id", default=None, type=int)
@pass_context
def ai_triage(ctx: AegisContext, session_id: Optional[int], finding_id: Optional[int]) -> None:
    """AI triage of findings."""
    if finding_id:
        findings = ctx.db.get_session_findings(session_id or 0)
        findings = [f for f in findings if f["id"] == finding_id] or findings[:1]
    elif session_id:
        findings = ctx.db.get_session_findings(session_id)
    else:
        findings = ctx.db.get_session_findings(0)
    if not findings:
        console.print("[warning]No findings to triage.[/warning]")
        return
    prompt = "Triage these security findings and provide remediation advice:\n" + "\n".join(
        f"- [{f.get('severity','?')}] {f.get('title','?')}: {f.get('description','')[:200]}" for f in findings
    )
    ai = _get_ai(ctx)
    try:
        result = ai.complete(prompt, "triage")
        from rich.panel import Panel
        console.print(Panel(result, title="AI Triage", border_style="bright_cyan"))
    except RuntimeError as e:
        console.print(f"[error]{e}[/error]")


@ai_group.command("summarize")
@click.option("--session", "session_id", default=None, type=int)
@pass_context
def ai_summarize(ctx: AegisContext, session_id: Optional[int]) -> None:
    """AI summary of a scan session."""
    findings = ctx.db.get_session_findings(session_id or 0)
    if not findings:
        console.print("[warning]No findings to summarize.[/warning]")
        return
    prompt = f"Summarize these {len(findings)} security findings concisely:\n" + "\n".join(
        f"- [{f.get('severity','?')}] {f.get('title','?')}" for f in findings
    )
    ai = _get_ai(ctx)
    try:
        result = ai.complete(prompt, "summarize")
        from rich.panel import Panel
        console.print(Panel(result, title="AI Summary", border_style="bright_cyan"))
    except RuntimeError as e:
        console.print(f"[error]{e}[/error]")


@ai_group.command("suggest")
@click.option("--target", required=True)
@pass_context
def ai_suggest(ctx: AegisContext, target: str) -> None:
    """AI attack surface suggestions for a target."""
    prompt = f"Suggest attack surface areas and testing approaches for target: {target}"
    ai = _get_ai(ctx)
    try:
        result = ai.complete(prompt, "suggest")
        from rich.panel import Panel
        console.print(Panel(result, title=f"AI Suggestions: {target}", border_style="bright_cyan"))
    except RuntimeError as e:
        console.print(f"[error]{e}[/error]")


@ai_group.command("report")
@click.option("--target", required=True)
@click.option("--format", "fmt", default="md", type=click.Choice(["md", "html", "pdf"]))
@pass_context
def ai_report(ctx: AegisContext, target: str, fmt: str) -> None:
    """Generate AI narrative report section."""
    prompt = f"Write a professional penetration test report narrative for target: {target}. Include executive summary, findings overview, and remediation recommendations."
    ai = _get_ai(ctx)
    try:
        result = ai.complete(prompt, "report")
        from rich.panel import Panel
        console.print(Panel(result, title=f"AI Report: {target}", border_style="bright_cyan"))
    except RuntimeError as e:
        console.print(f"[error]{e}[/error]")


@ai_group.command("chat")
@pass_context
def ai_chat(ctx: AegisContext) -> None:
    """Interactive AI chat about findings."""
    ai = _get_ai(ctx)
    console.print("[accent]AI Chat mode. Type 'exit' to quit.[/accent]")
    while True:
        try:
            user_input = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if user_input.lower() in ("exit", "quit", "q"):
            break
        if not user_input:
            continue
        try:
            result = ai.complete(user_input, "chat")
            console.print(f"[bright_cyan]{result}[/bright_cyan]")
        except RuntimeError as e:
            console.print(f"[error]{e}[/error]")
            break


@ai_group.command("auto")
@click.option("--target", required=True, help="Target host, IP, or CIDR.")
@click.option("--full", "full_run", is_flag=True, help="Run all 5 phases (default: recon + vuln).")
@click.option(
    "--format", "fmt",
    default="md",
    type=click.Choice(["md", "html", "pdf"]),
    show_default=True,
    help="Report output format.",
)
@click.option("--min-severity", default=None, help="Minimum severity for final report.")
@click.option("--dry-run", is_flag=True, help="Print planned tool invocations without executing.")
@pass_context
def ai_auto(
    ctx: AegisContext,
    target: str,
    full_run: bool,
    fmt: str,
    min_severity: Optional[str],
    dry_run: bool,
) -> None:
    """Autonomous AI-driven pentest: runs all phases end-to-end."""
    from aegis.core.ai_orchestrator import AIOrchestrator

    orchestrator = AIOrchestrator(
        target=target,
        config=ctx.config,
        db=ctx.db,
        scope=ctx.scope,
        full=full_run,
        dry_run=dry_run,
        report_format=fmt,
        min_severity=min_severity,
    )
    try:
        report_path = orchestrator.run()
        console.print(f"[primary]Autonomous run complete. Report:[/primary] {report_path}")
    except Exception as exc:
        console.print(f"[error]Autonomous run failed: {exc}[/error]")


# ─── notify ───────────────────────────────────────────────────────────────────

@cli.group("notify")
def notify_group() -> None:
    """Webhook notifications."""


@notify_group.command("test")
@click.option("--channel", default="both", type=click.Choice(["slack", "discord", "both"]))
@pass_context
def notify_test(ctx: AegisContext, channel: str) -> None:
    """Send a test notification."""
    notifier = Notifier(ctx.config)
    test_finding = [{"title": "Test Alert", "severity": "info", "description": "Aegis notification test."}]
    notifier.send_findings(test_finding, channel=channel)
    console.print(f"[primary]Test notification sent to {channel}.[/primary]")


@notify_group.command("send")
@click.option("--session", "session_id", required=True, type=int)
@click.option("--min-severity", default=None)
@click.option("--channel", default="both", type=click.Choice(["slack", "discord", "both"]))
@pass_context
def notify_send(ctx: AegisContext, session_id: int, min_severity: Optional[str], channel: str) -> None:
    """Send findings from a session as notifications."""
    findings = ctx.db.get_session_findings(session_id)
    notifier = Notifier(ctx.config)
    notifier.send_findings(findings, channel=channel, min_severity=min_severity)
    console.print(f"[primary]Notifications sent for session {session_id}.[/primary]")


# ─── watch ────────────────────────────────────────────────────────────────────

@cli.command("watch")
@click.option("--interval", default=3600, type=int, show_default=True)
@click.option("--min-severity", default="medium", show_default=True)
@click.option("--notify", "notify_channel", default=None, type=click.Choice(["slack", "discord", "both"]))
@pass_context
def watch_cmd(ctx: AegisContext, interval: int, min_severity: str, notify_channel: Optional[str]) -> None:
    """Continuously monitor in-scope targets."""
    notifier = Notifier(ctx.config) if notify_channel else None
    dedup = Deduplicator(ctx.db)
    console.print(f"[accent]Watch mode started. Interval: {interval}s  Min severity: {min_severity}[/accent]")
    try:
        while True:
            targets = [e.target for e in ctx.scope.list_targets()]
            if not targets:
                console.print("[warning]No scope targets defined. Add targets with 'aegis scope add'.[/warning]")
            else:
                console.print(f"[dim]Scanning {len(targets)} target(s)...[/dim]")
                # Placeholder: real scan pipeline would be invoked here
                new_findings: list[dict] = []
                truly_new = dedup.filter_new(new_findings)
                if truly_new and notifier:
                    notifier.send_findings(truly_new, channel=notify_channel or "both", min_severity=min_severity)
                    console.print(f"[accent]New findings: {len(truly_new)}[/accent]")
                else:
                    console.print("[dim]No new findings this iteration.[/dim]")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("[primary]Watch mode stopped.[/primary]")


# ─── timeline & compare ───────────────────────────────────────────────────────

@cli.command("timeline")
@click.option("--session", "session_id", default=None, type=int)
@click.option("--limit", default=50, show_default=True)
@pass_context
def timeline_cmd(ctx: AegisContext, session_id: Optional[int], limit: int) -> None:
    """Show scan session timeline."""
    sessions = ctx.db.get_scan_sessions(limit)
    table = Table(title="Scan Timeline")
    table.add_column("ID", style="cyan")
    table.add_column("Label", style="green")
    table.add_column("Started", style="magenta")
    table.add_column("Finished", style="dim")
    for s in sessions:
        table.add_row(str(s["id"]), str(s.get("label", "")), str(s.get("started_at", "")), str(s.get("finished_at", "")))
    console.print(table)


@cli.command("compare")
@click.argument("session_a", type=int)
@click.argument("session_b", type=int)
@pass_context
def compare_cmd(ctx: AegisContext, session_a: int, session_b: int) -> None:
    """Compare findings between two scan sessions."""
    findings_a = {f["title"]: f for f in ctx.db.get_session_findings(session_a)}
    findings_b = {f["title"]: f for f in ctx.db.get_session_findings(session_b)}
    new = [f for t, f in findings_b.items() if t not in findings_a]
    resolved = [f for t, f in findings_a.items() if t not in findings_b]
    persisting = [f for t, f in findings_b.items() if t in findings_a]
    table = Table(title=f"Compare sessions {session_a} vs {session_b}")
    table.add_column("Status", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="magenta")
    for f in new:
        table.add_row("[green]NEW[/green]", f["title"], str(f.get("severity", "")))
    for f in resolved:
        table.add_row("[yellow]RESOLVED[/yellow]", f["title"], str(f.get("severity", "")))
    for f in persisting:
        table.add_row("[red]PERSISTING[/red]", f["title"], str(f.get("severity", "")))
    console.print(table)


# ─── serve ────────────────────────────────────────────────────────────────────

@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
@pass_context
def serve_cmd(ctx: AegisContext, host: str, port: int) -> None:
    """Start the FastAPI web UI."""
    try:
        import uvicorn
        from aegis.web.app import app as web_app
        console.print(f"[primary]Starting web UI at http://{host}:{port}[/primary]")
        uvicorn.run(web_app, host=host, port=port)
    except ImportError:
        console.print("[error]uvicorn or aegis.web not available. Install with: pip install uvicorn[/error]")


# ─── interactive ──────────────────────────────────────────────────────────────

@cli.command("interactive")
@pass_context
def interactive_cmd(ctx: AegisContext) -> None:
    """Launch the Textual TUI."""
    try:
        from aegis.tui.app import AegisTUI
        AegisTUI(ctx.db).run()
    except ImportError:
        console.print("[error]Textual not available. Install with: pip install textual[/error]")


# ─── doctor ───────────────────────────────────────────────────────────────────

@cli.command("doctor")
@pass_context
@click.option("--fix", "fix_tools", is_flag=True, help="Auto-detect tool paths and save to config.")
@click.option("--force", "force_fix", is_flag=True, help="Overwrite existing paths even if already set.")
def doctor(ctx: AegisContext, fix_tools: bool, force_fix: bool) -> None:
    """Check configuration and external dependencies.

    Searches PATH, ~/go/bin, ~/.cargo/bin, .venv/bin, data/tools/,
    and common system locations — not just $PATH.
    """
    from aegis.core.tooling import tool_status

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
        console.print(f"[primary]Updated {len(detected)} tool path(s) in config.[/primary]")

    # Use tool_status for rich path-aware detection
    statuses = tool_status(tools)

    ok_count = sum(1 for s in statuses.values() if s["status"] == "ok")
    missing_count = len(statuses) - ok_count

    table = Table(title=f"External Tools  ({ok_count} found, {missing_count} missing)")
    table.add_column("Tool", style="cyan", min_width=14)
    table.add_column("Configured", style="dim", min_width=16)
    table.add_column("Resolved Path", style="magenta", min_width=30)
    table.add_column("Status", min_width=8)

    for name, info in statuses.items():
        status_str = "[green]ok[/green]" if info["status"] == "ok" else "[red]missing[/red]"
        resolved = info["path"] or "—"
        table.add_row(str(name), str(info["configured"]), resolved, status_str)

    console.print(table)

    if missing_count > 0:
        console.print(
            f"\n[yellow]{missing_count} tool(s) not found.[/yellow] "
            "Run [cyan]aegis doctor --fix[/cyan] to auto-detect paths, "
            "or [cyan]sudo bash install.sh[/cyan] to install everything."
        )

    key_table = Table(title="API Keys")
    key_table.add_column("Service", style="cyan")
    key_table.add_column("Configured", style="green")
    for name, value in api_keys.items():
        configured = bool(value) and value != "CHANGE_ME"
        key_table.add_row(str(name), "[green]yes[/green]" if configured else "[red]no[/red]")
    console.print(key_table)

    if ctx.json_out:
        emit_json({"tools": statuses, "api_keys": {k: (bool(v) and v != "CHANGE_ME") for k, v in api_keys.items()}}, ctx.json_output)


# ─── plugins ──────────────────────────────────────────────────────────────────

@cli.command("plugins")
def plugins() -> None:
    """List discovered plugins."""
    metadata = discover_manifests()
    table = Table(title="Discovered Plugins")
    table.add_column("Category", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Command", style="magenta")
    table.add_column("Description", style="white")
    for category, entries in metadata.items():
        for entry in entries:
            table.add_row(str(category), str(entry.get("name", "")), str(entry.get("command", "")), str(entry.get("description", "")))
    console.print(table)


# ─── pipeline helpers ─────────────────────────────────────────────────────────

def _invoke_pipeline(
    ctx: click.Context,
    domain: Optional[str],
    cidr: Optional[str],
    url: Optional[str],
    target_ip: Optional[str],
    full_run: bool,
    report_target: Optional[str],
) -> None:
    if domain:
        domain_cmd = recon.get_command(ctx, "domain")
        if domain_cmd:
            ctx.invoke(domain_cmd, domain_name=domain)
    if cidr:
        network_cmd = recon.get_command(ctx, "network")
        if network_cmd:
            ctx.invoke(network_cmd, cidr_range=cidr)
    if url:
        web_cmd = vuln.get_command(ctx, "web")
        if web_cmd:
            ctx.invoke(web_cmd, url=url)
    if target_ip:
        net_cmd = vuln.get_command(ctx, "net")
        if net_cmd:
            ctx.invoke(net_cmd, target_ip=target_ip)
    if full_run:
        target_name = report_target or domain or url or target_ip or cidr or "report"
        gen_cmd = report.get_command(ctx, "generate")
        if gen_cmd:
            ctx.invoke(gen_cmd, target=target_name)


@cli.command("run")
@click.option("--domain", default=None)
@click.option("--cidr", default=None)
@click.option("--url", default=None)
@click.option("--target-ip", default=None)
@click.option("--full", "full_run", is_flag=True)
@click.option("--report-target", default=None)
@click.pass_context
def run_pipeline(ctx: click.Context, domain: Optional[str], cidr: Optional[str], url: Optional[str], target_ip: Optional[str], full_run: bool, report_target: Optional[str]) -> None:
    """Run a basic pipeline across recon and vuln stages."""
    _invoke_pipeline(ctx, domain, cidr, url, target_ip, full_run, report_target)


# ─── setup / update ───────────────────────────────────────────────────────────

@cli.command("bootstrap")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation and install everything.")
@click.option("--dry-run", is_flag=True, help="Show what would be installed without doing it.")
@click.option("--skip-rust", is_flag=True, help="Skip Rust/Cargo installation (skips feroxbuster).")
@pass_context
def bootstrap_cmd(ctx: AegisContext, assume_yes: bool, dry_run: bool, skip_rust: bool) -> None:
    """One command to install ALL tools and dependencies. Requires root (sudo).

    Installs: apt packages, Go, Rust, subfinder, nuclei, trufflehog,
    gowitness, amass, feroxbuster, webtech, mcp, and sets up PATH.
    """
    from aegis.core.bootstrap import run_bootstrap

    if not dry_run and not assume_yes:
        console.print(
            "[bold yellow]This will install all Aegis dependencies system-wide.[/bold yellow]\n"
            "It requires [bold]root/sudo[/bold] privileges.\n"
        )
        try:
            answer = input("Continue? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[warning]Aborted.[/warning]")
            return
        if answer not in ("y", "yes"):
            console.print("[warning]Bootstrap cancelled.[/warning]")
            return

    summary = run_bootstrap(dry_run=dry_run, skip_rust=skip_rust)

    if ctx.json_out:
        emit_json({"bootstrap": summary}, ctx.json_output)


@cli.command("setup")
@click.option("--yes", "assume_yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--peas", "include_peas", is_flag=True)
@click.option("--fix-config", is_flag=True)
@pass_context
def setup_tools(ctx: AegisContext, assume_yes: bool, dry_run: bool, include_peas: bool, fix_config: bool) -> None:
    """Install external dependencies."""
    ok, reason = validate_environment()
    if not ok:
        console.print(f"[error]Setup not supported:[/error] {reason}")
        return
    if not assume_yes:
        if not click.confirm("Install external tools now?", default=False):
            console.print("[warning]Setup cancelled.[/warning]")
            return
    plan = build_install_plan(include_peas=include_peas)
    results = run_install_plan(plan, dry_run=dry_run)
    if fix_config and not dry_run:
        tools = ctx.config.get("external_tools", {}) or {}
        updated, _ = detect_external_tools(tools, force=True)
        config_data = ctx.config.load()
        config_data["external_tools"] = updated
        ctx.config.save(config_data)
    if ctx.json_out:
        emit_json({"setup": results}, ctx.json_output)


@cli.command("install-tools")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip prompts and install all tools.")
@click.option("--dry-run", is_flag=True, help="Print install commands without executing.")
@click.option("--peas", "include_peas", is_flag=True, help="Include PEAS privilege escalation scripts.")
@pass_context
def install_tools_cmd(ctx: AegisContext, assume_yes: bool, dry_run: bool, include_peas: bool) -> None:
    """Interactive per-tool installer with yes/no prompts."""
    import sys

    if not _is_linux_check():
        console.print("[error]install-tools supports Linux only.[/error]")
        sys.exit(1)

    plan = build_install_plan(include_peas=include_peas)
    results = run_install_plan_interactive(plan, assume_yes=assume_yes, dry_run=dry_run)

    # Print summary table
    from rich.table import Table as RichTable
    table = RichTable(title="Install Summary")
    table.add_column("Tool", style="cyan")
    table.add_column("Outcome", style="green")
    outcome_styles = {"ok": "green", "skipped": "yellow", "failed": "red", "dry-run": "blue"}
    for name, outcome in results.items():
        style = outcome_styles.get(outcome, "white")
        table.add_row(name, f"[{style}]{outcome}[/{style}]")
    console.print(table)

    if ctx.json_out:
        emit_json({"install_tools": results}, ctx.json_output)


@cli.command("uninstall")
@click.option("--remove-data", is_flag=True, help="Also delete the data/ directory (databases, reports, logs).")
@click.option("--remove-config", is_flag=True, help="Also delete config/config.yaml.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip confirmation prompt.")
@click.option("--dry-run", is_flag=True, help="Show what would be removed without doing it.")
@pass_context
def uninstall_cmd(ctx: AegisContext, remove_data: bool, remove_config: bool, assume_yes: bool, dry_run: bool) -> None:
    """Uninstall Aegis and its installed tools from the system."""
    from aegis.core.installer import run_uninstall

    if not dry_run and not assume_yes:
        console.print("[bold red]This will remove Aegis and its installed tools.[/bold red]")
        if remove_data:
            console.print("[bold red]  -- data/ directory will be deleted (all databases and reports)[/bold red]")
        if remove_config:
            console.print("[bold red]  -- config/config.yaml will be deleted[/bold red]")
        try:
            answer = input("Continue? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[warning]Aborted.[/warning]")
            return
        if answer not in ("y", "yes"):
            console.print("[warning]Uninstall cancelled.[/warning]")
            return

    results = run_uninstall(
        remove_data=remove_data,
        remove_config=remove_config,
        dry_run=dry_run,
    )

    from rich.table import Table as RichTable
    table = RichTable(title="Uninstall Summary")
    table.add_column("Component", style="cyan")
    table.add_column("Outcome", style="green")
    outcome_styles = {"ok": "green", "skipped": "yellow", "failed": "red", "dry-run": "blue"}
    for name, outcome in results.items():
        style = outcome_styles.get(outcome, "white")
        table.add_row(name, f"[{style}]{outcome}[/{style}]")
    console.print(table)

    if not dry_run:
        console.print("[primary]Aegis uninstalled. Goodbye.[/primary]")

    if ctx.json_out:
        emit_json({"uninstall": results}, ctx.json_output)


@cli.command("update")
@click.option("--nuclei", "nuclei_update", is_flag=True)
@click.option("--wordlists", is_flag=True)
@click.option("--all", "update_all", is_flag=True)
@click.option("--status", "show_status", is_flag=True)
@pass_context
def update_signatures(ctx: AegisContext, nuclei_update: bool, wordlists: bool, update_all: bool, show_status: bool) -> None:
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
        results["wordlists"] = update_wordlists(str(repo), str(dest)) if repo else {"status": "failed", "error": "wordlists_repo not set"}
    if ctx.json_out:
        emit_json({"updates": results}, ctx.json_output)
        return
    print_update_summary(results)


# ─── campaign ─────────────────────────────────────────────────────────────────

@cli.group("campaign")
def campaign_group() -> None:
    """Manage scan campaigns."""


@campaign_group.command("create")
@click.argument("name")
@click.option("--domain", default=None)
@click.option("--cidr", default=None)
@click.option("--url", default=None)
@click.option("--target-ip", default=None)
def campaign_create(name: str, domain: Optional[str], cidr: Optional[str], url: Optional[str], target_ip: Optional[str]) -> None:
    targets = {"domain": domain, "cidr": cidr, "url": url, "target_ip": target_ip}
    if not any(targets.values()):
        console.print("[warning]Provide at least one target option.[/warning]")
        return
    clean_targets: dict[str, str] = {k: v for k, v in targets.items() if v is not None}
    create_campaign(name, clean_targets)
    console.print(f"[primary]Campaign created:[/primary] {name}")


@campaign_group.command("list")
def campaign_list() -> None:
    campaigns = list_campaigns()
    table = Table(title="Campaigns")
    table.add_column("Name", style="cyan")
    table.add_column("Targets", style="magenta")
    table.add_column("Runs", style="green")
    for item in campaigns:
        table.add_row(str(item.get("name")), str(item.get("targets")), str(item.get("runs")))
    console.print(table)


@campaign_group.command("run")
@click.argument("name")
@click.option("--full", "full_run", is_flag=True)
@click.option("--report-target", default=None)
@click.pass_context
def campaign_run(ctx: click.Context, name: str, full_run: bool, report_target: Optional[str]) -> None:
    data = list_campaigns()
    campaign = next((c for c in data if c["name"] == name), None)
    if not campaign:
        console.print(f"[error]Campaign not found:[/error] {name}")
        return
    targets = campaign.get("targets", {})
    _invoke_pipeline(ctx, domain=targets.get("domain"), cidr=targets.get("cidr"), url=targets.get("url"), target_ip=targets.get("target_ip"), full_run=full_run, report_target=report_target)
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


@campaign_group.command("add-target")
@click.argument("name")
@click.argument("target")
@click.option("--kind", default="domain", type=click.Choice(["domain", "ip", "cidr", "url"]), show_default=True)
@pass_context
def campaign_add_target(ctx: AegisContext, name: str, target: str, kind: str) -> None:
    """Add a target to an existing campaign."""
    tid = ctx.db.add_campaign_target(name, target, kind)
    console.print(f"[primary]Target added to campaign '{name}':[/primary] id={tid}  {kind}:{target}")


@campaign_group.command("run-parallel")
@click.argument("name")
@click.option("--targets", "targets_file", required=True, help="File with one target per line.")
@click.option("--max-parallel", default=3, show_default=True, type=int)
@click.option("--phases", "phases_str", default="recon,vuln", show_default=True, help="Comma-separated phases.")
@click.option("--dry-run", is_flag=True)
@pass_context
def campaign_run_parallel(
    ctx: AegisContext,
    name: str,
    targets_file: str,
    max_parallel: int,
    phases_str: str,
    dry_run: bool,
) -> None:
    """Run parallel scans against multiple targets from a file."""
    from pathlib import Path as _Path
    from aegis.core.campaign_runner import CampaignRunner, CampaignTarget

    targets_path = _Path(targets_file)
    if not targets_path.exists():
        console.print(f"[error]Targets file not found:[/error] {targets_file}")
        return

    raw_lines = targets_path.read_text(encoding="utf-8").splitlines()
    targets: list[CampaignTarget] = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Detect kind
        if "/" in line and not line.startswith("http"):
            kind = "cidr"
        elif line.startswith("http"):
            kind = "url"
        elif any(c.isalpha() for c in line.split(".")[-1]):
            kind = "domain"
        else:
            kind = "ip"
        targets.append(CampaignTarget(target=line, kind=kind))

    if not targets:
        console.print("[warning]No targets found in file.[/warning]")
        return

    phases = [p.strip() for p in phases_str.split(",") if p.strip()]
    runner = CampaignRunner(
        config=ctx.config,
        db=ctx.db,
        scope=ctx.scope,
        max_parallel=max_parallel,
        phases=phases,
        dry_run=dry_run,
    )

    console.print(f"[accent]Running parallel campaign '{name}' against {len(targets)} targets (max_parallel={max_parallel})...[/accent]")
    run = runner.run(name, targets)

    table = Table(title=f"Campaign '{name}' Results")
    table.add_column("Target", style="cyan")
    table.add_column("Session", style="magenta")
    table.add_column("Findings", style="green")
    table.add_column("Duration", style="dim")
    table.add_column("Error", style="red")
    for result in run.results:
        table.add_row(
            result.target,
            str(result.session_id),
            str(result.findings_count),
            f"{result.duration_seconds:.1f}s",
            result.error or "",
        )
    console.print(table)
    console.print(f"[primary]Total findings:[/primary] {run.total_findings}")


# ─── burp ─────────────────────────────────────────────────────────────────────

@cli.group("burp")
def burp_group() -> None:
    """Burp Suite integration."""


@burp_group.command("import")
@click.argument("xml_file")
@click.option("--dry-run", is_flag=True, help="Preview without importing.")
@pass_context
def burp_import_cmd(ctx: AegisContext, xml_file: str, dry_run: bool) -> None:
    """Import findings from a Burp Suite XML export."""
    from aegis.core.burp_importer import import_burp_xml

    if dry_run:
        console.print(f"[accent]DRY RUN — parsing {xml_file}...[/accent]")
    else:
        console.print(f"[accent]Importing {xml_file}...[/accent]")

    counts = import_burp_xml(xml_file, ctx.db, dry_run=dry_run)
    table = Table(title="Burp Import Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")
    for key, val in counts.items():
        table.add_row(key, str(val))
    console.print(table)


@burp_group.command("list")
@pass_context
def burp_list_cmd(ctx: AegisContext) -> None:
    """List all Burp-imported findings."""
    conn = ctx.db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE source = 'burp' ORDER BY created_at DESC")
    findings = [dict(row) for row in cursor.fetchall()]
    table = Table(title="Burp Findings")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="magenta")
    table.add_column("Created", style="dim")
    for f in findings:
        table.add_row(str(f["id"]), str(f["title"]), str(f.get("severity", "")), str(f.get("created_at", "")))
    console.print(table)


# ─── cve ──────────────────────────────────────────────────────────────────────

@cli.group("cve")
def cve_group() -> None:
    """CVE correlation via NVD."""


@cve_group.command("correlate")
@click.option("--session", "session_id", default=None, type=int)
@pass_context
def cve_correlate_cmd(ctx: AegisContext, session_id: Optional[int]) -> None:
    """Correlate findings with CVEs from NVD."""
    from aegis.core.cve_correlator import correlate_all_findings

    api_key = str(ctx.config.get("api_keys.nvd", "") or "")
    console.print("[accent]Correlating findings with NVD CVEs...[/accent]")
    results = correlate_all_findings(ctx.db, session_id=session_id, api_key=api_key or None)
    total_cves = sum(len(v) for v in results.values())
    console.print(f"[primary]Correlated {len(results)} findings, found {total_cves} CVE matches.[/primary]")


@cve_group.command("search")
@click.argument("keyword")
@click.option("--max", "max_results", default=5, show_default=True, type=int)
@pass_context
def cve_search_cmd(ctx: AegisContext, keyword: str, max_results: int) -> None:
    """Search NVD directly for CVEs matching a keyword."""
    from aegis.core.cve_correlator import search_cve

    api_key = str(ctx.config.get("api_keys.nvd", "") or "")
    console.print(f"[accent]Searching NVD for:[/accent] {keyword}")
    matches = search_cve(keyword, max_results=max_results, api_key=api_key or None)
    if not matches:
        console.print("[warning]No CVEs found.[/warning]")
        return
    table = Table(title=f"CVE Search: {keyword}")
    table.add_column("CVE ID", style="cyan")
    table.add_column("CVSS", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Published", style="dim")
    table.add_column("Description", style="white")
    for m in matches:
        table.add_row(
            m.cve_id,
            str(m.cvss_score or "N/A"),
            m.severity,
            m.published[:10] if m.published else "",
            m.description[:80] + "..." if len(m.description) > 80 else m.description,
        )
    console.print(table)


@cve_group.command("list")
@click.option("--finding", "finding_id", required=True, type=int)
@pass_context
def cve_list_cmd(ctx: AegisContext, finding_id: int) -> None:
    """List CVEs linked to a finding."""
    cves = ctx.db.get_cve_correlations(finding_id)
    if not cves:
        console.print(f"[warning]No CVEs linked to finding {finding_id}.[/warning]")
        return
    table = Table(title=f"CVEs for finding {finding_id}")
    table.add_column("CVE ID", style="cyan")
    table.add_column("CVSS", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("URL", style="blue")
    for c in cves:
        table.add_row(
            str(c["cve_id"]),
            str(c.get("cvss_score") or "N/A"),
            str(c.get("severity", "")),
            str(c.get("url", "")),
        )
    console.print(table)


# ─── sarif ────────────────────────────────────────────────────────────────────

@cli.group("sarif")
def sarif_group() -> None:
    """SARIF export for GitHub Code Scanning."""


@sarif_group.command("export")
@click.option("--session", "session_id", default=None, type=int)
@click.option("--output", "output_path", default=None, help="Output file path.")
@pass_context
def sarif_export_cmd(ctx: AegisContext, session_id: Optional[int], output_path: Optional[str]) -> None:
    """Export findings as SARIF v2.1.0."""
    from aegis.core.sarif_exporter import export_sarif_file
    from pathlib import Path as _Path

    if not output_path:
        from datetime import datetime as _dt
        ts = _dt.utcnow().strftime("%Y%m%dT%H%M%S")
        suffix = f"session{session_id}" if session_id else "all"
        output_path = f"data/reports/aegis-{suffix}-{ts}.sarif"

    _Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    path = export_sarif_file(ctx.db, output_path, session_id=session_id)
    console.print(f"[primary]SARIF exported:[/primary] {path}")


# ─── template ─────────────────────────────────────────────────────────────────

@cli.group("template")
def template_group() -> None:
    """Manage report templates."""


@template_group.command("list")
def template_list_cmd() -> None:
    """List available report templates."""
    from aegis.core.template_manager import TemplateManager

    tm = TemplateManager()
    templates = tm.list_templates()
    table = Table(title="Report Templates")
    table.add_column("Name", style="cyan")
    table.add_column("Kind", style="magenta")
    table.add_column("Available", style="green")
    table.add_column("Path", style="dim")
    for t in templates:
        table.add_row(
            t["name"],
            t["kind"],
            "yes" if t["available"] else "no",
            str(t.get("path") or ""),
        )
    console.print(table)


@template_group.command("install")
@click.argument("path")
@click.option("--name", required=True, help="Template name.")
def template_install_cmd(path: str, name: str) -> None:
    """Install a custom template from a file."""
    from aegis.core.template_manager import TemplateManager

    tm = TemplateManager()
    try:
        dest = tm.install_template(path, name)
        console.print(f"[primary]Template installed:[/primary] {name} → {dest}")
    except FileNotFoundError as exc:
        console.print(f"[error]{exc}[/error]")


@template_group.command("validate")
@click.argument("path")
def template_validate_cmd(path: str) -> None:
    """Validate a template file."""
    from aegis.core.template_manager import TemplateManager

    tm = TemplateManager()
    valid, msg = tm.validate_template(path)
    if valid:
        console.print(f"[primary]Valid:[/primary] {msg}")
    else:
        console.print(f"[error]Invalid:[/error] {msg}")


# ─── api ──────────────────────────────────────────────────────────────────────

@cli.group("api")
def api_group() -> None:
    """REST API server."""


@api_group.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8888, show_default=True, type=int)
@pass_context
def api_serve_cmd(ctx: AegisContext, host: str, port: int) -> None:
    """Start the Aegis REST API server."""
    try:
        import uvicorn
        from aegis.api.app import app as rest_app, configure as api_configure

        api_configure(ctx.config, ctx.db)
        console.print(f"[primary]Starting REST API at http://{host}:{port}[/primary]")
        uvicorn.run(rest_app, host=host, port=port)
    except ImportError:
        console.print("[error]uvicorn not available. Install with: pip install uvicorn[/error]")


# ─── tool groups ──────────────────────────────────────────────────────────────

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


# ─── help ─────────────────────────────────────────────────────────────────────

@cli.command("help")
@click.argument("topic", required=False, default=None)
def help_cmd(topic: Optional[str]) -> None:
    """Show detailed help. Use 'aegis help <topic>' for a specific section.

    Topics: recon, vuln, exploit, post, ai, report, workflow, config, install
    """
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule

    if topic:
        _show_topic_help(topic.lower())
        return

    # ── Main help overview ────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold bright_green] AEGIS — Command Reference [/bold bright_green]", style="bright_green"))
    console.print()

    # Global flags
    t = Table(title="Global Flags (apply to every command)", border_style="dim green", show_header=True)
    t.add_column("Flag", style="bright_cyan", min_width=22)
    t.add_column("Default", style="dim white", min_width=20)
    t.add_column("Description", style="white")
    t.add_row("--config PATH",    "config/config.yaml", "Path to config file")
    t.add_row("--profile NAME",   "default",            "Scan profile (default/fast/deep/stealth)")
    t.add_row("--workspace NAME", "active workspace",   "Override active workspace for this command")
    t.add_row("--json",           "off",                "Print all output as JSON")
    t.add_row("--json-output FILE","—",                 "Write JSON output to a file")
    t.add_row("--debug",          "off",                "Enable verbose debug logging")
    console.print(t)
    console.print()

    # Command groups
    groups = [
        ("recon",     "bright_green",  "Information gathering",
         [
             ("domain <domain>",          "Subdomain enum + Shodan + tech detection"),
             ("network <cidr>",           "Nmap ping sweep + port scan"),
             ("dns <domain>",             "DNS record enumeration (A/MX/TXT/NS/CNAME)"),
             ("osint <target>",           "Emails, LinkedIn, GitHub dorks via theHarvester"),
             ("cloud <domain>",           "S3 / Azure Blob / GCP Storage bucket discovery"),
             ("secrets <path|url>",       "API key & credential scanning via trufflehog"),
             ("screenshot <url>",         "Web service screenshots via gowitness"),
             ("ad <dc_ip> --domain ...",  "Active Directory: BloodHound + ldapdomaindump + CME"),
         ]),
        ("vuln",      "bright_cyan",   "Vulnerability scanning",
         [
             ("web <url>",                "Nuclei + feroxbuster + HTTP evidence capture"),
             ("net <ip>",                 "Hydra brute-force + SMB enum + WAF detection"),
             ("ssl <host>",               "SSL/TLS analysis via testssl.sh"),
             ("api <url>",                "API endpoint fuzzing via ffuf"),
             ("smuggling <url>",          "HTTP request smuggling (CL.TE / TE.CL / TE.TE)"),
         ]),
        ("exploit",   "bold red",      "Exploitation",
         [
             ("web <url>",                "SQLmap + reflected XSS testing"),
             ("net <ip>",                 "Hydra brute-force + netcat listener"),
             ("lfi <url>",                "Local File Inclusion testing (9 payloads)"),
             ("ssrf <url>",               "SSRF parameter injection testing"),
             ("oob <url>",                "OOB SSRF/XXE via interactsh DNS callback"),
             ("msf <target>",             "Metasploit: auto-map findings → MSF modules"),
         ]),
        ("post",      "yellow",        "Post-exploitation",
         [
             ("shell <ip>",               "LinPEAS/WinPEAS enumeration + privesc hints"),
             ("creds --target <ip>",      "SMB share enumeration + credential file scanning"),
             ("pivoting <net> --ssh ...", "SOCKS5 proxy + port forward + internal scan"),
         ]),
        ("ai",        "bright_magenta","AI-powered analysis",
         [
             ("auto --target <host>",     "Full autonomous pentest: recon→vuln→exploit→report"),
             ("triage --session <id>",    "AI triage of findings with remediation advice"),
             ("summarize --session <id>", "Executive summary of a scan session"),
             ("suggest --target <host>",  "Attack surface suggestions for a target"),
             ("report --target <host>",   "AI-written pentest report narrative"),
             ("chat",                     "Interactive AI chat about findings"),
         ]),
        ("report",    "bright_white",  "Reporting & export",
         [
             ("generate <target>",        "Generate report (--format md|html|pdf)"),
             ("export",                   "Export findings as JSON"),
         ]),
    ]

    for group_name, color, desc, commands in groups:
        t = Table(
            title=f"[bold {color}]aegis {group_name}[/bold {color}]  —  {desc}",
            border_style="dim green",
            show_header=True,
            min_width=70,
        )
        t.add_column("Command", style=color, min_width=32)
        t.add_column("What it does", style="white")
        for cmd, what in commands:
            t.add_row(f"aegis {group_name} {cmd}", what)
        console.print(t)
        console.print()

    # Other top-level commands
    t = Table(title="Other Commands", border_style="dim green", show_header=True)
    t.add_column("Command", style="bright_cyan", min_width=32)
    t.add_column("What it does", style="white")
    rows = [
        ("aegis doctor",                  "Check all tools and API keys are configured"),
        ("aegis doctor --fix",            "Auto-detect tool paths and save to config"),
        ("aegis scope add <target>",      "Add a target to scope (domain/ip/cidr/url)"),
        ("aegis scope list",              "List all in-scope targets"),
        ("aegis workspace create <name>", "Create a new isolated engagement workspace"),
        ("aegis workspace switch <name>", "Switch active workspace"),
        ("aegis bootstrap --yes",         "Install ALL tools automatically (requires sudo)"),
        ("aegis install-tools --yes",     "Interactive tool installer"),
        ("aegis uninstall",               "Remove Aegis and installed tools"),
        ("aegis cve correlate",           "Correlate findings with NVD CVE database"),
        ("aegis sarif export",            "Export findings as SARIF for GitHub Code Scanning"),
        ("aegis burp import <file>",      "Import findings from Burp Suite XML export"),
        ("aegis notify test",             "Send test notification to Slack/Discord"),
        ("aegis campaign create <name>",  "Create a multi-target scan campaign"),
        ("aegis serve",                   "Start the FastAPI web UI"),
        ("aegis help <topic>",            "Detailed help for a topic"),
    ]
    for cmd, what in rows:
        t.add_row(cmd, what)
    console.print(t)
    console.print()

    console.print(
        Panel(
            "[dim white]For topic-specific help:[/dim white]\n"
            "  [bright_cyan]aegis help workflow[/bright_cyan]   — step-by-step pentest workflow\n"
            "  [bright_cyan]aegis help config[/bright_cyan]     — configuration reference\n"
            "  [bright_cyan]aegis help install[/bright_cyan]    — installation guide\n"
            "  [bright_cyan]aegis help recon[/bright_cyan]      — recon module deep-dive\n"
            "  [bright_cyan]aegis help ai[/bright_cyan]         — AI features guide",
            title="[bold bright_green] Tips [/bold bright_green]",
            border_style="bright_green",
            padding=(0, 2),
        )
    )
    console.print()


def _show_topic_help(topic: str) -> None:
    """Show detailed help for a specific topic."""
    topics: dict = {
        "workflow": _help_workflow,
        "config":   _help_config,
        "install":  _help_install,
        "recon":    _help_recon,
        "ai":       _help_ai,
        "vuln":     _help_vuln,
        "exploit":  _help_exploit,
        "post":     _help_post,
    }

    fn = topics.get(topic)
    if fn:
        fn()
    else:
        console.print(f"[yellow]Unknown topic: {topic}[/yellow]")
        console.print(f"Available topics: {', '.join(topics.keys())}")


def _help_workflow() -> None:
    from rich.rule import Rule
    console.print()
    console.print(Rule("[bold bright_green] Pentest Workflow [/bold bright_green]", style="bright_green"))
    console.print("""
[bold bright_cyan]Step 1 — Set up workspace and scope[/bold bright_cyan]
  aegis workspace create client-acme
  aegis workspace switch client-acme
  aegis scope add acme.com --kind domain
  aegis scope add 10.10.0.0/24 --kind cidr

[bold bright_cyan]Step 2 — Recon[/bold bright_cyan]
  aegis recon domain acme.com          # subdomains, tech stack, Shodan
  aegis recon network 10.10.0.0/24     # live hosts, open ports
  aegis recon osint acme.com --emails  # emails, LinkedIn, GitHub leaks
  aegis recon cloud acme.com           # exposed S3/Azure/GCP buckets
  aegis recon secrets /path/to/repo    # API keys in code

[bold bright_cyan]Step 3 — Vulnerability scanning[/bold bright_cyan]
  aegis vuln web https://acme.com      # Nuclei + directory scan
  aegis vuln net 10.10.0.5             # WAF detection + SMB + brute-force
  aegis vuln ssl acme.com              # SSL/TLS issues
  aegis vuln smuggling https://acme.com # HTTP request smuggling

[bold bright_cyan]Step 4 — Exploitation[/bold bright_cyan]
  aegis exploit web https://acme.com --force   # SQLi + XSS
  aegis exploit lfi https://acme.com/page?f=   # LFI testing
  aegis exploit oob https://acme.com --force   # OOB SSRF/XXE
  aegis exploit msf 10.10.0.5 --force          # Metasploit auto-exploit

[bold bright_cyan]Step 5 — Post-exploitation[/bold bright_cyan]
  aegis post creds --target 10.10.0.5 --deep   # credential hunting
  aegis post pivoting 10.0.0.0/24 --ssh user@10.10.0.5 --scan

[bold bright_cyan]Step 6 — Report[/bold bright_cyan]
  aegis ai triage --session 1
  aegis cve correlate --session 1
  aegis report generate acme.com --format html
  aegis sarif export --session 1 --output results.sarif

[bold bright_cyan]OR — Do everything in one command:[/bold bright_cyan]
  [bold yellow]aegis ai auto --target acme.com --full --format html[/bold yellow]
""")


def _help_config() -> None:
    from rich.rule import Rule
    console.print()
    console.print(Rule("[bold bright_green] Configuration Reference [/bold bright_green]", style="bright_green"))
    console.print("""
[bold white]File:[/bold white] [bright_cyan]config/config.yaml[/bright_cyan]

[bold bright_cyan]general:[/bold bright_cyan]
  db_path: data/aegis.db          [dim]# SQLite (default) or postgresql://user:pass@host/db[/dim]
  safe_mode: true                 [dim]# abort if target is out of scope[/dim]
  wordlists_path: data/wordlists

[bold bright_cyan]api_keys:[/bold bright_cyan]
  shodan: CHANGE_ME               [dim]# https://shodan.io (free tier)[/dim]
  openrouter: CHANGE_ME           [dim]# https://openrouter.ai (free tier) — for AI features[/dim]
  bytez: CHANGE_ME                [dim]# https://bytez.com (free tier) — for AI features[/dim]
  nvd: CHANGE_ME                  [dim]# https://nvd.nist.gov (free) — for CVE correlation[/dim]

[bold bright_cyan]profiles:[/bold bright_cyan]
  default:  timeout=30, nmap="-sC -sV", nuclei_rate=150
  fast:     timeout=10, nmap="-sS",     nuclei_rate=300
  deep:     timeout=90, nmap="-sC -sV -A -O --script=vuln"
  stealth:  timeout=120, nmap="-sS -T2 --randomize-hosts"

[bold bright_cyan]notifications:[/bold bright_cyan]
  slack_webhook: ""               [dim]# https://api.slack.com/messaging/webhooks[/dim]
  discord_webhook: ""             [dim]# Discord channel webhook URL[/dim]

[bold white]Switch profile:[/bold white]  aegis --profile stealth vuln web https://example.com
[bold white]Auto-detect tools:[/bold white]  aegis doctor --fix
""")


def _help_install() -> None:
    from rich.rule import Rule
    console.print()
    console.print(Rule("[bold bright_green] Installation Guide [/bold bright_green]", style="bright_green"))
    console.print("""
[bold bright_cyan]Option 1 — One command (recommended for Kali Linux):[/bold bright_cyan]
  git clone https://github.com/thecnical/aegis.git
  cd aegis
  sudo bash install.sh

[bold bright_cyan]Option 2 — Bootstrap (if Aegis already installed):[/bold bright_cyan]
  sudo aegis bootstrap --yes
  sudo aegis bootstrap --yes --skip-rust   [dim]# skip feroxbuster[/dim]
  aegis bootstrap --dry-run                [dim]# preview only[/dim]

[bold bright_cyan]Option 3 — Manual:[/bold bright_cyan]
  sudo apt update && sudo apt install -y python3-pip python3-venv git
  git clone https://github.com/thecnical/aegis.git && cd aegis
  python3 -m venv .venv && source .venv/bin/activate
  pip install -e .
  aegis install-tools --yes

[bold bright_cyan]After install:[/bold bright_cyan]
  source ~/.zshrc          [dim]# reload PATH for Go/Cargo tools[/dim]
  aegis doctor             [dim]# verify all tools found[/dim]
  aegis doctor --fix       [dim]# auto-detect tool paths[/dim]

[bold bright_cyan]External tools installed automatically:[/bold bright_cyan]
  apt:    nmap, sqlmap, nikto, whatweb, ffuf, hydra, smbclient
  go:     subfinder, nuclei, trufflehog, gowitness, amass
  cargo:  feroxbuster
  pip:    webtech, mcp
""")


def _help_recon() -> None:
    from rich.rule import Rule
    console.print()
    console.print(Rule("[bold bright_green] Recon Module [/bold bright_green]", style="bright_green"))
    console.print("""
[bold bright_cyan]aegis recon domain <domain>[/bold bright_cyan]
  Subdomain enumeration (subfinder), Shodan passive ports, tech detection (webtech/whatweb)
  Options: --no-subdomains  --no-shodan  --no-techdetect  --json

[bold bright_cyan]aegis recon network <cidr>[/bold bright_cyan]
  Nmap ping sweep to find live hosts, optional full port scan
  Options: --ping-only  --port-scan  --json

[bold bright_cyan]aegis recon dns <domain>[/bold bright_cyan]
  Query DNS records: A, MX, TXT, NS, CNAME, AAAA
  Options: --types A,MX,TXT

[bold bright_cyan]aegis recon osint <target>[/bold bright_cyan]
  theHarvester: emails, hosts, IPs, LinkedIn profiles, GitHub dorks
  Options: --emails  --github-dorks  --linkedin  --sources google,bing,crtsh

[bold bright_cyan]aegis recon cloud <domain>[/bold bright_cyan]
  Discover exposed S3 buckets, Azure Blob containers, GCP Storage buckets
  Options: --no-s3  --no-azure  --no-gcp  --wordlist <file>

[bold bright_cyan]aegis recon secrets <path|url>[/bold bright_cyan]
  trufflehog: scan for API keys, tokens, credentials in files or git repos
  Options: --mode filesystem|git  --timeout 120

[bold bright_cyan]aegis recon screenshot <url>[/bold bright_cyan]
  gowitness: screenshot web services, save to data/screenshots/
  Options: --from-db  --out-dir  --timeout

[bold bright_cyan]aegis recon ad <dc_ip> --domain <domain>[/bold bright_cyan]
  Active Directory: anonymous enum (rpcclient), ldapdomaindump, bloodhound-python, CME
  Options: --username  --password  --no-bloodhound  --no-ldap  --no-cme
""")


def _help_ai() -> None:
    from rich.rule import Rule
    console.print()
    console.print(Rule("[bold bright_green] AI Features [/bold bright_green]", style="bright_green"))
    console.print("""
[bold bright_cyan]aegis ai auto --target <host>[/bold bright_cyan]
  Full autonomous pentest. Real agentic loop:
    1. Nmap → parse hosts/ports/services
    2. AI reads services → selects tools
    3. Nuclei/feroxbuster → parse structured findings
    4. AI generates payloads → sends HTTP requests → checks responses
    5. AI writes executive summary → generates report

  Options: --full (all 5 phases)  --format md|html|pdf  --dry-run  --min-severity

[bold bright_cyan]aegis ai triage --session <id>[/bold bright_cyan]
  AI reads all findings from a session and provides remediation advice

[bold bright_cyan]aegis ai summarize --session <id>[/bold bright_cyan]
  3-sentence executive summary of a scan session

[bold bright_cyan]aegis ai suggest --target <host>[/bold bright_cyan]
  AI suggests attack surface areas and testing approaches

[bold bright_cyan]aegis ai chat[/bold bright_cyan]
  Interactive AI chat — ask anything about your findings

[bold bright_cyan]AI providers (free tiers):[/bold bright_cyan]
  OpenRouter: https://openrouter.ai/keys
  Bytez:      https://bytez.com
  Add keys to config/config.yaml under api_keys
""")


def _help_vuln() -> None:
    from rich.rule import Rule
    console.print()
    console.print(Rule("[bold bright_green] Vuln Module [/bold bright_green]", style="bright_green"))
    console.print("""
[bold bright_cyan]aegis vuln web <url>[/bold bright_cyan]
  Nuclei template scan + feroxbuster directory scan + HTTP evidence capture
  Options: --no-dir-scan  --no-nuclei  --cookies "session=abc"  --header "Auth: Bearer TOKEN"  --tags cve,sqli

[bold bright_cyan]aegis vuln net <ip>[/bold bright_cyan]
  WAF detection + SMB share enumeration + Hydra brute-force
  Options: --service ssh|ftp|mysql|all  --userlist  --passlist  --url  --force

[bold bright_cyan]aegis vuln ssl <host>[/bold bright_cyan]
  testssl.sh: comprehensive SSL/TLS analysis
  Options: --port 443

[bold bright_cyan]aegis vuln api <url>[/bold bright_cyan]
  ffuf: API endpoint fuzzing with wordlist
  Options: --wordlist <path>

[bold bright_cyan]aegis vuln smuggling <url>[/bold bright_cyan]
  Raw socket HTTP request smuggling: CL.TE, TE.CL, TE.TE (obfuscated)
  Options: --path /  --timeout 15
""")


def _help_exploit() -> None:
    from rich.rule import Rule
    console.print()
    console.print(Rule("[bold bright_green] Exploit Module [/bold bright_green]", style="bright_green"))
    console.print("""
[bold bright_cyan]aegis exploit web <url> --force[/bold bright_cyan]
  sqlmap (SQLi) + reflected XSS testing
  Options: --no-sqlmap  --no-xss  --param q

[bold bright_cyan]aegis exploit lfi <url> --param <name>[/bold bright_cyan]
  9 LFI payloads (path traversal + URL encoding), checks for /etc/passwd

[bold bright_cyan]aegis exploit ssrf <url> --callback <domain>[/bold bright_cyan]
  SSRF parameter injection with redirect detection

[bold bright_cyan]aegis exploit oob <url> --force[/bold bright_cyan]
  OOB SSRF/XXE via interactsh DNS/HTTP callback
  Options: --callback your.domain  --test-xxe  --wait 30

[bold bright_cyan]aegis exploit msf <target> --force[/bold bright_cyan]
  Auto-map Nuclei findings to Metasploit modules, run via resource scripts
  Options: --module  --finding-id  --check  --lhost  --lport  --rpc-host

[bold white]All exploit commands require --force to bypass safe_mode.[/bold white]
""")


def _help_post() -> None:
    from rich.rule import Rule
    console.print()
    console.print(Rule("[bold bright_green] Post-Exploitation Module [/bold bright_green]", style="bright_green"))
    console.print("""
[bold bright_cyan]aegis post shell <ip>[/bold bright_cyan]
  Run LinPEAS/WinPEAS, parse for CVEs and privilege escalation hints
  Options: --no-enum  --no-privesc

[bold bright_cyan]aegis post creds --target <ip>[/bold bright_cyan]
  List SMB shares. With --deep: download files and scan for passwords/tokens
  Options: --deep  --timeout

[bold bright_cyan]aegis post pivoting <network> --ssh user@host[/bold bright_cyan]
  SOCKS5 proxy via SSH dynamic port forwarding
  With --scan: enumerate internal network through proxy via proxychains+nmap
  With --forward local:remote_host:remote_port: set up port forward
  Options: --port 1080  --scan  --forward  --timeout
""")


def register_tools() -> None:
    tools = discover_tools()
    groups = {"recon": recon, "vuln": vuln, "exploit": exploit, "post": post, "report": report}
    for category, commands in tools.items():
        group = groups.get(category)
        if not group:
            continue
        for command in commands:
            group.add_command(command)


register_tools()


if __name__ == "__main__":
    cli()
