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
from aegis.core.utils import emit_json, which
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
@click.option("--fix", "fix_tools", is_flag=True)
@click.option("--force", "force_fix", is_flag=True)
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
        table.add_row(str(name), str(cmd), "ok" if found else "missing")
    console.print(table)
    key_table = Table(title="API Keys")
    key_table.add_column("Service", style="cyan")
    key_table.add_column("Configured", style="green")
    for name, value in api_keys.items():
        configured = bool(value) and value != "CHANGE_ME"
        key_table.add_row(str(name), "yes" if configured else "no")
    console.print(key_table)


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
