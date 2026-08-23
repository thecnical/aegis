from __future__ import annotations

# ── Standard library imports (must be at top for ruff E402) ──────────────────
import hashlib
import os
import secrets
import socket
from pathlib import Path
from typing import Optional

# ── Project-root resolution (before any relative imports) ────────────────────
# This runs at import time to set _PROJECT_DIR / _DEFAULT_CONFIG / _DEFAULT_LOG
# BEFORE click/aegis imports, so default= values are correct.


def _resolve_project_dir() -> Path:
    """Return the Aegis project root (where config/config.yaml lives).

    Resolution order:
    1. AEGIS_PROJECT_DIR env-var (set by __main__.py at startup)
    2. Directory of main.py itself (source-tree usage)
    3. CWD (legacy / in-tree invocation)
    """
    env = os.environ.get("AEGIS_PROJECT_DIR", "")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    if (here / "config" / "config.yaml").exists():
        return here
    return Path.cwd()


_PROJECT_DIR = _resolve_project_dir()
_DEFAULT_CONFIG = str(_PROJECT_DIR / "config" / "config.yaml")
_DEFAULT_LOG = str(_PROJECT_DIR / "data" / "logs" / "aegis.log")

# ── Third-party / project imports ────────────────────────────────────────────
import click  # noqa: E402
from rich.table import Table  # noqa: E402

from aegis.core.campaigns import (  # noqa: E402
    add_run, create_campaign, diff_runs,
    generate_campaign_report, get_runs, list_campaigns, summarize_db,
)
from aegis.core.config_manager import ConfigManager  # noqa: E402
from aegis.core.db_manager import DatabaseManager  # noqa: E402
from aegis.core.installer import (  # noqa: E402
    build_install_plan,
    run_install_plan,
    run_install_plan_interactive,
    validate_environment,
    _is_linux as _is_linux_check,
)
from aegis.core.logger import setup_logging  # noqa: E402
from aegis.core.plugin_loader import discover_manifests, discover_tools  # noqa: E402
from aegis.core.updater import (  # noqa: E402
    get_wordlist_status, print_update_summary,
    update_nuclei_templates, update_wordlists,
)
from aegis.core.tooling import detect_external_tools  # noqa: E402
from aegis.core.utils import emit_json, run_command  # noqa: E402
from aegis.core.ui import console, show_banner  # noqa: E402
from aegis.core.scope_manager import ScopeManager  # noqa: E402
from aegis.core.workspace_manager import WorkspaceManager  # noqa: E402
from aegis.core.ai_client import AIClient  # noqa: E402
from aegis.core.ai_client import MODEL_PREFERENCES  # noqa: E402
from aegis.core.notifier import Notifier  # noqa: E402
from aegis.core.workflow_engine import WorkflowEngine  # noqa: E402

def _make_abs(path: str, config_path: str) -> Path:
    """Convert a relative path to absolute using the config file's directory."""
    p = Path(path)
    if p.is_absolute():
        return p
    base = Path(config_path).resolve().parent
    return base / p


def _create_default_config(config_path: str) -> None:
    """Bootstrap a default config.yaml if one doesn't exist yet."""
    from aegis.core.ui import console as _con
    dest = Path(config_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    template = _PROJECT_DIR / "config" / "config.yaml"
    if template.exists() and template != dest:
        import shutil
        shutil.copy2(str(template), str(dest))
        _con.print(f"[accent]Created default config:[/accent] {dest}")
        return
    # Minimal fallback if template is also missing
    dest.write_text(
        "# Aegis auto-generated config\n"
        "general:\n"
        "  data_path: data\n"
        "  db_path: data/aegis.db\n"
        "  default_timeout: 30\n"
        "  safe_mode: true\n"
        "api_keys:\n"
        "  openrouter: CHANGE_ME\n"
        "  bytez: CHANGE_ME\n"
        "  shodan: CHANGE_ME\n"
        "  nvd: CHANGE_ME\n"
        "notifications:\n"
        "  slack_webhook: ''\n"
        "  discord_webhook: ''\n"
        "profiles:\n"
        "  default:\n"
        "    timeout: 30\n"
        "    nmap_args: '-sC -sV'\n"
        "    nuclei_rate: 150\n"
        "    ferox_depth: 2\n"
        "external_tools: {}\n",
        encoding="utf-8",
    )
    _con.print(f"[accent]Created minimal default config:[/accent] {dest}")


PHASE1_PROFILE_PRESETS: dict[str, dict[str, object]] = {
    "web-fast": {
        "timeout": 12,
        "nmap_args": "-sS -Pn",
        "nuclei_rate": 350,
        "ferox_depth": 1,
    },
    "web-deep": {
        "timeout": 90,
        "nmap_args": "-sC -sV -A -O --script=vuln",
        "nuclei_rate": 80,
        "ferox_depth": 5,
    },
    "api-deep": {
        "timeout": 75,
        "nmap_args": "-sV -Pn",
        "nuclei_rate": 120,
        "ferox_depth": 3,
    },
}


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
@click.option("--config", "config_path", default=_DEFAULT_CONFIG, show_default=True,
              help="Path to config YAML (auto-detected from install location).")
@click.option(
    "--profile",
    default="default",
    show_default=True,
    help="Scan profile (legacy: default/fast/deep/stealth; new: web-fast/web-deep/api-deep).",
)
@click.option("--log-file", default=_DEFAULT_LOG, show_default=True)
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
    # Ensure log directory exists before setup_logging tries to write it
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    setup_logging(log_file, debug)
    config = ConfigManager(config_path)
    # Auto-bootstrap a default config if one is missing
    if not Path(config_path).exists():
        _create_default_config(config_path)
    config.load()
    _ensure_phase1_profiles(config)

    # Resolve workspace — make db path absolute relative to project dir
    _raw_db = config.get("general.db_path", "data/aegis.db")
    root_db_path = str(_make_abs(_raw_db, config_path))
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
    _show_first_run_hints(ctx.obj)


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


def _ensure_phase1_profiles(config: ConfigManager) -> dict[str, dict[str, object]]:
    config_data = config.load()
    profiles = config_data.get("profiles", {}) or {}
    changed = False
    for profile_name, profile_values in PHASE1_PROFILE_PRESETS.items():
        if profile_name not in profiles:
            profiles[profile_name] = dict(profile_values)
            changed = True
    if changed:
        config_data["profiles"] = profiles
        config.save(config_data)
    return profiles


def _is_configured_secret(value: object) -> bool:
    if not isinstance(value, str):
        return False
    cleaned = value.strip()
    return bool(cleaned and cleaned != "CHANGE_ME")


def _prompt_ai_onboarding(config: ConfigManager) -> bool:
    if not click.confirm("Configure AI provider and API keys now?", default=True):
        return False

    provider = click.prompt(
        "Preferred AI provider",
        type=click.Choice(["auto", "bytez", "openrouter"], case_sensitive=False),
        default="auto",
        show_choices=True,
    ).lower()
    config_data = config.load()
    ai_cfg = config_data.get("ai", {}) or {}
    ai_cfg["preferred_provider"] = provider
    config_data["ai"] = ai_cfg
    api_keys = config_data.get("api_keys", {}) or {}

    if provider in ("auto", "bytez"):
        current = str(api_keys.get("bytez", "CHANGE_ME"))
        if click.confirm("Set/update Bytez API key?", default=not _is_configured_secret(current)):
            api_keys["bytez"] = click.prompt("Bytez API key", default=current, hide_input=True, show_default=False)

    if provider in ("auto", "openrouter"):
        current = str(api_keys.get("openrouter", "CHANGE_ME"))
        if click.confirm("Set/update OpenRouter API key?", default=not _is_configured_secret(current)):
            api_keys["openrouter"] = click.prompt("OpenRouter API key", default=current, hide_input=True, show_default=False)

    config_data["api_keys"] = api_keys
    config.save(config_data)
    return True


def _show_first_run_hints(ctx: AegisContext) -> None:
    config_data = ctx.config.load()
    ux = config_data.get("ux", {}) or {}
    if ux.get("first_run_hint_shown"):
        return
    console.print(
        "[accent]First-run hints:[/accent] "
        "`aegis ai doctor --strict` validates AI readiness, "
        "`aegis web-assess --target <url>` runs resumable authorized workflows."
    )
    ux["first_run_hint_shown"] = True
    config_data["ux"] = ux
    ctx.config.save(config_data)


def _run_setup_wizard(ctx: AegisContext) -> None:
    console.print("[accent]Aegis setup wizard (authorized testing only).[/accent]")
    config_data = ctx.config.load()
    general = config_data.get("general", {}) or {}
    profiles = _ensure_phase1_profiles(ctx.config)
    profile_names = sorted(profiles.keys())

    safe_mode_default = bool(general.get("safe_mode", True))
    timeout_default = int(general.get("default_timeout", 30))
    workspace_default = str(general.get("workspace", "default"))

    general["safe_mode"] = click.confirm("Enable safe_mode scope guard?", default=safe_mode_default)
    general["default_timeout"] = click.prompt("Default command timeout (seconds)", type=int, default=timeout_default)
    general["workspace"] = click.prompt("Default workspace", default=workspace_default)
    config_data["general"] = general

    selected_profile = click.prompt(
        "Default scan profile",
        type=click.Choice(profile_names, case_sensitive=False),
        default="web-fast" if "web-fast" in profile_names else profile_names[0],
        show_choices=True,
    )
    ai_cfg = config_data.get("ai", {}) or {}
    ai_cfg["default_profile"] = selected_profile
    config_data["ai"] = ai_cfg
    ctx.config.save(config_data)

    if click.confirm("Run AI onboarding now?", default=True):
        _prompt_ai_onboarding(ctx.config)

    console.print(
        "[primary]Wizard complete.[/primary] "
        f"Use [cyan]aegis --profile {selected_profile} <command>[/cyan] to run with your preferred profile."
    )


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
    prompt = (
        "You are assisting authorized red-team validation. "
        "For each finding provide: likelihood, impact, confidence rationale, and safe remediation.\n"
        "Return concise markdown bullets only.\n"
    ) + "\n".join(
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


@ai_group.command("doctor")
@click.option("--strict", is_flag=True, help="Exit non-zero when required AI config is missing.")
@pass_context
def ai_doctor(ctx: AegisContext, strict: bool) -> None:
    """Validate AI configuration, provider readiness, and fallback coverage."""
    from urllib.parse import urlparse

    config_data = ctx.config.load()
    ai_cfg = config_data.get("ai", {}) or {}
    preferred = str(ai_cfg.get("preferred_provider", "auto")).lower()
    keys = config_data.get("api_keys", {}) or {}
    bytez_ready = _is_configured_secret(keys.get("bytez"))
    openrouter_ready = _is_configured_secret(keys.get("openrouter"))

    endpoint_hosts = {
        "bytez": urlparse(AIClient.BYTEZ_BASE).hostname or "",
        "openrouter": urlparse(AIClient.OPENROUTER_BASE).hostname or "",
    }
    endpoint_dns: dict[str, bool] = {}
    for provider, host in endpoint_hosts.items():
        if not host:
            endpoint_dns[provider] = False
            continue
        try:
            socket.getaddrinfo(host, 443)
            endpoint_dns[provider] = True
        except OSError:
            endpoint_dns[provider] = False

    task_ready: dict[str, bool] = {}
    for task, models in MODEL_PREFERENCES.items():
        ready = False
        for model in models:
            provider, _ = model.split("/", 1)
            if provider == "bytez" and bytez_ready:
                ready = True
                break
            if provider == "openrouter" and openrouter_ready:
                ready = True
                break
        task_ready[task] = ready

    fallback_ready = all(task_ready.values())
    profiles = config_data.get("profiles", {}) or {}
    default_profile = str(ai_cfg.get("default_profile", "default"))
    profile_ready = default_profile in profiles
    preferred_ready = (
        (preferred == "auto" and (bytez_ready or openrouter_ready))
        or (preferred == "bytez" and bytez_ready)
        or (preferred == "openrouter" and openrouter_ready)
    )
    issues: list[str] = []
    if not preferred_ready:
        issues.append(f"preferred provider '{preferred}' is not fully configured")
    if not fallback_ready:
        issues.append("one or more AI tasks have no configured model fallback")
    if not profile_ready:
        issues.append(f"default AI profile '{default_profile}' is missing from config profiles")

    table = Table(title="AI Doctor")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Details", style="white")
    table.add_row("Preferred provider", preferred, "Configured in ai.preferred_provider")
    table.add_row("Bytez key", "[green]ok[/green]" if bytez_ready else "[yellow]missing[/yellow]", "api_keys.bytez")
    table.add_row(
        "OpenRouter key",
        "[green]ok[/green]" if openrouter_ready else "[yellow]missing[/yellow]",
        "api_keys.openrouter",
    )
    table.add_row(
        "Bytez endpoint DNS",
        "[green]ok[/green]" if endpoint_dns["bytez"] else "[yellow]unresolved[/yellow]",
        endpoint_hosts["bytez"],
    )
    table.add_row(
        "OpenRouter endpoint DNS",
        "[green]ok[/green]" if endpoint_dns["openrouter"] else "[yellow]unresolved[/yellow]",
        endpoint_hosts["openrouter"],
    )
    table.add_row(
        "Model fallback readiness",
        "[green]ready[/green]" if fallback_ready else "[yellow]degraded[/yellow]",
        f"{sum(1 for ok in task_ready.values() if ok)}/{len(task_ready)} tasks covered",
    )
    table.add_row(
        "Default AI profile",
        "[green]ok[/green]" if profile_ready else "[yellow]invalid[/yellow]",
        default_profile,
    )
    console.print(table)

    if issues:
        console.print("[warning]AI doctor found issues:[/warning]")
        for item in issues:
            console.print(f" - {item}")
        console.print("Run [cyan]aegis setup --wizard[/cyan] or [cyan]aegis ai doctor --strict[/cyan] after fixing config.")
        if strict:
            raise click.ClickException("AI doctor strict mode failed")
    else:
        console.print("[primary]AI configuration looks ready for authorized red-team workflows.[/primary]")


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
@click.option("--interval", default=3600, type=int, show_default=True, help="Base scan interval in seconds.")
@click.option("--min-interval", default=300, type=int, show_default=True, help="Minimum interval (for volatile targets).")
@click.option("--max-interval", default=86400, type=int, show_default=True, help="Maximum interval (for stable targets).")
@click.option("--min-severity", default="medium", show_default=True)
@click.option("--notify", "notify_channel", default=None, type=click.Choice(["slack", "discord", "both"]))
@click.option("--max-iterations", default=0, type=int, help="Stop after N iterations (0=infinite).")
@pass_context
def watch_cmd(
    ctx: AegisContext,
    interval: int,
    min_interval: int,
    max_interval: int,
    min_severity: str,
    notify_channel: Optional[str],
    max_iterations: int,
) -> None:
    """Adaptive continuous monitoring — self-tuning scanner.

    Unlike basic cron-based scanning, this adapts scan frequency based on
    target volatility. Targets that change frequently get scanned more often;
    stable targets get exponentially backed off. Integrates with the learning
    engine for intelligent tool selection and drift detection.
    """
    from aegis.core.adaptive_monitor import AdaptiveMonitor

    notifier = Notifier(ctx.config) if notify_channel else None

    def notify_delta(delta):
        if notifier and delta.has_changes:
            # Build notification message
            msg = delta.summary_text()
            try:
                notifier.send_text(msg, channel=notify_channel or "both")
            except Exception:
                pass

    monitor = AdaptiveMonitor(
        db=ctx.db,
        config=ctx.config,
        scope=ctx.scope,
        base_interval=interval,
        min_interval=min_interval,
        max_interval=max_interval,
        notify_callback=notify_delta if notifier else None,
    )

    # Load targets from scope
    monitor.load_scope_targets()
    status = monitor.get_status()

    if status["total_targets"] == 0:
        console.print("[warning]No scope targets defined. Add targets with 'aegis scope add'.[/warning]")
        return

    from rich.panel import Panel
    console.print(Panel(
        f"Targets: {status['total_targets']}\n"
        f"Base interval: {interval}s ({interval//60}m)\n"
        f"Adaptive range: {min_interval}s - {max_interval}s\n"
        f"Notifications: {notify_channel or 'disabled'}\n"
        f"Mode: {'limited' if max_iterations else 'continuous'}",
        title="[bold]Adaptive Monitor[/bold]",
        border_style="green",
    ))

    monitor.run_loop(max_iterations=max_iterations)


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


@cli.command("web-assess")
@click.option("--target", required=True, help="In-scope target URL for authorized assessment.")
@click.option("--resume-run-id", default=None, help="Resume a previous workflow run id.")
@click.option("--workers", default=4, show_default=True, type=int)
@click.option("--rate-limit", default=5, show_default=True, type=int, help="Max requests per second.")
@click.option("--retries", default=1, show_default=True, type=int)
@click.option("--require-cross-validation", is_flag=True, help="Do not elevate confidence without corroboration.")
@click.option("--dangerous-checks", is_flag=True, help="Enable explicit dangerous checks (opt-in only).")
@click.option("--ci", "ci_mode", is_flag=True, help="Deterministic CI mode with strict exit semantics.")
@pass_context
def web_assess_cmd(
    ctx: AegisContext,
    target: str,
    resume_run_id: Optional[str],
    workers: int,
    rate_limit: int,
    retries: int,
    require_cross_validation: bool,
    dangerous_checks: bool,
    ci_mode: bool,
) -> None:
    """Resumable orchestration pipeline for authorized web assessments."""
    ctx.scope.validate_or_abort(target)
    engine = WorkflowEngine(
        db=ctx.db,
        workspace=ctx.workspace_name,
        profile=ctx.profile,
        workers=workers,
        rate_limit_per_sec=rate_limit,
        retries=retries,
        require_cross_validation=require_cross_validation,
        dangerous_checks=dangerous_checks,
    )
    result = engine.run(target=target, resume_run_id=resume_run_id)
    state = result.get("state", {})
    finding_count = len(state.get("findings", []))
    critical_or_high = sum(1 for f in state.get("findings", []) if str(f.get("severity", "")).lower() in {"critical", "high"})
    console.print(f"[primary]Workflow complete:[/primary] run_id={result.get('run_id')} findings={finding_count}")
    if ci_mode:
        if critical_or_high > 0:
            raise click.ClickException(f"CI gate failed: {critical_or_high} high/critical findings")
        if state.get("errors"):
            raise click.ClickException("CI gate failed: workflow contained stage errors")


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
@click.option("--wizard", "wizard_mode", is_flag=True, help="Run first-time interactive setup wizard.")
@pass_context
def setup_tools(
    ctx: AegisContext,
    assume_yes: bool,
    dry_run: bool,
    include_peas: bool,
    fix_config: bool,
    wizard_mode: bool,
) -> None:
    """Install dependencies or launch guided first-time setup."""
    if wizard_mode:
        _run_setup_wizard(ctx)
        return

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
        return

    _ensure_phase1_profiles(ctx.config)
    if not assume_yes and not dry_run and click.confirm("Configure AI onboarding now?", default=False):
        configured = _prompt_ai_onboarding(ctx.config)
        if configured:
            console.print("[primary]AI onboarding saved to config.[/primary]")


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


# ─── learn ────────────────────────────────────────────────────────────────────

@cli.group("learn")
def learn_group() -> None:
    """Self-learning engine: profiles, drift detection, recommendations."""


@learn_group.command("status")
@click.pass_context
def learn_status(ctx: click.Context) -> None:
    """Show learning engine statistics and knowledge base size."""
    from aegis.core.learning_engine import LearningEngine
    context = ctx.obj
    engine = LearningEngine(context.db)
    stats = engine.get_statistics()

    from rich.panel import Panel
    kb = stats["knowledge_base"]
    lines = [
        f"Target profiles:       {kb['target_profiles']}",
        f"Tool effectiveness:    {kb['tool_effectiveness_records']}",
        f"Scan history:          {kb['scan_history_entries']}",
        f"Drift events:          {kb['drift_events']}",
        f"Patterns discovered:   {kb['patterns_discovered']}",
        f"Strategies learned:    {kb['strategies_learned']}",
    ]
    console.print(Panel("\n".join(lines), title="[bold]Learning Engine Knowledge Base[/bold]", border_style="green"))

    if stats["top_tools"]:
        t = Table(title="Top Performing Tools", border_style="dim green")
        t.add_column("Tool", style="cyan")
        t.add_column("Avg Score", style="green", justify="right")
        t.add_column("Total Findings", justify="right")
        for tool in stats["top_tools"]:
            t.add_row(tool["name"], f"{tool['avg_score']:.3f}", str(tool["total_findings"]))
        console.print(t)


@learn_group.command("profile")
@click.argument("target")
@click.pass_context
def learn_profile(ctx: click.Context, target: str) -> None:
    """Show the learned profile for a target."""
    from aegis.core.learning_engine import LearningEngine
    context = ctx.obj
    engine = LearningEngine(context.db)
    profile = engine.get_target_profile(target)

    if not profile:
        console.print(f"[yellow]No profile exists for:[/yellow] {target}")
        console.print("[dim]Run a scan against this target to build a profile.[/dim]")
        return

    from rich.panel import Panel
    console.print(Panel(
        f"Target: {profile.target}\n"
        f"Scans: {profile.scan_count}  |  "
        f"First seen: {profile.first_seen[:10]}  |  "
        f"Last seen: {profile.last_seen[:10]}\n"
        f"Technologies: {', '.join(profile.technologies) or 'unknown'}\n"
        f"Services: {len(profile.services)} discovered\n"
        f"Open ports: {', '.join(str(p) for p in profile.profile_data.get('open_ports', []))}\n"
        f"Server: {profile.profile_data.get('server_software', 'unknown')}\n"
        f"Fingerprint: {profile.last_fingerprint[:16]}...",
        title=f"[bold]Target Profile: {target}[/bold]",
        border_style="cyan",
    ))

    # Historical vulns
    vulns = profile.profile_data.get("historical_vulns", [])
    if vulns:
        console.print(f"\n[bold]Historical vulnerabilities ({len(vulns)}):[/bold]")
        for v in vulns[:15]:
            console.print(f"  [dim]●[/dim] {v}")

    # Patch history
    patches = profile.profile_data.get("patch_history", [])
    if patches:
        console.print(f"\n[bold green]Patched ({len(patches)}):[/bold green]")
        for p in patches[:10]:
            console.print(f"  [green]✓[/green] {p.get('title', '?')} @ {p.get('patched_at', '?')[:10]}")


@learn_group.command("recommend")
@click.argument("target")
@click.pass_context
def learn_recommend(ctx: click.Context, target: str) -> None:
    """Get AI-powered scan recommendations based on learned intelligence."""
    from aegis.core.learning_engine import LearningEngine
    context = ctx.obj
    engine = LearningEngine(context.db)
    rec = engine.recommend_strategy(target)

    from rich.panel import Panel
    console.print(Panel(
        f"Confidence: [bold]{rec['confidence'].upper()}[/bold]\n"
        f"Recommended tools: {', '.join(rec['recommended_tools'][:8]) or 'default set'}\n"
        f"Recommended phases: {', '.join(rec['recommended_phases'])}\n"
        f"Skip tools: {', '.join(rec['skip_tools'][:5]) or 'none'}\n"
        f"Focus areas: {', '.join(rec['focus_areas'][:5]) or 'none'}",
        title=f"[bold]Scan Recommendations for {target}[/bold]",
        border_style="magenta",
    ))

    if rec["reasoning"]:
        console.print("\n[bold]Reasoning:[/bold]")
        for reason in rec["reasoning"]:
            console.print(f"  [dim]→[/dim] {reason}")

    if rec["similar_targets"]:
        console.print("\n[bold]Similar targets in knowledge base:[/bold]")
        for sim in rec["similar_targets"][:3]:
            console.print(
                f"  [cyan]{sim['target']}[/cyan] "
                f"(similarity={sim['similarity_score']:.0%}, "
                f"shared: {', '.join(sim['shared_technologies'][:3])})"
            )

    if rec["drift_alerts"]:
        console.print(f"\n[bold yellow]Unacknowledged changes: {len(rec['drift_alerts'])}[/bold yellow]")
        for drift in rec["drift_alerts"][:3]:
            console.print(f"  [yellow]⚠[/yellow] {drift['description']}")


@learn_group.command("drift")
@click.argument("target", required=False, default=None)
@click.option("--all", "show_all", is_flag=True, help="Show all drift events, not just unacknowledged.")
@click.pass_context
def learn_drift(ctx: click.Context, target: Optional[str], show_all: bool) -> None:
    """Show drift events (changes detected between scans)."""
    from aegis.core.learning_engine import LearningEngine
    context = ctx.obj
    engine = LearningEngine(context.db)

    if show_all and target:
        events = engine.get_drift_history(target)
    else:
        events = engine.get_unacknowledged_drifts(target)

    if not events:
        console.print("[green]No drift events found.[/green]")
        return

    t = Table(title="Drift Events", border_style="yellow")
    t.add_column("Time", style="dim")
    t.add_column("Type", style="cyan")
    t.add_column("Description")
    t.add_column("Severity", justify="center")

    for event in events[:30]:
        sev = event.get("severity", "info")
        sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "dim"}.get(sev, "white")
        t.add_row(
            str(event.get("detected_at", ""))[:16],
            event.get("drift_type", ""),
            event.get("description", "")[:60],
            f"[{sev_style}]{sev}[/{sev_style}]",
        )
    console.print(t)


@learn_group.command("targets")
@click.pass_context
def learn_targets(ctx: click.Context) -> None:
    """List all known target profiles in the knowledge base."""
    from aegis.core.learning_engine import LearningEngine
    context = ctx.obj
    engine = LearningEngine(context.db)
    profiles = engine.get_all_profiles()

    if not profiles:
        console.print("[yellow]No target profiles in knowledge base yet.[/yellow]")
        console.print("[dim]Run scans to build intelligence.[/dim]")
        return

    t = Table(title=f"Known Targets ({len(profiles)})", border_style="green")
    t.add_column("Target", style="cyan")
    t.add_column("Scans", justify="right")
    t.add_column("Technologies", style="dim")
    t.add_column("Ports", style="dim")
    t.add_column("Last Seen", style="dim")

    for p in profiles:
        t.add_row(
            p.target[:40],
            str(p.scan_count),
            ", ".join(p.technologies[:3]) + ("..." if len(p.technologies) > 3 else ""),
            ", ".join(str(port) for port in p.profile_data.get("open_ports", [])[:5]),
            p.last_seen[:10],
        )
    console.print(t)


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


# ─── enterprise ───────────────────────────────────────────────────────────────

@cli.group("token")
def token_group() -> None:
    """Manage hardened API tokens."""


@token_group.command("create")
@click.option("--description", default="")
@pass_context
def token_create(ctx: AegisContext, description: str) -> None:
    raw = f"aeg_{secrets.token_urlsafe(24)}"
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    prefix = raw[:12]
    ctx.db.add_api_token(token_hash, prefix, description)
    ctx.db.add_audit_log(ctx.workspace_name, "cli", "token_create", prefix)
    console.print(f"[primary]Token created.[/primary] prefix={prefix}")
    console.print(f"[warning]Store this token now (shown once):[/warning] {raw}")


@cli.group("audit")
def audit_group() -> None:
    """Audit log operations."""


@audit_group.command("list")
@click.option("--limit", default=100, type=int, show_default=True)
@pass_context
def audit_list(ctx: AegisContext, limit: int) -> None:
    logs = ctx.db.list_audit_logs(limit=limit)
    table = Table(title="Audit Logs")
    table.add_column("Time", style="dim")
    table.add_column("Workspace", style="cyan")
    table.add_column("Actor", style="magenta")
    table.add_column("Action", style="green")
    table.add_column("Details", style="white")
    for row in logs:
        table.add_row(str(row.get("created_at", "")), str(row.get("workspace", "")), str(row.get("actor", "")), str(row.get("action", "")), str(row.get("details", "")))
    console.print(table)


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


# ─── forensics ────────────────────────────────────────────────────────────────

from aegis.forensics.cli import forensics_group  # noqa: E402
cli.add_command(forensics_group)


# ─── mitre ────────────────────────────────────────────────────────────────────

@cli.group("mitre")
def mitre_group() -> None:
    """MITRE ATT&CK mapping and kill chain analysis."""


@mitre_group.command("map")
@click.option("--session", "session_id", default=None, type=int, help="Map findings from a specific session.")
@click.option("--severity", default=None, help="Filter by severity before mapping.")
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def mitre_map(ctx: click.Context, session_id: Optional[int], severity: Optional[str], json_out: bool, json_output: Optional[str]) -> None:
    """Map all findings to MITRE ATT&CK techniques."""
    from aegis.core.mitre_attack import MitreAttackMapper
    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)
    db = context.db

    if session_id:
        findings = db.get_session_findings(session_id)
    else:
        findings = db.get_all_findings(limit=200)

    if severity:
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]

    if not findings:
        console.print("[yellow]No findings to map.[/yellow]")
        return

    mapper = MitreAttackMapper()
    mappings = mapper.map_findings(findings)
    summary = mapper.summary()

    if json_out:
        result = {
            "summary": summary,
            "mappings": [
                {"finding": m.finding_title, "severity": m.finding_severity,
                 "techniques": m.techniques[:5], "tactics": m.tactics_covered,
                 "confidence": m.confidence}
                for m in mappings if m.techniques
            ],
            "coverage": mapper.get_kill_chain_coverage(),
            "gaps": mapper.get_coverage_gaps(),
            "top_techniques": mapper.get_technique_frequency(),
        }
        emit_json(result, json_output)
        return

    from rich.panel import Panel
    console.print(Panel(
        f"Findings analyzed: {summary['total_findings']}\n"
        f"Successfully mapped: {summary['mapped_findings']} ({summary['coverage_percentage']}%)\n"
        f"Unique techniques: {summary['unique_techniques']}\n"
        f"Tactics covered: {summary['tactics_covered']}/{summary['total_tactics']} "
        f"({summary['kill_chain_coverage_pct']}%)",
        title="[bold]MITRE ATT&CK Mapping Summary[/bold]",
        border_style="magenta",
    ))

    # Show mapped findings
    mapped_results = [m for m in mappings if m.techniques]
    if mapped_results:
        t = Table(title="Findings → ATT&CK Techniques", border_style="magenta")
        t.add_column("Finding", style="white", width=35)
        t.add_column("Sev", style="bold", justify="center", width=6)
        t.add_column("Technique(s)", style="cyan", width=35)
        t.add_column("Tactic", style="yellow", width=20)
        t.add_column("Conf", justify="right", width=5)
        for m in mapped_results[:30]:
            techs = ", ".join(f"{tech['technique_id']}" for tech in m.techniques[:2])
            tactics = ", ".join(m.tactics_covered[:2])
            sev_style = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(m.finding_severity, "dim")
            t.add_row(
                m.finding_title[:35],
                f"[{sev_style}]{m.finding_severity[:4]}[/{sev_style}]",
                techs,
                tactics[:20],
                f"{m.confidence:.0%}",
            )
        console.print(t)

    # Kill chain coverage visualization
    console.print("\n[bold]Kill Chain Coverage:[/bold]")
    coverage = mapper.get_kill_chain_coverage()
    for tactic_id, info in sorted(coverage.items(), key=lambda x: x[1]["order"]):
        count = info["techniques_observed"]
        bar = "█" * min(count, 10) + "░" * (10 - min(count, 10))
        style = "green" if count > 0 else "dim red"
        console.print(f"  [{style}]{bar}[/{style}] {info['name']:<25} ({count} techniques)")

    # Gaps
    gaps = mapper.get_coverage_gaps()
    if gaps:
        console.print(f"\n[yellow]Kill Chain Gaps ({len(gaps)} tactics with no coverage):[/yellow]")
        for gap in gaps:
            console.print(f"  [dim]○[/dim] Phase {gap['phase']}: {gap['tactic_name']}")


@mitre_group.command("narrative")
@click.option("--session", "session_id", default=None, type=int)
@click.pass_context
def mitre_narrative(ctx: click.Context, session_id: Optional[int]) -> None:
    """Generate an attack narrative based on ATT&CK mapping."""
    from aegis.core.mitre_attack import MitreAttackMapper
    context = ctx.obj
    db = context.db

    findings = db.get_session_findings(session_id) if session_id else db.get_all_findings(limit=200)
    if not findings:
        console.print("[yellow]No findings to narrate.[/yellow]")
        return

    mapper = MitreAttackMapper()
    mapper.map_findings(findings)
    narrative = mapper.generate_attack_narrative()
    from rich.markdown import Markdown
    console.print(Markdown(narrative))


@mitre_group.command("techniques")
@click.option("--tactic", default=None, help="Filter by tactic name (e.g. 'Initial Access').")
@click.option("--search", default=None, help="Search techniques by keyword.")
@click.pass_context
def mitre_techniques(ctx: click.Context, tactic: Optional[str], search: Optional[str]) -> None:
    """List known ATT&CK techniques in the database."""
    from aegis.core.mitre_attack import TACTICS, TECHNIQUES
    results = list(TECHNIQUES.values())

    if tactic:
        tactic_lower = tactic.lower()
        matching_ids = [tid for tid, info in TACTICS.items() if tactic_lower in str(info["name"]).lower()]
        results = [t for t in results if any(tid in t.tactic_ids for tid in matching_ids)]

    if search:
        search_lower = search.lower()
        results = [t for t in results if search_lower in t.name.lower() or search_lower in t.description.lower()]

    if not results:
        console.print("[yellow]No techniques matched your filters.[/yellow]")
        return

    t = Table(title=f"ATT&CK Techniques ({len(results)})", border_style="dim magenta")
    t.add_column("ID", style="cyan", width=12)
    t.add_column("Name", style="white", width=35)
    t.add_column("Tactics", style="yellow", width=30)
    for tech in results[:40]:
        t.add_row(tech.technique_id, tech.name, ", ".join(tech.tactics)[:30])
    console.print(t)


# ─── chains ───────────────────────────────────────────────────────────────────

@cli.group("chains")
def chains_group() -> None:
    """Exploit chain analysis — multi-step attack path discovery."""


@chains_group.command("analyze")
@click.option("--session", "session_id", default=None, type=int, help="Analyze findings from a specific session.")
@click.option("--min-confidence", default=0.4, type=float, show_default=True, help="Minimum chain confidence.")
@click.option("--json", "json_out", is_flag=True)
@click.option("--json-output", default=None)
@click.pass_context
def chains_analyze(ctx: click.Context, session_id: Optional[int], min_confidence: float, json_out: bool, json_output: Optional[str]) -> None:
    """Discover exploit chains — how individual vulns combine into full compromise."""
    from aegis.core.exploit_chains import ExploitChainAnalyzer
    context = ctx.obj
    json_out = json_out or getattr(context, "json_out", False)
    json_output = json_output or getattr(context, "json_output", None)
    db = context.db

    findings = db.get_session_findings(session_id) if session_id else db.get_all_findings(limit=300)
    if not findings:
        console.print("[yellow]No findings to analyze.[/yellow]")
        return

    analyzer = ExploitChainAnalyzer()
    analyzer.add_findings(findings)
    chains = analyzer.analyze()

    # Filter by confidence
    chains = [c for c in chains if c.confidence >= min_confidence]
    summary = analyzer.summary()

    if json_out:
        emit_json({"summary": summary, "chains": [c.to_dict() for c in chains]}, json_output)
        return

    from rich.panel import Panel
    console.print(Panel(
        f"Findings analyzed: {summary['total_findings_analyzed']}\n"
        f"Classified: {summary['classified_findings']} | Unclassified: {summary['unclassified_findings']}\n"
        f"Chains discovered: {summary['chains_discovered']}\n"
        f"  Critical: {summary['critical_chains']} | High: {summary['high_chains']} | Medium: {summary['medium_chains']}\n"
        f"Vuln types present: {', '.join(summary['vulnerability_types_present'][:8])}",
        title="[bold]Exploit Chain Analysis[/bold]",
        border_style="red",
    ))

    if not chains:
        console.print("[green]No exploit chains discovered above confidence threshold.[/green]")
        return

    for i, chain in enumerate(chains, 1):
        impact_style = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(chain.impact, "white")
        console.print(f"\n[{impact_style}]━━━ Chain {i}: {chain.name} ━━━[/{impact_style}]")
        console.print(f"  Impact: [{impact_style}]{chain.impact.upper()}[/{impact_style}] | Confidence: {chain.confidence:.0%}")
        console.print(f"  [dim]{chain.description}[/dim]")
        console.print(f"  [bold]Final Impact:[/bold] {chain.final_impact}")
        console.print("  [bold]Steps:[/bold]")
        for j, step in enumerate(chain.steps, 1):
            sev_style = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(step.severity, "dim")
            console.print(f"    {j}. [{sev_style}][{step.severity.upper()}][/{sev_style}] {step.title}")
            if step.capability_gained:
                console.print(f"       [dim]→ Gains: {', '.join(step.capability_gained[:3])}[/dim]")
        if chain.mitigations:
            console.print("  [bold green]Mitigations:[/bold green]")
            for mit in chain.mitigations[:3]:
                console.print(f"    [green]•[/green] {mit}")


@chains_group.command("report")
@click.option("--session", "session_id", default=None, type=int)
@click.pass_context
def chains_report(ctx: click.Context, session_id: Optional[int]) -> None:
    """Generate a detailed exploit chain report in Markdown."""
    from aegis.core.exploit_chains import ExploitChainAnalyzer
    context = ctx.obj
    db = context.db

    findings = db.get_session_findings(session_id) if session_id else db.get_all_findings(limit=300)
    if not findings:
        console.print("[yellow]No findings.[/yellow]")
        return

    analyzer = ExploitChainAnalyzer()
    analyzer.add_findings(findings)
    analyzer.analyze()
    report = analyzer.generate_report()
    from rich.markdown import Markdown
    console.print(Markdown(report))


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
    t.add_row("--profile NAME",   "default",            "Scan profile (legacy + web-fast/web-deep/api-deep)")
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
        ("aegis setup --wizard",          "Guided first-time configuration (profiles + optional AI)"),
        ("aegis doctor",                  "Check all tools and API keys are configured"),
        ("aegis doctor --fix",            "Auto-detect tool paths and save to config"),
        ("aegis ai doctor",               "Validate AI provider keys, endpoint assumptions, and fallback readiness"),
        ("aegis web-assess --target URL", "Resumable authorized web workflow with checkpoints"),
        ("aegis token create",            "Create hashed API token for API/CI usage"),
        ("aegis audit list",              "View audit trail events"),
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
            "  [bright_cyan]aegis help ai[/bright_cyan]         — AI features + onboarding diagnostics",
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
  web-fast: timeout=12, nmap="-sS -Pn", nuclei_rate=350
  web-deep: timeout=90, nmap="-sC -sV -A -O --script=vuln", ferox_depth=5
  api-deep: timeout=75, nmap="-sV -Pn", nuclei_rate=120

[bold bright_cyan]notifications:[/bold bright_cyan]
  slack_webhook: ""               [dim]# https://api.slack.com/messaging/webhooks[/dim]
  discord_webhook: ""             [dim]# Discord channel webhook URL[/dim]

[bold white]Switch profile:[/bold white]  aegis --profile web-deep vuln web https://example.com
[bold white]Guided setup:[/bold white]    aegis setup --wizard
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

[bold bright_cyan]aegis ai doctor[/bold bright_cyan]
  Validate provider key configuration, endpoint DNS assumptions, and model fallback readiness
  Options: --strict (exit non-zero if degraded)

[bold bright_cyan]AI providers (free tiers):[/bold bright_cyan]
  OpenRouter: https://openrouter.ai/keys
  Bytez:      https://bytez.com
  Add keys to config/config.yaml under api_keys
  Use [bold]aegis setup --wizard[/bold] for guided onboarding
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


# ─── self-update ──────────────────────────────────────────────────────────────

@cli.command("self-update")
@click.option("--dry-run", is_flag=True, help="Show what would happen without doing it.")
@click.option("--pre", is_flag=True, help="Include pre-release versions.")
@pass_context
def self_update_cmd(ctx: AegisContext, dry_run: bool, pre: bool) -> None:
    """Update Aegis itself to the latest version from PyPI or git.

    Detects whether you are running from a git clone (uses git pull +
    pip install -e .) or from a pip install (uses pip install --upgrade).
    Also updates nuclei templates and optionally wordlists.
    """
    import sys as _sys

    project_dir = _PROJECT_DIR
    git_dir = project_dir / ".git"
    pip_bin = Path(_sys.executable)

    console.print("[accent]Aegis self-update starting...[/accent]")

    results: dict[str, str] = {}

    # ── 1. Update Aegis code ─────────────────────────────────────────────────
    if git_dir.exists():
        # Running from a git clone — pull latest
        console.print(f"[dim]Git clone detected at {project_dir}[/dim]")
        if dry_run:
            console.print("[primary]DRY-RUN[/primary] git pull")
            console.print("[primary]DRY-RUN[/primary] pip install -e .")
            results["git-pull"] = "dry-run"
            results["pip-reinstall"] = "dry-run"
        else:
            code, out, err = run_command(["git", "-C", str(project_dir), "pull"], timeout=120)
            if code != 0:
                console.print(f"[error]git pull failed:[/error] {err or out}")
                results["git-pull"] = "failed"
            else:
                console.print(f"[primary]git pull:[/primary] {out.strip() or 'already up-to-date'}")
                results["git-pull"] = "ok"

            pip_cmd = [str(pip_bin), "-m", "pip", "install", "-e", str(project_dir), "--quiet"]
            code, out, err = run_command(pip_cmd, timeout=180)
            if code != 0:
                console.print(f"[error]pip reinstall failed:[/error] {err or out}")
                results["pip-reinstall"] = "failed"
            else:
                console.print("[primary]pip reinstall:[/primary] ok")
                results["pip-reinstall"] = "ok"
    else:
        # Installed via pip — upgrade from PyPI
        console.print("[dim]pip install detected — upgrading from PyPI[/dim]")
        pip_cmd = [str(pip_bin), "-m", "pip", "install", "--upgrade", "aegis-cli"]
        if pre:
            pip_cmd.append("--pre")
        if dry_run:
            console.print(f"[primary]DRY-RUN[/primary] {' '.join(pip_cmd)}")
            results["pip-upgrade"] = "dry-run"
        else:
            code, out, err = run_command(pip_cmd, timeout=300)
            if code != 0:
                console.print(f"[error]pip upgrade failed:[/error] {err or out}")
                results["pip-upgrade"] = "failed"
            else:
                console.print("[primary]pip upgrade:[/primary] ok")
                results["pip-upgrade"] = "ok"

    # ── 2. Update Nuclei templates ───────────────────────────────────────────
    nuclei_cmd = str(ctx.config.get("external_tools.nuclei", "nuclei"))
    if dry_run:
        console.print(f"[primary]DRY-RUN[/primary] {nuclei_cmd} -update-templates")
        results["nuclei-templates"] = "dry-run"
    else:
        nres = update_nuclei_templates(nuclei_cmd)
        results["nuclei-templates"] = nres.get("status", "unknown")
        if nres.get("status") == "ok":
            console.print("[primary]nuclei templates:[/primary] updated")
        elif nres.get("status") == "missing":
            console.print("[warning]nuclei not found — skipping template update[/warning]")
        else:
            console.print(f"[warning]nuclei template update failed (non-fatal):[/warning] {nres.get('error', '')}")

    # ── 3. Print summary ─────────────────────────────────────────────────────
    table = Table(title="Self-Update Summary")
    table.add_column("Component", style="cyan")
    table.add_column("Outcome", style="green")
    outcome_styles = {"ok": "green", "skipped": "yellow", "failed": "red", "dry-run": "blue", "unknown": "dim"}
    for name, outcome in results.items():
        style = outcome_styles.get(outcome, "white")
        table.add_row(name, f"[{style}]{outcome}[/{style}]")
    console.print(table)

    if not dry_run and all(v in ("ok",) for v in results.values() if v != "dry-run"):
        console.print("[primary]Aegis is up to date.[/primary]")
    elif not dry_run:
        console.print("[warning]Some components may not have updated — see table above.[/warning]")

    if ctx.json_out:
        emit_json({"self_update": results}, ctx.json_output)


# ─── uni (full system uninstall) ──────────────────────────────────────────────

@cli.command("uni")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip all confirmation prompts.")
@click.option("--dry-run", is_flag=True, help="Show what would be removed without doing it.")
@click.option("--keep-data", is_flag=True, help="Keep data/ directory (databases, reports, logs).")
@click.option("--keep-config", is_flag=True, help="Keep config/config.yaml.")
@pass_context
def uni_cmd(ctx: AegisContext, assume_yes: bool, dry_run: bool, keep_data: bool, keep_config: bool) -> None:
    """Fully uninstall Aegis and ALL installed tools from the system.

    This removes:
    • The aegis-cli Python package from the active venv
    • The /usr/local/bin/aegis and /usr/local/bin/aegis-mcp wrapper scripts
    • Go-installed binaries (subfinder, nuclei, trufflehog, gowitness, amass)
    • Cargo-installed binaries (feroxbuster)
    • pip-installed tools (webtech, mcp)
    • Optionally: data/ directory and config/config.yaml
    """
    import shutil as _shutil
    import sys as _sys
    if not dry_run and not assume_yes:
        console.print(
            "[bold red]╔══════════════════════════════════════════╗[/bold red]\n"
            "[bold red]║  ⚠  FULL AEGIS UNINSTALL                ║[/bold red]\n"
            "[bold red]╚══════════════════════════════════════════╝[/bold red]\n"
        )
        console.print("[bold yellow]This will remove Aegis and ALL installed tools permanently.[/bold yellow]")
        if not keep_data:
            console.print("[bold red]  ⚠  data/ directory will be deleted (all databases, reports, logs)[/bold red]")
        if not keep_config:
            console.print("[bold red]  ⚠  config/config.yaml will be deleted[/bold red]")
        console.print()
        try:
            answer = input("Type 'yes' to confirm full uninstall: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[warning]Aborted.[/warning]")
            return
        if answer != "yes":
            console.print("[warning]Uninstall cancelled.[/warning]")
            return

    results: dict[str, str] = {}
    pip_bin = Path(_sys.executable)
    home = Path.home()
    go_bin = home / "go" / "bin"
    cargo_bin = home / ".cargo" / "bin"

    def _do(name: str, fn) -> None:  # type: ignore[type-arg]
        if dry_run:
            console.print(f"[primary]DRY-RUN[/primary] {name}")
            results[name] = "dry-run"
            return
        try:
            fn()
            console.print(f"[primary]{name}[/primary]: removed")
            results[name] = "ok"
        except Exception as exc:
            console.print(f"[warning]{name}:[/warning] {exc}")
            results[name] = "failed"

    # Pip packages
    for pkg in ["aegis-cli", "webtech", "mcp"]:
        cmd = [str(pip_bin), "-m", "pip", "uninstall", "-y", pkg]
        if dry_run:
            console.print(f"[primary]DRY-RUN[/primary] {' '.join(cmd)}")
            results[pkg] = "dry-run"
        else:
            code, _, err = run_command(cmd, timeout=60)
            results[pkg] = "ok" if code == 0 else "failed"
            console.print(f"[primary]{pkg}[/primary]: {'removed' if code == 0 else err[:60]}")

    # Go tools
    for tool in ("subfinder", "nuclei", "trufflehog", "gowitness", "amass"):
        path = go_bin / tool
        _do(f"go:{tool}", lambda p=path: p.unlink(missing_ok=True))

    # Cargo tools
    for tool in ("feroxbuster",):
        path = cargo_bin / tool
        _do(f"cargo:{tool}", lambda p=path: p.unlink(missing_ok=True))

    # Wrapper scripts
    for wrapper in ("/usr/local/bin/aegis", "/usr/local/bin/aegis-mcp"):
        wp = Path(wrapper)
        _do(f"wrapper:{wrapper}", lambda p=wp: p.unlink(missing_ok=True))

    # Data directory
    if not keep_data:
        data_dir = _PROJECT_DIR / "data"
        if dry_run:
            console.print(f"[primary]DRY-RUN[/primary] remove data dir: {data_dir}")
            results["data-dir"] = "dry-run"
        elif data_dir.exists():
            _shutil.rmtree(str(data_dir), ignore_errors=True)
            console.print("[primary]data/[/primary]: removed")
            results["data-dir"] = "ok"

    # Config
    if not keep_config:
        cfg = _PROJECT_DIR / "config" / "config.yaml"
        if dry_run:
            console.print(f"[primary]DRY-RUN[/primary] remove config: {cfg}")
            results["config"] = "dry-run"
        elif cfg.exists():
            cfg.unlink()
            console.print("[primary]config/config.yaml[/primary]: removed")
            results["config"] = "ok"

    # Summary
    table = Table(title="Uninstall Summary")
    table.add_column("Component", style="cyan")
    table.add_column("Outcome", style="green")
    outcome_styles = {"ok": "green", "failed": "red", "dry-run": "blue"}
    for name, outcome in results.items():
        style = outcome_styles.get(outcome, "white")
        table.add_row(name, f"[{style}]{outcome}[/{style}]")
    console.print(table)

    if not dry_run:
        console.print("[primary]Aegis fully uninstalled. Goodbye.[/primary]")
        console.print("[dim]You can also delete the project directory manually to remove all remaining files.[/dim]")

    if ctx.json_out:
        emit_json({"uni": results}, ctx.json_output)


# ─── api-key setup ────────────────────────────────────────────────────────────

@cli.command("configure-keys")
@click.option("--openrouter", default=None, help="OpenRouter API key (free: openrouter.ai/keys).")
@click.option("--bytez", default=None, help="Bytez API key (free: bytez.com).")
@click.option("--shodan", default=None, help="Shodan API key (free tier: shodan.io).")
@click.option("--nvd", default=None, help="NVD API key (free: nvd.nist.gov/developers).")
@click.option("--slack", default=None, help="Slack webhook URL.")
@click.option("--discord", default=None, help="Discord webhook URL.")
@click.option("--interactive", "-i", is_flag=True, help="Prompt for each key interactively.")
@pass_context
def configure_keys_cmd(
    ctx: AegisContext,
    openrouter: Optional[str],
    bytez: Optional[str],
    shodan: Optional[str],
    nvd: Optional[str],
    slack: Optional[str],
    discord: Optional[str],
    interactive: bool,
) -> None:
    """Set API keys and webhooks without manually editing config.yaml.

    Provide keys via flags OR use --interactive for guided prompts.

    All providers have completely free tiers — no credit card required.

    \\b
    Free key URLs:
      OpenRouter:  https://openrouter.ai/keys
      Bytez:       https://bytez.com
      Shodan:      https://shodan.io (free tier)
      NVD:         https://nvd.nist.gov/developers/request-an-api-key
    """
    config_data = ctx.config.load()
    api_keys = config_data.get("api_keys", {}) or {}
    notifications = config_data.get("notifications", {}) or {}

    def _set_key(key_dict: dict, name: str, value: Optional[str], prompt_text: str) -> None:
        if interactive and value is None:
            current = str(key_dict.get(name, "CHANGE_ME"))
            show_current = f" [{current[:8]}...]" if _is_configured_secret(current) else " [not set]"
            try:
                entered = input(f"{prompt_text}{show_current}: ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            if entered:
                key_dict[name] = entered
        elif value is not None:
            key_dict[name] = value

    _set_key(api_keys, "openrouter", openrouter, "OpenRouter API key (https://openrouter.ai/keys)")
    _set_key(api_keys, "bytez", bytez, "Bytez API key (https://bytez.com)")
    _set_key(api_keys, "shodan", shodan, "Shodan API key")
    _set_key(api_keys, "nvd", nvd, "NVD API key")
    _set_key(notifications, "slack_webhook", slack, "Slack webhook URL")
    _set_key(notifications, "discord_webhook", discord, "Discord webhook URL")

    config_data["api_keys"] = api_keys
    config_data["notifications"] = notifications
    ctx.config.save(config_data)

    # Show what's now configured
    table = Table(title="API Key Status")
    table.add_column("Service", style="cyan")
    table.add_column("Configured", style="green")
    table.add_column("URL", style="dim")
    key_urls = {
        "openrouter": "https://openrouter.ai/keys",
        "bytez": "https://bytez.com",
        "shodan": "https://shodan.io",
        "nvd": "https://nvd.nist.gov/developers",
    }
    for name, value in api_keys.items():
        configured = _is_configured_secret(value)
        table.add_row(
            str(name),
            "[green]yes[/green]" if configured else "[yellow]no — run aegis configure-keys[/yellow]",
            key_urls.get(str(name), ""),
        )
    console.print(table)
    console.print("[primary]Keys saved to config.[/primary] Run [cyan]aegis ai doctor[/cyan] to verify AI readiness.")


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
