"""Aegis REST API — headless CI/CD integration layer."""
from __future__ import annotations

import asyncio
import io
import json
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager
from aegis.core.scope_manager import ScopeManager

# ── App setup ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Aegis REST API",
    version="1.0.0",
    description="Headless REST API for Aegis penetration testing framework",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared state ───────────────────────────────────────────────────────────────

_config: Optional[ConfigManager] = None
_db: Optional[DatabaseManager] = None
_scan_jobs: dict[str, dict[str, Any]] = {}  # job_id -> job state


def _get_config() -> ConfigManager:
    global _config
    if _config is None:
        _config = ConfigManager("config/config.yaml")
        _config.load()
    return _config


def _get_db() -> DatabaseManager:
    global _db
    if _db is None:
        cfg = _get_config()
        db_path = str(cfg.get("general.db_path", "data/aegis.db"))
        _db = DatabaseManager(db_path)
        _db.init_db()
    return _db


def configure(config: ConfigManager, db: DatabaseManager) -> None:
    """Configure the API with pre-built config and db instances."""
    global _config, _db
    _config = config
    _db = db


# ── Auth ───────────────────────────────────────────────────────────────────────

def _verify_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Optional API key authentication. Skipped if no key is configured."""
    cfg = _get_config()
    configured_key = cfg.get("api.key", None)
    if not configured_key:
        return  # No key configured — open access
    if x_api_key != configured_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


AuthDep = Depends(_verify_api_key)

# ── Pydantic models ────────────────────────────────────────────────────────────


class FindingOut(BaseModel):
    id: int
    title: str
    severity: Optional[str]
    category: Optional[str]
    description: Optional[str]
    source: Optional[str]
    session_id: Optional[int]
    created_at: Optional[str]


class NoteIn(BaseModel):
    body: str


class NoteOut(BaseModel):
    id: int
    finding_id: int
    body: str
    created_at: Optional[str]


class SessionOut(BaseModel):
    id: int
    label: Optional[str]
    started_at: Optional[str]
    finished_at: Optional[str]
    summary: Optional[str]


class ScanRequest(BaseModel):
    target: str
    phases: list[str] = ["recon", "vuln"]
    profile: str = "default"


class ScanJobOut(BaseModel):
    job_id: str
    status: str
    target: str
    phases: list[str]
    session_id: Optional[int] = None
    findings_count: Optional[int] = None
    error: Optional[str] = None


class ScopeEntryIn(BaseModel):
    target: str
    kind: str = "domain"


class ScopeEntryOut(BaseModel):
    id: int
    target: str
    kind: str


class PaginatedFindings(BaseModel):
    total: int
    page: int
    per_page: int
    findings: list[FindingOut]


# ── Health ─────────────────────────────────────────────────────────────────────


@app.get("/api/v1/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "version": "1.0.0"}


# ── Findings ──────────────────────────────────────────────────────────────────


@app.get("/api/v1/findings", response_model=PaginatedFindings, tags=["findings"])
async def list_findings(
    page: int = 1,
    per_page: int = 25,
    _: None = AuthDep,
) -> PaginatedFindings:
    db = _get_db()
    offset = (page - 1) * per_page
    findings = db.get_all_findings(limit=per_page, offset=offset)
    # Count total
    conn = db.connect()
    total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    return PaginatedFindings(
        total=total,
        page=page,
        per_page=per_page,
        findings=[
            FindingOut(
                id=f["id"],
                title=f["title"],
                severity=f.get("severity"),
                category=f.get("category"),
                description=f.get("description"),
                source=f.get("source"),
                session_id=f.get("session_id"),
                created_at=str(f["created_at"]) if f.get("created_at") else None,
            )
            for f in findings
        ],
    )


@app.get("/api/v1/findings/{finding_id}", tags=["findings"])
async def get_finding(finding_id: int, _: None = AuthDep) -> dict[str, Any]:
    db = _get_db()
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    notes = db.get_notes(finding_id)
    tags = db.get_tags(finding_id)
    cves = db.get_cve_correlations(finding_id)
    return {
        "finding": finding,
        "notes": notes,
        "tags": tags,
        "cves": cves,
    }


@app.post("/api/v1/findings/{finding_id}/notes", response_model=NoteOut, tags=["findings"])
async def add_note(finding_id: int, note: NoteIn, _: None = AuthDep) -> NoteOut:
    db = _get_db()
    if not db.get_finding(finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    note_id = db.add_note(finding_id, note.body)
    notes = db.get_notes(finding_id)
    created = next((n for n in notes if n["id"] == note_id), None)
    if not created:
        raise HTTPException(status_code=500, detail="Failed to retrieve created note")
    return NoteOut(
        id=created["id"],
        finding_id=finding_id,
        body=created["body"],
        created_at=str(created.get("created_at", "")),
    )


# ── Sessions ──────────────────────────────────────────────────────────────────


@app.get("/api/v1/sessions", response_model=list[SessionOut], tags=["sessions"])
async def list_sessions(_: None = AuthDep) -> list[SessionOut]:
    db = _get_db()
    sessions = db.get_scan_sessions(50)
    return [
        SessionOut(
            id=s["id"],
            label=s.get("label"),
            started_at=str(s.get("started_at", "")),
            finished_at=str(s.get("finished_at", "")) if s.get("finished_at") else None,
            summary=s.get("summary"),
        )
        for s in sessions
    ]


@app.get("/api/v1/sessions/{session_id}/findings", response_model=list[FindingOut], tags=["sessions"])
async def session_findings(session_id: int, _: None = AuthDep) -> list[FindingOut]:
    db = _get_db()
    findings = db.get_session_findings(session_id)
    return [
        FindingOut(
            id=f["id"],
            title=f["title"],
            severity=f.get("severity"),
            category=f.get("category"),
            description=f.get("description"),
            source=f.get("source"),
            session_id=f.get("session_id"),
            created_at=str(f["created_at"]) if f.get("created_at") else None,
        )
        for f in findings
    ]


# ── Scan jobs ─────────────────────────────────────────────────────────────────


async def _run_scan_job(job_id: str, target: str, phases: list[str]) -> None:
    """Background coroutine that runs an AIOrchestrator scan."""
    from aegis.core.ai_orchestrator import AIOrchestrator

    db = _get_db()
    cfg = _get_config()
    scope = ScopeManager(db, safe_mode=False)

    _scan_jobs[job_id]["status"] = "running"

    try:
        orchestrator = AIOrchestrator(
            target=target,
            config=cfg,
            db=db,
            scope=scope,
            full=False,
            dry_run=False,
            report_format="md",
        )
        # Override phases
        from aegis.core.ai_orchestrator import PHASE_TOOLS
        orchestrator._phase_summaries = {}
        orchestrator._findings = []

        session_id = orchestrator._start_session()
        _scan_jobs[job_id]["session_id"] = session_id

        for phase in phases:
            if phase == "reporting":
                continue
            from rich.progress import Progress
            with Progress(transient=True) as progress:
                orchestrator._run_phase(phase, progress)

        orchestrator._finish_session()
        findings_count = len(orchestrator._findings)
        _scan_jobs[job_id]["status"] = "completed"
        _scan_jobs[job_id]["findings_count"] = findings_count

    except Exception as exc:
        _scan_jobs[job_id]["status"] = "failed"
        _scan_jobs[job_id]["error"] = str(exc)


@app.post("/api/v1/scan", response_model=ScanJobOut, status_code=202, tags=["scan"])
async def trigger_scan(req: ScanRequest, _: None = AuthDep) -> ScanJobOut:
    job_id = str(uuid.uuid4())
    _scan_jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "target": req.target,
        "phases": req.phases,
        "session_id": None,
        "findings_count": None,
        "error": None,
    }
    asyncio.create_task(_run_scan_job(job_id, req.target, req.phases))
    return ScanJobOut(**_scan_jobs[job_id])


@app.get("/api/v1/scan/{job_id}", response_model=ScanJobOut, tags=["scan"])
async def get_scan_status(job_id: str, _: None = AuthDep) -> ScanJobOut:
    job = _scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanJobOut(**job)


# ── Reports ───────────────────────────────────────────────────────────────────


@app.get("/api/v1/report/{target}", tags=["reports"])
async def download_report(
    target: str,
    format: str = "md",
    _: None = AuthDep,
) -> Response:
    reports_dir = Path("data/reports")
    # Try exact match first, then glob
    for ext in (format, "pdf", "html", "md"):
        path = reports_dir / f"{target}.{ext}"
        if path.exists():
            media_types = {
                "pdf": "application/pdf",
                "html": "text/html",
                "md": "text/markdown",
                "sarif": "application/json",
            }
            return FileResponse(
                str(path),
                media_type=media_types.get(ext, "application/octet-stream"),
                filename=path.name,
            )
    raise HTTPException(status_code=404, detail="Report not found")


# ── Burp import ───────────────────────────────────────────────────────────────


@app.post("/api/v1/burp/import", tags=["burp"])
async def burp_import(
    file: UploadFile = File(...),
    dry_run: bool = False,
    _: None = AuthDep,
) -> dict[str, Any]:
    from aegis.core.burp_importer import import_burp_xml

    # Save upload to a temp file
    import tempfile
    import os

    content = await file.read()
    with tempfile.NamedTemporaryFile(
        suffix=".xml", delete=False, mode="wb"
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        db = _get_db()
        counts = import_burp_xml(tmp_path, db, dry_run=dry_run)
    finally:
        os.unlink(tmp_path)

    return {"status": "ok", "dry_run": dry_run, **counts}


# ── CVE ───────────────────────────────────────────────────────────────────────


@app.get("/api/v1/cve/{finding_id}", tags=["cve"])
async def get_cves(finding_id: int, _: None = AuthDep) -> dict[str, Any]:
    db = _get_db()
    if not db.get_finding(finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    cves = db.get_cve_correlations(finding_id)
    return {"finding_id": finding_id, "cves": cves}


# ── SARIF ─────────────────────────────────────────────────────────────────────


@app.get("/api/v1/sarif/{session_id}", tags=["sarif"])
async def export_sarif(session_id: int, _: None = AuthDep) -> Response:
    from aegis.core.sarif_exporter import export_sarif as _export_sarif

    db = _get_db()
    sarif_doc = _export_sarif(db, session_id=session_id)
    return Response(
        content=json.dumps(sarif_doc, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=aegis-session-{session_id}.sarif"},
    )


# ── Scope ─────────────────────────────────────────────────────────────────────


@app.get("/api/v1/scope", response_model=list[ScopeEntryOut], tags=["scope"])
async def list_scope(_: None = AuthDep) -> list[ScopeEntryOut]:
    db = _get_db()
    entries = db.get_scope_entries()
    return [ScopeEntryOut(id=e["id"], target=e["target"], kind=e["kind"]) for e in entries]


@app.post("/api/v1/scope", response_model=ScopeEntryOut, status_code=201, tags=["scope"])
async def add_scope(entry: ScopeEntryIn, _: None = AuthDep) -> ScopeEntryOut:
    db = _get_db()
    entry_id = db.add_scope_entry(entry.target, entry.kind)
    return ScopeEntryOut(id=entry_id, target=entry.target, kind=entry.kind)


@app.delete("/api/v1/scope/{entry_id}", status_code=204, tags=["scope"])
async def remove_scope(entry_id: int, _: None = AuthDep) -> None:
    db = _get_db()
    db.remove_scope_entry(entry_id)
