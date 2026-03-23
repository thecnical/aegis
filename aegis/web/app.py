from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates

from aegis.core.db_manager import DatabaseManager
from aegis.core.config_manager import ConfigManager

app = FastAPI(title="Aegis Web UI")

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

_config = ConfigManager("config/config.yaml")
_config.load()
_db_path = _config.get("general.db_path", "data/aegis.db")
_db = DatabaseManager(_db_path)
_db.init_db()


def _get_db() -> DatabaseManager:
    return _db


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    db = _get_db()
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity")
    counts = {row["severity"]: row["cnt"] for row in cursor.fetchall()}
    cursor.execute("SELECT COUNT(*) as total FROM findings")
    total = cursor.fetchone()["total"]
    return templates.TemplateResponse(request, "dashboard.html", {
        "counts": counts, "total": total
    })


@app.get("/findings", response_class=HTMLResponse)
async def findings_list(request: Request, page: int = 1, per_page: int = 25) -> HTMLResponse:
    db = _get_db()
    conn = db.connect()
    cursor = conn.cursor()
    offset = (page - 1) * per_page
    cursor.execute("SELECT * FROM findings ORDER BY created_at DESC LIMIT ? OFFSET ?", (per_page, offset))
    findings = [dict(row) for row in cursor.fetchall()]
    return templates.TemplateResponse(request, "findings.html", {
        "findings": findings, "page": page
    })


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(request: Request, finding_id: int) -> HTMLResponse:
    db = _get_db()
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    if not row:
        return HTMLResponse("<h1>Not found</h1>", status_code=404)
    finding = dict(row)
    notes = db.get_notes(finding_id)
    tags = db.get_tags(finding_id)
    return templates.TemplateResponse(request, "finding_detail.html", {
        "finding": finding, "notes": notes, "tags": tags
    })


@app.post("/findings/{finding_id}/notes", response_class=HTMLResponse)
async def add_note(request: Request, finding_id: int, body: str = Form(...)) -> HTMLResponse:
    db = _get_db()
    db.add_note(finding_id, body)
    notes = db.get_notes(finding_id)
    return templates.TemplateResponse(request, "partials/notes.html", {
        "notes": notes, "finding_id": finding_id
    })


@app.get("/sessions", response_class=HTMLResponse)
async def sessions_list(request: Request) -> HTMLResponse:
    db = _get_db()
    sessions = db.get_scan_sessions(50)
    return templates.TemplateResponse(request, "sessions.html", {
        "sessions": sessions
    })


@app.get("/report/{target}")
async def download_report(target: str) -> HTMLResponse | FileResponse:
    for ext in ("pdf", "html", "md"):
        path = Path("data/reports") / f"{target}.{ext}"
        if path.exists():
            return FileResponse(str(path), filename=path.name)
    return HTMLResponse("<h1>Report not found</h1>", status_code=404)
