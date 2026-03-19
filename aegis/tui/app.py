from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Label
from textual.containers import Vertical
from textual.binding import Binding

from aegis.core.db_manager import DatabaseManager


class FindingsTable(DataTable):
    """Findings data table widget."""


class FindingDetail(Static):
    """Finding detail panel."""

    def update_finding(self, finding: dict) -> None:
        text = (
            f"[bold cyan]ID:[/bold cyan] {finding.get('id')}\n"
            f"[bold cyan]Title:[/bold cyan] {finding.get('title')}\n"
            f"[bold cyan]Severity:[/bold cyan] {finding.get('severity')}\n"
            f"[bold cyan]Category:[/bold cyan] {finding.get('category')}\n"
            f"[bold cyan]Source:[/bold cyan] {finding.get('source')}\n"
            f"[bold cyan]Description:[/bold cyan]\n{finding.get('description', '')}\n"
        )
        self.update(text)


class AegisTUI(App):
    """Aegis interactive TUI."""

    CSS = """
    Screen { background: #0d1117; }
    Header { background: #161b22; color: #39d353; }
    Footer { background: #161b22; }
    FindingsTable { height: 60%; border: solid #30363d; }
    FindingDetail { height: 40%; border: solid #30363d; padding: 1 2; color: #c9d1d9; }
    Label { color: #39d353; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
    ]

    def __init__(self, db: DatabaseManager) -> None:
        super().__init__()
        self._db = db
        self._findings: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("⚔ Aegis — Interactive Mode  |  ↑↓ Navigate  |  Enter: Detail  |  R: Refresh  |  Q: Quit")
        with Vertical():
            yield FindingsTable(id="findings_table")
            yield FindingDetail(id="detail_panel")
        yield Footer()

    def on_mount(self) -> None:
        self._load_findings()

    def _load_findings(self) -> None:
        table = self.query_one("#findings_table", FindingsTable)
        table.clear(columns=True)
        table.add_columns("ID", "Title", "Severity", "Source", "Created")
        conn = self._db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings ORDER BY created_at DESC LIMIT 200")
        self._findings = [dict(row) for row in cursor.fetchall()]
        for f in self._findings:
            table.add_row(
                str(f.get("id", "")),
                str(f.get("title", ""))[:60],
                str(f.get("severity", "")),
                str(f.get("source", "")),
                str(f.get("created_at", ""))[:16],
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_idx = event.cursor_row
        if 0 <= row_idx < len(self._findings):
            finding = self._findings[row_idx]
            detail = self.query_one("#detail_panel", FindingDetail)
            detail.update_finding(finding)

    def action_refresh(self) -> None:
        self._load_findings()
        self.query_one("#detail_panel", FindingDetail).update("Refreshed.")
