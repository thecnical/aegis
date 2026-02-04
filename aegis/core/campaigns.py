from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from aegis.core.ui import console
from aegis.core.utils import ensure_dir


def _campaign_path() -> Path:
    ensure_dir("data")
    return Path("data/campaigns.json")


def load_campaigns() -> Dict[str, dict]:
    path = _campaign_path()
    if not path.exists():
        return {"campaigns": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"campaigns": {}}


def save_campaigns(data: Dict[str, dict]) -> None:
    path = _campaign_path()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def create_campaign(name: str, targets: Dict[str, str]) -> None:
    data = load_campaigns()
    if name in data["campaigns"]:
        console.print(f"[warning]Campaign already exists:[/warning] {name}")
        return
    data["campaigns"][name] = {"targets": targets, "runs": []}
    save_campaigns(data)


def list_campaigns() -> List[dict]:
    data = load_campaigns()
    campaigns = []
    for name, info in data["campaigns"].items():
        campaigns.append(
            {
                "name": name,
                "targets": info.get("targets", {}),
                "runs": len(info.get("runs", [])),
            }
        )
    return campaigns


def add_run(name: str, summary: Dict[str, int]) -> None:
    data = load_campaigns()
    campaign = data["campaigns"].get(name)
    if not campaign:
        console.print(f"[error]Campaign not found:[/error] {name}")
        return
    run = {"timestamp": datetime.utcnow().isoformat(), "summary": summary}
    campaign.setdefault("runs", []).append(run)
    save_campaigns(data)


def get_runs(name: str) -> List[dict]:
    data = load_campaigns()
    campaign = data["campaigns"].get(name)
    if not campaign:
        return []
    return campaign.get("runs", [])


def summarize_db(db) -> Dict[str, int]:
    conn = db.connect()
    cursor = conn.cursor()
    summary = {
        "hosts": cursor.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
        "ports": cursor.execute("SELECT COUNT(*) FROM ports").fetchone()[0],
        "services": cursor.execute("SELECT COUNT(*) FROM services").fetchone()[0],
        "vulns": cursor.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
        "findings": cursor.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
    }
    return summary


def diff_runs(run_a: dict, run_b: dict) -> Dict[str, int]:
    summary_a = run_a.get("summary", {})
    summary_b = run_b.get("summary", {})
    deltas: Dict[str, int] = {}
    for key in set(summary_a.keys()) | set(summary_b.keys()):
        deltas[key] = int(summary_b.get(key, 0)) - int(summary_a.get(key, 0))
    return deltas


def generate_campaign_report(name: str) -> Path | None:
    runs = get_runs(name)
    if not runs:
        console.print(f"[warning]No runs found for campaign:[/warning] {name}")
        return None

    ensure_dir("data/reports")
    report_path = Path("data/reports") / f"campaign_{name}.md"
    lines: List[str] = []
    lines.append(f"# Campaign Report: {name}")
    lines.append("")
    lines.append(f"Total runs: {len(runs)}")
    lines.append("")
    lines.append("## Runs")
    for idx, run in enumerate(runs, start=1):
        lines.append(f"- Run {idx} @ {run.get('timestamp')}: {run.get('summary')}")

    if len(runs) >= 2:
        lines.append("")
        lines.append("## Latest Diff")
        delta = diff_runs(runs[-2], runs[-1])
        for key, value in delta.items():
            lines.append(f"- {key}: {value:+d}")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
