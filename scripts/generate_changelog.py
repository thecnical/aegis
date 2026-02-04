from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


CONVENTIONAL_RE = re.compile(
    r"^(?P<type>[a-zA-Z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?:\s*(?P<subject>.+)$"
)


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _all_tags() -> list[str]:
    tags = _run(["git", "tag", "--sort=-creatordate"])
    return [t for t in tags.splitlines() if t.strip()]


def _log_range(start: str | None, end: str) -> list[str]:
    if start:
        range_spec = f"{start}..{end}"
    else:
        range_spec = end
    log_text = _run(["git", "log", range_spec, "--pretty=format:%s"])
    return [line.strip() for line in log_text.splitlines() if line.strip()]


def _repo_url() -> str:
    url = _run(["git", "config", "--get", "remote.origin.url"])
    if url.startswith("git@github.com:"):
        path = url.split("git@github.com:", 1)[1].replace(".git", "")
        return f"https://github.com/{path}"
    if url.startswith("https://github.com/"):
        return url.replace(".git", "")
    return ""


def _linkify(message: str, repo: str) -> str:
    if not repo:
        return message
    message = re.sub(r"\(#(\d+)\)", rf"([#\1]({repo}/pull/\1))", message)
    message = re.sub(r"(?<!\w)#(\d+)", rf"[#\1]({repo}/issues/\1)", message)
    return message


def _categorize(messages: list[str], repo: str) -> dict[str, list[str]]:
    sections = {
        "Breaking Changes": [],
        "Features": [],
        "Fixes": [],
        "Docs": [],
        "Refactors": [],
        "Performance": [],
        "Tests": [],
        "Chores": [],
        "Other": [],
    }
    for msg in messages:
        linked = _linkify(msg, repo)
        match = CONVENTIONAL_RE.match(msg)
        if not match:
            sections["Other"].append(linked)
            continue
        type_name = match.group("type").lower()
        breaking = bool(match.group("breaking"))
        subject = match.group("subject").strip()
        scoped = _linkify(subject, repo)

        if breaking:
            sections["Breaking Changes"].append(scoped)

        if type_name == "feat":
            sections["Features"].append(scoped)
        elif type_name == "fix":
            sections["Fixes"].append(scoped)
        elif type_name == "docs":
            sections["Docs"].append(scoped)
        elif type_name == "refactor":
            sections["Refactors"].append(scoped)
        elif type_name == "perf":
            sections["Performance"].append(scoped)
        elif type_name == "test":
            sections["Tests"].append(scoped)
        elif type_name in {"chore", "build", "ci", "style"}:
            sections["Chores"].append(scoped)
        else:
            sections["Other"].append(scoped)
    return sections


def _format_section(title: str, items: list[str]) -> str:
    if not items:
        return f"## {title}\n- No changes recorded.\n"
    lines = "\n".join([f"- {item}" for item in items])
    return f"## {title}\n{lines}\n"


def _build_release_notes(tag: str | None, repo: str) -> str:
    tags = _all_tags()
    if tag and tag in tags:
        idx = tags.index(tag)
        previous = tags[idx + 1] if idx + 1 < len(tags) else None
        messages = _log_range(previous, tag)
        sections = _categorize(messages, repo)
        body = [f"## {tag}\n"]
        for name in sections:
            body.append(_format_section(name, sections[name]))
        return "\n".join(body)

    if tags:
        messages = _log_range(tags[0], "HEAD")
    else:
        messages = _log_range(None, "HEAD")
    sections = _categorize(messages, repo)
    body = ["## Unreleased\n"]
    for name in sections:
        body.append(_format_section(name, sections[name]))
    return "\n".join(body)


def _build_changelog(repo: str) -> str:
    tags = _all_tags()
    sections_text = ["# Changelog\n"]

    if tags:
        unreleased = _log_range(tags[0], "HEAD")
        if unreleased:
            sections = _categorize(unreleased, repo)
            sections_text.append("## Unreleased\n")
            for name in sections:
                sections_text.append(_format_section(name, sections[name]))

        for idx, tag in enumerate(tags):
            previous = tags[idx + 1] if idx + 1 < len(tags) else None
            messages = _log_range(previous, tag)
            sections = _categorize(messages, repo)
            sections_text.append(f"## {tag}\n")
            for name in sections:
                sections_text.append(_format_section(name, sections[name]))
    else:
        sections = _categorize(_log_range(None, "HEAD"), repo)
        sections_text.append("## Unreleased\n")
        for name in sections:
            sections_text.append(_format_section(name, sections[name]))

    return "\n".join(sections_text).strip() + "\n"


def main() -> None:
    repo = _repo_url()
    tag_name = os.environ.get("GITHUB_REF_NAME")
    release_notes = _build_release_notes(tag_name, repo)
    changelog = _build_changelog(repo)
    Path("CHANGELOG.md").write_text(changelog, encoding="utf-8")
    Path("RELEASE_NOTES.md").write_text(release_notes, encoding="utf-8")


if __name__ == "__main__":
    main()
