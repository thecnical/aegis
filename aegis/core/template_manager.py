"""Manage custom report templates for Aegis."""
from __future__ import annotations

import shutil
from importlib import resources
from pathlib import Path
from typing import Optional

BUILTIN_TEMPLATES: dict[str, str] = {
    "default": "report.md",
    "default-html": "report.html",
    "professional": "custom_report.html",
    "minimal": "minimal_report.html",
}

# Required placeholders that a valid template must contain at least one of
REQUIRED_PLACEHOLDERS = {"$title", "$generated_at", "$findings"}


class TemplateManager:
    """Manage built-in and custom report templates."""

    def __init__(self, templates_dir: Optional[str] = None) -> None:
        if templates_dir:
            self._custom_dir = Path(templates_dir)
        else:
            self._custom_dir = Path("data/templates")
        self._custom_dir.mkdir(parents=True, exist_ok=True)

    def _builtin_path(self, filename: str) -> Optional[Path]:
        """Resolve a built-in template filename to a Path."""
        try:
            ref = resources.files("aegis.templates").joinpath(filename)
            # resources.files returns a Traversable; convert to Path if possible
            path = Path(str(ref))
            if path.exists():
                return path
        except Exception:
            pass
        # Fallback: look relative to this file
        fallback = Path(__file__).parent.parent / "templates" / filename
        if fallback.exists():
            return fallback
        return None

    def list_templates(self) -> list[dict]:
        """List all available templates (builtin + custom)."""
        templates: list[dict] = []

        for name, filename in BUILTIN_TEMPLATES.items():
            path = self._builtin_path(filename)
            templates.append(
                {
                    "name": name,
                    "filename": filename,
                    "kind": "builtin",
                    "path": str(path) if path else None,
                    "available": path is not None and path.exists(),
                }
            )

        # Custom templates in data/templates/
        for custom_file in sorted(self._custom_dir.glob("*.html")) + sorted(
            self._custom_dir.glob("*.md")
        ):
            templates.append(
                {
                    "name": custom_file.stem,
                    "filename": custom_file.name,
                    "kind": "custom",
                    "path": str(custom_file),
                    "available": True,
                }
            )

        return templates

    def get_template_path(self, name: str) -> str:
        """Resolve template name to file path.

        Raises FileNotFoundError if not found.
        """
        # Check custom templates first
        for ext in (".html", ".md"):
            custom = self._custom_dir / f"{name}{ext}"
            if custom.exists():
                return str(custom)

        # Check built-in templates
        if name in BUILTIN_TEMPLATES:
            filename = BUILTIN_TEMPLATES[name]
            path = self._builtin_path(filename)
            if path and path.exists():
                return str(path)

        raise FileNotFoundError(f"Template '{name}' not found")

    def install_template(self, source_path: str, name: str) -> str:
        """Install a custom template from a file.

        Returns the installed template path.
        """
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"Source template not found: {source_path}")

        dest = self._custom_dir / f"{name}{src.suffix}"
        shutil.copy2(src, dest)
        return str(dest)

    def validate_template(self, template_path: str) -> tuple[bool, str]:
        """Validate a template has required placeholders.

        Returns (is_valid, message).
        """
        path = Path(template_path)
        if not path.exists():
            return False, f"File not found: {template_path}"

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            return False, f"Cannot read file: {exc}"

        missing = [p for p in REQUIRED_PLACEHOLDERS if p not in content]
        if missing:
            return (
                False,
                f"Missing required placeholders: {', '.join(missing)}",
            )

        return True, "Template is valid"
