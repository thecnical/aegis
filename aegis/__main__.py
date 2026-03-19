"""Aegis CLI entry point for installed package."""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running from source tree: python -m aegis
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import cli  # noqa: E402

if __name__ == "__main__":
    cli()
