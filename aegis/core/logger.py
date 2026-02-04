from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional


_DEF_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


def setup_logging(log_file: Optional[str], debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    handlers = []
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(path, encoding="utf-8"))
    logging.basicConfig(level=level, format=_DEF_FORMAT, handlers=handlers or None)


def get_logger(name: str = "aegis") -> logging.Logger:
    return logging.getLogger(name)