"""Logging setup.

By default we log to console via rich and, optionally, to a file. We never
write real server IPs / SNI / credentials to the log at INFO level; those
only appear at DEBUG, which is off unless the user opts in. This keeps a
shared or synced log file from leaking which endpoints you use.
"""
from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler

_SENSITIVE_PLACEHOLDER = "<redacted>"


def setup_logging(level: str = "INFO", logfile: str | None = None) -> logging.Logger:
    level_value = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [
        RichHandler(rich_tracebacks=True, show_path=False, markup=False)
    ]

    if logfile:
        path = Path(logfile).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=level_value,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )
    return logging.getLogger("netbypass")


def redact(value: str) -> str:
    """Return a placeholder for sensitive values logged at INFO level."""
    return _SENSITIVE_PLACEHOLDER
