"""
Centralized structured logger.

All modules import `get_logger(__name__)` rather than configuring
logging themselves, so log format/level stays consistent and can be
changed in one place (e.g. when this becomes an API service and we
want JSON logs shipped to stdout for a log collector).
"""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def _configure_root(level: int = logging.INFO) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    root = logging.getLogger("seo_security_analyzer")
    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False

    _CONFIGURED = True


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    _configure_root(level)
    return logging.getLogger(f"seo_security_analyzer.{name}")


def set_global_level(level: int) -> None:
    logging.getLogger("seo_security_analyzer").setLevel(level)
