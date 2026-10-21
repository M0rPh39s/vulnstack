"""Logging configuration.

Logs go to stderr so they never pollute machine-readable report output on
stdout. The default level hides internal detail; ``--verbose`` raises it to
DEBUG. Secrets (e.g. API keys) must never be passed to the logger.
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def configure_logging(verbose: bool = False) -> None:
    global _CONFIGURED
    level = logging.DEBUG if verbose else logging.WARNING
    root = logging.getLogger("vulnstack")
    root.setLevel(level)
    if not _CONFIGURED:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        root.addHandler(handler)
        root.propagate = False
        _CONFIGURED = True
    else:
        for handler in root.handlers:
            handler.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"vulnstack.{name}")
