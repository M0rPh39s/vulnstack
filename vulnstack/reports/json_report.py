"""JSON report rendering.

Produces a valid, machine-readable JSON document from a :class:`ScanResult`.
Never includes secrets (API keys, cookies, authorization headers): the scan
pipeline does not collect them, and only the fields assembled on the result are
serialized.
"""

from __future__ import annotations

import json

from vulnstack.scanner import ScanResult


def render(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)
