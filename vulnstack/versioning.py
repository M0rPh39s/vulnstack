"""Deterministic version comparison.

Comparing software versions correctly is central to accurate CVE matching.
Ordinary lexical string comparison is wrong (``"9" > "10"`` lexically), and
not every product follows semantic versioning or PEP 440. This module exposes
a small comparison abstraction:

* :func:`compare` returns -1/0/1, or ``None`` when the two versions cannot be
  compared safely (unknown/incompatible schemes). Callers must treat ``None``
  as *uncertain*, never as a match.
* :func:`in_range` evaluates a detected version against a structured
  affected-version range and returns a :class:`RangeResult`.

The comparator first tries :class:`packaging.version.Version` (correct for
PEP 440 / semantic-version-like strings). When that fails for either operand
it falls back to a loose, component-wise numeric/alpha tokenizer that still
avoids lexical pitfalls. If even that cannot interpret a token meaningfully it
reports uncertainty rather than fabricating an ordering.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from packaging.version import InvalidVersion, Version

__all__ = ["compare", "in_range", "RangeOutcome", "RangeResult", "normalize_version"]

_TOKEN_RE = re.compile(r"(\d+|[a-zA-Z]+)")
_SEP_RE = re.compile(r"[.\-_+~:]+")
# Wildcard / "not applicable" markers used by CPE and various feeds.
_WILDCARDS = {"", "*", "-", "n/a", "na", "none", "unknown", "any"}


def normalize_version(raw: str | None) -> str | None:
    """Strip a version-like token out of a free-form string.

    Returns ``None`` when nothing version-like is present. This never invents
    digits; it only extracts an existing dotted/numeric sequence.
    """
    if raw is None:
        return None
    text = raw.strip()
    if text.lower() in _WILDCARDS:
        return None
    # Prefer a dotted numeric run (e.g. "1.18.0"), optionally with a suffix.
    m = re.search(r"\d+(?:\.\d+)*(?:[.\-_]?[a-zA-Z0-9]+)*", text)
    if not m:
        return None
    return m.group(0)


def _tokenize(version: str) -> list[tuple[int, object]]:
    """Split a version into comparable tokens.

    Numeric runs become ``(0, int)`` and alphabetic runs ``(1, str)``.
    """
    tokens: list[tuple[int, object]] = []
    for part in _SEP_RE.split(version.strip().lower()):
        for match in _TOKEN_RE.finditer(part):
            tok = match.group(0)
            if tok.isdigit():
                tokens.append((0, int(tok)))
            else:
                tokens.append((1, tok))
    return tokens


def _loose_compare(a: str, b: str) -> int | None:
    ta, tb = _tokenize(a), _tokenize(b)
    if not ta or not tb:
        return None
    for xa, xb in zip(ta, tb):
        if xa[0] != xb[0]:
            # Numeric component (0) is treated as a release and ranks higher
            # than an alphabetic one (1), which we treat as a pre-release tag.
            return 1 if xa[0] == 0 else -1
        if xa[1] != xb[1]:
            return -1 if xa[1] < xb[1] else 1  # type: ignore[operator]
    if len(ta) == len(tb):
        return 0
    # The longer version has trailing tokens. A trailing numeric run means a
    # later release (1.2.1 > 1.2); a trailing alpha run is a pre-release tag
    # (1.2 > 1.2rc1), so the longer one ranks lower.
    longer, sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    first_extra = longer[min(len(ta), len(tb))]
    if first_extra[0] == 1:
        return -sign
    return sign


def compare(a: str | None, b: str | None) -> int | None:
    """Compare two versions.

    Returns -1 (a<b), 0 (a==b), 1 (a>b), or ``None`` if the comparison cannot
    be made safely.
    """
    if a is None or b is None:
        return None
    a, b = a.strip(), b.strip()
    if not a or not b:
        return None
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        return _loose_compare(a, b)
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


class RangeOutcome(str, Enum):
    IN_RANGE = "in_range"
    OUT_OF_RANGE = "out_of_range"
    UNCERTAIN = "uncertain"
    NO_CONSTRAINT = "no_constraint"


@dataclass
class RangeResult:
    outcome: RangeOutcome
    detail: str = ""


def _cmp_or_uncertain(a: str, b: str) -> int | None:
    return compare(a, b)


def in_range(
    detected: str | None,
    *,
    exact: str | None = None,
    start: str | None = None,
    start_including: bool = False,
    end: str | None = None,
    end_including: bool = False,
) -> RangeResult:
    """Evaluate ``detected`` against a structured affected-version constraint.

    * ``exact`` — the record names a single concrete affected version.
    * ``start`` / ``end`` with inclusive/exclusive boundary flags — a range.

    When no constraint is supplied the result is ``NO_CONSTRAINT`` (the record
    affects the product with no version discriminator). Any comparison that
    cannot be made safely yields ``UNCERTAIN``.
    """
    detected = normalize_version(detected) if detected else None

    exact = None if (exact is None or exact.strip().lower() in _WILDCARDS) else exact.strip()
    start = None if (start is None or start.strip().lower() in _WILDCARDS) else start.strip()
    end = None if (end is None or end.strip().lower() in _WILDCARDS) else end.strip()

    has_constraint = bool(exact or start or end)
    if not has_constraint:
        return RangeResult(RangeOutcome.NO_CONSTRAINT, "no version discriminator on record")

    if detected is None:
        return RangeResult(RangeOutcome.UNCERTAIN, "detected version unknown")

    if exact is not None:
        c = _cmp_or_uncertain(detected, exact)
        if c is None:
            return RangeResult(RangeOutcome.UNCERTAIN, f"cannot compare {detected} with {exact}")
        return (
            RangeResult(RangeOutcome.IN_RANGE, f"exact match {exact}")
            if c == 0
            else RangeResult(RangeOutcome.OUT_OF_RANGE, f"{detected} != {exact}")
        )

    # Range evaluation.
    if start is not None:
        c = _cmp_or_uncertain(detected, start)
        if c is None:
            return RangeResult(RangeOutcome.UNCERTAIN, f"cannot compare {detected} with start {start}")
        if c < 0 or (c == 0 and not start_including):
            return RangeResult(RangeOutcome.OUT_OF_RANGE, f"{detected} below start {start}")
    if end is not None:
        c = _cmp_or_uncertain(detected, end)
        if c is None:
            return RangeResult(RangeOutcome.UNCERTAIN, f"cannot compare {detected} with end {end}")
        if c > 0 or (c == 0 and not end_including):
            return RangeResult(RangeOutcome.OUT_OF_RANGE, f"{detected} above end {end}")
    return RangeResult(RangeOutcome.IN_RANGE, "within affected range")
