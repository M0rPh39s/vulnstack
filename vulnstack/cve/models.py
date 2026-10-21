"""Internal data model for normalized vulnerability records.

Provider-specific payloads (NVD, CVE List) are normalized into these
dataclasses before being written to the database, so the rest of the
application never depends on a particular provider's JSON shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VersionRange:
    version_start: str | None = None
    version_start_type: str | None = None  # "including" | "excluding" | None
    version_end: str | None = None
    version_end_type: str | None = None    # "including" | "excluding" | None
    version_scheme: str | None = None
    fixed_version: str | None = None


@dataclass
class AffectedProduct:
    vendor: str | None = None
    product: str | None = None
    cpe_vendor: str | None = None
    cpe_product: str | None = None
    cpe23: str | None = None
    version: str | None = None            # concrete version if the record names one
    version_scheme: str | None = None
    ranges: list[VersionRange] = field(default_factory=list)


@dataclass
class Reference:
    url: str
    ref_type: str | None = None


@dataclass
class Vulnerability:
    cve_id: str
    description: str = ""
    published: str | None = None
    last_modified: str | None = None
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    status: str | None = None
    source: str = "nvd"
    weaknesses: list[str] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    affected: list[AffectedProduct] = field(default_factory=list)
