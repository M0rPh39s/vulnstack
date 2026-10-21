"""Optional CVE List v5 (CVE Record Format) provider.

Supports the official CVE Project JSON records
(https://github.com/CVEProject/cvelistV5). Because the full repository is very
large, this provider ingests records from a *local* path — a single ``.json``
file or a directory tree of them (e.g. a clone or an export). This keeps normal
operation independent of any single website's availability and makes the
provider usable offline and in tests.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from vulnstack.cve.models import (
    AffectedProduct,
    Reference,
    Vulnerability,
    VersionRange,
)
from vulnstack.cve.nvd import _parse_cpe
from vulnstack.cve.providers import Provider, ProviderError, ProgressCallback, register
from vulnstack.logging_config import get_logger

log = get_logger("cvelist")


def _parse_versions(affected: dict) -> tuple[str | None, list[VersionRange]]:
    """Parse CVE 5.x ``versions`` into a concrete version and/or ranges."""
    concrete: str | None = None
    ranges: list[VersionRange] = []
    for v in affected.get("versions", []):
        status = (v.get("status") or "").lower()
        if status and status != "affected":
            continue
        version = v.get("version")
        less_than = v.get("lessThan")
        less_equal = v.get("lessThanOrEqual")
        if less_than or less_equal:
            ranges.append(
                VersionRange(
                    version_start=version if version not in (None, "0", "*") else None,
                    version_start_type="including" if version not in (None, "0", "*") else None,
                    version_end=less_than or less_equal,
                    version_end_type="excluding" if less_than else "including",
                    version_scheme=v.get("versionType"),
                )
            )
        elif version and version not in ("*", "-"):
            concrete = version
    return concrete, ranges


def parse_record(record: dict) -> Vulnerability | None:
    """Normalize one CVE 5.x record into a Vulnerability."""
    if not isinstance(record, dict):
        return None
    meta = record.get("cveMetadata", {})
    cve_id = meta.get("cveId")
    if not cve_id:
        return None
    containers = record.get("containers", {})
    cna = containers.get("cna", {})

    description = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            description = d.get("value", "")
            break

    score = cvss_version = vector = severity = None
    for metric in cna.get("metrics", []):
        for ver_key, ver in (("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0")):
            data = metric.get(ver_key)
            if data:
                score = data.get("baseScore")
                vector = data.get("vectorString")
                severity = (data.get("baseSeverity") or "").upper() or None
                cvss_version = ver
                break
        if score is not None:
            break

    weaknesses: list[str] = []
    for problem in cna.get("problemTypes", []):
        for desc in problem.get("descriptions", []):
            cwe = desc.get("cweId")
            if cwe:
                weaknesses.append(cwe.upper())

    references = [
        Reference(url=r["url"], ref_type=",".join(r.get("tags", [])) or None)
        for r in cna.get("references", [])
        if r.get("url")
    ]

    affected_products: list[AffectedProduct] = []
    for aff in cna.get("affected", []):
        vendor = aff.get("vendor")
        product = aff.get("product")
        concrete, ranges = _parse_versions(aff)
        cpes = aff.get("cpes") or []
        # Prefer the record's own CPE: display names ("Apache Software
        # Foundation" / "Apache HTTP Server") do not equal CPE vendor/product
        # fields ("apache" / "http_server") and would never match a scan.
        cpe_vendor, cpe_product, _ = _parse_cpe(cpes[0]) if cpes else (None, None, None)
        affected_products.append(
            AffectedProduct(
                vendor=vendor,
                product=product,
                cpe_vendor=cpe_vendor or (vendor or "").lower().replace(" ", "_") or None,
                cpe_product=cpe_product or (product or "").lower().replace(" ", "_") or None,
                cpe23=cpes[0] if cpes else None,
                version=concrete,
                ranges=ranges,
            )
        )

    return Vulnerability(
        cve_id=cve_id,
        description=description,
        published=meta.get("datePublished"),
        last_modified=meta.get("dateUpdated"),
        cvss_score=score,
        cvss_version=cvss_version,
        cvss_vector=vector,
        severity=severity,
        status=meta.get("state"),
        source="cvelist",
        weaknesses=weaknesses,
        references=references,
        affected=affected_products,
    )


class CveListProvider(Provider):
    name = "cvelist"

    def __init__(self, *, path: str | None = None, **_: object) -> None:
        if not path:
            raise ProviderError(
                "the 'cvelist' source requires a local path "
                "(set via config or VULNSTACK_CVELIST_PATH)"
            )
        self.path = Path(path).expanduser()
        self._latest: str | None = None

    def latest_source_modified(self) -> str | None:
        return self._latest

    def _iter_files(self) -> Iterator[Path]:
        if self.path.is_file():
            yield self.path
        elif self.path.is_dir():
            yield from sorted(self.path.rglob("CVE-*.json"))
        else:
            raise ProviderError(f"cvelist path does not exist: {self.path}")

    def fetch(
        self,
        *,
        modified_since: datetime | None,
        full: bool,
        progress: ProgressCallback | None = None,
    ) -> Iterator[Vulnerability]:
        # A local tree is always read in full: every file must be opened to
        # learn its dateUpdated anyway, and a first run should import the whole
        # mirror, so ``modified_since`` is deliberately not applied here.
        count = 0
        for file in self._iter_files():
            try:
                record = json.loads(file.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                log.warning("Skipping unreadable CVE record %s: %s", file, exc)
                continue
            vuln = parse_record(record)
            if vuln is None:
                log.warning("Skipping %s: not a CVE record", file)
                continue
            if vuln.last_modified and (self._latest is None or vuln.last_modified > self._latest):
                self._latest = vuln.last_modified
            count += 1
            if progress is not None and count % 100 == 0:
                progress(count, None)
            yield vuln


def _factory(**kwargs) -> CveListProvider:
    return CveListProvider(**kwargs)


register("cvelist", _factory)
