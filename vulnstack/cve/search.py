"""Deterministic local vulnerability search engine.

Implements the staged pipeline described in the project spec:

* **A. Normalization** — detected technology names are normalized via the
  explicit alias registry (:mod:`vulnstack.product_mapping`).
* **B. Product resolution** — names resolve to vendor/product/CPE identities;
  ambiguity is preserved, never guessed away.
* **C. Indexed candidate retrieval** — candidate CVEs are fetched with a single
  batched, index-backed query (``idx_affected_cpe``); no full-table scans, no
  per-product internet requests, no loading the whole corpus into RAM.
* **D. Version comparison** — detected versions are compared against structured
  affected-version ranges using :mod:`vulnstack.versioning` (never lexical).
* **E. Classification** — each result gets an explicit machine-readable class.
* **F. Deduplication** — CVEs found via multiple technologies/products are
  merged while preserving every matched product and piece of evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from vulnstack import product_mapping
from vulnstack.cve.database import Database
from vulnstack.logging_config import get_logger
from vulnstack.versioning import RangeOutcome, in_range, normalize_version

log = get_logger("search")


class Classification(str, Enum):
    MATCHED_AFFECTED_RANGE = "MATCHED_AFFECTED_RANGE"
    VERSION_NOT_MATCHED = "VERSION_NOT_MATCHED"
    VERSION_UNKNOWN = "VERSION_UNKNOWN"
    PRODUCT_MAPPING_AMBIGUOUS = "PRODUCT_MAPPING_AMBIGUOUS"
    AFFECTED_RANGE_UNAVAILABLE = "AFFECTED_RANGE_UNAVAILABLE"
    SOURCE_DATA_INCOMPLETE = "SOURCE_DATA_INCOMPLETE"


# Priority for picking a CVE's representative classification across products
# (higher = stronger / more important to surface).
_PRIORITY = {
    Classification.MATCHED_AFFECTED_RANGE: 6,
    Classification.VERSION_UNKNOWN: 5,
    Classification.PRODUCT_MAPPING_AMBIGUOUS: 4,
    Classification.AFFECTED_RANGE_UNAVAILABLE: 3,
    Classification.SOURCE_DATA_INCOMPLETE: 2,
    Classification.VERSION_NOT_MATCHED: 1,
}


@dataclass
class MatchedProduct:
    technology: str
    detected_version: str | None
    cpe_vendor: str | None
    cpe_product: str | None
    cpe23: str | None
    classification: Classification
    detail: str


@dataclass
class Finding:
    cve_id: str
    classification: Classification
    severity: str | None
    cvss_score: float | None
    cvss_version: str | None
    description: str
    published: str | None
    source: str
    technologies: list[str] = field(default_factory=list)
    matched_products: list[MatchedProduct] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "classification": self.classification.value,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "description": self.description,
            "published": self.published,
            "source": self.source,
            "technologies": self.technologies,
            "matched_products": [
                {
                    "technology": mp.technology,
                    "detected_version": mp.detected_version,
                    "cpe_vendor": mp.cpe_vendor,
                    "cpe_product": mp.cpe_product,
                    "cpe23": mp.cpe23,
                    "classification": mp.classification.value,
                    "detail": mp.detail,
                }
                for mp in self.matched_products
            ],
            "references": self.references,
        }


@dataclass
class SearchQuery:
    technology: str
    version: str | None = None


@dataclass
class TechnologyResolution:
    technology: str
    resolved: bool
    ambiguous: bool
    candidates: list[str] = field(default_factory=list)


@dataclass
class SearchReport:
    findings: list[Finding]
    unresolved: list[str]            # technologies with no local product identity
    resolutions: list[TechnologyResolution]


def _classify_product(detected_version: str | None, ap: dict) -> tuple[Classification, str]:
    ranges = ap.get("ranges") or []
    concrete = ap.get("version")

    if not ranges and not concrete:
        if detected_version is None:
            return Classification.VERSION_UNKNOWN, "product match; version unknown"
        return (
            Classification.AFFECTED_RANGE_UNAVAILABLE,
            "product matches but record carries no version range to confirm",
        )

    if detected_version is None:
        return Classification.VERSION_UNKNOWN, "candidate product; detected version unknown"

    if ranges:
        outcomes = []
        for r in ranges:
            res = in_range(
                detected_version,
                start=r.get("version_start"),
                start_including=(r.get("version_start_type") == "including"),
                end=r.get("version_end"),
                end_including=(r.get("version_end_type") == "including"),
            )
            outcomes.append(res)
        if any(o.outcome == RangeOutcome.IN_RANGE for o in outcomes):
            detail = next(o.detail for o in outcomes if o.outcome == RangeOutcome.IN_RANGE)
            return Classification.MATCHED_AFFECTED_RANGE, detail
        if any(o.outcome == RangeOutcome.UNCERTAIN for o in outcomes):
            return Classification.SOURCE_DATA_INCOMPLETE, "version comparison uncertain"
        if any(o.outcome == RangeOutcome.NO_CONSTRAINT for o in outcomes):
            return Classification.AFFECTED_RANGE_UNAVAILABLE, "no usable version constraint"
        return Classification.VERSION_NOT_MATCHED, "detected version outside all affected ranges"

    # Concrete version, no ranges -> exact comparison.
    res = in_range(detected_version, exact=concrete)
    if res.outcome == RangeOutcome.IN_RANGE:
        return Classification.MATCHED_AFFECTED_RANGE, res.detail
    if res.outcome == RangeOutcome.UNCERTAIN:
        return Classification.SOURCE_DATA_INCOMPLETE, res.detail
    return Classification.VERSION_NOT_MATCHED, res.detail


class VulnerabilitySearch:
    def __init__(self, db: Database) -> None:
        self.db = db

    def search(self, queries: list[SearchQuery]) -> SearchReport:
        # Stage A + B: normalize and resolve each technology.
        resolutions: list[TechnologyResolution] = []
        unresolved: list[str] = []
        # Map (cpe_vendor, cpe_product) -> list of (query, ambiguous)
        pair_to_queries: dict[tuple[str, str], list[tuple[SearchQuery, bool]]] = {}

        for q in queries:
            resolved = product_mapping.resolve(q.technology)
            if not resolved.resolved:
                unresolved.append(q.technology)
                resolutions.append(
                    TechnologyResolution(q.technology, resolved=False, ambiguous=False)
                )
                continue
            ambiguous = len(resolved.candidates) > 1
            resolutions.append(
                TechnologyResolution(
                    q.technology,
                    resolved=True,
                    ambiguous=ambiguous,
                    candidates=[c.canonical for c in resolved.candidates],
                )
            )
            for ident in resolved.candidates:
                key = (ident.cpe_vendor, ident.cpe_product)
                pair_to_queries.setdefault(key, []).append((q, ambiguous))

        # Stage C: one batched, index-backed candidate retrieval.
        candidates = self.db.candidates_for_products(list(pair_to_queries.keys()))

        # Stage D + E + F: compare, classify, deduplicate.
        findings: dict[str, Finding] = {}
        for pair, rows in candidates.items():
            query_entries = pair_to_queries.get(pair, [])
            for ap in rows:
                for query, ambiguous in query_entries:
                    detected = normalize_version(query.version) if query.version else None
                    classification, detail = _classify_product(detected, ap)
                    if ambiguous and classification != Classification.VERSION_NOT_MATCHED:
                        # Record ambiguity as an additional signal (not for non-matches).
                        effective = (
                            Classification.PRODUCT_MAPPING_AMBIGUOUS
                            if classification
                            in (
                                Classification.AFFECTED_RANGE_UNAVAILABLE,
                                Classification.VERSION_UNKNOWN,
                            )
                            else classification
                        )
                    else:
                        effective = classification

                    mp = MatchedProduct(
                        technology=query.technology,
                        detected_version=detected,
                        cpe_vendor=ap.get("cpe_vendor"),
                        cpe_product=ap.get("cpe_product"),
                        cpe23=ap.get("cpe23"),
                        classification=effective,
                        detail=detail,
                    )
                    self._merge(findings, ap, mp, query.technology)

        # Batch-load references for the surviving findings.
        refs = self.db.references_for_many(list(findings.keys()))
        for cve_id, finding in findings.items():
            finding.references = refs.get(cve_id, [])

        ordered = sorted(
            findings.values(),
            key=lambda f: (
                -_PRIORITY[f.classification],
                -_severity_rank(f.severity),
                f.cve_id,
            ),
        )
        return SearchReport(findings=ordered, unresolved=unresolved, resolutions=resolutions)

    @staticmethod
    def _merge(findings: dict[str, Finding], ap: dict, mp: MatchedProduct, tech: str) -> None:
        cve_id = ap["cve_id"]
        existing = findings.get(cve_id)
        if existing is None:
            findings[cve_id] = Finding(
                cve_id=cve_id,
                classification=mp.classification,
                severity=ap.get("severity"),
                cvss_score=ap.get("cvss_score"),
                cvss_version=ap.get("cvss_version"),
                description=ap.get("description", ""),
                published=ap.get("published"),
                source=ap.get("source", "nvd"),
                technologies=[tech],
                matched_products=[mp],
            )
            return
        existing.matched_products.append(mp)
        if tech not in existing.technologies:
            existing.technologies.append(tech)
        # Promote to the strongest classification seen.
        if _PRIORITY[mp.classification] > _PRIORITY[existing.classification]:
            existing.classification = mp.classification


def _severity_rank(severity: str | None) -> int:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1}
    return order.get((severity or "").upper(), 0)
