"""Scan workflow orchestration.

Ties together the safe HTTP client, the fingerprinting engine and the local
vulnerability search into the single ``vulnstack scan`` workflow:

    validate URL -> fetch (safe, validated redirects) -> fingerprint ->
    resolve products -> query local DB -> compare versions -> classify ->
    deduplicate -> assemble result

A normal scan never triggers a database update and never makes a per-product
internet request. With ``--no-cve`` the database step is skipped entirely while
fingerprinting still runs. If the database is missing or empty the scan still
completes and reports that no local vulnerability data is available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from vulnstack import __version__
from vulnstack.config import Config
from vulnstack.cve.database import Database
from vulnstack.cve.search import Finding, SearchQuery, SearchReport, VulnerabilitySearch
from vulnstack.fingerprinting import DetectedTechnology, fingerprint
from vulnstack.http_client import HttpError, SafeHttpClient, ScanSafetyError, validate_url
from vulnstack.logging_config import get_logger

log = get_logger("scanner")


@dataclass
class DatabaseInfo:
    initialized: bool
    path: str
    total_cves: int = 0
    last_successful_sync: str | None = None
    stale: bool = False
    stale_days: float | None = None


@dataclass
class ScanResult:
    target: str
    final_url: str | None
    timestamp: str
    status: str                      # "ok" | "error"
    tool_version: str
    config: dict
    technologies: list[DetectedTechnology] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    search_report: SearchReport | None = None
    database: DatabaseInfo | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)

    @property
    def has_matches(self) -> bool:
        return any(
            f.classification.value == "MATCHED_AFFECTED_RANGE" for f in self.findings
        )

    def to_dict(self) -> dict:
        return {
            "tool": "vulnstack",
            "tool_version": self.tool_version,
            "scan_timestamp": self.timestamp,
            "target": self.target,
            "final_url": self.final_url,
            "status": self.status,
            "scan_configuration": self.config,
            "redirect_chain": self.redirect_chain,
            "technologies": [t.to_dict() for t in self.technologies],
            "findings": [f.to_dict() for f in self.findings],
            "unresolved_technologies": (
                self.search_report.unresolved if self.search_report else []
            ),
            "database": (
                {
                    "initialized": self.database.initialized,
                    "path": self.database.path,
                    "total_cves": self.database.total_cves,
                    "last_successful_sync": self.database.last_successful_sync,
                    "stale": self.database.stale,
                    "stale_days": self.database.stale_days,
                }
                if self.database
                else None
            ),
            "warnings": self.warnings,
            "errors": self.errors,
            "summary": self.summary(),
        }

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.classification.value] = counts.get(f.classification.value, 0) + 1
        return {
            "technologies_detected": len(self.technologies),
            "findings_total": len(self.findings),
            "findings_by_classification": counts,
        }


STALE_THRESHOLD_DAYS = 14


def _db_info(db: Database, cfg: Config, source: str) -> DatabaseInfo:
    if not db.is_initialized():
        return DatabaseInfo(initialized=False, path=str(db.path))
    total = db.count_vulnerabilities()
    last_sync = db.last_successful_sync()
    stale = False
    stale_days: float | None = None
    if last_sync:
        try:
            dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - dt
            stale_days = age.total_seconds() / 86400
            stale = stale_days > STALE_THRESHOLD_DAYS
        except ValueError:
            pass
    return DatabaseInfo(
        initialized=True,
        path=str(db.path),
        total_cves=total,
        last_successful_sync=last_sync,
        stale=stale,
        stale_days=stale_days,
    )


def scan(
    url: str,
    *,
    config: Config,
    no_cve: bool = False,
    database: Database | None = None,
) -> ScanResult:
    timestamp = datetime.now(timezone.utc).isoformat()
    scan_config = {
        "no_cve": no_cve,
        "timeout": config.timeout,
        "max_redirects": config.max_redirects,
        "allow_private_targets": config.allow_private_targets,
    }
    result = ScanResult(
        target=url,
        final_url=None,
        timestamp=timestamp,
        status="ok",
        tool_version=__version__,
        config=scan_config,
    )

    # 1. Validate URL up front for a clean, early error.
    try:
        validate_url(url, allow_private=config.allow_private_targets)
    except ScanSafetyError as exc:
        result.status = "error"
        result.errors.append(f"target rejected: {exc}")
        return result

    # 2-5. Fetch the target safely.
    client = SafeHttpClient(
        timeout=config.timeout,
        max_redirects=config.max_redirects,
        max_response_bytes=config.max_response_bytes,
        user_agent=config.user_agent,
        allow_private=config.allow_private_targets,
    )
    try:
        resp = client.get(url)
    except (HttpError, ScanSafetyError) as exc:
        result.status = "error"
        result.errors.append(str(exc))
        return result

    result.final_url = resp.url
    result.redirect_chain = resp.history
    if resp.truncated:
        result.warnings.append(
            f"response body exceeded {config.max_response_bytes} bytes and was truncated"
        )

    # 6-8. Fingerprint and resolve versions.
    result.technologies = fingerprint(resp)

    if no_cve:
        result.warnings.append("CVE correlation skipped (--no-cve)")
        return result

    # 9-10. Open the database and assess freshness.
    own_db = database is None
    db = database or Database(config.database_path)
    try:
        db.connect()
        info = _db_info(db, config, config.default_source)
        result.database = info
        if not info.initialized:
            result.warnings.append(
                "Local vulnerability database is not initialized. "
                "Run 'vulnstack db update --full' (or 'vulnstack db update') to populate it. "
                "Technology detection completed; CVE correlation skipped."
            )
            return result
        if info.total_cves == 0:
            result.warnings.append(
                "Local vulnerability database is empty. "
                "Run 'vulnstack db update' to populate it."
            )
            return result
        if info.stale and info.last_successful_sync:
            result.warnings.append(
                f"Local vulnerability database may be outdated "
                f"(last successful sync: {info.last_successful_sync})."
            )

        # 11-14. Query, compare, classify, deduplicate.
        queries = [SearchQuery(technology=t.name, version=t.version) for t in result.technologies]
        engine = VulnerabilitySearch(db)
        report = engine.search(queries)
        result.search_report = report
        result.findings = report.findings
    finally:
        if own_db:
            db.close()

    return result
