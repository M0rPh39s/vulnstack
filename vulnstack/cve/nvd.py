"""NVD (NIST National Vulnerability Database) provider.

Uses the official CVE API 2.0 (https://nvd.nist.gov/developers/vulnerabilities).
Incremental updates use the ``lastModStartDate`` / ``lastModEndDate`` window
parameters; full synchronization pages through the whole corpus with
``startIndex``. The provider:

* respects NVD rate limits (5 requests / 30 s without a key, 50 with one),
* retries transient failures with exponential backoff and honours ``Retry-After``,
* handles pagination via ``startIndex`` / ``totalResults``,
* never logs or transmits the optional ``NVD_API_KEY`` anywhere but the
  request header to NVD.

Parsing is defensive: missing/inconsistent fields are tolerated and structured
affected-product data is never silently discarded.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import requests

from vulnstack.cve.models import (
    AffectedProduct,
    Reference,
    Vulnerability,
    VersionRange,
)
from vulnstack.cve.providers import Provider, ProviderError, ProgressCallback, register
from vulnstack.logging_config import get_logger

log = get_logger("nvd")

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD serves large pages very slowly (a 2000-record page can exceed 90 s), so
# keep pages small enough to finish well inside the read timeout.
PAGE_SIZE = 200
MAX_WINDOW_DAYS = 120  # NVD limit for a single date range


def _parse_cpe(criteria: str) -> tuple[str | None, str | None, str | None]:
    """Extract (vendor, product, version) from a CPE 2.3 string."""
    # cpe:2.3:part:vendor:product:version:update:edition:...
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None, None, None
    vendor = parts[3] or None
    product = parts[4] or None
    version = parts[5]
    if version in ("*", "-", ""):
        version = None
    return vendor, product, version


def _extract_metrics(metrics: dict) -> tuple[float | None, str | None, str | None, str | None]:
    """Return (score, cvss_version, vector, severity) preferring newer CVSS."""
    for key, ver in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString")
            severity = entry.get("baseSeverity") or data.get("baseSeverity")
            if severity:
                severity = severity.upper()
            return score, ver, vector, severity
    return None, None, None, None


def _parse_configurations(configurations: list) -> list[AffectedProduct]:
    """Flatten NVD configuration nodes into affected products + ranges."""
    products: dict[tuple, AffectedProduct] = {}
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                criteria = match.get("criteria", "")
                vendor, product, version = _parse_cpe(criteria)
                key = (vendor, product, version)
                ap = products.get(key)
                if ap is None:
                    ap = AffectedProduct(
                        vendor=vendor,
                        product=product,
                        cpe_vendor=vendor,
                        cpe_product=product,
                        cpe23=criteria,
                        version=version,
                    )
                    products[key] = ap
                start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                if start or end:
                    ap.ranges.append(
                        VersionRange(
                            version_start=match.get("versionStartIncluding")
                            or match.get("versionStartExcluding"),
                            version_start_type=(
                                "including"
                                if match.get("versionStartIncluding")
                                else ("excluding" if match.get("versionStartExcluding") else None)
                            ),
                            version_end=match.get("versionEndIncluding")
                            or match.get("versionEndExcluding"),
                            version_end_type=(
                                "including"
                                if match.get("versionEndIncluding")
                                else ("excluding" if match.get("versionEndExcluding") else None)
                            ),
                        )
                    )
    return list(products.values())


def parse_cve(item: dict) -> Vulnerability | None:
    """Normalize one NVD ``{"cve": {...}}`` entry into a Vulnerability."""
    cve = item.get("cve", item)
    cve_id = cve.get("id")
    if not cve_id:
        return None

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description and cve.get("descriptions"):
        description = cve["descriptions"][0].get("value", "")

    score, cvss_version, vector, severity = _extract_metrics(cve.get("metrics", {}))

    weaknesses: list[str] = []
    for w in cve.get("weaknesses", []):
        for desc in w.get("description", []):
            val = desc.get("value")
            if val and val.upper().startswith("CWE-"):
                weaknesses.append(val.upper())

    references = [
        Reference(url=r["url"], ref_type=",".join(r.get("tags", [])) or None)
        for r in cve.get("references", [])
        if r.get("url")
    ]

    affected = _parse_configurations(cve.get("configurations", []))

    return Vulnerability(
        cve_id=cve_id,
        description=description,
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        cvss_score=score,
        cvss_version=cvss_version,
        cvss_vector=vector,
        severity=severity,
        status=cve.get("vulnStatus"),
        source="nvd",
        weaknesses=weaknesses,
        references=references,
        affected=affected,
    )


class NvdProvider(Provider):
    name = "nvd"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        timeout: float = 60.0,
        session: requests.Session | None = None,
        max_retries: int = 4,
    ) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self._session = session or requests.Session()
        # Rate limiting: min seconds between requests.
        self._min_interval = 0.6 if api_key else 6.0
        self._last_request = 0.0
        self._latest_modified: str | None = None

    def latest_source_modified(self) -> str | None:
        return self._latest_modified

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key  # never logged
        return headers

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _request(self, params: dict) -> dict:
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                resp = self._session.get(
                    API_URL,
                    params=params,
                    headers=self._headers(),
                    timeout=(self.timeout, self.timeout),
                )
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                self._backoff(attempt)
                continue
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError as exc:
                    raise ProviderError(f"NVD returned invalid JSON: {exc}") from exc
            if resp.status_code in (429, 503):
                retry_after = resp.headers.get("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.isdigit() else None
                log.warning("NVD throttled (HTTP %s); backing off", resp.status_code)
                self._backoff(attempt, wait)
                last_exc = ProviderError(f"NVD HTTP {resp.status_code}")
                continue
            if resp.status_code in (403, 404):
                raise ProviderError(
                    f"NVD request rejected (HTTP {resp.status_code}); "
                    "check parameters or API key"
                )
            last_exc = ProviderError(f"NVD HTTP {resp.status_code}")
            self._backoff(attempt)
        raise ProviderError(f"NVD request failed after retries: {last_exc}")

    def _backoff(self, attempt: int, override: float | None = None) -> None:
        wait = override if override is not None else min(2 ** attempt, 32)
        time.sleep(wait)

    def _paginate(self, base_params: dict, progress: ProgressCallback | None) -> Iterator[Vulnerability]:
        start_index = 0
        total: int | None = None
        while True:
            params = dict(base_params)
            params["startIndex"] = start_index
            params["resultsPerPage"] = PAGE_SIZE
            payload = self._request(params)
            total = payload.get("totalResults", 0)
            items = payload.get("vulnerabilities", [])
            for item in items:
                vuln = parse_cve(item)
                if vuln is None:
                    continue
                if vuln.last_modified and (
                    self._latest_modified is None or vuln.last_modified > self._latest_modified
                ):
                    self._latest_modified = vuln.last_modified
                yield vuln
            start_index += len(items)
            if progress is not None:
                progress(start_index, total)
            if not items or start_index >= total:
                break

    def fetch(
        self,
        *,
        modified_since: datetime | None,
        full: bool,
        progress: ProgressCallback | None = None,
    ) -> Iterator[Vulnerability]:
        if full or modified_since is None:
            yield from self._paginate({}, progress)
            return

        # Incremental: iterate over <=120-day windows from the watermark to now.
        now = datetime.now(timezone.utc)
        window_start = modified_since
        if window_start.tzinfo is None:
            window_start = window_start.replace(tzinfo=timezone.utc)
        while window_start < now:
            window_end = min(window_start + timedelta(days=MAX_WINDOW_DAYS), now)
            base = {
                "lastModStartDate": _nvd_timestamp(window_start),
                "lastModEndDate": _nvd_timestamp(window_end),
            }
            yield from self._paginate(base, progress)
            window_start = window_end


def _nvd_timestamp(dt: datetime) -> str:
    # NVD expects ISO-8601 with milliseconds and timezone offset.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _factory(**kwargs) -> NvdProvider:
    return NvdProvider(**kwargs)


register("nvd", _factory)
