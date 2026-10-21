"""Pre-built database distribution via GitHub Releases.

Instead of every user crawling NVD, a scheduled workflow builds the database
once and publishes it to a fixed release of the VulnStack repository:

``manifest.json``
    Small JSON document describing the other two files (hashes, sizes,
    schema version, watermark). Always uploaded last.
``vulnstack-db-full.sqlite.gz``
    The complete SQLite database.
``vulnstack-db-delta.jsonl.gz``
    Only the records modified in the last few days, one JSON object per line.

``vulnstack db update`` pulls from there. Depending on how far behind the local
database is, it does nothing, applies the delta, or installs the full file.

Safety properties:

* The download location is a fixed constant; it is not configurable, so a
  config or environment change cannot redirect the database to another host.
* Only HTTPS to GitHub hosts is followed, and every redirect hop is checked
  *before* it is requested.
* Every file is verified (exact size and SHA-256 from the manifest) and size-
  capped, including decompressed size, before it is used.
* A full database is built and validated in a temporary file (schema version,
  SQLite integrity check, record count) and only then atomically swapped in. A
  failed pull never alters the existing database.
* The published data is a plain dataset; nothing in it is ever executed.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from vulnstack.cve import migrations
from vulnstack.cve.database import Database
from vulnstack.cve.models import AffectedProduct, Reference, Vulnerability, VersionRange
from vulnstack.logging_config import get_logger

log = get_logger("distribution")

RELEASE_BASE_URL = "https://github.com/M0rPh39s/vulnstack/releases/download/db-latest"
ALLOWED_HOST_SUFFIXES = ("github.com", "githubusercontent.com")

MANIFEST_NAME = "manifest.json"
FULL_NAME = "vulnstack-db-full.sqlite.gz"
DELTA_NAME = "vulnstack-db-delta.jsonl.gz"
FORMAT_VERSION = 1
DATA_SOURCE = "nvd"          # the data_sources row a published database carries

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_DOWNLOAD_BYTES = 2 * 1024 ** 3        # compressed
MAX_UNCOMPRESSED_BYTES = 8 * 1024 ** 3
MAX_REDIRECTS = 5
DEFAULT_DELTA_DAYS = 7
APPLY_BATCH = 500

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_REDIRECTS = (301, 302, 303, 307, 308)

ProgressFn = Callable[[int, int | None], None]


class DistributionError(Exception):
    """A pull or publish failed; the existing local database is untouched."""


class NotPublishedError(DistributionError):
    """The release has no manifest yet."""


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _nvd_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def validate_manifest(data: object) -> dict:
    """Return ``data`` if it is a well-formed manifest, else raise."""
    def bad(msg: str) -> DistributionError:
        return DistributionError(f"invalid manifest: {msg}")

    if not isinstance(data, dict):
        raise bad("not a JSON object")
    if data.get("format") != FORMAT_VERSION:
        raise bad(
            f"unsupported format {data.get('format')!r} (this VulnStack understands "
            f"{FORMAT_VERSION}); upgrade VulnStack"
        )
    schema = data.get("schema_version")
    if not isinstance(schema, int) or schema < 1:
        raise bad("missing schema_version")
    if _parse_ts(data.get("built_at")) is None:
        raise bad("missing or unparseable built_at")
    if _parse_ts(data.get("watermark")) is None:
        raise bad("missing or unparseable watermark")
    count = data.get("record_count")
    if not isinstance(count, int) or count < 1:
        raise bad("record_count must be a positive integer")

    def check_file(key: str, extra: tuple[str, ...]) -> None:
        entry = data.get(key)
        if not isinstance(entry, dict):
            raise bad(f"missing {key!r} entry")
        name = entry.get("file")
        if not isinstance(name, str) or not _NAME_RE.match(name) or name.startswith("."):
            raise bad(f"{key}.file is not a plain file name")
        if not isinstance(entry.get("sha256"), str) or not _SHA_RE.match(entry["sha256"]):
            raise bad(f"{key}.sha256 is not a SHA-256 hex digest")
        for field_name in ("size", "uncompressed_size", *extra):
            value = entry.get(field_name)
            if field_name == "since":
                if _parse_ts(value) is None:
                    raise bad(f"{key}.since is not a timestamp")
            elif not isinstance(value, int) or value < 0:
                raise bad(f"{key}.{field_name} must be a non-negative integer")
        if entry["size"] > MAX_DOWNLOAD_BYTES:
            raise bad(f"{key} is larger than the {MAX_DOWNLOAD_BYTES} byte limit")
        if entry["uncompressed_size"] > MAX_UNCOMPRESSED_BYTES:
            raise bad(f"{key} expands beyond the {MAX_UNCOMPRESSED_BYTES} byte limit")

    check_file("full", ())
    if data.get("delta") is not None:
        check_file("delta", ("since", "count"))
    return data


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def _host_allowed(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and any(
        host == s or host.endswith("." + s) for s in ALLOWED_HOST_SUFFIXES
    )


class Fetcher:
    """Minimal, host-restricted HTTPS downloader for release assets."""

    def __init__(
        self,
        base_url: str | None = None,
        session: requests.Session | None = None,
        timeout: tuple[float, float] = (15.0, 60.0),
    ) -> None:
        self.base_url = (base_url or RELEASE_BASE_URL).rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout

    def _open(self, name: str):
        url = f"{self.base_url}/{name}"
        for _ in range(MAX_REDIRECTS + 1):
            if not _host_allowed(url):
                raise DistributionError(f"refusing to download from {url!r}: not an HTTPS GitHub URL")
            try:
                resp = self.session.get(
                    url, stream=True, timeout=self.timeout, allow_redirects=False,
                    headers={"Accept": "application/octet-stream"},
                )
            except requests.exceptions.RequestException as exc:
                raise DistributionError(f"could not reach {url}: {exc}") from exc
            if resp.status_code in _REDIRECTS:
                location = resp.headers.get("Location")
                resp.close()
                if not location:
                    raise DistributionError(f"redirect without Location from {url}")
                url = urljoin(url, location)
                continue
            if resp.status_code == 404:
                resp.close()
                raise NotPublishedError(f"{name} not found at {self.base_url}")
            if resp.status_code != 200:
                resp.close()
                raise DistributionError(f"HTTP {resp.status_code} fetching {name}")
            return resp
        raise DistributionError(f"too many redirects fetching {name}")

    def get_json(self, name: str, max_bytes: int = MAX_MANIFEST_BYTES) -> object:
        resp = self._open(name)
        try:
            raw = bytearray()
            for chunk in resp.iter_content(chunk_size=16384):
                raw.extend(chunk)
                if len(raw) > max_bytes:
                    raise DistributionError(f"{name} exceeds {max_bytes} bytes")
        except requests.exceptions.RequestException as exc:
            raise DistributionError(f"download of {name} failed: {exc}") from exc
        finally:
            resp.close()
        try:
            return json.loads(bytes(raw).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise DistributionError(f"{name} is not valid JSON: {exc}") from exc

    def download(
        self, name: str, dest: Path, *, size: int, sha256: str,
        progress: ProgressFn | None = None,
    ) -> None:
        """Download ``name`` to ``dest``, enforcing the exact size and SHA-256."""
        resp = self._open(name)
        digest = hashlib.sha256()
        received = 0
        try:
            with dest.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    received += len(chunk)
                    if received > size:
                        raise DistributionError(f"{name} is larger than the {size} bytes the manifest declares")
                    digest.update(chunk)
                    fh.write(chunk)
                    if progress is not None:
                        progress(received, size)
        except requests.exceptions.RequestException as exc:
            raise DistributionError(f"download of {name} failed: {exc}") from exc
        finally:
            resp.close()
        if received != size:
            raise DistributionError(f"{name} is truncated ({received} of {size} bytes)")
        if digest.hexdigest() != sha256:
            raise DistributionError(f"{name} failed SHA-256 verification; refusing to use it")


def _gunzip(src: Path, dest: Path, expected_size: int) -> None:
    """Decompress ``src`` to ``dest``, refusing to exceed/miss ``expected_size``."""
    written = 0
    try:
        with gzip.open(src, "rb") as fin, dest.open("wb") as fout:
            while True:
                chunk = fin.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > expected_size:
                    raise DistributionError("decompressed data is larger than the manifest declares")
                fout.write(chunk)
    except (OSError, EOFError) as exc:  # includes gzip.BadGzipFile
        raise DistributionError(f"corrupt compressed file: {exc}") from exc
    if written != expected_size:
        raise DistributionError(
            f"decompressed size {written} does not match the manifest ({expected_size})"
        )


# ---------------------------------------------------------------------------
# (De)serialization of records
# ---------------------------------------------------------------------------

def vulnerability_from_dict(d: dict) -> Vulnerability:
    """Rebuild a Vulnerability from the dict form written by :func:`build_release`."""
    if not isinstance(d, dict) or not isinstance(d.get("cve_id"), str) or not d["cve_id"]:
        raise DistributionError("delta contains a record without a cve_id")
    products = []
    for p in d.get("affected_products") or []:
        ranges = [
            VersionRange(
                version_start=r.get("version_start"),
                version_start_type=r.get("version_start_type"),
                version_end=r.get("version_end"),
                version_end_type=r.get("version_end_type"),
                version_scheme=r.get("version_scheme"),
                fixed_version=r.get("fixed_version"),
            )
            for r in p.get("ranges") or []
        ]
        products.append(AffectedProduct(
            vendor=p.get("vendor"), product=p.get("product"),
            cpe_vendor=p.get("cpe_vendor"), cpe_product=p.get("cpe_product"),
            cpe23=p.get("cpe23"), version=p.get("version"),
            version_scheme=p.get("version_scheme"), ranges=ranges,
        ))
    return Vulnerability(
        cve_id=d["cve_id"],
        description=d.get("description") or "",
        published=d.get("published"),
        last_modified=d.get("last_modified"),
        cvss_score=d.get("cvss_score"),
        cvss_version=d.get("cvss_version"),
        cvss_vector=d.get("cvss_vector"),
        severity=d.get("severity"),
        status=d.get("status"),
        source=d.get("source") or DATA_SOURCE,
        weaknesses=[w for w in d.get("weaknesses") or [] if isinstance(w, str)],
        references=[Reference(url=r["url"], ref_type=r.get("ref_type"))
                    for r in d.get("references") or [] if r.get("url")],
        affected=products,
    )


def _iter_delta(path: Path) -> Iterator[Vulnerability]:
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield vulnerability_from_dict(json.loads(line))
            except (ValueError, AttributeError, TypeError, KeyError) as exc:
                raise DistributionError(f"delta line {lineno} is malformed: {exc}") from exc


# ---------------------------------------------------------------------------
# Client: pull
# ---------------------------------------------------------------------------

@dataclass
class PullResult:
    mode: str                       # "up-to-date" | "delta" | "full"
    inserted: int = 0
    updated: int = 0
    record_count: int = 0
    built_at: str | None = None
    watermark: str | None = None
    message: str = ""


def plan_pull(manifest: dict, db: Database, *, force_full: bool = False) -> str:
    """Decide between "up-to-date", "delta" and "full" for the local database."""
    if force_full or not db.is_initialized() or db.count_vulnerabilities() == 0:
        return "full"
    source = db.get_source(DATA_SOURCE)
    local = _parse_ts(source["last_source_modified"]) if source else None
    if local is None:
        return "full"
    if local >= _parse_ts(manifest["watermark"]):
        return "up-to-date"
    delta = manifest.get("delta")
    if delta and local >= _parse_ts(delta["since"]):
        return "delta"
    return "full"


def pull(
    db: Database,
    *,
    force_full: bool = False,
    fetcher: Fetcher | None = None,
    progress: ProgressFn | None = None,
) -> PullResult:
    """Bring ``db`` up to date from the published release."""
    fetcher = fetcher or Fetcher()
    manifest = validate_manifest(fetcher.get_json(MANIFEST_NAME))
    if manifest["schema_version"] > migrations.SCHEMA_VERSION:
        raise DistributionError(
            f"the published database uses schema v{manifest['schema_version']} but this "
            f"VulnStack only understands v{migrations.SCHEMA_VERSION}; upgrade VulnStack"
        )
    db.initialize()
    mode = plan_pull(manifest, db, force_full=force_full)
    base = dict(record_count=manifest["record_count"], built_at=manifest["built_at"],
                watermark=manifest["watermark"])
    if mode == "up-to-date":
        return PullResult(mode=mode, message="local database is already up to date", **base)
    if mode == "delta":
        inserted, updated = _apply_delta(db, manifest, fetcher, progress)
        return PullResult(mode=mode, inserted=inserted, updated=updated,
                          message="applied incremental update", **base)
    _install_full(db, manifest, fetcher, progress)
    return PullResult(mode=mode, message="installed full database", **base)


def _workdir(db: Database) -> Path:
    # Same directory as the live database so the final rename is atomic.
    return db.path.parent


def _apply_delta(db: Database, manifest: dict, fetcher: Fetcher, progress: ProgressFn | None) -> tuple[int, int]:
    entry = manifest["delta"]
    gz = _workdir(db) / (db.path.name + ".delta.gz")
    raw = _workdir(db) / (db.path.name + ".delta.jsonl")
    try:
        fetcher.download(entry["file"], gz, size=entry["size"], sha256=entry["sha256"], progress=progress)
        _gunzip(gz, raw, entry["uncompressed_size"])
        # Parse everything first so a malformed line applies nothing.
        records = list(_iter_delta(raw))
        if len(records) != entry["count"]:
            raise DistributionError(
                f"delta has {len(records)} records but the manifest declares {entry['count']}"
            )
        inserted = updated = 0
        for i in range(0, len(records), APPLY_BATCH):
            ins, upd = db.upsert_vulnerabilities(records[i:i + APPLY_BATCH])
            inserted += ins
            updated += upd
        db.record_source_sync(
            DATA_SOURCE, status="success",
            source_modified=manifest["watermark"], sync_time=manifest["built_at"],
        )
        return inserted, updated
    finally:
        for p in (gz, raw):
            p.unlink(missing_ok=True)


def _validate_candidate(path: Path, manifest: dict) -> None:
    """Check a freshly built database file before it may replace the live one."""
    try:
        probe = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise DistributionError(f"downloaded database cannot be opened: {exc}") from exc
    try:
        try:
            if probe.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise DistributionError("downloaded database failed the SQLite integrity check")
            version = int(probe.execute(
                "SELECT value FROM database_metadata WHERE key='schema_version'").fetchone()[0])
            count = probe.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            has_source = probe.execute(
                "SELECT 1 FROM data_sources WHERE name=?", (DATA_SOURCE,)).fetchone()
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise DistributionError(f"downloaded file is not a VulnStack database: {exc}") from exc
    finally:
        probe.close()
    if version > migrations.SCHEMA_VERSION:
        raise DistributionError(f"database schema v{version} is newer than supported; upgrade VulnStack")
    if count != manifest["record_count"]:
        raise DistributionError(
            f"database has {count} records but the manifest declares {manifest['record_count']}"
        )
    if not has_source:
        raise DistributionError("downloaded database carries no sync metadata")


def _install_full(db: Database, manifest: dict, fetcher: Fetcher, progress: ProgressFn | None) -> None:
    entry = manifest["full"]
    live = db.path
    gz = live.with_name(live.name + ".pull.gz")
    candidate = live.with_name(live.name + ".pull")
    try:
        live.parent.mkdir(parents=True, exist_ok=True)
        fetcher.download(entry["file"], gz, size=entry["size"], sha256=entry["sha256"], progress=progress)
        _gunzip(gz, candidate, entry["uncompressed_size"])
        _validate_candidate(candidate, manifest)
        # Upgrade an older-schema candidate in place before it goes live.
        upgrade = Database(candidate)
        try:
            upgrade.initialize()
        finally:
            upgrade.close()
        for suffix in ("-wal", "-shm"):
            candidate.with_name(candidate.name + suffix).unlink(missing_ok=True)
        db.close()
        for suffix in ("-wal", "-shm"):
            live.with_name(live.name + suffix).unlink(missing_ok=True)
        os.replace(candidate, live)
        db.connect()
    finally:
        gz.unlink(missing_ok=True)
        for suffix in ("", "-wal", "-shm"):
            candidate.with_name(candidate.name + suffix).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Publisher: build
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _gzip_file(src: Path, dest: Path) -> int:
    """Gzip ``src`` to ``dest`` deterministically; return the uncompressed size."""
    size = 0
    with src.open("rb") as fin, dest.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as fout:
            for chunk in iter(lambda: fin.read(1 << 20), b""):
                size += len(chunk)
                fout.write(chunk)
    return size


def build_release(
    db: Database,
    out_dir: str | Path,
    *,
    delta_days: int = DEFAULT_DELTA_DAYS,
    now: datetime | None = None,
) -> dict:
    """Write the full DB, delta and manifest for publication into ``out_dir``.

    ``manifest.json`` is written last. Raises :class:`DistributionError` rather
    than publishing an empty or unsynchronized database.
    """
    if delta_days < 1:
        raise DistributionError("delta_days must be at least 1")
    now = now or datetime.now(timezone.utc)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not db.is_initialized():
        raise DistributionError("nothing to publish: the database is not initialized")
    count = db.count_vulnerabilities()
    source = db.get_source(DATA_SOURCE)
    if count == 0:
        raise DistributionError("refusing to publish an empty database")
    if not source or source["last_status"] != "success" or not source["last_source_modified"]:
        raise DistributionError(
            f"refusing to publish: the {DATA_SOURCE!r} source has no successful sync recorded"
        )

    # Consistent, self-contained copy (no WAL sidecars), compacted.
    snapshot = out / "snapshot.sqlite"
    snapshot.unlink(missing_ok=True)
    src = db.connect()
    dst = sqlite3.connect(str(snapshot))
    try:
        src.backup(dst)
        dst.execute("PRAGMA journal_mode=DELETE")
        dst.execute("VACUUM")
        dst.commit()
    finally:
        dst.close()
    full_path = out / FULL_NAME
    full_uncompressed = _gzip_file(snapshot, full_path)
    snapshot.unlink()

    # Delta: every record modified since `since`.
    since = _nvd_ts(now - timedelta(days=delta_days))
    delta_raw = out / "delta.jsonl"
    n_delta = 0
    conn = db.connect()
    ids = [r[0] for r in conn.execute(
        "SELECT cve_id FROM vulnerabilities WHERE last_modified >= ? ORDER BY cve_id", (since,))]
    with delta_raw.open("w", encoding="utf-8") as fh:
        for cve_id in ids:
            record = db.get_vulnerability(cve_id)
            fh.write(json.dumps(record, separators=(",", ":"), sort_keys=True))
            fh.write("\n")
            n_delta += 1
    delta_path = out / DELTA_NAME
    delta_uncompressed = _gzip_file(delta_raw, delta_path)
    delta_raw.unlink()

    manifest = {
        "format": FORMAT_VERSION,
        "schema_version": db.schema_version(),
        "built_at": source["last_sync_time"] or now.isoformat(),
        "watermark": source["last_source_modified"],
        "record_count": count,
        "source": "NVD (https://nvd.nist.gov); not endorsed or certified by NIST",
        "full": {
            "file": FULL_NAME, "size": full_path.stat().st_size,
            "uncompressed_size": full_uncompressed, "sha256": _sha256_file(full_path),
        },
        "delta": {
            "file": DELTA_NAME, "size": delta_path.stat().st_size,
            "uncompressed_size": delta_uncompressed, "sha256": _sha256_file(delta_path),
            "since": since, "count": n_delta,
        },
    }
    validate_manifest(manifest)  # never publish something our own client would reject
    (out / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
