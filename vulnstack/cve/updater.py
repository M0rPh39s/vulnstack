"""Database update engine.

Drives a :class:`~vulnstack.cve.providers.Provider` to refresh the local
database independently of scanning. Key properties:

* **Incremental by default** — fetches only records modified since the last
  successful synchronization watermark (with a small overlap so records
  modified around the boundary are not skipped).
* **Safe full rebuild** — ``--full`` builds a fresh database in a temporary
  file, validates it, then atomically replaces the live file. A failed full
  sync never destroys existing records.
* **Crash-safe** — incremental writes are batched in transactions; an
  interrupted run leaves the existing database consistent.
* **Honest bookkeeping** — a failed sync is recorded as a failure (never a
  false success) and the watermark is not advanced past un-ingested records.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from vulnstack.cve.database import Database
from vulnstack.cve.providers import Provider, ProviderError
from vulnstack.logging_config import get_logger

log = get_logger("updater")

BATCH_SIZE = 500
WATERMARK_OVERLAP = timedelta(minutes=5)
DEFAULT_BOOTSTRAP_DAYS = 30

ProgressFn = Callable[[int, int | None], None]


@dataclass
class UpdateResult:
    source: str
    status: str                 # "success" | "failed"
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    errors: int = 0
    last_sync: str | None = None
    latest_source_modified: str | None = None
    full: bool = False
    bootstrap: bool = False
    message: str = ""
    notes: list[str] = field(default_factory=list)


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _batched(iterator, size):
    batch = []
    for item in iterator:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


class Updater:
    def __init__(self, db: Database, provider: Provider) -> None:
        self.db = db
        self.provider = provider

    def run(
        self,
        *,
        full: bool = False,
        bootstrap_days: int = DEFAULT_BOOTSTRAP_DAYS,
        progress: ProgressFn | None = None,
    ) -> UpdateResult:
        if full:
            return self._run_full(progress=progress)
        return self._run_incremental(bootstrap_days=bootstrap_days, progress=progress)

    # ---- incremental ------------------------------------------------------

    def _run_incremental(self, *, bootstrap_days: int, progress: ProgressFn | None) -> UpdateResult:
        self.db.initialize()
        source_row = self.db.get_source(self.provider.name)
        watermark = None
        bootstrap = False
        if source_row and source_row["last_status"] == "success" and source_row["last_source_modified"]:
            watermark = _parse_iso(source_row["last_source_modified"])
        if watermark is not None:
            modified_since = watermark - WATERMARK_OVERLAP
        else:
            # First run without a full sync: bootstrap a recent window.
            bootstrap = True
            modified_since = datetime.now(timezone.utc) - timedelta(days=bootstrap_days)

        result = UpdateResult(
            source=self.provider.name, status="failed", full=False, bootstrap=bootstrap
        )
        if bootstrap:
            result.notes.append(
                f"No previous full synchronization; fetched the last {bootstrap_days} days only. "
                "Run 'vulnstack db update --full' for a complete database."
            )
        inserted = updated = errors = 0
        try:
            stream = self.provider.fetch(modified_since=modified_since, full=False, progress=progress)
            for batch in _batched(stream, BATCH_SIZE):
                ins, upd = self.db.upsert_vulnerabilities(batch)
                inserted += ins
                updated += upd
        except ProviderError as exc:
            self.db.record_source_sync(
                self.provider.name, status="failed", error=str(exc)
            )
            result.errors = 1
            result.message = f"synchronization failed: {exc}"
            return result
        except Exception as exc:  # pragma: no cover - unexpected
            self.db.record_source_sync(
                self.provider.name, status="failed", error=repr(exc)
            )
            result.errors = 1
            result.message = f"unexpected error: {exc}"
            return result

        latest = self.provider.latest_source_modified()
        new_watermark = latest
        if new_watermark is None and watermark is not None:
            new_watermark = source_row["last_source_modified"]
        self.db.record_source_sync(
            self.provider.name,
            status="success",
            source_modified=new_watermark,
        )
        result.status = "success"
        result.inserted = inserted
        result.updated = updated
        result.errors = errors
        result.latest_source_modified = new_watermark
        result.last_sync = self.db.get_source(self.provider.name)["last_sync_time"]
        result.message = "synchronization completed"
        return result

    # ---- full rebuild -----------------------------------------------------

    def _run_full(self, *, progress: ProgressFn | None) -> UpdateResult:
        result = UpdateResult(source=self.provider.name, status="failed", full=True)
        live_path = self.db.path
        tmp_path = live_path.with_suffix(live_path.suffix + ".rebuild")
        # Clean any stale temp artifacts.
        for suffix in ("", "-wal", "-shm"):
            p = tmp_path.with_name(tmp_path.name + suffix)
            if p.exists():
                p.unlink()

        tmp_db = Database(tmp_path)
        tmp_db.initialize()
        inserted = 0
        try:
            stream = self.provider.fetch(modified_since=None, full=True, progress=progress)
            for batch in _batched(stream, BATCH_SIZE):
                ins, _ = tmp_db.upsert_vulnerabilities(batch)
                inserted += ins
        except ProviderError as exc:
            tmp_db.close()
            self._cleanup_tmp(tmp_path)
            # Live DB is untouched.
            self.db.initialize()
            self.db.record_source_sync(self.provider.name, status="failed", error=str(exc))
            result.errors = 1
            result.message = f"full synchronization failed; existing database kept: {exc}"
            return result
        except Exception as exc:  # pragma: no cover
            tmp_db.close()
            self._cleanup_tmp(tmp_path)
            self.db.initialize()
            self.db.record_source_sync(self.provider.name, status="failed", error=repr(exc))
            result.errors = 1
            result.message = f"full synchronization error; existing database kept: {exc}"
            return result

        # Validate the freshly built database before installing it.
        count = tmp_db.count_vulnerabilities()
        latest = self.provider.latest_source_modified()
        tmp_db.record_source_sync(
            self.provider.name, status="success", source_modified=latest
        )
        tmp_db.close()
        if count == 0:
            self._cleanup_tmp(tmp_path)
            self.db.initialize()
            self.db.record_source_sync(
                self.provider.name,
                status="failed",
                error="full sync produced zero records; existing database kept",
            )
            result.errors = 1
            result.message = "full synchronization produced no records; existing database kept"
            return result

        # Atomically replace the live database and drop stale WAL/SHM sidecars.
        self.db.close()
        for suffix in ("-wal", "-shm"):
            sidecar = live_path.with_name(live_path.name + suffix)
            if sidecar.exists():
                sidecar.unlink()
        os.replace(tmp_path, live_path)
        self.db.connect()

        result.status = "success"
        result.inserted = inserted
        result.latest_source_modified = latest
        result.last_sync = self.db.get_source(self.provider.name)["last_sync_time"]
        result.message = f"full rebuild installed ({count} records)"
        return result

    @staticmethod
    def _cleanup_tmp(tmp_path) -> None:
        for suffix in ("", "-wal", "-shm"):
            p = tmp_path.with_name(tmp_path.name + suffix)
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass
