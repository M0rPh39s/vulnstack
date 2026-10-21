from datetime import datetime, timezone

import pytest

from tests.conftest import make_vuln
from vulnstack.cve.database import Database
from vulnstack.cve.providers import Provider, ProviderError
from vulnstack.cve.updater import Updater


class FakeProvider(Provider):
    name = "fake"

    def __init__(self, vulns, *, fail=False, latest=None):
        self._vulns = vulns
        self._fail = fail
        self._latest = latest
        self.last_modified_since = None
        self.last_full = None

    def fetch(self, *, modified_since, full, progress=None):
        self.last_modified_since = modified_since
        self.last_full = full
        if self._fail:
            raise ProviderError("simulated provider failure")
        for i, v in enumerate(self._vulns):
            if progress:
                progress(i + 1, len(self._vulns))
            yield v

    def latest_source_modified(self):
        return self._latest


def test_initial_bootstrap_incremental(tmp_db):
    provider = FakeProvider([make_vuln("CVE-2024-0001", version="1.0")],
                            latest="2024-01-02T00:00:00")
    updater = Updater(tmp_db, provider)
    result = updater.run(full=False, bootstrap_days=30)
    assert result.status == "success"
    assert result.inserted == 1
    assert result.bootstrap is True
    assert provider.last_full is False
    # Bootstrap requested a recent window, not the whole corpus.
    assert provider.last_modified_since is not None


def test_incremental_uses_watermark(tmp_db):
    p1 = FakeProvider([make_vuln("CVE-2024-0001", version="1.0")], latest="2024-06-01T00:00:00")
    Updater(tmp_db, p1).run(full=False)
    # Second run should start from the stored watermark (minus overlap).
    p2 = FakeProvider([make_vuln("CVE-2024-0002", version="2.0")], latest="2024-06-15T00:00:00")
    p2.name = "fake"
    result = Updater(tmp_db, p2).run(full=False)
    assert result.status == "success"
    assert p2.last_modified_since is not None
    assert p2.last_modified_since < datetime(2024, 6, 2, tzinfo=timezone.utc)
    assert tmp_db.count_vulnerabilities() == 2


def test_failed_sync_not_marked_success(tmp_db):
    provider = FakeProvider([], fail=True)
    result = Updater(tmp_db, provider).run(full=False)
    assert result.status == "failed"
    assert result.errors == 1
    source = tmp_db.get_source("fake")
    assert source["last_status"] == "failed"
    assert source["last_error"]


def test_failed_full_keeps_existing_db(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    db.initialize()
    db.upsert_vulnerabilities([make_vuln("CVE-2020-1111", version="1.0")])
    db.close()

    db2 = Database(path)
    db2.initialize()
    provider = FakeProvider([], fail=True)
    result = Updater(db2, provider).run(full=True)
    assert result.status == "failed"
    # Existing records are preserved after a failed full rebuild.
    assert db2.count_vulnerabilities() == 1
    db2.close()


def test_full_rebuild_installs_new_db(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    db.initialize()
    db.upsert_vulnerabilities([make_vuln("CVE-OLD-0001", version="1.0")])
    db.close()

    db2 = Database(path)
    db2.initialize()
    provider = FakeProvider(
        [make_vuln("CVE-NEW-0001", version="2.0"), make_vuln("CVE-NEW-0002", version="3.0")],
        latest="2024-07-01T00:00:00",
    )
    result = Updater(db2, provider).run(full=True)
    assert result.status == "success"
    assert provider.last_full is True
    assert db2.count_vulnerabilities() == 2
    assert db2.get_vulnerability("CVE-OLD-0001") is None
    db2.close()


def test_empty_full_rebuild_keeps_existing(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    db.initialize()
    db.upsert_vulnerabilities([make_vuln("CVE-KEEP-0001", version="1.0")])
    db.close()

    db2 = Database(path)
    db2.initialize()
    provider = FakeProvider([])  # produces zero records
    result = Updater(db2, provider).run(full=True)
    assert result.status == "failed"
    assert db2.count_vulnerabilities() == 1
    db2.close()


def test_duplicate_records_deduplicated(tmp_db):
    provider = FakeProvider(
        [make_vuln("CVE-2024-9999", version="1.0"), make_vuln("CVE-2024-9999", version="1.0")],
        latest="2024-01-01T00:00:00",
    )
    Updater(tmp_db, provider).run(full=False)
    assert tmp_db.count_vulnerabilities() == 1


# ---- recovery ---------------------------------------------------------------

class MidStreamFailProvider(FakeProvider):
    """Yields some records, then fails (e.g. NVD dies on page 2)."""

    def fetch(self, *, modified_since, full, progress=None):
        self.last_modified_since = modified_since
        self.last_full = full
        yield from self._vulns
        raise ProviderError("connection dropped mid-stream")


class ExplodingProvider(FakeProvider):
    def fetch(self, *, modified_since, full, progress=None):
        raise RuntimeError("boom")
        yield  # pragma: no cover


def test_failure_after_success_keeps_watermark_for_next_run(tmp_db):
    """A transient failure must not reset the next run to a bootstrap window."""
    Updater(tmp_db, FakeProvider([make_vuln("CVE-2024-0001", version="1.0")],
                                 latest="2024-06-01T00:00:00")).run()
    failed = Updater(tmp_db, FakeProvider([], fail=True)).run()
    assert failed.status == "failed"
    assert tmp_db.get_source("fake")["last_source_modified"] == "2024-06-01T00:00:00"

    retry = FakeProvider([make_vuln("CVE-2024-0002", version="2.0")], latest="2024-06-20T00:00:00")
    result = Updater(tmp_db, retry).run()
    assert result.status == "success"
    assert result.bootstrap is False
    assert retry.last_modified_since < datetime(2024, 6, 2, tzinfo=timezone.utc)
    assert retry.last_modified_since > datetime(2024, 5, 31, tzinfo=timezone.utc)


def test_first_sync_failure_then_retry_bootstraps(tmp_db):
    assert Updater(tmp_db, FakeProvider([], fail=True)).run().status == "failed"
    assert tmp_db.get_source("fake")["last_source_modified"] is None
    result = Updater(tmp_db, FakeProvider([make_vuln("CVE-2024-0001", version="1.0")],
                                          latest="2024-06-01T00:00:00")).run()
    assert result.status == "success" and result.bootstrap is True


def test_mid_stream_failure_is_failure_and_watermark_not_advanced(tmp_db):
    Updater(tmp_db, FakeProvider([make_vuln("CVE-2024-0001", version="1.0")],
                                 latest="2024-06-01T00:00:00")).run()
    bad = MidStreamFailProvider([make_vuln("CVE-2024-0002", version="2.0")], latest="2099-01-01T00:00:00")
    result = Updater(tmp_db, bad).run()
    assert result.status == "failed"
    assert "connection dropped" in result.message
    source = tmp_db.get_source("fake")
    assert source["last_status"] == "failed"
    assert source["last_source_modified"] == "2024-06-01T00:00:00"  # not 2099


def test_unexpected_exception_recorded_as_failure(tmp_db):
    result = Updater(tmp_db, ExplodingProvider([])).run()
    assert result.status == "failed" and result.errors == 1
    assert "unexpected error" in result.message
    assert tmp_db.get_source("fake")["last_status"] == "failed"


def test_unparseable_watermark_falls_back_to_bootstrap(tmp_db):
    tmp_db.record_source_sync("fake", status="success", source_modified="not-a-date")
    result = Updater(tmp_db, FakeProvider([], latest=None)).run()
    assert result.bootstrap is True


def test_watermark_without_tz_is_treated_as_utc(tmp_db):
    tmp_db.record_source_sync("fake", status="success", source_modified="2024-06-01T00:00:00.000")
    provider = FakeProvider([], latest=None)
    Updater(tmp_db, provider).run()
    assert provider.last_modified_since.tzinfo is not None


def test_no_new_records_keeps_existing_watermark(tmp_db):
    tmp_db.record_source_sync("fake", status="success", source_modified="2024-06-01T00:00:00")
    result = Updater(tmp_db, FakeProvider([], latest=None)).run()
    assert result.status == "success"
    assert result.latest_source_modified == "2024-06-01T00:00:00"


def test_progress_callback_is_driven(tmp_db):
    seen = []
    Updater(tmp_db, FakeProvider([make_vuln("CVE-2024-0001"), make_vuln("CVE-2024-0002")])).run(
        progress=lambda done, total: seen.append((done, total)))
    assert seen == [(1, 2), (2, 2)]


def test_second_identical_run_reports_updates_not_inserts(tmp_db):
    vulns = [make_vuln("CVE-2024-0001", version="1.0")]
    Updater(tmp_db, FakeProvider(vulns, latest="2024-06-01T00:00:00")).run()
    again = Updater(tmp_db, FakeProvider(vulns, latest="2024-06-01T00:00:00")).run()
    assert again.inserted == 0 and again.updated == 1
    assert tmp_db.count_vulnerabilities() == 1


def test_batches_are_split_by_batch_size(tmp_db, monkeypatch):
    from vulnstack.cve import updater
    monkeypatch.setattr(updater, "BATCH_SIZE", 2)
    vulns = [make_vuln(f"CVE-2024-{i:04d}", version="1.0") for i in range(5)]
    result = Updater(tmp_db, FakeProvider(vulns, latest="2024-06-01T00:00:00")).run()
    assert result.inserted == 5 and tmp_db.count_vulnerabilities() == 5


def test_full_failure_mid_stream_keeps_db_and_cleans_temp(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    db.initialize()
    db.upsert_vulnerabilities([make_vuln("CVE-KEEP-0001", version="1.0")])
    result = Updater(db, MidStreamFailProvider([make_vuln("CVE-NEW-0001", version="1.0")])).run(full=True)
    assert result.status == "failed"
    assert db.count_vulnerabilities() == 1
    assert db.get_vulnerability("CVE-KEEP-0001") is not None
    assert not list(tmp_path.glob("*.rebuild*"))
    db.close()


def test_full_unexpected_exception_keeps_db(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    db.initialize()
    db.upsert_vulnerabilities([make_vuln("CVE-KEEP-0001", version="1.0")])
    result = Updater(db, ExplodingProvider([])).run(full=True)
    assert result.status == "failed" and "existing database kept" in result.message
    assert db.count_vulnerabilities() == 1
    db.close()


def test_full_sync_clears_stale_rebuild_files(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    db.initialize()
    (tmp_path / "db.sqlite.rebuild").write_text("junk from a crashed run")
    (tmp_path / "db.sqlite.rebuild-wal").write_text("junk")
    result = Updater(db, FakeProvider([make_vuln("CVE-NEW-0001", version="1.0")],
                                      latest="2024-07-01T00:00:00")).run(full=True)
    assert result.status == "success"
    assert db.count_vulnerabilities() == 1
    assert not (tmp_path / "db.sqlite.rebuild").exists()
    assert not (tmp_path / "db.sqlite.rebuild-wal").exists()
    db.close()


def test_full_rebuild_records_watermark_so_next_incremental_is_not_bootstrap(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    db.initialize()
    Updater(db, FakeProvider([make_vuln("CVE-NEW-0001", version="1.0")], latest="2024-07-01T00:00:00")).run(full=True)
    nxt = Updater(db, FakeProvider([], latest=None)).run()
    assert nxt.bootstrap is False
    db.close()


def test_last_sync_time_only_moves_on_success(tmp_db):
    assert tmp_db.last_successful_sync("fake") is None
    Updater(tmp_db, FakeProvider([make_vuln("CVE-2024-0001")], latest="2024-06-01T00:00:00")).run()
    first = tmp_db.last_successful_sync("fake")
    assert first is not None
    Updater(tmp_db, FakeProvider([], fail=True)).run()
    assert tmp_db.last_successful_sync("fake") == first        # failure did not touch it
    assert tmp_db.get_source("fake")["last_status"] == "failed"


def test_freshness_is_sync_time_not_newest_record_time(tmp_db):
    """A sync that found nothing new today is fresh, even if the newest CVE is old."""
    Updater(tmp_db, FakeProvider([make_vuln("CVE-2020-0001")], latest="2020-01-01T00:00:00")).run()
    stamp = tmp_db.last_successful_sync("fake")
    assert stamp > "2025"   # wall-clock sync time, not the 2020 record timestamp
