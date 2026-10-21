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
