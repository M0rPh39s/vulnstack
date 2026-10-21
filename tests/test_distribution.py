"""Publish -> (fake GitHub) -> pull round trips and attack cases."""

import gzip
import hashlib
import json
from datetime import datetime, timezone

import pytest

from tests.conftest import make_vuln
from vulnstack import cli
from vulnstack.cli import main
from vulnstack.cve import distribution as dist
from vulnstack.cve import migrations
from vulnstack.cve.database import Database
from vulnstack.cve.distribution import DistributionError, Fetcher, NotPublishedError
from vulnstack.cve.models import VersionRange
from vulnstack.cve.search import Classification, SearchQuery, VulnerabilitySearch

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
BASE = "https://github.com/M0rPh39s/vulnstack/releases/download/db-latest"


def _vuln(cve_id, modified, **kw):
    v = make_vuln(cve_id, **kw)
    v.last_modified = modified
    return v


def _publisher_db(path, vulns=None, watermark="2026-10-21T11:00:00.000"):
    db = Database(path)
    db.initialize()
    db.upsert_vulnerabilities(vulns if vulns is not None else [
        _vuln("CVE-2020-0001", "2020-01-01T00:00:00.000", version="2.4.49"),     # old: full only
        _vuln("CVE-2026-0002", "2026-10-20T00:00:00.000", cpe_vendor="nginx", cpe_product="nginx",
              ranges=[VersionRange(version_end="1.21.0", version_end_type="excluding")]),  # in delta
    ])
    db.record_source_sync("nvd", status="success", source_modified=watermark,
                          sync_time="2026-10-21T11:05:00+00:00")
    return db


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        pass


class FakeSession:
    """Serves release assets from a dict; records every requested URL."""

    def __init__(self, files=None, redirects=None):
        self.files = dict(files or {})
        self.redirects = redirects or {}
        self.requested = []

    @classmethod
    def from_dir(cls, directory):
        return cls({p.name: p.read_bytes() for p in directory.iterdir()})

    def get(self, url, **kw):
        self.requested.append(url)
        assert kw.get("allow_redirects") is False   # redirects are followed manually
        if url in self.redirects:
            return FakeResponse(302, headers={"Location": self.redirects[url]})
        name = url.rsplit("/", 1)[-1]
        if url.startswith(BASE + "/") and name in self.files:
            return FakeResponse(200, self.files[name])
        return FakeResponse(404)


@pytest.fixture
def release(tmp_path):
    pub = _publisher_db(tmp_path / "pub.db")
    out = tmp_path / "dist"
    manifest = dist.build_release(pub, out, now=NOW)
    pub.close()
    return out, manifest


def _fetcher(files):
    return Fetcher(session=FakeSession(files))


def _files(out):
    return {p.name: p.read_bytes() for p in out.iterdir()}


# ---- publish ---------------------------------------------------------------

def test_build_release_outputs_and_manifest(release):
    out, m = release
    assert sorted(p.name for p in out.iterdir()) == sorted(
        [dist.MANIFEST_NAME, dist.FULL_NAME, dist.DELTA_NAME])   # no temp files left behind
    dist.validate_manifest(json.loads((out / dist.MANIFEST_NAME).read_text()))
    assert m["record_count"] == 2
    assert m["watermark"] == "2026-10-21T11:00:00.000"
    assert m["delta"]["count"] == 1                      # only the recent record
    assert m["delta"]["since"] == "2026-10-14T12:00:00.000"
    assert m["full"]["sha256"] == hashlib.sha256((out / dist.FULL_NAME).read_bytes()).hexdigest()
    assert m["schema_version"] == migrations.SCHEMA_VERSION


def test_build_is_deterministic(tmp_path):
    pub = _publisher_db(tmp_path / "pub.db")
    a = dist.build_release(pub, tmp_path / "a", now=NOW)
    b = dist.build_release(pub, tmp_path / "b", now=NOW)
    assert a == b
    pub.close()


def test_published_snapshot_is_self_contained(release, tmp_path):
    out, _ = release
    raw = tmp_path / "x.sqlite"
    raw.write_bytes(gzip.decompress((out / dist.FULL_NAME).read_bytes()))
    assert not list(tmp_path.glob("x.sqlite-*"))
    snap = Database(raw)
    assert snap.count_vulnerabilities() == 2
    snap.close()


@pytest.mark.parametrize("mutate,msg", [
    (lambda db: db.clear(), "empty"),
    (lambda db: db.record_source_sync("nvd", status="failed", error="x"), "no successful sync"),
])
def test_publish_refuses_bad_databases(tmp_path, mutate, msg):
    pub = _publisher_db(tmp_path / "pub.db")
    mutate(pub)
    with pytest.raises(DistributionError, match=msg):
        dist.build_release(pub, tmp_path / "o", now=NOW)
    assert not (tmp_path / "o" / dist.MANIFEST_NAME).exists()
    pub.close()


def test_publish_refuses_uninitialized_and_unsynced(tmp_path):
    with pytest.raises(DistributionError, match="not initialized"):
        dist.build_release(Database(tmp_path / "none.db"), tmp_path / "o")
    db = Database(tmp_path / "nosync.db")
    db.initialize()
    db.upsert_vulnerabilities([make_vuln("CVE-2024-0001")])
    with pytest.raises(DistributionError, match="no successful sync"):
        dist.build_release(db, tmp_path / "o")
    with pytest.raises(DistributionError, match="delta_days"):
        dist.build_release(db, tmp_path / "o", delta_days=0)


# ---- pull: full / delta / up-to-date --------------------------------------

def test_fresh_install_gets_full_database_and_correlates(release, tmp_path):
    out, m = release
    local = Database(tmp_path / "local.db")
    result = dist.pull(local, fetcher=_fetcher(_files(out)))
    assert result.mode == "full"
    assert local.count_vulnerabilities() == 2
    assert local.last_successful_sync() == "2026-10-21T11:05:00+00:00"   # build's sync time, not pull time
    assert local.get_source("nvd")["last_source_modified"] == m["watermark"]
    report = VulnerabilitySearch(local).search([SearchQuery("Apache HTTP Server", "2.4.49")])
    assert [f.classification for f in report.findings] == [Classification.MATCHED_AFFECTED_RANGE]
    assert not list(tmp_path.glob("local.db.pull*"))
    local.close()


def test_up_to_date_downloads_nothing_but_manifest(release, tmp_path):
    out, _ = release
    session = FakeSession(_files(out))
    local = Database(tmp_path / "local.db")
    dist.pull(local, fetcher=Fetcher(session=session))
    session.requested.clear()
    result = dist.pull(local, fetcher=Fetcher(session=session))
    assert result.mode == "up-to-date"
    assert [u.rsplit("/", 1)[-1] for u in session.requested] == [dist.MANIFEST_NAME]
    local.close()


def test_delta_applies_new_and_changed_records(release, tmp_path):
    out, _ = release
    local = Database(tmp_path / "local.db")
    dist.pull(local, fetcher=_fetcher(_files(out)))

    # Publisher moves forward: one changed record, one brand-new record.
    pub = Database(tmp_path / "pub.db")
    pub.initialize()
    pub.upsert_vulnerabilities([
        _vuln("CVE-2026-0002", "2026-10-21T12:00:00.000", description="UPDATED description",
              cpe_vendor="nginx", cpe_product="nginx"),
        _vuln("CVE-2026-0003", "2026-10-21T12:30:00.000", cpe_vendor="wordpress", cpe_product="wordpress"),
    ])
    pub.record_source_sync("nvd", status="success", source_modified="2026-10-21T12:30:00.000",
                           sync_time="2026-10-22T06:00:00+00:00")
    out2 = tmp_path / "dist2"
    dist.build_release(pub, out2, now=datetime(2026, 10, 22, 6, 0, tzinfo=timezone.utc))
    pub.close()

    result = dist.pull(local, fetcher=_fetcher(_files(out2)))
    assert result.mode == "delta"
    assert (result.inserted, result.updated) == (1, 1)
    assert local.count_vulnerabilities() == 3
    assert local.get_vulnerability("CVE-2026-0002")["description"] == "UPDATED description"
    assert local.get_vulnerability("CVE-2020-0001") is not None           # untouched
    assert local.get_source("nvd")["last_source_modified"] == "2026-10-21T12:30:00.000"
    assert local.last_successful_sync() == "2026-10-22T06:00:00+00:00"
    # Structured data (ranges, references, weaknesses) survives the JSONL round trip.
    rec = local.get_vulnerability("CVE-2026-0003")
    assert rec["weaknesses"] == ["CWE-22"] and rec["references"]
    local.close()


def test_too_far_behind_falls_back_to_full(release, tmp_path):
    out, m = release
    local = Database(tmp_path / "local.db")
    local.initialize()
    local.upsert_vulnerabilities([make_vuln("CVE-OLD-0001")])
    local.record_source_sync("nvd", status="success", source_modified="2026-01-01T00:00:00.000")
    assert dist.plan_pull(m, local) == "full"
    result = dist.pull(local, fetcher=_fetcher(_files(out)))
    assert result.mode == "full"
    assert local.get_vulnerability("CVE-OLD-0001") is None       # replaced by the published DB
    local.close()


def test_force_full_redownloads(release, tmp_path):
    out, _ = release
    local = Database(tmp_path / "local.db")
    fetcher = _fetcher(_files(out))
    dist.pull(local, fetcher=fetcher)
    assert dist.pull(local, force_full=True, fetcher=fetcher).mode == "full"
    local.close()


def test_plan_empty_or_unwatermarked_local_is_full(release, tmp_path):
    _, m = release
    local = Database(tmp_path / "local.db")
    local.initialize()
    assert dist.plan_pull(m, local) == "full"
    local.upsert_vulnerabilities([make_vuln("CVE-2024-0001")])
    assert dist.plan_pull(m, local) == "full"                    # no watermark recorded
    local.close()


def test_pull_works_when_live_db_is_open_elsewhere_in_wal_mode(release, tmp_path):
    out, _ = release
    local = Database(tmp_path / "local.db")
    local.initialize()
    local.upsert_vulnerabilities([make_vuln("CVE-OLD-0001")])      # creates -wal/-shm sidecars
    dist.pull(local, force_full=True, fetcher=_fetcher(_files(out)))
    assert local.count_vulnerabilities() == 2
    assert local.is_initialized()
    local.close()


# ---- pull: failure keeps the existing database ----------------------------

def _seeded_local(tmp_path):
    local = Database(tmp_path / "local.db")
    local.initialize()
    local.upsert_vulnerabilities([make_vuln("CVE-KEEP-0001", version="1.0")])
    local.record_source_sync("nvd", status="success", source_modified="2026-01-01T00:00:00.000")
    return local


def _assert_untouched(local, tmp_path):
    assert local.count_vulnerabilities() == 1
    assert local.get_vulnerability("CVE-KEEP-0001") is not None
    assert not [p for p in tmp_path.iterdir() if ".pull" in p.name or ".delta" in p.name]


def _tamper_manifest(out, mutate):
    m = json.loads((out / dist.MANIFEST_NAME).read_text())
    mutate(m)
    files = _files(out)
    files[dist.MANIFEST_NAME] = json.dumps(m).encode()
    return files


@pytest.mark.parametrize("mutate,msg", [
    (lambda m: m["full"].update(sha256="0" * 64), "SHA-256"),
    (lambda m: m["full"].update(size=m["full"]["size"] - 1), "larger than"),
    (lambda m: m["full"].update(size=m["full"]["size"] + 1), "truncated"),
    (lambda m: m["full"].update(uncompressed_size=10), "larger than the manifest"),
    (lambda m: m["full"].update(uncompressed_size=m["full"]["uncompressed_size"] + 5), "does not match"),
    (lambda m: m.update(record_count=999), "manifest declares"),
])
def test_full_install_rejects_bad_files_and_keeps_db(release, tmp_path, mutate, msg):
    out, _ = release
    local = _seeded_local(tmp_path)
    with pytest.raises(DistributionError, match=msg):
        dist.pull(local, force_full=True, fetcher=_fetcher(_tamper_manifest(out, mutate)))
    _assert_untouched(local, tmp_path)
    local.close()


def test_corrupted_payload_rejected(release, tmp_path):
    out, m = release
    files = _files(out)
    bad = b"not gzip at all"
    files[dist.FULL_NAME] = bad
    mf = json.loads(files[dist.MANIFEST_NAME])
    mf["full"].update(size=len(bad), sha256=hashlib.sha256(bad).hexdigest())   # hash is "right"
    files[dist.MANIFEST_NAME] = json.dumps(mf).encode()
    local = _seeded_local(tmp_path)
    with pytest.raises(DistributionError, match="corrupt compressed"):
        dist.pull(local, force_full=True, fetcher=_fetcher(files))
    _assert_untouched(local, tmp_path)
    local.close()


def test_gzip_of_non_sqlite_rejected(release, tmp_path):
    out, _ = release
    files = _files(out)
    payload = b"definitely not a database" * 50
    gz = gzip.compress(payload)
    files[dist.FULL_NAME] = gz
    mf = json.loads(files[dist.MANIFEST_NAME])
    mf["full"].update(size=len(gz), sha256=hashlib.sha256(gz).hexdigest(), uncompressed_size=len(payload))
    files[dist.MANIFEST_NAME] = json.dumps(mf).encode()
    local = _seeded_local(tmp_path)
    with pytest.raises(DistributionError, match="cannot be opened|not a VulnStack database|integrity"):
        dist.pull(local, force_full=True, fetcher=_fetcher(files))
    _assert_untouched(local, tmp_path)
    local.close()


def test_newer_schema_in_manifest_refused(release, tmp_path):
    out, _ = release
    files = _tamper_manifest(out, lambda m: m.update(schema_version=migrations.SCHEMA_VERSION + 1))
    local = _seeded_local(tmp_path)
    with pytest.raises(DistributionError, match="upgrade VulnStack"):
        dist.pull(local, fetcher=_fetcher(files))
    _assert_untouched(local, tmp_path)
    local.close()


def test_newer_schema_inside_database_refused(release, tmp_path):
    out, _ = release
    import sqlite3
    raw = tmp_path / "evil.sqlite"
    raw.write_bytes(gzip.decompress((out / dist.FULL_NAME).read_bytes()))
    con = sqlite3.connect(raw)
    con.execute("UPDATE database_metadata SET value='99' WHERE key='schema_version'")
    con.commit(); con.close()
    data = raw.read_bytes()
    gz = gzip.compress(data)
    files = _files(out)
    files[dist.FULL_NAME] = gz
    mf = json.loads(files[dist.MANIFEST_NAME])
    mf["full"].update(size=len(gz), sha256=hashlib.sha256(gz).hexdigest(), uncompressed_size=len(data))
    files[dist.MANIFEST_NAME] = json.dumps(mf).encode()
    local = _seeded_local(tmp_path)
    with pytest.raises(DistributionError, match="newer than supported"):
        dist.pull(local, force_full=True, fetcher=_fetcher(files))
    _assert_untouched(local, tmp_path)
    local.close()


def _delta_files(out, lines, count=None):
    payload = ("\n".join(lines) + "\n").encode()
    gz = gzip.compress(payload)
    files = _files(out)
    files[dist.DELTA_NAME] = gz
    mf = json.loads(files[dist.MANIFEST_NAME])
    mf["watermark"] = "2026-10-21T11:00:00.000"
    mf["delta"].update(size=len(gz), sha256=hashlib.sha256(gz).hexdigest(),
                       uncompressed_size=len(payload), count=len(lines) if count is None else count,
                       since="2025-01-01T00:00:00.000")
    files[dist.MANIFEST_NAME] = json.dumps(mf).encode()
    return files


@pytest.mark.parametrize("lines,count,msg", [
    (["{not json"], None, "malformed"),
    (['{"no_id": 1}'], None, "malformed|without a cve_id"),
    (['{"cve_id": "CVE-2026-9999"}'], 5, "manifest declares"),
])
def test_bad_delta_applies_nothing(release, tmp_path, lines, count, msg):
    out, _ = release
    local = _seeded_local(tmp_path)
    with pytest.raises(DistributionError, match=msg):
        dist.pull(local, fetcher=_fetcher(_delta_files(out, lines, count)))
    _assert_untouched(local, tmp_path)
    assert local.get_source("nvd")["last_source_modified"] == "2026-01-01T00:00:00.000"   # watermark not advanced
    local.close()


def test_good_delta_with_bad_line_is_all_or_nothing(release, tmp_path):
    out, _ = release
    good = json.dumps({"cve_id": "CVE-2026-7777", "description": "x"})
    local = _seeded_local(tmp_path)
    with pytest.raises(DistributionError):
        dist.pull(local, fetcher=_fetcher(_delta_files(out, [good, "{broken"])))
    assert local.get_vulnerability("CVE-2026-7777") is None
    local.close()


# ---- manifest validation ----------------------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda m: m.update(format=2),
    lambda m: m.pop("schema_version"),
    lambda m: m.update(built_at="yesterday"),
    lambda m: m.update(watermark=None),
    lambda m: m.update(record_count=0),
    lambda m: m["full"].update(file="../../etc/passwd"),
    lambda m: m["full"].update(file="/abs/path"),
    lambda m: m["full"].update(file=".hidden"),
    lambda m: m["full"].update(file="a/b"),
    lambda m: m["full"].update(sha256="xyz"),
    lambda m: m["full"].update(size=-1),
    lambda m: m["full"].update(size=dist.MAX_DOWNLOAD_BYTES + 1),
    lambda m: m["full"].update(uncompressed_size=dist.MAX_UNCOMPRESSED_BYTES + 1),
    lambda m: m.pop("full"),
    lambda m: m["delta"].update(since="nope"),
    lambda m: m["delta"].pop("count"),
])
def test_invalid_manifests_rejected(release, mutate):
    _, m = release
    m = json.loads(json.dumps(m))
    mutate(m)
    with pytest.raises(DistributionError, match="invalid manifest|unsupported format"):
        dist.validate_manifest(m)


@pytest.mark.parametrize("junk", [[], "str", 5, None])
def test_non_object_manifest_rejected(junk):
    with pytest.raises(DistributionError, match="not a JSON object"):
        dist.validate_manifest(junk)


def test_manifest_without_delta_is_valid_and_forces_full(release, tmp_path):
    out, m = release
    m = json.loads(json.dumps(m))
    del m["delta"]
    dist.validate_manifest(m)
    local = _seeded_local(tmp_path)
    assert dist.plan_pull(m, local) == "full"
    local.close()


# ---- network behaviour ------------------------------------------------------

def test_not_published_is_distinct_error(tmp_path):
    local = Database(tmp_path / "local.db")
    with pytest.raises(NotPublishedError):
        dist.pull(local, fetcher=_fetcher({}))
    local.close()


def test_manifest_must_be_json_and_small(tmp_path):
    with pytest.raises(DistributionError, match="not valid JSON"):
        Fetcher(session=FakeSession({dist.MANIFEST_NAME: b"<html>"})).get_json(dist.MANIFEST_NAME)
    with pytest.raises(DistributionError, match="exceeds"):
        Fetcher(session=FakeSession({dist.MANIFEST_NAME: b"x" * 5000})).get_json(dist.MANIFEST_NAME, max_bytes=100)


def test_http_error_and_connection_error(tmp_path):
    import requests

    class Err500(FakeSession):
        def get(self, url, **kw):
            return FakeResponse(500)

    class Boom(FakeSession):
        def get(self, url, **kw):
            raise requests.exceptions.ConnectionError("no network")

    with pytest.raises(DistributionError, match="HTTP 500"):
        Fetcher(session=Err500()).get_json(dist.MANIFEST_NAME)
    with pytest.raises(DistributionError, match="could not reach"):
        Fetcher(session=Boom()).get_json(dist.MANIFEST_NAME)


def test_follows_redirects_to_github_cdn(release):
    out, _ = release
    cdn = "https://objects.githubusercontent.com/abc/manifest.json"
    session = FakeSession(redirects={f"{BASE}/{dist.MANIFEST_NAME}": cdn})
    session.files = {}
    # the CDN URL itself is served from a separate map
    orig = session.get

    def get(url, **kw):
        if url == cdn:
            session.requested.append(url)
            return FakeResponse(200, (out / dist.MANIFEST_NAME).read_bytes())
        return orig(url, **kw)

    session.get = get
    manifest = Fetcher(session=session).get_json(dist.MANIFEST_NAME)
    assert manifest["record_count"] == 2
    assert session.requested == [f"{BASE}/{dist.MANIFEST_NAME}", cdn]


@pytest.mark.parametrize("target", [
    "https://evil.example.com/manifest.json",
    "http://github.com/M0rPh39s/vulnstack/manifest.json",       # downgrade to http
    "https://github.com.evil.com/manifest.json",                # suffix trick
    "https://notgithub.com/manifest.json",
    "https://127.0.0.1/manifest.json",
    "file:///etc/passwd",
])
def test_redirect_to_disallowed_host_is_never_requested(target):
    session = FakeSession(redirects={f"{BASE}/{dist.MANIFEST_NAME}": target})
    with pytest.raises(DistributionError, match="refusing to download"):
        Fetcher(session=session).get_json(dist.MANIFEST_NAME)
    assert session.requested == [f"{BASE}/{dist.MANIFEST_NAME}"]     # the bad hop was not fetched


def test_redirect_loop_is_bounded():
    url = f"{BASE}/{dist.MANIFEST_NAME}"
    session = FakeSession(redirects={url: url})
    with pytest.raises(DistributionError, match="too many redirects"):
        Fetcher(session=session).get_json(dist.MANIFEST_NAME)


def test_redirect_without_location():
    class NoLoc(FakeSession):
        def get(self, url, **kw):
            return FakeResponse(302)

    with pytest.raises(DistributionError, match="without Location"):
        Fetcher(session=NoLoc()).get_json(dist.MANIFEST_NAME)


def test_base_url_is_a_fixed_github_constant():
    assert dist.RELEASE_BASE_URL.startswith("https://github.com/M0rPh39s/vulnstack/")
    assert dist._host_allowed(dist.RELEASE_BASE_URL)
    # Fetcher() with no argument uses the constant; nothing reads env/config for it.
    assert Fetcher().base_url == dist.RELEASE_BASE_URL


def test_progress_callback(release, tmp_path):
    out, _ = release
    seen = []
    dist.pull(Database(tmp_path / "l.db"), fetcher=_fetcher(_files(out)),
              progress=lambda done, total: seen.append((done, total)))
    assert seen and seen[-1][0] == seen[-1][1]


# ---- CLI --------------------------------------------------------------------

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNSTACK_DATABASE", str(tmp_path / "vulnstack.db"))
    monkeypatch.setenv("VULNSTACK_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("VULNSTACK_CONFIG", str(tmp_path / "config.toml"))
    return tmp_path


def _patch_fetcher(monkeypatch, files):
    monkeypatch.setattr(dist, "Fetcher", lambda *a, **k: Fetcher(session=FakeSession(files)))


def test_default_db_update_pulls_from_repo(env, release, monkeypatch, capsys):
    out, _ = release
    _patch_fetcher(monkeypatch, _files(out))
    assert main(["db", "update"]) == 0
    text = capsys.readouterr().out
    assert "Mode:             full" in text and "success" in text
    assert main(["db", "update"]) == 0
    assert "up-to-date" in capsys.readouterr().out
    assert main(["db", "update", "--full"]) == 0
    assert "Mode:             full" in capsys.readouterr().out
    assert main(["db", "status"]) == 0
    status = " ".join(capsys.readouterr().out.split())
    assert "Total CVE records │ 2" in status and "2026-10-21T11:05:00" in status


def test_db_update_not_published_exit_one(env, monkeypatch, capsys):
    _patch_fetcher(monkeypatch, {})
    assert main(["db", "update"]) == 1
    out = " ".join(capsys.readouterr().out.split())
    assert "No database has been published yet" in out and "--source nvd" in out


def test_db_update_pull_failure_keeps_db_and_exit_one(env, release, monkeypatch, capsys):
    out, _ = release
    files = _tamper_manifest(out, lambda m: m["full"].update(sha256="0" * 64))
    _patch_fetcher(monkeypatch, files)
    db = Database(env / "vulnstack.db")
    db.initialize(); db.upsert_vulnerabilities([make_vuln("CVE-KEEP-0001")]); db.close()
    assert main(["db", "update", "--full"]) == 1
    text = " ".join(capsys.readouterr().out.split())
    assert "SHA-256" in text and "not modified" in text
    db = Database(env / "vulnstack.db")
    assert db.count_vulnerabilities() == 1
    db.close()


def test_config_can_pin_direct_nvd_source(env, monkeypatch, capsys):
    (env / "config.toml").write_text('default_source = "bogus"\n')
    assert main(["db", "update"]) == 1
    assert "unknown data source" in capsys.readouterr().out


def test_db_publish_command(env, capsys):
    pub = _publisher_db(env / "vulnstack.db")
    pub.close()
    out = env / "release"
    assert main(["db", "publish", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert dist.FULL_NAME in text and "manifest last" in text
    dist.validate_manifest(json.loads((out / dist.MANIFEST_NAME).read_text()))


def test_db_publish_refuses_empty(env, capsys):
    assert main(["db", "publish", "--out", str(env / "o")]) == 1
    assert "Publish failed" in capsys.readouterr().out
    assert not (env / "o" / dist.MANIFEST_NAME).exists()


def test_end_to_end_publish_pull_scan(env, monkeypatch, capsys):
    """publisher DB -> release files -> user pulls -> scan finds the CVE."""
    from tests.conftest import make_response
    from vulnstack import scanner

    pub = _publisher_db(env / "pub.db")
    out = env / "release"
    dist.build_release(pub, out, now=NOW)
    pub.close()
    _patch_fetcher(monkeypatch, _files(out))
    assert main(["db", "update"]) == 0
    monkeypatch.setattr(scanner, "validate_url", lambda url, allow_private=False: ("example.com", "8.8.8.8"))

    class C:
        def __init__(self, **k): pass
        def get(self, url): return make_response(headers={"Server": "Apache/2.4.49"})

    monkeypatch.setattr(scanner, "SafeHttpClient", C)
    capsys.readouterr()
    assert main(["scan", "https://example.com", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [f["cve_id"] for f in data["findings"]] == ["CVE-2020-0001"]
    assert data["findings"][0]["classification"] == "MATCHED_AFFECTED_RANGE"
