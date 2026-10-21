import json

import pytest

from tests.conftest import make_response
from vulnstack import scanner
from vulnstack.config import Config
from vulnstack.cve.search import Classification
from vulnstack.reports import json_report


class FakeClient:
    def __init__(self, response, **kwargs):
        self._response = response

    def get(self, url):
        return self._response


@pytest.fixture
def patched_http(monkeypatch):
    """Patch the scanner's HTTP layer so no real network is used."""
    monkeypatch.setattr(scanner, "validate_url", lambda url, allow_private=False: ("example.com", "8.8.8.8"))

    def install(response):
        monkeypatch.setattr(scanner, "SafeHttpClient", lambda **kw: FakeClient(response, **kw))

    return install


def _cfg(db_path):
    cfg = Config()
    cfg.database_path = str(db_path)
    return cfg


def test_scan_to_cve_workflow(patched_http, seeded_db):
    patched_http(make_response(headers={"Server": "Apache/2.4.49 (Unix)"}))
    cfg = _cfg(seeded_db.path)
    result = scanner.scan("https://example.com", config=cfg, database=seeded_db)
    assert result.status == "ok"
    names = {t.name for t in result.technologies}
    assert "Apache HTTP Server" in names
    matched = [f for f in result.findings if f.classification == Classification.MATCHED_AFFECTED_RANGE]
    assert any(f.cve_id == "CVE-2021-41773" for f in matched)


def test_scan_multiple_technologies(patched_http, seeded_db):
    body = '<html><head><meta name="generator" content="WordPress 6.1.1"></head></html>'
    patched_http(make_response(headers={"Server": "Apache/2.4.50"}, body=body))
    cfg = _cfg(seeded_db.path)
    result = scanner.scan("https://example.com", config=cfg, database=seeded_db)
    names = {t.name for t in result.technologies}
    assert {"Apache HTTP Server", "WordPress"} <= names


def test_no_cve_flag_skips_search(patched_http, seeded_db):
    patched_http(make_response(headers={"Server": "Apache/2.4.49"}))
    cfg = _cfg(seeded_db.path)
    result = scanner.scan("https://example.com", config=cfg, no_cve=True, database=seeded_db)
    assert result.findings == []
    assert any("no-cve" in w for w in result.warnings)
    assert result.technologies  # fingerprinting still ran


def test_scan_empty_database(patched_http, tmp_db):
    patched_http(make_response(headers={"Server": "Apache/2.4.49"}))
    cfg = _cfg(tmp_db.path)
    result = scanner.scan("https://example.com", config=cfg, database=tmp_db)
    assert result.status == "ok"
    assert result.findings == []
    assert any("empty" in w.lower() for w in result.warnings)


def test_scan_uninitialized_database(patched_http, tmp_path):
    from vulnstack.cve.database import Database
    patched_http(make_response(headers={"Server": "Apache/2.4.49"}))
    db = Database(tmp_path / "fresh.db")  # connect lazily, not initialized
    cfg = _cfg(db.path)
    result = scanner.scan("https://example.com", config=cfg, database=db)
    assert result.status == "ok"
    assert any("not initialized" in w.lower() for w in result.warnings)
    db.close()


def test_scan_rejects_blocked_target(monkeypatch, seeded_db):
    from vulnstack.http_client import ScanSafetyError
    def boom(url, allow_private=False):
        raise ScanSafetyError("blocked")
    monkeypatch.setattr(scanner, "validate_url", boom)
    cfg = _cfg(seeded_db.path)
    result = scanner.scan("http://127.0.0.1", config=cfg, database=seeded_db)
    assert result.status == "error"
    assert result.errors


def test_scan_result_json_serializable(patched_http, seeded_db):
    patched_http(make_response(headers={"Server": "Apache/2.4.49"}))
    cfg = _cfg(seeded_db.path)
    result = scanner.scan("https://example.com", config=cfg, database=seeded_db)
    text = json_report.render(result)
    json.loads(text)  # does not raise
