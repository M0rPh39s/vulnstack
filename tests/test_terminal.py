"""Terminal report rendering (rich), captured to plain text."""

from rich.console import Console

from tests.conftest import make_response
from vulnstack import scanner
from vulnstack.config import Config
from vulnstack.fingerprinting import fingerprint
from vulnstack.reports import terminal
from vulnstack.scanner import DatabaseInfo, ScanResult


def _render(result, **kw):
    console = Console(record=True, width=200, force_terminal=False)
    terminal.render(result, console, **kw)
    return console.export_text()


def _result(**kw):
    base = dict(target="https://example.com", final_url="https://example.com", timestamp="2026-01-01T00:00:00+00:00",
                status="ok", tool_version="0.1.0", config={})
    base.update(kw)
    return ScanResult(**base)


def _scan(monkeypatch, db, headers, **kw):
    monkeypatch.setattr(scanner, "validate_url", lambda url, allow_private=False: ("example.com", "8.8.8.8"))

    class C:
        def __init__(self, **k): pass
        def get(self, url): return make_response(headers=headers)

    monkeypatch.setattr(scanner, "SafeHttpClient", C)
    cfg = Config()
    cfg.database_path = str(db.path)
    return scanner.scan("https://example.com", config=cfg, database=db, **kw)


def test_error_result_lists_errors():
    out = _render(_result(status="error", errors=["boom happened"]))
    assert "ERROR" in out and "boom happened" in out


def test_final_url_shown_only_when_different():
    assert "Final URL" not in _render(_result())
    assert "Final URL: https://www.example.com" in _render(_result(final_url="https://www.example.com"))


def test_no_cve_does_not_claim_no_candidates(monkeypatch, seeded_db):
    out = _render(_scan(monkeypatch, seeded_db, {"Server": "nginx/1.18.0"}, no_cve=True))
    assert "skipped (--no-cve)" in out
    assert "No candidate CVEs" not in out


def test_empty_database_does_not_claim_no_candidates(monkeypatch, tmp_db):
    out = _render(_scan(monkeypatch, tmp_db, {"Server": "nginx/1.18.0"}))
    assert "empty" in out
    assert "No candidate CVEs" not in out


def test_clean_search_says_no_candidates(monkeypatch, seeded_db):
    out = _render(_scan(monkeypatch, seeded_db, {"Server": "lighttpd/1.4.55"}))
    assert "No candidate CVEs found" in out
    assert "Lighttpd" in out


def test_match_and_unresolved_rendering(monkeypatch, seeded_db):
    out = _render(_scan(monkeypatch, seeded_db, {"Server": "Apache/2.4.49", "CF-Ray": "abc"}))
    assert "Version matches an affected range" in out
    assert "CVE-2021-41773" in out
    assert "Confirmed version matches: 2" in out
    assert "·" not in out.split("Confirmed version matches: 2")[1].splitlines()[0]  # no dangling separator
    assert "Cloudflare" in out and "No local product mapping for" in out  # infra hint, not correlated


def test_unmatched_hidden_unless_requested(monkeypatch, seeded_db):
    result = _scan(monkeypatch, seeded_db, {"Server": "Apache/2.4.58"})
    assert "not in affected range" not in _render(result)
    assert "not in affected range" in _render(result, show_unmatched=True)


def test_unknown_version_and_conflicts_rendered():
    resp = make_response(body='<script src="/jquery-1.0.0.min.js"></script><script src="/jquery-2.0.0.min.js"></script>')
    result = _result(technologies=fingerprint(resp))
    out = _render(result)
    assert "conflicts: 2.0.0" in out


def test_no_technologies_message():
    assert "none detected" in _render(_result())


def test_uninitialized_database_summary():
    result = _result(database=DatabaseInfo(initialized=False, path="/x.db"),
                     warnings=["Local vulnerability database is not initialized."])
    out = _render(result)
    assert "not initialized" in out and "Summary:" in out


def test_stale_marker_in_summary():
    result = _result(database=DatabaseInfo(initialized=True, path="/x", total_cves=5,
                                           last_successful_sync="2020-01-01T00:00:00+00:00", stale=True))
    assert "possibly outdated" in _render(result)
