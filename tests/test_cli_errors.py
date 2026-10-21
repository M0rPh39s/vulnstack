"""CLI error paths and exit codes."""

import io
import json

import pytest

from tests.conftest import make_vuln
from vulnstack import cli
from vulnstack.cli import main
from vulnstack.cve import providers
from vulnstack.cve.database import Database
from vulnstack.cve.providers import Provider, ProviderError
from vulnstack.scanner import ScanResult


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNSTACK_DATABASE", str(tmp_path / "vulnstack.db"))
    monkeypatch.setenv("VULNSTACK_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("VULNSTACK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    return tmp_path


@pytest.fixture
def seeded(env):
    db = Database(env / "vulnstack.db")
    db.initialize()
    db.upsert_vulnerabilities([make_vuln("CVE-2021-41773", version="2.4.49")])
    db.close()
    return env


class _Fake(Provider):
    name = "fake"
    fail = False

    def __init__(self, **_):
        pass

    def fetch(self, *, modified_since, full, progress=None):
        if _Fake.fail:
            raise ProviderError("simulated outage")
        if progress:
            progress(1, 1)
        yield make_vuln("CVE-2024-0001", version="1.0")

    def latest_source_modified(self):
        return "2024-01-01T00:00:00"


@pytest.fixture
def fake_source(monkeypatch):
    monkeypatch.setitem(providers._REGISTRY, "fake", _Fake)
    _Fake.fail = False
    yield _Fake
    _Fake.fail = False


# ---- usage ------------------------------------------------------------------

@pytest.mark.parametrize("command", ["db", "cve", "config", "cache"])
def test_missing_subcommand_is_usage_error(env, command, capsys):
    assert main([command]) == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_unknown_command_exit_two():
    with pytest.raises(SystemExit) as exc:
        main(["frobnicate"])
    assert exc.value.code == 2


def test_bad_format_choice_exit_two():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "https://example.com", "--format", "yaml"])
    assert exc.value.code == 2


# ---- configuration ----------------------------------------------------------

def test_invalid_config_file_exit_one(env, capsys):
    (env / "config.toml").write_text('timeout = -5\n')
    assert main(["config", "show"]) == 1
    assert "Configuration error" in capsys.readouterr().err


def test_malformed_config_file_does_not_traceback(env, capsys):
    (env / "config.toml").write_text("this is [[ not toml")
    code = main(["config", "show"])
    assert code in (0, 1)
    assert "Traceback" not in capsys.readouterr().err


def test_invalid_cli_timeout_exit_one(env, capsys):
    assert main(["scan", "https://example.com", "--timeout", "0"]) == 1
    assert "timeout" in capsys.readouterr().err.lower()


def test_config_show_never_prints_api_key(env, monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "super-secret-key-123")
    assert main(["config", "show"]) == 0
    out = capsys.readouterr()
    assert "super-secret-key-123" not in out.out + out.err
    assert "redacted" in out.out


# ---- db update --------------------------------------------------------------

def test_db_update_unknown_source(env, capsys):
    assert main(["db", "update", "--source", "bogus"]) == 1
    assert "unknown data source" in capsys.readouterr().out


def test_db_update_cvelist_requires_path(env, monkeypatch, capsys):
    monkeypatch.delenv("VULNSTACK_CVELIST_PATH", raising=False)
    assert main(["db", "update", "--source", "cvelist"]) == 1
    assert "requires a local path" in " ".join(capsys.readouterr().out.split())


def test_db_update_cvelist_missing_path_fails_cleanly(env, capsys):
    assert main(["db", "update", "--source", "cvelist", "--cvelist-path", str(env / "nope")]) == 1
    assert "does not exist" in " ".join(capsys.readouterr().out.split())


def test_db_update_cvelist_success_via_env(env, monkeypatch, capsys):
    record = {"cveMetadata": {"cveId": "CVE-2021-0001", "dateUpdated": "2023-01-01T00:00:00.000Z"},
              "containers": {"cna": {"descriptions": [{"lang": "en", "value": "x"}]}}}
    (env / "CVE-2021-0001.json").write_text(json.dumps(record))
    monkeypatch.setenv("VULNSTACK_CVELIST_PATH", str(env))
    assert main(["db", "update", "--source", "cvelist"]) == 0
    assert "Records inserted: 1" in capsys.readouterr().out


def test_db_update_success_and_failure_exit_codes(env, fake_source, capsys):
    assert main(["db", "update", "--source", "fake"]) == 0
    out = capsys.readouterr().out
    assert "Records inserted: 1" in out and "success" in out

    fake_source.fail = True
    assert main(["db", "update", "--source", "fake"]) == 1
    out = capsys.readouterr().out
    assert "failed" in out and "simulated outage" in out


def test_status_after_failed_sync_keeps_last_success_time(env, fake_source, capsys):
    main(["db", "update", "--source", "fake"])
    db = Database(env / "vulnstack.db")
    success_time = db.get_source("fake")["last_sync_time"]
    db.close()
    fake_source.fail = True
    main(["db", "update", "--source", "fake"])
    capsys.readouterr()
    assert main(["db", "status"]) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "Last successful sync" in out and success_time[:19] in out
    assert "Newest record synced" in out
    assert "failed" in out and "simulated outage" in out


def test_never_synced_source_reports_never_after_first_failure(env, fake_source, capsys):
    fake_source.fail = True
    main(["db", "update", "--source", "fake"])
    capsys.readouterr()
    main(["db", "status"])
    out = " ".join(capsys.readouterr().out.split())
    assert "Last successful sync │ never" in out


# ---- db status / stats / clear ---------------------------------------------

def test_db_status_uninitialized(env, capsys):
    assert main(["db", "status"]) == 0
    out = capsys.readouterr().out
    assert "no" in out and "vulnstack db update" in out


def test_db_stats_empty(env, capsys):
    assert main(["db", "stats"]) == 0
    assert "No vulnerability records" in capsys.readouterr().out


def test_db_clear_uninitialized(env, capsys):
    assert main(["db", "clear", "--yes"]) == 0
    assert "nothing to clear" in capsys.readouterr().out


@pytest.mark.parametrize("answer,cleared", [("yes", True), ("no", False), ("", False)])
def test_db_clear_prompt(seeded, monkeypatch, capsys, answer, cleared):
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)
    assert main(["db", "clear"]) == 0
    db = Database(seeded / "vulnstack.db")
    assert (db.count_vulnerabilities() == 0) is cleared
    db.close()
    assert ("Cleared" in capsys.readouterr().out) is cleared


def test_db_clear_eof_aborts(seeded, monkeypatch, capsys):
    def eof(prompt=""):
        raise EOFError
    monkeypatch.setattr("builtins.input", eof)
    assert main(["db", "clear"]) == 0
    assert "Aborted" in capsys.readouterr().out
    db = Database(seeded / "vulnstack.db")
    assert db.count_vulnerabilities() == 1
    db.close()


# ---- cve search / show ------------------------------------------------------

def test_cve_search_uninitialized(env, capsys):
    assert main(["cve", "search", "apache"]) == 1
    assert "not initialized" in capsys.readouterr().out


def test_cve_search_no_match(seeded, capsys):
    assert main(["cve", "search", "zzzznothing"]) == 0
    assert "No local records matched" in capsys.readouterr().out


def test_cve_show_uninitialized(env, capsys):
    assert main(["cve", "show", "CVE-2021-41773"]) == 1


def test_cve_show_lowercase_id_and_details(seeded, capsys):
    assert main(["cve", "show", "cve-2021-41773"]) == 0
    out = capsys.readouterr().out
    assert "CVE-2021-41773" in out and "Affected products" in out and "CWE-22" in out


def test_cve_show_prints_ranges(env, capsys):
    from vulnstack.cve.models import VersionRange
    db = Database(env / "vulnstack.db")
    db.initialize()
    db.upsert_vulnerabilities([make_vuln(
        "CVE-2024-1111", ranges=[VersionRange("2.0", "including", "2.5", "excluding")])])
    db.close()
    assert main(["cve", "show", "CVE-2024-1111"]) == 0
    out = capsys.readouterr().out
    assert ">=2.0" in out and "<2.5" in out


# ---- scan / technologies ----------------------------------------------------

def _ok_result(url="https://example.com", **kw):
    return ScanResult(target=url, final_url=url, timestamp="2026-01-01T00:00:00+00:00",
                      status="ok", tool_version="0.1.0", config={}, **kw)


def _error_result(url="https://example.com"):
    return ScanResult(target=url, final_url=None, timestamp="2026-01-01T00:00:00+00:00",
                      status="error", tool_version="0.1.0", config={}, errors=["connection refused"])


def test_scan_error_result_exit_one_in_every_format(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_scan", lambda url, *, config, no_cve=False, database=None: _error_result(url))
    for fmt in ("terminal", "json", "html"):
        assert main(["scan", "https://example.com", "--format", fmt]) == 1
    assert "connection refused" in capsys.readouterr().out


def test_scan_json_to_stdout_is_valid(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_scan", lambda url, *, config, no_cve=False, database=None: _ok_result(url))
    assert main(["scan", "https://example.com", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"


def test_scan_html_output_file_created_in_new_dir(env, monkeypatch):
    monkeypatch.setattr(cli, "run_scan", lambda url, *, config, no_cve=False, database=None: _ok_result(url))
    out = env / "nested" / "dir" / "r.html"
    assert main(["scan", "https://example.com", "--format", "html", "--output", str(out)]) == 0
    assert out.read_text().lstrip().lower().startswith("<!doctype html")


def test_no_cve_flag_is_forwarded(env, monkeypatch):
    seen = {}

    def fake(url, *, config, no_cve=False, database=None):
        seen["no_cve"] = no_cve
        return _ok_result(url)

    monkeypatch.setattr(cli, "run_scan", fake)
    main(["scan", "https://example.com", "--no-cve"])
    assert seen["no_cve"] is True
    main(["technologies", "https://example.com"])
    assert seen["no_cve"] is True  # `technologies` never correlates


@pytest.mark.parametrize("fmt", ["terminal", "json", "html"])
def test_technologies_formats(env, monkeypatch, capsys, fmt):
    monkeypatch.setattr(cli, "run_scan", lambda url, *, config, no_cve=False, database=None: _ok_result(url))
    assert main(["technologies", "https://example.com", "--format", fmt]) == 0


@pytest.mark.parametrize("url", ["ftp://example.com", "file:///etc/passwd", "http://127.0.0.1/",
                                 "http://169.254.169.254/latest/meta-data/", "http://[::1]/"])
def test_blocked_targets_exit_one_without_traceback(env, url, capsys):
    assert main(["scan", url]) == 1
    assert "Traceback" not in capsys.readouterr().err


def test_keyboard_interrupt_exit_one(env, monkeypatch, capsys):
    def boom(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "run_scan", boom)
    assert main(["scan", "https://example.com"]) == 1
    assert "Interrupted" in capsys.readouterr().err


def test_unexpected_error_concise_unless_verbose(env, monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(cli, "run_scan", boom)
    assert main(["scan", "https://example.com"]) == 1
    err = capsys.readouterr().err
    assert "kaboom" in err and "Traceback" not in err
    assert main(["--verbose", "scan", "https://example.com"]) == 1
    assert "Traceback" in capsys.readouterr().err


# ---- cache ------------------------------------------------------------------

def test_cache_clear_removes_entries(env, capsys):
    from vulnstack.cache import Cache
    cache = Cache(env / "cache")
    cache.set("a", {"x": 1})
    cache.set("b", {"x": 2})
    assert main(["cache", "clear"]) == 0
    assert "Cleared 2 cache entries" in capsys.readouterr().out
    assert cache.get("a") is None


@pytest.mark.parametrize("argv", [
    ["--verbose", "scan", "https://example.com"],
    ["-v", "scan", "https://example.com"],
    ["scan", "https://example.com", "--verbose"],
    ["scan", "https://example.com", "-v"],
])
def test_verbose_flag_works_before_or_after_subcommand(env, monkeypatch, capsys, argv):
    def boom(*a, **k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(cli, "run_scan", boom)
    assert main(argv) == 1
    assert "Traceback" in capsys.readouterr().err
