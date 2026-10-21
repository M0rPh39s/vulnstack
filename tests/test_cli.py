import json

import pytest

from tests.conftest import make_vuln
from vulnstack.cli import main
from vulnstack.cve.database import Database


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """Point all VulnStack paths at a temp directory."""
    db_path = tmp_path / "vulnstack.db"
    monkeypatch.setenv("VULNSTACK_DATABASE", str(db_path))
    monkeypatch.setenv("VULNSTACK_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("VULNSTACK_CONFIG", str(tmp_path / "config.toml"))
    return db_path


@pytest.fixture
def seeded_env(isolated_env):
    db = Database(isolated_env)
    db.initialize()
    db.upsert_vulnerabilities([make_vuln("CVE-2021-41773", version="2.4.49")])
    db.close()
    return isolated_env


def test_version_exit_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "vulnstack" in capsys.readouterr().out


def test_help_exit_zero():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_no_command_is_usage_exit():
    assert main([]) == 2


def test_invalid_argument_exit_two():
    with pytest.raises(SystemExit) as exc:
        main(["scan"])  # missing required url
    assert exc.value.code == 2


def test_db_status(isolated_env, capsys):
    assert main(["db", "status"]) == 0
    assert "database status" in capsys.readouterr().out.lower()


def test_db_update_and_status(seeded_env, capsys):
    assert main(["db", "status"]) == 0
    out = capsys.readouterr().out
    assert "Total CVE records" in out


def test_db_stats(seeded_env, capsys):
    assert main(["db", "stats"]) == 0
    assert "severity" in capsys.readouterr().out.lower()


def test_db_clear_with_yes(seeded_env, capsys):
    assert main(["db", "clear", "--yes"]) == 0
    assert "Cleared" in capsys.readouterr().out


def test_cve_search(seeded_env, capsys):
    assert main(["cve", "search", "Apache"]) == 0
    assert "CVE-2021-41773" in capsys.readouterr().out


def test_cve_show_found(seeded_env, capsys):
    assert main(["cve", "show", "CVE-2021-41773"]) == 0
    assert "CVE-2021-41773" in capsys.readouterr().out


def test_cve_show_missing(seeded_env, capsys):
    assert main(["cve", "show", "CVE-9999-0000"]) == 1
    assert "not found" in capsys.readouterr().out.lower()


def test_config_show(isolated_env, capsys):
    assert main(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert "configuration" in out.lower()
    # Secret presence reported without leaking a value.
    assert "NVD_API_KEY" in out


def test_cache_clear(isolated_env, capsys):
    assert main(["cache", "clear"]) == 0
    assert "Cleared" in capsys.readouterr().out


def test_scan_error_exit_one(isolated_env, monkeypatch, capsys):
    # A blocked/unreachable target yields a runtime error exit code.
    assert main(["scan", "http://127.0.0.1/"]) == 1


def test_scan_json_output_to_file(isolated_env, monkeypatch, tmp_path):
    # Patch the scan pipeline to avoid real network, produce a clean result.
    from vulnstack import cli
    from vulnstack.scanner import ScanResult

    def fake_scan(url, *, config, no_cve=False, database=None):
        return ScanResult(
            target=url, final_url=url, timestamp="2026-01-01T00:00:00+00:00",
            status="ok", tool_version="0.1.0", config={"no_cve": no_cve},
        )
    monkeypatch.setattr(cli, "run_scan", fake_scan)
    out_file = tmp_path / "report.json"
    assert main(["scan", "https://example.com", "--format", "json", "--output", str(out_file)]) == 0
    data = json.loads(out_file.read_text())
    assert data["target"] == "https://example.com"
