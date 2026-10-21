import pytest

from tests.conftest import make_vuln
from vulnstack.cve.database import Database
from vulnstack.cve.models import VersionRange


def test_initialize_creates_schema(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    version = db.initialize()
    assert version >= 1
    assert db.is_initialized()
    assert db.schema_version() == version
    db.close()


def test_persistence_between_connections(tmp_path):
    path = tmp_path / "db.sqlite"
    db = Database(path)
    db.initialize()
    db.upsert_vulnerabilities([make_vuln()])
    db.close()

    db2 = Database(path)
    db2.connect()
    assert db2.count_vulnerabilities() == 1
    db2.close()


def test_insert_then_update_is_idempotent(tmp_db):
    ins, upd = tmp_db.upsert_vulnerabilities([make_vuln(version="2.4.49")])
    assert (ins, upd) == (1, 0)
    # Re-upsert the same CVE: counts as an update, not a duplicate.
    ins2, upd2 = tmp_db.upsert_vulnerabilities([make_vuln(version="2.4.50")])
    assert (ins2, upd2) == (0, 1)
    assert tmp_db.count_vulnerabilities() == 1
    # The affected-product version should reflect the update (no dup rows).
    assert tmp_db.count_affected_products() == 1


def test_no_duplicate_references_or_weaknesses(tmp_db):
    tmp_db.upsert_vulnerabilities([make_vuln()])
    tmp_db.upsert_vulnerabilities([make_vuln()])
    rec = tmp_db.get_vulnerability("CVE-2021-41773")
    assert len(rec["references"]) == 1
    assert rec["weaknesses"] == ["CWE-22"]


def test_foreign_key_cascade_on_clear(seeded_db):
    assert seeded_db.count_version_ranges() > 0
    seeded_db.clear()
    assert seeded_db.count_vulnerabilities() == 0
    assert seeded_db.count_affected_products() == 0
    assert seeded_db.count_version_ranges() == 0


def test_transaction_rollback_on_error(tmp_db):
    good = make_vuln("CVE-2020-0001", version="1.0")

    class Exploding:
        """Looks like a Vulnerability but raises partway through insertion."""
        cve_id = "CVE-2020-0002"
        description = "x"
        published = last_modified = None
        cvss_score = cvss_version = cvss_vector = None
        severity = status = None
        source = "nvd"
        weaknesses: list = []
        affected: list = []

        @property
        def references(self):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        tmp_db.upsert_vulnerabilities([good, Exploding()])
    # The whole batch must be rolled back; neither record persists.
    assert tmp_db.count_vulnerabilities() == 0


def test_severity_and_year_breakdowns(seeded_db):
    sev = seeded_db.severity_breakdown()
    assert sev.get("CRITICAL", 0) >= 1
    years = seeded_db.year_breakdown()
    assert "2021" in years


def test_get_vulnerability_full_record(seeded_db):
    rec = seeded_db.get_vulnerability("CVE-2021-44790")
    assert rec["severity"] == "CRITICAL"
    assert rec["affected_products"][0]["ranges"][0]["version_end"] == "2.4.52"


def test_candidates_batched_retrieval(seeded_db):
    cands = seeded_db.candidates_for_products([("apache", "http_server"), ("nginx", "nginx")])
    assert ("apache", "http_server") in cands
    assert ("nginx", "nginx") in cands
    apache_cves = {row["cve_id"] for row in cands[("apache", "http_server")]}
    assert {"CVE-2021-41773", "CVE-2021-44790"} <= apache_cves


def test_search_by_text_is_injection_safe(seeded_db):
    # A malicious term must be treated as a literal, not executed.
    rows = seeded_db.search_by_text("'; DROP TABLE vulnerabilities; --")
    assert rows == []
    # Table still exists and is intact.
    assert seeded_db.count_vulnerabilities() == 4


def test_clear_requires_initialized_schema_preserved(seeded_db):
    seeded_db.clear()
    # Schema version metadata is preserved after clear.
    assert seeded_db.schema_version() >= 1
