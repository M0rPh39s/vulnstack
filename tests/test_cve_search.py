from tests.conftest import make_vuln
from vulnstack.cve.models import VersionRange
from vulnstack.cve.search import Classification, SearchQuery, VulnerabilitySearch


def _find(report, cve_id):
    return next((f for f in report.findings if f.cve_id == cve_id), None)


def test_exact_version_match(seeded_db):
    engine = VulnerabilitySearch(seeded_db)
    report = engine.search([SearchQuery("Apache HTTP Server", "2.4.49")])
    f = _find(report, "CVE-2021-41773")
    assert f is not None
    assert f.classification == Classification.MATCHED_AFFECTED_RANGE


def test_range_match(seeded_db):
    engine = VulnerabilitySearch(seeded_db)
    report = engine.search([SearchQuery("Apache HTTP Server", "2.4.50")])
    f = _find(report, "CVE-2021-44790")
    assert f.classification == Classification.MATCHED_AFFECTED_RANGE


def test_version_not_matched(seeded_db):
    engine = VulnerabilitySearch(seeded_db)
    # 2.4.60 is above the 44790 range and not equal to 41773's exact version.
    report = engine.search([SearchQuery("Apache HTTP Server", "2.4.60")])
    f = _find(report, "CVE-2021-44790")
    assert f.classification == Classification.VERSION_NOT_MATCHED


def test_version_unknown(seeded_db):
    engine = VulnerabilitySearch(seeded_db)
    report = engine.search([SearchQuery("Apache HTTP Server", None)])
    f = _find(report, "CVE-2021-41773")
    assert f.classification == Classification.VERSION_UNKNOWN


def test_affected_range_unavailable(seeded_db):
    engine = VulnerabilitySearch(seeded_db)
    report = engine.search([SearchQuery("WordPress", "6.1.1")])
    f = _find(report, "CVE-2022-00001")
    assert f.classification == Classification.AFFECTED_RANGE_UNAVAILABLE


def test_alias_resolution_in_search(seeded_db):
    engine = VulnerabilitySearch(seeded_db)
    report = engine.search([SearchQuery("httpd", "2.4.49")])
    assert _find(report, "CVE-2021-41773") is not None


def test_unresolved_technology_recorded(seeded_db):
    engine = VulnerabilitySearch(seeded_db)
    report = engine.search([SearchQuery("Made Up Product", "1.0")])
    assert "Made Up Product" in report.unresolved
    assert report.findings == []


def test_dedup_across_technologies(tmp_db):
    # A CVE reachable through two products should appear once with both merged.
    v = make_vuln("CVE-2099-0001", version="1.0")
    # Add a second affected product to the same CVE.
    from vulnstack.cve.models import AffectedProduct
    v.affected.append(
        AffectedProduct(cpe_vendor="nginx", cpe_product="nginx", version="1.0")
    )
    tmp_db.upsert_vulnerabilities([v])
    engine = VulnerabilitySearch(tmp_db)
    report = engine.search([SearchQuery("Apache", "1.0"), SearchQuery("Nginx", "1.0")])
    matches = [f for f in report.findings if f.cve_id == "CVE-2099-0001"]
    assert len(matches) == 1
    assert len(matches[0].matched_products) >= 2


def test_batched_retrieval_no_per_product_queries(seeded_db):
    # Verify candidates_for_products is called once for all technologies.
    calls = {"n": 0}
    original = seeded_db.candidates_for_products

    def counting(pairs):
        calls["n"] += 1
        return original(pairs)

    seeded_db.candidates_for_products = counting  # type: ignore[assignment]
    engine = VulnerabilitySearch(seeded_db)
    engine.search([
        SearchQuery("Apache", "2.4.49"),
        SearchQuery("Nginx", "1.20.0"),
        SearchQuery("WordPress", "6.0"),
    ])
    assert calls["n"] == 1


def test_source_data_incomplete_when_uncertain(tmp_db):
    # A range whose boundary has no interpretable version tokens, so the
    # comparison cannot be made safely and must be reported as uncertain.
    v = make_vuln(
        "CVE-2099-0002", cpe_vendor="apache", cpe_product="http_server",
        ranges=[VersionRange(version_end="???", version_end_type="excluding")],
    )
    tmp_db.upsert_vulnerabilities([v])
    engine = VulnerabilitySearch(tmp_db)
    report = engine.search([SearchQuery("Apache", "2.4.49")])
    f = _find(report, "CVE-2099-0002")
    assert f.classification == Classification.SOURCE_DATA_INCOMPLETE
