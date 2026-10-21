"""Performance / resource-usage characteristics of the search engine.

These are lightweight structural checks (not wall-clock promises): they verify
that candidate retrieval is index-backed, batched, and does not require loading
the whole corpus, using synthetic databases.
"""

from __future__ import annotations

import time

from tests.conftest import make_vuln
from vulnstack.cve.models import VersionRange
from vulnstack.cve.search import SearchQuery, VulnerabilitySearch


def _build_synthetic(db, n):
    vulns = []
    for i in range(n):
        # Spread across a few products so lookups are selective.
        if i % 3 == 0:
            v = make_vuln(f"CVE-SYN-{i:06d}", cpe_vendor="apache", cpe_product="http_server",
                          ranges=[VersionRange(version_start="2.0", version_start_type="including",
                                               version_end="2.9", version_end_type="excluding")])
        elif i % 3 == 1:
            v = make_vuln(f"CVE-SYN-{i:06d}", cpe_vendor="nginx", cpe_product="nginx",
                          ranges=[VersionRange(version_end="1.99", version_end_type="excluding")])
        else:
            v = make_vuln(f"CVE-SYN-{i:06d}", cpe_vendor=f"vendor{i}", cpe_product=f"product{i}")
        vulns.append(v)
    # Batched write.
    for start in range(0, len(vulns), 500):
        db.upsert_vulnerabilities(vulns[start:start + 500])


def test_candidate_query_uses_index(tmp_db):
    _build_synthetic(tmp_db, 300)
    conn = tmp_db.connect()
    plan = conn.execute(
        "EXPLAIN QUERY PLAN "
        "SELECT ap.id FROM affected_products ap "
        "JOIN vulnerabilities v ON v.cve_id = ap.cve_id "
        "WHERE (cpe_vendor = ? AND cpe_product = ?)",
        ("apache", "http_server"),
    ).fetchall()
    detail = " ".join(row["detail"] for row in plan)
    # The affected_products scan must use the CPE index, not a full scan.
    assert "idx_affected_cpe" in detail
    assert "SCAN affected_products" not in detail  # i.e. not a full table scan


def test_search_scales_to_thousands(tmp_db):
    _build_synthetic(tmp_db, 3000)
    engine = VulnerabilitySearch(tmp_db)
    start = time.perf_counter()
    report = engine.search([
        SearchQuery("Apache HTTP Server", "2.4.5"),
        SearchQuery("Nginx", "1.18.0"),
    ])
    elapsed = time.perf_counter() - start
    # Many matches expected, returned quickly (generous bound for CI).
    assert report.findings
    assert elapsed < 2.0


def test_single_batched_retrieval_call(tmp_db):
    _build_synthetic(tmp_db, 100)
    calls = {"n": 0}
    original = tmp_db.candidates_for_products

    def counting(pairs):
        calls["n"] += 1
        return original(pairs)

    tmp_db.candidates_for_products = counting  # type: ignore[assignment]
    engine = VulnerabilitySearch(tmp_db)
    engine.search([SearchQuery("Apache", "2.4.5"), SearchQuery("Nginx", "1.5")])
    assert calls["n"] == 1  # no per-product query explosion
