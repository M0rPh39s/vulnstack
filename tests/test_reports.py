import json

from vulnstack.reports import html_report, json_report
from vulnstack.scanner import ScanResult, DatabaseInfo
from vulnstack.cve.search import Classification, Finding, MatchedProduct
from vulnstack.fingerprinting import DetectedTechnology


def _result_with_untrusted():
    tech = DetectedTechnology(
        name="Apache HTTP Server", category="Web server", version="2.4.49",
        confidence="high",
        evidence=["header Server: Apache/2.4.49 <script>alert(1)</script>"],
    )
    finding = Finding(
        cve_id="CVE-2021-41773",
        classification=Classification.MATCHED_AFFECTED_RANGE,
        severity="HIGH", cvss_score=7.5, cvss_version="3.1",
        description="Path traversal <img src=x onerror=alert(1)>",
        published="2021-10-05", source="nvd",
        technologies=["Apache HTTP Server"],
        matched_products=[MatchedProduct(
            technology="Apache HTTP Server", detected_version="2.4.49",
            cpe_vendor="apache", cpe_product="http_server",
            cpe23="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            classification=Classification.MATCHED_AFFECTED_RANGE, detail="exact match",
        )],
        references=[{"url": "https://example.com/a", "ref_type": "Vendor"}],
    )
    return ScanResult(
        target="https://example.com", final_url="https://example.com",
        timestamp="2026-01-01T00:00:00+00:00", status="ok", tool_version="0.1.0",
        config={"no_cve": False},
        technologies=[tech], findings=[finding],
        database=DatabaseInfo(initialized=True, path="/tmp/x.db", total_cves=10,
                              last_successful_sync="2026-01-01T00:00:00"),
    )


def test_json_report_is_valid_and_complete():
    result = _result_with_untrusted()
    text = json_report.render(result)
    data = json.loads(text)  # must be valid JSON
    assert data["tool"] == "vulnstack"
    assert data["target"] == "https://example.com"
    assert data["findings"][0]["cve_id"] == "CVE-2021-41773"
    assert data["summary"]["findings_total"] == 1
    assert "database" in data


def test_json_report_has_no_secret_fields():
    text = json_report.render(_result_with_untrusted())
    lowered = text.lower()
    assert "apikey" not in lowered
    assert "authorization" not in lowered
    assert "set-cookie" not in lowered


def test_html_report_escapes_untrusted_content():
    html = html_report.render(_result_with_untrusted())
    # Raw script/img injection must be escaped, not present as live markup.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "CVE-2021-41773" in html


def test_html_report_is_self_contained():
    html = html_report.render(_result_with_untrusted())
    # No remote scripts/resources.
    assert "http-equiv" not in html.lower() or "refresh" not in html.lower()
    assert "<script src" not in html.lower()
    assert "exploitab" in html.lower()  # includes the exploitability caveat
