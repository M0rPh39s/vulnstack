"""Tests for the NVD provider: parsing, pagination, retry and date windows."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vulnstack.cve import nvd
from vulnstack.cve.providers import ProviderError


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(nvd.time, "sleep", lambda *_: None)


SAMPLE_CVE = {
    "cve": {
        "id": "CVE-2021-41773",
        "published": "2021-10-05T07:15:00",
        "lastModified": "2021-11-01T00:00:00",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49."}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {"baseScore": 7.5, "version": "3.1", "vectorString": "CVSS:3.1/..."},
                    "baseSeverity": "HIGH",
                }
            ]
        },
        "weaknesses": [{"description": [{"value": "CWE-22"}]}],
        "references": [{"url": "https://example.com/adv", "tags": ["Vendor Advisory"]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    }
}

SAMPLE_RANGE_CVE = {
    "cve": {
        "id": "CVE-2021-44790",
        "published": "2021-12-20T00:00:00",
        "lastModified": "2021-12-20T00:00:00",
        "descriptions": [{"lang": "en", "value": "mod_lua buffer overflow."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "version": "3.1"}, "baseSeverity": "CRITICAL"}]},
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.4.0",
                                "versionEndExcluding": "2.4.52",
                            }
                        ]
                    }
                ]
            }
        ],
    }
}


def test_parse_exact_version():
    v = nvd.parse_cve(SAMPLE_CVE)
    assert v.cve_id == "CVE-2021-41773"
    assert v.severity == "HIGH"
    assert v.cvss_score == 7.5
    assert v.weaknesses == ["CWE-22"]
    assert v.affected[0].cpe_vendor == "apache"
    assert v.affected[0].cpe_product == "http_server"
    assert v.affected[0].version == "2.4.49"


def test_parse_version_range():
    v = nvd.parse_cve(SAMPLE_RANGE_CVE)
    rng = v.affected[0].ranges[0]
    assert rng.version_start == "2.4.0"
    assert rng.version_start_type == "including"
    assert rng.version_end == "2.4.52"
    assert rng.version_end_type == "excluding"


def test_parse_ignores_non_vulnerable_cpe():
    record = {
        "cve": {
            "id": "CVE-X",
            "descriptions": [{"lang": "en", "value": "x"}],
            "configurations": [
                {"nodes": [{"cpeMatch": [
                    {"vulnerable": False, "criteria": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}
                ]}]}
            ],
        }
    }
    v = nvd.parse_cve(record)
    assert v.affected == []


class FakeResp:
    def __init__(self, status, payload=None, headers=None):
        self.status_code = status
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.requests = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append(params or {})
        return self._responses.pop(0)


def _page(items, total, start):
    return {"vulnerabilities": items, "totalResults": total, "startIndex": start,
            "resultsPerPage": nvd.PAGE_SIZE}


def test_pagination_follows_total():
    # Two pages worth of a 3-result corpus (page size forced small via total).
    session = FakeSession([
        FakeResp(200, _page([SAMPLE_CVE, SAMPLE_RANGE_CVE], total=3, start=0)),
        FakeResp(200, _page([SAMPLE_CVE], total=3, start=2)),
    ])
    provider = nvd.NvdProvider(session=session)
    vulns = list(provider.fetch(modified_since=None, full=True))
    assert len(vulns) == 3
    assert len(session.requests) == 2


def test_retry_on_429_then_success():
    session = FakeSession([
        FakeResp(429, headers={"Retry-After": "1"}),
        FakeResp(200, _page([SAMPLE_CVE], total=1, start=0)),
    ])
    provider = nvd.NvdProvider(session=session, max_retries=3)
    vulns = list(provider.fetch(modified_since=None, full=True))
    assert len(vulns) == 1


def test_403_raises_provider_error():
    session = FakeSession([FakeResp(403)])
    provider = nvd.NvdProvider(session=session)
    with pytest.raises(ProviderError):
        list(provider.fetch(modified_since=None, full=True))


def test_incremental_date_windows_bounded():
    # A >120-day gap must be split into multiple bounded windows.
    session = FakeSession([
        FakeResp(200, _page([], total=0, start=0)),
        FakeResp(200, _page([], total=0, start=0)),
        FakeResp(200, _page([], total=0, start=0)),
        FakeResp(200, _page([], total=0, start=0)),
        FakeResp(200, _page([], total=0, start=0)),
    ])
    provider = nvd.NvdProvider(session=session)
    since = datetime.now(timezone.utc).replace(microsecond=0)
    since = since.replace(year=since.year - 1)  # ~365 days ago
    list(provider.fetch(modified_since=since, full=False))
    # 365 days / 120 -> at least 4 windows, each carrying date params.
    assert len(session.requests) >= 4
    for req in session.requests:
        assert "lastModStartDate" in req and "lastModEndDate" in req


def test_api_key_sent_in_header_not_logged():
    session = FakeSession([FakeResp(200, _page([], total=0, start=0))])
    provider = nvd.NvdProvider(session=session, api_key="SECRET")
    headers = provider._headers()
    assert headers["apiKey"] == "SECRET"
    # The key is not part of the request params (which could be logged).
    list(provider.fetch(modified_since=None, full=True))
    for req in session.requests:
        assert "SECRET" not in str(req)
