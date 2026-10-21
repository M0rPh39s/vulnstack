"""Shared pytest fixtures and helpers.

Tests never touch the real network or the user's real database: every test
uses a temporary SQLite file and mocked HTTP/provider responses.
"""

from __future__ import annotations

import pytest

from vulnstack.cve.database import Database
from vulnstack.cve.models import AffectedProduct, Reference, Vulnerability, VersionRange
from vulnstack.http_client import HttpResponse


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Fail loudly if any test tries to open a real socket connection."""
    import socket

    def blocked(self, *args, **kwargs):
        raise AssertionError(f"test attempted a real network connection: {args!r}")

    monkeypatch.setattr(socket.socket, "connect", blocked)


@pytest.fixture
def tmp_db(tmp_path):
    db = Database(tmp_path / "test.db")
    db.initialize()
    yield db
    db.close()


def make_vuln(
    cve_id="CVE-2021-41773",
    *,
    cpe_vendor="apache",
    cpe_product="http_server",
    version=None,
    ranges=None,
    severity="HIGH",
    score=7.5,
    description="Path traversal in Apache HTTP Server.",
    source="nvd",
):
    product = AffectedProduct(
        vendor=cpe_vendor,
        product=cpe_product,
        cpe_vendor=cpe_vendor,
        cpe_product=cpe_product,
        cpe23=f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{version or '*'}:*:*:*:*:*:*:*",
        version=version,
        ranges=ranges or [],
    )
    return Vulnerability(
        cve_id=cve_id,
        description=description,
        published="2021-10-05T00:00:00",
        last_modified="2021-11-01T00:00:00",
        cvss_score=score,
        cvss_version="3.1",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        severity=severity,
        status="Analyzed",
        source=source,
        weaknesses=["CWE-22"],
        references=[Reference(url="https://httpd.apache.org/security/vulnerabilities_24.html", ref_type="Vendor")],
        affected=[product],
    )


@pytest.fixture
def seeded_db(tmp_db):
    """A database with a handful of realistic records for search tests."""
    vulns = [
        # Apache exact-version CVE (2.4.49).
        make_vuln("CVE-2021-41773", version="2.4.49"),
        # Apache range CVE: >=2.4.0 <2.4.52
        make_vuln(
            "CVE-2021-44790",
            version=None,
            ranges=[VersionRange(version_start="2.4.0", version_start_type="including",
                                 version_end="2.4.52", version_end_type="excluding")],
            severity="CRITICAL", score=9.8,
            description="Buffer overflow in mod_lua of Apache HTTP Server.",
        ),
        # nginx range CVE: <1.21.0
        make_vuln(
            "CVE-2021-23017", cpe_vendor="nginx", cpe_product="nginx",
            ranges=[VersionRange(version_end="1.21.0", version_end_type="excluding")],
            severity="HIGH", score=7.7,
            description="Off-by-one in nginx resolver.",
        ),
        # WordPress CVE with no version data (product-only).
        make_vuln(
            "CVE-2022-00001", cpe_vendor="wordpress", cpe_product="wordpress",
            version=None, ranges=[], severity=None, score=None,
            description="Example WordPress issue with no version range.",
        ),
    ]
    tmp_db.upsert_vulnerabilities(vulns)
    return tmp_db


def make_response(
    *,
    url="https://example.com/",
    status=200,
    headers=None,
    body="",
):
    return HttpResponse(
        url=url,
        status_code=status,
        headers=headers or {},
        text=body,
        content_length=len(body.encode("utf-8")),
    )
