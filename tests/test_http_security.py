import socket

import pytest

from vulnstack import http_client
from vulnstack.http_client import (
    HttpError,
    SafeHttpClient,
    ScanSafetyError,
    is_public_ip,
    validate_url,
)


@pytest.mark.parametrize("scheme", ["ftp://example.com", "file:///etc/passwd", "gopher://x", "javascript:alert(1)"])
def test_unsupported_schemes_rejected(scheme):
    with pytest.raises(ScanSafetyError):
        validate_url(scheme)


def test_malformed_url_rejected():
    with pytest.raises(ScanSafetyError):
        validate_url("http://")
    with pytest.raises(ScanSafetyError):
        validate_url("not a url")


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.1", "192.168.1.10", "172.16.5.5",
    "169.254.1.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "224.0.0.1",
])
def test_blocked_literal_ips(ip):
    url = f"http://[{ip}]/" if ":" in ip else f"http://{ip}/"
    with pytest.raises(ScanSafetyError):
        validate_url(url)


def test_public_literal_ip_allowed():
    host, pinned = validate_url("http://8.8.8.8/")
    assert pinned == "8.8.8.8"


def test_ipv4_mapped_ipv6_blocked():
    assert is_public_ip("::ffff:127.0.0.1") is False
    assert is_public_ip("::ffff:10.0.0.1") is False


def test_hostname_resolving_to_private_blocked(monkeypatch):
    def fake_getaddrinfo(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
    monkeypatch.setattr(http_client.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ScanSafetyError):
        validate_url("http://internal.example.com/")


def test_hostname_mixed_public_private_blocked(monkeypatch):
    def fake_getaddrinfo(host, *a, **k):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]
    monkeypatch.setattr(http_client.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ScanSafetyError):
        validate_url("http://rebind.example.com/")


def test_allow_private_bypass():
    host, pinned = validate_url("http://127.0.0.1/", allow_private=True)
    assert pinned == "127.0.0.1"


def test_redirect_to_blocked_host_rejected(monkeypatch):
    def fake_getaddrinfo(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
    monkeypatch.setattr(http_client.socket, "getaddrinfo", fake_getaddrinfo)

    client = SafeHttpClient()

    def fake_single_get(url, host, pinned_ip):
        return http_client.HttpResponse(
            url=url, status_code=302,
            headers={"Location": "http://127.0.0.1/admin"},
            text="", content_length=0,
        )
    monkeypatch.setattr(client, "_single_get", fake_single_get)
    with pytest.raises(ScanSafetyError):
        client.get("http://public.example.com/")


def test_redirect_to_unsupported_scheme_rejected(monkeypatch):
    def fake_getaddrinfo(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
    monkeypatch.setattr(http_client.socket, "getaddrinfo", fake_getaddrinfo)
    client = SafeHttpClient()

    def fake_single_get(url, host, pinned_ip):
        return http_client.HttpResponse(
            url=url, status_code=302,
            headers={"Location": "file:///etc/passwd"},
            text="", content_length=0,
        )
    monkeypatch.setattr(client, "_single_get", fake_single_get)
    with pytest.raises(ScanSafetyError):
        client.get("http://public.example.com/")


def test_redirect_limit(monkeypatch):
    def fake_getaddrinfo(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
    monkeypatch.setattr(http_client.socket, "getaddrinfo", fake_getaddrinfo)
    client = SafeHttpClient(max_redirects=2)

    def fake_single_get(url, host, pinned_ip):
        return http_client.HttpResponse(
            url=url, status_code=302,
            headers={"Location": "http://public.example.com/next"},
            text="", content_length=0,
        )
    monkeypatch.setattr(client, "_single_get", fake_single_get)
    with pytest.raises(HttpError):
        client.get("http://public.example.com/")


class _FakeRequestsResp:
    def __init__(self, chunks, headers, status=200):
        self._chunks = chunks
        self.headers = headers
        self.status_code = status
        self.encoding = "utf-8"
        self.apparent_encoding = "utf-8"

    def iter_content(self, chunk_size=16384):
        yield from self._chunks

    def close(self):
        pass


def test_response_truncation(monkeypatch):
    def fake_getaddrinfo(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
    monkeypatch.setattr(http_client.socket, "getaddrinfo", fake_getaddrinfo)

    big = [b"A" * 1000 for _ in range(10)]  # 10 KB total

    def fake_get(self, url, **kwargs):
        return _FakeRequestsResp(big, {"Server": "nginx/1.18.0"})

    monkeypatch.setattr(http_client.requests.Session, "get", fake_get)
    client = SafeHttpClient(max_response_bytes=2048)
    resp = client.get("http://public.example.com/")
    assert resp.truncated is True
    assert len(resp.text) <= 2048
    assert resp.headers["Server"] == "nginx/1.18.0"
