import socket

import pytest

from vulnstack import http_client
from vulnstack.http_client import (
    HttpError,
    HttpResponse,
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


# ---- multi-address handling (IPv6/IPv4 fallback) ---------------------------

def test_validate_orders_ipv4_before_ipv6(monkeypatch):
    from vulnstack import http_client
    monkeypatch.setattr(http_client, "_resolve", lambda host: ["2606:4700::1111", "1.1.1.1", "8.8.8.8"])
    host, ips = http_client.validate_url_all("https://example.com/")
    assert ips == ["1.1.1.1", "8.8.8.8", "2606:4700::1111"]
    assert http_client.validate_url("https://example.com/") == ("example.com", "1.1.1.1")


@pytest.mark.parametrize("resolved", [
    ["8.8.8.8", "10.0.0.5"],            # public first, private second
    ["2606:4700::1111", "127.0.0.1"],
    ["1.1.1.1", "::1"],
    ["1.1.1.1", "169.254.169.254"],
])
def test_any_blocked_address_refuses_the_whole_host(monkeypatch, resolved):
    from vulnstack import http_client
    monkeypatch.setattr(http_client, "_resolve", lambda host: resolved)
    with pytest.raises(ScanSafetyError):
        http_client.validate_url_all("https://example.com/")


def _client_with_ips(monkeypatch, ips, single_get):
    from vulnstack import http_client
    monkeypatch.setattr(http_client, "validate_url_all", lambda url, allow_private=False: ("example.com", ips))
    client = SafeHttpClient()
    monkeypatch.setattr(client, "_single_get", single_get)
    return client


def test_falls_back_to_next_validated_ip_on_connect_failure(monkeypatch):
    from vulnstack.http_client import HttpConnectError
    tried = []

    def single_get(url, host, ip):
        tried.append(ip)
        if ":" in ip:
            raise HttpConnectError("Network is unreachable")
        return HttpResponse(url=url, status_code=200, headers={}, text="ok", content_length=2)

    client = _client_with_ips(monkeypatch, ["2606:4700::1111", "1.1.1.1"], single_get)
    assert client.get("https://example.com/").text == "ok"
    assert tried == ["2606:4700::1111", "1.1.1.1"]


def test_all_addresses_unreachable_raises_last_connect_error(monkeypatch):
    from vulnstack.http_client import HttpConnectError

    def single_get(url, host, ip):
        raise HttpConnectError(f"no route to {ip}")

    client = _client_with_ips(monkeypatch, ["1.1.1.1", "8.8.8.8"], single_get)
    with pytest.raises(HttpConnectError, match="8.8.8.8"):
        client.get("https://example.com/")


def test_non_connect_errors_do_not_fall_through(monkeypatch):
    tried = []

    def single_get(url, host, ip):
        tried.append(ip)
        raise HttpError("TLS verification failed")

    client = _client_with_ips(monkeypatch, ["1.1.1.1", "8.8.8.8"], single_get)
    with pytest.raises(HttpError, match="TLS"):
        client.get("https://example.com/")
    assert tried == ["1.1.1.1"]  # a TLS failure is never retried on another address


def test_requests_connection_errors_map_to_connect_error(monkeypatch):
    import requests
    from vulnstack.http_client import HttpConnectError

    def boom(self, *a, **k):
        raise requests.exceptions.ConnectionError("Network is unreachable")

    monkeypatch.setattr(requests.Session, "get", boom)
    with pytest.raises(HttpConnectError):
        SafeHttpClient()._single_get("https://example.com/", "example.com", "1.1.1.1")


def test_connect_timeout_maps_to_connect_error_but_read_timeout_does_not(monkeypatch):
    import requests
    from vulnstack.http_client import HttpConnectError

    def make(exc):
        def boom(self, *a, **k):
            raise exc
        return boom

    monkeypatch.setattr(requests.Session, "get", make(requests.exceptions.ConnectTimeout("t")))
    with pytest.raises(HttpConnectError):
        SafeHttpClient()._single_get("https://example.com/", "example.com", "1.1.1.1")

    monkeypatch.setattr(requests.Session, "get", make(requests.exceptions.ReadTimeout("t")))
    with pytest.raises(HttpError) as ei:
        SafeHttpClient()._single_get("https://example.com/", "example.com", "1.1.1.1")
    assert not isinstance(ei.value, HttpConnectError)


def test_tls_errors_stay_plain_http_errors(monkeypatch):
    import requests
    from vulnstack.http_client import HttpConnectError

    def boom(self, *a, **k):
        raise requests.exceptions.SSLError("certificate verify failed")

    monkeypatch.setattr(requests.Session, "get", boom)
    with pytest.raises(HttpError, match="TLS verification failed") as ei:
        SafeHttpClient()._single_get("https://example.com/", "example.com", "1.1.1.1")
    assert not isinstance(ei.value, HttpConnectError)


def test_tls_verification_is_on_by_default():
    assert SafeHttpClient().verify_tls is True
