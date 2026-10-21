"""Safe HTTP client used for fingerprinting targets.

Security model (documented in README "Security considerations"):

* Only ``http`` and ``https`` schemes are accepted.
* Every destination hostname is resolved and *all* resolved IP addresses are
  validated against a blocklist of loopback / private / link-local / reserved
  ranges before any socket is opened. This blocks SSRF to internal services.
* Redirects are followed manually; each hop's destination is re-validated with
  the same rules, so a redirect cannot escape the IP policy, and the redirect
  count is bounded.
* To defeat DNS-rebinding and validation-to-connection races, the request is
  pinned to the exact IP address that was validated: for the duration of a
  single request we force name resolution for that host to the vetted IP, so
  the kernel never re-resolves the name to a different (internal) address at
  connect time. The hostname is still used for TLS SNI and the Host header.
* TLS certificate verification is always on and never disabled automatically.
* Connection and read timeouts are always set; the response body is read
  incrementally and capped, so an oversized body cannot exhaust memory.
* No cookies are persisted or sent; credentials are never forwarded across
  origins; ambient HTTP proxy environment variables are ignored for targets.

This module performs the *minimum* number of requests needed to fingerprint a
site and never executes downloaded JavaScript or other content.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from vulnstack.logging_config import get_logger

log = get_logger("http")

ALLOWED_SCHEMES = ("http", "https")
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class ScanSafetyError(Exception):
    """Raised when a target or redirect violates the network-safety policy."""


class HttpError(Exception):
    """Raised for network/HTTP failures during a scan."""


class HttpConnectError(HttpError):
    """TCP connect failed for one pinned address (another may still work)."""


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    content_length: int
    history: list[str] = field(default_factory=list)
    truncated: bool = False


def is_public_ip(ip: str) -> bool:
    """Return True only for globally routable, non-reserved public addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        # IPv4-mapped / 6to4 IPv6 can smuggle private v4 addresses.
        if addr.ipv4_mapped is not None:
            return is_public_ip(str(addr.ipv4_mapped))
        if addr.sixtofour is not None:
            return is_public_ip(str(addr.sixtofour))
    return True


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScanSafetyError(f"could not resolve host {host!r}: {exc}") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise ScanSafetyError(f"no addresses resolved for host {host!r}")
    return ips


def validate_url_all(url: str, *, allow_private: bool = False) -> tuple[str, list[str]]:
    """Validate a URL for scheme, host and resolved-IP safety.

    Returns ``(host, ips)`` where *every* address is validated and IPv4
    addresses come first. Raises :class:`ScanSafetyError` on any policy
    violation. All resolved addresses must be allowed — a host that resolves
    to even one blocked address is refused.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ScanSafetyError(
            f"unsupported URL scheme {parsed.scheme!r}; only http/https are allowed"
        )
    if not parsed.hostname:
        raise ScanSafetyError("URL has no host component")
    host = parsed.hostname

    try:
        ipaddress.ip_address(host)
        candidate_ips = [host]
    except ValueError:
        candidate_ips = _resolve(host)

    candidate_ips = sorted(candidate_ips, key=lambda ip: (":" in ip, ip))
    if allow_private:
        return host, candidate_ips

    safe_ips = [ip for ip in candidate_ips if is_public_ip(ip)]
    if not safe_ips:
        raise ScanSafetyError(
            f"host {host!r} resolves only to blocked addresses "
            f"({', '.join(candidate_ips)}); refusing to connect"
        )
    if len(safe_ips) != len(candidate_ips):
        blocked = set(candidate_ips) - set(safe_ips)
        raise ScanSafetyError(
            f"host {host!r} resolves to both public and blocked addresses "
            f"({', '.join(sorted(blocked))}); refusing to connect (possible DNS rebinding)"
        )
    return host, safe_ips


def validate_url(url: str, *, allow_private: bool = False) -> tuple[str, str]:
    """Like :func:`validate_url_all` but returns the preferred single address."""
    host, ips = validate_url_all(url, allow_private=allow_private)
    return host, ips[0]


_resolver_lock = threading.Lock()


@contextmanager
def _pin_host(host: str, ip: str):
    """Pin ``host`` to ``ip`` for the lifetime of the block.

    Replaces ``socket.getaddrinfo`` so that any lookup of ``host`` returns the
    validated IP. All other hostnames resolve normally. Guarded by a lock so a
    single client performs requests sequentially with respect to pinning.
    """
    with _resolver_lock:
        original = socket.getaddrinfo

        def patched(node, port, family=0, type=0, proto=0, flags=0):
            if node == host:
                return original(ip, port, family, type, proto, flags)
            return original(node, port, family, type, proto, flags)

        socket.getaddrinfo = patched  # type: ignore[assignment]
        try:
            yield
        finally:
            socket.getaddrinfo = original  # type: ignore[assignment]


class SafeHttpClient:
    def __init__(
        self,
        *,
        timeout: float = 15.0,
        max_redirects: int = 5,
        max_response_bytes: int = 5 * 1024 * 1024,
        user_agent: str = "VulnStack/0.1",
        allow_private: bool = False,
        verify_tls: bool = True,
    ) -> None:
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.user_agent = user_agent
        self.allow_private = allow_private
        self.verify_tls = verify_tls

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        }

    def get(self, url: str) -> HttpResponse:
        """Perform a safe GET with manual, validated redirect handling."""
        history: list[str] = []
        current = url
        for hop in range(self.max_redirects + 1):
            host, ips = validate_url_all(current, allow_private=self.allow_private)
            resp = self._get_first_reachable(current, host, ips)
            if resp.status_code in _REDIRECT_STATUSES:
                location = resp.headers.get("Location")
                if not location:
                    resp.history = history
                    return resp
                nxt = urljoin(current, location)
                parsed = urlparse(nxt)
                if parsed.scheme.lower() not in ALLOWED_SCHEMES:
                    raise ScanSafetyError(
                        f"redirect to unsupported scheme {parsed.scheme!r} blocked"
                    )
                if hop == self.max_redirects:
                    raise HttpError(f"exceeded maximum of {self.max_redirects} redirects")
                history.append(current)
                current = urlunparse(parsed)
                continue
            resp.history = history
            return resp
        raise HttpError("redirect handling terminated unexpectedly")

    def _get_first_reachable(self, url: str, host: str, ips: list[str]) -> HttpResponse:
        """Try each already-validated address until one accepts a connection.

        Only connection-level failures fall through to the next address (e.g.
        an IPv6 address on a host with no IPv6 route). TLS, timeout-after-
        connect and HTTP errors are reported immediately, and no address
        outside the validated set is ever used.
        """
        last: HttpConnectError | None = None
        for ip in ips:
            try:
                return self._single_get(url, host, ip)
            except HttpConnectError as exc:
                log.debug("connect to %s (%s) failed: %s", host, ip, exc)
                last = exc
        assert last is not None
        raise last

    def _single_get(self, url: str, host: str, pinned_ip: str) -> HttpResponse:
        session = requests.Session()
        session.trust_env = False  # ignore ambient proxy / netrc for targets
        session.max_redirects = 0
        try:
            with _pin_host(host, pinned_ip):
                resp = session.get(
                    url,
                    headers=self._headers(),
                    timeout=(self.timeout, self.timeout),
                    allow_redirects=False,
                    verify=self.verify_tls,
                    stream=True,
                )
                raw = bytearray()
                truncated = False
                for chunk in resp.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    raw.extend(chunk)
                    if len(raw) >= self.max_response_bytes:
                        truncated = True
                        break
        except requests.exceptions.SSLError as exc:
            raise HttpError(f"TLS verification failed for {url}: {exc}") from exc
        except requests.exceptions.ConnectTimeout as exc:
            raise HttpConnectError(f"connecting to {url} timed out after {self.timeout}s") from exc
        except requests.exceptions.Timeout as exc:
            raise HttpError(f"request to {url} timed out after {self.timeout}s") from exc
        except requests.exceptions.ConnectionError as exc:
            raise HttpConnectError(f"request to {url} failed: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise HttpError(f"request to {url} failed: {exc}") from exc

        try:
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            try:
                text = bytes(raw[: self.max_response_bytes]).decode(encoding, errors="replace")
            except (LookupError, TypeError):
                text = bytes(raw[: self.max_response_bytes]).decode("utf-8", errors="replace")
            return HttpResponse(
                url=url,
                status_code=resp.status_code,
                headers={k: v for k, v in resp.headers.items()},
                text=text,
                content_length=len(raw),
                truncated=truncated,
            )
        finally:
            resp.close()
            session.close()
