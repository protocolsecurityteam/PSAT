"""SSRF guard for outbound HTTP to attacker-influenced URLs.

A URL is fetched only if every resolved address is ``ip.is_global`` (an allowlist, so CGNAT and future non-global ranges
are refused too).

Residual: the request re-resolves DNS independently (rebinding TOCTOU). Closing it needs IP pinning; ``safe_get``
narrows it by re-validating each redirect hop.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
from urllib3.util import parse_url

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_METADATA_IP = ipaddress.ip_address("169.254.169.254")
_MAX_REDIRECT_HOPS = 5
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


class UnsafeUrlError(ValueError): ...


def _unwrap_ipv6(ip: IPAddress) -> IPAddress:
    """Reduce IPv4-mapped/compat IPv6 to its IPv4 so a private v4 can't hide in a v6 wrapper."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is not None:
            return embedded
    return ip


def _is_forbidden(ip: IPAddress) -> bool:
    ip = _unwrap_ipv6(ip)
    if ip == _METADATA_IP:
        return True
    return not ip.is_global


def connect_host(url: str) -> str:
    """The host the HTTP client will actually dial.

    ``urlparse`` and urllib3 disagree on authority ends (a backslash): ``http://169.254.169.254\\@example.com/`` guards
    ``example.com`` but dials the metadata IP. Parse failures raise ``UnsafeUrlError`` so callers don't turn a bad port
    into a 500.
    """
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"scheme {parsed.scheme!r} not allowed")
    if "\\" in parsed.netloc:
        raise UnsafeUrlError("URL authority contains a backslash")
    try:
        host = parse_url(url).host
    except ValueError as exc:  # LocationParseError (port out of range, bad authority) subclasses this
        raise UnsafeUrlError(f"cannot parse URL authority: {exc}") from exc
    if not host:
        raise UnsafeUrlError("URL has no host")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def assert_public_http_url(url: str) -> str:
    host = connect_host(url)
    parsed = urlparse(url)

    try:
        infos = socket.getaddrinfo(host, parsed.port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"cannot resolve host {host!r}: {exc}") from exc

    resolved = {info[4][0] for info in infos}
    if not resolved:
        raise UnsafeUrlError(f"host {host!r} resolved to no addresses")
    for addr in resolved:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise UnsafeUrlError(f"host {host!r} resolved to bad address {addr!r}") from exc
        if _is_forbidden(ip):
            raise UnsafeUrlError(f"host {host!r} resolves to non-public address {addr}")
    return url


def safe_get(
    url: str,
    *,
    timeout,
    session: requests.Session | None = None,
    **kw,
) -> requests.Response:
    """``requests.get`` that validates the target and every redirect hop.

    Redirects are followed manually to close redirect-to-internal.
    """
    getter = session.get if session is not None else requests.get
    kw.pop("allow_redirects", None)
    current = assert_public_http_url(url)
    for _ in range(_MAX_REDIRECT_HOPS + 1):
        resp = getter(current, allow_redirects=False, timeout=timeout, **kw)
        if resp.status_code not in _REDIRECT_STATUS:
            return resp
        location = resp.headers.get("Location")
        if not location:
            return resp
        resp.close()  # release the intermediate hop before following
        current = assert_public_http_url(urljoin(current, location))
    raise UnsafeUrlError(f"too many redirects (>{_MAX_REDIRECT_HOPS})")
