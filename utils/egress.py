"""Shared SSRF egress guard for outbound HTTP to attacker-influenced URLs.

Invariant: a URL is only fetched when every address its hostname resolves to
is a public, routable unicast address. Private/loopback/link-local/reserved/
multicast/unspecified/unique-local targets — and the cloud metadata IP — are
refused, so a crawler- or LLM-sourced URL cannot be turned into a read of an
internal service.

Residual: ``assert_public_http_url`` validates the name it resolves, but the
socket the subsequent request opens re-resolves independently — a DNS-rebinding
TOCTOU. Closing it fully requires pinning the resolved IP into the connection
(a custom adapter), which is out of scope here; ``safe_get`` narrows the window
by re-validating every redirect hop rather than delegating redirect-following
to requests.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_METADATA_IP = ipaddress.ip_address("169.254.169.254")
_MAX_REDIRECT_HOPS = 5


class UnsafeUrlError(ValueError):
    """Raised when a URL is not a public HTTP(S) target safe to fetch."""


def _unwrap_ipv6(ip: IPAddress) -> IPAddress:
    """Reduce IPv4-mapped/compat IPv6 (``::ffff:x``, ``::x``) to the IPv4 it
    embeds, so an address that is private in v4 is classified as private and
    not smuggled past the checks in a v6 wrapper."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is not None:
            return embedded
    return ip


def _is_forbidden(ip: IPAddress) -> bool:
    ip = _unwrap_ipv6(ip)
    if ip == _METADATA_IP:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True
    # is_private already covers IPv6 unique-local (fc00::/7); named for intent.
    return bool(getattr(ip, "is_site_local", False))


def assert_public_http_url(url: str) -> str:
    """Return *url* unchanged if it is an http(s) URL whose host resolves
    exclusively to public unicast addresses; raise ``UnsafeUrlError`` otherwise."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"scheme {parsed.scheme!r} not allowed")
    host = parsed.hostname
    if not host:
        raise UnsafeUrlError("URL has no host")

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


def safe_get(url: str, *, timeout, **kw) -> requests.Response:
    """``requests.get`` that validates the target — and every redirect hop —
    against ``assert_public_http_url`` before connecting.

    Redirects are followed manually (``allow_redirects=False``) so the
    ``Location`` of each hop is re-validated; this closes redirect-to-internal
    (DNS-rebinding-via-redirect), which delegating to requests would not.
    """
    kw.pop("allow_redirects", None)
    current = assert_public_http_url(url)
    for _ in range(_MAX_REDIRECT_HOPS + 1):
        resp = requests.get(current, allow_redirects=False, timeout=timeout, **kw)
        if not resp.is_redirect and not resp.is_permanent_redirect:
            return resp
        location = resp.headers.get("Location")
        if not location:
            return resp
        current = assert_public_http_url(urljoin(current, location))
    raise UnsafeUrlError(f"too many redirects (>{_MAX_REDIRECT_HOPS})")
