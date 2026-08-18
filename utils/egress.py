"""Shared SSRF egress guard for outbound HTTP to attacker-influenced URLs.

Invariant: a URL is only fetched when every address its hostname resolves to
is a globally-routable public unicast address. Classification is an allowlist
(``ip.is_global``), which refuses private/loopback/link-local/reserved/
multicast/unspecified/unique-local ranges AND non-global unicast the denylist
form would miss — RFC 6598 CGNAT (100.64.0.0/10, e.g. Alibaba metadata and k8s
NAT fabrics). The cloud metadata IP keeps an explicit guard as belt-and-suspenders.
So a crawler- or LLM-sourced URL cannot be turned into a read of an internal service.

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
from urllib3.util import parse_url

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_METADATA_IP = ipaddress.ip_address("169.254.169.254")
_MAX_REDIRECT_HOPS = 5
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


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
    # Allowlist: only globally-routable unicast passes. Subsumes private,
    # loopback, link-local, CGNAT (100.64/10), reserved, multicast, ULA, and
    # any future non-global range a denylist would forget.
    return not ip.is_global


def connect_host(url: str) -> str:
    """The bare host the HTTP client will actually open a socket to.

    ``urlparse`` and urllib3 disagree on where the authority ends — a backslash
    is userinfo to ``urlparse`` but an authority terminator to urllib3, the parser
    ``requests`` connects with. Deriving the guarded host from ``urlparse().hostname``
    therefore validates a *different* host than the one dialed, an SSRF bypass
    (``http://169.254.169.254\\@example.com/`` guards ``example.com``, dials the
    metadata IP). Every host gate derives its host from here so all three agree
    with the client. Raises ``UnsafeUrlError`` for a disallowed scheme, a backslash
    in the authority, or an authority/port urllib3 cannot parse — the last so a
    malformed port surfaces as ``UnsafeUrlError``, not a bare ``ValueError`` that
    ``UnsafeUrlError``-only callers turn into a 500.
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
    # urllib3 keeps IPv6 literals bracketed; ``ipaddress.ip_address`` wants them bare.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def assert_public_http_url(url: str) -> str:
    """Return *url* unchanged if it is an http(s) URL whose host resolves
    exclusively to public unicast addresses; raise ``UnsafeUrlError`` otherwise."""
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
    """``requests.get`` that validates the target — and every redirect hop —
    against ``assert_public_http_url`` before connecting.

    Redirects are followed manually (``allow_redirects=False``) so the
    ``Location`` of each hop is re-validated; this closes redirect-to-internal
    (DNS-rebinding-via-redirect), which delegating to requests would not. Any
    ``**kw`` (e.g. ``stream=True``, ``headers=...``) and a tuple ``timeout``
    pass straight through, so streamed downloads route through here too.

    An optional ``session`` reuses a caller's connection pool; the returned
    (final, non-redirect) response is unread when ``stream=True``.
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
