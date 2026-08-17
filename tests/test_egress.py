"""Unit tests for the SSRF egress guard (``utils.egress``).

Pure: ``socket.getaddrinfo`` and ``requests.get`` are stubbed so no network
is touched and resolution is deterministic.
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from utils.egress import UnsafeUrlError, assert_public_http_url, safe_get


def _addrinfo(ip: str):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0))]


@pytest.mark.parametrize(
    "url,ip",
    [
        ("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
        ("http://metadata.internal/", "169.254.169.254"),
        ("http://localhost/", "127.0.0.1"),
        ("http://internal.example.com/", "10.0.0.5"),
        ("http://intranet/", "192.168.1.10"),
        ("http://six/", "::1"),
        ("http://mapped/", "::ffff:127.0.0.1"),
        ("http://mapped2/", "::ffff:10.0.0.5"),
        ("http://uniquelocal/", "fd00::1"),
        # RFC 6598 CGNAT (100.64.0.0/10): Alibaba metadata, k8s NAT fabrics.
        # Python tags it neither is_private nor is_global, so the is_global
        # allowlist is what refuses it.
        ("http://cgnat-metadata/", "100.100.100.200"),
        ("http://cgnat-low/", "100.64.0.1"),
    ],
)
def test_rejects_non_public_addresses(url, ip):
    with patch("socket.getaddrinfo", return_value=_addrinfo(ip)):
        with pytest.raises(UnsafeUrlError):
            assert_public_http_url(url)


@pytest.mark.parametrize(
    "host,resolved",
    [
        # Decimal (2130706433) and hex (0x7f000001) integer spellings of
        # 127.0.0.1: the guard classifies on the RESOLVED address, so however
        # the literal is spelled it resolves to loopback and is refused. Pins
        # that a refactor can't start deciding on the textual host instead.
        ("2130706433", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
    ],
)
def test_rejects_alternate_ip_literal_encodings(host, resolved):
    with patch("socket.getaddrinfo", return_value=_addrinfo(resolved)):
        with pytest.raises(UnsafeUrlError):
            assert_public_http_url(f"http://{host}/")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x/", "javascript:alert(1)", "ftp://host/"])
def test_rejects_non_http_schemes(url):
    with pytest.raises(UnsafeUrlError):
        assert_public_http_url(url)


def test_accepts_public_host():
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        assert assert_public_http_url("https://example.com/x.pdf") == "https://example.com/x.pdf"


def test_rejects_when_any_resolved_address_is_private():
    infos = _addrinfo("93.184.216.34") + _addrinfo("10.0.0.5")
    with patch("socket.getaddrinfo", return_value=infos):
        with pytest.raises(UnsafeUrlError):
            assert_public_http_url("https://rebind.example/")


def test_rejects_unresolvable_host():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
        with pytest.raises(UnsafeUrlError):
            assert_public_http_url("https://does-not-resolve.example/")


class _FakeResp:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}

    def close(self):
        self.closed = True


def test_safe_get_returns_non_redirect():
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        with patch("requests.get", return_value=_FakeResp(200)) as mock_get:
            resp = safe_get("https://example.com/", timeout=5)
    assert resp.status_code == 200
    # allow_redirects is forced off — redirects are followed manually.
    assert mock_get.call_args.kwargs["allow_redirects"] is False


def test_safe_get_refuses_redirect_to_internal_host():
    # First hop resolves public and returns a redirect to an internal host;
    # the redirect target must be re-validated and rejected.
    resolutions = {"example.com": "93.184.216.34", "internal.local": "169.254.169.254"}

    def fake_getaddrinfo(host, *a, **k):
        return _addrinfo(resolutions[host])

    redirect = _FakeResp(302, {"Location": "http://internal.local/steal"})
    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        with patch("requests.get", return_value=redirect):
            with pytest.raises(UnsafeUrlError):
                safe_get("https://example.com/", timeout=5)


def test_safe_get_follows_public_redirect():
    resolutions = {"example.com": "93.184.216.34", "cdn.example": "93.184.216.35"}

    def fake_getaddrinfo(host, *a, **k):
        return _addrinfo(resolutions[host])

    responses = [
        _FakeResp(302, {"Location": "https://cdn.example/final"}),
        _FakeResp(200),
    ]
    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        with patch("requests.get", side_effect=responses):
            resp = safe_get("https://example.com/", timeout=5)
    assert resp.status_code == 200


def test_safe_get_uses_injected_session_and_refuses_redirect():
    # An injected session is used for the connection, and a redirect to an
    # internal host is still re-validated and refused rather than followed.
    resolutions = {"example.com": "93.184.216.34", "internal.local": "169.254.169.254"}

    def fake_getaddrinfo(host, *a, **k):
        return _addrinfo(resolutions[host])

    session = MagicMock()
    session.get.return_value = _FakeResp(302, {"Location": "http://internal.local/steal"})
    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        with pytest.raises(UnsafeUrlError):
            safe_get("https://example.com/", timeout=5, session=session)
    # Only the first (public) hop was fetched; the internal target never was.
    assert session.get.call_count == 1


def test_download_audit_body_refuses_redirect_to_internal():
    # End-to-end on the text-extraction path: a discovery-sourced URL that
    # 302s to the metadata IP must be refused, not stored/served.
    from services.audits.text_extraction import PdfDownloadError, download_audit_body

    resolutions = {"example.com": "93.184.216.34", "internal.local": "169.254.169.254"}

    def fake_getaddrinfo(host, *a, **k):
        return _addrinfo(resolutions[host])

    session = MagicMock()
    session.get.return_value = _FakeResp(302, {"Location": "http://internal.local/latest/meta-data/"})
    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        with pytest.raises(PdfDownloadError, match="non-public"):
            download_audit_body("https://example.com/audit.md", session=session, kind="text")
    # The internal redirect target was never fetched for its body.
    assert session.get.call_count == 1
