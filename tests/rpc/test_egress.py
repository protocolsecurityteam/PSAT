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
        # CGNAT (Alibaba metadata, k8s NAT) is neither is_private nor is_global in Python; the is_global allowlist
        # refuses it.
        ("http://cgnat-metadata/", "100.100.100.200"),
        ("http://cgnat-low/", "100.64.0.1"),
        # The guard classifies the resolved address, not the textual host.
        ("http://2130706433/", "127.0.0.1"),
        ("http://0x7f000001/", "127.0.0.1"),
    ],
)
def test_rejects_non_public_addresses(url, ip):
    with patch("socket.getaddrinfo", return_value=_addrinfo(ip)):
        with pytest.raises(UnsafeUrlError):
            assert_public_http_url(url)


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
    assert mock_get.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize("injected", [False, True], ids=["module-requests", "injected-session"])
def test_safe_get_refuses_redirect_to_internal_host(injected):
    resolutions = {"example.com": "93.184.216.34", "internal.local": "169.254.169.254"}

    def fake_getaddrinfo(host, *a, **k):
        return _addrinfo(resolutions[host])

    redirect = _FakeResp(302, {"Location": "http://internal.local/steal"})
    session = MagicMock()
    session.get.return_value = redirect
    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        with patch("requests.get", return_value=redirect) as requests_get:
            with pytest.raises(UnsafeUrlError):
                safe_get("https://example.com/", timeout=5, **({"session": session} if injected else {}))
    assert (session.get if injected else requests_get).call_count == 1
