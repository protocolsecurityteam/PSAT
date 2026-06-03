"""Self-tests for the offline network guard installed by ``tests/conftest.py``.

The guard blocks any attempt to reach an external host over ``requests`` or
``urllib.request`` so the offline suite never makes a real external call. These
exercise the block path directly and pin the loopback/private host policy.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest
import requests

from tests.conftest import _host_is_local

# `.invalid` never resolves, so even a regressed guard can't make a real connect.
_PROBE = "https://offline-guard-probe.invalid/x"


def test_external_requests_call_is_blocked():
    with pytest.raises(requests.exceptions.ConnectionError, match="offline-guard"):
        requests.get(_PROBE, timeout=1)


def test_external_urlopen_is_blocked():
    with pytest.raises(urllib.error.URLError, match="offline-guard"):
        urllib.request.urlopen(_PROBE, timeout=1)


@pytest.mark.parametrize("host", ["localhost", "svc.local", "127.0.0.1", "::1", "10.0.0.5", "192.168.1.1"])
def test_local_hosts_allowed(host):
    assert _host_is_local(host) is True


@pytest.mark.parametrize("host", ["api.github.com", "8.8.8.8", "openrouter.ai", "", None])
def test_external_hosts_blocked(host):
    assert _host_is_local(host) is False
