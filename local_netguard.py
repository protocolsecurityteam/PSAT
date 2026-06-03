"""LOCAL-ONLY pytest plugin — proves/maps real network egress from the suite.

Load with ``-p local_netguard``. Wraps ``socket.getaddrinfo`` (to learn the
hostname behind each IP) and ``socket.socket.connect`` / ``connect_ex`` (to
BLOCK connects to globally-routable / public IPs). Loopback, private and
link-local stay allowed, so Postgres, MinIO and docker networking are untouched;
only the public internet — where the paid APIs live — is fenced off.

On a blocked connect it records ``(test nodeid, hostname, port)`` and, at session
end, prints a per-host summary with the test files that reached it. A clean run
(``OK``) means every external call was mocked and nothing reached a real
endpoint. psycopg2 uses libpq (C) and bypasses Python's socket layer, so the DB
never trips this; requests/httpx/urllib3/boto3 do, which is the surface we map.

Committed: this is the offline suite's socket-level egress backstop, loaded via
``-p local_netguard`` by ``run_tests_fast.sh`` and the CI offline job
(``.github/workflows/_ci-checks.yml``). It complements the in-process guard in
``tests/conftest.py`` (which fences the ``requests``/``urllib`` wires with clearer
errors); this one catches anything that bypasses them. A blocked connect fails
the session, so a leak can't pass silently on a degraded path.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
from collections import defaultdict

_blocked: list[tuple[str, str, int]] = []  # (nodeid, host, port)
_ip_to_host: dict[str, str] = {}
_current = {"nodeid": "<import/collection>"}

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_getaddrinfo = socket.getaddrinfo


def _gai(host, *args, **kwargs):
    res = _real_getaddrinfo(host, *args, **kwargs)
    if isinstance(host, str):
        for _fam, _typ, _proto, _canon, sockaddr in res:
            if sockaddr and isinstance(sockaddr[0], str):
                _ip_to_host.setdefault(sockaddr[0], host)
    return res


socket.getaddrinfo = _gai


def _external_ip(address):
    try:
        ip = ipaddress.ip_address(address[0])
    except (TypeError, IndexError, ValueError):
        return None
    return ip if ip.is_global else None


def _wrap(real):
    def connect(self, address, *args, **kwargs):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            ip = _external_ip(address)
            if ip is not None:
                host = _ip_to_host.get(str(ip), str(ip))
                port = address[1] if len(address) > 1 else -1
                _blocked.append((_current["nodeid"], host, port))
                raise RuntimeError(f"[netguard] BLOCKED {_current['nodeid']} -> {host}:{port}")
        return real(self, address, *args, **kwargs)

    return connect


socket.socket.connect = _wrap(_real_connect)
socket.socket.connect_ex = _wrap(_real_connect_ex)


def pytest_runtest_logstart(nodeid, location):
    _current["nodeid"] = nodeid


def pytest_sessionfinish(session, exitstatus):
    worker = getattr(session.config, "workerinput", None)
    tag = worker["workerid"] if worker else "main"
    if not _blocked:
        print(f"\n[netguard:{tag}] OK — no external (public-IP) connects attempted", file=sys.stderr)
        return
    by_host: dict[str, set[str]] = defaultdict(set)
    for nodeid, host, port in _blocked:
        by_host[f"{host}:{port}"].add(nodeid.split("::")[0])
    print(f"\n[netguard:{tag}] {len(_blocked)} external connect(s) to {len(by_host)} host(s):", file=sys.stderr)
    for hp in sorted(by_host):
        for f in sorted(by_host[hp]):
            print(f"[netguard:{tag}] {hp} <= {f}", file=sys.stderr)
    # Fail the session on any external connect — a test that swallows the blocked
    # connect on a degraded path still passes, so the per-test result alone won't
    # catch the leak. Under xdist this runs per-worker (the report above is the
    # signal there); the CI offline job runs serially, so this gates the build.
    if session.exitstatus == 0:
        session.exitstatus = 1
