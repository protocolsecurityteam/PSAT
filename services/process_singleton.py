"""Non-expiring PostgreSQL session ownership for process-group handover.

Use a DIRECT database endpoint, never a transaction-pooling proxy. The owning
launcher keeps this connection open until every child is gone. Business work
uses normal short pooled transactions. No lease can expire during a long build.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import psycopg2

KEYS = {"workers": 1, "monitor": 2, "indexer": 3}
NAMESPACE = 0x50534154


class ProcessSingleton:
    def __init__(self, name: str, url: str | None = None):
        url = url or os.environ.get("PSAT_LIFECYCLE_DATABASE_URL")
        if not url or "-pooler" in (urlsplit(url).hostname or ""):
            raise ValueError("PSAT_LIFECYCLE_DATABASE_URL must be an explicit direct PostgreSQL endpoint")
        self.connection = psycopg2.connect(
            url,
            connect_timeout=10,
            application_name=f"psat-singleton-{name}:{os.getenv('FLY_MACHINE_ID', 'local')}",
            options="-c statement_timeout=5000",
            keepalives=1,
            keepalives_idle=5,
            keepalives_interval=2,
            keepalives_count=3,
            tcp_user_timeout=10000,
        )
        self.connection.autocommit = True
        self.key = KEYS[name]
        self.pid: int | None = None

    def acquire(self) -> bool:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s, %s), pg_backend_pid()", (NAMESPACE, self.key))
            row = cursor.fetchone()
            assert row is not None
            owned, pid = row
        if owned:
            self.pid = pid
        return owned

    def check(self) -> None:
        # Detect a connection loss or accidental transaction-pool endpoint.
        # Never reconnect: that would silently discard ownership.
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_backend_pid(), EXISTS (SELECT 1 FROM pg_locks "
                "WHERE pid=pg_backend_pid() AND locktype='advisory' "
                "AND classid=%s AND objid=%s AND granted)",
                (NAMESPACE, self.key),
            )
            row = cursor.fetchone()
            assert row is not None
            pid, owned = row
        if pid != self.pid or not owned:
            raise RuntimeError("process singleton ownership lost")

    def close(self) -> None:
        self.connection.close()
