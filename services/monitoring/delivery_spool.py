"""Disposable exact delivery identity store with a bounded Python/SQLite heap."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from itertools import chain
from typing import Any

from services.resolution.repos.event_logs_rpc import FetchedEventLog


class DeliverySpoolError(Exception):
    """The entire discovery group must be discarded; no partial summaries are safe."""


class DeliverySpool:
    # A quota on the disposable database, not on the number we claim to observe.
    MAX_BYTES = 1024 * 1024 * 1024

    def __enter__(self) -> DeliverySpool:
        # /var/tmp is disk-backed in our container; deployments overriding this
        # path must also use disk, not tmpfs. No production DB staging is needed.
        self._directory = tempfile.TemporaryDirectory(
            prefix="psat-deliveries-", dir=os.getenv("PSAT_DISPOSITION_SPOOL_DIR", "/var/tmp")
        )
        self._db: sqlite3.Connection | None = None
        try:
            if os.path.exists("/proc/self/mountinfo"):
                device = os.stat(self._directory.name).st_dev
                device_id = f"{os.major(device)}:{os.minor(device)}"
                with open("/proc/self/mountinfo") as mounts:
                    for line in mounts:
                        if line.split()[2] == device_id and line.split(" - ", 1)[1].split()[0] in {"tmpfs", "ramfs"}:
                            raise DeliverySpoolError("delivery spool requires disk, not a memory-backed filesystem")
            self._db = sqlite3.connect(os.path.join(self._directory.name, "deliveries.sqlite"))
            self._db.execute("PRAGMA page_size=4096")
            self._db.execute(f"PRAGMA max_page_count={max(1, self.MAX_BYTES // 4096)}")
            self._db.execute("PRAGMA cache_size=-2048")
            self._db.execute("PRAGMA mmap_size=0")
            self._db.execute("PRAGMA temp_store=FILE")
            # The whole file is disposable. Journaling would add unbounded
            # temporary storage with no recovery benefit for this scan.
            self._db.execute("PRAGMA journal_mode=OFF")
            self._db.execute("PRAGMA synchronous=OFF")
            self._db.execute(
                "CREATE TABLE deliveries (pair INTEGER, tx BLOB, log_index INTEGER, block INTEGER, "
                "meterable INTEGER, fingerprint BLOB, PRIMARY KEY(pair,tx,log_index), UNIQUE(pair,block,log_index))"
            )
            # SQLite keeps its open file descriptor. With journaling disabled,
            # POSIX unlink makes cleanup automatic even on SIGKILL/OOM; no stale
            # scratch files accumulate when a producer cannot run its finally.
            if os.name == "posix":
                os.unlink(os.path.join(self._directory.name, "deliveries.sqlite"))
                self._directory.cleanup()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_exc: Any) -> None:
        try:
            if self._db is not None:
                self._db.close()
        finally:
            self._directory.cleanup()

    def add(self, pair: int, log: FetchedEventLog, *, meterable: bool) -> None:
        assert self._db is not None
        digest = hashlib.sha256(log.block_hash)
        digest.update(str(log.transaction_index).encode("ascii"))
        digest.update(log.address.encode("ascii"))
        digest.update(len(log.topics).to_bytes(1, "big"))
        for word in chain(log.topics, log.data_words):
            digest.update(word.encode("ascii"))
        fingerprint = digest.digest()
        try:
            inserted = self._db.execute(
                "INSERT INTO deliveries VALUES(?,?,?,?,?,?) ON CONFLICT(pair,tx,log_index) DO NOTHING",
                (pair, log.tx_hash, log.log_index, log.block_number, int(meterable), fingerprint),
            ).rowcount
            if not inserted:
                prior = self._db.execute(
                    "SELECT block,meterable,fingerprint FROM deliveries WHERE pair=? AND tx=? AND log_index=?",
                    (pair, log.tx_hash, log.log_index),
                ).fetchone()
                if prior != (log.block_number, int(meterable), fingerprint):
                    raise DeliverySpoolError("conflicting duplicate delivery; discovery discarded")
        except sqlite3.Error as exc:
            raise DeliverySpoolError("delivery spool write failed; discovery discarded") from exc

    def summary(self, pair: int, *, cursor: int, keep: int) -> tuple[int, list[dict[str, Any]]]:
        assert self._db is not None
        try:
            count = self._db.execute(
                "SELECT count(*) FROM deliveries WHERE pair=? AND block>?", (pair, cursor)
            ).fetchone()[0]
            rows = self._db.execute(
                "SELECT tx,log_index,block,meterable FROM deliveries WHERE pair=? AND block>? "
                "ORDER BY block,log_index LIMIT ?",
                (pair, cursor, keep),
            )
            return count, [
                {"tx": "0x" + tx.hex(), "log_index": index, "block": block, "meterable": bool(meterable)}
                for tx, index, block, meterable in rows
            ]
        except sqlite3.Error as exc:
            raise DeliverySpoolError("delivery spool read failed; discovery discarded") from exc
