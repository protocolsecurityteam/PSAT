"""Claim-time authority for transactions published by a worker attempt.

The context is copied into worker fan-outs; a session keeps its first bound
attempt across commits and rollbacks so it cannot silently become a system
session when a caller leaves the context. System consumers run without a bound
attempt. Lifecycle mutations validate before clearing the token in their own
transaction; all other commits validate immediately before publication.
"""

from __future__ import annotations

import contextvars
import os
import signal
import subprocess
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from sqlalchemy import event, select
from sqlalchemy.orm import Session


class LeaseLost(RuntimeError):
    """The claim no longer authorizes publishing output."""


@dataclass
class JobAttempt:
    job_id: uuid.UUID
    lease_id: uuid.UUID
    cancelled: threading.Event = field(default_factory=threading.Event)
    started_at: str | None = None
    started_monotonic: float | None = None
    processes: list[subprocess.Popen] = field(default_factory=list)
    process_lock: threading.RLock = field(default_factory=threading.RLock)

    def check_cancelled(self) -> None:
        if self.cancelled.is_set():
            raise LeaseLost(f"Job {self.job_id}: attempt cancelled")

    def cancel(self) -> None:
        with self.process_lock:
            self.cancelled.set()
            for proc in self.processes:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


_original_popen = subprocess.Popen


class _AttemptPopen(_original_popen):
    def __init__(self, *args, **kwargs):
        attempt = current_attempt.get()
        if attempt is None:
            super().__init__(*args, **kwargs)
            return
        # CryticCompile and solc-select also use subprocess.Popen/run. Install
        # at worker startup so their child compiler trees share this registry.
        with attempt.process_lock:
            attempt.check_cancelled()
            kwargs["start_new_session"] = True
            super().__init__(*args, **kwargs)
            attempt.processes.append(self)
            if attempt.cancelled.is_set():
                try:
                    os.killpg(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.wait()
                attempt.check_cancelled()


def install_attempt_subprocess_tracking() -> None:
    subprocess.Popen = _AttemptPopen


current_attempt: contextvars.ContextVar[JobAttempt | None] = contextvars.ContextVar("job_attempt", default=None)


@contextmanager
def bind_job_attempt(attempt: JobAttempt) -> Iterator[None]:
    token = current_attempt.set(attempt)
    try:
        attempt.check_cancelled()
        yield
    finally:
        current_attempt.reset(token)


def session_attempt(session: Session) -> JobAttempt | None:
    attempt = session.info.get("job_attempt")
    if attempt is None and (attempt := current_attempt.get()) is not None:
        session.info["job_attempt"] = attempt
    return attempt


def assert_current_job_attempt(session: Session, job_id: uuid.UUID, lease_id: uuid.UUID, *, lock: bool = True):
    from db.models import Job, JobStatus

    if lease_id is None:
        raise LeaseLost(f"Job {job_id}: missing claim-time lease")
    with session.no_autoflush:
        stmt = select(Job.id).where(Job.id == job_id, Job.status == JobStatus.processing, Job.lease_id == lease_id)
        if lock:
            stmt = stmt.with_for_update()
        if session.execute(stmt).scalar_one_or_none() is None:
            raise LeaseLost(f"Job {job_id}: lease {lease_id} no longer holds the processing row")


def fence_session(session: Session) -> None:
    if (attempt := session_attempt(session)) is not None:
        attempt.check_cancelled()
        assert_current_job_attempt(session, attempt.job_id, attempt.lease_id)


@event.listens_for(Session, "before_commit")
def _fence_commit(session: Session) -> None:
    # A transition's conditional SQL already validated this exact transaction.
    # Flush first so hooks cannot queue additional output after validation.
    session.flush()
    attempt = session_attempt(session)
    if attempt is not None:
        attempt.check_cancelled()
        if session.info.get("attempt_transition") is not session.get_transaction():
            assert_current_job_attempt(session, attempt.job_id, attempt.lease_id)


@event.listens_for(Session, "after_transaction_end")
def _clear_transition(session: Session, transaction) -> None:
    if session.info.get("attempt_transition") is transaction:
        session.info.pop("attempt_transition", None)
