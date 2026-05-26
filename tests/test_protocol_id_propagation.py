"""Tests proving that protocol_id must propagate through proxy→impl child jobs.

Bug: static_worker._resolve_proxy creates child jobs for implementation
contracts without including protocol_id in the child_request dict. This
causes all impl-descended jobs to have protocol_id=NULL, which silently
prevents the monitoring enrollment system from activating.

These tests should FAIL before the fix and PASS after.

Run with:
    uv run pytest tests/test_protocol_id_propagation.py -v

Integration tests (requires PostgreSQL):
    TEST_DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test \
        uv run pytest tests/test_protocol_id_propagation.py -v
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# ---------------------------------------------------------------------------
# Postgres skip condition (shared with test_queue.py)
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


def _can_connect() -> bool:
    if not DATABASE_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_job(protocol_id: int | None = 1, address="0x" + "aa" * 20, name="eETH"):
    """Build a mock Job object with the fields _resolve_proxy reads."""
    job = MagicMock()
    job.id = uuid.uuid4()
    job.address = address
    job.name = name
    job.protocol_id = protocol_id
    job.request = {
        "address": address,
        "rpc_url": "http://localhost:8545",
        "chain": "ethereum",
        "protocol_id": protocol_id,
    }
    return job


def _proxy_classification(impl_addr="0x" + "bb" * 20):
    """Return a classify_single result indicating an EIP-1967 proxy."""
    return {
        "type": "proxy",
        "proxy_type": "eip1967",
        "implementation": impl_addr,
        "beacon": None,
        "admin": None,
        "facets": None,
    }


# ---------------------------------------------------------------------------
# Test 1: static worker must propagate protocol_id to impl child jobs
# ---------------------------------------------------------------------------


class TestStaticWorkerProtocolIdPropagation:
    """Verify _resolve_proxy includes protocol_id in child job requests."""

    @patch("workers.static_worker.store_artifact")
    @patch("workers.static_worker.create_job")
    def test_child_job_inherits_protocol_id(self, mock_create_job, mock_store_artifact):
        """The child_request dict passed to create_job must contain protocol_id.

        Before the fix, the child_request at static_worker.py:797 omitted
        protocol_id, so create_job() set it to NULL. This test catches that.
        """
        from workers.static_worker import StaticWorker

        impl_addr = "0x" + "bb" * 20
        mock_classify = MagicMock(return_value=_proxy_classification(impl_addr))

        # create_job should return a mock child job
        mock_child = MagicMock(id=uuid.uuid4())
        mock_create_job.return_value = mock_child

        # Mock session: both Contract and Job queries return None
        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        job = _make_job(protocol_id=1)

        worker = StaticWorker()

        with patch("services.discovery.classifier.classify_single", mock_classify):
            worker._resolve_proxy(mock_session, job, job.address, "eETH")

        # create_job must have been called
        mock_create_job.assert_called_once()
        child_request = mock_create_job.call_args[0][1]  # 2nd positional arg

        assert "protocol_id" in child_request, (
            "child_request must include protocol_id — without it, the child "
            "job gets protocol_id=NULL and monitoring enrollment never fires"
        )
        assert child_request["protocol_id"] == 1

    @patch("workers.static_worker.store_artifact")
    @patch("workers.static_worker.create_job")
    def test_child_job_no_protocol_id_when_parent_has_none(self, mock_create_job, mock_store_artifact):
        """If the parent job has no protocol_id, child should not get one either."""
        from workers.static_worker import StaticWorker

        impl_addr = "0x" + "bb" * 20
        mock_classify = MagicMock(return_value=_proxy_classification(impl_addr))

        mock_child = MagicMock(id=uuid.uuid4())
        mock_create_job.return_value = mock_child

        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        job = _make_job(protocol_id=None)
        job.request = {"address": job.address, "rpc_url": "http://localhost:8545"}

        worker = StaticWorker()

        with patch("services.discovery.classifier.classify_single", mock_classify):
            worker._resolve_proxy(mock_session, job, job.address, "TestContract")

        mock_create_job.assert_called_once()
        child_request = mock_create_job.call_args[0][1]

        # protocol_id should NOT be in the dict (or should be None)
        assert child_request.get("protocol_id") is None, (
            "child_request should not have protocol_id when parent has none"
        )

    @patch("workers.static_worker.store_artifact")
    @patch("workers.static_worker.create_job")
    def test_diamond_proxy_facets_inherit_protocol_id(self, mock_create_job, mock_store_artifact):
        """Diamond proxy facets should also get protocol_id."""
        from workers.static_worker import StaticWorker

        facet1 = "0x" + "cc" * 20
        facet2 = "0x" + "dd" * 20
        classification = {
            "type": "proxy",
            "proxy_type": "diamond",
            "implementation": None,
            "beacon": None,
            "admin": None,
            "facets": [facet1, facet2],
        }
        mock_classify = MagicMock(return_value=classification)

        mock_create_job.return_value = MagicMock(id=uuid.uuid4())

        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        job = _make_job(protocol_id=5)

        worker = StaticWorker()

        with patch("services.discovery.classifier.classify_single", mock_classify):
            worker._resolve_proxy(mock_session, job, job.address, "DiamondProxy")

        # Should create 2 child jobs (one per facet)
        assert mock_create_job.call_count == 2

        for call in mock_create_job.call_args_list:
            child_request = call[0][1]
            assert child_request.get("protocol_id") == 5, f"Facet child_request missing protocol_id: {child_request}"


# ---------------------------------------------------------------------------
# Test 2: enrollment must fire for protocols with proxy contracts
# ---------------------------------------------------------------------------


class TestEnrollmentWithProxyContracts:
    """Verify that maybe_enroll_protocol is reachable for impl-descended jobs."""

    def test_enrollment_skipped_when_protocol_id_null(self):
        """Simulates the policy_worker check: if job.protocol_id is None,
        enrollment is never attempted.

        This demonstrates the downstream effect of the static worker bug.
        """
        # This is the exact check from policy_worker.py:255
        job = MagicMock()
        job.protocol_id = None  # BUG: impl jobs get NULL

        enrollment_attempted = False
        if job.protocol_id:
            enrollment_attempted = True

        assert not enrollment_attempted, "Enrollment should NOT fire when protocol_id is NULL (current broken behavior)"

    def test_enrollment_fires_when_protocol_id_set(self):
        """When protocol_id is properly propagated, enrollment is attempted."""
        job = MagicMock()
        job.protocol_id = 1  # FIXED: impl jobs inherit protocol_id

        enrollment_attempted = False
        if job.protocol_id:
            enrollment_attempted = True

        assert enrollment_attempted, "Enrollment must fire when protocol_id is set"

    @patch("services.monitoring.enrollment.enroll_protocol_contracts")
    def test_maybe_enroll_called_with_correct_protocol(self, mock_enroll):
        """``maybe_enroll_protocol`` runs ``enroll_protocol_contracts``
        with the protocol id it was called with, once at least one job
        has completed."""
        from services.monitoring.enrollment import maybe_enroll_protocol

        mock_enroll.return_value = []

        mock_session = MagicMock()
        result = MagicMock()
        # Completed-job gate: returning a row means the trigger proceeds.
        result.scalars.return_value.first.return_value = MagicMock()
        mock_session.execute.return_value = result

        enrolled = maybe_enroll_protocol(mock_session, 1, "http://rpc", "ethereum")

        assert enrolled is True
        # Fast-path hint skips the expensive primary-controller pass.
        mock_enroll.assert_called_once_with(mock_session, 1, "http://rpc", "ethereum", None, enroll_controllers=False)

    @patch("services.monitoring.enrollment.enroll_protocol_contracts")
    def test_exclude_job_id_threads_through_to_enroll(self, mock_enroll):
        """``exclude_job_id`` (the calling PolicyWorker's still-processing
        job id) must reach ``enroll_protocol_contracts`` so its address
        is included in the analyzed-addrs set despite the not-yet-flipped
        status. This used to also gate the in-flight skip; the gate is
        gone but the calling-job-id threading remains.
        """
        from services.monitoring.enrollment import maybe_enroll_protocol

        mock_enroll.return_value = []

        calling_job_id = uuid.uuid4()

        mock_session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.first.return_value = MagicMock()
        mock_session.execute.return_value = result

        enrolled = maybe_enroll_protocol(
            mock_session,
            1,
            "http://rpc",
            "ethereum",
            exclude_job_id=calling_job_id,
        )
        assert enrolled is True
        mock_enroll.assert_called_once_with(
            mock_session, 1, "http://rpc", "ethereum", calling_job_id, enroll_controllers=False
        )


# ---------------------------------------------------------------------------
# Integration tests — real DB, real create_job, real _resolve_proxy
# ---------------------------------------------------------------------------


@pytest.fixture()
def pg_session():
    """Create all tables, yield a session, clean up only test-created rows."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from db.models import Base, Job, Protocol

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    original_protocol_ids: set[int] = set()

    # Track existing protocols so we only clean up test ones
    for p in session.execute(select(Protocol)).scalars():
        original_protocol_ids.add(p.id)

    try:
        yield session
    finally:
        session.rollback()
        # Find the test protocol
        test_proto = session.execute(
            select(Protocol).where(Protocol.name == "__test_propagation__")
        ).scalar_one_or_none()

        if test_proto:
            # Delete jobs (and cascaded artifacts/source_files) for test protocol
            test_jobs = session.execute(select(Job).where(Job.protocol_id == test_proto.id)).scalars().all()
            for j in test_jobs:
                session.delete(j)
            # Also delete jobs with NULL protocol_id that have test addresses
            null_jobs = (
                session.execute(
                    select(Job).where(
                        Job.protocol_id.is_(None),
                        Job.address.in_(
                            [
                                "0x" + "11" * 20,
                                "0x" + "22" * 20,
                                "0x" + "33" * 20,
                                "0x" + "44" * 20,
                                "0x" + "55" * 20,
                                "0x" + "66" * 20,
                                "0x" + "77" * 20,
                                "0x" + "88" * 20,
                                "0x" + "99" * 20,
                            ]
                        ),
                    )
                )
                .scalars()
                .all()
            )
            for j in null_jobs:
                session.delete(j)
            session.flush()
            session.delete(test_proto)

        session.commit()
        session.close()
        engine.dispose()


@requires_postgres
class TestProtocolIdPropagationIntegration:
    """End-to-end tests using a real PostgreSQL database.

    These create actual Job rows and verify protocol_id survives the
    full create_job code path — no mocks on the DB layer.
    """

    def test_child_job_has_protocol_id_in_db(self, pg_session):
        """_resolve_proxy → create_job → child row in DB has protocol_id."""
        from db.models import Job, Protocol
        from db.queue import create_job
        from workers.static_worker import StaticWorker

        # Set up a protocol and parent job
        protocol = Protocol(name="__test_propagation__")
        pg_session.add(protocol)
        pg_session.commit()

        parent_job = create_job(
            pg_session,
            {
                "address": "0x" + "11" * 20,
                "name": "TestProxy",
                "rpc_url": "http://localhost:8545",
                "protocol_id": protocol.id,
            },
        )
        assert parent_job.protocol_id == protocol.id

        impl_addr = "0x" + "22" * 20
        classify_result = _proxy_classification(impl_addr)

        worker = StaticWorker()

        with patch("services.discovery.classifier.classify_single", return_value=classify_result):
            assert parent_job.address is not None
            worker._resolve_proxy(pg_session, parent_job, parent_job.address, "TestProxy")

        # Query the child job directly from the DB
        from sqlalchemy import select

        child = pg_session.execute(select(Job).where(Job.address == impl_addr)).scalar_one()

        assert child.protocol_id == protocol.id, (
            f"Child impl job must have protocol_id={protocol.id}, got {child.protocol_id}"
        )
        # Also verify it's stored in the request JSONB
        assert child.request.get("protocol_id") == protocol.id

    def test_enrolls_with_in_flight_sibling(self, pg_session):
        """A queued / processing sibling must not block the trigger from
        enrolling completed contracts. The historical in-flight gate
        used to skip in this case with no fallback; that's the bug pinned
        by ``test_in_flight_sibling_job_does_not_block_enrollment`` in
        ``tests/test_monitoring_enrollment_anvil.py``. This unit-level
        version covers the same shape against pg_session without anvil,
        and additionally covers the caller-job-self-block case (a
        PolicyWorker calling for its own still-processing job).
        """
        from db.models import JobStage, JobStatus, Protocol
        from db.queue import create_job
        from services.monitoring.enrollment import maybe_enroll_protocol

        protocol = Protocol(name="__test_propagation__")
        pg_session.add(protocol)
        pg_session.commit()

        first = create_job(
            pg_session,
            {
                "address": "0x" + "88" * 20,
                "name": "FirstContract",
                "protocol_id": protocol.id,
            },
        )
        first.status = JobStatus.completed
        first.stage = JobStage.done
        pg_session.commit()

        # The calling job (still processing) plus an unrelated sibling
        # also in-flight. Pre-fix both would trigger the gate; now both
        # are ignored.
        caller = create_job(
            pg_session,
            {
                "address": "0x" + "99" * 20,
                "name": "SecondContract",
                "protocol_id": protocol.id,
            },
        )
        caller.status = JobStatus.processing
        caller.stage = JobStage.policy

        sibling = create_job(
            pg_session,
            {
                "address": "0x" + "aa" * 20,
                "name": "QueuedSibling",
                "protocol_id": protocol.id,
            },
        )
        sibling.status = JobStatus.queued
        sibling.stage = JobStage.discovery
        pg_session.commit()

        with patch("services.monitoring.enrollment.enroll_protocol_contracts") as mock_enroll:
            mock_enroll.return_value = []
            result = maybe_enroll_protocol(
                pg_session,
                protocol.id,
                "http://localhost:8545",
                "ethereum",
                exclude_job_id=caller.id,
            )
            assert result is True, (
                "Enrollment must fire even when both the calling job and an unrelated sibling are in_flight."
            )
            mock_enroll.assert_called_once()

    def test_multi_hop_propagation(self, pg_session):
        """protocol_id survives proxy → impl → resolution-discovered chain."""
        from db.models import Job, Protocol
        from db.queue import create_job
        from workers.static_worker import StaticWorker

        protocol = Protocol(name="__test_propagation__")
        pg_session.add(protocol)
        pg_session.commit()

        # Root proxy job
        root = create_job(
            pg_session,
            {
                "address": "0x" + "55" * 20,
                "name": "RootProxy",
                "rpc_url": "http://localhost:8545",
                "protocol_id": protocol.id,
            },
        )

        # Static worker creates impl child
        impl_addr = "0x" + "66" * 20
        worker = StaticWorker()
        with patch("services.discovery.classifier.classify_single", return_value=_proxy_classification(impl_addr)):
            assert root.address is not None
            worker._resolve_proxy(pg_session, root, root.address, "RootProxy")

        from sqlalchemy import select

        impl_job = pg_session.execute(select(Job).where(Job.address == impl_addr)).scalar_one()
        assert impl_job.protocol_id == protocol.id

        # Resolution worker would then propagate from impl_job.
        # Simulate: create a grandchild using resolution worker's pattern.
        grandchild_addr = "0x" + "77" * 20
        grandchild = create_job(
            pg_session,
            {
                "address": grandchild_addr,
                "name": "DiscoveredContract",
                "rpc_url": "http://localhost:8545",
                "discovered_by": "resolution",
            },
        )
        # Resolution worker pattern (resolution_worker.py:323-325)
        if impl_job.protocol_id:
            grandchild.protocol_id = impl_job.protocol_id
        pg_session.commit()

        pg_session.refresh(grandchild)
        assert grandchild.protocol_id == protocol.id, (
            "Grandchild (resolution-discovered from impl) must inherit protocol_id"
        )
