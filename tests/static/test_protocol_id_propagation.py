"""``_resolve_proxy`` omitted protocol_id from child requests, so impl-descended jobs had NULL protocol_id and
monitoring never enrolled. Integration tests need ``TEST_DATABASE_URL``.
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import requires_postgres

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


def _make_job(protocol_id: int | None = 1, address="0x" + "aa" * 20, name="eETH"):
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
    return {
        "type": "proxy",
        "proxy_type": "eip1967",
        "implementation": impl_addr,
        "beacon": None,
        "admin": None,
        "facets": None,
    }


class TestStaticWorkerProtocolIdPropagation:
    @patch("workers.static_worker.store_artifact")
    @patch("workers.static_worker.create_job")
    def test_child_job_inherits_protocol_id(self, mock_create_job, mock_store_artifact):
        from workers.static_worker import StaticWorker

        impl_addr = "0x" + "bb" * 20
        mock_classify = MagicMock(return_value=_proxy_classification(impl_addr))

        mock_child = MagicMock(id=uuid.uuid4())
        mock_create_job.return_value = mock_child

        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        job = _make_job(protocol_id=1)

        worker = StaticWorker()

        with patch("services.discovery.classifier.classify_single", mock_classify):
            worker._resolve_proxy(mock_session, job, job.address, "eETH")

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

        assert child_request.get("protocol_id") is None, (
            "child_request should not have protocol_id when parent has none"
        )

    @patch("workers.static_worker.store_artifact")
    @patch("workers.static_worker.create_job")
    def test_diamond_proxy_facets_inherit_protocol_id(self, mock_create_job, mock_store_artifact):
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

        assert mock_create_job.call_count == 2

        for call in mock_create_job.call_args_list:
            child_request = call[0][1]
            assert child_request.get("protocol_id") == 5, f"Facet child_request missing protocol_id: {child_request}"


class TestEnrollmentWithProxyContracts:
    @patch("services.monitoring.enrollment.enroll_protocol_contracts")
    def test_maybe_enroll_called_with_correct_protocol(self, mock_enroll):
        from services.monitoring.enrollment import maybe_enroll_protocol

        mock_enroll.return_value = []

        mock_session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.first.return_value = MagicMock()
        mock_session.execute.return_value = result

        enrolled = maybe_enroll_protocol(mock_session, 1, "http://rpc", "ethereum")

        assert enrolled is True
        mock_enroll.assert_called_once_with(mock_session, 1, "http://rpc", "ethereum", None, enroll_controllers=False)

    @patch("services.monitoring.enrollment.enroll_protocol_contracts")
    def test_exclude_job_id_threads_through_to_enroll(self, mock_enroll):
        """Its address must be in the analyzed set despite the not-yet-flipped status."""
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


@pytest.fixture()
def pg_session():
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from db.models import Base, Job, Protocol

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    original_protocol_ids: set[int] = set()

    for p in session.execute(select(Protocol)).scalars():
        original_protocol_ids.add(p.id)

    try:
        yield session
    finally:
        session.rollback()
        test_proto = session.execute(
            select(Protocol).where(Protocol.name == "__test_propagation__")
        ).scalar_one_or_none()

        if test_proto:
            test_jobs = session.execute(select(Job).where(Job.protocol_id == test_proto.id)).scalars().all()
            for j in test_jobs:
                session.delete(j)
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
    def test_child_job_has_protocol_id_in_db(self, pg_session):
        from db.models import Job, Protocol
        from db.queue import create_job
        from workers.static_worker import StaticWorker

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

        from sqlalchemy import select

        child = pg_session.execute(select(Job).where(Job.address == impl_addr)).scalar_one()

        assert child.protocol_id == protocol.id, (
            f"Child impl job must have protocol_id={protocol.id}, got {child.protocol_id}"
        )
        assert child.request.get("protocol_id") == protocol.id

    def test_enrolls_with_in_flight_sibling(self, pg_session):
        """Unit twin of ``test_in_flight_sibling_job_does_not_block_enrollment`` in
        ``tests/monitoring/test_monitoring_enrollment_anvil.py``.
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
