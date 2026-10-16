"""``hasRole(getRoleAdmin(role), msg.sender)`` publishes the holders of every observed role's admin; one role whose
admin read fails leaves that admin's holders unread, so the published set can't be exact.

Index rows are real test-DB rows folded by the real ``EventIndexedAdapter``; only the JSON-RPC HTTP wire is stubbed.
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from tests.conftest import requires_postgres
from tests.resolution.test_pass_leaf_memo import _ROLE_LEAF, GRANTED, REVOKED, _topic

pytestmark = [requires_postgres, pytest.mark.usefixtures("_stub_live_authority")]

ACL = "0x" + "ac" * 20
BLOCK = 26078900
GET_ROLE_ADMIN = "0x248a9ca3"
ROLE_A = "0x" + "a0" * 32
ROLE_B = "0x" + "b0" * 32
ADMIN_A = "0x" + "a1" * 32
ADMIN_B = "0x" + "b1" * 32
HOLDER_A = "0x" + "1a" * 20
HOLDER_B = "0x" + "1b" * 20
GRANTEE = "0x" + "99" * 20


@pytest.fixture
def seeded(db_session):
    from db.models import IndexedEventCursor, IndexedEventLog, Job, JobStage, JobStatus
    from db.queue import store_artifact

    for topic0 in (GRANTED, REVOKED):
        db_session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=ACL,
                topic0=topic0,
                last_indexed_block=BLOCK,
                backfill_complete=True,
                first_indexed_block=0,
                first_indexed_block_basis="creation_block_minus_one",
            )
        )
    for offset, (role, account) in enumerate(
        ((ROLE_A, GRANTEE), (ROLE_B, GRANTEE), (ADMIN_A, HOLDER_A), (ADMIN_B, HOLDER_B))
    ):
        db_session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=ACL,
                topic0=GRANTED,
                tx_hash=uuid.uuid4().bytes * 2,
                log_index=0,
                block_number=BLOCK - 1000 + offset,
                block_hash=b"\x11" * 32,
                transaction_index=0,
                topics=[GRANTED, role, _topic(account), _topic(account)],
                data_words=[],
            )
        )
    job = Job(
        address=ACL,
        request={"address": ACL, "name": "AccessControlled"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.flush()
    store_artifact(
        db_session,
        job.id,
        "predicate_trees",
        data={
            "schema_version": "semantic",
            "contract_name": "AccessControlled",
            "trees": {"grantRole(bytes32,address)": copy.deepcopy(_ROLE_LEAF)},
        },
    )
    return job


class _Wire:
    """The JSON-RPC HTTP session: answers ``getRoleAdmin`` per role; roles in ``failing`` answer with ``failure``."""

    def __init__(self, admins: dict[str, str], failing: dict[str, str]):
        self.admins = admins
        self.failing = failing
        self.requests = 0
        self.calls = 0

    def post(self, _url, *, json, **_kwargs):
        self.requests += 1
        out = []
        for item in json:
            assert item["method"] == "eth_call"
            data = item["params"][0]["data"]
            assert data.startswith(GET_ROLE_ADMIN)
            self.calls += 1
            role = "0x" + data[len(GET_ROLE_ADMIN) :]
            failure = self.failing.get(role)
            if failure == "error":
                out.append(
                    {"jsonrpc": "2.0", "id": item["id"], "error": {"code": -32000, "message": "header not found"}}
                )
            elif failure == "malformed":
                out.append({"jsonrpc": "2.0", "id": item["id"], "result": "0x"})
            elif failure is None:
                out.append({"jsonrpc": "2.0", "id": item["id"], "result": self.admins[role]})
        return _Response(out)


class _Response:
    def __init__(self, payload: list[dict[str, Any]]):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> list[dict[str, Any]]:
        return self.payload


def _resolve(db_session, seeded, monkeypatch, failing: dict[str, str]) -> tuple[dict[str, Any], _Wire]:
    from services.resolution.capability_resolver import resolve_contract_capabilities

    wire = _Wire({ROLE_A: ADMIN_A, ROLE_B: ADMIN_B, ADMIN_A: ADMIN_A, ADMIN_B: ADMIN_A}, failing)
    monkeypatch.setattr("services.clients.rpc._get_session", lambda: wire)
    out = resolve_contract_capabilities(
        db_session, address=ACL, chain_id=1, block=BLOCK, job_id=seeded.id, chain="ethereum"
    )
    assert out is not None
    return out["grantRole(bytes32,address)"], wire


def test_every_admin_read_answers_an_exact_set(db_session, seeded, monkeypatch):
    cap, wire = _resolve(db_session, seeded, monkeypatch, failing={})

    assert cap["kind"] == "finite_set"
    assert cap["members"] == [HOLDER_A, HOLDER_B]
    assert cap["membership_quality"] == "exact"
    assert (wire.requests, wire.calls) == (1, 4)


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param("error", id="rpc-error"),
        pytest.param("transport", id="unanswered-slot"),
        pytest.param("malformed", id="malformed-answer"),
    ],
)
def test_one_failed_admin_read_publishes_the_holders_read_as_a_lower_bound(db_session, seeded, monkeypatch, failure):
    from services.policy.capability_surface import project_capability_surface

    cap, wire = _resolve(db_session, seeded, monkeypatch, failing={ROLE_B: failure})

    assert (wire.requests, wire.calls) == (1, 4)
    assert cap["kind"] == "finite_set"
    assert cap["members"] == [HOLDER_A]
    assert cap["membership_quality"] == "lower_bound"
    assert cap["confidence"] == "partial"
    rows = project_capability_surface(cap).principal_rows
    assert [(row["address"], row["details"]["membership_quality"]) for row in rows] == [(HOLDER_A, "lower_bound")]


def test_every_admin_read_failing_publishes_an_unresolved_check(db_session, seeded, monkeypatch):
    cap, _wire = _resolve(
        db_session, seeded, monkeypatch, failing=dict.fromkeys((ROLE_A, ROLE_B, ADMIN_A, ADMIN_B), "error")
    )

    assert cap["kind"] == "external_check_only"
