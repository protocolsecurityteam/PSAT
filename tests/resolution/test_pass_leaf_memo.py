"""An entry point and its effect-scope sites share one evaluation of an identical leaf within a resolution pass.

The leaf is PendleGovernanceProxy's ``grantRole`` gate, ``hasRole(getRoleAdmin(role), msg.sender)``: every site under
``grantRole`` carries the same leaf, and before the pass memo each one re-ran the role-word scan, the ``getRoleAdmin``
batch and the event fold.
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from tests.conftest import requires_postgres

pytestmark = [requires_postgres, pytest.mark.usefixtures("_stub_live_authority")]

PROXY = "0x53c26f7645500fea9a856bfa09e820dacf643ab9"
SAFE = "0x8119ec16f0573b7dac7c0cb94eb504fb32456ee1"
BLOCK = 26078900
DEFAULT_ADMIN_ROLE = "0x" + "0" * 64
GRANTED = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
REVOKED = "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b"

_ROLE_LEAF: dict[str, Any] = {
    "op": "LEAF",
    "leaf": {
        "kind": "membership",
        "operator": "truthy",
        "authority_role": "caller_authority",
        "operands": [
            {"source": "view_call", "callee": "getRoleAdmin(bytes32)", "callee_signature": "getRoleAdmin(bytes32)"},
            {"source": "msg_sender"},
        ],
        "references_msg_sender": True,
        "parameter_indices": [],
        "expression": "return REF_127",
        "basis": ["if-revert via always-reverting branch"],
        "set_descriptor": {
            "kind": "mapping_membership",
            "key_sources": [
                {
                    "source": "view_call",
                    "callee": "getRoleAdmin(bytes32)",
                    "callee_signature": "getRoleAdmin(bytes32)",
                    "callee_selector": "0x248a9ca3",
                },
                {"source": "msg_sender"},
            ],
            "storage_var": "_roles",
            "enumeration_hint": [
                {
                    "topic0": topic0,
                    "topics_to_keys": {"1": 0, "2": 1},
                    "data_to_keys": {},
                    "direction": direction,
                    "event_signature": f"{name}(bytes32,address,address)",
                    "event_name": name,
                    "mapping_name": "_roles",
                    "key_position": 1,
                    "indexed_positions": [0, 1, 2],
                    "value_position": None,
                    "writer_function": writer,
                }
                for topic0, direction, name, writer in (
                    (GRANTED, "add", "RoleGranted", "_grantRole(bytes32,address)"),
                    (REVOKED, "remove", "RoleRevoked", "_revokeRole(bytes32,address)"),
                )
            ],
        },
    },
}


def _site(site_id: str, origin: str) -> dict[str, Any]:
    return {
        "id": site_id,
        "kind": "storage_write",
        "target": "_roles",
        "sink_ids": [site_id],
        "origin": origin,
        "predicate": copy.deepcopy(_ROLE_LEAF),
    }


def _artifact() -> dict[str, Any]:
    signature = "grantRole(bytes32,address)"
    return {
        "schema_version": "semantic",
        "contract_name": "PendleGovernanceProxy",
        "trees": {signature: copy.deepcopy(_ROLE_LEAF)},
        "effect_scopes": {
            signature: [
                _site(f"{signature}/0", "body"),
                _site(f"{signature}/1", "guard"),
                _site(f"{signature}/2", "guard"),
            ]
        },
    }


def _topic(value: str) -> str:
    return "0x" + value[2:].rjust(64, "0")


@pytest.fixture
def seeded(db_session):
    from db.models import IndexedEventCursor, IndexedEventLog, Job, JobStage, JobStatus
    from db.queue import store_artifact

    for topic0 in (GRANTED, REVOKED):
        db_session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=PROXY,
                topic0=topic0,
                last_indexed_block=BLOCK,
                backfill_complete=True,
                first_indexed_block=0,
                first_indexed_block_basis="creation_block_minus_one",
            )
        )
    db_session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=PROXY,
            topic0=GRANTED,
            tx_hash=uuid.uuid4().bytes * 2,
            log_index=0,
            block_number=BLOCK - 1000,
            block_hash=b"\x11" * 32,
            transaction_index=0,
            topics=[GRANTED, DEFAULT_ADMIN_ROLE, _topic(SAFE), _topic(SAFE)],
            data_words=[],
        )
    )
    job = Job(
        address=PROXY,
        request={"address": PROXY, "name": "PendleGovernanceProxy"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.flush()
    store_artifact(db_session, job.id, "predicate_trees", data=_artifact())
    return job


@pytest.fixture
def calls(monkeypatch):
    from services.resolution.adapters.event_indexed import EventIndexedAdapter
    from services.resolution.predicate_evaluator import membership

    counts = {"role_words": 0, "role_admin": 0, "fold": 0}
    # The uncached scan; before the pass memo the scan was ``_observed_event_key_words`` itself.
    scan_name = (
        "_scan_observed_event_key_words"
        if hasattr(membership, "_scan_observed_event_key_words")
        else "_observed_event_key_words"
    )
    scan = getattr(membership, scan_name)
    fold = EventIndexedAdapter.enumerate

    def counted_scan(**kwargs):
        counts["role_words"] += 1
        return scan(**kwargs)

    def role_admin(**_kwargs):
        counts["role_admin"] += 1
        return [DEFAULT_ADMIN_ROLE]

    def counted_fold(self, descriptor, ctx):
        counts["fold"] += 1
        return fold(self, descriptor, ctx)

    monkeypatch.setattr(membership, scan_name, counted_scan)
    monkeypatch.setattr(membership, "_call_unary_bytes32_view", role_admin)
    monkeypatch.setattr(EventIndexedAdapter, "enumerate", counted_fold)
    return counts


def test_sites_reuse_the_entry_points_leaf_evaluation(db_session, seeded, calls):
    from services.resolution.capability_resolver import resolve_contract_capabilities

    out = resolve_contract_capabilities(
        db_session, address=PROXY, chain_id=1, block=BLOCK, job_id=seeded.id, chain="ethereum"
    )

    assert out is not None
    cap = out["grantRole(bytes32,address)"]
    assert cap["kind"] == "finite_set" and cap["members"] == [SAFE]
    sites = cap["effect_capabilities"]
    assert len(sites) == 3
    assert all(site["capability"]["members"] == [SAFE] for site in sites)
    assert calls == {"role_words": 1, "role_admin": 1, "fold": 1}


def test_a_new_pass_evaluates_again(db_session, seeded, calls):
    from services.resolution.capability_resolver import resolve_contract_capabilities

    for _ in range(2):
        resolve_contract_capabilities(
            db_session, address=PROXY, chain_id=1, block=BLOCK, job_id=seeded.id, chain="ethereum"
        )

    assert calls == {"role_words": 2, "role_admin": 2, "fold": 2}


class _CountingAdapter:
    calls = 0

    @classmethod
    def matches(cls, descriptor, ctx):
        return 10

    @classmethod
    def supports_external_check_only(cls):
        return False

    def enumerate(self, descriptor, ctx):
        from services.resolution.capabilities import CapabilityExpr

        type(self).calls += 1
        return CapabilityExpr.finite_set([SAFE], quality="exact", confidence="enumerable")


def _ctx(memo: dict, **overrides: Any):
    from services.resolution.adapters import CallFrame, EvaluationContext
    from services.resolution.pass_memo import PASS_MEMO

    fields: dict[str, Any] = {
        "chain_id": 1,
        "block": BLOCK,
        "contract_address": PROXY,
        "state_var_values": {"owner": SAFE},
        "call_frame": CallFrame.root(contract_address=PROXY, function_signature="f()", function_selector="0x26121ff0"),
        "meta": {PASS_MEMO: memo},
    }
    fields.update(overrides)
    return EvaluationContext(**fields)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"contract_address": SAFE}, id="contract"),
        pytest.param({"block": BLOCK + 1}, id="block"),
        pytest.param({"state_var_values": {"owner": PROXY}}, id="state_values"),
        pytest.param({"chain_id": 8453}, id="chain"),
    ],
)
def test_memo_key_separates_whatever_an_adapter_reads(overrides):
    from services.resolution.adapters import AdapterRegistry, CallFrame

    registry = AdapterRegistry()
    registry.register(_CountingAdapter)  # type: ignore[arg-type]
    _CountingAdapter.calls = 0
    memo: dict = {}
    descriptor = _ROLE_LEAF["leaf"]["set_descriptor"]
    registry.enumerate(descriptor, _ctx(memo))
    other_function = CallFrame.root(contract_address=PROXY, function_signature="g()", function_selector="0x26121ff0")
    registry.enumerate(descriptor, _ctx(memo, call_frame=other_function))
    assert _CountingAdapter.calls == 1, "same selector, same inputs: one evaluation"
    other_selector = CallFrame.root(contract_address=PROXY, function_signature="g()", function_selector="0xe2179b8e")
    registry.enumerate(descriptor, _ctx(memo, call_frame=other_selector))
    assert _CountingAdapter.calls == 2
    registry.enumerate(descriptor, _ctx(memo, **overrides))
    assert _CountingAdapter.calls == 3


def test_memoized_capability_is_a_private_copy():
    from services.resolution.adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(_CountingAdapter)  # type: ignore[arg-type]
    memo: dict = {}
    descriptor = _ROLE_LEAF["leaf"]["set_descriptor"]
    first = registry.enumerate(descriptor, _ctx(memo))
    first.subject = "bound"
    assert first.members is not None
    first.members.append(PROXY)
    second = registry.enumerate(descriptor, _ctx(memo))
    assert second.members == [SAFE]
    assert second.subject == "root"
