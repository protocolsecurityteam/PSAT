"""Graph mapping-member replay reads the durable event index first and falls back to HyperSync only when the index can't
prove the member set; an unsettled replay re-runs once the index can answer.

The wires are stubbed (HyperSync client, ``eth_getLogs`` / ``eth_blockNumber``); cursors and rows are real test-DB
rows read by the real ``PostgresEventLogRepo``.
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy import func

from db.models import (
    ENROLLMENT_BASIS_PREDICATE_HINT,
    Contract,
    ControlGraphNode,
    EffectiveFunction,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    JobStage,
    JobStatus,
)
from services.resolution import recursive
from services.resolution.deferred_reconciler import (
    reconcile_deferred_resolutions,
    reconcile_unsettled_mapping_replays,
)
from services.resolution.event_tail import TailScan
from services.resolution.mapping_enumerator import (
    INDEX_COLD,
    INDEX_UNDECODABLE,
    INDEX_UNPINNED,
    _event_topic0,
    clear_enumeration_cache,
    enumerate_mapping_allowlist,
    enumerate_mapping_allowlist_from_index,
)
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from tests.conftest import SessionFactory, requires_postgres
from tests.support.hypersync_fakes import _FakeHypersyncModule

pytestmark = requires_postgres

TIMELOCK = "0x" + "d8" * 20
SAFE = "0x" + "ce" * 20
EXECUTOR = "0x" + "7a" * 20
CANCELLER = "0x" + "05" * 20
GRANTED = "RoleGranted(bytes32,address,address)"
REVOKED = "RoleRevoked(bytes32,address,address)"
GRANT_T0 = _event_topic0(GRANTED)
REVOKE_T0 = _event_topic0(REVOKED)
PROPOSER_ROLE = "0x" + "b0" * 32
PIN = 20_000


def _spec(signature: str, direction: str) -> dict[str, Any]:
    return {
        "mapping_name": "_roles",
        "event_signature": signature,
        "event_name": signature.split("(")[0],
        "key_position": 1,
        "indexed_positions": [0, 1, 2],
        "direction": direction,
        "writer_function": "",
        "value_position": None,
    }


SPECS: list[Any] = [_spec(GRANTED, "add"), _spec(REVOKED, "remove")]


def _word(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def _topics(topic0: str, member: str) -> list[str]:
    return [topic0, PROPOSER_ROLE, _word(member), _word(SAFE)]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, db_session):
    monkeypatch.setenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "0")
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    monkeypatch.setattr("db.models.SessionLocal", SessionFactory(db_session))
    monkeypatch.setitem(sys.modules, "hypersync", _FakeHypersyncModule())
    monkeypatch.setattr("services.resolution.creation_block_floor.resolve_scan_floor", lambda *_a, **_k: 100)
    clear_enumeration_cache()
    yield
    clear_enumeration_cache()


class _HyperSync:
    """The HyperSync client wire: serves ``logs`` once, or raises ``error`` on every request."""

    def __init__(self, logs: list[Any] | None = None, error: Exception | None = None) -> None:
        self.logs = logs or []
        self.error = error
        self.built = 0

    def install(self, monkeypatch) -> _HyperSync:
        def _build(_module, *, url, bearer_token):
            self.built += 1
            return self

        monkeypatch.setattr("services.resolution.hypersync_bound.build_hypersync_client", _build)
        return self

    async def get(self, _query):
        if self.error is not None:
            raise self.error
        return SimpleNamespace(data=list(self.logs), next_block=None)


def _hs_log(topic0: str, member: str, block: int) -> SimpleNamespace:
    return SimpleNamespace(topics=_topics(topic0, member), data="0x", block_number=block)


def _cursor(
    session,
    topic0: str,
    *,
    last: int = PIN,
    complete: bool = True,
    chain_id: int = 1,
    address: str = TIMELOCK,
    enrollment_basis: str | None = ENROLLMENT_BASIS_PREDICATE_HINT,
    first_basis: str = "creation_block_minus_one",
) -> None:
    session.add(
        IndexedEventCursor(
            chain_id=chain_id,
            event_address=address.lower(),
            topic0=topic0,
            last_indexed_block=last,
            backfill_complete=complete,
            first_indexed_block=0,
            first_indexed_block_basis=first_basis,
            enrollment_basis=enrollment_basis,
        )
    )
    session.commit()


def _warm(session, *, last: int = PIN, chain_id: int = 1, address: str = TIMELOCK) -> None:
    for topic0 in (GRANT_T0, REVOKE_T0):
        _cursor(session, topic0, last=last, chain_id=chain_id, address=address)


_LOG_SEQ = {"n": 0}


def _row(
    session,
    topic0: str,
    member: str,
    block: int,
    *,
    chain_id: int = 1,
    address: str = TIMELOCK,
    data_hex: str | None = None,
) -> None:
    _LOG_SEQ["n"] += 1
    session.add(
        IndexedEventLog(
            chain_id=chain_id,
            event_address=address.lower(),
            topic0=topic0,
            tx_hash=_LOG_SEQ["n"].to_bytes(32, "big"),
            log_index=0,
            block_number=block,
            block_hash=b"\x01" * 32,
            transaction_index=0,
            topics=_topics(topic0, member),
            data_words=[],
            data_hex=data_hex,
        )
    )
    session.commit()


def _tail_log(topic0: str, member: str, block: int, *, data_hex: str | None = None) -> FetchedEventLog:
    return FetchedEventLog(
        tx_hash=b"\x02" * 32,
        log_index=0,
        block_number=block,
        block_hash=b"\x03" * 32,
        transaction_index=0,
        topics=_topics(topic0, member),
        data_words=[],
        data_hex=data_hex,
    )


def _complete_tail(*logs: FetchedEventLog):
    calls: list[tuple[int, int]] = []

    def _scan(_address, _topics, frontier, block):
        calls.append((frontier, block))
        return TailScan(complete=True, from_block=frontier + 1, to_block=block, logs=tuple(logs))

    return _scan, calls


def _failed_tail(_address, _topics, frontier, block):
    return TailScan(complete=False, from_block=frontier + 1, to_block=block, reason="tail_scan_failed")


def _read(db_session, *, chain_id: int = 1, block: int | None = PIN, tail=None):
    return enumerate_mapping_allowlist_from_index(
        PostgresEventLogRepo(db_session),
        chain_id=chain_id,
        contract_address=TIMELOCK,
        writer_specs=SPECS,
        block=block,
        tail=tail,
    )


def _members(principals) -> list[str]:
    return sorted(p["address"] for p in principals)


def _replay(*, rpc_url: str | None = None, block: int | None = PIN, chain_id: int = 1):
    nodes: dict = {}
    edges: dict = {}
    replay = recursive._replay_mapping_principals(
        address=TIMELOCK,
        mapping_specs=SPECS,
        contract_node_id=f"address:{TIMELOCK}",
        depth=0,
        nodes=nodes,
        edges=edges,
        chain_id=chain_id,
        rpc_url=rpc_url,
        resolution_block=block,
    )
    return replay, nodes, edges


def _member_edges(edges: dict) -> list[str]:
    return sorted(e["to_id"] for e in edges.values() if e["relation"] == "mapping_member")


# Durable read ---------------------------------------------------------------------------------------------------------


def test_warm_cursors_covering_the_pin_read_members_from_the_index(db_session):
    _warm(db_session, last=PIN + 50)
    _row(db_session, GRANT_T0, SAFE, 150)
    _row(db_session, GRANT_T0, EXECUTOR, 160)
    _row(db_session, REVOKE_T0, EXECUTOR, 170)
    # Past the pin but inside the frontier: indexed writes are never cut at the finality pin.
    _row(db_session, GRANT_T0, CANCELLER, PIN + 10)

    result = _read(db_session)

    assert result.complete
    assert _members(result.principals) == sorted([SAFE, CANCELLER])
    assert result.topic0s == tuple(sorted([GRANT_T0, REVOKE_T0]))


def test_a_complete_tail_licenses_complete_and_cuts_rows_at_the_least_advanced_cursor(db_session):
    _cursor(db_session, GRANT_T0, last=PIN - 100)
    _cursor(db_session, REVOKE_T0, last=PIN + 20)
    _row(db_session, GRANT_T0, SAFE, 150)
    # Indexed by the further-ahead cursor, past the pin; folded before the tail it would replay out of order.
    _row(db_session, REVOKE_T0, SAFE, PIN + 10)
    tail, calls = _complete_tail(_tail_log(GRANT_T0, EXECUTOR, PIN - 5))

    result = _read(db_session, tail=tail)

    assert calls == [(PIN - 100, PIN)]
    assert result.complete
    assert _members(result.principals) == sorted([SAFE, EXECUTOR])


def test_a_failed_or_missing_tail_is_not_complete(db_session):
    _warm(db_session, last=PIN - 100)
    _row(db_session, GRANT_T0, SAFE, 150)

    assert not _read(db_session, tail=_failed_tail).complete
    assert _read(db_session, tail=_failed_tail).reason == "tail_scan_failed"
    assert not _read(db_session, tail=None).complete


@pytest.mark.parametrize(
    "cursor_kwargs",
    [
        {"complete": False},
        {"first_basis": "explicit_seed"},
        {"enrollment_basis": "not_determined"},
        {"enrollment_basis": "tracked_topics_asserted"},
    ],
)
def test_cold_or_ineligible_cursors_are_not_complete(db_session, cursor_kwargs):
    _cursor(db_session, GRANT_T0)
    _cursor(db_session, REVOKE_T0, **cursor_kwargs)
    _row(db_session, GRANT_T0, SAFE, 150)

    result = _read(db_session)

    assert not result.complete
    assert result.reason == INDEX_COLD


def test_a_missing_topic_cursor_is_cold(db_session):
    _cursor(db_session, GRANT_T0)

    assert _read(db_session).reason == INDEX_COLD


def test_an_unpinned_pass_is_not_complete_over_warm_cursors(db_session):
    _warm(db_session)

    result = _read(db_session, block=None)

    assert not result.complete
    assert result.reason == INDEX_UNPINNED


def test_an_undecodable_row_or_tail_log_is_not_complete(db_session):
    _warm(db_session, last=PIN - 10)
    _row(db_session, GRANT_T0, SAFE, 150)
    tail, _ = _complete_tail(_tail_log(GRANT_T0, EXECUTOR, PIN - 5, data_hex="0xabcd"))
    assert _read(db_session, tail=tail).reason == INDEX_UNDECODABLE

    _row(db_session, REVOKE_T0, SAFE, 160, data_hex="0x1234")
    tail, _ = _complete_tail()
    result = _read(db_session, tail=tail)
    assert not result.complete
    assert result.reason == INDEX_UNDECODABLE


def test_index_reads_never_cross_chains(db_session):
    # 0x80ce-style: the same address on mainnet and Base with different holders.
    _warm(db_session, chain_id=8453)
    _row(db_session, GRANT_T0, EXECUTOR, 150, chain_id=8453)
    assert _read(db_session, chain_id=1).reason == INDEX_COLD

    _warm(db_session, chain_id=1)
    _row(db_session, GRANT_T0, SAFE, 150, chain_id=1)
    assert _members(_read(db_session, chain_id=1).principals) == [SAFE]
    assert _members(_read(db_session, chain_id=8453).principals) == [EXECUTOR]


@pytest.mark.parametrize(
    "sequence",
    [
        # grant -> revoke -> grant
        [(GRANT_T0, SAFE, 150), (REVOKE_T0, SAFE, 160), (GRANT_T0, SAFE, 170), (GRANT_T0, EXECUTOR, 180)],
        # A revoke as the last log, landing in the tail.
        [(GRANT_T0, SAFE, 150), (GRANT_T0, CANCELLER, 155), (REVOKE_T0, CANCELLER, PIN - 99)],
    ],
)
def test_index_and_hypersync_folds_agree(db_session, sequence):
    hypersync = asyncio.run(
        enumerate_mapping_allowlist(
            TIMELOCK,
            SPECS,
            from_block=0,
            client=_HyperSync([_hs_log(t, m, b) for t, m, b in sequence]),
            hypersync_module=_FakeHypersyncModule(),
        )
    )

    warm_block = PIN - 100
    _warm(db_session, last=warm_block)
    for topic0, member, block in sequence:
        if block <= warm_block:
            _row(db_session, topic0, member, block)
    tail, _ = _complete_tail(*[_tail_log(t, m, b) for t, m, b in sequence if b > warm_block])
    indexed = _read(db_session, tail=tail)

    assert hypersync["status"] == "complete"
    assert indexed.complete
    key = lambda p: (p["address"], p["mapping_name"])  # noqa: E731
    assert sorted(indexed.principals, key=key) == sorted(hypersync["principals"], key=key)


def test_index_and_hypersync_folds_agree_on_a_key_in_event_data(db_session):
    allowed, disallowed = "Allowed(address)", "Disallowed(address)"
    specs: list[Any] = [
        {**_spec(allowed, "add"), "key_position": 0, "indexed_positions": []},
        {**_spec(disallowed, "remove"), "key_position": 0, "indexed_positions": []},
    ]
    add_t0, remove_t0 = _event_topic0(allowed), _event_topic0(disallowed)
    sequence = [(add_t0, SAFE, 150), (add_t0, EXECUTOR, 160), (remove_t0, SAFE, 170)]
    hypersync = asyncio.run(
        enumerate_mapping_allowlist(
            TIMELOCK,
            specs,
            from_block=0,
            client=_HyperSync([SimpleNamespace(topics=[t], data=_word(m), block_number=b) for t, m, b in sequence]),
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    for topic0 in (add_t0, remove_t0):
        _cursor(db_session, topic0)
    for i, (topic0, member, block) in enumerate(sequence):
        db_session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=TIMELOCK,
                topic0=topic0,
                tx_hash=(10_000 + i).to_bytes(32, "big"),
                log_index=0,
                block_number=block,
                block_hash=b"\x01" * 32,
                transaction_index=0,
                topics=[topic0],
                data_words=[_word(member)],
            )
        )
    db_session.commit()
    indexed = enumerate_mapping_allowlist_from_index(
        PostgresEventLogRepo(db_session),
        chain_id=1,
        contract_address=TIMELOCK,
        writer_specs=specs,
        block=PIN,
        tail=None,
    )

    assert indexed.complete and hypersync["status"] == "complete"
    assert indexed.principals == hypersync["principals"]
    assert _members(indexed.principals) == [EXECUTOR]


# Source selection in the graph replay ---------------------------------------------------------------------------------


def test_replay_reads_the_index_without_constructing_hypersync(db_session, monkeypatch):
    monkeypatch.setenv("ENVIO_API_TOKEN", "rejected-token")
    hypersync = _HyperSync(error=RuntimeError("403 Forbidden")).install(monkeypatch)
    _warm(db_session)
    _row(db_session, GRANT_T0, SAFE, 150)

    replay, nodes, edges = _replay()

    assert replay == recursive.MappingReplay("complete", "event_index", None)
    assert hypersync.built == 0
    assert _member_edges(edges) == [f"address:{SAFE}"]


def test_replay_reads_the_index_with_no_hypersync_token(db_session):
    _warm(db_session)
    _row(db_session, GRANT_T0, SAFE, 150)

    replay, _nodes, edges = _replay()

    assert replay.source == "event_index"
    assert _member_edges(edges) == [f"address:{SAFE}"]


def _getlogs_wire(monkeypatch, logs: list[dict] | Exception):
    calls: list[list] = []

    def _rpc(_url, method, params, **_kw):
        assert method == "eth_getLogs"
        calls.append(params)
        if isinstance(logs, Exception):
            raise logs
        return logs

    monkeypatch.setattr("services.resolution.event_tail.rpc_request", _rpc)
    return calls


def _rpc_log(topic0: str, member: str, block: int) -> dict:
    return {
        "address": TIMELOCK,
        "topics": _topics(topic0, member),
        "data": "0x",
        "blockNumber": hex(block),
        "blockHash": "0x" + "11" * 32,
        "transactionHash": "0x" + "22" * 32,
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": False,
    }


def test_replay_completes_a_lagging_index_with_a_tail_over_rpc(db_session, monkeypatch):
    hypersync = _HyperSync().install(monkeypatch)
    _warm(db_session, last=PIN - 100)
    _row(db_session, GRANT_T0, SAFE, 150)
    calls = _getlogs_wire(monkeypatch, [_rpc_log(GRANT_T0, EXECUTOR, PIN - 50)])

    replay, _nodes, edges = _replay(rpc_url="http://rpc.test")

    assert replay.source == "event_index" and replay.status == "complete"
    assert calls and hypersync.built == 0
    assert _member_edges(edges) == sorted([f"address:{SAFE}", f"address:{EXECUTOR}"])


def test_a_failed_tail_falls_back_to_hypersync_and_awaits_the_missed_block(db_session, monkeypatch):
    monkeypatch.setenv("ENVIO_API_TOKEN", "token")
    hypersync = _HyperSync([_hs_log(GRANT_T0, SAFE, 150)]).install(monkeypatch)
    _warm(db_session, last=PIN - 100)
    _getlogs_wire(monkeypatch, RuntimeError("upstream 503"))

    replay, _nodes, edges = _replay(rpc_url="http://rpc.test")

    assert hypersync.built == 1
    assert replay.status == "complete" and replay.source == "hypersync"
    assert replay.awaits is None
    assert _member_edges(edges) == [f"address:{SAFE}"]

    hypersync.error = RuntimeError("429 Too Many Requests")
    clear_enumeration_cache()
    replay, _nodes, edges = _replay(rpc_url="http://rpc.test")
    assert replay.status == "error"
    assert replay.awaits == {
        "chain_id": 1,
        "event_address": TIMELOCK,
        "topic0s": sorted([GRANT_T0, REVOKE_T0]),
        "covers_block": PIN,
    }


@pytest.mark.parametrize("cold", ["absent", "backfilling", "explicit_seed", "not_determined"])
def test_cold_or_ineligible_index_falls_back_to_hypersync(db_session, monkeypatch, cold):
    monkeypatch.setenv("ENVIO_API_TOKEN", "token")
    hypersync = _HyperSync([_hs_log(GRANT_T0, EXECUTOR, 150)]).install(monkeypatch)
    _cursor(db_session, GRANT_T0)
    if cold == "backfilling":
        _cursor(db_session, REVOKE_T0, complete=False)
    elif cold == "explicit_seed":
        _cursor(db_session, REVOKE_T0, first_basis="explicit_seed")
    elif cold == "not_determined":
        _cursor(db_session, REVOKE_T0, enrollment_basis="not_determined")
    # Present in the index but unproven; the published set comes from HyperSync.
    _row(db_session, GRANT_T0, SAFE, 150)

    replay, _nodes, edges = _replay()

    assert hypersync.built == 1
    assert replay.status == "complete" and replay.source == "hypersync"
    assert _member_edges(edges) == [f"address:{EXECUTOR}"]


def test_cold_index_with_hypersync_403_is_error_with_no_members_and_awaits(db_session, monkeypatch):
    monkeypatch.setenv("ENVIO_API_TOKEN", "bad-token")
    _HyperSync(error=RuntimeError("403 Forbidden: invalid API token")).install(monkeypatch)

    replay, nodes, edges = _replay()

    assert replay.status == "error"
    assert replay.source == "hypersync"
    assert edges == {} and nodes == {}
    assert replay.awaits == {"chain_id": 1, "event_address": TIMELOCK, "topic0s": sorted([GRANT_T0, REVOKE_T0])}


def test_cold_index_with_no_token_is_skipped_and_awaits(db_session):
    replay, _nodes, edges = _replay()

    assert replay.status == "skipped" and replay.source == "none"
    assert edges == {}
    assert replay.awaits is not None


def test_an_undecodable_row_falls_back_and_awaits_nothing(db_session, monkeypatch):
    monkeypatch.setenv("ENVIO_API_TOKEN", "token")
    _HyperSync(error=RuntimeError("403")).install(monkeypatch)
    _warm(db_session)
    _row(db_session, GRANT_T0, SAFE, 150, data_hex="0xab")

    replay, _nodes, edges = _replay()

    assert replay.status == "error" and replay.source == "hypersync"
    assert edges == {}
    # The index can't settle it by advancing, so nothing would re-run it.
    assert replay.awaits is None


def test_index_replay_keeps_the_self_membership_skip_and_edge_shape(db_session):
    _warm(db_session)
    _row(db_session, GRANT_T0, TIMELOCK, 140)
    _row(db_session, GRANT_T0, SAFE, 150)

    _replay_result, nodes, edges = _replay()

    assert list(edges.values()) == [
        {
            "from_id": f"address:{TIMELOCK}",
            "to_id": f"address:{SAFE}",
            "relation": "mapping_member",
            "label": "_roles",
            "source_controller_id": "mapping:_roles",
            "notes": [],
        }
    ]
    assert f"address:{TIMELOCK}" not in nodes
    assert nodes[f"address:{SAFE}"]["details"]["mapping_name"] == "_roles"


# Refresh re-walks unsettled nested replays ----------------------------------------------------------------------------


def _bundle(address: str, name: str, *, predicate_trees: dict | None = None, controllers: dict | None = None) -> Any:
    bundle: dict[str, Any] = {
        "analysis": {"subject": {"address": address, "name": name}},
        "tracking_plan": {"schema_version": "0.1", "contract_address": address, "tracked_controllers": []},
        "snapshot": {
            "schema_version": "0.1",
            "contract_address": address,
            "contract_name": name,
            "block_number": 1,
            "controller_values": controllers or {},
        },
    }
    if predicate_trees is not None:
        bundle["predicate_trees"] = predicate_trees
    return cast(LoadedArtifacts, bundle)


def _timelock_trees() -> dict:
    hints = [
        {
            "topic0": GRANT_T0 if spec["direction"] == "add" else REVOKE_T0,
            "direction": spec["direction"],
            "event_signature": spec["event_signature"],
            "event_name": spec["event_name"],
            "mapping_name": "_roles",
            "key_position": 1,
            "indexed_positions": [0, 1, 2],
            "value_position": None,
            "writer_function": "grantRole(bytes32,address)",
        }
        for spec in SPECS
    ]
    leaf = {
        "kind": "membership",
        "operator": "truthy",
        "authority_role": "caller_authority",
        "set_descriptor": {"kind": "mapping_membership", "storage_var": "_roles", "enumeration_hint": hints},
    }
    return {"schema_version": "semantic", "trees": {"schedule()": {"op": "LEAF", "leaf": leaf}}}


def _node(address: str, depth: int, details: dict) -> dict:
    return {
        "id": f"address:{address}",
        "address": address,
        "node_type": "contract",
        "resolved_type": "timelock",
        "label": "Timelock",
        "contract_name": "Timelock",
        "depth": depth,
        "analyzed": True,
        "details": {"address": address, **details},
        "artifacts": {},
    }


def test_refresh_rewalks_an_unsettled_nested_replay_without_rematerializing(db_session, monkeypatch):
    root = "0x" + "11" * 20
    middle = "0x" + "22" * 20
    settled = "0x" + "33" * 20
    stale_member = "0x" + "99" * 20
    cold_lock = "0x" + "44" * 20
    # The unsettled timelock's index is now warm; ``cold_lock``'s isn't.
    _warm(db_session)
    _row(db_session, GRANT_T0, SAFE, 150)

    replayed: list[str] = []
    real_replay = recursive._replay_mapping_principals

    def _spy(**kwargs):
        replayed.append(kwargs["address"])
        return real_replay(**kwargs)

    monkeypatch.setattr(recursive, "_replay_mapping_principals", _spy)
    monkeypatch.setattr(
        recursive,
        "_materialize_contract_artifacts",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("nested artifacts must come from the override")),
    )
    monkeypatch.setattr(
        recursive,
        "classify_resolved_address_with_status",
        lambda _rpc, addr, **_k: ("timelock", {"address": addr}, True),
    )
    pins: list[int | None] = []

    def _pin(_rpc, _block, *, chain_id=None):
        pins.append(chain_id)
        return PIN

    monkeypatch.setattr("services.resolution.capability_resolver._resolve_resolution_block", _pin)

    initial_graph = {
        "schema_version": "0.1",
        "root_contract_address": root,
        "max_depth": 6,
        "nodes": [
            _node(root, 0, {}),
            _node(middle, 1, {}),
            _node(TIMELOCK, 2, {"mapping_enumeration_status": "error", "mapping_enumeration_source": "hypersync"}),
            _node(settled, 2, {"mapping_enumeration_status": "complete", "mapping_enumeration_source": "hypersync"}),
            _node(cold_lock, 3, {"mapping_enumeration_status": "skipped", "mapping_enumeration_source": "none"}),
            {
                "id": f"address:{stale_member}",
                "address": stale_member,
                "node_type": "principal",
                "resolved_type": "unknown",
                "label": "_roles",
                "contract_name": None,
                "depth": 3,
                "analyzed": False,
                "details": {"address": stale_member},
                "artifacts": {},
            },
        ],
        "edges": [
            {
                "from_id": f"address:{TIMELOCK}",
                "to_id": f"address:{stale_member}",
                "relation": "mapping_member",
                "label": "_roles",
                "source_controller_id": "mapping:_roles",
                "notes": [],
            }
        ],
    }

    graph, _nested = resolve_control_graph(
        root_artifacts=_bundle(root, "Root"),
        rpc_url="http://rpc.test",
        chain_id=1,
        nested_artifacts_override={
            middle: _bundle(middle, "Middle"),
            TIMELOCK: _bundle(TIMELOCK, "Timelock", predicate_trees=_timelock_trees()),
            settled: _bundle(settled, "Settled", predicate_trees=_timelock_trees()),
            cold_lock: _bundle(cold_lock, "ColdTimelock", predicate_trees=_timelock_trees()),
        },
        initial_graph=cast(Any, initial_graph),
    )

    assert replayed == [TIMELOCK, cold_lock]
    assert pins == [1]
    nodes = {n["address"]: n for n in graph["nodes"]}
    details = nodes[TIMELOCK]["details"]
    assert details["mapping_enumeration_status"] == "complete"
    assert details["mapping_enumeration_source"] == "event_index"
    assert "mapping_enumeration_awaits" not in details
    assert nodes[settled]["details"]["mapping_enumeration_source"] == "hypersync"
    # A complete replay replaces, never unions with, the members a prior partial scan published.
    members = sorted(e["to_id"] for e in graph["edges"] if e["relation"] == "mapping_member")
    assert members == [f"address:{SAFE}"]
    assert stale_member not in nodes
    assert cast(dict, nodes[cold_lock]["details"]["mapping_enumeration_awaits"])["event_address"] == cold_lock


def _rewalk(monkeypatch, seeded_details: dict, override: dict) -> dict:
    root = "0x" + "11" * 20
    monkeypatch.setattr(
        recursive,
        "_materialize_contract_artifacts",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("no re-materialization")),
    )
    monkeypatch.setattr(
        recursive,
        "classify_resolved_address_with_status",
        lambda _rpc, addr, **_k: ("timelock", {"address": addr}, True),
    )
    monkeypatch.setattr("services.resolution.capability_resolver._resolve_resolution_block", lambda *_a, **_k: PIN)
    graph, _ = resolve_control_graph(
        root_artifacts=_bundle(root, "Root"),
        rpc_url="http://rpc.test",
        chain_id=1,
        nested_artifacts_override=override,
        initial_graph=cast(
            Any,
            {
                "schema_version": "0.1",
                "root_contract_address": root,
                "max_depth": 6,
                "nodes": [_node(root, 0, {}), _node(TIMELOCK, 2, seeded_details)],
                "edges": [],
            },
        ),
    )
    return {n["address"]: n for n in graph["nodes"]}[TIMELOCK]["details"]


def test_an_unsettled_node_without_its_artifacts_drops_its_await(monkeypatch):
    details = _rewalk(monkeypatch, _awaiting(), override={})

    # No replay ran, so the status stands, but nothing here can settle the await.
    assert details["mapping_enumeration_status"] == "error"
    assert "mapping_enumeration_awaits" not in details


def test_an_unsettled_node_whose_trees_name_no_writer_clears_its_replay_keys(monkeypatch):
    details = _rewalk(
        monkeypatch, _awaiting(), override={TIMELOCK: _bundle(TIMELOCK, "Timelock", predicate_trees={"trees": {}})}
    )

    assert not {"mapping_enumeration_status", "mapping_enumeration_source", "mapping_enumeration_awaits"} & set(details)


def test_an_unsettled_node_without_its_trees_keeps_its_status_and_drops_its_await(monkeypatch):
    # The policy stage's nested bundles carry no trees unless hydrated for a replay.
    details = _rewalk(monkeypatch, _awaiting(), override={TIMELOCK: _bundle(TIMELOCK, "Timelock")})

    assert details["mapping_enumeration_status"] == "error"
    assert details["mapping_enumeration_source"] == "hypersync"
    assert "mapping_enumeration_awaits" not in details


def test_an_unsettled_node_beyond_the_depth_horizon_drops_its_await(monkeypatch):
    seeded = _awaiting()
    monkeypatch.setattr(
        recursive, "_maybe_queue_address", lambda *_a, **_k: pytest.fail("a node past max_depth is not re-walked")
    )
    root = "0x" + "11" * 20
    monkeypatch.setattr(
        recursive,
        "classify_resolved_address_with_status",
        lambda _rpc, addr, **_k: ("timelock", {"address": addr}, True),
    )
    graph, _ = resolve_control_graph(
        root_artifacts=_bundle(root, "Root"),
        rpc_url="http://rpc.test",
        chain_id=1,
        max_depth=1,
        nested_artifacts_override={TIMELOCK: _bundle(TIMELOCK, "Timelock", predicate_trees=_timelock_trees())},
        initial_graph=cast(
            Any,
            {"nodes": [_node(root, 0, {}), _node(TIMELOCK, 2, seeded)], "edges": []},
        ),
    )

    details = {n["address"]: n for n in graph["nodes"]}[TIMELOCK]["details"]
    assert details["mapping_enumeration_status"] == "error"
    assert "mapping_enumeration_awaits" not in details


def test_the_root_replays_from_its_trees_and_keeps_its_status_without_them(db_session, monkeypatch):
    root = TIMELOCK
    _warm(db_session)
    _row(db_session, GRANT_T0, SAFE, 150)
    monkeypatch.setattr(
        recursive,
        "classify_resolved_address_with_status",
        lambda _rpc, addr, **_k: ("timelock", {"address": addr}, True),
    )
    monkeypatch.setattr("services.resolution.capability_resolver._resolve_resolution_block", lambda *_a, **_k: PIN)
    seeded = cast(Any, {"nodes": [_node(root, 0, _awaiting())], "edges": []})

    without_trees, _ = resolve_control_graph(
        root_artifacts=_bundle(root, "Timelock"), rpc_url="http://rpc.test", chain_id=1, initial_graph=seeded
    )
    with_trees, _ = resolve_control_graph(
        root_artifacts=_bundle(root, "Timelock", predicate_trees=_timelock_trees()),
        rpc_url="http://rpc.test",
        chain_id=1,
        initial_graph=seeded,
    )

    kept = without_trees["nodes"][0]["details"]
    assert kept["mapping_enumeration_status"] == "error" and "mapping_enumeration_awaits" not in kept
    replayed = {n["address"]: n for n in with_trees["nodes"]}[root]["details"]
    assert replayed["mapping_enumeration_status"] == "complete"
    assert replayed["mapping_enumeration_source"] == "event_index"
    assert [e["to_id"] for e in with_trees["edges"] if e["relation"] == "mapping_member"] == [f"address:{SAFE}"]
    assert "mapping_enumeration_awaits" not in replayed


def test_a_seeded_rewalk_does_not_jump_ahead_of_shallower_contracts(monkeypatch):
    root = "0x" + "11" * 20
    child = "0x" + "22" * 20
    order: list[str] = []

    def _classify(_rpc, addr, **_k):
        order.append(addr)
        return "timelock", {"address": addr}, True

    monkeypatch.setattr(recursive, "classify_resolved_address_with_status", _classify)
    monkeypatch.setattr("services.resolution.capability_resolver._resolve_resolution_block", lambda *_a, **_k: PIN)
    controllers = {
        "state_variable:owner": {
            "source": "owner",
            "value": child,
            "resolved_type": "contract",
            "details": {"address": child},
            "authority_provenance": "caller_gate",
        }
    }
    resolve_control_graph(
        root_artifacts=_bundle(root, "Root", controllers=controllers),
        rpc_url="http://rpc.test",
        chain_id=1,
        nested_artifacts_override={
            child: _bundle(child, "Child"),
            TIMELOCK: _bundle(TIMELOCK, "Timelock", predicate_trees=_timelock_trees()),
        },
        initial_graph=cast(Any, {"nodes": [_node(root, 0, {}), _node(TIMELOCK, 2, _awaiting())], "edges": []}),
    )

    assert order.index(child) < order.index(TIMELOCK)


def test_policy_hydrates_trees_only_for_unsettled_nested_replays(monkeypatch):
    from unittest.mock import MagicMock

    from db.nested_artifacts import artifact_key
    from workers import policy_worker

    unsettled, settled, failed = TIMELOCK, "0x" + "33" * 20, "0x" + "44" * 20
    rows = [SimpleNamespace(name=artifact_key(addr, "snapshot")) for addr in (unsettled, settled, failed)]
    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = rows
    monkeypatch.setattr(policy_worker, "get_artifact", lambda *_a, **_kw: {"controller_values": {}})
    monkeypatch.setattr(
        "db.contract_materializations.find_by_address",
        lambda _s, *, chain, address: SimpleNamespace(address=address, analysis={"subject": {}}, tracking_plan={}),
    )
    unreadable = "0x" + "55" * 20
    rows.append(SimpleNamespace(name=artifact_key(unreadable, "snapshot")))
    trees = {unsettled: _timelock_trees(), failed: {"schema_version": "semantic", "error": "build failed"}}
    hydrated: list[str] = []

    def _hydrate(row):
        hydrated.append(row.address)
        if row.address == unreadable:
            raise RuntimeError("blob unreadable")
        return trees.get(row.address)

    monkeypatch.setattr("db.contract_materializations.hydrate_predicate_trees", _hydrate)
    stored_graph = {
        "nodes": [
            _node(unsettled, 1, _awaiting()),
            _node(settled, 1, {"mapping_enumeration_status": "complete"}),
            _node(failed, 1, {"mapping_enumeration_status": "incomplete_timeout"}),
            _node(unreadable, 1, {"mapping_enumeration_status": "error"}),
        ]
    }

    bundles = policy_worker._load_nested_artifacts(
        session,
        "job-1",
        chain="ethereum",
        replay_trees_for=recursive.unsettled_replay_addresses(stored_graph),
    )

    assert sorted(hydrated) == sorted([unsettled, failed, unreadable])
    # An unreadable blob degrades that node's replay, never the whole stage.
    assert "predicate_trees" not in bundles[unreadable]
    assert bundles[unsettled].get("predicate_trees") == {"trees": _timelock_trees()["trees"]}
    assert "predicate_trees" not in bundles[settled]
    # A failed build is not determined, never an empty tree set.
    assert "predicate_trees" not in bundles[failed]


def test_a_walk_with_no_replay_takes_no_pin(monkeypatch):
    monkeypatch.setattr(
        "services.resolution.capability_resolver._resolve_resolution_block",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("no replay, no eth_blockNumber")),
    )
    monkeypatch.setattr(
        recursive,
        "classify_resolved_address_with_status",
        lambda _rpc, addr, **_k: ("contract", {"address": addr}, True),
    )

    graph, _ = resolve_control_graph(root_artifacts=_bundle("0x" + "11" * 20, "Root"), rpc_url="http://x", chain_id=1)

    assert len(graph["nodes"]) == 1


# Reconciler --------------------------------------------------------------------------------------------------------


def _job_with_graph(db_session, address: str, node_details: list[dict], *, chain: str = "ethereum") -> Job:
    db_session.query(Contract).filter(func.lower(Contract.address) == address.lower()).delete()
    db_session.query(Job).filter(func.lower(Job.address) == address.lower()).delete()
    db_session.commit()
    job = Job(address=address, status=JobStatus.completed, stage=JobStage.done, request={"chain": chain})
    db_session.add(job)
    db_session.flush()
    contract = Contract(address=address, chain=chain, job_id=job.id)
    db_session.add(contract)
    db_session.flush()
    for i, details in enumerate(node_details):
        db_session.add(
            ControlGraphNode(
                contract_id=contract.id,
                address=str(details.get("address") or f"0x{i:040x}"),
                node_type="contract",
                depth=1,
                analyzed=True,
                details=details,
            )
        )
    db_session.commit()
    return job


def _awaiting(status: str = "error", *, chain_id: int = 1, covers_block: int | None = None) -> dict:
    awaits: dict[str, Any] = {
        "chain_id": chain_id,
        "event_address": TIMELOCK,
        "topic0s": sorted([GRANT_T0, REVOKE_T0]),
    }
    if covers_block is not None:
        awaits["covers_block"] = covers_block
    return {
        "address": TIMELOCK,
        "mapping_enumeration_status": status,
        "mapping_enumeration_source": "hypersync",
        "mapping_enumeration_awaits": awaits,
    }


def test_reconciler_reenqueues_an_unsettled_replay_once_its_cursors_warm(db_session):
    job = _job_with_graph(db_session, "0x" + "a1" * 20, [_awaiting()])
    _cursor(db_session, GRANT_T0)
    _cursor(db_session, REVOKE_T0, complete=False)

    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 0

    db_session.query(IndexedEventCursor).update({"backfill_complete": True})
    db_session.commit()
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 1
    db_session.refresh(job)
    assert (job.stage, job.status) == (JobStage.policy, JobStatus.queued)
    # Queued now, so it's no longer a candidate.
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 0


def test_a_settled_rerun_is_not_selected_again(db_session, monkeypatch):
    from services.resolution.graph_tables import replace_control_graph_rows

    job = _job_with_graph(db_session, "0x" + "a9" * 20, [_awaiting()])
    contract = db_session.query(Contract).filter(Contract.job_id == job.id).one()
    _warm(db_session)
    _row(db_session, GRANT_T0, SAFE, 150)
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 1

    # The re-enqueued policy refresh: re-walk the seeded graph and rewrite its rows, then finish the job.
    details = _rewalk(
        monkeypatch,
        _awaiting(),
        override={TIMELOCK: _bundle(TIMELOCK, "Timelock", predicate_trees=_timelock_trees())},
    )
    assert details["mapping_enumeration_status"] == "complete"
    replace_control_graph_rows(
        db_session,
        contract_id=contract.id,
        deployment_address=None,
        resolved_graph={"nodes": [{"address": TIMELOCK, "details": details}], "edges": []},
    )
    job.stage, job.status = JobStage.done, JobStatus.completed
    db_session.commit()

    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 0


def test_reconciler_skips_settled_cold_ineligible_and_other_chain_replays(db_session):
    _job_with_graph(db_session, "0x" + "a2" * 20, [{**_awaiting("complete")}])
    _job_with_graph(db_session, "0x" + "a3" * 20, [_awaiting(chain_id=8453)])
    _warm(db_session, chain_id=1)
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 0
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=8453) == 0

    db_session.query(IndexedEventCursor).delete()
    db_session.commit()
    _job_with_graph(db_session, "0x" + "a4" * 20, [_awaiting()])
    _cursor(db_session, GRANT_T0)
    _cursor(db_session, REVOKE_T0, first_basis="explicit_seed")
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 0


def test_reconciler_waits_for_the_frontier_a_failed_tail_missed(db_session):
    job = _job_with_graph(db_session, "0x" + "a5" * 20, [_awaiting(covers_block=PIN)])
    _warm(db_session, last=PIN - 1)
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 0

    db_session.query(IndexedEventCursor).update({"last_indexed_block": PIN})
    db_session.commit()
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 1
    db_session.refresh(job)
    assert job.status == JobStatus.queued


def test_reconciler_honours_the_active_job_guard(db_session):
    address = "0x" + "a6" * 20
    _job_with_graph(db_session, address, [_awaiting()])
    db_session.add(
        Job(address=address, status=JobStatus.processing, stage=JobStage.policy, request={"chain": "ethereum"})
    )
    db_session.commit()
    _warm(db_session)

    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 0


def test_the_marker_arm_ignores_graph_awaits(db_session):
    address = "0x" + "a7" * 20
    job = _job_with_graph(db_session, address, [_awaiting()])
    contract = db_session.query(Contract).filter(Contract.job_id == job.id).one()
    db_session.add(
        EffectiveFunction(
            contract_id=contract.id,
            function_name="pause",
            abi_signature="pause()",
            selector="0x8456cb59",
            capability_expr={"kind": "conditional_universal"},
        )
    )
    db_session.commit()
    _warm(db_session)

    assert reconcile_deferred_resolutions(db_session, chain_id=1) == 0
    assert reconcile_unsettled_mapping_replays(db_session, chain_id=1) == 1


# Enrollment ---------------------------------------------------------------------------------------------------------


def test_unsettled_nested_replays_enrol_their_writer_topics(db_session):
    from workers.event_log_indexer import HintTarget, hint_targets_for_job

    job = _job_with_graph(
        db_session,
        "0x" + "a8" * 20,
        [_awaiting(), _awaiting(chain_id=8453), {"address": "0x" + "33" * 20, **_awaiting("complete")}],
    )

    targets = list(hint_targets_for_job(db_session, job))

    assert targets == [HintTarget("hint", 1, TIMELOCK, tuple(sorted([GRANT_T0, REVOKE_T0])))]


def test_policy_refresh_hands_the_walk_the_trees_its_replays_need(monkeypatch):
    from unittest.mock import MagicMock

    from workers.policy_worker import PolicyWorker

    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    trees = _timelock_trees()
    stored_graph = {"nodes": [_node(TIMELOCK, 0, {}), _node(SAFE, 1, {**_awaiting(), "address": SAFE})], "edges": []}
    artifacts = {
        "contract_analysis": {"contract_address": TIMELOCK, "contract_name": "Timelock", "functions": []},
        "control_snapshot": {"contract_address": TIMELOCK, "controller_values": {}},
        "resolved_control_graph": stored_graph,
        "control_tracking_plan": {"schema_version": "0.1", "contract_address": TIMELOCK},
        "predicate_trees": trees,
    }
    monkeypatch.setattr("workers.policy_worker.get_artifact", lambda _s, _j, name: artifacts.get(name))
    monkeypatch.setattr("workers.policy_worker.store_artifact", lambda *a, **kw: None)
    loaded: dict[str, Any] = {}
    monkeypatch.setattr(
        "workers.policy_worker._load_nested_artifacts",
        lambda *_a, **kw: loaded.update(kw) or {},
    )
    monkeypatch.setattr(
        "workers.policy_worker.build_effective_permissions", lambda *a, **kw: {"schema_version": "1", "functions": []}
    )
    walked: dict[str, Any] = {}
    monkeypatch.setattr(
        "workers.policy_worker.resolve_control_graph",
        lambda **kw: walked.update(kw) or ({"nodes": [], "edges": []}, {}),
    )
    monkeypatch.setattr("workers.policy_worker.build_principal_labels", lambda *a, **kw: {"principals": []})
    monkeypatch.setattr(PolicyWorker, "_enrich_cross_contract", lambda *a, **kw: {})
    job = SimpleNamespace(
        id="job-1",
        address=TIMELOCK,
        name="Timelock",
        company=None,
        protocol_id=None,
        request={"rpc_url": "https://rpc.example", "chain_id": 1},
    )

    PolicyWorker().process(session, cast(Any, job))

    assert loaded["replay_trees_for"] == {SAFE}
    assert walked["root_artifacts"]["predicate_trees"] is trees
