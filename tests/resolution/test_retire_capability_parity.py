"""Retiring activity- and hint-tier tracked cursors changes no capability the real resolver publishes.

The Veda stack (Teller, BoringVault, shared RolesAuthority; real trees and role events) gives both shapes the retire
gates reason about: the vault is the target of the teller's void ``enter`` / ``exit`` checks and the authority of
every ``canCall`` bool check, and the authority also carries predicate-hint cursors. Tracked activity / hint cursors,
with rows whose words decode to plausible callers, are added at both; the teller and vault are resolved before and
after ``retire --apply``.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, func, select

from db.floor_witnesses import WITNESS_PROVEN, record_floor_witness
from db.models import (
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    FIRST_INDEXED_BASIS_CREATION,
    IndexedEventCursor,
    IndexedEventLog,
    MonitoredContract,
    Protocol,
)
from services.resolution.external_check_materializer import clear_candidate_cache
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from workers import retire_event_cursors as retire

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "solmate" / "veda_teller_stack.json"
_ROLE_TOPICS = [
    "0xa52ea92e6e955aa8ac66420b86350f7139959adfcc7e6a14eee1bd116d09860e",
    "0x950a343f5d10445e82a71036d3f4fb3016180a25805141932543b83e2078a93e",
    "0x4c9bdd0c8e073eb5eda2250b18d8e5121ff27b62064fbeeeed4869bb99bc5bf2",
]
_FRONTIER = 30_000_000
_ZERO = "0x" + "0" * 40
_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_ENTER = "0x" + "e1" * 32
_EXCHANGE_RATE = "0x" + "e2" * 32
_CALLER = "0x" + "c4" * 20


@pytest.fixture(autouse=True)
def _no_wire(monkeypatch):
    """Keep the resolver's bytecode probes (``rpc.get_code`` for adapter selector checks) off the wire; the probe
    failure is the path an unreachable RPC already takes. The materializer's own call is stubbed per test."""
    import services.clients.rpc as rpc

    def _no_rpc(*_a, **_k):
        raise RuntimeError("offline: resolver wire stubbed")

    monkeypatch.setattr(rpc, "rpc_request", _no_rpc)


@pytest.fixture
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import AddressFloorWitness, Contract, ControllerValue, IndexerWork, Job

    def _wipe(sess):
        for model in (
            IndexedEventLog,
            IndexedEventCursor,
            AddressFloorWitness,
            MonitoredContract,
            ControllerValue,
            Contract,
            Job,
            Protocol,
            IndexerWork,
        ):
            sess.query(model).delete()
        sess.commit()

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    _wipe(s)
    try:
        yield s
    finally:
        s.rollback()
        _wipe(s)
        s.close()
        engine.dispose()


def _job(session, address: str, trees: dict, controllers: dict[str, str]):
    from db.models import Contract, ControllerValue, Job, JobStage, JobStatus
    from db.queue import store_artifact

    job = Job(
        address=address,
        chain_id=1,
        request={"address": address, "name": "T", "chain": "ethereum"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    store_artifact(session, job.id, "predicate_trees", data=trees)
    protocol = Protocol(name=f"g8_{uuid.uuid4().hex[:8]}")
    session.add(protocol)
    session.flush()
    contract = Contract(address=address, chain="ethereum", protocol_id=protocol.id, job_id=job.id)
    session.add(contract)
    session.flush()
    for cid, value in controllers.items():
        session.add(ControllerValue(contract_id=contract.id, controller_id=cid, value=value, source="test"))
    session.flush()
    return job


def _cursor(session, address: str, topic0: str, basis: str | None) -> None:
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            last_indexed_block=_FRONTIER,
            backfill_complete=True,
            first_indexed_block=0,
            first_indexed_block_basis=FIRST_INDEXED_BASIS_CREATION,
            enrollment_basis=basis,
        )
    )


def _word(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


def _tracked(session, address: str, topic0: str, count: int) -> None:
    _cursor(session, address, topic0, ENROLLMENT_BASIS_TRACKED_TOPICS)
    for i in range(count):
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=address,
                topic0=topic0,
                tx_hash=(10_000 + i).to_bytes(32, "big"),
                log_index=i,
                block_number=20_000_000 + i,
                block_hash=b"\x05" * 32,
                transaction_index=0,
                topics=[topic0, _word(_CALLER), _word(f"0x{0xF00D0000 + i:040x}")],
                data_words=[_word(_CALLER)],
            )
        )


def _monitor(session, address: str, specs: list[dict[str, Any]]) -> None:
    protocol = Protocol(name=f"g8m_{uuid.uuid4().hex[:8]}")
    session.add(protocol)
    session.flush()
    session.add(
        MonitoredContract(
            address=address,
            chain="ethereum",
            protocol_id=protocol.id,
            is_active=True,
            monitoring_config={"tracked_topics": specs},
        )
    )


def _seed(session, fixture: dict):
    teller, vault, authority = fixture["teller_address"], fixture["vault_address"], fixture["authority_address"]
    teller_job = _job(
        session,
        teller,
        fixture["teller_trees"],
        {"external_contract:authority": authority, "external_contract:vault": vault, "state_variable:owner": _ZERO},
    )
    vault_job = _job(
        session,
        vault,
        fixture["vault_trees"],
        {"external_contract:authority": authority, "state_variable:owner": _ZERO},
    )
    for i, e in enumerate(fixture["role_events"]):
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=authority,
                topic0=e["topic0"],
                tx_hash=i.to_bytes(32, "big"),
                log_index=e["log_index"],
                block_number=e["block_number"],
                block_hash=(i // 50).to_bytes(32, "big"),
                transaction_index=e["transaction_index"],
                topics=e["topics"],
                data_words=e["data_words"],
            )
        )
    for topic0 in _ROLE_TOPICS:
        _cursor(session, authority, topic0, None)
    # The tracked cursors retire is asked about: activity / hint tier at the vault (a void-check target) and at the
    # authority (a bool-check target that also carries predicate-hint cursors).
    _tracked(session, vault, _TRANSFER, 6)
    _tracked(session, vault, _ENTER, 3)
    _tracked(session, authority, _EXCHANGE_RATE, 4)
    _tracked(session, teller, _TRANSFER, 5)
    _tracked(session, teller, _ENTER, 2)
    _monitor(
        session,
        vault,
        [{"topic0": _TRANSFER, "witness_tier": "activity"}, {"topic0": _ENTER, "witness_tier": "hint"}],
    )
    _monitor(session, authority, [{"topic0": _EXCHANGE_RATE, "witness_tier": "activity"}])
    _monitor(
        session,
        teller,
        [{"topic0": _TRANSFER, "witness_tier": "activity"}, {"topic0": _ENTER, "witness_tier": "hint"}],
    )
    session.flush()
    for address in (teller, vault, authority):
        record_floor_witness(session, chain_id=1, address=address, outcome=WITNESS_PROVEN, first_indexed_block=1)
    session.commit()
    return teller_job, vault_job


def _abis(fixture: dict):
    def entry(name: str, inputs: list[str], outputs: list[str]) -> dict[str, Any]:
        return {
            "type": "function",
            "name": name,
            "inputs": [{"type": t} for t in inputs],
            "outputs": [{"type": t} for t in outputs],
        }

    by_address = {
        fixture["vault_address"]: [
            entry("enter", ["address", "address", "uint256", "address", "uint256"], []),
            entry("exit", ["address", "address", "uint256", "address", "uint256"], []),
        ],
        fixture["authority_address"]: [entry("canCall", ["address", "address", "bytes4"], ["bool"])],
    }
    return lambda _chain_id, address: by_address.get(address)


def _resolve_all(session, _fixture: dict, jobs) -> dict[str, Any]:
    from services.resolution.capability_resolver import resolve_contract_capabilities
    from services.resolution.creation_block_floor import clear_scan_floor_cache

    clear_candidate_cache()
    clear_scan_floor_cache()
    out = {}
    for job in jobs:
        caps = resolve_contract_capabilities(session, address=job.address, chain_id=1, job_id=job.id, block=_FRONTIER)
        assert caps is not None
        out[job.address] = json.loads(json.dumps(caps, sort_keys=True, default=str))
    session.rollback()
    return out


@requires_postgres
def test_retiring_tracked_cursors_leaves_every_capability_expression_unchanged(session):
    fixture = json.loads(_FIXTURE.read_text())
    teller, vault, authority = fixture["teller_address"], fixture["vault_address"], fixture["authority_address"]
    jobs = _seed(session, fixture)

    before = _resolve_all(session, fixture, jobs)
    assert before[teller], "the teller must resolve to capabilities for the comparison to mean much"

    plan = retire.plan_retirement(session, abi_lookup=_abis(fixture))
    session.rollback()
    blocked = {(v.address, v.topic0): sorted(n for n in retire.GATES if not v.gates[n]["pass"]) for v in plan}
    # The vault's checks name a non-canonical selector no ABI entry matches, and canCall returns bool: both keep rows.
    assert blocked[(vault, _TRANSFER)] == blocked[(vault, _ENTER)] == ["no_materializable_check"]
    assert blocked[(authority, _EXCHANGE_RATE)] == ["no_materializable_check"]

    retired = retire.apply_retirement(session, addresses=[teller, vault, authority], abi_lookup=_abis(fixture))
    assert {(v.address, v.topic0) for v in retired} == {(teller, _TRANSFER), (teller, _ENTER)}
    assert _resolve_all(session, fixture, jobs) == before

    # The world where these tiers were never indexed at all: every tracked cursor and its rows gone.
    tracked = session.execute(
        select(IndexedEventCursor.event_address, IndexedEventCursor.topic0).where(
            IndexedEventCursor.enrollment_basis == ENROLLMENT_BASIS_TRACKED_TOPICS
        )
    ).all()
    assert {tuple(r) for r in tracked} == {(vault, _TRANSFER), (vault, _ENTER), (authority, _EXCHANGE_RATE)}
    for address, topic0 in tracked:
        session.execute(
            delete(IndexedEventLog).where(IndexedEventLog.event_address == address, IndexedEventLog.topic0 == topic0)
        )
        session.execute(
            delete(IndexedEventCursor).where(
                IndexedEventCursor.event_address == address, IndexedEventCursor.topic0 == topic0
            )
        )
    session.commit()
    assert session.execute(select(func.count()).select_from(IndexedEventLog)).scalar_one() == len(
        fixture["role_events"]
    )
    assert _resolve_all(session, fixture, jobs) == before


# A gate whose bool check targets a registry with no predicate trees, so the resolver materializes the caller set from
# whatever rows are indexed at the registry, and a void check on a second registry.
_REGISTRY = "0x" + "4b" * 20
_HOOK = "0x" + "4c" * 20
_ROOT = "0x" + "4d" * 20
_MINTER_A = "0x" + "e1" * 20
_MINTER_B = "0x" + "e2" * 20
_IS_MINTER = "isMinter(address)"
_BEFORE_MINT = "beforeMint(address)"


def _selector(signature: str) -> str:
    from eth_utils.crypto import keccak

    return "0x" + keccak(text=signature).hex()[:8]


def _caller_check(state_variable: str, signature: str) -> dict[str, Any]:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "external_bool",
            "operator": "truthy",
            "authority_role": "delegated_authority",
            "operands": [{"source": "msg_sender"}],
            "set_descriptor": {
                "kind": "external_set",
                "authority_contract": {
                    "address_source": {"source": "state_variable", "state_variable_name": state_variable}
                },
                "callee_signature": signature,
                "callee_selector": _selector(signature),
            },
            "references_msg_sender": True,
            "parameter_indices": [],
            "expression": f"{state_variable}.{signature.split('(')[0]}(msg.sender)",
            "basis": [],
        },
    }


def _registry_rows(session, address: str, members: list[str]) -> None:
    _cursor(session, address, _TRANSFER, ENROLLMENT_BASIS_TRACKED_TOPICS)
    for i, member in enumerate(members):
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=address,
                topic0=_TRANSFER,
                tx_hash=(50_000 + i).to_bytes(32, "big"),
                log_index=i,
                block_number=20_000_000 + i,
                block_hash=b"\x06" * 32,
                transaction_index=0,
                topics=[_TRANSFER, _word(member), _word(member)],
                data_words=[],
            )
        )


@pytest.fixture
def materializer_wire(monkeypatch):
    """The materializer's eth_call batch: ``isMinter`` answers true for every candidate, the void ``beforeMint``
    returns nothing, as on chain. HyperSync (its fallback candidate source) has nothing."""
    import services.resolution.external_check_materializer as materializer

    calls: list[tuple[str, str]] = []

    def batch(_rpc_url, batch_calls):
        out = []
        for _method, params in batch_calls:
            call = params[0]
            calls.append((call["to"], call["data"][:10]))
            void = call["data"].startswith(_selector(_BEFORE_MINT))
            out.append(("0x" if void else "0x" + "0" * 63 + "1", False))
        return out

    monkeypatch.setattr(materializer, "rpc_batch_request_with_status", batch)
    monkeypatch.setattr(materializer, "_candidate_addresses_from_hypersync", lambda **_k: [])
    return calls


def _seed_materialized(session):
    root_trees = {
        "trees": {
            "mint(address,uint256)": _caller_check("registry", _IS_MINTER),
            "mintWithHook(address,uint256)": _caller_check("hook", _BEFORE_MINT),
        }
    }
    root = _job(session, _ROOT, root_trees, {"external_contract:registry": _REGISTRY, "external_contract:hook": _HOOK})
    root.request = {**(root.request or {}), "rpc_url": "http://rpc.stub"}
    for address in (_REGISTRY, _HOOK):
        _job(session, address, {"trees": {}, "check_trees": {}}, {})
    _registry_rows(session, _REGISTRY, [_MINTER_A, _MINTER_B])
    _registry_rows(session, _HOOK, [_MINTER_A])
    _monitor(session, _REGISTRY, [{"topic0": _TRANSFER, "witness_tier": "activity"}])
    _monitor(session, _HOOK, [{"topic0": _TRANSFER, "witness_tier": "activity"}])
    session.flush()
    for address in (_REGISTRY, _HOOK):
        record_floor_witness(session, chain_id=1, address=address, outcome=WITNESS_PROVEN, first_indexed_block=1)
    session.commit()
    return root


def _materialized_abis(_chain_id: int, address: str) -> list[dict[str, Any]] | None:
    entry = {"type": "function", "inputs": [{"type": "address"}]}
    if address == _REGISTRY:
        return [{**entry, "name": "isMinter", "outputs": [{"type": "bool"}]}]
    if address == _HOOK:
        return [{**entry, "name": "beforeMint", "outputs": []}]
    return None


def _members(caps: dict[str, Any], function: str) -> set[str]:
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for member in node.get("members") or []:
                if isinstance(member, str):
                    found.add(member.lower())
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(caps[function])
    return found


@requires_postgres
def test_retire_keeps_rows_a_bool_check_materializes_from_and_drops_only_void_check_rows(session, materializer_wire):
    root = _seed_materialized(session)

    before = _resolve_all(session, {}, [root])
    # The registry's tracked rows are the materializer's candidates: they reach the published caller set.
    assert {_MINTER_A, _MINTER_B} <= _members(before[_ROOT], "mint(address,uint256)")
    assert (_REGISTRY, _selector(_IS_MINTER)) in materializer_wire
    assert (_HOOK, _selector(_BEFORE_MINT)) in materializer_wire

    retired = retire.apply_retirement(session, addresses=[_REGISTRY, _HOOK], abi_lookup=_materialized_abis)
    assert {(v.address, v.topic0) for v in retired} == {(_HOOK, _TRANSFER)}
    assert _resolve_all(session, {}, [root]) == before

    # Had gate 5 let the bool-check target's rows go, the published caller set would shrink.
    session.execute(delete(IndexedEventLog).where(IndexedEventLog.event_address == _REGISTRY))
    session.commit()
    stripped = _resolve_all(session, {}, [root])
    assert stripped != before
    assert not {_MINTER_A, _MINTER_B} & _members(stripped[_ROOT], "mint(address,uint256)")
