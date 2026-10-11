"""A two-key mapping replay (``_roles[role][account]``) harvests only the roles the contract's own leaves check, and the
roles that administer them through ``getRoleAdmin``: a holder of any other role is not a controller in the scorer's
closure or on Surface, while a holder of a checked or administering role still is.

The wires are stubbed (``eth_call`` batch for ``getRoleAdmin``, the resolution pin, classification); the event rows and
cursors are real test-DB rows, and the readers are the scorer's ``load_control_closure`` and the company overview.
"""

from __future__ import annotations

import json
import sys
from typing import Any, cast

import pytest

from db.models import ENROLLMENT_BASIS_PREDICATE_HINT, IndexedEventCursor, IndexedEventLog
from services.aggregations.company_overview import build_company_overview
from services.resolution import recursive
from services.resolution.graph_tables import replace_control_graph_rows
from services.resolution.mapping_enumerator import _event_topic0, clear_enumeration_cache
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph
from services.scoring.planes import load_control_closure
from services.scoring.schema import entity_key
from tests.conftest import SessionFactory, requires_postgres
from tests.support.hypersync_fakes import _FakeHypersyncModule
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol

pytestmark = requires_postgres

ANCHOR = "0x" + "d9" * 20
GRANTED = "RoleGranted(bytes32,address,address)"
REVOKED = "RoleRevoked(bytes32,address,address)"
GRANT_T0 = _event_topic0(GRANTED)
REVOKE_T0 = _event_topic0(REVOKED)
GET_ROLE_ADMIN = "0x248a9ca3"
PIN = 20_000

PROPOSER_ROLE = "0x" + "b0" * 32
ADMIN_ROLE = "0x" + "5f" * 32
OPERATOR_ROLE = "0x" + "0e" * 32
ROLE_ADMINS = {PROPOSER_ROLE: ADMIN_ROLE, ADMIN_ROLE: ADMIN_ROLE, OPERATOR_ROLE: ADMIN_ROLE}

PROPOSER = "0x" + "a1" * 20
ADMIN = "0x" + "a2" * 20
OPERATOR_ONLY = "0x" + "a3" * 20
PROPOSER_REVOKED_OPERATOR_KEPT = "0x" + "a4" * 20
OPERATOR_REVOKED_PROPOSER_KEPT = "0x" + "a5" * 20
SENDER = "0x" + "ee" * 20
CONSUMER = "0x" + "c0" * 20


def _word(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, db_session):
    monkeypatch.setenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "0")
    monkeypatch.delenv("ENVIO_API_TOKEN", raising=False)
    monkeypatch.setattr("db.models.SessionLocal", SessionFactory(db_session))
    monkeypatch.setitem(sys.modules, "hypersync", _FakeHypersyncModule())
    monkeypatch.setattr(
        recursive,
        "classify_resolved_address_with_status",
        lambda _rpc, addr, **_k: ("timelock", {"address": addr}, True),
    )
    monkeypatch.setattr("services.resolution.capability_resolver._resolve_resolution_block", lambda *_a, **_k: PIN)
    clear_enumeration_cache()
    yield
    clear_enumeration_cache()


def _role_admin_wire(monkeypatch, *, fail: bool = False) -> list[tuple[str, list[Any]]]:
    asked: list[tuple[str, list[Any]]] = []

    def _batch(_url, calls, *_a, **_k):
        asked.extend(calls)
        out = []
        for method, params in calls:
            assert method == "eth_call" and params[0]["to"] == ANCHOR and params[1] == hex(PIN)
            data = params[0]["data"]
            assert data.startswith(GET_ROLE_ADMIN)
            out.append((None, "transport") if fail else (ROLE_ADMINS["0x" + data[10:]], "ok"))
        return out

    monkeypatch.setattr("services.clients.rpc.rpc_batch_request_classified", _batch)
    return asked


def _hint(signature: str, direction: str) -> dict[str, Any]:
    return {
        "topic0": _event_topic0(signature),
        "topics_to_keys": {"1": 0, "2": 1},
        "data_to_keys": {},
        "direction": direction,
        "event_signature": signature,
        "event_name": signature.split("(")[0],
        "mapping_name": "_roles",
        "key_position": 1,
        "indexed_positions": [0, 1, 2],
        "value_position": None,
        "writer_function": "_grantRole(bytes32,address)" if direction == "add" else "_revokeRole(bytes32,address)",
    }


def _role_leaf(role_key: dict[str, Any]) -> dict[str, Any]:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "membership",
            "operator": "truthy",
            "authority_role": "caller_authority",
            "operands": [role_key, {"source": "msg_sender"}],
            "set_descriptor": {
                "kind": "mapping_membership",
                "key_sources": [role_key, {"source": "msg_sender"}],
                "storage_var": "_roles",
                "enumeration_hint": [_hint(GRANTED, "add"), _hint(REVOKED, "remove")],
            },
            "confidence": "high",
        },
    }


# The shapes the static stage writes for ``onlyRole(PROPOSER_ROLE)`` and ``onlyRole(getRoleAdmin(role))``.
PROPOSER_KEY = {"source": "state_variable", "state_variable_name": "PROPOSER_ROLE"}
ROLE_ADMIN_KEY = {
    "source": "view_call",
    "callee": "getRoleAdmin(bytes32)",
    "callee_signature": "getRoleAdmin(bytes32)",
    "callee_selector": GET_ROLE_ADMIN,
    "derived_from": [{"source": "parameter", "parameter_index": 0, "parameter_name": "role"}],
}


def _trees() -> dict[str, Any]:
    return {
        "schema_version": "semantic",
        "trees": {
            "schedule(address,uint256,bytes,bytes32,bytes32,uint256)": _role_leaf(PROPOSER_KEY),
            "grantRole(bytes32,address)": _role_leaf(ROLE_ADMIN_KEY),
        },
    }


def _bundle(
    *, address: str = ANCHOR, trees: dict[str, Any] | None = None, controllers: dict[str, Any] | None = None
) -> LoadedArtifacts:
    return cast(
        LoadedArtifacts,
        {
            "analysis": {"subject": {"address": address, "name": "Timelock"}},
            "tracking_plan": {"schema_version": "0.1", "contract_address": address, "tracked_controllers": []},
            "snapshot": {
                "schema_version": "0.1",
                "contract_address": address,
                "contract_name": "Timelock",
                "block_number": PIN,
                "controller_values": controllers
                or {"role_identifier:PROPOSER_ROLE": {"source": "PROPOSER_ROLE", "value": PROPOSER_ROLE}},
            },
            "predicate_trees": _trees() if trees is None else trees,
        },
    )


_SEQ = {"n": 0}


def _log(session, topic0: str, role: str, member: str, block: int) -> None:
    _SEQ["n"] += 1
    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=ANCHOR,
            topic0=topic0,
            tx_hash=(500_000 + _SEQ["n"]).to_bytes(32, "big"),
            log_index=0,
            block_number=block,
            block_hash=b"\x01" * 32,
            transaction_index=0,
            topics=[topic0, role, _word(member), _word(SENDER)],
            data_words=[],
        )
    )


def _history(session) -> None:
    for topic0 in (GRANT_T0, REVOKE_T0):
        session.add(
            IndexedEventCursor(
                chain_id=1,
                event_address=ANCHOR,
                topic0=topic0,
                last_indexed_block=PIN,
                backfill_complete=True,
                first_indexed_block=0,
                first_indexed_block_basis="creation_block_minus_one",
                enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
            )
        )
    _log(session, GRANT_T0, ADMIN_ROLE, ANCHOR, 100)
    _log(session, GRANT_T0, ADMIN_ROLE, ADMIN, 101)
    _log(session, GRANT_T0, PROPOSER_ROLE, PROPOSER, 102)
    _log(session, GRANT_T0, OPERATOR_ROLE, OPERATOR_ONLY, 103)
    _log(session, GRANT_T0, PROPOSER_ROLE, PROPOSER_REVOKED_OPERATOR_KEPT, 104)
    _log(session, GRANT_T0, OPERATOR_ROLE, PROPOSER_REVOKED_OPERATOR_KEPT, 105)
    _log(session, REVOKE_T0, PROPOSER_ROLE, PROPOSER_REVOKED_OPERATOR_KEPT, 106)
    _log(session, GRANT_T0, PROPOSER_ROLE, OPERATOR_REVOKED_PROPOSER_KEPT, 107)
    _log(session, GRANT_T0, OPERATOR_ROLE, OPERATOR_REVOKED_PROPOSER_KEPT, 108)
    _log(session, REVOKE_T0, OPERATOR_ROLE, OPERATOR_REVOKED_PROPOSER_KEPT, 109)
    session.commit()


def _member_with_graph(session, protocol, root: LoadedArtifacts, address: str, override=None) -> None:
    job = _add_job(session, address=address, protocol_id=protocol.id, request={"address": address, "chain": "ethereum"})
    contract = _add_contract(session, address=address, job=job, protocol_id=protocol.id, contract_name="Member")
    graph, _ = resolve_control_graph(
        root_artifacts=root, rpc_url="http://rpc.test", chain_id=1, nested_artifacts_override=override
    )
    replace_control_graph_rows(session, contract_id=contract.id, deployment_address=None, resolved_graph=graph)
    session.commit()


def _controllers_read_by_scorer_and_surface(
    session, bundle: LoadedArtifacts | None = None, *, consumer: bool = False
) -> tuple[set[str], set[str]]:
    protocol = _add_protocol(session, "role-keys")
    anchor_bundle = bundle or _bundle()
    _member_with_graph(session, protocol, anchor_bundle, ANCHOR)
    if consumer:
        # The consumer gates on ``registry.hasRole(PAUSER_ROLE, msg.sender)``; its graph walks into the registry.
        consumer_bundle = _bundle(
            address=CONSUMER,
            trees={"schema_version": "semantic", "trees": {}},
            controllers={
                "external_contract:roleRegistry": {
                    "source": "roleRegistry",
                    "value": ANCHOR,
                    "resolved_type": "contract",
                    "authority_provenance": "caller_gate",
                }
            },
        )
        _member_with_graph(session, protocol, consumer_bundle, CONSUMER, override={ANCHOR: anchor_bundle})

    anchor_key = entity_key("ethereum", ANCHOR)
    closure = load_control_closure(session, protocol.id)
    scorer = {edge.principal.split("::")[-1] for edge in closure.edges if edge.anchor == anchor_key}
    overview = build_company_overview(session, protocol.name)
    surface = {
        flow["from"].lower()
        for flow in overview["fund_flows"]
        if flow["to"].lower() == ANCHOR and flow["type"] == "controller"
    }
    return scorer, surface


def test_only_holders_of_checked_or_administering_roles_are_controllers(db_session, monkeypatch):
    _history(db_session)
    asked = _role_admin_wire(monkeypatch)

    scorer, surface = _controllers_read_by_scorer_and_surface(db_session)

    expected = {PROPOSER, ADMIN, OPERATOR_REVOKED_PROPOSER_KEPT}
    assert scorer == expected
    assert surface == expected
    # The administering role is read at the pinned block, once per role in play.
    assert {call[1][0]["data"][10:] for call in asked} >= {PROPOSER_ROLE[2:], OPERATOR_ROLE[2:]}


def test_an_unreadable_role_admin_keeps_every_holder(db_session, monkeypatch):
    _history(db_session)
    _role_admin_wire(monkeypatch, fail=True)

    scorer, surface = _controllers_read_by_scorer_and_surface(db_session)

    # Who administers the checked role is unknown, so no holder is dropped; a revoke still only ends the role it names.
    expected = {PROPOSER, ADMIN, OPERATOR_ONLY, PROPOSER_REVOKED_OPERATOR_KEPT, OPERATOR_REVOKED_PROPOSER_KEPT}
    assert scorer == expected
    assert surface == expected


def test_the_spec_carries_the_checked_role_and_the_role_admin_view():
    specs = recursive._mapping_writer_specs_from_predicate_trees(
        _trees(), key_words=recursive._snapshot_key_words(_bundle()["snapshot"]), address=ANCHOR
    )

    assert {spec["direction"] for spec in specs} == {"add", "remove"}
    for spec in specs:
        assert spec.get("key_filter") == {"position": 0, "words": [PROPOSER_ROLE], "views": [GET_ROLE_ADMIN]}


@pytest.mark.parametrize(
    "role_key",
    [
        pytest.param({"source": "state_variable", "state_variable_name": "UNREAD_ROLE"}, id="constant-not-read"),
        pytest.param({"source": "parameter", "parameter_index": 0}, id="caller-chosen-role"),
        pytest.param({**ROLE_ADMIN_KEY, "callee_signature": "roleFor(bytes32)"}, id="other-view"),
    ],
)
def test_a_role_key_that_cannot_be_read_filters_nothing(role_key):
    trees = _trees()
    trees["trees"]["cancel(bytes32)"] = _role_leaf(role_key)

    specs = recursive._mapping_writer_specs_from_predicate_trees(
        trees, key_words=recursive._snapshot_key_words(_bundle()["snapshot"]), address=ANCHOR
    )

    filters = [spec.get("key_filter") for spec in specs]
    assert filters and all(f is not None and f["words"] is None for f in filters)


def test_a_one_key_mapping_gets_no_filter():
    leaf = _role_leaf(PROPOSER_KEY)
    leaf["leaf"]["set_descriptor"]["key_sources"] = [{"source": "msg_sender"}]
    for hint in leaf["leaf"]["set_descriptor"]["enumeration_hint"]:
        hint["topics_to_keys"] = {"2": 0}

    specs = recursive._mapping_writer_specs_from_predicate_trees({"trees": {"mint()": leaf}}, key_words={})

    assert specs and all("key_filter" not in spec for spec in specs)


ALL_HOLDERS = {PROPOSER, ADMIN, OPERATOR_ONLY, PROPOSER_REVOKED_OPERATOR_KEPT, OPERATOR_REVOKED_PROPOSER_KEPT}
REGISTRY_TREES = {"schema_version": "semantic", "trees": {"grantRole(bytes32,address)": _role_leaf(ROLE_ADMIN_KEY)}}


def test_a_registry_alone_keeps_only_its_own_checked_roles(db_session, monkeypatch):
    _history(db_session)
    _role_admin_wire(monkeypatch)

    scorer, surface = _controllers_read_by_scorer_and_surface(db_session, _bundle(trees=REGISTRY_TREES))

    assert scorer == surface == {ADMIN}


def test_a_registry_another_contract_gates_on_keeps_every_role_holder(db_session, monkeypatch):
    _history(db_session)
    _role_admin_wire(monkeypatch)

    scorer, surface = _controllers_read_by_scorer_and_surface(db_session, _bundle(trees=REGISTRY_TREES), consumer=True)

    # The consumer checks a role the registry's own leaves never name, so every holder may be its controller.
    assert scorer == surface == ALL_HOLDERS


HAS_ROLE_CHECK = {
    "op": "LEAF",
    "leaf": {
        "kind": "membership",
        "operator": "truthy",
        "authority_role": "business",
        "operands": [{"source": "parameter", "parameter_index": 0}, {"source": "parameter", "parameter_index": 1}],
        "set_descriptor": {
            "kind": "mapping_membership",
            "key_sources": [
                {"source": "parameter", "parameter_index": 0, "parameter_name": "role"},
                {"source": "parameter", "parameter_index": 1, "parameter_name": "account"},
            ],
            "storage_var": "_roles",
            "enumeration_hint": [_hint(GRANTED, "add"), _hint(REVOKED, "remove")],
        },
    },
}


def _filters(trees: dict[str, Any]) -> list[Any]:
    specs = recursive._mapping_writer_specs_from_predicate_trees(
        trees, key_words=recursive._snapshot_key_words(_bundle()["snapshot"]), address=ANCHOR
    )
    return [spec.get("key_filter") for spec in specs]


def test_a_role_check_other_contracts_can_call_with_any_role_filters_nothing(db_session, monkeypatch):
    trees = {**_trees(), "check_trees": {"hasRole(bytes32,address)": HAS_ROLE_CHECK}}
    assert {f["words"] if f else "missing" for f in _filters(trees)} == {None}

    _history(db_session)
    _role_admin_wire(monkeypatch)
    scorer, surface = _controllers_read_by_scorer_and_surface(db_session, _bundle(trees=trees))
    assert scorer == surface == ALL_HOLDERS


def test_a_role_check_on_a_constant_role_adds_that_role():
    operator_check = json.loads(json.dumps(HAS_ROLE_CHECK))
    operator_check["leaf"]["set_descriptor"]["key_sources"][0] = {"source": "constant", "constant_value": OPERATOR_ROLE}
    trees = {**_trees(), "check_trees": {"isOperator(address)": operator_check}}

    (first, *_rest) = _filters(trees)
    assert first is not None and first["words"] == sorted([PROPOSER_ROLE, OPERATOR_ROLE])


def test_an_uncertain_guard_filters_nothing():
    trees = {**_trees(), "guard_extraction_uncertain": ["setPauser(address)"]}
    assert {f["words"] if f else "missing" for f in _filters(trees)} == {None}
    # The checked roles alone still filter without one.
    assert {tuple(f["words"]) for f in _filters(_trees()) if f} == {(PROPOSER_ROLE,)}


def test_the_cache_fingerprint_follows_the_key_filter():
    from db.mapping_enumeration_cache import specs_fingerprint

    specs: list[dict[str, Any]] = [
        dict(spec)
        for spec in recursive._mapping_writer_specs_from_predicate_trees(
            _trees(), key_words=recursive._snapshot_key_words(_bundle()["snapshot"]), address=ANCHOR
        )
    ]
    unfiltered = [{k: v for k, v in spec.items() if k != "key_filter"} for spec in specs]
    other = [{**spec, "key_filter": {**spec["key_filter"], "words": None}} for spec in specs]

    assert len({specs_fingerprint(specs), specs_fingerprint(unfiltered), specs_fingerprint(other)}) == 3
