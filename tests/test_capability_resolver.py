"""Integration tests for ``resolve_contract_capabilities``.

End-to-end: seeds a Job + predicate_trees artifact + (optionally)
generic indexed event rows, then calls the resolver and asserts the
serialized CapabilityExpr per function.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

# offline: no live owner()/governor() eth_call during predicate evaluation
pytestmark = pytest.mark.usefixtures("_stub_live_authority")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""


def _can_connect() -> bool:
    if not _DB_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


@pytest.fixture
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import (
        Contract,
        IndexedEventCursor,
        IndexedEventLog,
        Job,
        Protocol,
    )

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        for model in (
            IndexedEventLog,
            IndexedEventCursor,
            Contract,
        ):
            s.query(model).delete()
        s.query(Job).delete()
        s.query(Protocol).delete()
        s.commit()
        s.close()
        engine.dispose()


def _seed_job_with_artifact(session, *, address: str, predicate_trees: dict | None):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact

    job = Job(
        address=address,
        request={"address": address, "name": "T"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    if predicate_trees is not None:
        store_artifact(session, job.id, "predicate_trees", data=predicate_trees)
    session.commit()
    return job


def _seed_contract(session, *, address: str):
    from db.models import Contract, Protocol

    proto = Protocol(name=f"capres_test_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(address=address, chain="ethereum", protocol_id=proto.id)
    session.add(contract)
    session.flush()
    session.commit()
    return contract


def _address_topic(address: str) -> str:
    return "0x" + address.lower()[2:].rjust(64, "0")


def _bytes4_topic(selector: str) -> str:
    return "0x" + selector.lower()[2:].ljust(64, "0")


@requires_postgres
def test_resolve_returns_none_when_no_completed_job(session):
    from services.resolution.capability_resolver import resolve_contract_capabilities

    out = resolve_contract_capabilities(session, address="0x" + "ee" * 20, chain_id=1)
    assert out is None


@requires_postgres
def test_resolve_returns_none_when_no_artifact(session):
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + "ab" * 20
    _seed_job_with_artifact(session, address=address, predicate_trees=None)
    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is None


@requires_postgres
def test_resolve_returns_per_function_capabilities(session):
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + uuid.uuid4().hex[:8] + "01" * 16
    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "f()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "msg_sender"},
                        {"source": "state_variable", "state_variable_name": "owner"},
                    ],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "msg.sender == owner",
                    "basis": [],
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is not None
    assert "f()" in out
    cap = out["f()"]
    # The eq-against-state-variable shape produces a finite_set
    # over the state-var holder (lower_bound until probed). The
    # exact shape is the resolver's job — we pin the protocol-shape
    # contract: kind is one of the typed CapKind values + a
    # confidence + a membership_quality field.
    assert "kind" in cap
    assert "confidence" in cap
    assert "membership_quality" in cap


@requires_postgres
def test_resolve_yields_finite_set_with_indexed_event_repo(session):
    """A multi-key membership leaf resolves through generic indexed events."""
    from db.models import IndexedEventCursor, IndexedEventLog
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + uuid.uuid4().hex[:8] + "02" * 16
    role_const_hex = "0x" + "01" * 32
    member = "0x" + "44" * 20
    topic0 = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"

    _seed_contract(session, address=address)
    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            tx_hash=b"\xaa" * 32,
            log_index=0,
            block_number=100,
            block_hash=b"\xbb" * 32,
            transaction_index=0,
            topics=[topic0, role_const_hex, _address_topic(member)],
            data_words=[],
        )
    )
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            last_indexed_block=18_500_000,
            last_indexed_block_hash=b"\xcc" * 32,
            backfill_complete=True,
        )
    )
    session.commit()

    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "guardedFn()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "key_sources": [
                            {"source": "constant", "constant_value": role_const_hex},
                            {"source": "msg_sender"},
                        ],
                        "storage_var": "_roles",
                        "enumeration_hint": [
                            {
                                "event_address": address,
                                "topic0": topic0,
                                "topics_to_keys": {1: 0, 2: 1},
                                "data_to_keys": {},
                                "direction": "add",
                            }
                        ],
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "_roles[ROLE][msg.sender]",
                    "basis": [],
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is not None
    cap = out["guardedFn()"]
    assert cap["kind"] == "finite_set"
    assert member in (cap.get("members") or [])


@requires_postgres
def test_resolve_serializes_unsupported_with_reason(session):
    """An unsupported leaf serializes to a CapabilityExpr with
    kind=unsupported and the reason flowed through, so the UI can
    render 'we know there's a gate but cannot characterize it.'"""
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + uuid.uuid4().hex[:8] + "03" * 16
    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "tryFn()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "unsupported",
                    "operator": "truthy",
                    "authority_role": "business",
                    "operands": [],
                    "unsupported_reason": "opaque_try_catch",
                    "references_msg_sender": False,
                    "parameter_indices": [],
                    "expression": "h.helper()",
                    "basis": ["opaque_try_catch"],
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is not None
    cap = out["tryFn()"]
    assert cap["kind"] == "unsupported"
    # Reason flows through to the wire (UI surfaces it).
    assert cap.get("unsupported_reason") == "opaque_try_catch"


@requires_postgres
def test_resolve_returns_empty_dict_for_unguarded_only_contract(session):
    """A contract with no guarded functions has trees={} in the
    artifact. The resolver returns an empty dict — every function
    is implicitly public per the resolver convention."""
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + uuid.uuid4().hex[:8] + "04" * 16
    artifact = {"schema_version": "semantic", "contract_name": "T", "trees": {}}
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out == {}


@requires_postgres
def test_capability_to_dict_handles_composite():
    """``capability_to_dict`` recurses through AND/OR children +
    signer (signature_witness). Pinned because a regression in
    the recursion would silently drop nested capability data."""
    from services.resolution.capabilities import CapabilityExpr
    from services.resolution.capability_resolver import capability_to_dict

    inner_finite = CapabilityExpr.finite_set(["0x" + "11" * 20], quality="exact")
    inner_thresh = CapabilityExpr.threshold_group(2, ["0x" + "22" * 20, "0x" + "33" * 20])
    composite = CapabilityExpr(kind="OR", children=[inner_finite, inner_thresh])  # type: ignore[arg-type]
    out = capability_to_dict(composite)

    assert out["kind"] == "OR"
    assert "children" in out
    assert len(out["children"]) == 2
    finite_child = next(c for c in out["children"] if c["kind"] == "finite_set")
    thresh_child = next(c for c in out["children"] if c["kind"] == "threshold_group")
    assert finite_child["members"] == ["0x" + "11" * 20]
    assert thresh_child["threshold"]["m"] == 2
    assert thresh_child["threshold"]["signers"] == ["0x" + "22" * 20, "0x" + "33" * 20]


# ---------------------------------------------------------------------------
# Bug 2: state-variable operand enrichment. The predicate builder produces a
# correct leaf for inherited OZ Ownable (``operands: [_owner, msg_sender]``,
# ``authority_role: caller_authority``) — confirmed via the EtherFi
# LiquidityPool predicate_trees artifact. But the RESOLVER never reads the
# current ``_owner`` value, so it emits ``finite_set`` with
# ``membership_quality=lower_bound`` / ``confidence=partial`` and an empty
# members list. The frontend then shows transferOwnership / renounceOwnership
# as having no controllers. The fix: when a state-variable operand is
# resolvable via an existing ``controller_values`` row (already populated by
# the static-analysis pipeline), enumerate it into the finite_set.
# ---------------------------------------------------------------------------


@requires_postgres
def test_state_variable_owner_resolved_via_controller_values(session):
    """An OZ-Ownable predicate tree with a stored ``ControllerValue`` row
    for ``_owner`` should resolve to ``finite_set([owner_addr],
    quality=exact)`` — not the lower_bound/partial empty set EtherFi shows
    today."""
    from db.models import ControllerValue
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + uuid.uuid4().hex[:8] + "12" * 16
    owner_addr = "0x" + "ab" * 20

    contract = _seed_contract(session, address=address)
    session.add(
        ControllerValue(
            contract_id=contract.id,
            controller_id="_owner",
            value=owner_addr,
            resolved_type="eoa",
            source="state_variable",
        )
    )
    session.commit()

    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "transferOwnership(address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "state_variable", "state_variable_name": "_owner"},
                        {"source": "msg_sender"},
                    ],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "owner() == _msgSender()",
                    "basis": [],
                    "confidence": "high",
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is not None
    cap = out["transferOwnership(address)"]
    assert cap["kind"] == "finite_set", (
        f"expected resolver to enumerate state_variable _owner via controller_values "
        f"into a finite_set; got kind={cap.get('kind')}"
    )
    assert owner_addr.lower() in {m.lower() for m in (cap.get("members") or [])}, (
        f"expected {owner_addr} in members (sourced from ControllerValue row); got members={cap.get('members')}"
    )
    # Membership quality should be exact when enumerated from the persisted
    # value — not lower_bound (the partial fallback).
    assert cap.get("membership_quality") == "exact", (
        f"expected membership_quality=exact when controller_values has the answer; got {cap.get('membership_quality')}"
    )


@requires_postgres
def test_signature_auth_signer_state_variable_resolved_via_controller_values(session):
    """A ``signature_auth`` predicate whose signer is a state variable
    must resolve through ``ControllerValue`` the same way
    ``_resolve_equality_principal`` does for the OZ-Ownable case above.

    Today ``_resolve_signer_from_leaf`` ignores ``ctx.state_var_values``
    and unconditionally returns ``finite_set([], quality=lower_bound)``
    for any state-variable signer — so ``signature_witness(...)`` wraps
    an empty signer, and ``_rows_for_signature_witness`` writes zero
    ``FunctionPrincipal`` rows. Every signature-gated function whose
    signer is a state variable silently drops its signer from the
    governance / chat / per-function principal views.

    The pin: with a persisted ``ControllerValue`` row for ``signerAddr``,
    the resolved capability must be
    ``signature_witness(finite_set([signer], exact, enumerable))`` so
    the writer emits one ``signature_witness`` row downstream.
    """
    from db.models import ControllerValue
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + uuid.uuid4().hex[:8] + "34" * 16
    signer_addr = "0x" + "cd" * 20

    contract = _seed_contract(session, address=address)
    session.add(
        ControllerValue(
            contract_id=contract.id,
            controller_id="signerAddr",
            value=signer_addr,
            resolved_type="eoa",
            source="state_variable",
        )
    )
    session.commit()

    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "claim(bytes32,uint8,bytes32,bytes32)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "signature_auth",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "signature_recovery"},
                        {"source": "state_variable", "state_variable_name": "signerAddr"},
                    ],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "signerAddr == ecrecover(h, v, r, s)",
                    "basis": [],
                    "confidence": "high",
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is not None
    cap = out["claim(bytes32,uint8,bytes32,bytes32)"]
    assert cap["kind"] == "signature_witness", (
        f"expected signature_witness wrapping the resolved signer; got kind={cap.get('kind')}"
    )
    signer = cap.get("signer") or {}
    assert signer.get("kind") == "finite_set", (
        f"expected signer to be a finite_set sourced from ControllerValue; got kind={signer.get('kind')}"
    )
    assert signer_addr.lower() in {m.lower() for m in (signer.get("members") or [])}, (
        f"expected {signer_addr} in signer members (sourced from ControllerValue row); "
        f"got members={signer.get('members')}"
    )
    assert signer.get("membership_quality") == "exact", (
        f"expected signer membership_quality=exact when controller_values has the answer; "
        f"got {signer.get('membership_quality')}"
    )


@requires_postgres
def test_signature_auth_signer_zero_address_collapses_to_empty_exact(session):
    """Sibling of the equality path's zero-address handling:
    ``_resolve_equality_principal`` collapses ``msg.sender == _owner``
    to ``finite_set([], exact, enumerable)`` when ``_owner`` is the
    zero address (predicate_evaluator.py:418-419). The signer path
    must do the same — a zero-addressed signer means no valid
    signature can ever satisfy the gate.

    Why exact instead of lower_bound: "we know the answer and the
    answer is no one" is qualitatively different from "we don't know
    yet". The writer interprets ``finite_set([], exact)`` as
    ``status="resolved_empty"`` (capability_surface.py:114), surfacing
    the function as guarded-but-uncallable. The lower_bound fallback
    instead surfaces as "guarded but unresolved" — false suggestion
    of pending resolution.
    """
    from db.models import ControllerValue
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + uuid.uuid4().hex[:8] + "56" * 16
    zero_addr = "0x" + "0" * 40

    contract = _seed_contract(session, address=address)
    session.add(
        ControllerValue(
            contract_id=contract.id,
            controller_id="signerAddr",
            value=zero_addr,
            resolved_type="eoa",
            source="state_variable",
        )
    )
    session.commit()

    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "claim(bytes32,uint8,bytes32,bytes32)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "signature_auth",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "signature_recovery"},
                        {"source": "state_variable", "state_variable_name": "signerAddr"},
                    ],
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "signerAddr == ecrecover(h, v, r, s)",
                    "basis": [],
                    "confidence": "high",
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is not None
    cap = out["claim(bytes32,uint8,bytes32,bytes32)"]
    assert cap["kind"] == "signature_witness", (
        f"expected signature_witness wrapping the resolved signer; got kind={cap.get('kind')}"
    )
    signer = cap.get("signer") or {}
    assert signer.get("kind") == "finite_set", f"expected signer to be a finite_set; got kind={signer.get('kind')}"
    assert signer.get("members") == [], (
        f"expected empty signer members for zero-address signerAddr; got members={signer.get('members')}"
    )
    assert signer.get("membership_quality") == "exact", (
        f"expected membership_quality=exact when the resolved value is the zero address "
        f"(this is a known-empty answer, not 'unresolved'); got {signer.get('membership_quality')}"
    )


# ---------------------------------------------------------------------------
# Bug 4: end-to-end external-authority traversal. Given a descriptor whose
# authority contract emits relevant membership events, the resolver must
# expand to event-derived member addresses. The registry contract itself is
# only the source of logs, not the principal.
# ---------------------------------------------------------------------------


@requires_postgres
def test_external_set_resolves_to_indexed_event_members(session):
    """A semantic leaf that says 'membership in role X on registry Y' must
    serialize as ``finite_set(members=[m1, m2], confidence=enumerable)``
    when indexed_event_logs has the data. The registry contract itself
    is never an answer — that's the indirection layer, not the principal."""
    from db.models import IndexedEventCursor, IndexedEventLog
    from services.resolution.capability_resolver import resolve_contract_capabilities

    address = "0x" + uuid.uuid4().hex[:8] + "ef" * 16
    role_const_hex = "0x" + "ee" * 32  # PROTOCOL_UPGRADER
    member_a = "0x" + "aa" * 20
    member_b = "0x" + "bb" * 20
    topic0 = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"

    _seed_contract(session, address=address)
    for i, m in enumerate((member_a, member_b)):
        session.add(
            IndexedEventLog(
                chain_id=1,
                event_address=address,
                topic0=topic0,
                tx_hash=bytes([0x10 + i]) * 32,
                log_index=0,
                block_number=100 + i,
                block_hash=bytes([0x20 + i]) * 32,
                transaction_index=0,
                topics=[topic0, role_const_hex, _address_topic(m)],
                data_words=[],
            )
        )
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            last_indexed_block=18_500_000,
            last_indexed_block_hash=b"\xcc" * 32,
            backfill_complete=True,
        )
    )
    session.commit()

    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "upgradeTo(address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": {
                        # The cross-contract `roleRegistry.hasRole(role,
                        # sender)` shape is represented as a generic
                        # membership descriptor with an event hint.
                        "kind": "mapping_membership",
                        "key_sources": [
                            {"source": "constant", "constant_value": role_const_hex},
                            {"source": "msg_sender"},
                        ],
                        "storage_var": "_roles",
                        "enumeration_hint": [
                            {
                                "event_address": address,
                                "topic0": topic0,
                                "topics_to_keys": {1: 0, 2: 1},
                                "data_to_keys": {},
                                "direction": "add",
                            }
                        ],
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "roleRegistry.hasRole(PROTOCOL_UPGRADER, msg.sender)",
                    "basis": [],
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is not None
    cap = out["upgradeTo(address)"]
    assert cap["kind"] == "finite_set", (
        f"expected indexed events to expand the external leaf into a finite_set "
        f"of granted members; got kind={cap.get('kind')} (registry contract is not a principal)"
    )
    members = set(cap.get("members") or [])
    assert {member_a, member_b} <= members, (
        f"seeded indexed-event members not present in resolved capability; got {sorted(members)}"
    )


@requires_postgres
def test_external_authority_inlining_follows_proxy_to_impl_predicate_trees(session):
    """If an authority contract is a proxy, inline the implementation's
    predicate_trees while keeping event reads keyed to the runtime proxy."""
    from db.models import (
        Contract,
        ControllerValue,
        IndexedEventCursor,
        IndexedEventLog,
        JobStage,
        JobStatus,
        Protocol,
    )
    from services.resolution.capability_resolver import resolve_contract_capabilities

    target_addr = "0x" + uuid.uuid4().hex[:8] + "a1" * 16
    registry_proxy = "0x" + uuid.uuid4().hex[:8] + "b2" * 16
    registry_impl = "0x" + uuid.uuid4().hex[:8] + "c3" * 16
    member = "0x" + "77" * 20
    role_const_hex = "0x" + "12" * 32
    topic0 = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"

    proto = Protocol(name=f"capres_proxy_inline_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    target_artifact = {
        "schema_version": "semantic",
        "contract_name": "EtherFiAdmin",
        "trees": {
            "upgradeTo(address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [
                        {"source": "constant", "constant_value": role_const_hex},
                        {"source": "msg_sender"},
                    ],
                    "set_descriptor": {
                        "kind": "external_set",
                        "key_sources": [
                            {"source": "constant", "constant_value": role_const_hex},
                            {"source": "msg_sender"},
                        ],
                        "authority_contract": {
                            "address_source": {
                                "source": "state_variable",
                                "state_variable_name": "roleRegistry",
                            }
                        },
                        "callee_signature": "hasRole(bytes32,address)",
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "roleRegistry.hasRole(PROTOCOL_UPGRADER, msg.sender)",
                    "basis": [],
                },
            }
        },
    }
    target_job = _seed_job_with_artifact(session, address=target_addr, predicate_trees=target_artifact)
    target_contract = Contract(address=target_addr, chain="ethereum", protocol_id=proto.id, job_id=target_job.id)
    session.add(target_contract)
    session.flush()
    session.add(
        ControllerValue(
            contract_id=target_contract.id,
            controller_id="external_contract:roleRegistry",
            value=registry_proxy,
            resolved_type="contract",
            source="state_variable",
        )
    )

    proxy_job = _seed_job_with_artifact(session, address=registry_proxy, predicate_trees=None)
    proxy_contract = Contract(
        address=registry_proxy,
        chain="ethereum",
        protocol_id=proto.id,
        job_id=proxy_job.id,
        is_proxy=True,
        implementation=registry_impl,
    )
    session.add(proxy_contract)

    registry_artifact = {
        "schema_version": "semantic",
        "contract_name": "RoleRegistry",
        "trees": {
            "hasRole(bytes32,address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "parameter", "parameter_index": 1, "parameter_name": "account"},
                    ],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "key_sources": [
                            {"source": "parameter", "parameter_index": 0, "parameter_name": "role"},
                            {"source": "parameter", "parameter_index": 1, "parameter_name": "account"},
                        ],
                        "storage_var": "_roles",
                        "enumeration_hint": [
                            {
                                "event_address": registry_proxy,
                                "topic0": topic0,
                                "topics_to_keys": {1: 0, 2: 1},
                                "data_to_keys": {},
                                "direction": "add",
                            }
                        ],
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "_roles[role][msg.sender]",
                    "basis": [],
                },
            }
        },
    }
    impl_job = _seed_job_with_artifact(session, address=registry_impl, predicate_trees=registry_artifact)
    # The dependency gate unblocks dependers when the provider finishes
    # policy, which leaves the provider queued for coverage rather than
    # status=completed. Inlining must still be allowed at that point.
    impl_job.stage = JobStage.coverage
    impl_job.status = JobStatus.queued
    impl_job.request = {
        "address": registry_impl,
        "name": "RoleRegistry: (impl)",
        "chain": "ethereum",
        "parent_job_id": str(proxy_job.id),
        "proxy_address": registry_proxy,
    }
    session.add(Contract(address=registry_impl, chain="ethereum", protocol_id=proto.id, job_id=impl_job.id))

    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=registry_proxy,
            topic0=topic0,
            tx_hash=b"\xdd" * 32,
            log_index=0,
            block_number=100,
            block_hash=b"\xee" * 32,
            transaction_index=0,
            topics=[topic0, role_const_hex, _address_topic(member)],
            data_words=[],
        )
    )
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=registry_proxy,
            topic0=topic0,
            last_indexed_block=18_500_000,
            last_indexed_block_hash=b"\xff" * 32,
            backfill_complete=True,
        )
    )
    session.commit()

    out = resolve_contract_capabilities(session, address=target_addr, chain_id=1, job_id=target_job.id)
    assert out is not None
    cap = out["upgradeTo(address)"]
    assert cap["kind"] == "finite_set"
    assert member in (cap.get("members") or [])


@requires_postgres
def test_unscanned_event_cursor_defers_pending_index(session, monkeypatch):
    """A just-enrolled cursor at block 0 (cold, no backfill_complete) is index-cold:
    the caller-keyed ACL leaf defers to external_check_only tagged
    ``deferred_pending_index`` rather than a live genesis scan. The reconciler
    re-resolves once the indexer backfills the event address."""
    import services.resolution.mapping_enumerator as mapping_enumerator
    from db.models import IndexedEventCursor
    from services.resolution.capability_resolver import resolve_contract_capabilities

    def boom(*_args, **_kwargs):
        raise AssertionError("cold cursor must defer, never live-scan")

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values_sync", boom)

    address = "0x" + uuid.uuid4().hex[:8] + "c9" * 16
    role_const_hex = "0x" + "44" * 32
    topic0 = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"

    _seed_contract(session, address=address)
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=address,
            topic0=topic0,
            last_indexed_block=0,
            last_indexed_block_hash=None,
        )
    )
    session.commit()

    artifact = {
        "schema_version": "semantic",
        "contract_name": "T",
        "trees": {
            "pause()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "key_sources": [
                            {"source": "constant", "constant_value": role_const_hex},
                            {"source": "msg_sender"},
                        ],
                        "enumeration_hint": [
                            {
                                "event_address": address,
                                "topic0": topic0,
                                "topics_to_keys": {1: 0, 2: 1},
                                "data_to_keys": {},
                                "direction": "add",
                            }
                        ],
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "hasRole(ROLE, msg.sender)",
                    "basis": [],
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=address, predicate_trees=artifact)

    out = resolve_contract_capabilities(session, address=address, chain_id=1)
    assert out is not None
    cap = out["pause()"]
    assert cap["kind"] == "external_check_only"
    assert cap["check"]["extra"].get("deferred_pending_index") is True


@requires_postgres
def test_external_authority_inlining_binds_msg_sender_argument(session):
    """Inlining B(account) must bind A's msg.sender argument before
    evaluating B's parameter-based guard."""
    from db.models import Contract, ControllerValue, Protocol
    from services.resolution.capability_resolver import resolve_contract_capabilities

    target_addr = "0x" + uuid.uuid4().hex[:8] + "d1" * 16
    registry_proxy = "0x" + uuid.uuid4().hex[:8] + "d2" * 16
    registry_impl = "0x" + uuid.uuid4().hex[:8] + "d3" * 16
    owner = "0x" + "66" * 20

    proto = Protocol(name=f"capres_bind_args_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    target_artifact = {
        "schema_version": "semantic",
        "contract_name": "EtherFiAdmin",
        "trees": {
            "upgradeTo(address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [
                        {
                            "source": "external_call",
                            "callee": "onlyProtocolUpgrader",
                            "callee_selector": "0x5006bb7b",
                            "callee_signature": "onlyProtocolUpgrader(address)",
                        },
                        {"source": "msg_sender"},
                    ],
                    "set_descriptor": {
                        "kind": "external_set",
                        "authority_contract": {
                            "address_source": {
                                "source": "state_variable",
                                "state_variable_name": "roleRegistry",
                            }
                        },
                        "callee_signature": "onlyProtocolUpgrader(address)",
                        "callee_selector": "0x5006bb7b",
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "roleRegistry.onlyProtocolUpgrader(msg.sender)",
                    "basis": [],
                },
            }
        },
    }
    target_job = _seed_job_with_artifact(session, address=target_addr, predicate_trees=target_artifact)
    target_contract = Contract(address=target_addr, chain="ethereum", protocol_id=proto.id, job_id=target_job.id)
    session.add(target_contract)
    session.flush()
    session.add(
        ControllerValue(
            contract_id=target_contract.id,
            controller_id="external_contract:roleRegistry",
            value=registry_proxy,
            resolved_type="contract",
            source="state_variable",
        )
    )

    proxy_job = _seed_job_with_artifact(session, address=registry_proxy, predicate_trees=None)
    session.add(
        Contract(
            address=registry_proxy,
            chain="ethereum",
            protocol_id=proto.id,
            job_id=proxy_job.id,
            is_proxy=True,
            implementation=registry_impl,
        )
    )

    registry_artifact = {
        "schema_version": "semantic",
        "contract_name": "RoleRegistry",
        "trees": {
            "onlyProtocolUpgrader(address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "business",
                    "operands": [
                        {"source": "state_variable", "state_variable_name": "_owner"},
                        {"source": "parameter", "parameter_name": "account", "parameter_index": 0},
                    ],
                    "references_msg_sender": False,
                    "parameter_indices": [0],
                    "expression": "owner() != account",
                    "basis": [],
                },
            }
        },
    }
    impl_job = _seed_job_with_artifact(session, address=registry_impl, predicate_trees=registry_artifact)
    impl_job.request = {
        "address": registry_impl,
        "name": "RoleRegistry: (impl)",
        "chain": "ethereum",
        "parent_job_id": str(proxy_job.id),
        "proxy_address": registry_proxy,
    }
    impl_contract = Contract(address=registry_impl, chain="ethereum", protocol_id=proto.id, job_id=impl_job.id)
    session.add(impl_contract)
    session.flush()
    session.add(
        ControllerValue(
            contract_id=impl_contract.id,
            controller_id="state_variable:_owner",
            value=owner,
            resolved_type="eoa",
            source="state_variable",
        )
    )
    session.commit()

    out = resolve_contract_capabilities(session, address=target_addr, chain_id=1, job_id=target_job.id)
    assert out is not None
    cap = out["upgradeTo(address)"]
    assert cap["kind"] == "finite_set"
    assert cap.get("members") == [owner]


@requires_postgres
def test_external_authority_inlining_through_empty_proxy_artifact(session):
    """Regression mirroring live EtherFi data (PR-95): an authority contract
    that is a UUPS proxy has an *empty-but-present* ``predicate_trees`` artifact
    of its own — the static pipeline writes ``{"trees": {}}`` for the logicless
    proxy. The implementation child job holds the real
    ``onlyProtocolUpgrader(account) => _owner == account`` tree, and the
    implementation's ``_owner`` ControllerValue is the EtherFiTimelock.

    Before the fix, ``find_analysis_job_for_address`` accepted the proxy job
    because its empty artifact counted as "present", shadowing the
    implementation's trees. The inliner then saw an empty tree set, fell through
    to event-materialization (which cannot resolve a void-revert
    ``onlyProtocolUpgrader`` — it never returns a bool), and emitted
    ``external_check_only`` with **zero principals**. The net effect on the
    Surface: every UUPS upgrade function in the protocol (19 on EtherFi) was
    ownerless, with the true upgrade authority (the timelock behind the
    RoleRegistry) missing entirely.

    The sibling ``test_external_authority_inlining_binds_msg_sender_argument``
    seeds the proxy with *no* artifact (``predicate_trees=None`` skips
    ``store_artifact``), so it never exercised the empty-artifact short-circuit
    that the real pipeline produces. This test pins exactly that gap: the empty
    proxy artifact must not shadow the implementation's trees, and the gate must
    resolve via the registry's real ``_owner == account`` check.
    """
    from db.models import Contract, ControllerValue, Protocol
    from services.resolution.capability_resolver import resolve_contract_capabilities

    target_addr = "0x" + uuid.uuid4().hex[:8] + "e1" * 16
    registry_proxy = "0x" + uuid.uuid4().hex[:8] + "e2" * 16
    registry_impl = "0x" + uuid.uuid4().hex[:8] + "e3" * 16
    timelock = "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761"  # EtherFiTimelock (real)

    proto = Protocol(name=f"capres_empty_proxy_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    target_artifact = {
        "schema_version": "semantic",
        "contract_name": "PriorityWithdrawalQueue",
        "trees": {
            "upgradeTo(address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [
                        {
                            "source": "external_call",
                            "callee": "onlyProtocolUpgrader",
                            "callee_selector": "0x5006bb7b",
                            "callee_signature": "onlyProtocolUpgrader(address)",
                        },
                        {"source": "msg_sender"},
                    ],
                    "set_descriptor": {
                        "kind": "external_set",
                        "authority_contract": {
                            "address_source": {
                                "source": "state_variable",
                                "state_variable_name": "roleRegistry",
                            }
                        },
                        "callee_signature": "onlyProtocolUpgrader(address)",
                        "callee_selector": "0x5006bb7b",
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "roleRegistry.onlyProtocolUpgrader(msg.sender)",
                    "basis": ["external call must not revert"],
                },
            }
        },
    }
    target_job = _seed_job_with_artifact(session, address=target_addr, predicate_trees=target_artifact)
    target_contract = Contract(address=target_addr, chain="ethereum", protocol_id=proto.id, job_id=target_job.id)
    session.add(target_contract)
    session.flush()
    session.add(
        ControllerValue(
            contract_id=target_contract.id,
            controller_id="external_contract:roleRegistry",
            value=registry_proxy,
            resolved_type="contract",
            source="state_variable",
        )
    )

    # The crux: the proxy job carries an empty-but-present predicate_trees
    # artifact (what the static pipeline writes for a logicless proxy), NOT a
    # missing one. This is the exact shape the sibling test never seeded.
    proxy_job = _seed_job_with_artifact(
        session,
        address=registry_proxy,
        predicate_trees={"schema_version": "semantic", "contract_name": "RoleRegistry", "trees": {}},
    )
    session.add(
        Contract(
            address=registry_proxy,
            chain="ethereum",
            protocol_id=proto.id,
            job_id=proxy_job.id,
            is_proxy=True,
            implementation=registry_impl,
        )
    )

    registry_artifact = {
        "schema_version": "semantic",
        "contract_name": "RoleRegistry",
        "trees": {
            "onlyProtocolUpgrader(address)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "business",
                    "operands": [
                        {"source": "state_variable", "state_variable_name": "_owner"},
                        {"source": "parameter", "parameter_name": "account", "parameter_index": 0},
                    ],
                    "references_msg_sender": False,
                    "parameter_indices": [0],
                    "expression": "owner() != account",
                    "basis": ["if-revert via successor NodeType.EXPRESSION"],
                },
            }
        },
    }
    impl_job = _seed_job_with_artifact(session, address=registry_impl, predicate_trees=registry_artifact)
    impl_job.request = {
        "address": registry_impl,
        "name": "RoleRegistry: (impl)",
        "chain": "ethereum",
        "parent_job_id": str(proxy_job.id),
        "proxy_address": registry_proxy,
    }
    impl_contract = Contract(address=registry_impl, chain="ethereum", protocol_id=proto.id, job_id=impl_job.id)
    session.add(impl_contract)
    session.flush()
    session.add(
        ControllerValue(
            contract_id=impl_contract.id,
            controller_id="state_variable:_owner",
            value=timelock,
            resolved_type="timelock",
            source="state_variable",
        )
    )
    session.commit()

    out = resolve_contract_capabilities(session, address=target_addr, chain_id=1, job_id=target_job.id)
    assert out is not None
    cap = out["upgradeTo(address)"]
    assert cap["kind"] == "finite_set", (
        f"empty proxy predicate_trees must not shadow the implementation's onlyProtocolUpgrader "
        f"tree; expected finite_set([timelock]) but got kind={cap.get('kind')} "
        f"(external_check_only here is the bug: the upgrade gate resolved to zero principals)"
    )
    assert [m.lower() for m in (cap.get("members") or [])] == [timelock], (
        f"expected the EtherFiTimelock resolved from RoleRegistry._owner; got {cap.get('members')}"
    )
    # Resolved via the registry's real `_owner == account` check (read from the
    # ControllerValue), not a heuristic owner() guess — so exact / enumerable.
    assert cap.get("membership_quality") == "exact", (
        f"expected exact membership from the real check logic; got {cap.get('membership_quality')}"
    )
    assert cap.get("confidence") == "enumerable", (
        f"expected enumerable confidence from the real check logic; got {cap.get('confidence')}"
    )


@requires_postgres
def test_external_authority_inlining_uses_check_trees_and_call_frame(session):
    from eth_utils.crypto import keccak

    from db.models import Contract, ControllerValue, IndexedEventCursor, IndexedEventLog, Protocol
    from services.resolution.capability_resolver import resolve_contract_capabilities

    target_addr = "0x" + uuid.uuid4().hex[:8] + "a4" * 16
    registry_addr = "0x" + uuid.uuid4().hex[:8] + "b5" * 16
    member = "0x" + "88" * 20
    guarded_selector = "0x" + keccak(text="guarded()").hex()[:8]
    topic0 = "0x" + "44" * 32

    proto = Protocol(name=f"capres_check_tree_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    target_artifact = {
        "schema_version": "semantic",
        "contract_name": "Protected",
        "trees": {
            "guarded()": {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [
                        {"source": "msg_sender"},
                        {"source": "self_address"},
                        {"source": "computed", "computed_kind": "msg.sig"},
                    ],
                    "set_descriptor": {
                        "kind": "external_set",
                        "authority_contract": {
                            "address_source": {
                                "source": "state_variable",
                                "state_variable_name": "authority",
                            }
                        },
                        "callee_signature": "allowed(address,address,bytes4)",
                        "callee_selector": "0x77777777",
                    },
                    "references_msg_sender": True,
                    "parameter_indices": [],
                    "expression": "authority.allowed(msg.sender,address(this),msg.sig)",
                    "basis": [],
                },
            }
        },
    }
    target_job = _seed_job_with_artifact(session, address=target_addr, predicate_trees=target_artifact)
    target_contract = Contract(address=target_addr, chain="ethereum", protocol_id=proto.id, job_id=target_job.id)
    session.add(target_contract)
    session.flush()
    session.add(
        ControllerValue(
            contract_id=target_contract.id,
            controller_id="external_contract:authority",
            value=registry_addr,
            resolved_type="contract",
            source="state_variable",
        )
    )

    registry_artifact = {
        "schema_version": "semantic",
        "contract_name": "RenamedAuthority",
        "trees": {},
        "check_trees": {
            "allowed(address,address,bytes4)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "business",
                    "operands": [
                        {"source": "parameter", "parameter_index": 1},
                        {"source": "parameter", "parameter_index": 2},
                        {"source": "parameter", "parameter_index": 0},
                    ],
                    "set_descriptor": {
                        "kind": "mapping_membership",
                        "key_sources": [
                            {"source": "parameter", "parameter_index": 1},
                            {"source": "parameter", "parameter_index": 2},
                            {"source": "parameter", "parameter_index": 0},
                        ],
                        "storage_var": "can",
                        "enumeration_hint": [
                            {
                                "event_address": registry_addr,
                                "topic0": topic0,
                                "topics_to_keys": {1: 0, 2: 1, 3: 2},
                                "data_to_keys": {},
                                "direction": "add",
                            }
                        ],
                    },
                    "references_msg_sender": False,
                    "parameter_indices": [0, 1, 2],
                    "expression": "can[target][sig][user]",
                    "basis": [],
                },
            }
        },
    }
    _seed_job_with_artifact(session, address=registry_addr, predicate_trees=registry_artifact)

    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=registry_addr,
            topic0=topic0,
            tx_hash=b"\x84" * 32,
            log_index=0,
            block_number=100,
            block_hash=b"\x85" * 32,
            transaction_index=0,
            topics=[topic0, _address_topic(target_addr), _bytes4_topic(guarded_selector), _address_topic(member)],
            data_words=[],
        )
    )
    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=registry_addr,
            topic0=topic0,
            last_indexed_block=200,
            last_indexed_block_hash=b"\x86" * 32,
            backfill_complete=True,
        )
    )
    session.commit()

    out = resolve_contract_capabilities(session, address=target_addr, chain_id=1, job_id=target_job.id)
    assert out is not None
    cap = out["guarded()"]
    assert cap["kind"] == "finite_set"
    assert cap.get("members") == [member]


@requires_postgres
def test_dependency_provider_lookup_returns_impl_child_for_proxy(session):
    from db.models import Contract, Protocol
    from db.queue import store_artifact
    from services.resolution.capability_resolver import find_dependency_provider_job_for_address

    proxy_addr = "0x" + uuid.uuid4().hex[:8] + "d4" * 16
    impl_addr = "0x" + uuid.uuid4().hex[:8] + "e5" * 16

    proto = Protocol(name=f"capres_dep_provider_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    proxy_job = _seed_job_with_artifact(session, address=proxy_addr, predicate_trees=None)
    proxy_job.request = {"address": proxy_addr, "name": "Registry", "chain": "ethereum"}
    session.add(
        Contract(
            address=proxy_addr,
            chain="ethereum",
            protocol_id=proto.id,
            job_id=proxy_job.id,
            is_proxy=True,
            implementation=impl_addr,
        )
    )

    impl_job = _seed_job_with_artifact(session, address=impl_addr, predicate_trees=None)
    impl_job.request = {
        "address": impl_addr,
        "name": "Registry: (impl)",
        "chain": "ethereum",
        "parent_job_id": str(proxy_job.id),
        "proxy_address": proxy_addr,
    }
    store_artifact(session, impl_job.id, "effective_permissions", data={"functions": []})
    session.commit()

    lookup = find_dependency_provider_job_for_address(session, proxy_addr, chain="ethereum")
    assert lookup is not None
    assert lookup.runtime_job.id == proxy_job.id
    assert lookup.analysis_job.id == impl_job.id


@requires_postgres
def test_static_proxy_resolution_redirects_pending_policy_dependency_to_impl(session):
    from db.models import JobDependency, JobStage
    from workers.static_worker import _redirect_proxy_policy_dependencies

    depender_addr = "0x" + uuid.uuid4().hex[:8] + "f6" * 16
    proxy_addr = "0x" + uuid.uuid4().hex[:8] + "a7" * 16
    impl_addr = "0x" + uuid.uuid4().hex[:8] + "b8" * 16

    depender = _seed_job_with_artifact(session, address=depender_addr, predicate_trees=None)
    session.add(
        JobDependency(
            depender_job_id=depender.id,
            provider_chain="ethereum",
            provider_address=proxy_addr,
            required_stage=JobStage.policy,
            status="pending",
        )
    )
    session.commit()

    changed = _redirect_proxy_policy_dependencies(
        session,
        chain="ethereum",
        proxy_addr=proxy_addr,
        impl_addr=impl_addr,
    )

    assert changed == 1
    row = session.query(JobDependency).filter_by(depender_job_id=depender.id).one()
    assert row.provider_address == impl_addr.lower()
    assert row.status == "pending"


# ---------------------------------------------------------------------------
# C.1 cutover: ``_load_state_var_values`` scoped by exact Contract.job_id
# first, then by address/chain fallback for legacy rows.
# ---------------------------------------------------------------------------


@requires_postgres
def test_load_state_var_values_scoped_by_chain(session):
    """Two Contract rows for the same address, different chains. The
    resolver, given chain='ethereum', must read only the ethereum
    Contract's ControllerValue — not the optimism row's stale value."""
    from db.models import Contract, ControllerValue, Protocol
    from services.resolution.capability_resolver import _load_state_var_values

    address = "0x" + uuid.uuid4().hex[:8] + "c1" * 16
    eth_owner = "0x" + "ee" * 20
    op_owner = "0x" + "ff" * 20

    proto = Protocol(name=f"capres_chain_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    eth_contract = Contract(address=address, chain="ethereum", protocol_id=proto.id)
    op_contract = Contract(address=address, chain="optimism", protocol_id=proto.id)
    session.add_all([eth_contract, op_contract])
    session.flush()

    session.add(
        ControllerValue(
            contract_id=eth_contract.id,
            controller_id="state_variable:_owner",
            value=eth_owner,
            resolved_type="eoa",
            source="state_variable",
        )
    )
    session.add(
        ControllerValue(
            contract_id=op_contract.id,
            controller_id="state_variable:_owner",
            value=op_owner,
            resolved_type="eoa",
            source="state_variable",
        )
    )
    session.commit()

    # No Contract.job_id here, so this exercises the legacy address/chain fallback.
    job = _seed_job_with_artifact(session, address=address, predicate_trees=None)

    eth_values = _load_state_var_values(session, address, job_id=job.id, chain="ethereum")
    assert eth_values.get("_owner") == eth_owner, (
        f"expected ethereum-chain owner ({eth_owner}); got {eth_values.get('_owner')} "
        f"(would have been the optimism row {op_owner} without chain scoping)"
    )

    op_values = _load_state_var_values(session, address, job_id=job.id, chain="optimism")
    assert op_values.get("_owner") == op_owner, (
        f"expected optimism-chain owner ({op_owner}); got {op_values.get('_owner')}"
    )


@requires_postgres
def test_load_state_var_values_prefers_exact_job_contract_over_created_at(session):
    """A Contract row tied to the analysis job must be selected even if its
    ``created_at`` is later than the Job row.

    Static/resolution can create or update the Contract row after the Job
    record exists. Filtering on ``Contract.created_at <= Job.created_at``
    drops the very ControllerValue rows the current job just wrote."""
    from datetime import timedelta

    from db.models import Contract, ControllerValue, Job, JobStage, JobStatus, Protocol
    from services.resolution.capability_resolver import _load_state_var_values

    address = "0x" + uuid.uuid4().hex[:8] + "c2" * 16
    late_owner = "0x" + "22" * 20

    proto = Protocol(name=f"capres_temporal_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()

    base_time = datetime.now(timezone.utc) - timedelta(hours=2)
    job_time = base_time + timedelta(minutes=30)

    # Job at job_time (30 minutes after base).
    job = Job(
        address=address,
        request={"address": address, "name": "T", "chain": "ethereum"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=job_time,
        updated_at=job_time,
    )
    session.add(job)
    session.commit()

    # Contract row created AFTER job_time, but explicitly owned by this job.
    late_contract = Contract(address=address, chain="ethereum", protocol_id=proto.id, job_id=job.id)
    late_contract.created_at = job_time + timedelta(hours=1)
    session.add(late_contract)
    session.flush()
    session.add(
        ControllerValue(
            contract_id=late_contract.id,
            controller_id="state_variable:_owner",
            value=late_owner,
            resolved_type="eoa",
            source="state_variable",
        )
    )
    session.commit()

    values = _load_state_var_values(session, address, job_id=job.id, chain="ethereum")
    assert values.get("_owner") == late_owner


@requires_postgres
def test_load_state_var_values_falls_back_when_job_id_missing(session, caplog):
    """Legacy behavior: when job_id is None, fall back to the latest
    Contract by address (today's behavior). MUST WARN-log the
    fallback so callers can audit the regression risk."""
    import logging

    from db.models import Contract, ControllerValue, Protocol
    from services.resolution.capability_resolver import _load_state_var_values

    address = "0x" + uuid.uuid4().hex[:8] + "c3" * 16
    owner = "0x" + "33" * 20

    proto = Protocol(name=f"capres_fallback_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(address=address, chain="ethereum", protocol_id=proto.id)
    session.add(contract)
    session.flush()
    session.add(
        ControllerValue(
            contract_id=contract.id,
            controller_id="state_variable:_owner",
            value=owner,
            resolved_type="eoa",
            source="state_variable",
        )
    )
    session.commit()

    with caplog.at_level(logging.WARNING, logger="services.resolution.capability_resolver"):
        values = _load_state_var_values(session, address, job_id=None, chain=None)

    assert values.get("_owner") == owner, "legacy address-only fallback should still resolve"
    # WARN-log fired so an operator can spot the unscoped path.
    assert any("without job_id" in rec.message for rec in caplog.records), (
        f"expected a warn-log about job_id=None fallback; got {[r.message for r in caplog.records]}"
    )


def test_capability_kind_label_buckets_and_lowercases():
    """The per-job capability-kind tally (the Veda OR-regression detector) must
    use uniform lowercase keys. ``CapabilityExpr`` stores composite kinds as
    "OR"/"AND"; without lowercasing, the diff splits across cap_or vs cap_OR."""
    from services.resolution.capabilities import CapabilityExpr, Condition, ExternalCheck
    from services.resolution.capability_resolver import _capability_kind_label

    assert _capability_kind_label(CapabilityExpr.finite_set(["0x" + "11" * 20])) == "finite_set"
    # Exact-empty finite_set is a real "nobody", bucketed separately.
    assert _capability_kind_label(CapabilityExpr.finite_set([], quality="exact")) == "resolved_empty"
    assert (
        _capability_kind_label(CapabilityExpr.external_check_only(ExternalCheck("0x" + "22" * 20, "0x12345678")))
        == "external_check_only"
    )
    # The cold-index marker promotes external_check_only into its own bucket.
    deferred = CapabilityExpr.external_check_only(ExternalCheck(None, None, extra={"deferred_pending_index": True}))
    assert _capability_kind_label(deferred) == "deferred_pending_index"
    assert _capability_kind_label(CapabilityExpr.unsupported("nope")) == "unsupported"
    assert (
        _capability_kind_label(CapabilityExpr.conditional_universal(Condition(kind="business")))
        == "conditional_universal"
    )
    # The fix: composite kinds are stored uppercase but must tally lowercase.
    leaf = CapabilityExpr.finite_set(["0x" + "33" * 20])
    assert _capability_kind_label(CapabilityExpr.structural_or([leaf, leaf])) == "or"
    assert _capability_kind_label(CapabilityExpr.structural_and([leaf, leaf])) == "and"
