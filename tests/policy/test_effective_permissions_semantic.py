"""Per-kind row representation tests for the semantic
``build_effective_permissions`` + ``write_effective_function_rows``
pipeline.

Each test fabricates a ``CapabilityExpr`` directly and asserts the
resulting ``EffectiveFunction`` columns and ``FunctionPrincipal`` row
counts match the table below:

| kind                          | EF columns                       | FP rows |
|-------------------------------|----------------------------------|---------|
| finite_set                    | capability_expr only             | N       |
| threshold_group               | capability_expr only             | 1       |
| signature_witness(finite)     | capability_expr only             | N       |
| signature_witness(non-finite) | capability_expr only             | 0       |
| finite_set(empty exact)       | + status='resolved_empty'        | 0       |
| cofinite_blacklist            | + conditions, status='public',   | 0       |
|                               |   authority_public=True          |         |
| external_check_only           | capability_expr only             | 0       |
| conditional_universal         | + conditions, status='public',   | 0       |
|                               |   authority_public=True          |         |
| unsupported                   | + status='unsupported'           | 0       |
| resolvable composite paths    | full tree + projected path cols  | path N  |
| irreducible composite         | full tree in capability_expr     | 0       |
| OR pure-finite                | resolver simplifies to union     | union   |

Tests don't go through Slither; they instantiate ``CapabilityExpr``
shapes directly and feed them to the writer through a SQLAlchemy
in-memory session backed by an SQLite store.

The Postgres-only column types (JSONB, ARRAY, GIN index) are swapped
to their SQLite equivalents inside ``_in_memory_session`` so the test
suite runs offline.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.types import JSON

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.policy.effective_permissions_writer import (
    _column_values_for_capability,
    _principal_rows_for_capability,
    write_effective_function_rows,
)
from services.resolution.capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
)
from services.resolution.capability_resolver import capability_to_dict

# ---------------------------------------------------------------------------
# In-memory SQLite mirror of the columns the writer touches.
# Lets us assert row writes without spinning up Postgres.
# ---------------------------------------------------------------------------


_TestBase = declarative_base()


class _TContract(_TestBase):
    __tablename__ = "contracts"
    id = Column(Integer, primary_key=True)
    address = Column(String(42))


class _TEffectiveFunction(_TestBase):
    __tablename__ = "effective_functions"
    id = Column(Integer, primary_key=True)
    contract_id = Column(Integer, ForeignKey("contracts.id"))
    deployment_address = Column(String(42))
    function_name = Column(String(255))
    selector = Column(String(10))
    abi_signature = Column(Text)
    effect_labels = Column(JSON)
    effect_targets = Column(JSON)
    action_summary = Column(Text)
    authority_public = Column(Boolean, default=False)
    authority_openness = Column(String(20))
    authority_roles = Column(JSON)
    capability_expr = Column(JSON)
    conditions = Column(JSON)
    status = Column(String(50))
    claims = Column(JSON)
    principals = relationship(
        "_TFunctionPrincipal",
        backref="function",
        cascade="all, delete-orphan",
    )


class _TFunctionPrincipal(_TestBase):
    __tablename__ = "function_principals"
    id = Column(Integer, primary_key=True)
    function_id = Column(Integer, ForeignKey("effective_functions.id"))
    address = Column(String(42))
    resolved_type = Column(String(50))
    origin = Column(String(255))
    principal_type = Column(String(50))
    details = Column(JSON)


@pytest.fixture
def db_session(monkeypatch: pytest.MonkeyPatch):
    """In-memory SQLite session with the writer's models swapped for
    JSON-friendly equivalents."""
    engine = create_engine("sqlite:///:memory:")
    _TestBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    monkeypatch.setattr(
        "services.policy.effective_permissions_writer.EffectiveFunction",
        _TEffectiveFunction,
    )
    monkeypatch.setattr(
        "services.policy.effective_permissions_writer.FunctionPrincipal",
        _TFunctionPrincipal,
    )

    contract = _TContract(id=1, address="0x" + "1" * 40)
    session.add(contract)
    session.commit()
    yield session
    session.close()
    engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fn_record(signature: str, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "function": signature,
        "abi_signature": signature,
        "selector": "0xdeadbeef",
        "effect_labels": [],
        "effect_targets": [],
        "action_summary": "stub",
        "authority_public": False,
        "authority_roles": [],
        "controllers": [],
        "direct_owner": None,
    }
    base.update(overrides)
    return base


def _ef_row(session) -> Any:
    return session.query(_TEffectiveFunction).first()


def _principals(session) -> list[Any]:
    return list(session.query(_TFunctionPrincipal).order_by(_TFunctionPrincipal.address).all())


# ---------------------------------------------------------------------------
# finite_set
# ---------------------------------------------------------------------------


def test_finite_set_emits_n_principal_rows(db_session) -> None:
    members = [
        "0x" + "a" * 40,
        "0x" + "b" * 40,
        "0x" + "c" * 40,
    ]
    cap = CapabilityExpr.finite_set(members)

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("doThing()")],
        capability_by_function={"doThing()": cap},
    )
    db_session.commit()

    rows = _principals(db_session)
    assert len(rows) == 3
    assert {r.address for r in rows} == set(m.lower() for m in members)
    for r in rows:
        assert r.principal_type == "controller"
    ef = _ef_row(db_session)
    assert ef.capability_expr["kind"] == "finite_set"
    assert sorted(ef.capability_expr["members"]) == sorted(m.lower() for m in members)
    assert ef.conditions is None
    assert ef.status is None
    assert ef.authority_public is False


def test_finite_set_with_conditions_writes_rows_and_preserves_conditions(db_session) -> None:
    condition = Condition(kind="business", description="token transfer return data accepted")
    member = "0x" + "a" * 40
    cap = CapabilityExpr.finite_set([member], conditions=[condition])

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("recoverToken(address,address,uint256)")],
        capability_by_function={"recoverToken(address,address,uint256)": cap},
    )
    db_session.commit()

    expected_conditions = [{"kind": "business", "description": "token transfer return data accepted"}]
    rows = _principals(db_session)
    assert len(rows) == 1
    assert rows[0].address == member
    assert rows[0].details["conditions"] == expected_conditions
    ef = _ef_row(db_session)
    assert ef.conditions == expected_conditions
    assert ef.status is None
    assert ef.authority_public is False


def test_exact_empty_finite_set_marks_resolved_empty(db_session) -> None:
    cap = CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("renounceOnly()")],
        capability_by_function={"renounceOnly()": cap},
    )
    db_session.commit()

    assert len(_principals(db_session)) == 0
    ef = _ef_row(db_session)
    assert ef.status == "resolved_empty"
    assert ef.authority_public is False
    assert ef.capability_expr["kind"] == "finite_set"
    assert ef.capability_expr["members"] == []
    assert ef.capability_expr["membership_quality"] == "exact"


def test_lower_bound_empty_finite_set_stays_unresolved_gap(db_session) -> None:
    cap = CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial")

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("guardedButNotEnumerated()")],
        capability_by_function={"guardedButNotEnumerated()": cap},
    )
    db_session.commit()

    assert len(_principals(db_session)) == 0
    ef = _ef_row(db_session)
    assert ef.status is None
    assert ef.capability_expr["membership_quality"] == "lower_bound"


# ---------------------------------------------------------------------------
# threshold_group (Safe)
# ---------------------------------------------------------------------------


def test_threshold_group_emits_one_safe_row(db_session) -> None:
    signers = [f"0x{(0x10 + i):040x}" for i in range(5)]
    cap = CapabilityExpr.threshold_group(3, signers)
    safe_addr = "0x" + "5" * 40

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("manage()")],
        capability_by_function={"manage()": cap},
        safe_address_lookup={"default": safe_addr},
    )
    db_session.commit()

    rows = _principals(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.address == safe_addr.lower()
    assert row.resolved_type == "safe"
    assert row.principal_type == "controller"
    assert row.details["threshold"] == 3
    assert len(row.details["owners"]) == 5
    assert all(o.startswith("0x") for o in row.details["owners"])

    ef = _ef_row(db_session)
    assert ef.capability_expr["kind"] == "threshold_group"
    assert ef.capability_expr["threshold"]["m"] == 3
    assert len(ef.capability_expr["threshold"]["signers"]) == 5


# ---------------------------------------------------------------------------
# signature_witness
# ---------------------------------------------------------------------------


def test_signature_witness_finite_emits_signer_rows(db_session) -> None:
    inner = CapabilityExpr.finite_set(["0x" + "a" * 40, "0x" + "b" * 40])
    cap = CapabilityExpr.signature_witness(inner)

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("permit()")],
        capability_by_function={"permit()": cap},
    )
    db_session.commit()

    rows = _principals(db_session)
    assert len(rows) == 2
    for r in rows:
        assert r.principal_type == "signature_witness"
        assert r.details["signer_kind"] == "finite_set"
    ef = _ef_row(db_session)
    assert ef.capability_expr["kind"] == "signature_witness"
    assert ef.capability_expr["signer"]["kind"] == "finite_set"


def test_signature_witness_external_emits_zero_rows(db_session) -> None:
    inner = CapabilityExpr.external_check_only(
        ExternalCheck(target_address="0x" + "9" * 40, target_call_selector="0x12345678"),
    )
    cap = CapabilityExpr.signature_witness(inner)

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("permit()")],
        capability_by_function={"permit()": cap},
    )
    db_session.commit()

    rows = _principals(db_session)
    assert len(rows) == 0
    ef = _ef_row(db_session)
    assert ef.capability_expr["kind"] == "signature_witness"
    assert ef.capability_expr["signer"]["kind"] == "external_check_only"


# ---------------------------------------------------------------------------
# cofinite_blacklist / external_check_only
# ---------------------------------------------------------------------------


def test_cofinite_blacklist_is_public_with_no_rows(db_session) -> None:
    # "Anyone except a finite exclusion" is permissionless modulo a denylist: it projects
    # to a PUBLIC path with no enumerated principals, carrying the exclusion as a business
    # side-condition so a reviewer still sees the filter — NOT an under-resolved residual
    # (status=None), which is the dead-end behavior this asserts we no longer produce.
    cap = CapabilityExpr.cofinite_blacklist(["0x" + "a" * 40, "0x" + "b" * 40])

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("openCall()")],
        capability_by_function={"openCall()": cap},
    )
    db_session.commit()

    assert len(_principals(db_session)) == 0
    ef = _ef_row(db_session)
    assert ef.capability_expr["kind"] == "cofinite_blacklist"
    assert len(ef.capability_expr["blacklist"]) == 2
    assert ef.status == "public"
    assert ef.authority_public is True
    assert ef.conditions is not None
    assert any(
        c.get("kind") == "denylist" and "denylist exclusion" in (c.get("description") or "") for c in ef.conditions
    ), f"the denylist must be surfaced as a side-condition; got {ef.conditions}"


def test_external_check_only_emits_zero_rows(db_session) -> None:
    check = ExternalCheck(
        target_address="0x" + "5" * 40,
        target_call_selector="0xdeadbeef",
        extra={"kind": "eip1271"},
    )
    cap = CapabilityExpr.external_check_only(check)

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("validate()")],
        capability_by_function={"validate()": cap},
    )
    db_session.commit()

    assert len(_principals(db_session)) == 0
    ef = _ef_row(db_session)
    assert ef.capability_expr["kind"] == "external_check_only"
    assert ef.capability_expr["check"]["target_address"] == "0x" + "5" * 40
    assert ef.capability_expr["check"]["target_call_selector"] == "0xdeadbeef"


# ---------------------------------------------------------------------------
# conditional_universal / unsupported
# ---------------------------------------------------------------------------


def test_conditional_universal_emits_zero_rows_authority_public_true(db_session) -> None:
    cap = CapabilityExpr.conditional_universal(
        Condition(kind="time", description="after 2026-01-01"),
    )

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("settle()")],
        capability_by_function={"settle()": cap},
    )
    db_session.commit()

    assert len(_principals(db_session)) == 0
    ef = _ef_row(db_session)
    assert ef.authority_public is True
    assert ef.status == "public"
    assert ef.conditions is not None
    assert len(ef.conditions) == 1
    assert ef.conditions[0]["kind"] == "time"


def test_unsupported_emits_zero_rows_status_unsupported(db_session) -> None:
    cap = CapabilityExpr.unsupported("opaque_authority_check")

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("opaque()")],
        capability_by_function={"opaque()": cap},
    )
    db_session.commit()

    assert len(_principals(db_session)) == 0
    ef = _ef_row(db_session)
    assert ef.status == "unsupported"
    assert ef.capability_expr["kind"] == "unsupported"
    assert ef.capability_expr["unsupported_reason"] == "opaque_authority_check"


# ---------------------------------------------------------------------------
# AND / OR
# ---------------------------------------------------------------------------


def test_irreducible_and_emits_zero_rows_with_tree(db_session) -> None:
    """``finite_set AND threshold_group`` doesn't reduce to a single
    kind (the resolver's ``intersect`` returns ``structural_and`` for
    that mix). The tree lives on ``capability_expr``; zero principal
    rows because no consumer should treat one leaf in isolation as
    'address can call as itself'."""
    finite = CapabilityExpr.finite_set(["0x" + "a" * 40])
    safe = CapabilityExpr.threshold_group(2, ["0x" + "b" * 40, "0x" + "c" * 40])
    cap = CapabilityExpr.structural_and([finite, safe])

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("dangerous()")],
        capability_by_function={"dangerous()": cap},
    )
    db_session.commit()

    assert len(_principals(db_session)) == 0
    ef = _ef_row(db_session)
    assert ef.capability_expr["kind"] == "AND"
    children = ef.capability_expr["children"]
    assert len(children) == 2
    assert {c["kind"] for c in children} == {"finite_set", "threshold_group"}


def test_or_pure_set_emits_union(db_session) -> None:
    """OR of two finite_sets is simplified by the resolver's ``union``
    combinator into a single finite_set covering the merged member
    list. The writer sees a finite_set and emits N rows."""
    from services.resolution.capabilities import union

    a = CapabilityExpr.finite_set(["0x" + "a" * 40, "0x" + "b" * 40])
    b = CapabilityExpr.finite_set(["0x" + "b" * 40, "0x" + "c" * 40])
    merged = union(a, b)
    assert merged.kind == "finite_set"

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("anyOf()")],
        capability_by_function={"anyOf()": merged},
    )
    db_session.commit()

    rows = _principals(db_session)
    assert len(rows) == 3
    assert {r.address for r in rows} == {
        "0x" + "a" * 40,
        "0x" + "b" * 40,
        "0x" + "c" * 40,
    }


def test_mixed_or_public_and_finite_writes_public_and_principal(db_session) -> None:
    finite = CapabilityExpr.finite_set(["0x" + "a" * 40])
    public = CapabilityExpr.conditional_universal(
        Condition(kind="business", description="public capability enabled"),
    )
    cap = CapabilityExpr.structural_or([finite, public])

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("send((uint32,bytes32,bytes,bytes,bytes),address)")],
        capability_by_function={"send((uint32,bytes32,bytes,bytes,bytes),address)": cap},
    )
    db_session.commit()

    rows = _principals(db_session)
    assert len(rows) == 1
    assert rows[0].address == "0x" + "a" * 40
    ef = _ef_row(db_session)
    assert ef.authority_public is True
    assert ef.status == "public"
    assert ef.conditions == [{"kind": "business", "description": "public capability enabled"}]


def test_and_of_mixed_or_and_side_condition_preserves_both_paths(db_session) -> None:
    finite = CapabilityExpr.finite_set(["0x" + "b" * 40])
    public = CapabilityExpr.conditional_universal(
        Condition(kind="business", description="public capability enabled"),
    )
    paused = CapabilityExpr.conditional_universal(Condition(kind="pause", description="not paused"))
    cap = CapabilityExpr.structural_and([CapabilityExpr.structural_or([finite, public]), paused])

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("verify((uint32,bytes32,uint64),address,bytes32)")],
        capability_by_function={"verify((uint32,bytes32,uint64),address,bytes32)": cap},
    )
    db_session.commit()

    rows = _principals(db_session)
    assert len(rows) == 1
    assert rows[0].details["conditions"] == [{"kind": "pause", "description": "not paused"}]
    ef = _ef_row(db_session)
    assert ef.authority_public is True
    assert ef.status == "public"
    assert ef.conditions == [
        {"kind": "pause", "description": "not paused"},
        {"kind": "business", "description": "public capability enabled"},
    ]


# ---------------------------------------------------------------------------
# Pure-function helpers
# ---------------------------------------------------------------------------


def test_principal_rows_for_capability_finite_set() -> None:
    cap_dict = capability_to_dict(CapabilityExpr.finite_set(["0x" + "a" * 40]))
    rows = _principal_rows_for_capability(cap_dict)
    assert len(rows) == 1
    assert rows[0]["principal_type"] == "controller"


def test_column_values_conditional_universal() -> None:
    cap_dict = capability_to_dict(
        CapabilityExpr.conditional_universal(Condition(kind="pause", description="paused")),
    )
    cols = _column_values_for_capability(cap_dict)
    assert cols["status"] == "public"
    assert cols["authority_public"] is True
    assert cols["conditions"] and cols["conditions"][0]["kind"] == "pause"


def test_column_values_resolved_empty() -> None:
    cap_dict = capability_to_dict(CapabilityExpr.finite_set([], quality="exact", confidence="enumerable"))
    cols = _column_values_for_capability(cap_dict)
    assert cols["status"] == "resolved_empty"
    assert cols["authority_public"] is False


def test_column_values_lower_bound_empty_is_not_resolved_empty() -> None:
    cap_dict = capability_to_dict(CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial"))
    cols = _column_values_for_capability(cap_dict)
    assert cols["status"] is None
    assert cols["authority_public"] is False


def test_column_values_public_or_composite() -> None:
    left = CapabilityExpr.conditional_universal(Condition(kind="business", description="initialized branch"))
    right = CapabilityExpr.conditional_universal(Condition(kind="business", description="constructor branch"))
    cap_dict = capability_to_dict(CapabilityExpr.structural_or([left, right]))

    cols = _column_values_for_capability(cap_dict)

    assert cols["status"] == "public"
    assert cols["authority_public"] is True
    assert cols["conditions"] == [
        {"kind": "business", "description": "initialized branch"},
        {"kind": "business", "description": "constructor branch"},
    ]


def test_column_values_unsupported() -> None:
    cap_dict = capability_to_dict(CapabilityExpr.unsupported("reason_x"))
    cols = _column_values_for_capability(cap_dict)
    assert cols["status"] == "unsupported"
    assert cols["authority_public"] is False


# ---------------------------------------------------------------------------
# resolve_principal_type — write-time typing of caller principals
# ---------------------------------------------------------------------------


def test_finite_set_rows_typed_via_resolver(db_session) -> None:
    """Regression: finite_set caller rows are typed via the injected
    classifier, so ``function_principals.resolved_type`` carries
    Safe/Timelock/EOA instead of NULL.

    Root cause this pins: the capability surface projects finite_set members
    with ``resolved_type=None`` and (pre-fix) the writer never classified
    them, leaving every per-function caller NULL. A governance Safe reachable
    only through per-function authority (e.g. a Safe that controls a Timelock
    which owns the protocol's contracts) then never surfaces in
    ``_fp_governance`` / primary-controller assignment. Typing at the writer
    fixes every downstream consumer at the source.
    """
    safe_addr = "0x" + "a" * 40
    eoa_addr = "0x" + "b" * 40
    cap = CapabilityExpr.finite_set([safe_addr, eoa_addr])

    classified = {
        safe_addr.lower(): ("safe", {"owners": ["0x" + "1" * 40], "threshold": 1}),
        eoa_addr.lower(): ("eoa", {}),
    }

    def _resolver(addr: str):
        return classified.get(addr.lower(), (None, None))

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("doThing()")],
        capability_by_function={"doThing()": cap},
        resolve_principal_type=_resolver,
    )
    db_session.commit()

    rows = {r.address: r for r in _principals(db_session)}
    assert rows[safe_addr.lower()].resolved_type == "safe"
    # Classifier details (owners/threshold) are merged alongside the surface trace.
    assert rows[safe_addr.lower()].details.get("owners") == ["0x" + "1" * 40]
    assert rows[eoa_addr.lower()].resolved_type == "eoa"


def test_finite_set_rows_untyped_without_resolver(db_session) -> None:
    """Baseline: with no resolver the rows stay untyped. Typing is purely
    additive and resolver-gated — no behavior change for callers (tests,
    fixtures) that don't pass one."""
    member = "0x" + "a" * 40
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("doThing()")],
        capability_by_function={"doThing()": CapabilityExpr.finite_set([member])},
    )
    db_session.commit()
    rows = _principals(db_session)
    assert len(rows) == 1
    assert rows[0].resolved_type is None


def test_resolver_not_called_for_signature_witness(db_session) -> None:
    """Signature-witness rows are signers, not callers, and are excluded from
    the governance/primary-controller consumers — so the writer must not spend
    a classify probe on them."""
    inner = CapabilityExpr.finite_set(["0x" + "a" * 40, "0x" + "b" * 40])
    cap = CapabilityExpr.signature_witness(inner)

    def _resolver(addr: str):
        raise AssertionError(f"resolver must not be called for a signer ({addr})")

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("approveHash(bytes32)")],
        capability_by_function={"approveHash(bytes32)": cap},
        resolve_principal_type=_resolver,
    )
    db_session.commit()
    rows = _principals(db_session)
    assert rows, "signature_witness(finite) should still emit signer rows"
    for r in rows:
        assert r.principal_type == "signature_witness"
        assert r.resolved_type is None


def test_resolver_does_not_override_threshold_group_safe(db_session) -> None:
    """threshold_group already resolves to 'safe'; the resolver is only a
    fallback for untyped rows and must not override an already-typed row."""
    signers = [f"0x{(0x10 + i):040x}" for i in range(3)]
    cap = CapabilityExpr.threshold_group(2, signers)

    def _resolver(addr: str):
        return ("eoa", {})  # wrong on purpose; must not be consulted

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("exec()")],
        capability_by_function={"exec()": cap},
        safe_address_lookup={"default": "0x" + "5" * 40},
        resolve_principal_type=_resolver,
    )
    db_session.commit()
    rows = _principals(db_session)
    assert len(rows) == 1
    assert rows[0].resolved_type == "safe"


# ---------------------------------------------------------------------------
# The row's abi_signature must be the one its own selector was computed from
# ---------------------------------------------------------------------------


def test_row_abi_signature_is_the_canonical_one(db_session) -> None:
    """``build_effective_permissions`` computes the canonical signature and the
    selector together and emits both; writing the Slither full_name instead left
    a row whose ``abi_signature`` does not hash to its own ``selector``.

    That column is what the API publishes as the function's signature, and for a
    struct param the full_name has no tuple layout at all — you cannot encode a
    call or recompute a selector from ``f(A.PermitInput)``."""
    from eth_utils.crypto import keccak

    canonical = "requestWithdrawWithPermit(uint256,address,(uint256,uint256,uint8,bytes32,bytes32))"
    selector = "0x" + keccak(text=canonical).hex()[:8]

    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[
            _fn_record(
                "requestWithdrawWithPermit(uint256,address,IWeETHWithdrawAdapter.PermitInput)",
                abi_signature=canonical,
                selector=selector,
            )
        ],
        capability_by_function=None,
    )
    db_session.commit()

    ef = _ef_row(db_session)
    assert ef.abi_signature == canonical
    assert "0x" + keccak(text=ef.abi_signature).hex()[:8] == ef.selector
    # The full_name still names the function for display.
    assert ef.function_name == "requestWithdrawWithPermit"


def test_row_abi_signature_falls_back_to_the_full_name(db_session) -> None:
    """Older test metadata and degraded records carry no ``abi_signature``; the
    row must still name the function rather than going empty."""
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[{"function": "doThing()", "selector": "0xdeadbeef"}],
        capability_by_function=None,
    )
    db_session.commit()
    assert _ef_row(db_session).abi_signature == "doThing()"


# ---------------------------------------------------------------------------
# authority_openness — the three-state split of the authority_public bool
# ``authority_public=False`` reported a WITNESSED caller
# restriction and "the authority could not be determined" with one value.
# ---------------------------------------------------------------------------


def _openness(session) -> str | None:
    return _ef_row(session).authority_openness


def test_openness_open_on_conditional_universal(db_session) -> None:
    cap = CapabilityExpr.conditional_universal(Condition(kind="time", description="after cooldown"))
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function={"f()": cap},
    )
    row = _ef_row(db_session)
    assert row.authority_public is True
    assert row.authority_openness == "open"


def test_openness_restricted_on_resolved_finite_set(db_session) -> None:
    cap = CapabilityExpr.finite_set(["0x" + "a" * 40])
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function={"f()": cap},
    )
    row = _ef_row(db_session)
    assert row.authority_public is False
    assert row.authority_openness == "restricted"


def test_openness_restricted_on_witnessed_empty_set(db_session) -> None:
    # ``resolved_empty`` is a WITNESSED restriction (a complete enumeration that
    # admits nobody) — the same bucket as a populated set, not not-determined.
    cap = CapabilityExpr.finite_set([], quality="exact")
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function={"f()": cap},
    )
    row = _ef_row(db_session)
    assert row.status == "resolved_empty"
    assert row.authority_openness == "restricted"


def test_openness_not_determined_on_unsupported(db_session) -> None:
    cap = CapabilityExpr.unsupported("guard_extraction_uncertain")
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function={"f()": cap},
    )
    row = _ef_row(db_session)
    assert row.authority_public is False
    assert row.status == "unsupported"
    assert row.authority_openness == "not_determined"


def test_openness_not_determined_on_external_check_only(db_session) -> None:
    # The exact collapse the bool caused: a probe interface with no enumeration
    # got the same ``False`` a fully-resolved gated function gets.
    from services.resolution.capabilities import ExternalCheck

    cap = CapabilityExpr.external_check_only(
        ExternalCheck(target_address="0x" + "b" * 40, target_call_selector="0xdeadbeef")
    )
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function={"f()": cap},
    )
    row = _ef_row(db_session)
    assert row.authority_public is False
    assert row.authority_openness == "not_determined"


def test_openness_null_when_no_producer_said(db_session) -> None:
    # A record from a caller that does not carry the key leaves the column NULL:
    # "this producer could not say" is a FOURTH state and must not be folded
    # into the resolver's own 'not_determined'.
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function=None,
    )
    assert _ef_row(db_session).authority_openness is None


def test_authority_roles_persists_witnessed_role_grant(db_session) -> None:
    """The column stops being the literal [] — a single-role
    Solmate capability persists a real (role, principals) grant."""
    cap = {
        "kind": "finite_set",
        "members": ["0x" + "a" * 40],
        "membership_quality": "exact",
        "confidence": "enumerable",
        "trace": [{"step": "solmate_roles_authority", "roles": [8], "authority": "0x" + "1" * 40}],
    }
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function={"f()": cap},
    )
    row = _ef_row(db_session)
    assert row.authority_roles is not None
    assert [g["role"] for g in row.authority_roles] == [8]
    assert [p["address"] for g in row.authority_roles for p in g["principals"]] == ["0x" + "a" * 40]


def test_authority_roles_null_when_role_identity_dissolved(db_session) -> None:
    """Role-gated with the role NOT determined must persist NULL, not [] —
    ``[]`` is the proven-absent answer and would erase the middle state."""
    cap = {
        "kind": "finite_set",
        "members": ["0x" + "a" * 40],
        "membership_quality": "exact",
        "trace": [{"step": "enumerable_role_store", "authority": "0x" + "1" * 40}],
    }
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function={"f()": cap},
    )
    assert _ef_row(db_session).authority_roles is None


def test_authority_roles_empty_when_proven_not_role_gated(db_session) -> None:
    cap = CapabilityExpr.finite_set(["0x" + "a" * 40])
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function={"f()": cap},
    )
    assert _ef_row(db_session).authority_roles == []


def test_authority_roles_null_when_no_capability_resolved(db_session) -> None:
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function=None,
    )
    assert _ef_row(db_session).authority_roles is None


def test_resolver_crash_warns_once_per_contract_and_records_degraded(db_session, caplog) -> None:
    """A principal resolver that crashes leaves every row's ``resolved_type``
    NULL — downstream that reads as "not a Safe/Timelock", so the writer says
    so once per contract."""
    import logging

    from utils.logging import degraded_errors_var

    cap = CapabilityExpr.finite_set(["0x" + "a" * 40, "0x" + "b" * 40])

    def _boom(_address: str):
        raise RuntimeError("classify service down")

    degraded: list = []
    token = degraded_errors_var.set(degraded)
    try:
        with caplog.at_level(logging.WARNING, logger="services.policy.effective_permissions_writer"):
            write_effective_function_rows(
                db_session,
                contract_id=1,
                function_records=[_fn_record("a()"), _fn_record("b()")],
                capability_by_function={"a()": cap, "b()": cap},
                resolve_principal_type=_boom,
            )
    finally:
        degraded_errors_var.reset(token)

    # Two functions × two principals = four classify attempts, one line.
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].contract_id == 1
    assert warnings[0].failed_addresses == 2
    assert warnings[0].exc_type == "RuntimeError"

    entries = [e for e in degraded if e.phase == "principal_classification"]
    assert len(entries) == 1
    # The resolver's own text is what tells a 402 from a timeout downstream.
    assert "classify service down" in entries[0].message

    assert all(row.resolved_type is None for row in _principals(db_session))
