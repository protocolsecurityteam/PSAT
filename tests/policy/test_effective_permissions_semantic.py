"""Per-kind row representation for ``build_effective_permissions`` + ``write_effective_function_rows``, on in-memory
SQLite with Postgres-only types swapped.

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
"""

from __future__ import annotations

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

from services.policy.effective_permissions_writer import (
    write_effective_function_rows,
)
from services.resolution.capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
)

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


def test_finite_set_rows_typed_via_resolver(db_session) -> None:
    """Untyped, a Safe reachable only via per-function authority never surfaces in ``_fp_governance``."""
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
    assert rows[safe_addr.lower()].details.get("owners") == ["0x" + "1" * 40]
    assert rows[eoa_addr.lower()].resolved_type == "eoa"


def test_resolver_does_not_override_threshold_group_safe(db_session) -> None:
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


def test_row_abi_signature_is_the_canonical_one(db_session) -> None:
    """The Slither full_name doesn't hash to the selector and can't encode struct params."""
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
    assert ef.function_name == "requestWithdrawWithPermit"


# ``authority_public=False`` used to report a witnessed restriction and "not determined" with one value.


@pytest.mark.parametrize(
    ("cap", "expected"),
    [
        pytest.param(
            CapabilityExpr.conditional_universal(Condition(kind="time", description="after cooldown")),
            {"authority_public": True, "authority_openness": "open"},
            id="open_on_conditional_universal",
        ),
        pytest.param(
            CapabilityExpr.finite_set(["0x" + "a" * 40]),
            {"authority_public": False, "authority_openness": "restricted", "authority_roles": []},
            id="restricted_on_resolved_finite_set",
        ),
        # A complete enumeration admitting nobody is a witnessed restriction.
        pytest.param(
            CapabilityExpr.finite_set([], quality="exact"),
            {"status": "resolved_empty", "authority_openness": "restricted"},
            id="restricted_on_witnessed_empty_set",
        ),
        # Fail-open polarity: an unsupported gate must not read as restricted.
        pytest.param(
            CapabilityExpr.unsupported("guard_extraction_uncertain"),
            {"authority_public": False, "status": "unsupported", "authority_openness": "not_determined"},
            id="not_determined_on_unsupported",
        ),
        # The exact collapse the bool caused.
        pytest.param(
            CapabilityExpr.external_check_only(
                ExternalCheck(target_address="0x" + "b" * 40, target_call_selector="0xdeadbeef")
            ),
            {"authority_public": False, "authority_openness": "not_determined"},
            id="not_determined_on_external_check_only",
        ),
        # A producer that can't say leaves NULL, a fourth state distinct from the resolver's 'not_determined'.
        pytest.param(
            None,
            {"authority_openness": None, "authority_roles": None},
            id="null_when_no_producer_said",
        ),
    ],
)
def test_authority_openness_and_roles(db_session, cap, expected) -> None:
    write_effective_function_rows(
        db_session,
        contract_id=1,
        function_records=[_fn_record("f()")],
        capability_by_function=None if cap is None else {"f()": cap},
    )
    row = _ef_row(db_session)
    for attr, value in expected.items():
        assert getattr(row, attr) == value


def test_authority_roles_null_when_role_identity_dissolved(db_session) -> None:
    """``[]`` means proven-absent and would erase the middle state."""
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


def test_resolver_crash_warns_once_per_contract_and_records_degraded(db_session, caplog) -> None:
    """A NULL ``resolved_type`` reads downstream as "not a Safe/Timelock"."""
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

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].contract_id == 1
    assert warnings[0].failed_addresses == 2
    assert warnings[0].exc_type == "RuntimeError"

    entries = [e for e in degraded if e.phase == "principal_classification"]
    assert len(entries) == 1
    assert "classify service down" in entries[0].message

    assert all(row.resolved_type is None for row in _principals(db_session))
