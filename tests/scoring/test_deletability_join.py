"""A composed magnitude transfers only where the principal holds a setter over the authority the destination's
gate consults. Hop count, selector name and contract shape partition the reference corpus identically, so the
only defence is reading ``function_principals`` rows. ``principal_type`` is ``'controller'`` on 28,689 of 28,689
rows. The three-arm rule consuming this verdict is tested elsewhere.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any

import pytest

from db.models import (
    Contract,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    Protocol,
)
from services.scoring import planes as P

VAULT = "0x" + "11" * 20
AUTHORITY = "0x" + "22" * 20
SAFE = "0x" + "33" * 20
TIMELOCK = "0x" + "44" * 20
EOA = "0x" + "55" * 20
UNRELATED = "0x" + "66" * 20
OTHER_AUTHORITY = "0x" + "77" * 20

EXIT = "0x18457e61"

VAULT_KEY = f"ethereum::{VAULT}"


def _setter(
    fp_id: int,
    *,
    contract: str,
    function_name: str,
    principal: str,
    chain: str = "ethereum",
    selector: str | None = None,
    membership_quality: str | None = "exact",
) -> P.SetterPrincipal:
    return P.SetterPrincipal(
        function_principal_id=fp_id,
        chain=chain,
        contract_address=contract,
        function_name=function_name,
        selector=selector or "0x7a9e5e4b",
        principal_address=principal,
        membership_quality=membership_quality,
    )


def _plane(
    rows: tuple[P.SetterPrincipal, ...] = (),
    *,
    gating: dict[tuple[str, str, str], tuple[str, ...]] | None = None,
    crosscheck: dict[tuple[str, str], tuple[str, ...]] | None = None,
    tainted: tuple[tuple[str, str, str], ...] = (),
) -> P.DeletabilityPlane:
    setters: dict[tuple[str, str], list[P.SetterPrincipal]] = defaultdict(list)
    for row in rows:
        setters[(row.chain, row.contract_address)].append(row)
    return P.DeletabilityPlane(
        setters={key: tuple(sorted(value)) for key, value in setters.items()},
        gating=dict(gating or {}),
        crosscheck=dict(crosscheck or {}),
        tainted=frozenset(tainted),
    )


def _gated(authority: str = AUTHORITY, selector: str = EXIT) -> dict[str, Any]:
    return {
        "gating": {("ethereum", VAULT, selector): (authority,)},
        "crosscheck": {("ethereum", VAULT): (authority,)},
    }


def _roles_setter(**over: Any) -> P.SetterPrincipal:
    return _setter(3, contract=AUTHORITY, function_name="setUserRole", principal=SAFE, **over)


@pytest.mark.parametrize(
    "plane,principals,destination,state,reason",
    [
        pytest.param(
            _plane((_roles_setter(),), **_gated()),
            [EOA],
            VAULT_KEY,
            P.DELETABILITY_PROVEN_NOT_DELETABLE,
            P.DELETABILITY_NO_SETTER_ROW,
            id="no_qualifying_row",
        ),
        # (f) Unscoped, the corpus's EOA holds all four setters on unrelated solver contracts.
        pytest.param(
            _plane(
                tuple(
                    _setter(index, contract=UNRELATED, function_name=name, principal=EOA)
                    for index, name in enumerate(
                        ("setAuthority", "transferOwnership", "setUserRole", "setRoleCapability"), start=1
                    )
                ),
                **_gated(),
            ),
            [EOA],
            VAULT_KEY,
            P.DELETABILITY_PROVEN_NOT_DELETABLE,
            P.DELETABILITY_NO_SETTER_ROW,
            id="setters_on_an_unrelated_contract",
        ),
        pytest.param(
            _plane(
                (_setter(8, contract=VAULT, function_name="setAuthority", principal=SAFE, membership_quality=None),),
                **_gated(),
            ),
            [SAFE],
            VAULT_KEY,
            P.DELETABILITY_NOT_DETERMINED,
            P.DELETABILITY_MEMBERSHIP_NOT_EXACT,
            id="membership_absent",
        ),
        pytest.param(
            _plane(),
            [],
            VAULT_KEY,
            P.DELETABILITY_NOT_DETERMINED,
            P.DELETABILITY_NO_PRINCIPAL_ADDRESS,
            id="no_principal_address",
        ),
        pytest.param(
            _plane(),
            [SAFE],
            VAULT,
            P.DELETABILITY_NOT_DETERMINED,
            P.DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED,
            id="destination_not_chain_scoped",
        ),
    ],
)
def test_a_join_that_does_not_qualify_a_row_publishes_its_own_typed_token(
    plane, principals, destination, state, reason
):
    _declines(plane, principals, destination, state, reason)


def _declines(plane, principals, destination, state, reason) -> None:
    verdict = P.authority_deletability(plane, principals, destination, EXIT)

    assert verdict.state == state
    assert verdict.reason == reason
    assert not verdict.is_deletable
    assert verdict.basis is None
    assert verdict.basis_block() is None
    assert verdict.arm is None


# Named by node id in ``constants.uncalibrated_arm_disclosures``; kept standalone so the pointer resolves.


def test_two_selector_scoped_authorities_are_no_answer():
    _declines(
        _plane(
            (_setter(3, contract=OTHER_AUTHORITY, function_name="setUserRole", principal=SAFE),),
            gating={("ethereum", VAULT, EXIT): (AUTHORITY, OTHER_AUTHORITY)},
        ),
        [SAFE],
        VAULT_KEY,
        P.DELETABILITY_NOT_DETERMINED,
        P.DELETABILITY_AUTHORITY_NOT_UNIQUE,
    )


def test_a_lower_bound_membership_row_is_not_determined_never_deletable():
    _declines(
        _plane((_roles_setter(membership_quality="lower_bound"),), **_gated()),
        [SAFE],
        VAULT_KEY,
        P.DELETABILITY_NOT_DETERMINED,
        P.DELETABILITY_MEMBERSHIP_NOT_EXACT,
    )


def test_authority_sources_that_disagree_resolve_to_not_determined():
    plane = _plane(
        (_roles_setter(),),
        gating={("ethereum", VAULT, EXIT): (AUTHORITY,)},
        crosscheck={("ethereum", VAULT): (OTHER_AUTHORITY,)},
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_AUTHORITY_SOURCES_DISAGREE
    assert verdict.crosscheck == P.CROSSCHECK_DISAGREES
    assert verdict.gating_authorities == (AUTHORITY,)
    assert verdict.crosscheck_authorities == (OTHER_AUTHORITY,)


# --- the published verdict ----------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"state": P.DELETABILITY_DELETABLE},
        {"state": P.DELETABILITY_DELETABLE, "arm": P.DELETABILITY_ARM_HOST},
        {"state": P.DELETABILITY_PROVEN_NOT_DELETABLE},
        {"state": P.DELETABILITY_NOT_DETERMINED, "arm": P.DELETABILITY_ARM_HOST, "reason": "x"},
        {"state": "probably"},
    ],
)
def test_the_verdict_cannot_be_constructed_unpaired(kwargs):
    with pytest.raises(ValueError):
        P.DeletabilityVerdict(
            destination_key=VAULT_KEY,
            selector=EXIT,
            principal_addresses=(SAFE,),
            **kwargs,
        )


@pytest.fixture()
def loaded(db_session):
    protocol = Protocol(name=f"deletability-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()
    job = Job(id=uuid.uuid4(), protocol_id=protocol.id)
    db_session.add(job)
    db_session.commit()

    made: list[Contract] = []

    def contract(address: str, *, chain: str = "ethereum", protocol_id: int | None = None) -> Contract:
        row = Contract(address=address, chain=chain, protocol_id=protocol_id, job_id=job.id)
        db_session.add(row)
        db_session.commit()
        made.append(row)
        return row

    def function(row: Contract, *, name: str, selector: str, capability_expr: Any = None) -> EffectiveFunction:
        fn = EffectiveFunction(
            contract_id=row.id,
            deployment_address=row.address,
            function_name=name,
            selector=selector,
            abi_signature=f"{name}()",
            authority_public=False,
            authority_openness="restricted",
            capability_expr=capability_expr,
        )
        db_session.add(fn)
        db_session.commit()
        return fn

    def principal(fn: EffectiveFunction, *, address: str, details: dict[str, Any]) -> FunctionPrincipal:
        row = FunctionPrincipal(
            function_id=fn.id,
            address=address,
            resolved_type="safe",
            principal_type="controller",
            details=details,
        )
        db_session.add(row)
        db_session.commit()
        return row

    def controller_value(row: Contract, *, value: str) -> None:
        db_session.add(
            ControllerValue(
                contract_id=row.id,
                deployment_address=row.address,
                controller_id=P.AUTHORITY_CONTROLLER_ID,
                value=value,
                resolved_type="contract",
            )
        )
        db_session.commit()

    try:
        yield protocol, contract, function, principal, controller_value
    finally:
        db_session.rollback()
        for row in made:
            db_session.query(Contract).filter_by(id=row.id).delete()
        db_session.query(Job).filter_by(id=job.id).delete()
        db_session.query(Protocol).filter_by(id=protocol.id).delete()
        db_session.commit()


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


def test_the_loader_reads_membership_quality_out_of_details_not_a_column(db_session, loaded):
    protocol, contract, function, principal, controller_value = loaded
    vault, authority = _addr(), _addr()
    host = contract(vault, protocol_id=protocol.id)
    registry = contract(authority, protocol_id=protocol.id)
    exit_fn = function(host, name="exit", selector=EXIT)
    principal(
        exit_fn,
        address=SAFE,
        details={"trace": [{"step": P.SOLMATE_ROLES_AUTHORITY_STEP, "authority": authority, "roles": [4]}]},
    )
    principal(
        function(registry, name="setUserRole", selector="0x67aff484"),
        address=SAFE,
        details={"membership_quality": "exact"},
    )
    controller_value(host, value=authority)

    plane = P.load_deletability_plane(db_session)

    rows = plane.setter_rows("ethereum", authority, P.DELETABILITY_AUTHORITY_SETTERS, [SAFE])
    assert [row.membership_quality for row in rows] == ["exact"]
    assert plane.gating[("ethereum", vault, EXIT)] == (authority,)
    assert plane.crosscheck[("ethereum", vault)] == (authority,)

    verdict = P.authority_deletability(plane, [SAFE], f"ethereum::{vault}", EXIT)
    assert verdict.state == P.DELETABILITY_DELETABLE
    assert verdict.arm == P.DELETABILITY_ARM_GATING_AUTHORITY
    assert verdict.crosscheck == P.CROSSCHECK_AGREES


@pytest.mark.parametrize(
    "step,taint,reason",
    [
        (P.SOLMATE_ROLES_AUTHORITY_STEP, True, P.DELETABILITY_AUTHORITY_TAINTED),
        ("owner_state_variable", False, P.DELETABILITY_AUTHORITY_UNRESOLVED),
    ],
    ids=["tainted_gate", "non_solmate_step"],
)
def test_the_loader_reads_the_gate_the_trace_and_the_taint_apart(db_session, loaded, step, taint, reason):
    protocol, contract, function, principal, _controller_value = loaded
    vault, authority = _addr(), _addr()
    host = contract(vault, protocol_id=protocol.id)
    registry = contract(authority, protocol_id=protocol.id)
    exit_fn = function(
        host,
        name="exit",
        selector=EXIT,
        capability_expr=({"check": {"extra": {"basis": [P.CALLER_TAINTED_AUTHORITY_UNRESOLVED]}}} if taint else None),
    )
    principal(exit_fn, address=SAFE, details={"trace": [{"step": step, "authority": authority}]})
    principal(
        function(registry, name="setUserRole", selector="0x67aff484"),
        address=SAFE,
        details={"membership_quality": "exact"},
    )

    plane = P.load_deletability_plane(db_session)

    assert (("ethereum", vault, EXIT) in plane.tainted) is taint
    assert (("ethereum", vault, EXIT) in plane.gating) is (step == P.SOLMATE_ROLES_AUTHORITY_STEP)
    verdict = P.authority_deletability(plane, [SAFE], f"ethereum::{vault}", EXIT)
    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == reason
