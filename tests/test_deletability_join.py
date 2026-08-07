"""The authority-deletability join: can this principal author the call itself?

A composed magnitude is a dollar figure proven by an execution the principal
never made — a direct impersonated call to the destination, published as a route
through a wrapper that authors the call's arguments. The figure transfers to the
principal only where the principal can author that calldata itself, and that is
what this join decides: does it hold a setter that repoints or rewrites the
authority the destination's gate consults?

Every test here pins one of the ways that decision could quietly stop being a
witness:

  * a hop count, a selector name or a contract shape standing in for the join —
    on the reference corpus all three partition the population identically, so
    the only defence is that the decision reads ``function_principals`` rows;
  * ``principal_unit`` read where the ROW's ``principal_addresses`` is meant,
    which under-resolves every row reached through an ``access_path``;
  * an unscoped join, where a setter held on some unrelated contract proves
    control of this destination;
  * an unresolvable, ambiguous or contradicted gating authority failing to
    "not deletable" instead of to ``not_determined`` — an earned negative minted
    out of an absence;
  * ``membership_quality: lower_bound`` read as membership;
  * ``principal_type`` used as a filter, which is ``'controller'`` on 28,689 of
    28,689 rows and so fails open while looking scoped.

The three-arm composition rule that CONSUMES this verdict is not exercised here;
these are join-level tests.
"""

from __future__ import annotations

import inspect
import sys
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import (  # noqa: E402
    Contract,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    Protocol,
)
from services.scoring import planes as P  # noqa: E402

VAULT = "0x" + "11" * 20
AUTHORITY = "0x" + "22" * 20
SAFE = "0x" + "33" * 20
TIMELOCK = "0x" + "44" * 20
EOA = "0x" + "55" * 20
UNRELATED = "0x" + "66" * 20
OTHER_AUTHORITY = "0x" + "77" * 20

EXIT = "0x18457e61"
MANAGE = "0xf6e715d0"

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
    """A destination whose gating authority both witnesses agree on."""
    return {
        "gating": {("ethereum", VAULT, selector): (authority,)},
        "crosscheck": {("ethereum", VAULT): (authority,)},
    }


# --- (a) the two arms, each independently sufficient -------------------------


def test_authority_arm_qualifying_row_is_deletable_and_names_its_basis():
    """(a) A setter on the RESOLVED gating authority proves deletability."""
    plane = _plane(
        (
            _setter(41, contract=AUTHORITY, function_name="setUserRole", principal=SAFE, selector="0x67aff484"),
            _setter(42, contract=AUTHORITY, function_name="setRoleCapability", principal=SAFE, selector="0x7d40583d"),
        ),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_DELETABLE
    assert verdict.is_deletable
    assert verdict.reason is None
    assert verdict.arm == P.DELETABILITY_ARM_GATING_AUTHORITY
    # The two fields §14's positive arm requires: the setter selector and the
    # ``function_principals`` row id, so the republished figure is re-checkable
    # by hand rather than asserted.
    basis = verdict.basis_block()
    assert basis is not None
    assert basis["function_principal_id"] == 41
    assert basis["setter_selector"] == "0x67aff484"
    assert basis["setter_function_name"] == "setUserRole"
    assert basis["setter_contract"] == f"ethereum::{AUTHORITY}"
    assert basis["principal_address"] == SAFE
    assert basis["membership_quality"] == "exact"
    assert verdict.gating_authorities == (AUTHORITY,)
    assert verdict.crosscheck == P.CROSSCHECK_AGREES


def test_host_arm_qualifying_row_is_deletable_without_any_authority_witness():
    """(a) The HOST arm asks nothing about the authority and is not a fallback."""
    plane = _plane(
        (_setter(7, contract=VAULT, function_name="setAuthority", principal=SAFE),),
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_DELETABLE
    assert verdict.arm == P.DELETABILITY_ARM_HOST
    assert (verdict.basis_block() or {})["function_principal_id"] == 7
    # No authority was resolved and none was needed; saying the cross-check
    # "agrees" here would claim a comparison that never happened.
    assert verdict.gating_authorities == ()
    assert verdict.crosscheck == P.CROSSCHECK_NOT_COMPARED


def test_the_basis_is_the_lowest_id_qualifying_row():
    """Replay (inv. 11): two qualifying rows must not publish either one."""
    rows = (
        _setter(90, contract=VAULT, function_name="transferOwnership", principal=SAFE),
        _setter(12, contract=VAULT, function_name="setAuthority", principal=SAFE),
    )
    forward = P.authority_deletability(_plane(rows), [SAFE], VAULT_KEY, EXIT)
    reversed_ = P.authority_deletability(_plane(tuple(reversed(rows))), [SAFE], VAULT_KEY, EXIT)

    assert (forward.basis_block() or {})["function_principal_id"] == 12
    assert forward.basis_block() == reversed_.basis_block()


# --- (b) the earned negative -------------------------------------------------


def test_no_qualifying_row_is_a_typed_refusal_not_a_silent_admission():
    """(b) The join ran, both arms were asked, neither returned a row."""
    plane = _plane(
        (_setter(3, contract=AUTHORITY, function_name="setUserRole", principal=SAFE),),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [EOA], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_PROVEN_NOT_DELETABLE
    assert verdict.reason == P.DELETABILITY_NO_SETTER_ROW
    assert verdict.arm is None
    assert verdict.basis is None
    assert verdict.basis_block() is None
    # The earned negative is only earned because a witness answered the "which
    # authority" question; the verdict publishes which one it asked about.
    assert verdict.gating_authorities == (AUTHORITY,)


# --- (c) an unresolvable gating authority ------------------------------------


def test_unresolvable_gating_authority_is_not_determined_never_deletable():
    """(c) No witness names the authority, so neither answer is earned."""
    plane = _plane((_setter(3, contract=AUTHORITY, function_name="setUserRole", principal=SAFE),))

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_AUTHORITY_UNRESOLVED
    assert not verdict.is_deletable
    # ...and NOT the earned negative: the principal does hold setters on a
    # RolesAuthority, and nothing proved that authority is not the one.
    assert verdict.state != P.DELETABILITY_PROVEN_NOT_DELETABLE


def test_the_three_states_are_three_distinct_tokens():
    """The refusal a consumer counts must decompose (inv. 1)."""
    setter = _setter(3, contract=AUTHORITY, function_name="setUserRole", principal=SAFE)
    deletable = P.authority_deletability(_plane((setter,), **_gated()), [SAFE], VAULT_KEY, EXIT)
    negative = P.authority_deletability(_plane((setter,), **_gated()), [EOA], VAULT_KEY, EXIT)
    unknown = P.authority_deletability(_plane((setter,)), [SAFE], VAULT_KEY, EXIT)

    states = {deletable.state, negative.state, unknown.state}
    assert states == set(P.DELETABILITY_STATES)
    assert negative.reason != unknown.reason


def test_a_tainted_destination_gate_is_not_determined_even_with_a_named_authority():
    """(c) The gate's own resolution records that it could not resolve.

    A trace that names an authority anyway names a candidate, not the gate's
    answer, and control over a candidate proves nothing about the real gate.
    """
    plane = _plane(
        (_setter(3, contract=AUTHORITY, function_name="setUserRole", principal=SAFE),),
        tainted=(("ethereum", VAULT, EXIT),),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_AUTHORITY_TAINTED


def test_a_tainted_gate_does_not_defeat_the_host_arm():
    """The host arm never consults the authority, so the taint is irrelevant to it."""
    plane = _plane(
        (_setter(3, contract=VAULT, function_name="setAuthority", principal=SAFE),),
        tainted=(("ethereum", VAULT, EXIT),),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_DELETABLE
    assert verdict.arm == P.DELETABILITY_ARM_HOST


# --- (d) the two authority sources -------------------------------------------


def test_authority_sources_that_disagree_resolve_to_not_determined():
    """(d) Selector-scoped and contract-scoped witnesses name different authorities."""
    plane = _plane(
        (_setter(3, contract=AUTHORITY, function_name="setUserRole", principal=SAFE),),
        gating={("ethereum", VAULT, EXIT): (AUTHORITY,)},
        crosscheck={("ethereum", VAULT): (OTHER_AUTHORITY,)},
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_AUTHORITY_SOURCES_DISAGREE
    assert verdict.crosscheck == P.CROSSCHECK_DISAGREES
    # Both readings are published: a reader must be able to see WHAT disagreed.
    assert verdict.gating_authorities == (AUTHORITY,)
    assert verdict.crosscheck_authorities == (OTHER_AUTHORITY,)


def test_an_absent_crosscheck_is_not_a_disagreement():
    """A witness that did not answer is not a witness that answered differently."""
    plane = _plane(
        (_setter(3, contract=AUTHORITY, function_name="setUserRole", principal=SAFE),),
        gating={("ethereum", VAULT, EXIT): (AUTHORITY,)},
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_DELETABLE
    assert verdict.crosscheck == P.CROSSCHECK_NOT_CORROBORATED


def test_two_selector_scoped_authorities_are_no_answer():
    """Taking the union would read control over a candidate as control of the gate."""
    plane = _plane(
        (_setter(3, contract=OTHER_AUTHORITY, function_name="setUserRole", principal=SAFE),),
        gating={("ethereum", VAULT, EXIT): (AUTHORITY, OTHER_AUTHORITY)},
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_AUTHORITY_NOT_UNIQUE


def test_the_authority_is_read_per_selector_not_per_contract():
    """One host, two selectors, two authorities — the contract-scoped read cannot separate them."""
    plane = _plane(
        (_setter(3, contract=OTHER_AUTHORITY, function_name="setUserRole", principal=SAFE),),
        gating={
            ("ethereum", VAULT, EXIT): (AUTHORITY,),
            ("ethereum", VAULT, MANAGE): (OTHER_AUTHORITY,),
        },
    )

    assert P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT).state == P.DELETABILITY_PROVEN_NOT_DELETABLE
    assert P.authority_deletability(plane, [SAFE], VAULT_KEY, MANAGE).state == P.DELETABILITY_DELETABLE


# --- (e) principal_addresses, never principal_unit ---------------------------


def test_the_join_keys_on_principal_addresses_not_on_the_principal_unit():
    """(e) The S3/S7 shape: the unit is the Safe, the setters are the timelock's.

    Measured on the reference corpus, the row whose ``principal_unit`` is the
    Safe reaches its destination through ``access_path: via_timelock:…`` and its
    ``principal_addresses`` names the timelock. The Safe holds ZERO setter rows
    at that destination and at its gating authority; the timelock holds all
    four. Keying on the unit withholds $11,358,880.43 and publishes no
    diagnostic saying why.
    """
    plane = _plane(
        (_setter(55, contract=VAULT, function_name="setAuthority", principal=TIMELOCK),),
        **_gated(),
    )

    by_addresses = P.authority_deletability(plane, [TIMELOCK], VAULT_KEY, EXIT)
    by_unit = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert by_addresses.state == P.DELETABILITY_DELETABLE
    assert (by_addresses.basis_block() or {})["principal_address"] == TIMELOCK
    assert by_unit.state == P.DELETABILITY_PROVEN_NOT_DELETABLE


def test_any_one_of_several_addresses_qualifying_is_enough_and_the_row_is_named():
    plane = _plane(
        (_setter(55, contract=VAULT, function_name="setAuthority", principal=TIMELOCK),),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [EOA, TIMELOCK], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_DELETABLE
    assert (verdict.basis_block() or {})["principal_address"] == TIMELOCK
    assert verdict.principal_addresses == tuple(sorted((EOA, TIMELOCK)))


def test_a_row_naming_no_principal_address_is_not_determined():
    """Nothing to ask the join about is not the same as asking and being told no."""
    verdict = P.authority_deletability(_plane(), [], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_NO_PRINCIPAL_ADDRESS


# --- (f) destination scoping and chain scoping -------------------------------


def test_setters_on_an_unrelated_contract_do_not_delete_this_destination():
    """(f) Unscoped, the reference corpus's EOA holds all four setters on solver
    contracts unrelated to these vaults, and every withheld entry republishes.
    """
    plane = _plane(
        (
            _setter(1, contract=UNRELATED, function_name="setAuthority", principal=EOA),
            _setter(2, contract=UNRELATED, function_name="transferOwnership", principal=EOA),
            _setter(3, contract=UNRELATED, function_name="setUserRole", principal=EOA),
            _setter(4, contract=UNRELATED, function_name="setRoleCapability", principal=EOA),
        ),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [EOA], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_PROVEN_NOT_DELETABLE
    assert verdict.reason == P.DELETABILITY_NO_SETTER_ROW


def test_a_setter_on_the_other_chains_copy_of_the_address_does_not_qualify():
    """The same address on two chains is two contracts (#158 twin aliasing)."""
    plane = _plane(
        (_setter(1, contract=VAULT, function_name="setAuthority", principal=SAFE, chain="base"),),
        gating={("ethereum", VAULT, EXIT): (AUTHORITY,), ("base", VAULT, EXIT): (AUTHORITY,)},
    )

    assert P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT).state == P.DELETABILITY_PROVEN_NOT_DELETABLE
    assert P.authority_deletability(plane, [SAFE], f"base::{VAULT}", EXIT).state == P.DELETABILITY_DELETABLE


def test_a_destination_key_with_no_chain_scope_is_not_determined():
    verdict = P.authority_deletability(_plane(), [SAFE], VAULT, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_DESTINATION_NOT_CHAIN_SCOPED


# --- membership quality ------------------------------------------------------


def test_a_lower_bound_membership_row_is_not_determined_never_deletable():
    """``membership_quality`` is a floor on the SET, not a proof about this address."""
    plane = _plane(
        (
            _setter(
                8,
                contract=AUTHORITY,
                function_name="setUserRole",
                principal=SAFE,
                membership_quality="lower_bound",
            ),
        ),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_MEMBERSHIP_NOT_EXACT


def test_an_absent_membership_quality_is_read_as_unproven_not_as_exact():
    plane = _plane(
        (_setter(8, contract=VAULT, function_name="setAuthority", principal=SAFE, membership_quality=None),),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_MEMBERSHIP_NOT_EXACT


def test_an_exact_row_still_wins_beside_a_lower_bound_one():
    plane = _plane(
        (
            _setter(
                8,
                contract=AUTHORITY,
                function_name="setUserRole",
                principal=SAFE,
                membership_quality="lower_bound",
            ),
            _setter(9, contract=AUTHORITY, function_name="setRoleCapability", principal=SAFE),
        ),
        **_gated(),
    )

    verdict = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT)

    assert verdict.state == P.DELETABILITY_DELETABLE
    assert (verdict.basis_block() or {})["function_principal_id"] == 9


# --- (g) principal_type is never a filter ------------------------------------


def test_no_filter_anywhere_on_principal_type():
    """(g) ``principal_type`` is ``'controller'`` on 28,689 of 28,689 rows.

    Asserted on the source because the failure mode is a filter that changes
    nothing on this corpus and fails open on the next one — there is no input
    that distinguishes a join carrying it from one that does not, so no
    behavioural test can catch it.
    """
    source = "".join(
        inspect.getsource(obj)
        for obj in (
            P.authority_deletability,
            P.load_deletability_plane,
            P.DeletabilityPlane,
            P.SetterPrincipal,
            P.DeletabilityVerdict,
        )
    )
    assert "principal_type" not in source
    assert not hasattr(P.SetterPrincipal, "principal_type")
    assert "principal_type" not in {field.name for field in P.SetterPrincipal.__dataclass_fields__.values()}


def test_the_decision_reads_setter_rows_and_never_a_chain_length():
    """The banned shortcut: hop count, selector name, contract shape.

    All three partition the reference corpus identically to the correct join, so
    the numeric gate cannot tell them apart. This is a source assertion for the
    same reason the previous test is.
    """
    source = inspect.getsource(P.authority_deletability)
    for banned in ("act_as_chain", "len(chain", "hop", "contract_name"):
        assert banned not in source


# --- the published verdict (inv. 13) ----------------------------------------


def test_a_withheld_verdict_discloses_its_state_reason_and_authority_witnesses():
    """Obscuring evidence must not pay (inv. 13).

    Under this rule a protocol whose gating authority cannot be resolved lands
    on ``not_determined``, its figure is withheld, and its published exposure
    FALLS. What stops that being a gaming route is that the withheld entry
    publishes the state, the typed reason and the authority it asked about, so a
    suppressed authority presents as a disclosed unknown and not as an absent
    finding — and the reason token is what the consumer's ``refused`` counter is
    keyed on.
    """
    plane = _plane((_setter(3, contract=AUTHORITY, function_name="setUserRole", principal=SAFE),))

    block = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT).disclosure()

    assert block["state"] == P.DELETABILITY_NOT_DETERMINED
    assert block["reason"] == P.DELETABILITY_AUTHORITY_UNRESOLVED
    assert block["reason"] in P.DELETABILITY_REASONS
    assert block["destination"] == VAULT_KEY
    assert block["selector"] == EXIT
    assert block["principal_addresses"] == [SAFE]
    assert block["basis"] is None
    assert block["gating_authority_witness"] == {
        "selector_scoped": [],
        "contract_scoped_crosscheck": [],
        "crosscheck": P.CROSSCHECK_NOT_COMPARED,
    }


def test_a_deletable_verdict_discloses_the_row_that_proved_it():
    plane = _plane((_setter(3, contract=VAULT, function_name="setAuthority", principal=SAFE),))

    block = P.authority_deletability(plane, [SAFE], VAULT_KEY, EXIT).disclosure()

    assert block["state"] == P.DELETABILITY_DELETABLE
    assert block["reason"] is None
    assert block["basis"]["function_principal_id"] == 3
    assert block["basis"]["arm"] == P.DELETABILITY_ARM_HOST


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
    """A deletable state with no basis is a control claim with no witness."""
    with pytest.raises(ValueError):
        P.DeletabilityVerdict(
            destination_key=VAULT_KEY,
            selector=EXIT,
            principal_addresses=(SAFE,),
            **kwargs,
        )


# --- the loader --------------------------------------------------------------


@pytest.fixture()
def loaded(db_session):
    """A tiny two-contract corpus, loaded through the real plane loader."""
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

    def function(
        row: Contract,
        *,
        name: str,
        selector: str,
        capability_expr: Any = None,
    ) -> EffectiveFunction:
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
    """A distinct address per test — the loader reads the whole table."""
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


def test_the_loader_is_not_protocol_scoped(db_session, loaded):
    """A setter row on a contract nothing attributed is still a witness.

    Measured on the reference snapshot: 51 of the 262 setter rows sit on 33
    contracts whose ``protocol_id`` is NULL. Dropping them does not fail safe —
    the join would return no row and the entry would publish the earned negative
    ``proven_not_deletable``, minted out of our own scoping.
    """
    _protocol, contract, function, principal, _controller_value = loaded
    vault = _addr()
    orphan = contract(vault, protocol_id=None)
    principal(
        function(orphan, name="setAuthority", selector="0x7a9e5e4b"),
        address=SAFE,
        details={"membership_quality": "exact"},
    )

    plane = P.load_deletability_plane(db_session)

    assert P.authority_deletability(plane, [SAFE], f"ethereum::{vault}", EXIT).state == P.DELETABILITY_DELETABLE


def test_the_loader_marks_a_gate_whose_caller_authority_is_unresolved(db_session, loaded):
    protocol, contract, function, principal, _controller_value = loaded
    vault, authority = _addr(), _addr()
    host = contract(vault, protocol_id=protocol.id)
    registry = contract(authority, protocol_id=protocol.id)
    exit_fn = function(
        host,
        name="exit",
        selector=EXIT,
        capability_expr={"check": {"extra": {"basis": [P.CALLER_TAINTED_AUTHORITY_UNRESOLVED]}}},
    )
    principal(
        exit_fn,
        address=SAFE,
        details={"trace": [{"step": P.SOLMATE_ROLES_AUTHORITY_STEP, "authority": authority}]},
    )
    principal(
        function(registry, name="setUserRole", selector="0x67aff484"),
        address=SAFE,
        details={"membership_quality": "exact"},
    )

    plane = P.load_deletability_plane(db_session)

    assert ("ethereum", vault, EXIT) in plane.tainted
    verdict = P.authority_deletability(plane, [SAFE], f"ethereum::{vault}", EXIT)
    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_AUTHORITY_TAINTED


def test_the_loader_reads_only_the_solmate_step_for_the_authority(db_session, loaded):
    """A trace step of some other kind names no gating authority."""
    protocol, contract, function, principal, _controller_value = loaded
    vault, authority = _addr(), _addr()
    host = contract(vault, protocol_id=protocol.id)
    principal(
        function(host, name="exit", selector=EXIT),
        address=SAFE,
        details={"trace": [{"step": "owner_state_variable", "authority": authority}]},
    )

    plane = P.load_deletability_plane(db_session)

    assert ("ethereum", vault, EXIT) not in plane.gating
    verdict = P.authority_deletability(plane, [SAFE], f"ethereum::{vault}", EXIT)
    assert verdict.state == P.DELETABILITY_NOT_DETERMINED
    assert verdict.reason == P.DELETABILITY_AUTHORITY_UNRESOLVED
