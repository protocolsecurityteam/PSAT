"""Primary assignment decides which principals get MonitoredContract rows and which group each contract joins on the
canvas.
"""

from __future__ import annotations

import pytest

from services.governance.primary_controller import (
    _UNCHIPPED_CONTROL_CLAIMS,
    CLAIM_CAPABILITY,
    assign_co_controllers,
    assign_operand_render_groups,
    assign_primary_controllers,
    function_capabilities,
)
from services.static.claims import CONTROL_GRANT_CLASSES, claim_ids_of_class


def _p(addr: str, ptype: str) -> dict:
    return {"address": addr, "type": ptype}


def _fn(callers: set[str], *, claims: list[str] | None = None) -> dict:
    fn: dict = {"callers": set(callers)}
    if claims is not None:
        fn["claims"] = list(claims)
    return fn


def test_unknown_type_excluded():
    principals = [_p("0xa", "contract"), _p("0xb", "safe")]
    fp = {"0xc1": {"0xa", "0xb"}}
    result = assign_primary_controllers(principals, fp)
    assert "0xa" not in result
    assert result["0xb"] == ["0xc1"]


def test_output_is_sorted():
    fp = {"0xc3": {"0xa"}, "0xc1": {"0xa"}, "0xc2": {"0xa"}}
    result = assign_primary_controllers([_p("0xa", "safe")], fp)
    assert result["0xa"] == ["0xc1", "0xc2", "0xc3"]


def test_governance_passthrough_resolves_safe_behind_timelock():
    """The ether.fi shape: the Timelock is a contract, never a principal, so it passes through."""
    vault, timelock, safe = "0xc1", "0xtl", "0xsafe"
    fp = {
        vault: {timelock},  # vault.onlyOwner caller resolves to the timelock
        timelock: {safe},  # timelock.execute caller resolves to the safe
    }
    result = assign_primary_controllers([_p(safe, "safe")], fp, governance_passthrough={timelock})
    assert sorted(result[safe]) == sorted([vault, timelock])


def test_governance_passthrough_off_is_unchanged_one_hop():
    """The ``None`` default preserves one-hop behavior."""
    vault, timelock, safe = "0xc1", "0xtl", "0xsafe"
    fp = {vault: {timelock}, timelock: {safe}}
    result = assign_primary_controllers([_p(safe, "safe")], fp)
    assert result[safe] == [timelock]  # vault is NOT attributed without pass-through


def test_governance_passthrough_does_not_recurse_through_non_governance():
    """Otherwise ordinary operational contracts over-attribute."""
    vault, manager, safe = "0xc1", "0xmgr", "0xsafe"
    fp = {vault: {manager}, manager: {safe}}
    result = assign_primary_controllers([_p(safe, "safe")], fp, governance_passthrough=set())
    assert result[safe] == [manager]


# Contest key: (tier on this contract, type, lex address), per-contract facts only so assignments don't flip as coverage
# grows.


def test_partial_claim_coverage_does_not_read_as_veto_only():
    """The veto test is per function, not per claim union."""
    vault, tl = "0xc1", "0xtl"
    canceller, prop = "0xbbb", "0xaaa"  # prop lex-smaller irrelevant; gating is the test
    fp = {vault: {tl}, tl: {canceller, prop}}
    detail = {
        vault: [_fn({tl}, claims=["upgrade.implementation"])],
        tl: [
            _fn({canceller, prop}, claims=["timelock.cancel"]),
            _fn({prop}),  # claim-less row: driving power not determined
        ],
    }
    result = assign_primary_controllers(
        [_p(canceller, "safe"), _p(prop, "safe")],
        fp,
        governance_passthrough={tl},
        fp_function_detail_by_contract=detail,
    )
    assert sorted(result[prop]) == [vault, tl]
    assert result[canceller] == []


def test_proven_non_driver_does_not_inherit():
    """Inheritance needs a positive driving witness."""
    vault, tl = "0xc1", "0xtl"
    delay_setter, driver = "0xaaa", "0xzzz"  # delay setter lex-smaller: gating must do the work
    fp = {vault: {tl}, tl: {delay_setter, driver}}
    detail = {
        vault: [_fn({tl}, claims=["upgrade.implementation"])],
        tl: [
            _fn({delay_setter}, claims=["timelock.set_delay"]),
            _fn({driver}, claims=["timelock.schedule", "timelock.execute"]),
        ],
    }
    result = assign_primary_controllers(
        [_p(delay_setter, "safe"), _p(driver, "safe")],
        fp,
        governance_passthrough={tl},
        fp_function_detail_by_contract=detail,
    )
    assert sorted(result[driver]) == [vault, tl]
    assert result[delay_setter] == []


def test_delegatecall_is_governing_tier():
    """Delegatecall runs arbitrary code in the contract's storage."""
    dc, granter = "0xzzz", "0xaaa"  # delegatecall holder lex-larger: tier must decide
    fp = {"0xc1": {dc, granter}}
    detail = {
        "0xc1": [
            _fn({dc}, claims=["delegatecall.execute"]),
            _fn({granter}, claims=["roles.grant"]),
        ]
    }
    result = assign_primary_controllers(
        [_p(dc, "safe"), _p(granter, "safe")],
        fp,
        fp_function_detail_by_contract=detail,
    )
    assert result[dc] == ["0xc1"]
    assert result[granter] == []


# The override changes only the render group, not primary_for.


def _all_contracts(fp: dict) -> set:
    return set(fp.keys())


def test_mediator_render_group_tie_is_split_evidence():
    tl = "0xtl"
    primary_for = {"0xgov1": ["0xc1"], "0xgov2": ["0xc2"], "0xops": [tl]}
    fp = {"0xc1": {tl}, "0xc2": {tl}, tl: {"0xops"}}
    assert assign_operand_render_groups(fp, _all_contracts(fp), {tl}, primary_for) == {}


def test_mediator_render_group_ignores_unowned_operands():
    tl = "0xtl"
    primary_for = {"0xops": [tl]}
    fp = {"0xc1": {tl}, "0xc2": {tl}, tl: {"0xops"}}
    assert assign_operand_render_groups(fp, _all_contracts(fp), {tl}, primary_for) == {}


def test_mediator_plurality_tolerates_stray_operands():
    tl = "0xtl"
    primary_for = {"0xgov": ["0xc1", "0xc2"], "0xother": ["0xc3"], "0xops": [tl]}
    fp = {"0xc1": {tl}, "0xc2": {tl}, "0xc3": {tl}, tl: {"0xops"}}
    result = assign_operand_render_groups(fp, _all_contracts(fp), {tl}, primary_for)
    assert result == {tl: "0xgov"}


# A pauser/guardian Safe is recovered as a co-controller; a permissionless caller is not.


def test_co_controller_non_principal_types_ignored():
    contract = "0xc1"
    detail = {contract: [_fn({"0xinner", "0xsafe"}, claims=["pause.set"])]}
    result = assign_co_controllers([_p("0xinner", "contract"), _p("0xsafe", "safe")], detail, {"0xsafe": []})
    assert "0xinner" not in result
    assert result["0xsafe"] == [contract]


@pytest.mark.parametrize(
    "claims_by_contract",
    [
        # The legacy label was corpus-dead, so the claim is what fires.
        pytest.param({"0xc1": ["upgrade.implementation"]}, id="upgrade-implementation"),
        pytest.param(
            {"0xsafecontract": ["safe.signer_mgmt"], "0xtlcontract": ["timelock.schedule"]},
            id="new-claim-families",
        ),
        pytest.param({"0xkernel": ["delegatecall.execute"]}, id="delegatecall"),
        pytest.param({"0xtoken": ["transfer_policy.configure"]}, id="transfer-policy-config"),
    ],
)
def test_co_controller_privileged_claims(claims_by_contract):
    big, guardian = "0xbig", "0xguardian"
    wide = {guardian, big} | {f"0xrando{i}" for i in range(8)}
    contracts = sorted(claims_by_contract)
    primary_for = {big: contracts, guardian: []}
    detail = {c: [_fn(wide, claims=claims)] for c, claims in claims_by_contract.items()}
    result = assign_co_controllers([_p(big, "safe"), _p(guardian, "safe")], detail, primary_for)
    assert sorted(result[guardian]) == contracts
    assert result[big] == []


def test_every_control_claim_is_chipped_or_deliberately_unchipped():
    """A control claim added to the registry must be given a chip or an explicit exclusion."""
    control = claim_ids_of_class(*CONTROL_GRANT_CLASSES)
    assert control - _UNCHIPPED_CONTROL_CLAIMS <= set(CLAIM_CAPABILITY)
    assert _UNCHIPPED_CONTROL_CLAIMS <= control


@pytest.mark.parametrize(
    ("claims", "chips"),
    [
        (["delegatecall.execute"], {"delegatecall"}),
        (["transfer_policy.configure"], {"config"}),
        (["value_router", "flow.in"], {"fund-in"}),
        (["callee_pointer.rotate", "erc20.transfer"], set()),
        ([], set()),
    ],
)
def test_function_capabilities_come_from_claims(claims, chips):
    assert function_capabilities(claims) == chips


def test_transfer_policy_setter_is_privileged_but_not_governing():
    """Config is control, so a wide caller set still co-controls; it grants no governing tier."""
    token, owner, setter = "0xc1", "0xzzz", "0xaaa"
    detail = {
        token: [
            _fn({owner}, claims=["ownership.transfer"]),
            _fn({setter}, claims=["transfer_policy.configure"]),
        ]
    }
    result = assign_primary_controllers(
        [_p(owner, "safe"), _p(setter, "safe")], {token: {owner, setter}}, fp_function_detail_by_contract=detail
    )
    assert result == {owner: [token], setter: []}
