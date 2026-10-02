"""Only typed ``policy_derived`` claims cross a call boundary; control-plane labels never do."""

from __future__ import annotations

import pytest
from eth_utils.crypto import keccak

from services.static.cross_contract import (
    TRANSFER_POLICY_CONFIGURE,
    build_callee_claim_map,
    derive_cross_contract_claims,
    proxy_provenance_from_classifications,
    sibling_transfer_hook_links,
)

TOKEN = "0x1111111111111111111111111111111111111111"
VAULT = "0x2222222222222222222222222222222222222222"
TELLER = "0x3333333333333333333333333333333333333333"
BEACON = "0x4444444444444444444444444444444444444444"
IMPL = "0x9999999999999999999999999999999999999999"

TRANSFER_SELECTOR = "0xa9059cbb"  # transfer(address,uint256)
UPGRADE_TO = "0x3659cfe6"  # upgradeTo(address)


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _std(claim_id: str) -> dict:
    return {"claim_id": claim_id, "tier": "standard_exact", "witness": {}}


def _external_sink(target: str, selector: str, *, origin: str = "body", sid: str = "s0") -> dict:
    return {"id": sid, "kind": "external_call", "target": target, "selector": selector, "origin": origin}


def _caller(fn_sig: str, sinks: list[dict]) -> dict:
    return {"functions": {fn_sig: {"selector": _selector(fn_sig), "sinks": sinks, "claims": []}}}


def _vault_with_hook_pointer(pointer: str = "hook") -> dict:
    return {
        "functions": {
            "setBeforeTransferHook(address)": {
                "selector": "0xaabbccdd",
                "claims": [
                    {
                        "claim_id": "callee_pointer.rotate",
                        "tier": "idiom_structural",
                        "witness": {"kind": "use_link", "links": [{"pointer": pointer, "invoked_by": "transfer()"}]},
                    }
                ],
            }
        }
    }


def _teller_with_setter(var: str, declared_type: str) -> dict:
    return {
        "functions": {
            "allowFrom(address)": {
                "selector": "0xccddeeff",
                "state_writes": [
                    {
                        "var": var,
                        "declared_type": declared_type,
                        "member_path": [],
                        "granularity": "var",
                        "hygiene_class": "normal",
                        "origin": "body",
                    }
                ],
                "claims": [],
            }
        }
    }


def test_transfer_policy_configure_on_bool_mapping_setter():
    links = sibling_transfer_hook_links(
        TELLER,
        {VAULT: _vault_with_hook_pointer()},
        {VAULT: {"controller_values": {"state_variable:hook": {"value": TELLER}}}},
    )
    out = derive_cross_contract_claims(
        _teller_with_setter("allowlist", "mapping(address => bool)"),
        {},
        {},
        sibling_transfer_hooks=links,
    )
    claim = out["allowFrom(address)"][0]
    assert claim["claim_id"] == TRANSFER_POLICY_CONFIGURE
    assert claim["tier"] == "policy_derived"
    assert claim["witness"]["configures"] == VAULT
    assert claim["witness"]["set_vars"] == ["allowlist"]


@pytest.mark.parametrize(
    ("var", "declared_type", "links"),
    [
        pytest.param("owner", "address", [{"sibling_address": VAULT, "pointer_var": "hook"}], id="not_bool_mapping"),
        pytest.param("allowlist", "mapping(address => bool)", [], id="no_sibling_hook_link"),
    ],
)
def test_transfer_policy_negatives(var, declared_type, links):
    out = derive_cross_contract_claims(
        _teller_with_setter(var, declared_type),
        {},
        {},
        sibling_transfer_hooks=links,
    )
    assert out == {}


def _classifications(address: str, **info) -> dict:
    return {"classifications": {address: {"address": address, **info}}}


def test_provenance_upgrade_emits_policy_derived():
    pp = proxy_provenance_from_classifications(
        TELLER, _classifications(TELLER, type="proxy", proxy_type="eip1967", implementation=IMPL)
    )
    impl_effects = {
        "functions": {
            "upgradeTo(address)": {"selector": UPGRADE_TO, "claims": []},
            "foo()": {"selector": "0x12341234", "claims": []},
        }
    }
    out = derive_cross_contract_claims(impl_effects, {}, {}, proxy_provenance=pp)
    claim = out["upgradeTo(address)"][0]
    assert claim["claim_id"] == "upgrade.implementation"
    assert claim["tier"] == "policy_derived"
    assert claim["witness"]["implementation"] == IMPL
    assert "foo()" not in out  # non-upgrade selectors untouched


# The join meets through ``abi_selector`` when the callee's declared signature isn't the ABI form.

# The declared form the callee record keys on; not dispatchable.
DECLARED_SWEEP_TO = _selector("sweepTo(IERC20,address,uint256)")
CANONICAL_SWEEP_TO = _selector("sweepTo(address,address,uint256)")


def _interface_param_callee(claims: list[dict], *, stamped: bool) -> dict:
    record: dict = {"selector": DECLARED_SWEEP_TO, "claims": claims}
    if stamped:
        record["abi_selector"] = CANONICAL_SWEEP_TO
    return {"functions": {"sweepTo(IERC20,address,uint256)": record}}


def test_interface_param_callee_joins_via_the_canonical_key():
    """AssetRecovery's record says 0x38541c00 and the caller's sink 0x0aeef8c8.

    The caller inherits at its own policy_derived rank, not the callee's.
    """
    callee_map = build_callee_claim_map({TOKEN: _interface_param_callee([_std("flow.out")], stamped=True)})
    assert CANONICAL_SWEEP_TO in callee_map[TOKEN]
    target = _caller("recoverVia(address,address,uint256)", [_external_sink("recovery.sweepTo", CANONICAL_SWEEP_TO)])
    out = derive_cross_contract_claims(target, {"state_variable:recovery": {"value": TOKEN}}, callee_map)
    claim = out["recoverVia(address,address,uint256)"][0]
    assert claim["claim_id"] == "flow.out"
    assert claim["tier"] == "policy_derived"
    assert claim["witness"]["selector"] == CANONICAL_SWEEP_TO


def test_non_propagatable_claims_never_join_even_via_the_canonical_key():
    """The canonical key widens the join, not the propagation rule."""
    weak = {"claim_id": "exec.arbitrary", "tier": "idiom_structural", "witness": {}}
    control = _std("authority.replace")
    callee_map = build_callee_claim_map({TOKEN: _interface_param_callee([weak, control], stamped=True)})
    assert callee_map == {}
    target = _caller("recoverVia(address,address,uint256)", [_external_sink("recovery.sweepTo", CANONICAL_SWEEP_TO)])
    assert derive_cross_contract_claims(target, {"state_variable:recovery": {"value": TOKEN}}, callee_map) == {}
