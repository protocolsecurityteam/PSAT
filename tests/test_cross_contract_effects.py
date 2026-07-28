"""Cross-contract policy-derived claim tests (unit layer).

Drives the real production functions in ``services.static.cross_contract`` — the
registry, ``emit_claim``, ``resolve_claim_precedence``, and every derivation —
over ``effects``-shaped fact dicts (input data, not faked collaborators). No
Slither/DB, so these run in every offline suite.

The legacy propagate-every-effect-label rule is gone: these assert typed
``policy_derived`` claims only, and that a control-plane label never rides across
a call boundary.
"""

from __future__ import annotations

from eth_utils.crypto import keccak

from services.static.claims import is_registered
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


def _callee(selector: str, claims: list[dict]) -> dict:
    return {"functions": {"someFn()": {"selector": selector, "claims": claims}}}


def _std(claim_id: str) -> dict:
    return {"claim_id": claim_id, "tier": "standard_exact", "witness": {}}


def _external_sink(target: str, selector: str, *, origin: str = "body", sid: str = "s0") -> dict:
    return {"id": sid, "kind": "external_call", "target": target, "selector": selector, "origin": origin}


def _caller(fn_sig: str, sinks: list[dict]) -> dict:
    return {"functions": {fn_sig: {"selector": _selector(fn_sig), "sinks": sinks, "claims": []}}}


# ---------------------------------------------------------------------------
# The new claim id is registered (emit_claim would fail closed otherwise)
# ---------------------------------------------------------------------------


def test_transfer_policy_claim_is_registered():
    assert is_registered(TRANSFER_POLICY_CONFIGURE)


# ---------------------------------------------------------------------------
# build_callee_claim_map — only propagatable claims survive
# ---------------------------------------------------------------------------


def test_callee_map_keeps_flow_drops_control_and_weak_tiers():
    effects = {
        "functions": {
            "transfer(address,uint256)": {"selector": TRANSFER_SELECTOR, "claims": [_std("flow.out")]},
            "grantRole(bytes32,address)": {"selector": "0x2f2ff15d", "claims": [_std("roles.grant")]},
            "burn(uint256)": {
                "selector": "0x42966c68",
                "claims": [{"claim_id": "supply.burn", "tier": "idiom_structural", "witness": {}}],
            },
        }
    }
    callee_map = build_callee_claim_map({TOKEN: effects})
    assert TOKEN in callee_map
    # flow.out (flow family, standard) kept; roles.grant (control plane) and
    # supply.burn (only idiom tier) dropped.
    assert set(callee_map[TOKEN]) == {TRANSFER_SELECTOR}
    assert callee_map[TOKEN][TRANSFER_SELECTOR][0]["claim_id"] == "flow.out"


def test_callee_map_empty_for_missing_claims():
    assert build_callee_claim_map({TOKEN: {"functions": {}}}) == {}
    assert build_callee_claim_map(None) == {}


# ---------------------------------------------------------------------------
# Derivation 1: value-flow propagation
# ---------------------------------------------------------------------------


def test_value_flow_propagation_emits_policy_derived():
    callee_map = build_callee_claim_map({TOKEN: _callee(TRANSFER_SELECTOR, [_std("flow.out")])})
    target = _caller("sweep(address)", [_external_sink("token.transfer", TRANSFER_SELECTOR)])
    controller_values = {"state_variable:token": {"value": TOKEN}}

    out = derive_cross_contract_claims(target, controller_values, callee_map)

    assert "sweep(address)" in out
    claim = out["sweep(address)"][0]
    assert claim["claim_id"] == "flow.out"
    assert claim["tier"] == "policy_derived"
    assert claim["witness"]["callee"] == TOKEN
    assert claim["witness"]["selector"] == TRANSFER_SELECTOR
    assert claim["witness"]["source_tier"] == "standard_exact"


def test_guard_origin_call_is_not_a_value_flow():
    callee_map = build_callee_claim_map({TOKEN: _callee(TRANSFER_SELECTOR, [_std("flow.out")])})
    target = _caller("guarded(address)", [_external_sink("token.transfer", TRANSFER_SELECTOR, origin="guard")])
    out = derive_cross_contract_claims(target, {"state_variable:token": {"value": TOKEN}}, callee_map)
    assert out == {}


def test_no_join_when_controller_value_unresolved():
    callee_map = build_callee_claim_map({TOKEN: _callee(TRANSFER_SELECTOR, [_std("flow.out")])})
    target = _caller("sweep(address)", [_external_sink("token.transfer", TRANSFER_SELECTOR)])
    # No controller_values: "token" cannot resolve to an address.
    assert derive_cross_contract_claims(target, {}, callee_map) == {}


def test_no_join_when_callee_not_analyzed():
    target = _caller("sweep(address)", [_external_sink("token.transfer", TRANSFER_SELECTOR)])
    assert derive_cross_contract_claims(target, {"state_variable:token": {"value": TOKEN}}, {}) == {}


def test_control_plane_callee_claim_never_propagates():
    # A callee whose transfer selector somehow carried an authority claim must
    # not contaminate the caller: build_callee_claim_map already dropped it.
    callee_map = build_callee_claim_map({TOKEN: _callee(TRANSFER_SELECTOR, [_std("authority.replace")])})
    target = _caller("sweep(address)", [_external_sink("token.transfer", TRANSFER_SELECTOR)])
    assert derive_cross_contract_claims(target, {"state_variable:token": {"value": TOKEN}}, callee_map) == {}


def test_external_contract_controller_id_format_resolves():
    callee_map = build_callee_claim_map({TOKEN: _callee(TRANSFER_SELECTOR, [_std("flow.in")])})
    target = _caller("pull(address)", [_external_sink("registry.transferFrom", TRANSFER_SELECTOR)])
    controller_values = {"external_contract:registry": {"value": TOKEN}}
    out = derive_cross_contract_claims(target, controller_values, callee_map)
    assert out["pull(address)"][0]["claim_id"] == "flow.in"


# ---------------------------------------------------------------------------
# Derivation 3: beacon upgrade (the one control-plane claim that DOES ride)
# ---------------------------------------------------------------------------


def test_beacon_upgrade_propagates_upgrade_implementation():
    callee_map = build_callee_claim_map({BEACON: _callee(UPGRADE_TO, [_std("upgrade.implementation")])})
    target = _caller("upgradeEtherFiNode(address)", [_external_sink("beacon.upgradeTo", UPGRADE_TO)])
    controller_values = {"state_variable:beacon": {"value": BEACON}}
    out = derive_cross_contract_claims(target, controller_values, callee_map)
    claim = out["upgradeEtherFiNode(address)"][0]
    assert claim["claim_id"] == "upgrade.implementation"
    assert claim["tier"] == "policy_derived"


# ---------------------------------------------------------------------------
# Derivation 2: transfer_policy.configure
# ---------------------------------------------------------------------------


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


def test_sibling_transfer_hook_links_resolves_to_this_contract():
    links = sibling_transfer_hook_links(
        TELLER,
        {VAULT: _vault_with_hook_pointer()},
        {VAULT: {"controller_values": {"state_variable:hook": {"value": TELLER}}}},
    )
    assert links == [{"sibling_address": VAULT, "pointer_var": "hook"}]


def test_sibling_transfer_hook_links_ignores_pointer_to_other_address():
    links = sibling_transfer_hook_links(
        TELLER,
        {VAULT: _vault_with_hook_pointer()},
        {VAULT: {"controller_values": {"state_variable:hook": {"value": TOKEN}}}},
    )
    assert links == []


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


def test_transfer_policy_requires_bool_mapping_shape():
    links = [{"sibling_address": VAULT, "pointer_var": "hook"}]
    # A scalar address write (e.g. setOwner) is not a transfer allow/deny list.
    out = derive_cross_contract_claims(
        _teller_with_setter("owner", "address"),
        {},
        {},
        sibling_transfer_hooks=links,
    )
    assert out == {}


def test_transfer_policy_requires_a_sibling_hook_link():
    out = derive_cross_contract_claims(
        _teller_with_setter("allowlist", "mapping(address => bool)"),
        {},
        {},
        sibling_transfer_hooks=[],
    )
    assert out == {}


# ---------------------------------------------------------------------------
# Derivation 4: proxy-verified upgrade provenance
# ---------------------------------------------------------------------------


def _classifications(address: str, **info) -> dict:
    return {"classifications": {address: {"address": address, **info}}}


def test_proxy_provenance_from_slot_confirmed_proxy():
    art = _classifications(TELLER, type="proxy", proxy_type="eip1967", implementation=IMPL)
    pp = proxy_provenance_from_classifications(TELLER, art)
    assert pp is not None
    assert pp == {"proxy": TELLER, "implementation": IMPL, "proxy_type": "eip1967", "slot": pp["slot"]}
    assert pp["slot"].startswith("0x360894")


def test_proxy_provenance_none_for_non_slot_proxy_or_non_proxy():
    # eip1167 is a bytecode proxy, not a slot-confirmed one.
    assert (
        proxy_provenance_from_classifications(
            TELLER, _classifications(TELLER, type="proxy", proxy_type="eip1167", implementation=IMPL)
        )
        is None
    )
    assert proxy_provenance_from_classifications(TELLER, _classifications(TELLER, type="eoa")) is None
    assert proxy_provenance_from_classifications(TELLER, {}) is None


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


def test_provenance_does_not_override_static_standard_exact():
    """A static standard_exact upgrade claim on the same function survives the
    per-function precedence merge; the policy_derived duplicate is dropped."""
    from services.static.claims import Claim, resolve_claim_precedence

    pp = proxy_provenance_from_classifications(
        TELLER, _classifications(TELLER, type="proxy", proxy_type="eip1967", implementation=IMPL)
    )
    out = derive_cross_contract_claims(
        {"functions": {"upgradeTo(address)": {"selector": UPGRADE_TO, "claims": []}}},
        {},
        {},
        proxy_provenance=pp,
    )
    static_claim: Claim = {"claim_id": "upgrade.implementation", "tier": "standard_exact", "witness": {"static": True}}
    merged = resolve_claim_precedence([static_claim, *out["upgradeTo(address)"]])
    assert len(merged) == 1
    assert merged[0]["tier"] == "standard_exact"


# ---------------------------------------------------------------------------
# The four derivations compose without clobbering each other
# ---------------------------------------------------------------------------


def test_derivations_merge_per_function():
    callee_map = build_callee_claim_map({TOKEN: _callee(TRANSFER_SELECTOR, [_std("flow.out")])})
    target = {
        "functions": {
            "sweep(address)": {
                "selector": _selector("sweep(address)"),
                "sinks": [_external_sink("token.transfer", TRANSFER_SELECTOR)],
                "state_writes": [],
                "claims": [],
            },
            "allowFrom(address)": {
                "selector": "0xccddeeff",
                "sinks": [],
                "state_writes": [
                    {
                        "var": "allowlist",
                        "declared_type": "mapping(address => bool)",
                        "member_path": [],
                        "granularity": "var",
                        "hygiene_class": "normal",
                        "origin": "body",
                    }
                ],
                "claims": [],
            },
        }
    }
    out = derive_cross_contract_claims(
        target,
        {"state_variable:token": {"value": TOKEN}},
        callee_map,
        sibling_transfer_hooks=[{"sibling_address": VAULT, "pointer_var": "hook"}],
    )
    assert out["sweep(address)"][0]["claim_id"] == "flow.out"
    assert out["allowFrom(address)"][0]["claim_id"] == TRANSFER_POLICY_CONFIGURE


# ---------------------------------------------------------------------------
# L-17: the join meets through the canonical ``abi_selector`` when the callee's
# declared signature is not the ABI form (interface/enum/struct params).
# ---------------------------------------------------------------------------

# keccak("sweepTo(IERC20,address,uint256)")[:4] — the DECLARED form the callee
# record keys today; NOT a dispatchable selector.
DECLARED_SWEEP_TO = _selector("sweepTo(IERC20,address,uint256)")
# keccak("sweepTo(address,address,uint256)")[:4] — the canonical ABI form the
# caller's sink records.
CANONICAL_SWEEP_TO = _selector("sweepTo(address,address,uint256)")


def _interface_param_callee(claims: list[dict], *, stamped: bool) -> dict:
    record: dict = {"selector": DECLARED_SWEEP_TO, "claims": claims}
    if stamped:
        record["abi_selector"] = CANONICAL_SWEEP_TO
    return {"functions": {"sweepTo(IERC20,address,uint256)": record}}


def test_interface_param_callee_joins_via_the_canonical_key():
    """The realised L-17 pair: AssetRecovery's record says 0x38541c00, the
    caller's sink says 0x0aeef8c8; with the canonical stamp the join meets and
    the caller inherits flow.out at policy_derived — its OWN rank, not the
    callee's standard_exact (the tier lattice scores it as the weakest tier)."""
    callee_map = build_callee_claim_map({TOKEN: _interface_param_callee([_std("flow.out")], stamped=True)})
    assert CANONICAL_SWEEP_TO in callee_map[TOKEN]
    target = _caller("recoverVia(address,address,uint256)", [_external_sink("recovery.sweepTo", CANONICAL_SWEEP_TO)])
    out = derive_cross_contract_claims(target, {"state_variable:recovery": {"value": TOKEN}}, callee_map)
    claim = out["recoverVia(address,address,uint256)"][0]
    assert claim["claim_id"] == "flow.out"
    assert claim["tier"] == "policy_derived"
    assert claim["witness"]["selector"] == CANONICAL_SWEEP_TO


def test_unstamped_interface_param_callee_still_misses_honestly():
    """An artifact minted before the stamp existed carries no canonical key.
    Absence is not-determined: the join must NOT guess a lowering, so the
    pre-fix miss is preserved rather than a claim being manufactured."""
    callee_map = build_callee_claim_map({TOKEN: _interface_param_callee([_std("flow.out")], stamped=False)})
    assert CANONICAL_SWEEP_TO not in callee_map[TOKEN]
    target = _caller("recoverVia(address,address,uint256)", [_external_sink("recovery.sweepTo", CANONICAL_SWEEP_TO)])
    assert derive_cross_contract_claims(target, {"state_variable:recovery": {"value": TOKEN}}, callee_map) == {}


def test_non_propagatable_claims_never_join_even_via_the_canonical_key():
    """Negative control: the canonical key widens the JOIN, not the
    propagation rule. A weak-tier claim and a control-plane claim on the same
    stamped callee still derive nothing."""
    weak = {"claim_id": "exec.arbitrary", "tier": "idiom_structural", "witness": {}}
    control = _std("authority.replace")
    callee_map = build_callee_claim_map({TOKEN: _interface_param_callee([weak, control], stamped=True)})
    assert callee_map == {}
    target = _caller("recoverVia(address,address,uint256)", [_external_sink("recovery.sweepTo", CANONICAL_SWEEP_TO)])
    assert derive_cross_contract_claims(target, {"state_variable:recovery": {"value": TOKEN}}, callee_map) == {}


def test_elementary_callee_is_not_double_counted_by_the_two_keys():
    """When canonical == declared the two keys collapse to one map entry, so a
    caller inherits the claim exactly once."""
    record = {"selector": TRANSFER_SELECTOR, "abi_selector": TRANSFER_SELECTOR, "claims": [_std("flow.out")]}
    callee_map = build_callee_claim_map({TOKEN: {"functions": {"transfer(address,uint256)": record}}})
    assert list(callee_map[TOKEN]) == [TRANSFER_SELECTOR]
    assert len(callee_map[TOKEN][TRANSFER_SELECTOR]) == 1
    target = _caller("sweep(address)", [_external_sink("token.transfer", TRANSFER_SELECTOR)])
    out = derive_cross_contract_claims(target, {"state_variable:token": {"value": TOKEN}}, callee_map)
    assert len(out["sweep(address)"]) == 1
