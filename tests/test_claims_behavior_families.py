"""Behavior-family claim matchers over the frozen fixture corpus.

Drives the real static stack — Slither compile -> ``build_predicate_artifacts``
-> ``build_effects`` -> ``build_claims`` -> the registered matchers — on the
corpus contracts, and asserts the pause / flow / supply / callee_pointer /
user-plane claims each contract must (and must not) carry. Each family keeps at
least one positive and one negative; where a family's real positive left the
corpus (gov.delegate / flow.in), it is pinned through ``build_claims`` on the
documented facts shape instead (input data, not a faked collaborator).

The whole corpus pins solc 0.8.27 (the version the offline CI ``test`` job
installs); each contract compiles once (shared per-address cache) and the gate
never reaches the network to resolve a version.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

pytest.importorskip("slither")

from tests.support.label_corpus import SolcNotInstalled, claims_for_address  # noqa: E402

# address -> name of every corpus contract these tests touch.
TOKEN = "0x0000000000000000000000000000000000000010"
VAULT_HOOK = "0x0000000000000000000000000000000000000040"
LZ_OAPP = "0x0000000000000000000000000000000000000050"
WRAPPED_NATIVE = "0x000000000000000000000000000000000000dead"


def _load(address: str) -> dict[str, list[Any]]:
    try:
        return claims_for_address(address)
    except SolcNotInstalled as exc:  # pragma: no cover - only when a solc version is absent
        pytest.skip(str(exc))


def _ids(claims: Sequence[dict[str, Any]]) -> set[str]:
    return {c["claim_id"] for c in claims}


def _one(claims: Sequence[dict[str, Any]], claim_id: str) -> dict[str, Any]:
    matches = [c for c in claims if c["claim_id"] == claim_id]
    assert len(matches) == 1, f"expected exactly one {claim_id}, got {[c['claim_id'] for c in claims]}"
    return matches[0]


# ---------------------------------------------------------------------------
# pause.set / pause.unset
# ---------------------------------------------------------------------------


def test_pause_standard_require_toggle():
    fns = _load(TOKEN)
    assert _one(fns["pause()"], "pause.set")["tier"] == "standard_exact"
    assert _one(fns["unpause()"], "pause.unset")["tier"] == "standard_exact"
    # A require-based flag never mislabels its own toggle as the opposite polarity.
    assert "pause.unset" not in _ids(fns["pause()"])
    assert "pause.set" not in _ids(fns["unpause()"])
    # Counterexample: a non-toggle setter on the same contract carries no pause claim.
    assert not _ids(fns["mint(address,uint256)"]) & {"pause.set", "pause.unset"}


# ---------------------------------------------------------------------------
# flow.out / flow.in + supply.mint / supply.burn
# ---------------------------------------------------------------------------


def test_flow_out_and_supply_burn_native_withdraw():
    fns = _load(WRAPPED_NATIVE)
    withdraw = fns["withdraw(uint256)"]
    assert "flow.out" in _ids(withdraw)
    assert "supply.burn" in _ids(withdraw)
    flow = _one(withdraw, "flow.out")
    assert flow["witness"]["direction"] == "out"
    assert any(f["kind"] == "native_transfer_send" for f in flow["witness"]["flows"])


def test_flow_in_pull_from_third_party():
    """A callee ERC-20 ``transferFrom`` whose ``from`` is not this contract pulls
    value *in* — driven through the real ``build_claims`` on the documented facts
    shape (input data, not a faked collaborator)."""
    from services.static.claims import build_claims

    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Puller",
        "functions": {
            "pullIn(address,uint256)": {
                "function": "pullIn(address,uint256)",
                "selector": "0x00000000",
                "sinks": [
                    {
                        "id": "pullIn:sink0:external_call:token.transferFrom",
                        "function": "pullIn(address,uint256)",
                        "kind": "external_call",
                        "target": "token.transferFrom",
                        "selector": "0x23b872dd",
                        "origin": "body",
                    }
                ],
                "state_writes": [],
                "value_flows": [
                    {
                        "kind": "callee_erc20_selector",
                        "selector": "0x23b872dd",
                        "direction": "in",
                        "from_is_self": False,
                        "origin": "body",
                    }
                ],
                "effect_labels": [],
            }
        },
    }
    claims: list[Any] = build_claims(None, effects, {})["functions"]["pullIn(address,uint256)"]
    flow = _one(claims, "flow.in")
    assert flow["tier"] == "standard_exact"
    assert flow["witness"]["direction"] == "in"
    assert flow["witness"]["sink_ids"] == ["pullIn:sink0:external_call:token.transferFrom"]
    assert "flow.out" not in _ids(claims)


def test_supply_sign_idiom_vault_enter_exit():
    fns = _load(VAULT_HOOK)
    enter = "enter(address,uint256)"
    exit_ = "exit(address,uint256)"
    assert _one(fns[enter], "supply.mint")["tier"] == "idiom_structural"
    assert _one(fns[exit_], "supply.burn")["tier"] == "idiom_structural"
    # Direction is not crossed: enter never burns, exit never mints.
    assert "supply.burn" not in _ids(fns[enter])
    assert "supply.mint" not in _ids(fns[exit_])


def test_flow_counterexample_pure_token_transfer_is_not_a_flow():
    """An ERC-20's own ``transfer`` moves its ledger, not value out of the
    contract — no flow claim, only the user-plane claim."""
    fns = _load(WRAPPED_NATIVE)
    assert not _ids(fns["transfer(address,uint256)"]) & {"flow.out", "flow.in"}
    assert not _ids(fns["approve(address,uint256)"]) & {"flow.out", "flow.in", "supply.mint", "supply.burn"}


# ---------------------------------------------------------------------------
# callee_pointer.rotate
# ---------------------------------------------------------------------------


def test_callee_pointer_rotate_vault_hook():
    fns = _load(VAULT_HOOK)
    claim = _one(fns["setBeforeTransferHook(address)"], "callee_pointer.rotate")
    assert claim["tier"] == "idiom_structural"
    links = claim["witness"]["links"]
    assert any(link["pointer"] == "hook" and link["invoked_by"].startswith("transfer") for link in links)


def test_callee_pointer_counterexample_erc20_approve():
    """``approve`` writes a mapping, not a callable scalar pointer a sibling
    invokes — no callee_pointer claim."""
    fns = _load(VAULT_HOOK)
    assert "callee_pointer.rotate" not in _ids(fns["approve(address,uint256)"])


def test_callee_pointer_near_miss_ozv5_pseudo_slot_setter():
    """``setLockBox`` writes an OZ-v5 namespaced pseudo-slot member (hygiene
    ``storage_location_pseudo``), not a hygiene-normal scalar pointer — no
    callee_pointer claim even though ``lockBox`` is address-typed."""
    fns = _load(LZ_OAPP)
    assert "callee_pointer.rotate" not in _ids(fns["setLockBox(address)"])


# ---------------------------------------------------------------------------
# user-plane: erc20 / weth / gov.delegate / lz_oapp
# ---------------------------------------------------------------------------


def test_erc20_user_plane_claims():
    fns = _load(WRAPPED_NATIVE)
    assert "erc20.approve" in _ids(fns["approve(address,uint256)"])
    assert "erc20.transfer" in _ids(fns["transfer(address,uint256)"])
    assert "erc20.transfer_from" in _ids(fns["transferFrom(address,address,uint256)"])


def test_weth_wrap_unwrap_idiom():
    fns = _load(WRAPPED_NATIVE)
    assert "weth.deposit" in _ids(fns["deposit()"])
    assert "weth.withdraw" in _ids(fns["withdraw(uint256)"])


def test_erc20_counterexample_non_token_contract_has_no_erc20_claims():
    """LzOApp is not an ERC-20; its config setters carry no user-plane token
    claims."""
    fns = _load(LZ_OAPP)
    for sig, claims in fns.items():
        assert not _ids(claims) & {"erc20.approve", "erc20.transfer", "erc20.transfer_from"}, sig


def test_gov_delegate_positive_writes_delegates_and_checkpoints():
    """Comp-style delegation — writing both the ``delegates`` map and the
    ``checkpoints`` voting-power ledger is the voting-power move. The gate is
    facts-only, so it is pinned through the real ``build_claims`` on the
    documented state-write shape."""
    ids = _claim_ids_over(
        {
            "delegate(address)": _fn_record(
                "delegate(address)",
                "0x5c19a95c",
                state_writes=[
                    {"var": "delegates", "declared_type": "mapping(address => address)", "origin": "body"},
                    {
                        "var": "checkpoints",
                        "declared_type": "mapping(address => mapping(uint32 => Checkpoint))",
                        "origin": "body",
                    },
                ],
            )
        }
    )
    assert "gov.delegate" in ids["delegate(address)"]


def test_gov_delegate_counterexample_non_voting_token():
    """WrappedNative writes no ``delegates``/``checkpoints`` maps — no delegation
    claim on any of its functions."""
    fns = _load(WRAPPED_NATIVE)
    for claims in fns.values():
        assert "gov.delegate" not in _ids(claims)


def test_lz_oapp_config_claims():
    fns = _load(LZ_OAPP)
    assert _one(fns["setPeer(uint32,bytes32)"], "lz_oapp.set_peer")["tier"] == "standard_exact"
    assert _one(fns["setDelegate(address)"], "lz_oapp.set_delegate")["tier"] == "standard_exact"


def test_lz_oapp_counterexample_non_oapp_has_no_peer_claim():
    """A contract without the OApp gate never gets an lz_oapp claim — WrappedNative
    has none, proving no accidental fire."""
    fns = _load(WRAPPED_NATIVE)
    for claims in fns.values():
        assert not _ids(claims) & {"lz_oapp.set_peer", "lz_oapp.set_delegate"}


# ---------------------------------------------------------------------------
# user-plane adversarial near-misses (spec §6.2): each peripheral entry gets a
# same-selector / same-named sibling whose *standard gate* is absent, driven
# through the real build_claims on the documented facts shape (input data, not
# a faked collaborator — the contract is intentionally absent so is_erc20 / the
# OApp gate read as not-a-standard).
# ---------------------------------------------------------------------------


def _claim_ids_over(functions: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    from services.static.claims import build_claims

    effects = {"schema_version": "semantic-2", "contract_name": "NearMiss", "functions": functions}
    artifact = build_claims(None, effects, {})
    return {sig: {c["claim_id"] for c in claims} for sig, claims in artifact["functions"].items()}


def _fn_record(signature: str, selector: str, **extra: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "function": signature,
        "selector": selector,
        "sinks": [],
        "state_writes": [],
        "value_flows": [],
        "effect_labels": [],
    }
    record.update(extra)
    return record


def test_erc20_near_miss_selectors_without_the_erc20_standard():
    """The ERC-20 transfer/approve/transferFrom selectors on a contract that is
    not an ERC-20 mint no user-plane token claim — the standard, not the
    selector, is the discriminator."""
    ids = _claim_ids_over(
        {
            "approve(address,uint256)": _fn_record("approve(address,uint256)", "0x095ea7b3"),
            "transfer(address,uint256)": _fn_record("transfer(address,uint256)", "0xa9059cbb"),
            "transferFrom(address,address,uint256)": _fn_record("transferFrom(address,address,uint256)", "0x23b872dd"),
        }
    )
    assert "erc20.approve" not in ids["approve(address,uint256)"]
    assert "erc20.transfer" not in ids["transfer(address,uint256)"]
    assert "erc20.transfer_from" not in ids["transferFrom(address,address,uint256)"]


def test_weth_near_miss_deposit_withdraw_on_non_erc20():
    """A vault-shaped contract exposing ``deposit()``/``withdraw(uint256)`` that
    is not an ERC-20 is not wrapped ETH — no weth claim."""
    ids = _claim_ids_over(
        {
            "deposit()": _fn_record("deposit()", "0xd0e30db0"),
            "withdraw(uint256)": _fn_record("withdraw(uint256)", "0x2e1a7d4d"),
        }
    )
    assert "weth.deposit" not in ids["deposit()"]
    assert "weth.withdraw" not in ids["withdraw(uint256)"]


def test_lz_oapp_near_miss_set_delegate_outside_the_oapp_gate():
    """A ``setDelegate(address)`` on a contract with no ``setPeer`` (no OApp
    gate) is an ordinary setter, not LayerZero endpoint configuration."""
    ids = _claim_ids_over({"setDelegate(address)": _fn_record("setDelegate(address)", "0xca5eb5e1")})
    assert "lz_oapp.set_delegate" not in ids["setDelegate(address)"]


def test_gov_delegate_near_miss_writes_only_delegates_map():
    """A delegation-shaped setter that writes only the ``delegates`` map (not the
    Comp ``checkpoints`` voting-power ledger) is not the voting-power move."""
    ids = _claim_ids_over(
        {
            "delegate(address)": _fn_record(
                "delegate(address)",
                "0x5c19a95c",
                state_writes=[{"var": "delegates", "declared_type": "mapping(address => address)", "origin": "body"}],
            )
        }
    )
    assert "gov.delegate" not in ids["delegate(address)"]
