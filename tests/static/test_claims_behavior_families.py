"""Behavior-family matchers over the real stack on the frozen corpus, a positive and a negative per family.

gov.delegate / flow.in positives left the corpus and are pinned through ``build_claims`` instead. The corpus pins solc
0.8.27 so the gate never hits the network.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

pytest.importorskip("slither")

from tests.support.label_corpus import SolcNotInstalled, claims_for_address

TOKEN = "0x0000000000000000000000000000000000000010"
VAULT_HOOK = "0x0000000000000000000000000000000000000040"
LZ_OAPP = "0x0000000000000000000000000000000000000050"
WRAPPED_NATIVE = "0x000000000000000000000000000000000000dead"
NAMESPACED_PAUSABLE = "0x0000000000000000000000000000000000000060"
OZ_V5_NAMESPACED_OWNABLE = "0x0000000000000000000000000000000000000020"


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


def test_pause_standard_require_toggle():
    fns = _load(TOKEN)
    assert _one(fns["pause()"], "pause.set")["tier"] == "standard_exact"
    assert _one(fns["unpause()"], "pause.unset")["tier"] == "standard_exact"
    assert "pause.unset" not in _ids(fns["pause()"])
    assert "pause.set" not in _ids(fns["unpause()"])
    assert not _ids(fns["mint(address,uint256)"]) & {"pause.set", "pause.unset"}


def test_pause_namespaced_erc7201_latch():
    """Plane 0 records the ERC-7201 flag as a ``bytes32`` slot, so a bool-only filter missed every OZ-v5 / etherfi
    pauser.
    """
    fns = _load(NAMESPACED_PAUSABLE)
    assert _one(fns["pause()"], "pause.set")
    assert _one(fns["unpause()"], "pause.unset")
    # The assignment names the local pointer, so without the guard-read member alias both directions would fire.
    assert "pause.unset" not in _ids(fns["pause()"])
    assert "pause.set" not in _ids(fns["unpause()"])
    assert not _ids(fns["transfer(address,uint256)"]) & {"pause.set", "pause.unset"}
    assert not _ids(fns["paused()"]) & {"pause.set", "pause.unset"}
    assert not _ids(fns["approveSelf(uint256)"]) & {"pause.set", "pause.unset"}


def test_namespaced_authority_write_is_not_a_pause():
    """A namespaced slot holds the whole struct, so an owner change "writes a slot some gate reads"; only a
    constant-bool toggle of a guard-read member is a pause.
    """
    fns = _load(OZ_V5_NAMESPACED_OWNABLE)
    for signature in ("transferOwnership(address)", "renounceOwnership()"):
        assert not _ids(fns[signature]) & {"pause.set", "pause.unset"}, signature
        assert _ids(fns[signature]) & {"ownership.transfer", "ownership.renounce"}


def test_flow_out_and_supply_burn_native_withdraw():
    fns = _load(WRAPPED_NATIVE)
    withdraw = fns["withdraw(uint256)"]
    assert "flow.out" in _ids(withdraw)
    assert "supply.burn" in _ids(withdraw)
    flow = _one(withdraw, "flow.out")
    assert flow["witness"]["direction"] == "out"
    assert any(f["kind"] == "native_transfer_send" for f in flow["witness"]["flows"])


def test_flow_in_pull_from_third_party():
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
    assert "supply.burn" not in _ids(fns[enter])
    assert "supply.mint" not in _ids(fns[exit_])


def test_flow_counterexample_pure_token_transfer_is_not_a_flow():
    fns = _load(WRAPPED_NATIVE)
    assert not _ids(fns["transfer(address,uint256)"]) & {"flow.out", "flow.in"}
    assert not _ids(fns["approve(address,uint256)"]) & {"flow.out", "flow.in", "supply.mint", "supply.burn"}


def test_callee_pointer_rotate_vault_hook():
    fns = _load(VAULT_HOOK)
    claim = _one(fns["setBeforeTransferHook(address)"], "callee_pointer.rotate")
    assert claim["tier"] == "idiom_structural"
    links = claim["witness"]["links"]
    assert any(link["pointer"] == "hook" and link["invoked_by"].startswith("transfer") for link in links)


@pytest.mark.parametrize(
    ("address", "signature"),
    [
        pytest.param(VAULT_HOOK, "approve(address,uint256)", id="counterexample-erc20-approve"),
        # An OZ-v5 namespaced pseudo-slot member, not a hygiene-normal scalar pointer.
        pytest.param(LZ_OAPP, "setLockBox(address)", id="near-miss-ozv5-pseudo-slot-setter"),
    ],
)
def test_callee_pointer_negatives(address, signature):
    fns = _load(address)
    assert "callee_pointer.rotate" not in _ids(fns[signature])


@pytest.mark.parametrize(
    ("signature", "expected_claim"),
    [
        pytest.param("approve(address,uint256)", "erc20.approve", id="erc20-approve"),
        pytest.param("transfer(address,uint256)", "erc20.transfer", id="erc20-transfer"),
        pytest.param("transferFrom(address,address,uint256)", "erc20.transfer_from", id="erc20-transfer-from"),
        pytest.param("deposit()", "weth.deposit", id="weth-deposit"),
        pytest.param("withdraw(uint256)", "weth.withdraw", id="weth-withdraw"),
    ],
)
def test_wrapped_native_user_plane_claims(signature, expected_claim):
    fns = _load(WRAPPED_NATIVE)
    assert expected_claim in _ids(fns[signature])


def test_gov_delegate_positive_writes_delegates_and_checkpoints():
    """The gate is facts-only, so it's pinned through ``build_claims``."""
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


def test_lz_oapp_config_claims():
    fns = _load(LZ_OAPP)
    assert _one(fns["setPeer(uint32,bytes32)"], "lz_oapp.set_peer")["tier"] == "standard_exact"
    assert _one(fns["setDelegate(address)"], "lz_oapp.set_delegate")["tier"] == "standard_exact"


# ---------------------------------------------------------------------------
# user-plane adversarial near-misses: each peripheral entry gets a
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
    ids = _claim_ids_over(
        {
            "deposit()": _fn_record("deposit()", "0xd0e30db0"),
            "withdraw(uint256)": _fn_record("withdraw(uint256)", "0x2e1a7d4d"),
        }
    )
    assert "weth.deposit" not in ids["deposit()"]
    assert "weth.withdraw" not in ids["withdraw(uint256)"]


def test_lz_oapp_near_miss_set_delegate_outside_the_oapp_gate():
    ids = _claim_ids_over({"setDelegate(address)": _fn_record("setDelegate(address)", "0xca5eb5e1")})
    assert "lz_oapp.set_delegate" not in ids["setDelegate(address)"]


def test_gov_delegate_near_miss_writes_only_delegates_map():
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
