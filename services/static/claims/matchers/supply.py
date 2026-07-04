"""``supply.mint`` / ``supply.burn`` — the contract increases or decreases its
own token supply or share balances.

Evidence, most-exact first:

* own canonical ``mint``/``burn`` selector inside an ERC-20 / FiatToken gate
  (``standard_exact``);
* a callee ``mint``/``burn`` selector on a body external call (``standard_exact``);
* the supply-write-sign idiom — ERC-20 and a ``totalSupply`` write whose Binary
  IR operation is an increase/decrease (``idiom_structural``);
* the WETH wrap/unwrap idiom — inside the WETH gate, ``deposit`` mints and
  ``withdraw`` burns the wrapped supply (``idiom_structural``).
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts

_OWN_SELECTORS = {
    "mint": frozenset({"0x40c10f19"}),  # mint(address,uint256)
    "burn": frozenset({"0x42966c68", "0x9dc29fac", "0x79cc6790"}),  # burn(uint256)/burn(address,uint256)/burnFrom
}
_CALLEE_SELECTORS = _OWN_SELECTORS


def _token_gate(ctx: ClaimContext) -> bool:
    return _facts.is_erc20(ctx) or ctx.has_functions("configureMinter", "isMinter")


def _weth_gate(ctx: ClaimContext) -> bool:
    return _facts.is_erc20(ctx) and ctx.has_signature("deposit()") and ctx.has_signature("withdraw(uint256)")


def _supply_evidence(ctx: ClaimContext, function: str, kind: str) -> ClaimEvidence | None:
    selector = ctx.selector(function)
    if _token_gate(ctx) and selector in _OWN_SELECTORS[kind]:
        return ClaimEvidence(
            tier="standard_exact",
            witness={"kind": "own_selector", "selector": selector, "supply": kind},
        )

    callee_sink_ids = [
        s["id"]
        for s in _facts.body_sinks(ctx, function)
        if s.get("kind") == "external_call" and s.get("selector") in _CALLEE_SELECTORS[kind]
    ]
    if callee_sink_ids:
        return ClaimEvidence(
            tier="standard_exact",
            witness={"kind": "callee_selector", "sink_ids": sorted(set(callee_sink_ids)), "supply": kind},
        )

    if _facts.is_erc20(ctx):
        fn = _facts.contract_function(ctx, function)
        if fn is not None and _facts.total_supply_sign(fn) == kind:
            return ClaimEvidence(
                tier="idiom_structural",
                witness={"kind": "total_supply_sign", "supply": kind},
            )

    if _weth_gate(ctx):
        if kind == "mint" and function == "deposit()":
            return ClaimEvidence(tier="idiom_structural", witness={"kind": "weth_wrap", "supply": "mint"})
        if kind == "burn" and function == "withdraw(uint256)":
            return ClaimEvidence(tier="idiom_structural", witness={"kind": "weth_unwrap", "supply": "burn"})
    return None


@claim_matcher(
    claim_id="supply.mint",
    sentence="increases token supply or share balances",
    legacy_projection="mint",
    consumer_family="flow",
)
def supply_mint(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _supply_evidence(ctx, function, "mint")


@claim_matcher(
    claim_id="supply.burn",
    sentence="decreases token supply or share balances",
    legacy_projection="burn",
    consumer_family="flow",
)
def supply_burn(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _supply_evidence(ctx, function, "burn")
