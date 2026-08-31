"""``supply.mint`` / ``supply.burn`` — the contract increases or decreases its
own token supply or share balances.

Evidence, most-exact first:

* own canonical ``mint``/``burn`` selector inside an ERC-20 / FiatToken gate
  (``standard_exact``);
* a callee ``mint``/``burn`` selector on a body external call (``standard_exact``);
* the supply-write-sign idiom — ERC-20 and a Binary-IR increase/decrease of the
  variable the contract publishes as ``totalSupply()`` (``idiom_structural``);
* the mint/burn Transfer idiom — ERC-20 and a zero-address-endpoint
  ``Transfer(address,address,uint256)`` corroborated by a matching-direction
  monotone state-var write, so a rebasing token that publishes no supply variable
  is still recognized (``idiom_structural``);
* the WETH wrap/unwrap idiom — inside the WETH gate, ``deposit`` mints and
  ``withdraw`` burns, corroborated by an observed one-directional balance write
  (WETH9 keeps no supply variable and emits no ``Transfer`` on wrap, so this is
  the only path that sees it) (``idiom_structural``).
"""

from __future__ import annotations

from ..context import ClaimContext, abi_selector, selectors_of
from ..decorator import claim_matcher
from ..types import MatchedEvidence
from . import _facts

_OWN_SELECTORS = {
    "mint": selectors_of("mint(address,uint256)"),
    "burn": selectors_of("burn(uint256)", "burn(address,uint256)", "burnFrom(address,uint256)"),
}
_CALLEE_SELECTORS = _OWN_SELECTORS

# Circle FiatToken's published minter ABI — the non-ERC-20 half of the token gate.
_FIAT_TOKEN_SELECTORS = selectors_of("configureMinter(address,uint256)", "isMinter(address)")
_DEPOSIT = abi_selector("deposit()")
_WITHDRAW = abi_selector("withdraw(uint256)")


def _token_gate(ctx: ClaimContext) -> bool:
    return _facts.is_erc20(ctx) or ctx.has_selectors(*_FIAT_TOKEN_SELECTORS)


def _weth_gate(ctx: ClaimContext) -> bool:
    return _facts.is_erc20(ctx) and ctx.has_selectors(_DEPOSIT, _WITHDRAW)


def _supply_evidence(ctx: ClaimContext, function: str, kind: str) -> MatchedEvidence | None:
    selector = ctx.canonical_selector(function)
    if _token_gate(ctx) and selector in _OWN_SELECTORS[kind]:
        return MatchedEvidence(
            tier="standard_exact",
            witness={"kind": "own_selector", "selector": selector, "supply": kind},
        )

    callee_sink_ids = [
        s["id"]
        for s in _facts.body_sinks(ctx, function)
        if s.get("kind") == "external_call" and s.get("selector") in _CALLEE_SELECTORS[kind]
    ]
    if callee_sink_ids:
        return MatchedEvidence(
            tier="standard_exact",
            witness={"kind": "callee_selector", "sink_ids": sorted(set(callee_sink_ids)), "supply": kind},
        )

    fn = _facts.contract_function(ctx, function) if _facts.is_erc20(ctx) else None
    if fn is not None:
        if _facts.total_supply_sign(fn, _facts.total_supply_vars(ctx)) == kind:
            return MatchedEvidence(
                tier="idiom_structural",
                witness={"kind": "total_supply_sign", "supply": kind},
            )
        if _facts.mint_burn_transfer_sign(fn) == kind:
            return MatchedEvidence(
                tier="idiom_structural",
                witness={"kind": "mint_burn_transfer", "supply": kind},
            )
        # The wrap/unwrap arm asserts a supply move, so it must observe one: the
        # gate alone says the contract is wrapped native, not that this call
        # created or destroyed anything.
        if _weth_gate(ctx) and _facts.monotone_balance_delta(fn) == kind:
            if kind == "mint" and selector == _DEPOSIT:
                return MatchedEvidence(tier="idiom_structural", witness={"kind": "weth_wrap", "supply": "mint"})
            if kind == "burn" and selector == _WITHDRAW:
                return MatchedEvidence(tier="idiom_structural", witness={"kind": "weth_unwrap", "supply": "burn"})
    return None


@claim_matcher(
    claim_id="supply.mint",
    sentence="increases token supply or share balances",
    consumer_family="flow",
)
def supply_mint(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    return _supply_evidence(ctx, function, "mint")


@claim_matcher(
    claim_id="supply.burn",
    sentence="decreases token supply or share balances",
    consumer_family="flow",
)
def supply_burn(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    return _supply_evidence(ctx, function, "burn")
