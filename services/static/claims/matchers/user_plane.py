"""User-plane behavior claims: token-holder operations and OApp config.

These describe what an ordinary caller does (``erc20.*``, ``weth.*``,
``gov.delegate``) or a peer/delegate configuration (``lz_oapp.*``). They are
registered in their own consumer families so the value/user operations stay out
of the control lane while the LayerZero config claims read as control-plane.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts


def _erc20_op(ctx: ClaimContext, function: str, selector: str) -> ClaimEvidence | None:
    if not _facts.is_erc20(ctx) or ctx.selector(function) != selector:
        return None
    return ClaimEvidence(tier="standard_exact", witness={"kind": "erc20_selector", "selector": selector})


@claim_matcher(
    claim_id="erc20.approve",
    sentence="approves a token allowance (user operation)",
    legacy_projection=None,
    consumer_family="user_plane",
)
def erc20_approve(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _erc20_op(ctx, function, "0x095ea7b3")


@claim_matcher(
    claim_id="erc20.transfer",
    sentence="transfers tokens (user operation)",
    legacy_projection=None,
    consumer_family="user_plane",
)
def erc20_transfer(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _erc20_op(ctx, function, "0xa9059cbb")


@claim_matcher(
    claim_id="erc20.transfer_from",
    sentence="transfers tokens on behalf of another account (user operation)",
    legacy_projection=None,
    consumer_family="user_plane",
)
def erc20_transfer_from(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _erc20_op(ctx, function, "0x23b872dd")


def _weth_gate(ctx: ClaimContext) -> bool:
    return _facts.is_erc20(ctx) and ctx.has_signature("deposit()") and ctx.has_signature("withdraw(uint256)")


@claim_matcher(
    claim_id="weth.deposit",
    sentence="wraps ETH into the token (user deposit)",
    legacy_projection=None,
    consumer_family="user_plane",
)
def weth_deposit(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function != "deposit()" or not _weth_gate(ctx):
        return None
    return ClaimEvidence(tier="idiom_structural", witness={"kind": "weth", "op": "deposit"})


@claim_matcher(
    claim_id="weth.withdraw",
    sentence="unwraps ETH from the token (user withdrawal)",
    legacy_projection=None,
    consumer_family="user_plane",
)
def weth_withdraw(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function != "withdraw(uint256)" or not _weth_gate(ctx):
        return None
    return ClaimEvidence(tier="idiom_structural", witness={"kind": "weth", "op": "withdraw"})


@claim_matcher(
    claim_id="gov.delegate",
    sentence="delegates voting power (user operation)",
    legacy_projection=None,
    consumer_family="user_plane",
)
def gov_delegate(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    """Comp-style delegation: writing both the ``delegates`` map and the
    ``checkpoints`` map is the voting-power move (self-gating identity)."""
    written = {w["var"] for w in _facts.state_writes(ctx, function)}
    if "delegates" in written and "checkpoints" in written:
        return ClaimEvidence(
            tier="standard_exact", witness={"kind": "comp_votes", "writes": ["delegates", "checkpoints"]}
        )
    return None


def _lz_oapp_gate(ctx: ClaimContext) -> bool:
    return ctx.has_signature("setPeer(uint32,bytes32)") and (
        ctx.has_signature("peers(uint32)") or ctx.has_functions("endpoint")
    )


@claim_matcher(
    claim_id="lz_oapp.set_peer",
    sentence="sets the trusted remote peer (LayerZero OApp configuration)",
    legacy_projection=None,
    consumer_family="control_plane",
)
def lz_oapp_set_peer(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function != "setPeer(uint32,bytes32)" or not _lz_oapp_gate(ctx):
        return None
    return ClaimEvidence(tier="standard_exact", witness={"kind": "lz_oapp", "op": "set_peer"})


@claim_matcher(
    claim_id="lz_oapp.set_delegate",
    sentence="sets the LayerZero endpoint delegate",
    legacy_projection=None,
    consumer_family="control_plane",
)
def lz_oapp_set_delegate(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function != "setDelegate(address)" or not _lz_oapp_gate(ctx):
        return None
    return ClaimEvidence(tier="standard_exact", witness={"kind": "lz_oapp", "op": "set_delegate"})
