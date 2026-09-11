"""User-plane behavior claims: token-holder operations and OApp config.

These describe what an ordinary caller does (``erc20.*``, ``weth.*``,
``gov.delegate``) or a peer/delegate configuration (``lz_oapp.*``). They are
registered in their own consumer families so the value/user operations stay out
of the control lane while the LayerZero config claims read as control-plane.
"""

from __future__ import annotations

from ..context import ClaimContext, abi_selector, abi_topic0
from ..decorator import claim_matcher
from ..types import MatchedEvidence
from . import _facts

# LayerZero OApp published configuration ABI.
_SET_PEER = abi_selector("setPeer(uint32,bytes32)")
_PEERS = abi_selector("peers(uint32)")
_ENDPOINT = abi_selector("endpoint()")
_SET_DELEGATE = abi_selector("setDelegate(address)")
_DEPOSIT = abi_selector("deposit()")
_WITHDRAW = abi_selector("withdraw(uint256)")


def _erc20_op(ctx: ClaimContext, function: str, selector: str) -> MatchedEvidence | None:
    if not _facts.is_erc20(ctx) or ctx.canonical_selector(function) != selector:
        return None
    return MatchedEvidence(tier="standard_exact", witness={"kind": "erc20_selector", "selector": selector})


@claim_matcher(
    claim_id="erc20.approve",
    sentence="approves a token allowance (user operation)",
    consumer_family="user_plane",
)
def erc20_approve(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    return _erc20_op(ctx, function, "0x095ea7b3")


@claim_matcher(
    claim_id="erc20.transfer",
    sentence="transfers tokens (user operation)",
    consumer_family="user_plane",
)
def erc20_transfer(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    return _erc20_op(ctx, function, "0xa9059cbb")


@claim_matcher(
    claim_id="erc20.transfer_from",
    sentence="transfers tokens on behalf of another account (user operation)",
    consumer_family="user_plane",
)
def erc20_transfer_from(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    return _erc20_op(ctx, function, "0x23b872dd")


def _weth_gate(ctx: ClaimContext) -> bool:
    return _facts.is_erc20(ctx) and ctx.has_selectors(_DEPOSIT, _WITHDRAW)


@claim_matcher(
    claim_id="weth.deposit",
    sentence="wraps ETH into the token (user deposit)",
    consumer_family="user_plane",
)
def weth_deposit(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    if ctx.canonical_selector(function) != _DEPOSIT or not _weth_gate(ctx):
        return None
    return MatchedEvidence(tier="idiom_structural", witness={"kind": "weth", "op": "deposit"})


@claim_matcher(
    claim_id="weth.withdraw",
    sentence="unwraps ETH from the token (user withdrawal)",
    consumer_family="user_plane",
)
def weth_withdraw(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    if ctx.canonical_selector(function) != _WITHDRAW or not _weth_gate(ctx):
        return None
    return MatchedEvidence(tier="idiom_structural", witness={"kind": "weth", "op": "withdraw"})


# The Compound/OZ Votes delegation log. Its argument list is fixed by the
# standard, so topic0 is what a delegation provably writes to the chain.
DELEGATE_CHANGED_TOPIC0 = abi_topic0("DelegateChanged(address,address,address)")


@claim_matcher(
    claim_id="gov.delegate",
    sentence="delegates voting power (user operation)",
    consumer_family="user_plane",
)
def gov_delegate(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    """Comp/OZ-Votes delegation.

    ``standard_exact`` when the call emits ``DelegateChanged`` — the published
    governance log, matched on topic0, so the proof is the record the chain
    keeps. The older state-write shape (``delegates`` + ``checkpoints``) is kept
    as a fallback, but only at ``idiom_structural``: those are variable names, and
    a name cannot prove a standard.
    """
    fn = _facts.contract_function(ctx, function)
    if fn is not None and _facts.emits_event_topic(ctx, fn, DELEGATE_CHANGED_TOPIC0):
        return MatchedEvidence(
            tier="standard_exact",
            witness={"kind": "delegate_changed_log", "topic0": DELEGATE_CHANGED_TOPIC0},
        )
    written = {w["var"] for w in _facts.state_writes(ctx, function)}
    if "delegates" in written and "checkpoints" in written:
        return MatchedEvidence(
            tier="idiom_structural", witness={"kind": "comp_votes_writes", "writes": ["delegates", "checkpoints"]}
        )
    return None


def _lz_oapp_gate(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(_SET_PEER) and (ctx.has_selectors(_PEERS) or ctx.has_selectors(_ENDPOINT))


@claim_matcher(
    claim_id="lz_oapp.set_peer",
    sentence="sets the trusted remote peer (LayerZero OApp configuration)",
    consumer_family="control_plane",
)
def lz_oapp_set_peer(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    if ctx.canonical_selector(function) != _SET_PEER or not _lz_oapp_gate(ctx):
        return None
    return MatchedEvidence(tier="standard_exact", witness={"kind": "lz_oapp", "op": "set_peer"})


@claim_matcher(
    claim_id="lz_oapp.set_delegate",
    sentence="sets the LayerZero endpoint delegate",
    consumer_family="control_plane",
)
def lz_oapp_set_delegate(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    if ctx.canonical_selector(function) != _SET_DELEGATE or not _lz_oapp_gate(ctx):
        return None
    return MatchedEvidence(tier="standard_exact", witness={"kind": "lz_oapp", "op": "set_delegate"})
