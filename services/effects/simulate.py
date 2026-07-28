"""``eth_simulateV1`` transport seam for the value-out and supply recipes.

Tier 1 recipes that need *multi-call context* (read → mutate → read in one
simulated block) or *value tracing* (balance / ``Transfer`` diffs) cannot use
plain ``eth_call``, which returns neither carried state nor logs. This module
defines the injectable ``Simulate`` seam and its dataclasses, plus the single
real-I/O implementation (:func:`eth_simulate_v1`) mirroring
``utils.rpc.eth_call_batch`` — so recipes stay pure/testable against stubbed
wires exactly like ``differential_probe``. Tests never call the real
wrapper; they inject recorded :class:`SimResult`s.

Capability is *probed, never assumed*: ``eth_simulateV1`` support is
checked per chain (``services.effects.preflight``); where unsupported a recipe
declares its Tier-2 fallback explicitly, never a silent degradation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak

# topic0 of ERC-20/721 ``Transfer(address,address,uint256)``; ``eth_simulateV1``
# with ``traceTransfers`` also emits a synthetic Transfer log for raw ETH moves.
TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()


@dataclass(frozen=True)
class SimCall:
    """One call in a simulated block. ``from_addr`` varies ``msg.sender`` of the
    target (state carries forward to later calls in the same block)."""

    to: str
    data: str
    from_addr: str | None = None
    value: int = 0


@dataclass(frozen=True)
class SimLog:
    address: str
    topics: tuple[str, ...]
    data: str


@dataclass(frozen=True)
class SimCallResult:
    """Per-call outcome, preserving RAW revert data (never decoded here)."""

    success: bool
    return_data: str
    revert_data: str | None
    logs: tuple[SimLog, ...] = ()


@dataclass(frozen=True)
class SimResult:
    """A simulated block's per-call results plus any post-execution storage the
    recipe asked to read.

    ``storage`` is ``{address_lower: {slot_hex: value_hex}}`` of post-block
    values — the seam through which the code-upgrade recipe re-reads the
    impl slot after the sentinel call. The real wrapper obtains it via the fork
    the caller runs the simulation against; the value is state-plane residue and
    never enters a behavioral-hash cache key.
    """

    calls: tuple[SimCallResult, ...]
    storage: dict[str, dict[str, str]] = field(default_factory=dict)


# A Simulate issues an ordered list of calls as ONE simulated block at a pinned
# block tag, under optional per-account state overrides, and returns per-call
# results with carried state + logs. Injected so recipes are hermetic.
StateOverride = dict[str, dict[str, Any]]
Simulate = Callable[[Sequence[SimCall], str, "StateOverride | None"], SimResult]


class SimulateUnsupportedError(RuntimeError):
    """The upstream node does not implement ``eth_simulateV1``. Routes
    the class to its declared Tier-2 fallback, never a silent degrade."""


def transfers_out(
    result: SimCallResult, source_address: str, *, only_asset: str | None = None
) -> list[tuple[str, str, str]]:
    """``(from, to, value_hex)`` for every ``Transfer`` log whose sender is
    ``source_address`` — i.e. value LEAVING that contract. Raw-log level only;
    no name/semantic inference. ETH moves surface here too via ``traceTransfers``.

    ``only_asset`` restricts the match to logs EMITTED BY that token
    (``SimLog.address``). A ``Transfer`` topic says nothing about which contract
    emitted it, so a caller asking "did *this specific* asset move" must pin the
    emitter: the supply recipe measures ``totalSupply`` on ONE token, and an
    unrelated token minting inside the same call would otherwise satisfy its
    mint/sentinel witness. Unset (the value-out use) means any asset leaving
    the contract counts, which is the intended reading there.
    """
    src = source_address.lower()
    asset = only_asset.lower() if only_asset else None
    out: list[tuple[str, str, str]] = []
    for log in result.logs:
        if not log.topics or log.topics[0].lower() != TRANSFER_TOPIC.lower():
            continue
        if len(log.topics) < 3:
            continue
        if asset is not None and log.address.lower() != asset:
            continue
        frm = _topic_addr(log.topics[1])
        to = _topic_addr(log.topics[2])
        if frm == src:
            out.append((frm, to, log.data))
    return out


def transfers_out_with_asset(result: SimCallResult, source_address: str) -> list[tuple[str, str, str, str]]:
    """:func:`transfers_out` plus the ASSET each move was in — the log's EMITTER.

    The downstream value-reach measurement needs the asset, not just the fact of a
    move: a holder's balance sheet is per asset, and attributing the whole sheet to
    whichever asset happened to move over-claims (a synthetic native-ETH move matched
    a holder whose USD was 99.99% eETH). ``transfers_out(only_asset=…)`` pins ONE
    asset per call, so a caller with N holdings would need N scans and still could not
    see an asset it holds no row for; this returns what actually moved, once.

    Native moves surface here with the emitter ``eth_simulateV1``'s
    ``traceTransfers`` uses for them (``config.NATIVE_ASSET_LOG_EMITTER``, measured
    against the live node) — the same pseudo-address a native holding is keyed on, so
    the two match without special-casing at the call site.
    """
    src = source_address.lower()
    out: list[tuple[str, str, str, str]] = []
    for log in result.logs:
        if not log.topics or log.topics[0].lower() != TRANSFER_TOPIC.lower():
            continue
        if len(log.topics) < 3:
            continue
        frm = _topic_addr(log.topics[1])
        to = _topic_addr(log.topics[2])
        if frm == src:
            out.append((frm, to, log.data, log.address.lower()))
    return out


def transfers_in(
    result: SimCallResult, dest_address: str, *, exclude_asset: str | None = None, only_asset: str | None = None
) -> list[tuple[str, str, str]]:
    """``(from, to, value_hex)`` for every ``Transfer`` log whose recipient is
    ``dest_address`` — i.e. value ARRIVING at that contract. The mirror of
    :func:`transfers_out`: raw-log level only, no name/semantic inference, ETH moves
    surface here too via ``traceTransfers``.

    Used by the supply recipe's mint-backing check: an asset transfer INTO the vault during a
    mint call is the co-occurring inflow that distinguishes a deposit-backed
    conversion from an unbacked (dilutive) admin mint. No new I/O — the logs are the
    ones the mint call already emitted.

    ``exclude_asset`` drops logs EMITTED BY that token, and the backing check passes
    the minted token itself. Without it ``_mint(address(this), fee)`` — a mint of the
    vault's OWN token to the vault — emits ``Transfer(0x0 -> vault)`` from the vault's
    own token contract and reads as an asset inflow, so pure dilution produces the
    byte-identical ``inflow_observed: true`` a genuine deposit-backed conversion
    does. Backing means an inflow of some OTHER asset; newly-printed units of the
    token whose supply just rose back nothing.

    ``only_asset`` is the opposite pin, and the burn witness needs it: units
    destroyed are a ``Transfer`` to the zero address emitted BY the token whose
    ``totalSupply`` moved, and some OTHER token burning inside the same call says
    nothing about this one's supply. Passing both is contradictory and yields
    nothing, which is the honest answer to a contradictory question.
    """
    dst = dest_address.lower()
    excluded = exclude_asset.lower() if exclude_asset else None
    included = only_asset.lower() if only_asset else None
    out: list[tuple[str, str, str]] = []
    for log in result.logs:
        if not log.topics or log.topics[0].lower() != TRANSFER_TOPIC.lower():
            continue
        if len(log.topics) < 3:
            continue
        if excluded is not None and log.address.lower() == excluded:
            continue
        if included is not None and log.address.lower() != included:
            continue
        frm = _topic_addr(log.topics[1])
        to = _topic_addr(log.topics[2])
        if to == dst:
            out.append((frm, to, log.data))
    return out


def _topic_addr(topic: str) -> str:
    """Last 20 bytes of a 32-byte indexed topic, lowercased 0x address."""
    body = topic[2:] if topic.startswith("0x") else topic
    return "0x" + body[-40:].lower()


# ---------------------------------------------------------------------------
# The single real-I/O implementation. Never invoked by the offline suite.
# ---------------------------------------------------------------------------


def eth_simulate_v1(
    rpc_url: str,
    calls: Sequence[SimCall],
    block_tag: str = "latest",
    overrides: StateOverride | None = None,
    *,
    chain_id: int | None = None,
) -> SimResult:
    """Issue one ``eth_simulateV1`` block against ``rpc_url`` (the production
    seam impl; wire it as the injected ``Simulate`` in the worker).

    ``traceTransfers`` is requested so ETH moves surface as synthetic Transfer
    logs alongside ERC-20 ones; ``validation`` stays off (state-override probes
    routinely skip nonce/balance checks). Raises :class:`SimulateUnsupportedError`
    when the node rejects the method so the caller routes to Tier 2."""
    from utils.rpc import rpc_request

    block_state_call: dict[str, Any] = {
        "calls": [_encode_call(c) for c in calls],
    }
    if overrides:
        block_state_call["stateOverrides"] = overrides
    params: list[Any] = [
        {
            "blockStateCalls": [block_state_call],
            "traceTransfers": True,
            "validation": False,
            "returnFullTransactions": False,
        },
        block_tag,
    ]
    try:
        raw = rpc_request(rpc_url, "eth_simulateV1", params, chain_id=chain_id)
    except RuntimeError as exc:
        msg = str(exc).lower()
        if "method not found" in msg or "not supported" in msg or "unsupported" in msg:
            raise SimulateUnsupportedError(str(exc)) from exc
        raise
    return _parse_sim_result(raw)


def _encode_call(c: SimCall) -> dict[str, str]:
    call: dict[str, str] = {"to": c.to, "data": c.data}
    if c.from_addr is not None:
        call["from"] = c.from_addr
    if c.value:
        call["value"] = hex(c.value)
    return call


def _parse_sim_result(raw: Any) -> SimResult:
    """Map the ``eth_simulateV1`` response (a list of blocks) to a
    :class:`SimResult`. Defensive against provider shape drift — an unexpected
    payload yields empty calls (the recipe then withholds, never fabricates)."""
    blocks = raw if isinstance(raw, list) else []
    call_results: list[SimCallResult] = []
    if blocks and isinstance(blocks[0], Mapping):
        for item in blocks[0].get("calls", []) or []:
            call_results.append(_parse_call(item))
    return SimResult(calls=tuple(call_results))


def _parse_call(item: Mapping[str, Any]) -> SimCallResult:
    status = item.get("status")
    success = status in (1, "0x1", "0x01", True)
    error = item.get("error")
    revert_data: str | None = None
    if error and isinstance(error, Mapping):
        data = error.get("data")
        if isinstance(data, str) and data.startswith("0x"):
            revert_data = data.lower()
    logs = tuple(_parse_log(le) for le in item.get("logs", []) or [] if isinstance(le, Mapping))
    ret = item.get("returnData")
    return SimCallResult(
        success=bool(success),
        return_data=ret if isinstance(ret, str) else "0x",
        revert_data=revert_data,
        logs=logs,
    )


def _parse_log(item: Mapping[str, Any]) -> SimLog:
    topics = tuple(str(t) for t in item.get("topics", []) or [])
    return SimLog(
        address=str(item.get("address", "")).lower(),
        topics=topics,
        data=str(item.get("data", "0x")),
    )
