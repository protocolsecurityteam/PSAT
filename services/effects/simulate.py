"""``eth_simulateV1`` transport seam for the value-out and supply recipes.

Multi-call context (read, mutate, read in one block) and value tracing need ``eth_simulateV1``, not ``eth_call``.
Defines the injectable ``Simulate`` seam and the single real implementation (:func:`eth_simulate_v1`, mirroring
``services.clients.rpc.eth_call_batch``); tests inject recorded :class:`SimResult`s. Support is probed per chain
(``services.effects.preflight``); unsupported chains route to the declared Tier-2 fallback.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak

# With ``traceTransfers``, raw ETH moves also emit a synthetic Transfer log.
TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()


@dataclass(frozen=True)
class SimCall:
    """One call in a simulated block; state carries forward to later calls."""

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
    """Per-call outcome with raw revert data."""

    success: bool
    return_data: str
    revert_data: str | None
    logs: tuple[SimLog, ...] = ()


@dataclass(frozen=True)
class SimResult:
    """A simulated block's results plus requested post-block storage (``{address: {slot: value}}``), used to re-read
    the impl slot after an upgrade. State-plane; never in a cache key.
    """

    calls: tuple[SimCallResult, ...]
    storage: dict[str, dict[str, str]] = field(default_factory=dict)


# One ordered block of calls at a pinned tag with optional state overrides.
StateOverride = dict[str, dict[str, Any]]
Simulate = Callable[[Sequence[SimCall], str, "StateOverride | None"], SimResult]


class SimulateUnsupportedError(RuntimeError):
    """The node lacks ``eth_simulateV1``; route to the Tier-2 fallback."""


def transfers_out(
    result: SimCallResult, source_address: str, *, only_asset: str | None = None
) -> list[tuple[str, str, str]]:
    """``(from, to, value_hex)`` for each Transfer out of ``source_address`` (raw logs; ETH via ``traceTransfers``).

    ``only_asset`` pins the emitter so an unrelated token moving in the same call doesn't count (the supply recipe
    measures one token). Unset counts any asset.
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
    """:func:`transfers_out` plus each move's asset (the log emitter).

    Reach needs the asset because balances are per asset (asset-blind matching over-claimed). Returns what actually
    moved in one pass. Native moves use ``config.NATIVE_ASSET_LOG_EMITTER``, matching how native holdings are keyed.
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
    """``(from, to, value_hex)`` for each Transfer into ``dest_address``; the mirror of :func:`transfers_out`.

    Used for mint backing. ``exclude_asset`` drops logs from the minted token, since a fee mint to the vault would
    otherwise look like an inflow. ``only_asset`` pins the burn witness to the token whose supply moved. Passing both
    yields nothing.
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
    body = topic[2:] if topic.startswith("0x") else topic
    return "0x" + body[-40:].lower()


# The single real-I/O implementation; never used by the offline suite.


def eth_simulate_v1(
    rpc_url: str,
    calls: Sequence[SimCall],
    block_tag: str = "latest",
    overrides: StateOverride | None = None,
    *,
    chain_id: int | None = None,
) -> SimResult:
    """Issue one ``eth_simulateV1`` block.

    ``traceTransfers`` on (ETH moves as logs), ``validation`` off (overrides skip nonce/balance checks). Raises
    :class:`SimulateUnsupportedError` when unsupported.
    """
    from services.clients.rpc import rpc_request

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
    """Map the response to a :class:`SimResult`; unexpected shapes give empty calls (the recipe withholds)."""
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
