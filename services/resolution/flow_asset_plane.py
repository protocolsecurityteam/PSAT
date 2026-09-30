"""Plane 2: the address a flow-sink receiver holds, and the height it held it at.

The static effects plane publishes the receiver's structure and, where solc minted one, its accessor selector
(``sinks[].receiver.auto_getter_selector``), but no address (it has no proxy knowledge). This dereferences that selector
at the runtime address and publishes ``asset_address``, ``observed_at_block`` (constructed together in
:class:`AssetObservation`) and ``asset_identity_invariant``.

The invariant has no closed value: behind a proxy even an ``immutable`` lives in replaceable implementation bytecode, so
the best is ``redirectable_by_upgrade_authority``, else ``not_determined``.

Safeguards:

* Only compiler-minted accessors of ``public`` state variables are called. The corpus has an ERC-7201 local whose
``getTokenOut()`` answers while ``tokenOut()`` reverts; its binding is ``local``, so it stays unresolved.
* ``decode_address_word`` requires exactly 64 nibbles and a zero high 12 bytes, with a post-``fromhex`` length check
(``fromhex`` ignores whitespace).
* A failed call yields no ``asset_address`` and no ``observed_at_block``. No fallback reads, no ``"latest"``.

The zero address is a third state, ``observed_zero_address``, with its block and without ``asset_address``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from services.clients.rpc import EthCallResult, eth_call_batch
from services.monitoring.restaking_reads import ZERO_ADDRESS, decode_address_word
from services.resolution.role_holder_plane import ProbeBlock

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "flow-asset-1"

# Only this binding's auto-getter is licensed; ``local`` has the ``getTokenOut()`` trap and ``parameter`` receivers have
# no accessor.
LICENSED_BINDING = "state_variable"
LICENSED_VISIBILITY = "public"

# ``asset_address_status``: three states.
STATUS_RESOLVED = "resolved"
STATUS_OBSERVED_ZERO = "observed_zero_address"
STATUS_NOT_DETERMINED = "not_determined"

# ``asset_identity_invariant``; deliberately no closed member.
INVARIANT_REDIRECTABLE = "redirectable_by_upgrade_authority"
INVARIANT_NOT_DETERMINED = "not_determined"

# Revert and transport failure are one reason: error text can't reliably tell them apart, and neither is a witness.
REASON_CALL_DID_NOT_ANSWER = "call_did_not_answer"
REASON_MALFORMED_RETURN_WORD = "malformed_return_word"

_SELECTOR_HEX_LEN = 10  # "0x" + 8 nibbles


@dataclass(frozen=True)
class AssetReceiver:
    """One state-variable receiver, folded across its sinks.

    Keyed on ``auto_getter_selector``, a compiler-minted binding. ``variables`` is for display and source joins only:
    same-named declarations on different contracts would otherwise merge.
    """

    auto_getter_selector: str
    variables: tuple[str, ...]
    declared_mutability: str | None
    sink_ids: tuple[str, ...]


@dataclass(frozen=True)
class AssetObservation:
    """An address and the height it was read at, validated together so they can't be separated."""

    address: str
    block_number: int
    block_hash: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.address, str) or len(self.address) != 42 or not self.address.startswith("0x"):
            raise ValueError(f"not a canonical address: {self.address!r}")
        if not isinstance(self.block_number, int) or isinstance(self.block_number, bool) or self.block_number <= 0:
            raise ValueError(f"not a usable observation height: {self.block_number!r}")

    @property
    def is_zero(self) -> bool:
        return self.address == ZERO_ADDRESS


def _normalize_selector(value: Any) -> str | None:
    """A 4-byte selector as lowercase ``0x`` hex, or ``None``.

    Length-checked, since a wrong-length string still addresses some function.
    """
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if len(text) != _SELECTOR_HEX_LEN or not text.startswith("0x"):
        return None
    if set(text[2:]) - set("0123456789abcdef"):
        return None
    return text


def collect_asset_receivers(effects: Mapping[str, Any]) -> list[AssetReceiver]:
    """Every licensed state-variable receiver in a static ``effects`` artifact.

    Sinks with no receiver, a non-``state_variable`` binding, or no ``auto_getter_selector`` yield nothing.
    ``visibility`` is re-checked. Folded by selector (one read per asset) and sorted for byte-stable output.
    """
    folded: dict[str, dict[str, Any]] = {}
    functions = effects.get("functions") if isinstance(effects, Mapping) else None
    records: Iterable[Any]
    if isinstance(functions, Mapping):
        records = functions.values()
    elif isinstance(functions, list):
        records = functions
    else:
        return []

    for record in records:
        if not isinstance(record, Mapping):
            continue
        sinks = record.get("sinks")
        if not isinstance(sinks, list):
            continue
        for sink in sinks:
            if not isinstance(sink, Mapping):
                continue
            receiver = sink.get("receiver")
            if not isinstance(receiver, Mapping):
                continue
            if receiver.get("binding") != LICENSED_BINDING:
                continue
            raw_selector = receiver.get("auto_getter_selector")
            if raw_selector is None:
                continue
            selector_hex = _normalize_selector(raw_selector)
            if selector_hex is None:
                # A producer defect: no row, but logged.
                logger.warning(
                    "flow asset plane: refusing a malformed auto_getter_selector",
                    extra={"auto_getter_selector": repr(raw_selector)},
                )
                continue
            if receiver.get("visibility") != LICENSED_VISIBILITY:
                logger.warning(
                    "flow asset plane: refusing a minted selector on a non-public declaration",
                    extra={"auto_getter_selector": selector_hex, "visibility": repr(receiver.get("visibility"))},
                )
                continue
            entry = folded.setdefault(
                selector_hex,
                {"variables": set(), "mutabilities": set(), "sink_ids": set()},
            )
            variable = receiver.get("variable")
            if isinstance(variable, str) and variable:
                entry["variables"].add(variable)
            mutability = receiver.get("mutability")
            if isinstance(mutability, str) and mutability:
                entry["mutabilities"].add(mutability)
            sink_id = sink.get("id")
            if isinstance(sink_id, str) and sink_id:
                entry["sink_ids"].add(sink_id)

    receivers: list[AssetReceiver] = []
    for selector_hex, entry in sorted(folded.items()):
        mutabilities = entry["mutabilities"]
        receivers.append(
            AssetReceiver(
                auto_getter_selector=selector_hex,
                variables=tuple(sorted(entry["variables"])),
                # Two answers mean two declarations; publish neither.
                declared_mutability=next(iter(mutabilities)) if len(mutabilities) == 1 else None,
                sink_ids=tuple(sorted(entry["sink_ids"])),
            )
        )
    return receivers


def observe_asset_address(result: EthCallResult, probe_block: ProbeBlock) -> tuple[AssetObservation | None, str | None]:
    """One accessor read as ``(observation, not_determined_reason)``, exactly one None.

    ``success`` isn't sufficient: ``eth_call_batch`` reports unreadable results as ``(True, "0x")``, and decoding that
    mints 0x0.
    """
    if not result.success:
        return None, REASON_CALL_DID_NOT_ANSWER
    address = decode_address_word(result.return_data)
    if address is None:
        return None, REASON_MALFORMED_RETURN_WORD
    return (
        AssetObservation(
            address=address,
            block_number=probe_block.number,
            block_hash=probe_block.block_hash.hex() if probe_block.block_hash else None,
        ),
        None,
    )


def _row(
    receiver: AssetReceiver,
    observation: AssetObservation | None,
    reason: str | None,
    *,
    proven_proxied: bool,
) -> dict[str, Any]:
    """One published row.

    * ``asset_address`` iff status is ``resolved``.
    * ``observed_at_block`` iff a read completed (``resolved`` or ``observed_zero_address``), from the same object as
    the address.
    * ``asset_identity_invariant`` only with a published address.
    * ``not_determined_reason`` only on the not-determined arm.
    """
    row: dict[str, Any] = {
        "asset_getter_selector": receiver.auto_getter_selector,
        "sink_ids": list(receiver.sink_ids),
        # Display only; never a resolution basis.
        "receiver_variables": list(receiver.variables),
        "declared_mutability": receiver.declared_mutability,
    }
    if observation is None:
        row["asset_address_status"] = STATUS_NOT_DETERMINED
        row["not_determined_reason"] = reason or REASON_CALL_DID_NOT_ANSWER
        return row

    row["observed_at_block"] = observation.block_number
    if observation.block_hash is not None:
        row["observed_block_hash"] = observation.block_hash
    if observation.is_zero:
        # A completed zero read: not an asset, not a failure, and kept so it's distinguishable from unread.
        row["asset_address_status"] = STATUS_OBSERVED_ZERO
        return row

    row["asset_address_status"] = STATUS_RESOLVED
    row["asset_address"] = observation.address
    row["asset_identity_invariant"] = INVARIANT_REDIRECTABLE if proven_proxied else INVARIANT_NOT_DETERMINED
    return row


def resolve_flow_asset_addresses(
    receivers: Sequence[AssetReceiver],
    *,
    rpc_url: str,
    chain_id: int,
    deployment_address: str,
    proven_proxied: bool,
    probe_block: ProbeBlock,
) -> dict[str, Any]:
    """Dereference every licensed receiver at one pinned height.

    ``deployment_address`` is the runtime (proxy) address; reading the implementation gives a constant nobody prices.
    ``proven_proxied`` must be earned and is the only licence for ``redirectable_by_upgrade_authority``. Every call uses
    ``probe_block``; there is no ``"latest"`` path.
    """
    calls = [{"to": deployment_address, "data": receiver.auto_getter_selector} for receiver in receivers]
    results = eth_call_batch(rpc_url, calls, hex(probe_block.number), chain_id=chain_id) if calls else []

    rows: list[dict[str, Any]] = []
    for receiver, result in zip(receivers, results):
        observation, reason = observe_asset_address(result, probe_block)
        rows.append(_row(receiver, observation, reason, proven_proxied=proven_proxied))

    return {
        "schema_version": SCHEMA_VERSION,
        # Rows are keyed (chain_id, deployment_address, asset_getter_selector).
        "chain_id": chain_id,
        "deployment_address": deployment_address,
        "deployment_proven_proxied": proven_proxied,
        "probe_block": probe_block.number,
        "probe_block_hash": probe_block.block_hash.hex() if probe_block.block_hash else None,
        "receivers": rows,
    }


def count_resolved(payload: Mapping[str, Any]) -> int:
    """Rows with a priceable address; zero-address rows name no asset."""
    receivers = payload.get("receivers")
    if not isinstance(receivers, list):
        return 0
    return sum(
        1 for row in receivers if isinstance(row, Mapping) and row.get("asset_address_status") == STATUS_RESOLVED
    )
