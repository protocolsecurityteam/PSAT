"""Plane 2 — the ADDRESS a flow-sink receiver holds, and the height it held it at.

The static effects plane publishes a receiver's structural identity and, where
solc itself minted one, the selector of the accessor that reads it
(``sinks[].receiver.auto_getter_selector``). It resolves no address, on purpose:
it has no proxy knowledge, so it cannot know which deployment to read. The
consequence was that ``receiver_provenance: contract_state_unresolved`` named no
address at all and no flow asset was ever priceable.

This module closes that by DEREFERENCING the minted selector at the runtime
address, and it publishes only what a completed read proves:

* ``asset_address`` — the 20 bytes a full 32-byte return word held;
* ``observed_at_block`` — the height that word came from. It is emitted from the
  same object as the address (:class:`AssetObservation`), so an address without
  its block cannot be constructed, let alone published;
* ``asset_identity_invariant`` — how much that address may be trusted to STAY
  the asset.

**The invariant enum has no closed value.** Every deployment in scope here is
reached through a proxy, and behind a proxy an ``immutable`` is not an invariant
of the address a consumer prices against: it is inlined into the IMPLEMENTATION's
bytecode, and the upgrade authority can point the proxy at an implementation with
a different constant. So the strongest publishable value is
``redirectable_by_upgrade_authority``, and the only alternative is
``not_determined`` — never ``immutable``, never ``true``.

Three ways this could quietly become a lie, and what stops each:

* **A same-named hand-written getter.** Only the COMPILER-MINTED accessor, minted
  from the DECLARED TYPE of a ``public`` state variable, may be called. The
  corpus carries the exact counter-example: an ERC-7201 local whose
  ``getTokenOut()`` answers ``0xcd5fe23c…`` while ``tokenOut()`` REVERTS (both
  verified at 25643300). That receiver's binding is ``local``, it carries no
  ``auto_getter_selector``, and this module refuses every binding but
  ``state_variable`` — so it stays unresolved rather than borrowing an answer
  from a function that is not its accessor.
* **A short or malformed return decoded anyway.** ``decode_address_word`` is
  reused rather than re-derived: it requires exactly 64 nibbles and all-zero
  high-order 12 bytes, and it goes through ``bytes.fromhex`` with an explicit
  post-conversion length check because ``bytes.fromhex`` silently ignores ASCII
  whitespace (a 62-nibble body plus two spaces passes a naive length test).
* **A revert resolving to something.** A failed call yields NO ``asset_address``
  key and NO ``observed_at_block`` key — absent, not null and not the zero
  address. Nothing here has a fallback read, and nothing here reads ``"latest"``.

The zero address is kept as its own third state. It is a real answer — the read
completed and the word was well formed — but it is not an asset and must never
reach a pricer, so it is published as ``observed_zero_address`` WITH its block
and WITHOUT an ``asset_address`` key.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from services.monitoring.restaking_reads import ZERO_ADDRESS, decode_address_word
from services.resolution.role_holder_plane import ProbeBlock
from utils.rpc import EthCallResult, eth_call_batch

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "flow-asset-1"

# The only receiver binding whose auto-getter is licensed. ``local`` is where
# the ``getTokenOut()`` trap lives; ``parameter`` receivers are caller-named and
# have no accessor at all.
LICENSED_BINDING = "state_variable"
LICENSED_VISIBILITY = "public"

# ``asset_address_status`` — three states that never collapse into two.
STATUS_RESOLVED = "resolved"
STATUS_OBSERVED_ZERO = "observed_zero_address"
STATUS_NOT_DETERMINED = "not_determined"

# ``asset_identity_invariant``. There is deliberately no third, closed member:
# see the module docstring.
INVARIANT_REDIRECTABLE = "redirectable_by_upgrade_authority"
INVARIANT_NOT_DETERMINED = "not_determined"

# ``not_determined_reason``. Revert and transport failure are ONE reason on
# purpose: a node's error text is not a reliable discriminator between them
# (a bare "execution reverted" arrives with no ``error.data``, exactly as a
# provider-side failure does), and neither is a witness, so splitting them
# would publish a distinction the evidence does not support.
REASON_CALL_DID_NOT_ANSWER = "call_did_not_answer"
REASON_MALFORMED_RETURN_WORD = "malformed_return_word"

_SELECTOR_HEX_LEN = 10  # "0x" + 8 nibbles


@dataclass(frozen=True)
class AssetReceiver:
    """One state-variable receiver, folded across every sink that names it.

    Identity is ``auto_getter_selector`` — a compiler-minted 1:1 binding to the
    declaration, which solc refuses to let a hand-written function collide with.
    ``variables`` is carried for display and for joining back to source ONLY;
    ``variable + "()"`` is the banned shape this plane exists to replace, and two
    same-named declarations on different contracts produce byte-identical
    descriptors, so a name would fold two distinct assets into one row.
    """

    auto_getter_selector: str
    variables: tuple[str, ...]
    declared_mutability: str | None
    sink_ids: tuple[str, ...]


@dataclass(frozen=True)
class AssetObservation:
    """An address AND the height it was read at, as one indivisible object.

    ``asset_address`` and ``observed_at_block`` are never separable — a resolved
    address whose block is unknown is a now-fact with no citation, which may not
    be published. Making them one constructor argument list, validated here, is
    what makes the separated form unrepresentable rather than merely discouraged.
    """

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
    """A 4-byte selector as lower-case ``0x``-hex, or ``None``.

    Explicitly length-checked rather than parsed: an over-long or truncated
    string would still address SOME function, and calling four bytes nobody
    minted is how a fabricated positive gets on chain.
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

    A sink whose ``receiver`` key is ABSENT, whose binding is not
    ``state_variable``, or whose ``auto_getter_selector`` is ``None`` yields no
    row and is left exactly as it was: absent means "never computed", which
    fails every downstream precondition already. ``visibility`` is re-checked
    even though the producer only mints a selector for a ``public`` declaration —
    a selector on a non-public row would be an incoherent descriptor, and this
    plane refuses to place a call on the strength of one.

    Rows are folded by selector, so the N sinks that all move the same asset cost
    one read and carry one answer, and the returned list is sorted so the
    published payload is byte-stable across runs.
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
                # A producer-side defect, not a chain fact. It cannot be keyed
                # (the selector IS the key) so it mints no row, but it is never
                # swallowed silently.
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
                # One declaration cannot be two classes at once; two answers
                # mean the fold saw two declarations, so neither is published.
                declared_mutability=next(iter(mutabilities)) if len(mutabilities) == 1 else None,
                sink_ids=tuple(sorted(entry["sink_ids"])),
            )
        )
    return receivers


def observe_asset_address(result: EthCallResult, probe_block: ProbeBlock) -> tuple[AssetObservation | None, str | None]:
    """One accessor read, as ``(observation, not_determined_reason)``.

    Exactly one of the two is ``None``. ``success`` is necessary and not
    sufficient: ``eth_call_batch`` reports a node result it cannot read as
    ``EthCallResult(True, "0x", …)``, and an empty return carries no address —
    decoding it anyway is how ``0x0`` gets minted out of nothing.
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
    """One published receiver row.

    The key discipline, stated once so no arm can drift from it:

    * ``asset_address`` is present IFF the status is ``resolved``;
    * ``observed_at_block`` is present IFF a read completed (``resolved`` or
      ``observed_zero_address``) — and it is written from the same object as the
      address, so ``asset_address`` present without it is unreachable;
    * ``asset_identity_invariant`` qualifies a PUBLISHED address, so it appears
      only where one is published;
    * ``not_determined_reason`` appears only on the not-determined arm and
      carries no consumption obligation.
    """
    row: dict[str, Any] = {
        "asset_getter_selector": receiver.auto_getter_selector,
        "sink_ids": list(receiver.sink_ids),
        # Display and source-join only. Never a resolution basis.
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
        # A completed read of a real zero. Not an asset, not a failure, and not
        # droppable: a consumer that saw nothing here could not tell it apart
        # from a receiver that was never read.
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
    """Dereference every licensed receiver at ONE pinned height.

    ``deployment_address`` is the RUNTIME address — the proxy an implementation's
    code actually executes at, never the implementation its ``contracts`` row is
    keyed to. Reading the implementation directly would answer with whatever
    constant that bytecode carries for a deployment nobody prices.

    ``proven_proxied`` must be an EARNED fact about that deployment. It is the
    sole licence for ``redirectable_by_upgrade_authority``; where it is false the
    invariant is ``not_determined``, because "no proxy was proven" is not the
    same as "no proxy exists" and this enum has no closed member to fall back to.

    Every call goes out at ``hex(probe_block.number)``. There is no ``"latest"``
    path and no retry against one: a caller with no pinned height must not call
    this function at all.
    """
    calls = [{"to": deployment_address, "data": receiver.auto_getter_selector} for receiver in receivers]
    results = eth_call_batch(rpc_url, calls, hex(probe_block.number), chain_id=chain_id) if calls else []

    rows: list[dict[str, Any]] = []
    for receiver, result in zip(receivers, results):
        observation, reason = observe_asset_address(result, probe_block)
        rows.append(_row(receiver, observation, reason, proven_proxied=proven_proxied))

    return {
        "schema_version": SCHEMA_VERSION,
        # The scope half of every row's identity. Rows are keyed by
        # ``asset_getter_selector`` WITHIN this scope; the full structural key is
        # (chain_id, deployment_address, asset_getter_selector).
        "chain_id": chain_id,
        "deployment_address": deployment_address,
        "deployment_proven_proxied": proven_proxied,
        "probe_block": probe_block.number,
        "probe_block_hash": probe_block.block_hash.hex() if probe_block.block_hash else None,
        "receivers": rows,
    }


def count_resolved(payload: Mapping[str, Any]) -> int:
    """Rows carrying a priceable address. The zero-address rows are excluded on
    purpose — they completed, but they name no asset."""
    receivers = payload.get("receivers")
    if not isinstance(receivers, list):
        return 0
    return sum(
        1 for row in receivers if isinstance(row, Mapping) and row.get("asset_address_status") == STATUS_RESOLVED
    )
