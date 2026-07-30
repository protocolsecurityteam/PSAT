"""On-chain one-shot latch resolution — consumed vs live.

The static stage can prove a function is an initializer-family one-shot and
where its latch lives (``one_shot.apply_one_shot_pass``); whether the latch
is CONSUMED is mutable on-chain state only a live read can answer. This
module performs that read against the function's runtime deployment address
and classifies:

  consumed      — the latch is set (or carries the ``_disableInitializers``
                  sentinel): the one-shot is inert at this address.
  live          — the latch is unset ON A CONFIRMED LIVE DEPLOYMENT (a
                  recognized proxy, or a DB-linked proxy): anyone can call
                  it once. A live verdict is never earned from a bare,
                  unconfirmed address — an implementation/template with an
                  empty latch reads exactly the same and labeling it live
                  re-manufactures the false-open this branch removes.
  indeterminate — unset latch on an unconfirmed address, unreadable slot,
                  no latch location, or RPC failure.

The proxy confirmation is a multi-standard resolver, not one slot read:
EIP-1967 (impl/beacon/admin), the legacy zeppelinos slot, the Aragon app
kernel slot, an ``implementation()`` getter (EIP-897 / Aragon AppProxy),
and an EIP-2535 diamond loupe answer. Storage for every one of these lives
on the proxy/diamond itself, so the latch read always targets the runtime
address — never ``contracts.address``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable

from eth_utils.crypto import keccak

from utils.rpc import rpc_request

logger = logging.getLogger(__name__)

RpcFn = Callable[..., Any]


def one_shot_probe_enabled() -> bool:
    """Default ON; ``PSAT_ONE_SHOT_PROBE=0`` is the kill switch. The read is
    strictly additive — a disabled or failing probe leaves the static badge
    exactly as it was."""
    return os.getenv("PSAT_ONE_SHOT_PROBE", "1").strip().lower() not in ("0", "false", "no", "off")


def _slot_hex(value: int) -> str:
    return "0x" + format(value, "064x")


# Proxy-standard storage slots, computed from their canonical preimages.
EIP1967_IMPL_SLOT = _slot_hex(int.from_bytes(keccak(text="eip1967.proxy.implementation"), "big") - 1)
EIP1967_BEACON_SLOT = _slot_hex(int.from_bytes(keccak(text="eip1967.proxy.beacon"), "big") - 1)
EIP1967_ADMIN_SLOT = _slot_hex(int.from_bytes(keccak(text="eip1967.proxy.admin"), "big") - 1)
ZEPPELINOS_IMPL_SLOT = "0x" + keccak(text="org.zeppelinos.proxy.implementation").hex()
ARAGON_KERNEL_SLOT = "0x" + keccak(text="aragonOS.appStorage.kernel").hex()

_IMPLEMENTATION_SELECTOR = "0x" + keccak(text="implementation()").hex()[:8]
_FACET_ADDRESSES_SELECTOR = "0x" + keccak(text="facetAddresses()").hex()[:8]

# ``_disableInitializers()`` sentinels: type-max of the latch word — uint8
# (OZ v4) and uint64 (OZ v5).
_DISABLED_SENTINELS = {1: 0xFF, 8: 0xFFFFFFFFFFFFFFFF}

# The four oracles ``_classify_value`` can decide from. Unordered by
# construction: sentinel and value_gt_zero have zero realized rows and guard
# six, so no reliability ranking over them is measurable here — the value is a
# discriminator a consumer gates and cites on, never a strength score.
LATCH_BASIS_SENTINEL = "sentinel"
LATCH_BASIS_VERSION_GE = "version_ge"
LATCH_BASIS_VALUE_GT_ZERO = "value_gt_zero"
LATCH_BASIS_GUARD = "guard"
LATCH_BASIS_NOT_DETERMINED = "not_determined"

# Descriptor keys copied verbatim onto the published witness. Each is a fact the
# static producer recorded; a key whose descriptor value is None is OMITTED, so
# "the producer had nothing" is a missing key rather than a null a consumer can
# mistake for a measured zero.
_WITNESS_DESCRIPTOR_KEYS = (
    "standard",
    "role",
    "variable",
    "slot",
    "byte_offset",
    "size_bytes",
    "value_type",
)


@dataclass(frozen=True)
class LatchReadResult:
    state: str  # "consumed" | "live" | "indeterminate"
    value: int | None
    target_kind: str  # "proxy:<standard>" | "db_linked_proxy" | "diamond" | "unverified"
    transcript: dict[str, Any] = field(default_factory=dict)
    # The replayable witness for ``state``: which latch decided, which oracle
    # decided it, and the read (address/block/slot/raw word) it decided from.
    # Empty when no latch was read at all — the consumer then has no witness and
    # must treat the row as the weakest branch, never as a proven fact.
    witness: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Proxy confirmation
# ---------------------------------------------------------------------------


def _storage_at(rpc: RpcFn, rpc_url: str, address: str, slot: str, block_tag: str) -> int | None:
    try:
        raw = rpc(rpc_url, "eth_getStorageAt", [address, slot, block_tag], retries=1)
    except Exception:
        return None
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    try:
        return int(raw, 16)
    except ValueError:
        return None


def _eth_call(rpc: RpcFn, rpc_url: str, address: str, data: str, block_tag: str) -> str | None:
    try:
        raw = rpc(rpc_url, "eth_call", [{"to": address, "data": data}, block_tag], retries=1)
    except Exception:
        return None
    return raw if isinstance(raw, str) and raw.startswith("0x") else None


def detect_proxy_standard(
    rpc: RpcFn,
    rpc_url: str,
    address: str,
    block_tag: str,
    transcript: dict[str, Any] | None = None,
) -> str | None:
    """The first proxy standard whose marker confirms ``address`` is a live
    proxy/diamond deployment, or None. Each probe is one point read."""
    checks: list[tuple[str, str]] = [
        ("eip1967", EIP1967_IMPL_SLOT),
        ("eip1967_beacon", EIP1967_BEACON_SLOT),
        ("eip1967_admin", EIP1967_ADMIN_SLOT),
        ("zeppelinos", ZEPPELINOS_IMPL_SLOT),
        ("aragon_app", ARAGON_KERNEL_SLOT),
    ]
    reads: list[dict[str, Any]] = []
    found: str | None = None
    for standard, slot in checks:
        value = _storage_at(rpc, rpc_url, address, slot, block_tag)
        reads.append({"standard": standard, "slot": slot, "value": None if value is None else hex(value)})
        if value:
            found = standard
            break
    if found is None:
        # EIP-897 / Aragon AppProxy expose implementation() as a view; an
        # EIP-2535 diamond answers facetAddresses(). Either confirms a live
        # deployment (a bare template answers neither).
        raw = _eth_call(rpc, rpc_url, address, _IMPLEMENTATION_SELECTOR, block_tag)
        reads.append({"standard": "implementation_getter", "result": raw and raw[:66]})
        if raw and len(raw) >= 66 and int(raw[2:66], 16) != 0:
            found = "implementation_getter"
        else:
            raw = _eth_call(rpc, rpc_url, address, _FACET_ADDRESSES_SELECTOR, block_tag)
            reads.append({"standard": "eip2535_diamond", "result": raw and raw[:66]})
            if raw and len(raw) > 130:  # non-empty dynamic array answer
                found = "eip2535_diamond"
    if transcript is not None:
        transcript["proxy_probe"] = reads
        transcript["proxy_standard"] = found
    return found


# ---------------------------------------------------------------------------
# Latch read + decode
# ---------------------------------------------------------------------------


def _read_latch_value(
    rpc: RpcFn,
    rpc_url: str,
    address: str,
    latch: dict[str, Any],
    block_tag: str,
    transcript: dict[str, Any],
) -> tuple[int | None, dict[str, Any] | None]:
    """``(value, read)`` — the latch's current integer value at ``address`` and
    the transcript record of the read it came from, or ``(None, None)`` when
    unreadable. Prefers a public getter when the latch payload carries one
    (layout-independent), falling back to the raw storage read; the returned
    record is the read that actually produced the value, so a witness built from
    it can never attribute a getter answer to the descriptor's slot."""
    selector = latch.get("getter_selector")
    if isinstance(selector, str) and selector.startswith("0x") and len(selector) == 10:
        raw = _eth_call(rpc, rpc_url, address, selector, block_tag)
        read: dict[str, Any] = {"kind": "getter", "selector": selector, "result": raw and raw[:66]}
        transcript.setdefault("reads", []).append(read)
        if raw and len(raw) >= 66:
            try:
                return int(raw[2:66], 16), read
            except ValueError:
                pass
        # fall through to the slot read when the getter reverts (e.g. called
        # on an address that doesn't expose it)

    slot = latch.get("slot")
    if not isinstance(slot, str) or not slot.startswith("0x"):
        return None, None
    word = _storage_at(rpc, rpc_url, address, slot, block_tag)
    read = {"kind": "storage", "slot": slot, "value": None if word is None else hex(word)}
    transcript.setdefault("reads", []).append(read)
    if word is None:
        return None, None
    byte_offset = latch.get("byte_offset")
    size_bytes = latch.get("size_bytes")
    if isinstance(byte_offset, int) and isinstance(size_bytes, int) and size_bytes > 0:
        return (word >> (8 * byte_offset)) & ((1 << (8 * size_bytes)) - 1), read
    return word, read


def _guard_allows(operator: Any, constant: int | None, value: int) -> bool | None:
    """Evaluate the (polarity-folded) ALLOW predicate against the live latch
    value. None when the guard can't be evaluated."""
    if operator == "falsy":
        return value == 0
    if operator == "truthy":
        return value != 0
    if constant is None:
        return None
    if operator == "eq":
        return value == constant
    if operator == "ne":
        return value != constant
    if operator == "lt":
        return value < constant
    if operator == "lte":
        return value <= constant
    if operator == "gt":
        return value > constant
    if operator == "gte":
        return value >= constant
    return None


def _parse_guard_constant(raw: Any) -> int | None:
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw.strip(), 0)
        except ValueError:
            return None
    return None


def _is_transient_flag_latch(latch: dict[str, Any]) -> bool:
    """A latch payload targeting the OZ standard's transient ``_initializing``
    flag rather than the persistent version member — the shape artifacts
    persisted before role-stamping can carry. On the v5 namespaced slot only
    the version member's exact byte range (uint64 at offset 0) is trusted;
    on a v4 storage layout the standard's own field name marks the flag."""
    standard = latch.get("standard")
    if standard == "oz_v5_namespaced":
        return (latch.get("byte_offset"), latch.get("size_bytes")) != (0, 8)
    if standard == "storage_layout":
        return latch.get("variable") == "_initializing"
    return False


def _latch_may_decide(latch: dict[str, Any]) -> bool:
    """The safety invariant, stated positively: a consumed/live verdict may
    only be decided by a latch that is a consumption oracle —

      * ``role="version"``: the static pass's claim that the location holds
        the persistent version member; or
      * a ``guard``-carrying structural candidate, decisive by evaluating
        its own guard.

    The transient in-flight flag reads zero at rest on consumed and live
    deployments alike, so its payloads never qualify. Untagged payloads from
    artifacts persisted before role-stamping keep deciding via version
    semantics when they have a standard shape and are not transient-shaped;
    anything else (e.g. a slot-only ``namespaced_slot_constant`` record) is
    excluded up front rather than being read first and masking a decisive
    latch behind an ``unknown`` classification."""
    if latch.get("role") == "version":
        return True
    if isinstance(latch.get("guard"), dict):
        return True
    if _is_transient_flag_latch(latch):
        return False
    return latch.get("standard") in ("storage_layout", "oz_v5_namespaced")


def _classify_value(latch: dict[str, Any], value: int) -> tuple[str, str | None]:
    """``(classification, basis)`` — ``consumed`` / ``armed`` (latch would admit
    a caller) / ``unknown`` from the latch's own semantics, paired with the
    oracle that decided it. Proxy confirmation is applied later. ``basis`` is
    None exactly when nothing decided (``unknown``), which the publication layer
    renders as ``not_determined`` rather than picking a branch."""
    standard = latch.get("standard")
    if standard in ("storage_layout", "oz_v5_namespaced"):
        size_bytes = latch.get("size_bytes")
        sentinel = _DISABLED_SENTINELS.get(size_bytes) if isinstance(size_bytes, int) else None
        if sentinel is not None and value == sentinel:
            # _disableInitializers(): locked forever
            return "consumed", LATCH_BASIS_SENTINEL
        expected = latch.get("expected_version")
        if isinstance(expected, int) and expected > 0:
            return ("consumed" if value >= expected else "armed"), LATCH_BASIS_VERSION_GE
        return ("consumed" if value > 0 else "armed"), LATCH_BASIS_VALUE_GT_ZERO
    guard = latch.get("guard") or {}
    allows = _guard_allows(guard.get("operator"), _parse_guard_constant(guard.get("constant")), value)
    if allows is None:
        return "unknown", None
    return ("armed" if allows else "consumed"), LATCH_BASIS_GUARD


def latch_descriptor_digest(latches: list[dict[str, Any]]) -> str:
    """Stable identity of the descriptor list a probe result was computed from.

    Two rows may share one cached read only when their descriptors are
    byte-identical. Keying on the slot alone is not enough now that the result
    carries a witness naming which descriptor decided: FiatTokenV2_2's
    ``initializeV2``/``initializeV2_1``/``initializeV2_2`` read the same slot
    behind guards ``eq 0`` / ``eq 1`` / ``eq 2``, so a slot-keyed cache would
    stamp one function's guard onto the other two.
    """
    canonical = json.dumps(latches, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_latch_witness(
    latch: dict[str, Any],
    read: dict[str, Any] | None,
    *,
    basis: str | None,
    block: int | None,
    address: str,
) -> dict[str, Any]:
    """The published witness for one decided latch read.

    Every key is emit-when-known: a key the producer had no value for is absent,
    never null and never defaulted. ``latch_basis`` is the one key always
    present, and it carries ``not_determined`` when no oracle decided — the
    state a failed classification lands on, never a branch label.
    """
    witness: dict[str, Any] = {
        "latch_basis": basis or LATCH_BASIS_NOT_DETERMINED,
        "probe_address": address,
    }
    if isinstance(block, int) and block > 0:
        # Only a pinned height is published. A ``"latest"`` read has no
        # reproducible height, so it publishes none rather than a height that
        # cannot be replayed.
        witness["probe_block"] = block

    for key in _WITNESS_DESCRIPTOR_KEYS:
        value = latch.get(key)
        if value is not None:
            witness[key] = value

    # ``expected_version`` is publishable only alongside the basis that says
    # where the integer came from (it is derived from a modifier NAME match, so
    # bare it reads as compiler-forced). A descriptor predating basis stamping
    # therefore publishes neither.
    expected_version = latch.get("expected_version")
    expected_version_basis = latch.get("expected_version_basis")
    if isinstance(expected_version, int) and isinstance(expected_version_basis, str) and expected_version_basis:
        witness["expected_version"] = expected_version
        witness["expected_version_basis"] = expected_version_basis

    guard = latch.get("guard")
    if isinstance(guard, dict):
        published_guard = {key: guard[key] for key in ("operator", "constant") if guard.get(key) is not None}
        if published_guard:
            witness["guard"] = published_guard

    if read is not None:
        kind = read.get("kind")
        if isinstance(kind, str):
            witness["read_kind"] = kind
        raw = read.get("value") if kind == "storage" else read.get("result")
        if isinstance(raw, str):
            witness["raw_word"] = raw
        selector = read.get("selector")
        if kind == "getter" and isinstance(selector, str):
            witness["getter_selector"] = selector

    return witness


def _copy_witness(witness: dict[str, Any]) -> dict[str, Any]:
    """A per-condition copy — one cached ``LatchReadResult`` annotates many
    conditions, and a shared nested ``guard`` dict would alias across rows."""
    return {key: (dict(value) if isinstance(value, dict) else value) for key, value in witness.items()}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def resolve_one_shot_state(
    *,
    rpc_url: str,
    address: str,
    latches: list[dict[str, Any]],
    block: int | None = None,
    db_proxy_linked: bool = False,
    rpc: RpcFn = rpc_request,
) -> LatchReadResult:
    """Read the one-shot latch state for ``address`` (the runtime deployment
    address). ``latches`` are the static latch payloads collected from the
    function's predicate tree; only consumption oracles are read at all
    (``_latch_may_decide``), version-tagged payloads first, then legacy
    untagged standard shapes, then guard-carrying structural candidates —
    the first readable one wins. A tree carrying no decisive latch yields
    indeterminate, never live."""
    transcript: dict[str, Any] = {}
    if not rpc_url or not isinstance(address, str) or not address.startswith("0x") or len(address) != 42:
        return LatchReadResult("indeterminate", None, "unverified", {"reason": "no_target"})
    block_tag = hex(block) if isinstance(block, int) and block > 0 else "latest"
    transcript["block"] = block_tag
    address = address.lower()

    ordered = sorted(
        (latch for latch in latches if isinstance(latch, dict) and _latch_may_decide(latch)),
        key=lambda latch: (
            0
            if latch.get("role") == "version"
            else 1
            if latch.get("standard") in ("storage_layout", "oz_v5_namespaced")
            else 2
        ),
    )
    if not ordered:
        reason = "no_decisive_latch" if any(isinstance(latch, dict) for latch in latches) else "no_latch_location"
        return LatchReadResult("indeterminate", None, "unverified", {"reason": reason})

    if db_proxy_linked:
        # The pipeline's own proxy resolution already linked this runtime
        # address to an implementation job — it IS a live proxy.
        target_kind = "db_linked_proxy"
        transcript["proxy_standard"] = "db_linked"
    else:
        standard = detect_proxy_standard(rpc, rpc_url, address, block_tag, transcript)
        target_kind = f"proxy:{standard}" if standard else "unverified"
        if standard == "eip2535_diamond":
            target_kind = "diamond"

    value: int | None = None
    chosen: dict[str, Any] | None = None
    chosen_read: dict[str, Any] | None = None
    for latch in ordered:
        value, chosen_read = _read_latch_value(rpc, rpc_url, address, latch, block_tag, transcript)
        if value is not None:
            chosen = latch
            break
    if value is None or chosen is None:
        return LatchReadResult("indeterminate", None, target_kind, transcript)

    classified, basis = _classify_value(chosen, value)
    transcript["latch_value"] = value
    transcript["latch_standard"] = chosen.get("standard")
    witness = _build_latch_witness(chosen, chosen_read, basis=basis, block=block, address=address)
    if classified == "consumed":
        state = "consumed"
    elif classified == "armed" and target_kind != "unverified":
        # The latch would admit a caller AND the address is a confirmed live
        # deployment: a real live one-shot.
        state = "live"
    else:
        # Armed-but-unconfirmed (a bare impl/template with an empty latch reads
        # exactly like this) or an unevaluable guard: never claim live.
        state = "indeterminate"
    logger.debug(
        "one_shot probe decision",
        extra={
            "adapter": "one_shot_probe",
            "address": address,
            "decision": state,
            "reason": classified,
            "target_kind": target_kind,
        },
    )
    return LatchReadResult(state, value, target_kind, transcript, witness)


# ---------------------------------------------------------------------------
# Tree → latch collection and capability annotation (resolver-side glue)
# ---------------------------------------------------------------------------


def collect_one_shot_latches(tree: Any) -> dict[str, list[dict[str, Any]]]:
    """``{"standard": [...], "candidate": [...]}`` latch payloads from a
    predicate tree: standard = leaves the A-spine stamped (role one_shot),
    candidate = structural-detector stamps (leaf or tree-root)."""
    out: dict[str, list[dict[str, Any]]] = {"standard": [], "candidate": []}
    if not isinstance(tree, dict):
        return out

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf")
            if not isinstance(leaf, dict):
                return
            latch = leaf.get("one_shot_latch")
            if isinstance(latch, dict):
                if leaf.get("authority_role") == "one_shot":
                    out["standard"].append(latch)
                elif leaf.get("one_shot_candidate"):
                    out["candidate"].append(latch)
            return
        for child in node.get("children") or []:
            walk(child)

    walk(tree)
    root_latch = tree.get("one_shot_candidate_latch")
    if isinstance(root_latch, dict):
        out["candidate"].append(root_latch)
    return out


def tree_has_one_shot_role(tree: Any) -> bool:
    if not isinstance(tree, dict):
        return False
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        return isinstance(leaf, dict) and leaf.get("authority_role") == "one_shot"
    return any(tree_has_one_shot_role(child) for child in tree.get("children") or [])


def annotate_capability_one_shot(
    cap_dict: dict[str, Any], result: LatchReadResult, *, confirmed_candidate: bool
) -> None:
    """Land the latch read on the serialized capability dict.

    Standard one-shots: every ``kind=one_shot`` condition (anywhere in the
    expression) gains ``latch_state``/``latch_value``/``latch_target`` and, when
    a latch was actually read, ``latch_witness``. A confirmed structural
    candidate (consumed or live — never indeterminate) additionally APPENDS a
    one_shot condition at the root, since the static side deliberately left its
    badge untouched.

    ``latch_witness`` describes the ONE read that produced ``latch_state`` for
    this row; a function carrying several one_shot conditions gets that same
    witness on each, because one read is what decided them all. An absent
    ``latch_witness`` means no latch was read — the state has no replayable
    evidence behind it and must be consumed as the weakest branch.
    """

    def annotate(node: dict[str, Any]) -> None:
        for condition in node.get("conditions") or []:
            if isinstance(condition, dict) and condition.get("kind") == "one_shot":
                condition["latch_state"] = result.state
                if result.value is not None:
                    condition["latch_value"] = result.value
                condition["latch_target"] = result.target_kind
                if result.witness:
                    condition["latch_witness"] = _copy_witness(result.witness)
        for child in node.get("children") or []:
            if isinstance(child, dict):
                annotate(child)
        signer = node.get("signer")
        if isinstance(signer, dict):
            annotate(signer)

    annotate(cap_dict)
    if confirmed_candidate and result.state in ("consumed", "live"):
        conditions = cap_dict.setdefault("conditions", [])
        appended: dict[str, Any] = {
            "kind": "one_shot",
            "description": "structural one-shot latch (confirmed by on-chain read)",
            "latch_state": result.state,
            "latch_target": result.target_kind,
        }
        if result.value is not None:
            appended["latch_value"] = result.value
        if result.witness:
            appended["latch_witness"] = _copy_witness(result.witness)
        conditions.append(appended)
