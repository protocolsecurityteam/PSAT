"""On-chain one-shot latch resolution: consumed vs live.

The static stage finds initializer-family one-shots and their latch (``one_shot.apply_one_shot_pass``); whether the
latch is consumed needs a live read at the runtime address.

  consumed      the latch is set (or holds the ``_disableInitializers`` sentinel)
  live          unset on a confirmed live deployment (recognized or DB-linked proxy)
  indeterminate unset on an unconfirmed address, unreadable, no latch, or RPC failure

An unconfirmed address never earns live: an implementation template reads the same. Proxy confirmation covers EIP-1967
(impl/beacon/admin), zeppelinos, the Aragon kernel slot, ``implementation()`` (EIP-897 / Aragon AppProxy) and the
EIP-2535 loupe. The latch read always targets the runtime address.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable

from eth_utils.crypto import keccak

from services.clients.rpc import rpc_request
from utils.evm import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPL_SLOT,
    IMPLEMENTATION_SELECTOR,
    OZ_LEGACY_IMPL_SLOT,
)

logger = logging.getLogger(__name__)

RpcFn = Callable[..., Any]


def one_shot_probe_enabled() -> bool:
    """Default on; ``PSAT_ONE_SHOT_PROBE=0`` disables. Strictly additive."""
    return os.getenv("PSAT_ONE_SHOT_PROBE", "1").strip().lower() not in ("0", "false", "no", "off")


def _slot_hex(value: int) -> str:
    return "0x" + format(value, "064x")


# Preimages documented in utils.evm.
ARAGON_KERNEL_SLOT = "0x" + keccak(text="aragonOS.appStorage.kernel").hex()

_IMPLEMENTATION_SELECTOR = IMPLEMENTATION_SELECTOR
_FACET_ADDRESSES_SELECTOR = "0x" + keccak(text="facetAddresses()").hex()[:8]

# ``_disableInitializers()`` sentinels: type-max of uint8 (OZ v4) and uint64 (OZ v5).
_DISABLED_SENTINELS = {1: 0xFF, 8: 0xFFFFFFFFFFFFFFFF}

# Oracles ``_classify_value`` can decide from. Unordered: a discriminator to gate and cite on, not a strength score.
LATCH_BASIS_SENTINEL = "sentinel"
LATCH_BASIS_VERSION_GE = "version_ge"
LATCH_BASIS_VALUE_GT_ZERO = "value_gt_zero"
LATCH_BASIS_GUARD = "guard"
LATCH_BASIS_NOT_DETERMINED = "not_determined"

# Copied onto the witness; None-valued keys are omitted so "producer had nothing" isn't a measured zero.
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
    # Which latch and oracle decided, and the read it came from. Empty when nothing was read; treat as the weakest
    # branch.
    witness: dict[str, Any] = field(default_factory=dict)


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
    """The first proxy standard confirming ``address`` is a live deployment, or None."""
    checks: list[tuple[str, str]] = [
        ("eip1967", EIP1967_IMPL_SLOT),
        ("eip1967_beacon", EIP1967_BEACON_SLOT),
        ("eip1967_admin", EIP1967_ADMIN_SLOT),
        ("zeppelinos", OZ_LEGACY_IMPL_SLOT),
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
        # A bare template answers neither ``implementation()`` nor ``facetAddresses()``.
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


def _read_latch_value(
    rpc: RpcFn,
    rpc_url: str,
    address: str,
    latch: dict[str, Any],
    block_tag: str,
    transcript: dict[str, Any],
) -> tuple[int | None, dict[str, Any] | None]:
    """``(value, read)``: the latch value and the read that produced it, or ``(None, None)``.

    Prefers a public getter, falling back to the raw slot; the record is the read actually used.
    """
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
        # Fall through to the slot when the getter reverts.

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
    """Evaluate the polarity-folded allow predicate against the latch value; None when unevaluable."""
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
    """A payload targeting OZ's transient ``_initializing`` flag rather than the version member (possible in
    pre-role-stamping artifacts). On the v5 namespaced slot only the uint64 at offset 0 is trusted; on v4 the
    field name marks the flag.
    """
    standard = latch.get("standard")
    if standard == "oz_v5_namespaced":
        return (latch.get("byte_offset"), latch.get("size_bytes")) != (0, 8)
    if standard == "storage_layout":
        return latch.get("variable") == "_initializing"
    return False


def _latch_may_decide(latch: dict[str, Any]) -> bool:
    """Whether a latch may decide consumed/live: ``role="version"``, or a structural candidate with its own guard.

    The transient flag reads zero at rest on both consumed and live deployments, so it never qualifies. Untagged legacy
    payloads decide via version semantics when standard-shaped and not transient-shaped; anything else is excluded up
    front so it can't mask a decisive latch.
    """
    if latch.get("role") == "version":
        return True
    if isinstance(latch.get("guard"), dict):
        return True
    if _is_transient_flag_latch(latch):
        return False
    return latch.get("standard") in ("storage_layout", "oz_v5_namespaced")


def _classify_value(latch: dict[str, Any], value: int) -> tuple[str, str | None]:
    """``(classification, basis)``: ``consumed`` / ``armed`` / ``unknown`` with the deciding oracle.

    ``basis`` is None exactly for ``unknown``. Proxy confirmation comes later.
    """
    standard = latch.get("standard")
    if standard in ("storage_layout", "oz_v5_namespaced"):
        size_bytes = latch.get("size_bytes")
        sentinel = _DISABLED_SENTINELS.get(size_bytes) if isinstance(size_bytes, int) else None
        if sentinel is not None and value == sentinel:
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
    """Stable identity of the descriptor list a result was computed from.

    Slot alone isn't enough: FiatTokenV2_2's three initializers share a slot behind different guards.
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
    """The published witness for one latch read.

    Keys are omitted when unknown; ``latch_basis`` is always present (``not_determined`` when nothing decided).
    """
    witness: dict[str, Any] = {
        "latch_basis": basis or LATCH_BASIS_NOT_DETERMINED,
        "probe_address": address,
    }
    if isinstance(block, int) and block > 0:
        # Only pinned heights are published.
        witness["probe_block"] = block

    for key in _WITNESS_DESCRIPTOR_KEYS:
        value = latch.get(key)
        if value is not None:
            witness[key] = value

    # Published only with the basis for where the integer came from (a modifier name match).
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
    """A per-condition copy so a shared ``guard`` dict doesn't alias across rows."""
    return {key: (dict(value) if isinstance(value, dict) else value) for key, value in witness.items()}


def resolve_one_shot_state(
    *,
    rpc_url: str,
    address: str,
    latches: list[dict[str, Any]],
    block: int | None = None,
    db_proxy_linked: bool = False,
    rpc: RpcFn = rpc_request,
) -> LatchReadResult:
    """Read the one-shot latch state at the runtime ``address``.

    Only consumption oracles are read (``_latch_may_decide``): version-tagged first, then legacy standard shapes, then
    guarded candidates; the first readable wins. No decisive latch means indeterminate.
    """
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
        # Already linked to an implementation job, so it's a live proxy.
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
        state = "live"
    else:
        # An unconfirmed address or unevaluable guard never claims live.
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


def collect_one_shot_latches(tree: Any) -> dict[str, list[dict[str, Any]]]:
    """``{"standard": [...], "candidate": [...]}`` latch payloads from a predicate tree: A-spine one_shot leaves vs
    structural-detector stamps.
    """
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

    Every ``kind=one_shot`` condition gets ``latch_state``/``latch_value``/``latch_target`` and, when read,
    ``latch_witness`` (the same witness on each, since one read decided them). A confirmed structural candidate also
    appends a root one_shot condition. No ``latch_witness`` means nothing was read.
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
