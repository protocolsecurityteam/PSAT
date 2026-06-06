"""Controller state snapshot builder and address classifier."""

from __future__ import annotations

import copy
import logging
import os
import threading
import time
from collections.abc import Callable
from typing import Any, cast

from eth_abi.abi import decode

from schemas.common import Contract, make_contract
from schemas.control_tracking import ControlSnapshot, ControlTrackingPlan, TrackedController
from services.resolution.tracking_plan import is_primitive_scalar_read_spec
from services.static.contract_analysis_pipeline.analysis_types import AssociatedEvent, ControllerReadSpec
from utils.rpc import (
    normalize_hex as _normalize_hex,
)
from utils.rpc import (
    rpc_batch_request_with_status as _rpc_batch_request_with_status,
)
from utils.rpc import (
    rpc_request as _rpc_request,
)
from utils.rpc import (
    selector as _selector,
)

logger = logging.getLogger(__name__)

# Distinguishes "RPC succeeded, function absent" (None) from "RPC raised" — caching the latter would cement
# misclassification.
_PROBE_ERROR = object()

# Process-wide classify cache keyed on (rpc_url, address, block_tag); skips error returns and applies a TTL so latest-
# block reads eventually re-probe.
_CLASSIFY_CACHE: dict[tuple[str, str, str], tuple[str, dict[str, object], float]] = {}
_CLASSIFY_CACHE_LOCK = threading.Lock()
_CLASSIFY_CACHE_MAX = 4096
_CLASSIFY_CACHE_TTL_S = float(os.getenv("PSAT_CLASSIFY_CACHE_TTL_S", "1800"))

# Single-batch classify probes (default ON); falls back to sequential on whole-batch failure. Toggle
# PSAT_CLASSIFY_BATCH=0 to force sequential.
_CLASSIFY_BATCH_ENABLED = os.getenv("PSAT_CLASSIFY_BATCH", "1").lower() in ("1", "true", "yes")


def type_authority_contract(rpc_url: str, address: str, block_tag: str = "latest") -> dict[str, object]:
    """Compatibility hook for old callers/tests.

    Runtime authority expansion is now handled by semantic predicate
    capabilities, not by standard-specific controller probes.
    """
    del rpc_url, address, block_tag
    return {}


def clear_classify_cache() -> None:
    """Clear the process-wide classify cache. For tests + manual reset."""
    from utils.memory import reset_cache_pressure_state

    with _CLASSIFY_CACHE_LOCK:
        _CLASSIFY_CACHE.clear()
    reset_cache_pressure_state("classify")


def _log_classify_pressure() -> None:
    """Log when _CLASSIFY_CACHE crosses 50/75/95% of bound (caller holds the lock)."""
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("classify", len(_CLASSIFY_CACHE), _CLASSIFY_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


# ``controller_values.value`` is ``String(66)`` (db/models.py): an address is
# 42 chars, a single 32-byte word 66. A wider value is not a storable single
# controller identity — almost always a struct/array getter whose raw multi-word
# ABI return reaches the fallthrough below with no ``member_path`` to project
# (e.g. AccountantWithRateProviders.accountantState()), or a projected uint256
# that stringifies past 66 digits.
_CONTROLLER_VALUE_MAX_LEN = 66


def _decode_controller_value(
    raw_value: Any,
    controller_kind: str,
    read_spec: ControllerReadSpec | None = None,
) -> str:
    value = _normalize_hex(raw_value if isinstance(raw_value, str) else "0x")
    if isinstance(read_spec, dict) and read_spec.get("member_path"):
        decoded = _decode_projected_member_value(value, read_spec)
    elif controller_kind in {"state_variable", "external_contract"} and len(value) == 66:
        decoded = "0x" + value[-40:]
    else:
        decoded = value
    # Refuse an unstorable value here rather than letting the resolution
    # worker's controller_values INSERT raise StringDataRightTruncation
    # mid-commit (which poisons the worker session). The caller
    # (build_control_snapshot) turns this into a value=None entry.
    if len(decoded) > _CONTROLLER_VALUE_MAX_LEN:
        member_path = read_spec.get("member_path") if isinstance(read_spec, dict) else None
        raise ValueError(
            f"controller value ({len(decoded)} chars) exceeds storable width "
            f"{_CONTROLLER_VALUE_MAX_LEN}: a struct/array getter without a member_path "
            f"projection has no single storable value "
            f"(controller_kind={controller_kind!r}, member_path={member_path!r})"
        )
    return decoded


def _decode_projected_member_value(raw_value: str, read_spec: ControllerReadSpec) -> str:
    member_path = read_spec.get("member_path")
    components = read_spec.get("components")
    if not isinstance(member_path, list) or len(member_path) != 1:
        raise RuntimeError(f"Unsupported projected member path: {member_path!r}")
    if not isinstance(components, list) or not components:
        raise RuntimeError("Projected member read is missing struct components")

    names = [component.get("name") for component in components if isinstance(component, dict)]
    abi_types = [component.get("abi_type") for component in components if isinstance(component, dict)]
    if member_path[0] not in names or not all(isinstance(abi_type, str) and abi_type for abi_type in abi_types):
        raise RuntimeError(f"Projected member {member_path[0]!r} is not present in struct components")

    data = bytes.fromhex(_normalize_hex(raw_value)[2:])
    values = decode(list(abi_types), data)
    value = values[names.index(member_path[0])]
    projected_type = read_spec.get("type")
    if projected_type in {"address", "address payable"}:
        return str(value).lower()
    if projected_type == "bytes32":
        if isinstance(value, bytes):
            return "0x" + value.hex()
        return str(value)
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    return str(value)


def _eth_call_raw(rpc_url: str, contract_address: str, signature: str, block_tag: str = "latest") -> str:
    call = {"to": contract_address, "data": _selector(signature)}
    raw = _rpc_request(rpc_url, "eth_call", [call, block_tag])
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise RuntimeError(f"Unexpected eth_call result for {signature}: {raw!r}")
    return raw


def _decode_abi_value(raw_value: str, abi_type: str):
    data = bytes.fromhex(_normalize_hex(raw_value)[2:])
    if not data:
        raise RuntimeError("Empty ABI data")
    value = decode([abi_type], data)[0]
    if abi_type == "address":
        return str(value).lower()
    if abi_type == "address[]":
        return [str(item).lower() for item in value]
    return value


def _decode_topic_value(raw_value: str, abi_type: str):
    normalized = _normalize_hex(raw_value)
    if abi_type == "address" and len(normalized) == 66:
        return "0x" + normalized[-40:]
    if abi_type == "bytes4" and len(normalized) == 66:
        return "0x" + normalized[2:10]
    if abi_type.startswith("uint"):
        return int(normalized, 16)
    if abi_type == "bool":
        return bool(int(normalized, 16))
    return normalized


def _try_eth_call_decoded(
    rpc_url: str, contract_address: str, signature: str, abi_type: str, block_tag: str = "latest"
) -> object | None:
    """Decoded value, None (function absent / decode failure), or _PROBE_ERROR (transient RPC issue — caller should not
    cache)."""
    try:
        raw = _eth_call_raw(rpc_url, contract_address, signature, block_tag)
        if _normalize_hex(raw) in {"0x", "0x0"}:
            return None
        try:
            return _decode_abi_value(raw, abi_type)
        except Exception:
            return None
    except Exception:
        return _PROBE_ERROR


def _get_code(rpc_url: str, address: str, block_tag: str = "latest") -> str:
    raw = _rpc_request(rpc_url, "eth_getCode", [address, block_tag])
    return _normalize_hex(raw if isinstance(raw, str) else "0x")


def _coerce_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    raise RuntimeError(f"Unsupported integer value: {value!r}")


def classify_resolved_address_with_status(
    rpc_url: str, address: str, block_tag: str = "latest"
) -> tuple[str, dict[str, object], bool]:
    """Like ``classify_resolved_address`` but also returns a ``cacheable`` flag (False if any probe errored)."""
    normalized = _normalize_hex(address)
    cache_key = (rpc_url, normalized, block_tag)
    now = time.monotonic()

    with _CLASSIFY_CACHE_LOCK:
        cached = _CLASSIFY_CACHE.get(cache_key)
        if cached is not None:
            kind, cached_details, inserted_at = cached
            if now - inserted_at < _CLASSIFY_CACHE_TTL_S:
                return kind, copy.deepcopy(cached_details), True
            del _CLASSIFY_CACHE[cache_key]

    if _CLASSIFY_BATCH_ENABLED:
        kind, details, had_error = _classify_uncached_batched(rpc_url, normalized, block_tag)
    else:
        kind, details, had_error = _classify_uncached(rpc_url, normalized, block_tag)

    if not had_error:
        with _CLASSIFY_CACHE_LOCK:
            if len(_CLASSIFY_CACHE) >= _CLASSIFY_CACHE_MAX:
                for old_key in list(_CLASSIFY_CACHE.keys())[: _CLASSIFY_CACHE_MAX // 2]:
                    del _CLASSIFY_CACHE[old_key]
            _CLASSIFY_CACHE[cache_key] = (kind, copy.deepcopy(details), now)
            _log_classify_pressure()

    return kind, details, not had_error


def classify_resolved_address(rpc_url: str, address: str, block_tag: str = "latest") -> tuple[str, dict[str, object]]:
    """Backwards-compatible wrapper that drops the cacheable flag; use the ``_with_status`` form if you maintain a
    downstream cache."""
    kind, details, _cacheable = classify_resolved_address_with_status(rpc_url, address, block_tag)
    return kind, details


# Probe set for the batched classifier; order is load-bearing — `_classify_uncached_batched` unpacks by index.
_CLASSIFY_PROBE_SIGS: tuple[tuple[str, str], ...] = (
    ("getOwners()", "address[]"),  # 0: Safe
    ("getThreshold()", "uint256"),  # 1: Safe
    ("getMinDelay()", "uint256"),  # 2: Timelock primary
    ("delay()", "uint256"),  # 3: Timelock fallback
    ("UPGRADE_INTERFACE_VERSION()", "string"),  # 4: ProxyAdmin
    ("owner()", "address"),  # 5: Timelock + ProxyAdmin secondary
)


def _decode_probe_result(raw: object, abi_type: str) -> object | None:
    """Decode a pre-fetched probe result; returns None on empty/decode-failure (caller maps RPC errors to _PROBE_ERROR
    before calling)."""
    if not isinstance(raw, str):
        return None
    if _normalize_hex(raw) in {"0x", "0x0"}:
        return None
    try:
        return _decode_abi_value(raw, abi_type)
    except Exception:
        return None


def _batch_probe(rpc_url: str, address: str, block_tag: str) -> list[object]:
    """Fire all 6 classify probes in one JSON-RPC batch; per-slot errors yield _PROBE_ERROR so callers skip caching."""
    calls = [("eth_call", [{"to": address, "data": _selector(sig)}, block_tag]) for sig, _abi in _CLASSIFY_PROBE_SIGS]
    raw_results = _rpc_batch_request_with_status(rpc_url, calls)
    decoded: list[object] = []
    for (raw, had_err), (_sig, abi_type) in zip(raw_results, _CLASSIFY_PROBE_SIGS):
        if had_err:
            decoded.append(_PROBE_ERROR)
            continue
        decoded.append(_decode_probe_result(raw, abi_type))
    return decoded


def _classify_uncached_batched(rpc_url: str, normalized: str, block_tag: str) -> tuple[str, dict[str, object], bool]:
    """Same contract as ``_classify_uncached`` but batches the 6 probes upfront, saving 5 RTT in the common generic-
    contract case."""
    if normalized == "0x0000000000000000000000000000000000000000":
        return "zero", {"address": normalized}, False

    try:
        code = _get_code(rpc_url, normalized, block_tag)
    except Exception:
        return "contract", {"address": normalized}, True
    if code in {"0x", "0x0"}:
        return "eoa", {"address": normalized}, False

    # Bytecode-keccak shortcut: skip the batch round trip when bytecode matches a canonical impl.
    if _KNOWN_BYTECODE_IMPLS:
        try:
            from utils.rpc import get_code_with_keccak

            _, bytecode_keccak = get_code_with_keccak(rpc_url, normalized)
        except Exception:
            bytecode_keccak = None
        if bytecode_keccak is not None:
            hit = _KNOWN_BYTECODE_IMPLS.get(bytecode_keccak)
            if hit is not None:
                kind, partial = hit
                details: dict[str, object] = {"address": normalized}
                details.update(partial)
                return kind, details, False

    probes = _batch_probe(rpc_url, normalized, block_tag)
    # Whole-batch failure → fall back to sequential so providers that reject batches don't degrade classification
    # accuracy.
    if all(p is _PROBE_ERROR for p in probes):
        return _classify_uncached(rpc_url, normalized, block_tag)
    safe_owners_raw, safe_threshold_raw, min_delay_a, min_delay_b, upgrade_iv, owner_raw = probes

    def _ok(v: object) -> object | None:
        """Map _PROBE_ERROR → None to match the sequential ``_probe()`` shape."""
        if v is _PROBE_ERROR:
            return None
        return v

    had_error = any(p is _PROBE_ERROR for p in probes)
    safe_owners = _ok(safe_owners_raw)
    safe_threshold = _ok(safe_threshold_raw)
    if safe_owners is not None and safe_threshold is not None:
        return (
            "safe",
            {
                "address": normalized,
                "owners": [str(item).lower() for item in safe_owners] if isinstance(safe_owners, list) else [],
                "threshold": _coerce_int(safe_threshold),
            },
            had_error,
        )

    min_delay = _ok(min_delay_a)
    if min_delay is None:
        min_delay = _ok(min_delay_b)
    if min_delay is not None:
        owner = _ok(owner_raw)
        details: dict[str, object] = {"address": normalized, "delay": _coerce_int(min_delay)}
        if owner is not None:
            details["owner"] = owner
        return "timelock", details, had_error

    upgrade_interface_version = _ok(upgrade_iv)
    if upgrade_interface_version is not None:
        owner = _ok(owner_raw)
        details = {
            "address": normalized,
            "upgrade_interface_version": str(upgrade_interface_version),
        }
        if owner is not None:
            details["owner"] = owner
        return "proxy_admin", details, had_error

    details = {"address": normalized}
    try:
        details.update(type_authority_contract(rpc_url, normalized, block_tag))
    except Exception:
        had_error = True
    return "contract", details, had_error


# Canonical-impl bytecode keccak registry; matches short-circuit the 6-probe classifier (empty by default — populate via
# follow-up or test monkeypatch).
_KNOWN_BYTECODE_IMPLS: dict[str, tuple[str, dict[str, object]]] = {}


def _classify_uncached(rpc_url: str, normalized: str, block_tag: str) -> tuple[str, dict[str, object], bool]:
    """The classifier. Returns ``(kind, details, had_rpc_error)``; caller must skip caching on had_rpc_error."""
    if normalized == "0x0000000000000000000000000000000000000000":
        return "zero", {"address": normalized}, False

    try:
        code = _get_code(rpc_url, normalized, block_tag)
    except Exception:
        return "contract", {"address": normalized}, True
    if code in {"0x", "0x0"}:
        return "eoa", {"address": normalized}, False

    # Bytecode-keccak shortcut: skip the 6-probe sequence when bytecode matches a registered canonical impl.
    if _KNOWN_BYTECODE_IMPLS:
        try:
            from utils.rpc import get_code_with_keccak

            _, bytecode_keccak = get_code_with_keccak(rpc_url, normalized)
        except Exception:
            bytecode_keccak = None
        if bytecode_keccak is not None:
            hit = _KNOWN_BYTECODE_IMPLS.get(bytecode_keccak)
            if hit is not None:
                kind, partial = hit
                details: dict[str, object] = {"address": normalized}
                details.update(partial)
                return kind, details, False

    had_error = False

    def _probe(signature: str, abi_type: str) -> object | None:
        nonlocal had_error
        result = _try_eth_call_decoded(rpc_url, normalized, signature, abi_type, block_tag)
        if result is _PROBE_ERROR:
            had_error = True
            return None
        return result

    safe_owners = _probe("getOwners()", "address[]")
    safe_threshold = _probe("getThreshold()", "uint256")
    if safe_owners is not None and safe_threshold is not None:
        return (
            "safe",
            {
                "address": normalized,
                "owners": [str(item).lower() for item in safe_owners] if isinstance(safe_owners, list) else [],
                "threshold": _coerce_int(safe_threshold),
            },
            had_error,
        )

    min_delay = _probe("getMinDelay()", "uint256")
    if min_delay is None:
        min_delay = _probe("delay()", "uint256")
    if min_delay is not None:
        owner = _probe("owner()", "address")
        details: dict[str, object] = {"address": normalized, "delay": _coerce_int(min_delay)}
        if owner is not None:
            details["owner"] = owner
        return "timelock", details, had_error

    upgrade_interface_version = _probe("UPGRADE_INTERFACE_VERSION()", "string")
    if upgrade_interface_version is not None:
        owner = _probe("owner()", "address")
        details = {
            "address": normalized,
            "upgrade_interface_version": str(upgrade_interface_version),
        }
        if owner is not None:
            details["owner"] = owner
        return "proxy_admin", details, had_error

    details = {"address": normalized}
    try:
        details.update(type_authority_contract(rpc_url, normalized, block_tag))
    except Exception:
        had_error = True
    return "contract", details, had_error


def _current_block_number(rpc_url: str) -> int:
    raw = _rpc_request(rpc_url, "eth_blockNumber", [])
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise RuntimeError(f"Unexpected eth_blockNumber result: {raw!r}")
    return int(raw, 16)


def _read_polling_source(
    rpc_url: str,
    contract_address: str,
    source: str,
    controller_kind: str,
    block_tag: str = "latest",
    read_spec: ControllerReadSpec | None = None,
) -> str:
    target = source
    if isinstance(read_spec, dict) and read_spec.get("strategy") == "getter_call":
        read_target = read_spec.get("target")
        if isinstance(read_target, str) and read_target:
            target = read_target
    raw = _eth_call_raw(rpc_url, contract_address, f"{target}()", block_tag)
    return _decode_controller_value(raw, controller_kind, read_spec)


def build_control_snapshot(
    plan: ControlTrackingPlan,
    rpc_url: str,
    block_tag: str = "latest",
    *,
    heartbeat: Callable[[], None] | None = None,
    getter_fallback_address: str | None = None,
) -> ControlSnapshot:
    """Resolve every tracked controller's value at the given block.

    The classification cache is the process-wide ``_CLASSIFY_CACHE`` (see
    ``classify_resolved_address``); the previous per-snapshot cache was an
    unsynchronised dict that becomes a race once the level fan-out runs in
    threads, and the global cache already handles dedup with a lock.

    ``getter_fallback_address`` — the implementation address to retry a getter
    against when the primary read (usually a proxy) reverts. Storage-backed
    state lives in the proxy, but ``immutable`` authority addresses live in the
    implementation bytecode and revert when the runtime address doesn't
    delegatecall to that impl (beacon / per-instance patterns). Defaults to
    ``None`` (no fallback), preserving the prior reverting-getter behavior.
    """
    from utils.concurrency import parallel_map

    def _call_with_heartbeat(fn: Callable[[], int]) -> int:
        if heartbeat is None:
            return fn()
        results = parallel_map(lambda _item: fn(), [None], max_workers=1, heartbeat=heartbeat)
        outcome = results[0][1]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    block_number = (
        _call_with_heartbeat(lambda: _current_block_number(rpc_url)) if block_tag == "latest" else int(block_tag, 16)
    )
    controller_values: dict[str, Any] = {}

    def _compute_controller(controller: TrackedController) -> tuple[str, dict[str, Any] | None]:
        """Pure function: compute one controller's value dict, or None to skip."""
        controller_id = controller["controller_id"]
        source = controller["source"]
        read_spec = controller.get("read_spec")
        # Primitive-scalar state vars are admitted to the plan only so the event
        # pathway can watch them — the value snapshot is address-only (every
        # consumer reads ``value`` as a 0x-address). Reading a scalar slot and
        # classifying it as an address mints phantom EOA principals: a uint
        # _minDelay==864000 resolves to 0x…0d2f00, has no code, classifies
        # "eoa", and is promoted to a controller of every contract declaring it.
        # Skip only primitive scalars — address/contract slots are real
        # principals, and mapping/array/struct slots are enumerated elsewhere
        # (a bare getter reverts on them) so they must pass through untouched.
        if controller["kind"] == "state_variable" and is_primitive_scalar_read_spec(read_spec):
            return controller_id, None
        spec = cast(ControllerReadSpec | None, read_spec if isinstance(read_spec, dict) else None)

        def _read_entry(read_address: str, observed_via: str) -> dict[str, Any]:
            value = _read_polling_source(rpc_url, read_address, source, controller["kind"], block_tag, read_spec=spec)
            if controller["kind"] == "role_identifier":
                return {
                    "source": source,
                    "value": value,
                    "block_number": block_number,
                    "observed_via": observed_via,
                    "resolved_type": "unknown",
                    "details": {
                        "source": source,
                        "role_id": value,
                        # Membership is enforced at the runtime address even when
                        # the role-id constant was read from the implementation.
                        "authority_contract": plan["contract_address"],
                        "principal_source": "capability_expr",
                    },
                }
            entry: dict[str, Any] = {
                "source": source,
                "value": value,
                "block_number": block_number,
                "observed_via": observed_via,
            }
            resolved_type, details = classify_resolved_address(rpc_url, value, block_tag)
            entry["resolved_type"] = resolved_type
            entry["details"] = details
            return entry

        try:
            return controller_id, _read_entry(plan["contract_address"], "eth_call")
        except Exception as exc:
            # Storage-backed getters live in the proxy, but immutable-backed
            # authority addresses live in the implementation bytecode and revert
            # when the runtime address doesn't delegatecall to that impl (beacon
            # / per-instance patterns — e.g. EtherFiNode, whose
            # etherFiNodesManager/delegationManager are immutable). Retry against
            # the implementation: impl storage reads as zero so a storage getter
            # just yields the empty answer, while an immutable getter recovers
            # its real value instead of being recorded null.
            if getter_fallback_address and getter_fallback_address.lower() != str(plan["contract_address"]).lower():
                try:
                    return controller_id, _read_entry(getter_fallback_address, "eth_call_impl_fallback")
                except Exception:
                    pass
            return controller_id, {
                "source": source,
                "value": None,
                "block_number": block_number,
                "observed_via": "eth_call_error",
                "resolved_type": "unknown",
                "details": {
                    "source": source,
                    "error": str(exc),
                },
            }

    results = parallel_map(_compute_controller, plan["tracked_controllers"], max_workers=8, heartbeat=heartbeat)
    for _controller, outcome in results:
        if isinstance(outcome, BaseException):
            # parallel_map captures exceptions, but ``_compute_controller``
            # already converts every internal failure to an error-shaped
            # entry. Anything reaching here is a genuine bug — surface it.
            raise outcome
        cid, entry = outcome
        if entry is None:
            continue
        controller_values[cid] = entry

    raw_contract = plan.get("contract")
    contract = (
        cast(Contract, raw_contract)
        if isinstance(raw_contract, dict)
        else make_contract(address=plan["contract_address"], name=plan.get("contract_name"))
    )

    return {
        "schema_version": "0.1",
        "contract": contract,
        "contract_address": plan["contract_address"],
        "contract_name": plan["contract_name"],
        "block_number": block_number,
        "controller_values": controller_values,
    }


def _decode_event_log_fields(event_ref: AssociatedEvent, log_entry: dict[str, Any]) -> dict[str, Any]:
    topics = list(log_entry.get("topics") or [])
    topic_index = 1
    non_indexed_types = [item["type"] for item in event_ref.get("inputs", []) if not item.get("indexed")]
    non_indexed_values = []
    data = _normalize_hex(log_entry.get("data"))
    if non_indexed_types and data not in {"0x", "0x0"}:
        non_indexed_values = list(decode(non_indexed_types, bytes.fromhex(data[2:])))

    decoded: dict[str, Any] = {}
    non_indexed_index = 0
    for item in event_ref.get("inputs", []):
        name = item.get("name") or item["type"]
        abi_type = item["type"]
        if item.get("indexed"):
            if topic_index >= len(topics):
                break
            decoded[name] = _decode_topic_value(topics[topic_index], abi_type)
            topic_index += 1
            continue

        if non_indexed_index >= len(non_indexed_values):
            break
        value = non_indexed_values[non_indexed_index]
        non_indexed_index += 1
        if abi_type == "address":
            decoded[name] = str(value).lower()
        elif abi_type == "bytes4":
            decoded[name] = "0x" + bytes(value).hex()
        elif abi_type == "bool":
            decoded[name] = bool(value)
        elif abi_type.startswith("uint"):
            decoded[name] = int(value)
        else:
            decoded[name] = value
    return decoded
