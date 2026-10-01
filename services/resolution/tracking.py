"""Controller state snapshot builder and address classifier."""

from __future__ import annotations

import copy
import logging
import os
import threading
import time
from collections.abc import Callable
from typing import Any

from eth_abi.abi import decode

from schemas.contract_analysis import ControllerReadSpec
from schemas.control_tracking import (
    ControlSnapshot,
    ControlTrackingPlan,
    ResolvedControllerType,
    TrackedController,
)
from services.clients.rpc import (
    eth_call_batch as _eth_call_batch,
)
from services.clients.rpc import (
    normalize_hex as _normalize_hex,
)
from services.clients.rpc import (
    rpc_batch_request_with_status as _rpc_batch_request_with_status,
)
from services.clients.rpc import (
    rpc_request as _rpc_request,
)
from services.clients.rpc import (
    selector as _selector,
)
from services.monitoring.restaking_reads import decode_word as _decode_word
from services.resolution.tracking_plan import is_primitive_scalar_read_spec
from utils.evm import EIP1967_IMPL_SLOT, SAFE_GUARD_SLOT, SAFE_MODULES_HEAD_SLOT
from utils.logging import record_degraded
from utils.scoring_status import NOT_DETERMINED

logger = logging.getLogger(__name__)

# Distinguishes "function absent" (None) from "RPC raised"; caching the latter would cement misclassification.
_PROBE_ERROR = object()

# Keyed on (rpc_url, address, block_tag); error results aren't cached. 'latest' entries with mutable details (Safe
# owners, timelock delay) use a short TTL.
_CLASSIFY_CACHE: dict[tuple[str, str, str], tuple[ResolvedControllerType, dict[str, object], float]] = {}
_CLASSIFY_CACHE_LOCK = threading.Lock()
_CLASSIFY_CACHE_MAX = 4096
_CLASSIFY_CACHE_TTL_S = float(os.getenv("PSAT_CLASSIFY_CACHE_TTL_S", "1800"))
_CLASSIFY_CACHE_MUTABLE_TTL_S = float(os.getenv("PSAT_CLASSIFY_CACHE_MUTABLE_TTL_S", "60"))

_MUTABLE_DETAIL_KEYS = frozenset({"owners", "threshold", "delay", "min_delay", "erc1967_implementation"})

# Falls back to sequential on whole-batch failure; PSAT_CLASSIFY_BATCH=0 forces sequential.
_CLASSIFY_BATCH_ENABLED = os.getenv("PSAT_CLASSIFY_BATCH", "1").lower() in ("1", "true", "yes")

# Collapse the classify probes (and snapshot getters) into one Multicall3 aggregate3 eth_call. Any anomaly falls back to
# the JSON-RPC path, so results are identical (see the parity tests). PSAT_CLASSIFY_MULTICALL=0 /
# PSAT_SNAPSHOT_MULTICALL=0 are kill switches; tests/conftest.py forces them off because tests stub the per-call wire.
_CLASSIFY_MULTICALL_ENABLED = os.getenv("PSAT_CLASSIFY_MULTICALL", "1").lower() in ("1", "true", "yes")
_SNAPSHOT_MULTICALL_ENABLED = os.getenv("PSAT_SNAPSHOT_MULTICALL", "1").lower() in ("1", "true", "yes")


def type_authority_contract(
    rpc_url: str, address: str, block_tag: str = "latest", *, chain_id: int | None = None
) -> dict[str, object]:
    """Compatibility hook for old callers; authority expansion now happens via semantic predicate capabilities."""
    del rpc_url, address, block_tag, chain_id
    return {}


def clear_classify_cache() -> None:
    from utils.memory import reset_cache_pressure_state

    with _CLASSIFY_CACHE_LOCK:
        _CLASSIFY_CACHE.clear()
    reset_cache_pressure_state("classify")


def _log_classify_pressure() -> None:
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("classify", len(_CLASSIFY_CACHE), _CLASSIFY_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _classify_ttl(block_tag: str, details: dict[str, object]) -> float:
    if block_tag == "latest" and any(key in details for key in _MUTABLE_DETAIL_KEYS):
        return _CLASSIFY_CACHE_MUTABLE_TTL_S
    return _CLASSIFY_CACHE_TTL_S


# ``controller_values.value`` is ``String(66)``. Wider values are almost always struct/array getters with no
# ``member_path`` or huge uint256s, not a single controller identity.
_CONTROLLER_VALUE_MAX_LEN = 66

# Bounded sample of reverted ids for the summary WARNING; the count is the fact.
_REVERTED_SAMPLE_LIMIT = 10


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
    # Refuse here rather than let the INSERT raise StringDataRightTruncation and poison the worker session; the caller
    # records value=None.
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


def _eth_call_raw(
    rpc_url: str, contract_address: str, signature: str, block_tag: str = "latest", *, chain_id: int | None = None
) -> str:
    call = {"to": contract_address, "data": _selector(signature)}
    raw = _rpc_request(rpc_url, "eth_call", [call, block_tag], chain_id=chain_id)
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise RuntimeError(f"Unexpected eth_call result for {signature}: {raw!r}")
    return raw


# ``eth_abi.decode`` ignores trailing bytes, so a catch-all fallback or struct getter would still decode as a plausible
# word. The length check closes that (the negative-control probe is the other defence).
_EXACT_WORD_ABI_TYPES = frozenset({"address", "uint256", "bytes32"})


def _decode_abi_value(raw_value: str, abi_type: str):
    data = bytes.fromhex(_normalize_hex(raw_value)[2:])
    if not data:
        raise RuntimeError("Empty ABI data")
    if abi_type in _EXACT_WORD_ABI_TYPES and len(data) != 32:
        raise RuntimeError(f"{abi_type} return must be exactly 32 bytes, got {len(data)}")
    value = decode([abi_type], data)[0]
    if abi_type == "address":
        return str(value).lower()
    if abi_type == "address[]":
        return [str(item).lower() for item in value]
    return value


def _try_eth_call_decoded(
    rpc_url: str,
    contract_address: str,
    signature: str,
    abi_type: str,
    block_tag: str = "latest",
    *,
    chain_id: int | None = None,
) -> object | None:
    """Decoded value, None (function absent or decode failure), or _PROBE_ERROR (transient; don't cache)."""
    try:
        raw = _eth_call_raw(rpc_url, contract_address, signature, block_tag, chain_id=chain_id)
        if _normalize_hex(raw) in {"0x", "0x0"}:
            return None
        try:
            return _decode_abi_value(raw, abi_type)
        except Exception:
            return None
    except Exception:
        return _PROBE_ERROR


def _get_code(rpc_url: str, address: str, block_tag: str = "latest", *, chain_id: int | None = None) -> str:
    raw = _rpc_request(rpc_url, "eth_getCode", [address, block_tag], chain_id=chain_id)
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
    rpc_url: str, address: str, block_tag: str = "latest", *, chain_id: int | None = None
) -> tuple[ResolvedControllerType, dict[str, object], bool]:
    normalized = _normalize_hex(address)
    cache_key = (rpc_url, normalized, block_tag)
    now = time.monotonic()

    with _CLASSIFY_CACHE_LOCK:
        cached = _CLASSIFY_CACHE.get(cache_key)
        if cached is not None:
            kind, cached_details, inserted_at = cached
            if now - inserted_at < _classify_ttl(block_tag, cached_details):
                return kind, copy.deepcopy(cached_details), True
            del _CLASSIFY_CACHE[cache_key]

    if _CLASSIFY_BATCH_ENABLED:
        kind, details, had_error = _classify_uncached_batched(rpc_url, normalized, block_tag, chain_id=chain_id)
    else:
        kind, details, had_error = _classify_uncached(rpc_url, normalized, block_tag, chain_id=chain_id)

    if not had_error:
        with _CLASSIFY_CACHE_LOCK:
            if len(_CLASSIFY_CACHE) >= _CLASSIFY_CACHE_MAX:
                for old_key in list(_CLASSIFY_CACHE.keys())[: _CLASSIFY_CACHE_MAX // 2]:
                    del _CLASSIFY_CACHE[old_key]
            _CLASSIFY_CACHE[cache_key] = (kind, copy.deepcopy(details), now)
            _log_classify_pressure()

    return kind, details, not had_error


def classify_resolved_address(
    rpc_url: str, address: str, block_tag: str = "latest", *, chain_id: int | None = None
) -> tuple[ResolvedControllerType, dict[str, object]]:
    """Drops the cacheable flag; use the ``_with_status`` form if you keep a cache."""
    kind, details, _cacheable = classify_resolved_address_with_status(rpc_url, address, block_tag, chain_id=chain_id)
    return kind, details


# Canonical control getters in precedence order, for plain ``contract`` principals, since ``classify_resolved_address``
# only reads ``owner()`` for timelock/proxy_admin shapes.
_CONTROLLER_GETTER_SIGS: tuple[str, ...] = ("owner()", "authority()", "admin()")


def read_contract_controllers(
    rpc_url: str, address: str, block_tag: str = "latest", *, chain_id: int | None = None
) -> list[str] | None:
    """The distinct nonzero controllers of a plain contract via ``owner()`` / ``authority()`` / ``admin()``, or
    ``None`` when not dispositively complete.

    Returns the full set: Solmate/Solady ``Auth`` exposes ``owner`` and ``authority`` as parallel control planes, so
    callers must see both and fail closed on ambiguity.

    All getters are always probed. A clean revert, empty or zero return means "not a control plane"; a transient error
    on any getter returns ``None`` (retry), since a plane could be hiding behind it.

    ``[]`` means every canonical getter answered and named nothing. It is not proof of no controller (non-canonical
    getters, the ERC-1967 admin slot); the walk publishes it as ``controllers_not_determined`` (see
    ``services.governance.principals``).
    """
    controllers: list[str] = []
    seen: set[str] = set()
    had_probe_error = False
    # The last call is the negative control: an address answering an unimplemented selector answers everything, so its
    # getter answers aren't evidence.
    calls = [{"to": address, "data": _selector(signature)} for signature in _CONTROLLER_GETTER_SIGS]
    calls.append({"to": address, "data": _selector(_NEGATIVE_CONTROL_SIG)})
    try:
        results = _eth_call_batch(rpc_url, calls, block_tag, chain_id=chain_id)
    except Exception:
        return None
    if len(results) != len(calls):
        return None
    control = results[-1]
    if control.success and _normalize_hex(control.return_data) not in {"0x", "0x0"}:
        # Catch-all fallback: not determined.
        return None
    if not control.success and not _is_definitive_revert(control):
        had_probe_error = True
    for outcome in results[: len(_CONTROLLER_GETTER_SIGS)]:
        if not outcome.success:
            if _is_definitive_revert(outcome):
                continue
            had_probe_error = True
            continue
        raw = outcome.return_data
        if _normalize_hex(raw) in {"0x", "0x0"}:
            continue
        try:
            decoded = _decode_abi_value(raw, "address")
        except Exception:
            # Undecodable as an address: not a plane, and not a transport failure.
            continue
        owner = str(decoded).lower()
        if owner.startswith("0x") and len(owner) == 42 and set(owner[2:]) != {"0"} and owner not in seen:
            seen.add(owner)
            controllers.append(owner)
    if had_probe_error:
        return None
    return controllers


# A bare ``"execution reverted"`` has no data but is still a definitive EVM answer, unlike a transport/OOG failure.
_REVERT_MESSAGE_MARKERS = ("execution reverted", "revert")


def _is_definitive_revert(outcome: Any) -> bool:
    """Did the EVM answer (a revert), or did the read fail to happen?

    Previously every failure was ``_PROBE_ERROR``, so any contract without ``authority()`` tripped the
    incomplete-witness guard and ``terminal_principal.status`` was ``unknown_unfetched`` on every armed row. A revert
    (with or without data) is definitive, since that's how a missing selector fails; transport, timeout and OOG are not.
    Unrecognised stays indeterminate.
    """
    if getattr(outcome, "revert_data", None) is not None:
        return True
    message = str(getattr(outcome, "error_message", "") or "").lower()
    return any(marker in message for marker in _REVERT_MESSAGE_MARKERS)


# A selector nothing implements (0xaa2fed30). An address that answers it has a catch-all fallback, so its per-selector
# answers prove no interface.
_NEGATIVE_CONTROL_SIG = "psatNegativeControlProbeW62()"


def _eth_call_tristate(
    rpc_url: str, address: str, signature: str, block_tag: str, *, chain_id: int | None = None
) -> tuple[str | None, str]:
    """One ``eth_call`` with a revert/transport discriminator: ``(raw, "answered")``, ``(None, "silent")`` on empty
    return or definitive revert, or ``(None, "error")`` when the read didn't dispositively happen (retryable).
    """
    try:
        raw = _eth_call_raw(rpc_url, address, signature, block_tag, chain_id=chain_id)
    except Exception as exc:
        message = str(exc).lower()
        if any(marker in message for marker in _REVERT_MESSAGE_MARKERS):
            return None, "silent"
        return None, "error"
    if _normalize_hex(raw) in {"0x", "0x0"}:
        return None, "silent"
    return raw, "answered"


def _negative_control_probe(rpc_url: str, address: str, block_tag: str, *, chain_id: int | None = None) -> str:
    """Fire the negative control.

    ``"passed"``: the address rejects the nonsense selector, so positive probes are meaningful. ``"failed"``: it answers
    everything, so duck-typed matches are worthless. ``"error"``: not determined; concrete types are withheld and the
    result isn't cached. Called lazily, at most once, only after a duck-typed arm matched.
    """
    raw, state = _eth_call_tristate(rpc_url, address, _NEGATIVE_CONTROL_SIG, block_tag, chain_id=chain_id)
    del raw
    if state == "silent":
        return "passed"
    if state == "answered":
        return "failed"
    return "error"


def _get_storage_at(rpc_url: str, address: str, slot: str, block_tag: str, *, chain_id: int | None = None) -> str:
    """Raw ``eth_getStorageAt``; raises on transport or malformed response. Module-level so tests can stub it."""
    raw = _rpc_request(rpc_url, "eth_getStorageAt", [address, slot, block_tag], chain_id=chain_id)
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise RuntimeError(f"Unexpected eth_getStorageAt result: {raw!r}")
    return raw


# Safe module/guard probe (C1). Modules head: Safe's ``modules`` mapping is at slot 1 seeded with
# ``modules[address(0x1)] = address(0x1)``, so the head is ``keccak256(abi.encode(address(0x1), uint256(1)))``. Guard:
# ``keccak256("guard_manager.guard.address")`` (Safe 1.3.0 and 1.4.1). Canonical values live in ``utils.evm``; tests
# recompute them from the preimages.
_SAFE_MODULES_HEAD_SLOT = SAFE_MODULES_HEAD_SLOT
_SAFE_GUARD_SLOT = SAFE_GUARD_SLOT
_SAFE_SENTINEL_ADDRESS = "0x" + "0" * 39 + "1"

_ADDRESS_WORD_MAX = (1 << 160) - 1

# Releases whose singleton source was checked for ``GUARD_STORAGE_SLOT``. A zero word means "no guard" only on releases
# with the feature; unread variants (e.g. ``1.3.0+L2``) are not_determined.
_SAFE_VERSIONS_WITH_GUARD = frozenset({"1.3.0", "1.4.1"})
_SAFE_VERSIONS_WITHOUT_GUARD = frozenset({"1.1.1"})

_BLOCK_TAG_ALIASES = frozenset({"latest", "pending", "earliest", "safe", "finalized"})


def _resolve_pinned_block(rpc_url: str, block_tag: str, *, chain_id: int | None = None) -> int | None:
    """The integer height the protection probe pins its reads to, or ``None``.

    Aliases are resolved to a number first so ``probe_block`` is the height the words came from. ``None`` (head read
    failed) suppresses the probe: a module set at an unknown height can't be published.
    """
    tag = (block_tag or "").strip().lower()
    if tag.startswith("0x"):
        try:
            return int(tag, 16)
        except ValueError:
            return None
    if tag not in _BLOCK_TAG_ALIASES:
        return None
    try:
        return _current_block_number(rpc_url, chain_id=chain_id)
    except Exception:
        return None


def _word_to_address(word: str | None) -> str | None:
    """The address a 32-byte word holds, or ``None`` if it isn't exactly 64 nibbles or the top 12 bytes are set.

    Uses ``decode_word``; padding first would turn ``"0x1"`` into the modules sentinel.
    """
    value = _decode_word(word)
    if value is None or value > _ADDRESS_WORD_MAX:
        return None
    return "0x" + f"{value:040x}"


def _safe_guard_state(guard_word: str | None, version: str | None) -> tuple[str, str | None]:
    """``(guard_state, guard_address)`` from the guard slot word and VERSION().

    Unread words, unknown versions, and words contradicting the version's feature set are all ``not_determined``.
    """
    if guard_word is None or version is None:
        return NOT_DETERMINED, None
    address = _word_to_address(guard_word)
    if address is None:
        return NOT_DETERMINED, None
    is_zero = address == "0x" + "0" * 40
    if version in _SAFE_VERSIONS_WITH_GUARD:
        return ("proven_zero", None) if is_zero else ("proven_address", address)
    if version in _SAFE_VERSIONS_WITHOUT_GUARD:
        # A nonzero word at an unimplemented slot is unexplained, not "feature_absent".
        return ("feature_absent", None) if is_zero else (NOT_DETERMINED, None)
    return NOT_DETERMINED, None


def _probe_safe_protection(rpc_url: str, address: str, block_tag: str, *, chain_id: int | None = None) -> dict:
    """The Safe module/guard protection witness at a pinned height.

    Two storage words plus ``VERSION()``. The module list isn't walked, so the head only proves emptiness; a
    non-sentinel head proves at least one module (k/n becomes an upper bound on protection) but the set stays
    ``not_determined``. Never raises.
    """
    out: dict[str, object] = {
        "probe_block": NOT_DETERMINED,
        "safe_version": NOT_DETERMINED,
        "modules_head": NOT_DETERMINED,
        "module_set": NOT_DETERMINED,
        "module_set_basis": NOT_DETERMINED,
        "protection_is_upper_bound": NOT_DETERMINED,
        "guard": NOT_DETERMINED,
    }
    probe_block = _resolve_pinned_block(rpc_url, block_tag, chain_id=chain_id)
    if probe_block is None:
        return out
    out["probe_block"] = probe_block
    pinned = hex(probe_block)

    decoded_version = _try_eth_call_decoded(rpc_url, address, "VERSION()", "string", pinned, chain_id=chain_id)
    version = decoded_version if isinstance(decoded_version, str) else None
    if version is not None:
        out["safe_version"] = version

    def _word(slot: str) -> str | None:
        """The 32-byte word at ``slot``, or ``None`` for a failed or malformed read.

        Nothing is padded: a short or odd reply isn't a word, and padding it would mint a sentinel or zero from a
        non-observation.
        """
        try:
            raw = _get_storage_at(rpc_url, address, slot, pinned, chain_id=chain_id)
        except Exception:
            return None
        if not isinstance(raw, str) or _decode_word(raw) is None:
            return None
        return "0x" + raw[2:].lower()

    head_word = _word(_SAFE_MODULES_HEAD_SLOT)
    if head_word is not None:
        out["modules_head"] = head_word
        head_address = _word_to_address(head_word)
        if head_address == _SAFE_SENTINEL_ADDRESS:
            out["module_set"] = []
            out["module_set_basis"] = "storage_linked_list_terminated"
        elif head_address is not None and head_address != "0x" + "0" * 40:
            # A module can act without meeting the threshold, so k/n bounds protection from above. Count stays unknown.
            out["protection_is_upper_bound"] = True
            out["modules_head_address"] = head_address

    out["guard"], guard_address = _safe_guard_state(_word(_SAFE_GUARD_SLOT), version)
    if guard_address is not None:
        out["guard_address"] = guard_address
    return out


# Read by selector with a negative control, not by name. The published fact is address equality at a pinned height.
_BACKLINK_GETTER_SIG = "vault()"


def probe_declared_vault_backlink(
    rpc_url: str,
    principal_address: str,
    gated_contract_address: str,
    block_tag: str = "latest",
    *,
    chain_id: int | None = None,
) -> dict[str, object] | None:
    """Does *principal_address* declare *gated_contract_address* as its ``vault()``, at a pinned height, with the
    negative control passed?

    This corroborates the (M, V) pairing structurally. It says nothing about what M is: half the positive pairs
    on the corpus are Tellers, solvers and vaults, not managers.

    Returns ``None`` when the height can't be pinned. ``declared_vault_matches_gated_contract`` is ``True`` or
    ``"not_determined"``, never false, since a mismatch doesn't disprove a pairing established otherwise.

    The non-match payload must be byte-identical to the never-read payload. The control only fires after a decodable
    address, so publishing its verdict on a mismatch would reveal the mismatch. It's recorded only on the positive arm.
    (The raw ``vault`` address is already published via ``controller_value`` edges.)
    """
    probe_block = _resolve_pinned_block(rpc_url, block_tag, chain_id=chain_id)
    if probe_block is None:
        return None
    pinned = hex(probe_block)
    # Names the verdict's subject so a later graph merge can't reattribute it.
    out: dict[str, object] = {
        "probe_block": probe_block,
        "backlink_getter": _BACKLINK_GETTER_SIG,
        "gated_contract_address": (gated_contract_address or "").lower(),
        "backlink_address": NOT_DETERMINED,
        "negative_control": NOT_DETERMINED,
        "declared_vault_matches_gated_contract": NOT_DETERMINED,
    }

    declared = _try_eth_call_decoded(
        rpc_url, principal_address, _BACKLINK_GETTER_SIG, "address", pinned, chain_id=chain_id
    )
    if not isinstance(declared, str):
        # No positive result, so no control is fired.
        return out

    if declared.lower() != (gated_contract_address or "").lower():
        # Deliberately identical to the branch above; recording a control verdict here would leak the mismatch.
        return out

    control = _negative_control_probe(rpc_url, principal_address, pinned, chain_id=chain_id)
    if control != "passed":
        # Safe to record here: only reached on a match, so it reveals nothing about the pairing.
        out["negative_control"] = control
        return out

    out["negative_control"] = control
    out["backlink_address"] = declared.lower()
    out["declared_vault_matches_gated_contract"] = True
    return out


def _read_erc1967_implementation(rpc_url: str, address: str, block_tag: str, *, chain_id: int | None = None) -> object:
    """The ERC-1967 implementation slot: an address when nonzero (a proxy), ``None`` when zero, ``_PROBE_ERROR`` when
    the read didn't happen. "Zero" requires a full 64-nibble zero word.
    """
    try:
        raw = _get_storage_at(rpc_url, address, EIP1967_IMPL_SLOT, block_tag, chain_id=chain_id)
    except Exception:
        return _PROBE_ERROR
    word = raw[2:].lower()
    if len(word) != 64 or set(word) - set("0123456789abcdef"):
        return _PROBE_ERROR
    if set(word) == {"0"}:
        return None
    return "0x" + word[-40:]


def _resolve_uiv_shape(
    rpc_url: str,
    normalized: str,
    block_tag: str,
    upgrade_interface_version: object,
    owner: object | None,
    *,
    chain_id: int | None = None,
) -> tuple[ResolvedControllerType, dict[str, object], bool]:
    """Type an address whose ``UPGRADE_INTERFACE_VERSION()`` answered.

    UIV is compiled into ``UUPSUpgradeable`` (answered through every OZ-v5 UUPS proxy and by bare implementations) and
    the v5 ``ProxyAdmin``, but not the v4 ``ProxyAdmin``. Typing on UIV alone labelled proxies as proxy admins.

    * ERC-1967 slot nonzero: a proxy, ``contract`` (non-terminal) with ``erc1967_implementation``.
    * Slot zero and ``proxiableUUID()`` answers: bare UUPS implementation, ``contract`` with ``uups_implementation``.
    * Slot zero, no ``proxiableUUID()``, ``owner()`` answers: v5 ``ProxyAdmin``, ``proxy_admin``.
    * Any read failing: ``contract`` with ``had_error`` so it isn't cached.

    Returns ``(kind, details, had_probe_error)``.
    """
    details: dict[str, object] = {
        "address": normalized,
        "upgrade_interface_version": str(upgrade_interface_version),
    }
    if owner is not None:
        details["owner"] = owner
    impl = _read_erc1967_implementation(rpc_url, normalized, block_tag, chain_id=chain_id)
    if impl is _PROBE_ERROR:
        return "contract", details, True
    if impl is not None:
        details["erc1967_implementation"] = impl
        return "contract", details, False
    raw, state = _eth_call_tristate(rpc_url, normalized, "proxiableUUID()", block_tag, chain_id=chain_id)
    if state == "error":
        return "contract", details, True
    if state == "answered" and raw is not None:
        try:
            decoded = _decode_abi_value(raw, "bytes32")
        except Exception:
            decoded = None
        if decoded is not None:
            details["uups_implementation"] = True
            return "contract", details, False
        # Not a bytes32: neither UUPS nor a v5 ProxyAdmin.
        return "contract", details, False
    if owner is not None:
        return "proxy_admin", details, False
    return "contract", details, False


# Order matters: ``_classify_uncached_batched`` unpacks by index.
_CLASSIFY_PROBE_SIGS: tuple[tuple[str, str], ...] = (
    ("getOwners()", "address[]"),  # 0: Safe
    ("getThreshold()", "uint256"),  # 1: Safe
    ("getMinDelay()", "uint256"),  # 2: Timelock primary
    ("delay()", "uint256"),  # 3: Timelock fallback
    ("UPGRADE_INTERFACE_VERSION()", "string"),  # 4: OZ-v5 upgrade machinery (see _resolve_uiv_shape)
    ("owner()", "address"),  # 5: Timelock + ProxyAdmin secondary
)


def _decode_probe_result(raw: object, abi_type: str) -> object | None:
    """Decode a pre-fetched probe result; None on empty or decode failure."""
    if not isinstance(raw, str):
        return None
    if _normalize_hex(raw) in {"0x", "0x0"}:
        return None
    try:
        return _decode_abi_value(raw, abi_type)
    except Exception:
        return None


def _batch_probe(rpc_url: str, address: str, block_tag: str, *, chain_id: int | None = None) -> list[object]:
    """Fire all classify probes in one JSON-RPC batch; per-slot errors become _PROBE_ERROR."""
    calls = [("eth_call", [{"to": address, "data": _selector(sig)}, block_tag]) for sig, _abi in _CLASSIFY_PROBE_SIGS]
    raw_results = _rpc_batch_request_with_status(rpc_url, calls, chain_id=chain_id)
    decoded: list[object] = []
    for (raw, had_err), (_sig, abi_type) in zip(raw_results, _CLASSIFY_PROBE_SIGS):
        if had_err:
            decoded.append(_PROBE_ERROR)
            continue
        decoded.append(_decode_probe_result(raw, abi_type))
    return decoded


def _multicall_probe(rpc_url: str, address: str, block_tag: str, *, chain_id: int | None = None) -> list[object]:
    """The classify probes as one Multicall3 aggregate3 call.

    They're caller-independent view getters, so values are identical; reverts become ``_PROBE_ERROR``. Raises on
    transport/malformed response so the caller can fall back.
    """
    from services.clients.rpc import multicall3_aggregate3

    calls = [(address, _selector(sig)) for sig, _abi in _CLASSIFY_PROBE_SIGS]
    raw_results = multicall3_aggregate3(rpc_url, calls, block_tag, chain_id=chain_id)
    decoded: list[object] = []
    for (success, raw), (_sig, abi_type) in zip(raw_results, _CLASSIFY_PROBE_SIGS):
        if not success:
            decoded.append(_PROBE_ERROR)
            continue
        decoded.append(_decode_probe_result(raw, abi_type))
    return decoded


def _probe_classify(rpc_url: str, address: str, block_tag: str, *, chain_id: int | None = None) -> list[object]:
    """Multicall3 when enabled, falling back to the JSON-RPC batch on any failure."""
    if _CLASSIFY_MULTICALL_ENABLED:
        try:
            return _multicall_probe(rpc_url, address, block_tag, chain_id=chain_id)
        except Exception:
            pass
    return _batch_probe(rpc_url, address, block_tag, chain_id=chain_id)


def _classify_uncached_batched(
    rpc_url: str, normalized: str, block_tag: str, *, chain_id: int | None = None
) -> tuple[ResolvedControllerType, dict[str, object], bool]:
    """``_classify_uncached`` with the probes batched upfront, saving round trips for generic contracts."""
    if normalized == "0x0000000000000000000000000000000000000000":
        return "zero", {"address": normalized}, False

    try:
        code = _get_code(rpc_url, normalized, block_tag, chain_id=chain_id)
    except Exception:
        return "contract", {"address": normalized}, True
    if code in {"0x", "0x0"}:
        return "eoa", {"address": normalized}, False

    # Skip the batch when the bytecode matches a canonical impl.
    if _KNOWN_BYTECODE_IMPLS:
        try:
            from services.clients.rpc import get_code_with_keccak

            _, bytecode_keccak = get_code_with_keccak(rpc_url, normalized, chain_id=chain_id)
        except Exception:
            bytecode_keccak = None
        if bytecode_keccak is not None:
            hit = _KNOWN_BYTECODE_IMPLS.get(bytecode_keccak)
            if hit is not None:
                kind, partial = hit
                details: dict[str, object] = {"address": normalized}
                details.update(partial)
                return kind, details, False

    probes = _probe_classify(rpc_url, normalized, block_tag, chain_id=chain_id)
    # Whole-batch failure: fall back to sequential so batch-rejecting providers aren't degraded.
    if all(p is _PROBE_ERROR for p in probes):
        return _classify_uncached(rpc_url, normalized, block_tag, chain_id=chain_id)
    safe_owners_raw, safe_threshold_raw, min_delay_a, min_delay_b, upgrade_iv, owner_raw = probes

    def _ok(v: object) -> object | None:
        if v is _PROBE_ERROR:
            return None
        return v

    had_error = any(p is _PROBE_ERROR for p in probes)
    # Lazy negative control: publish a duck-typed kind only if the address rejects an unimplemented selector.
    control_state: list[str | None] = [None]

    def _duck_type_permitted() -> bool:
        if control_state[0] is None:
            control_state[0] = _negative_control_probe(rpc_url, normalized, block_tag, chain_id=chain_id)
        return control_state[0] == "passed"

    safe_owners = _ok(safe_owners_raw)
    safe_threshold = _ok(safe_threshold_raw)
    if safe_owners is not None and safe_threshold is not None and _duck_type_permitted():
        return (
            "safe",
            {
                "address": normalized,
                "owners": [str(item).lower() for item in safe_owners] if isinstance(safe_owners, list) else [],
                "threshold": _coerce_int(safe_threshold),
                # Nested so module_set is never read without its probe_block.
                "safe_protection": _probe_safe_protection(rpc_url, normalized, block_tag, chain_id=chain_id),
            },
            had_error,
        )

    min_delay = _ok(min_delay_a)
    if min_delay is None:
        min_delay = _ok(min_delay_b)
    if min_delay is not None and _duck_type_permitted():
        owner = _ok(owner_raw)
        details: dict[str, object] = {"address": normalized, "delay": _coerce_int(min_delay)}
        if owner is not None:
            details["owner"] = owner
        return "timelock", details, had_error

    upgrade_interface_version = _ok(upgrade_iv)
    if upgrade_interface_version is not None and _duck_type_permitted():
        kind, details, uiv_err = _resolve_uiv_shape(
            rpc_url, normalized, block_tag, upgrade_interface_version, _ok(owner_raw), chain_id=chain_id
        )
        return kind, details, had_error or uiv_err

    details = {"address": normalized}
    try:
        details.update(type_authority_contract(rpc_url, normalized, block_tag, chain_id=chain_id))
    except Exception:
        had_error = True
    if control_state[0] == "failed":
        # Published so consumers can tell a plain contract from a catch-all.
        details["duck_type_negative_control"] = "failed"
    elif control_state[0] == "error":
        had_error = True
    return "contract", details, had_error


# Canonical-impl bytecode keccak registry; empty by default (tests monkeypatch it).
_KNOWN_BYTECODE_IMPLS: dict[str, tuple[ResolvedControllerType, dict[str, object]]] = {}


def _classify_uncached(
    rpc_url: str, normalized: str, block_tag: str, *, chain_id: int | None = None
) -> tuple[ResolvedControllerType, dict[str, object], bool]:
    """The classifier. Returns ``(kind, details, had_rpc_error)``; don't cache when had_rpc_error."""
    if normalized == "0x0000000000000000000000000000000000000000":
        return "zero", {"address": normalized}, False

    try:
        code = _get_code(rpc_url, normalized, block_tag, chain_id=chain_id)
    except Exception:
        return "contract", {"address": normalized}, True
    if code in {"0x", "0x0"}:
        return "eoa", {"address": normalized}, False

    # Skip the probe sequence when the bytecode matches a registered canonical impl.
    if _KNOWN_BYTECODE_IMPLS:
        try:
            from services.clients.rpc import get_code_with_keccak

            _, bytecode_keccak = get_code_with_keccak(rpc_url, normalized, chain_id=chain_id)
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
        result = _try_eth_call_decoded(rpc_url, normalized, signature, abi_type, block_tag, chain_id=chain_id)
        if result is _PROBE_ERROR:
            had_error = True
            return None
        return result

    # Same lazy negative-control gate as the batched path.
    control_state: list[str | None] = [None]

    def _duck_type_permitted() -> bool:
        if control_state[0] is None:
            control_state[0] = _negative_control_probe(rpc_url, normalized, block_tag, chain_id=chain_id)
        return control_state[0] == "passed"

    safe_owners = _probe("getOwners()", "address[]")
    safe_threshold = _probe("getThreshold()", "uint256")
    if safe_owners is not None and safe_threshold is not None and _duck_type_permitted():
        return (
            "safe",
            {
                "address": normalized,
                "owners": [str(item).lower() for item in safe_owners] if isinstance(safe_owners, list) else [],
                "threshold": _coerce_int(safe_threshold),
                "safe_protection": _probe_safe_protection(rpc_url, normalized, block_tag, chain_id=chain_id),
            },
            had_error,
        )

    min_delay = _probe("getMinDelay()", "uint256")
    if min_delay is None:
        min_delay = _probe("delay()", "uint256")
    if min_delay is not None and _duck_type_permitted():
        owner = _probe("owner()", "address")
        details: dict[str, object] = {"address": normalized, "delay": _coerce_int(min_delay)}
        if owner is not None:
            details["owner"] = owner
        return "timelock", details, had_error

    upgrade_interface_version = _probe("UPGRADE_INTERFACE_VERSION()", "string")
    if upgrade_interface_version is not None and _duck_type_permitted():
        owner = _probe("owner()", "address")
        kind, details, uiv_err = _resolve_uiv_shape(
            rpc_url, normalized, block_tag, upgrade_interface_version, owner, chain_id=chain_id
        )
        return kind, details, had_error or uiv_err

    details = {"address": normalized}
    try:
        details.update(type_authority_contract(rpc_url, normalized, block_tag, chain_id=chain_id))
    except Exception:
        had_error = True
    if control_state[0] == "failed":
        details["duck_type_negative_control"] = "failed"
    elif control_state[0] == "error":
        had_error = True
    return "contract", details, had_error


def _current_block_number(rpc_url: str, *, chain_id: int | None = None) -> int:
    raw = _rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise RuntimeError(f"Unexpected eth_blockNumber result: {raw!r}")
    return int(raw, 16)


def _getter_target(source: str, read_spec: ControllerReadSpec | None) -> str:
    """The getter name ``_read_polling_source`` reads a controller through (``source`` unless a ``getter_call``
    read_spec overrides it). Shared with the Multicall3 prewarm so selectors agree.
    """
    target = source
    if isinstance(read_spec, dict) and read_spec.get("strategy") == "getter_call":
        read_target = read_spec.get("target")
        if isinstance(read_target, str) and read_target:
            target = read_target
    return target


def _read_polling_source(
    rpc_url: str,
    contract_address: str,
    source: str,
    controller_kind: str,
    block_tag: str = "latest",
    read_spec: ControllerReadSpec | None = None,
    *,
    prewarm: dict[tuple[str, str], str] | None = None,
    chain_id: int | None = None,
) -> str:
    signature = f"{_getter_target(source, read_spec)}()"
    if prewarm is not None:
        # Only successful prewarm reads are cached, so reverting getters still take the live read and impl fallback.
        cached = prewarm.get((contract_address.lower(), _selector(signature)))
        if cached is not None:
            return _decode_controller_value(cached, controller_kind, read_spec)
    raw = _eth_call_raw(rpc_url, contract_address, signature, block_tag, chain_id=chain_id)
    return _decode_controller_value(raw, controller_kind, read_spec)


def _prewarm_snapshot_getters(
    rpc_url: str, plan: ControlTrackingPlan, block_tag: str, *, chain_id: int | None = None
) -> dict[tuple[str, str], str]:
    """Pre-read every tracked controller's getter in one Multicall3 at the snapshot's ``block_tag``.

    Returns ``{(contract_addr_lower, selector): raw}`` for successful reads only. Best-effort: any failure returns
    ``{}``.
    """
    contract_address = plan["contract_address"]
    selectors: list[str] = []
    seen: set[str] = set()
    for controller in plan.get("tracked_controllers", []):
        read_spec = controller.get("read_spec")
        # Primitive-scalar state vars are never read on-chain (see _compute_controller).
        if controller.get("kind") == "state_variable" and is_primitive_scalar_read_spec(read_spec):
            continue
        try:
            sel = _selector(f"{_getter_target(controller['source'], read_spec)}()")
        except Exception:
            continue
        if sel not in seen:
            seen.add(sel)
            selectors.append(sel)
    if not selectors:
        return {}
    from services.clients.rpc import multicall3_aggregate3

    try:
        results = multicall3_aggregate3(
            rpc_url, [(contract_address, sel) for sel in selectors], block_tag, chain_id=chain_id
        )
    except Exception:
        return {}
    key_addr = contract_address.lower()
    prewarm: dict[tuple[str, str], str] = {}
    for sel, (success, raw) in zip(selectors, results):
        if success and isinstance(raw, str) and raw.startswith("0x"):
            prewarm[(key_addr, sel)] = raw
    return prewarm


def build_control_snapshot(
    plan: ControlTrackingPlan,
    rpc_url: str,
    block_tag: str = "latest",
    *,
    heartbeat: Callable[[], None] | None = None,
    getter_fallback_address: str | None = None,
    beacon_address: str | None = None,
    chain_id: int | None = None,
) -> ControlSnapshot:
    """Resolve every tracked controller's value at the given block.

    ``getter_fallback_address`` is the implementation to retry a reverting getter against: ``immutable`` authority
    addresses live in implementation bytecode and revert on beacon/per-instance runtimes.

    ``beacon_address`` is the governing UpgradeableBeacon, whose ``owner()`` is the instance's upgrade authority; it's
    recorded as a ``beacon_owner`` controller.
    """
    from services.concurrency import parallel_map

    def _call_with_heartbeat(fn: Callable[[], int]) -> int:
        if heartbeat is None:
            return fn()
        results = parallel_map(lambda _item: fn(), [None], max_workers=1, heartbeat=heartbeat)
        outcome = results[0][1]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    block_number = (
        _call_with_heartbeat(lambda: _current_block_number(rpc_url, chain_id=chain_id))
        if block_tag == "latest"
        else int(block_tag, 16)
    )
    # One Multicall3 up front; ``{}`` when disabled or failed.
    prewarm = (
        _prewarm_snapshot_getters(rpc_url, plan, block_tag, chain_id=chain_id) if _SNAPSHOT_MULTICALL_ENABLED else {}
    )
    controller_values: dict[str, Any] = {}

    def _compute_controller(controller: TrackedController) -> tuple[str, dict[str, Any] | None]:
        """Compute one controller's value dict, or None to skip."""
        controller_id = controller["controller_id"]
        source = controller["source"]
        read_spec = controller.get("read_spec")
        # Scalars are in the plan only for event watching. Reading them as addresses mints phantom EOAs (e.g.
        # ``_minDelay`` 864000 becomes 0x…0d2f00). Mapping/array/struct slots pass through; they're enumerated
        # elsewhere.
        if controller["kind"] == "state_variable" and is_primitive_scalar_read_spec(read_spec):
            return controller_id, None
        spec = read_spec if isinstance(read_spec, dict) else None

        def _read_entry(read_address: str, observed_via: str) -> dict[str, Any]:
            value = _read_polling_source(
                rpc_url,
                read_address,
                source,
                controller["kind"],
                block_tag,
                read_spec=spec,
                prewarm=prewarm,
                chain_id=chain_id,
            )
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
                        # Membership is enforced at the runtime address even if the role id came from the
                        # implementation.
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
            resolved_type, details = classify_resolved_address(rpc_url, value, block_tag, chain_id=chain_id)
            entry["resolved_type"] = resolved_type
            entry["details"] = details
            return entry

        try:
            return controller_id, _read_entry(plan["contract_address"], "eth_call")
        except Exception as exc:
            # Immutable authority addresses live in implementation bytecode and revert on beacon/per-instance runtimes
            # (e.g. EtherFiNode). Retrying on the impl recovers them; storage getters just read zero there.
            if getter_fallback_address and getter_fallback_address.lower() != str(plan["contract_address"]).lower():
                try:
                    entry = _read_entry(getter_fallback_address, "eth_call_impl_fallback")
                except Exception:
                    pass
                else:
                    logger.debug(
                        "controller read recovered via impl getter-fallback",
                        extra={
                            "controller_id": controller_id,
                            "address": plan["contract_address"],
                            "fallback_address": getter_fallback_address,
                            "decision": "impl_getter_fallback",
                        },
                    )
                    return controller_id, entry
            # Both reads reverted: record NULL. ``record_degraded`` keeps the per-controller witness; the log is DEBUG
            # because the per-snapshot count below is the useful line.
            record_degraded(
                phase="controller_read",
                exc=exc,
                context={"controller_id": controller_id, "address": plan["contract_address"]},
            )
            logger.debug(
                "controller read reverted; recording NULL value",
                extra={
                    "controller_id": controller_id,
                    "address": plan["contract_address"],
                    "exc_type": type(exc).__name__,
                },
            )
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
            # ``_compute_controller`` converts internal failures to entries, so anything here is a bug.
            raise outcome
        cid, entry = outcome
        if entry is None:
            continue
        # Provenance is static, so it applies whether or not the read succeeded.
        provenance = _controller.get("authority_provenance") if isinstance(_controller, dict) else None
        if provenance:
            entry["authority_provenance"] = provenance
        controller_values[cid] = entry

    # One WARNING per snapshot, partitioned from the entries themselves so no counter crosses threads.
    reverted = [cid for cid, entry in controller_values.items() if entry.get("observed_via") == "eth_call_error"]
    if reverted:
        logger.warning(
            "%d of %d tracked controller reads reverted; recorded NULL",
            len(reverted),
            len(controller_values),
            extra={
                "reverted_controllers": len(reverted),
                "tracked_controllers": len(controller_values),
                # Not ``address``: that contextvar is bound per job and the formatter drops a colliding extra.
                "contract_address": plan["contract_address"],
                "block_number": block_number,
                "reverted_sample": sorted(reverted)[:_REVERTED_SAMPLE_LIMIT],
            },
        )

    if beacon_address:
        beacon_entry = _read_beacon_owner(rpc_url, beacon_address, block_tag, block_number, chain_id=chain_id)
        if beacon_entry is not None:
            controller_values["beacon_owner"] = beacon_entry

    return {
        "schema_version": "0.1",
        "contract_address": plan["contract_address"],
        "contract_name": plan["contract_name"],
        "block_number": block_number,
        "controller_values": controller_values,
    }


def _read_beacon_owner(
    rpc_url: str, beacon_address: str, block_tag: str, block_number: int, *, chain_id: int | None = None
) -> dict[str, Any] | None:
    """Read the governing beacon's ``owner()`` as an upgrade-authority controller value, or ``None`` if it reverts or
    is zero.
    """
    try:
        raw = _eth_call_raw(rpc_url, beacon_address, "owner()", block_tag, chain_id=chain_id)
        owner = _decode_controller_value(raw, "external_contract")
    except Exception as exc:
        logger.debug("beacon owner read failed for %s: %s", beacon_address, exc)
        return None
    if not owner or owner in {"0x", "0x0"} or set(owner.replace("0x", "")) <= {"0"}:
        return None
    resolved_type, details = classify_resolved_address(rpc_url, owner, block_tag, chain_id=chain_id)
    details = {**details, "source": "beacon", "beacon_address": beacon_address.lower()}
    return {
        "source": "beacon",
        "value": owner,
        "block_number": block_number,
        "observed_via": "beacon_owner",
        "resolved_type": resolved_type,
        "details": details,
    }
