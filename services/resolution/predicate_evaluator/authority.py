"""Authority getter tables and live authority reads."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from utils.evm import OWNER_SELECTOR

from ..capabilities import (
    CapabilityExpr,
    ExternalCheck,
)
from .binding import _selector_for_signature
from .telemetry import _bump_resolve_counter, _is_zero_address, _pass_live_read_memo

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger("services.resolution.predicate_evaluator")


def _nullary_getter_selector(name: str | None) -> str | None:
    """4-byte selector for ``<name>()``, or ``None`` for an empty name."""
    if not isinstance(name, str) or not name:
        return None
    return _selector_for_signature(f"{name}()")


# Canonical public authority getters. Gates often read authority via a non-callable accessor (``_governor()``, a slot
# constant, an ERC-7201 struct member); every such standard also exposes the canonical getter over the same storage, so
# read that instead.
_OWNER_SELECTOR = OWNER_SELECTOR
_GOVERNOR_SELECTOR = "0x0c340a24"  # governor()
_AUTHORITY_SELECTOR = "0xbf7e214f"  # authority()

# Ownership renounced to 0x…dEaD: no live controller, so don't mint it as a principal.
_BURN_ADDRESS = "0x" + "00" * 18 + "dead"

# Keyword to canonical getter for slot-constant operands, matched as a substring of a storage-locator name
# (``_OWNER_SLOT``, OZ-v5 ``OwnableStorageLocation`` via "ownable", ``_GOVERNOR_SLOT``, ``AuthorityStorageLocation``).
#
# This is the one selection here that a name decides, with nothing to cross-check the result against. So names matching
# several roles are refused, and the winner stamps ``authority_getter_basis`` into the trace.
_SLOT_KEYWORD_TO_GETTER = (
    ("governor", _GOVERNOR_SELECTOR),
    ("authority", _AUTHORITY_SELECTOR),
    ("ownable", _OWNER_SELECTOR),
    ("owner", _OWNER_SELECTOR),
)

# The internal-accessor fallback only de-underscores these (optionally ``pending``-prefixed); an arbitrary ``_x()``
# stays fail-closed, since a wrong controller is worse than a missing one.
_AUTHORITY_GETTER_BASENAMES = frozenset({"owner", "governor", "authority"})


def _live_authority_result(read_addr: str, selector: str, contract: str, block: int | None = None) -> CapabilityExpr:
    """The capability a completed live authority read yields (fresh or memoized).

    * A concrete address: exact singleton.
    * The zero word: exact empty, ``owner_read_zero``, with provenance (getter, contract, height), since it's the
    strongest negative this module publishes.
    * ``0x…dEaD``: lower_bound empty, ``owner_read_burn_address``. 0x0 can't be ``msg.sender`` but dEaD is only believed
    keyless.

    ``observed_at_block`` is set only when the call was pinned; ``latest`` reads have no height to state.
    """
    step: dict[str, Any] = {"step": "live_getter_resolution", "selector": selector, "contract": contract.lower()}
    if isinstance(block, int) and not isinstance(block, bool):
        step["observed_at_block"] = block
    if not (isinstance(read_addr, str) and read_addr.startswith("0x") and len(read_addr) == 42):
        # Not address-shaped: fail closed.
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="bad_input", trace=[step]
        )
    if _is_zero_address(read_addr):
        return CapabilityExpr.finite_set(
            [], quality="exact", confidence="enumerable", empty_reason="owner_read_zero", trace=[step]
        )
    if read_addr.lower() == _BURN_ADDRESS:
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
            empty_reason="owner_read_burn_address",
            trace=[{**step, "read_address": read_addr.lower()}],
        )
    return CapabilityExpr.finite_set(
        [read_addr],
        quality="exact",
        confidence="enumerable",
        trace=[step],
    )


def _live_resolve_authority(ctx: EvaluationContext | None, selector: str | None) -> CapabilityExpr | None:
    """Resolve ``msg.sender == X`` by reading ``X`` live when ``state_var_values`` lacks it.

    Returns exact ``[addr]``, exact ``[]`` for the zero address, a labelled lower_bound empty when the read was
    attempted but unreadable (``unreadable_revert`` / ``unreadable_empty``), or ``None`` when nothing was attempted (no
    RPC, bad selector or address). The last two let the caller try a fallback getter while recording why the placeholder
    is empty.
    """
    if ctx is None or not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        return None
    outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    rpc_url = getattr(outer, "rpc_url", None)
    contract = getattr(outer, "contract_address", None) or ctx.contract_address
    block = getattr(outer, "block", None) if outer is not None else ctx.block
    if not isinstance(rpc_url, str) or not rpc_url:
        return None
    if not isinstance(contract, str) or not contract.startswith("0x") or len(contract) != 42:
        return None
    # Pass-scoped dedup of deterministic getter reads; only successes are memoized so failures retry independently.
    memo = _pass_live_read_memo(outer)
    block_repr = block if isinstance(block, int) else "latest"
    memo_key = ("live_authority", rpc_url, contract.lower(), selector, block_repr)
    if memo is not None and memo_key in memo:
        _bump_resolve_counter(outer, "live_getter_memo_hits")
        # Pass ``block`` so a memo hit reproduces ``observed_at_block``.
        return _live_authority_result(memo[memo_key], selector, contract, block if isinstance(block, int) else None)

    _bump_resolve_counter(outer, "live_getter_calls")
    try:
        from services.clients.rpc import rpc_request

        raw = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": contract.lower(), "data": selector}, hex(block) if isinstance(block, int) else "latest"],
            retries=1,
            chain_id=getattr(outer, "chain_id", None),
        )
    except Exception:
        _bump_resolve_counter(outer, "live_getter_failures")
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="unreadable_revert"
        )
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="unreadable_empty"
        )
    addr = "0x" + raw[-40:].lower()
    # Memoize the raw address so zero and burn stay distinct.
    if memo is not None:
        memo[memo_key] = addr
    return _live_authority_result(addr, selector, contract, block if isinstance(block, int) else None)


def _live_resolve_authority_slot(
    ctx: EvaluationContext | None,
    slot: str | None,
) -> CapabilityExpr | None:
    """Resolve ``msg.sender == <getter-less slot reader>`` by reading the storage slot live.

    Covers internal accessors that ``sload`` a constant slot (Governable ``_pendingGovernor``) and non-public address
    state vars (``MembershipNFT.membershipManager``, sequential slot). Read at the runtime address (the proxy when
    linked).

    Same outcomes as :func:`_live_resolve_authority`, with ``slot_read_zero`` for a zero slot. Classifying a zero as an
    accept-side ceiling is :func:`_pending_ceiling_capability`'s job, since it rests on the accessor name.
    """
    if ctx is None or not isinstance(slot, str) or not slot.startswith("0x") or len(slot) != 66:
        return None
    outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    rpc_url = getattr(outer, "rpc_url", None)
    contract = getattr(outer, "contract_address", None) or ctx.contract_address
    block = getattr(outer, "block", None) if outer is not None else ctx.block
    if not isinstance(rpc_url, str) or not rpc_url:
        return None
    if not isinstance(contract, str) or not contract.startswith("0x") or len(contract) != 42:
        return None
    _bump_resolve_counter(outer, "live_slot_calls")
    try:
        from services.clients.rpc import rpc_request

        raw = rpc_request(
            rpc_url,
            "eth_getStorageAt",
            [contract.lower(), slot, hex(block) if isinstance(block, int) else "latest"],
            retries=1,
            chain_id=getattr(outer, "chain_id", None),
        )
    except Exception:
        _bump_resolve_counter(outer, "live_slot_failures")
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="unreadable_revert"
        )
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return CapabilityExpr.finite_set(
            [], quality="lower_bound", confidence="partial", empty_reason="unreadable_empty"
        )
    addr = "0x" + raw[-40:].lower()
    step: dict[str, Any] = {"step": "live_slot_resolution", "slot": slot, "contract": contract.lower()}
    if isinstance(block, int) and not isinstance(block, bool):
        step["observed_at_block"] = block
    if _is_zero_address(addr):
        return CapabilityExpr.finite_set(
            [], quality="exact", confidence="enumerable", empty_reason="slot_read_zero", trace=[step]
        )
    if addr == _BURN_ADDRESS:
        # A burned slot isn't a proven "nobody".
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
            empty_reason="owner_read_burn_address",
            trace=[{**step, "read_address": addr}],
        )
    return CapabilityExpr.finite_set(
        [addr],
        quality="exact",
        confidence="enumerable",
        trace=[step],
    )


def _resolve_authority_via_getters(
    ctx: EvaluationContext | None,
    selectors: list[str | None],
    *,
    bases: list[str] | None = None,
) -> CapabilityExpr | None:
    """Read an authority through the first of ``selectors`` that gives a concrete answer.

    ``bases`` records why each selector was tried (``abi_auto_getter``, a name match, or ``callee_selector``); the
    winner's basis goes into the trace. Only ``abi_auto_getter`` outranks the name-matched arms, which are unordered
    among themselves.

    Short-circuits only on an exact read, so a reverting literal getter falls through (the internal-accessor and
    slot-constant fallbacks rely on this). If all were unreadable, returns the last labelled lower_bound empty; ``None``
    only when nothing was attempted.
    """
    attempted_failure: CapabilityExpr | None = None
    for index, selector in enumerate(selectors):
        if selector is None:
            continue
        live = _live_resolve_authority(ctx, selector)
        if live is None:
            continue
        if live.membership_quality == "exact":
            basis = bases[index] if bases is not None and index < len(bases) else None
            if basis is not None:
                live.trace.append({"step": "authority_getter_basis", "basis": basis, "selector": selector})
            return live
        attempted_failure = live
    return attempted_failure


def _public_getter_selector_for_internal_accessor(signature: str | None) -> str | None:
    """Selector for the public getter behind a nullary internal authority accessor, or ``None``.

    ``_governor()`` → ``governor()``, ``_owner()`` → ``owner()``: the leading-underscore convention is shared across OZ,
    Solady, Solmate and Governable. Limited to owner/governor/authority (optionally pending) to fail closed.
    """
    if not isinstance(signature, str) or not signature.endswith("()"):
        return None
    name = signature[:-2]
    if not name.startswith("_") or "(" in name:
        return None
    public_name = name.lstrip("_")
    if not public_name:
        return None
    base = public_name[len("pending") :] if public_name.lower().startswith("pending") else public_name
    if base.lower() not in _AUTHORITY_GETTER_BASENAMES:
        return None
    return _selector_for_signature(f"{public_name}()")


def _oz_v5_namespaced_authority_selector(signature: str | None) -> str | None:
    """Canonical getter selector for an OZ-v5 namespaced ownership accessor, or ``None``.

    OZ-v5 ownership lives in an ERC-7201 struct, so an ``owner()`` gate can inline to a private accessor with no
    selector. Matched by exact accessor name (shared OZ-v5 table) so other ``_get<X>Storage()`` accessors aren't
    rerouted.
    """
    if not isinstance(signature, str) or not signature.endswith("()"):
        return None
    from services.static.contract_analysis_pipeline.tracking import (
        _oz_v5_ownership_getter_for_accessor,
    )

    getter = _oz_v5_ownership_getter_for_accessor(signature[:-2])
    if getter is None:
        return None
    return _selector_for_signature(f"{getter}()")


def _leaf_is_keyed_set_membership(leaf: Mapping[str, Any] | None) -> bool:
    """Whether the leaf tests keyed-set membership, where a ``bytes32`` constant may be a set key rather than a slot
    locator.

    Wider than the static plane's ``summaries._operand_is_role_key``, which is safe here: this only withholds a reroute,
    so over-matching loses a resolution but never publishes a wrong address.
    """
    if not isinstance(leaf, Mapping):
        return False
    if leaf.get("kind") not in ("membership", "external_bool"):
        return False
    descriptor = leaf.get("set_descriptor")
    return isinstance(descriptor, Mapping) and descriptor.get("kind") in ("mapping_membership", "external_set")


def _canonical_authority_selector_for_slot(name: str | None, leaf: Mapping[str, Any] | None = None) -> str | None:
    """Canonical getter selector for a storage-slot-constant operand, or ``None``.

    Slot locators (``_OWNER_SLOT``, ``OwnableStorageLocation``) aren't getters, but the canonical getter reads the same
    slot. Keyed-set membership leaves are refused first (a role key read through ``owner()`` would publish a wrong
    caller); :func:`_is_storage_layout_constant` then excludes ordinary address vars.
    """
    if not isinstance(name, str) or not name:
        return None
    if _leaf_is_keyed_set_membership(leaf):
        return None
    from services.static.contract_analysis_pipeline.tracking import _is_storage_layout_constant

    if not _is_storage_layout_constant(name):
        return None
    lowered = name.lower()
    matched = {selector for keyword, selector in _SLOT_KEYWORD_TO_GETTER if keyword in lowered}
    # A locator naming two roles gives no basis to pick either.
    if len(matched) != 1:
        return None
    return next(iter(matched))


# Authority roles whose ``pending`` half is the accept side of a 2-step transfer (Governable, OZ
# AccessControlDefaultAdminRules, Ownable2Step). Exact match after stripping ``pending``.
_PENDING_AUTHORITY_BASENAMES = frozenset({"owner", "governor", "authority", "admin", "defaultadmin"})


def _pending_authority_base(name: str | None) -> str | None:
    """The authority role behind a ``pending``-prefixed accessor (``_pendingGovernor`` → ``governor``), or ``None``."""
    if not isinstance(name, str):
        return None
    bare = name.lstrip("_").lower()
    if not bare.startswith("pending"):
        return None
    base = bare[len("pending") :]
    return base if base in _PENDING_AUTHORITY_BASENAMES else None


def _pending_ceiling_capability(op: dict[str, Any], read_outcome: CapabilityExpr | None) -> CapabilityExpr:
    """The accept-side ceiling, with the evidence it rests on.

    Reached when nothing could be read; the classification comes from the ``pending`` prefix. The trace records that
    basis and the preceding read outcome, so this ``resolved_empty`` is distinguishable from a read-confirmed one.
    """
    source = op.get("source")
    accessor = op.get("callee_signature") if source == "view_call" else op.get("state_variable_name")
    accessor = accessor if isinstance(accessor, str) else None
    bare = accessor[:-2] if accessor and accessor.endswith("()") else accessor
    return CapabilityExpr.finite_set(
        [],
        quality="exact",
        empty_reason="empty_by_design",
        trace=[
            {
                "step": "pending_transfer_ceiling",
                "basis": "accessor_name",
                "accessor": accessor,
                "role": _pending_authority_base(bare),
                "read_outcome": (read_outcome.empty_reason if read_outcome is not None else "not_attempted"),
            }
        ],
    )


def _is_pending_authority_accessor_operand(op: dict[str, Any]) -> bool:
    """Whether an equality operand reads the pending half of a 2-step transfer (``_pendingGovernor()`` accessor or OZ
    ``_pendingDefaultAdmin.newAdmin``). Plain ``owner()``/``governor()`` gates never match.
    """
    src = op.get("source")
    if src == "view_call":
        signature = op.get("callee_signature")
        name = signature[:-2] if isinstance(signature, str) and signature.endswith("()") else signature
    elif src == "state_variable":
        name = op.get("state_variable_name")
    else:
        return False
    return _pending_authority_base(name) is not None


def _resolve_param_keyed_authority_mapping(op: dict[str, Any], ctx: EvaluationContext | None) -> CapabilityExpr:
    """``msg.sender == <mapping>[<param>]``: resolve to the mapping's value set (claim #3 group C).

    E.g. L1BaseSyncPool's ``receivers[originEid]``: the caller picks the key, so the principal is every value. Folded
    from setter events at the runtime address as a lower_bound ``finite_set``. With no event source, no setter spec, or
    an empty fold, emits ``external_check_only`` rather than a phantom "nobody".
    """
    mapping_name = op.get("mapping_name") or ""
    writer_specs = op.get("mapping_writer_specs") or []
    outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None) if ctx is not None else None
    contract = getattr(outer, "contract_address", None) or (ctx.contract_address if ctx is not None else None)

    def _unresolved(basis: str) -> CapabilityExpr:
        target = contract.lower() if isinstance(contract, str) and contract.startswith("0x") else None
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=target,
                target_call_selector=None,
                extra={"basis": [basis], "mapping_name": mapping_name},
            )
        )

    if not writer_specs:
        return _unresolved("param_keyed_mapping_no_writer_spec")
    if not isinstance(contract, str) or not contract.startswith("0x") or len(contract) != 42:
        return _unresolved("param_keyed_mapping_no_address")

    values = _enumerate_param_keyed_mapping_values(contract, list(writer_specs), outer)
    if not values:
        # An honest query interface, never a fabricated empty set.
        return _unresolved("param_keyed_mapping_unresolved")
    return CapabilityExpr.finite_set(
        values,
        quality="lower_bound",
        confidence="partial",
        trace=[{"step": "param_keyed_mapping_enumeration", "mapping": mapping_name, "contract": contract.lower()}],
    )


def _enumerate_param_keyed_mapping_values(contract: str, writer_specs: list[dict[str, Any]], outer: Any) -> list[str]:
    """Fold the non-zero address values of a parameter-keyed mapping from its ``set`` events.

    Empty when there's no event source, the scan errors, or nothing folds. The HyperSync client comes from
    ``outer.meta`` so tests can seed it.
    """
    import os

    meta = getattr(outer, "meta", None) or {}
    token = meta.get("hypersync_token") or os.getenv("ENVIO_API_TOKEN")
    client = meta.get("hypersync_client")
    module = meta.get("hypersync_module")
    if not token and client is None:
        return []
    block = getattr(outer, "block", None)
    chain_id = getattr(outer, "chain_id", None)
    if not isinstance(chain_id, int):
        # No chain means nothing to scan (inv. 6).
        return []
    _bump_resolve_counter(outer, "mapping_value_scans")
    from services.resolution.creation_block_floor import resolve_scan_floor

    # No floor: defer rather than scan from genesis.
    floor = resolve_scan_floor(
        contract,
        chain_id,
        session=getattr(outer, "session", None),
    )
    if floor is None:
        return []
    kwargs: dict[str, Any] = {"from_block": floor}
    if isinstance(block, int):
        kwargs["to_block"] = block
    if token:
        kwargs["bearer_token"] = token
    if client is not None:
        kwargs["client"] = client
    if module is not None:
        kwargs["hypersync_module"] = module
    hypersync_url = meta.get("hypersync_url")
    if isinstance(hypersync_url, str) and hypersync_url:
        kwargs["hypersync_url"] = hypersync_url
    try:
        from services.resolution.mapping_enumerator import enumerate_mapping_values_sync
        from utils.chains import chain_cache_token

        scan = enumerate_mapping_values_sync(
            contract,
            cast(Any, writer_specs),
            # inv. 11: one cache-key token format.
            chain=chain_cache_token(chain_id),
            **kwargs,
        )
    except Exception:
        return []
    if scan["status"] == "error":
        return []
    values: list[str] = []
    seen: set[str] = set()
    for entry in scan["entries"]:
        value_hex = entry.get("value_hex") or ""
        if not isinstance(value_hex, str) or len(value_hex) != 66:
            continue
        addr = "0x" + value_hex[-40:].lower()
        if _is_zero_address(addr) or addr == _BURN_ADDRESS or addr in seen:
            continue
        seen.add(addr)
        values.append(addr)
    return sorted(values)


def _view_call_caller_selects_key(op: Mapping[str, Any]) -> bool:
    """Does the caller choose this view call's lookup key? With recorded ``callee_args``, some arg must derive from a
    parameter or the caller; constant keys (``roleAdmin(ROLE)``) are fixed lookups. Compiled trees don't record
    args, and the derived fold only fires when a parameter flows in, so missing args means parameter-keyed.
    """
    args = op.get("callee_args")
    if not args:
        return True
    return any((arg or {}).get("source") in ("parameter", "msg_sender", "tx_origin", "root_caller") for arg in args)
