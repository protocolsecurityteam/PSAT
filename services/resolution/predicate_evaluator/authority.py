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

# ---------------------------------------------------------------------------
# Operand resolution helpers
# ---------------------------------------------------------------------------


def _nullary_getter_selector(name: str | None) -> str | None:
    """4-byte selector for ``<name>()`` — the auto-getter of a public state
    variable. ``None`` for an empty name."""
    if not isinstance(name, str) or not name:
        return None
    return _selector_for_signature(f"{name}()")


# Canonical public authority view-getters. A caller-equality gate may read the
# authority through a non-canonical accessor — an internal helper (``_governor()``),
# an explicit storage-slot constant (Solady ``_OWNER_SLOT``, OZ-v5
# ``OwnableStorageLocation``), or an ERC-7201 namespaced struct member — none of
# which is itself a readable public getter (reading ``_governor()`` /
# ``_OWNER_SLOT()`` reverts). Every such standard still exposes the SAME canonical
# public view getter, which reads the same storage, so we read that live instead.
# OZ v4 keeps a plain ``_owner`` state var and OZ v5 keeps it in a namespaced
# storage struct, but both expose ``owner()`` identically.
_OWNER_SELECTOR = OWNER_SELECTOR
_GOVERNOR_SELECTOR = "0x0c340a24"  # governor()
_AUTHORITY_SELECTOR = "0xbf7e214f"  # authority()

# Burn sentinel: ownership renounced to a dead address (e.g. Solady TopUp, whose
# owner is 0x…dEaD). A gate against it has no live controller — treat it like the
# zero address rather than minting 0x…dEaD as a phantom principal everywhere.
_BURN_ADDRESS = "0x" + "00" * 18 + "dead"

# Keyword → canonical getter, for slot-constant authority operands. Matched as a
# substring of the (lowercased) slot-constant name, which must itself be a
# storage-layout locator (``_is_storage_layout_constant`` — a ``*_slot`` /
# ``*StorageLocation`` suffix): ``_OWNER_SLOT`` → owner(); OZ-v5
# ``OwnableStorageLocation`` → owner() (note "ownable", not "owner");
# ``_GOVERNOR_SLOT`` / ``GovernorStorageLocation`` → governor();
# ``_AUTHORITY_SLOT`` / ``AuthorityStorageLocation`` → authority().
#
# This is the one authority selection in this module that a NAME decides, and the
# read it drives is published as the principal. The slot's own value is not on the
# operand (provenance carries only the identifier for a ``state_variable``
# source), so there is nothing here to cross-check the getter's return against.
# Two things bound the damage: a name matching keywords for MORE THAN ONE role is
# refused outright rather than silently resolved to whichever came first, and the
# winning candidate stamps its basis into the capability trace
# (``authority_getter_basis``) so a consumer can see the principal rests on the
# identifier.
_SLOT_KEYWORD_TO_GETTER = (
    ("governor", _GOVERNOR_SELECTOR),
    ("authority", _AUTHORITY_SELECTOR),
    ("ownable", _OWNER_SELECTOR),
    ("owner", _OWNER_SELECTOR),
)

# Public authority view-getter base names (optionally ``pending``-prefixed). The
# internal-accessor fallback de-underscores ``_x()`` → ``x()`` only when ``x`` is
# one of these; an arbitrary ``_x()`` is left fail-closed, because resolving it to
# whatever public ``x()`` returns would risk a *wrong* controller — worse than a
# missing one for this tool.
_AUTHORITY_GETTER_BASENAMES = frozenset({"owner", "governor", "authority"})


def _live_authority_result(read_addr: str, selector: str, contract: str, block: int | None = None) -> CapabilityExpr:
    """Build the capability a completed live authority read yields — identical whether the address came from
    a fresh eth_call or the pass memo.

    Three outcomes, each carrying the read that produced it:

    * a concrete address → exact singleton;
    * the zero word → exact EMPTY, ``owner_read_zero``. The empty set is the
      strongest earned negative this module can publish, so it is published with
      its provenance (which getter, on which contract, at which height) rather
      than bare — a provenance-less exact-empty is unreconstructible after the
      fact, and four such rows exist that nothing can explain;
    * ``0x…dEaD`` → a ``lower_bound`` empty, ``owner_read_burn_address``. It must
      NOT share the zero shape: ``0x0`` cannot be ``msg.sender`` on mainnet, which
      is what makes the zero read a real "nobody", whereas ``0x…dEaD`` is an
      ordinary address merely BELIEVED keyless. Treating a convention as proof of
      unspendability would publish an unproven negative, so the raw address read
      is recorded for downstream checking and the set stays a lower bound.

    ``observed_at_block`` rides in the trace step and ONLY when the call was
    pinned to a block: when it is not, the read went to ``"latest"`` and there is
    no height to state — the key is absent (not_determined), never backfilled
    from the head.
    """
    step: dict[str, Any] = {"step": "live_getter_resolution", "selector": selector, "contract": contract.lower()}
    if isinstance(block, int) and not isinstance(block, bool):
        step["observed_at_block"] = block
    if not (isinstance(read_addr, str) and read_addr.startswith("0x") and len(read_addr) == 42):
        # Not an address-shaped read: fail closed rather than canonicalizing
        # whatever arrived into a member.
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
    """Resolve ``msg.sender == X`` by reading ``X`` live when the static
    ``state_var_values`` feed didn't carry it.

    ``msg.sender == owner()`` / ``== governor()`` / ``== <stateVar>`` names a
    single authorized caller; the persisted ``ControllerValue`` feed is the
    only thing :func:`_resolve_equality_principal` consults, so an
    owner()/governor()-gated function whose value was never captured (or was
    captured under a different key) dropped every principal. This reads the
    getter on the contract under analysis and materializes the result.

    Returns ``finite_set([addr], exact)`` for a concrete non-zero address,
    ``finite_set([], exact)`` when the getter returns the zero address
    (genuinely unset / renounced), a labeled ``finite_set([], lower_bound)``
    when a read was *attempted but unreadable* (``unreadable_revert`` on a
    revert, ``unreadable_empty`` on an empty / no-code return), or ``None`` when
    nothing was attempted — no RPC reachable through the outer context, a
    malformed selector, or an unusable contract address. The labeled-empty vs
    ``None`` split lets the caller fall through to a fallback getter (a revert is
    not a final answer) yet still record *why* the final placeholder is empty.
    Gating on a reachable ``rpc_url`` keeps pure-unit evaluations (no RPC) on
    their existing empty-placeholder behaviour."""
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
    # Pass-scoped dedup: owner()/governor()/<stateVar>() reads are deterministic at a fixed block, so N
    # functions gating on the same getter need ONE read, not N. Only SUCCESSFUL reads are memoized — a revert
    # or transient RPC error is never cached, so each gated function still reads/retries independently (no
    # poisoning). Result is byte-identical to the un-memoized path.
    memo = _pass_live_read_memo(outer)
    block_repr = block if isinstance(block, int) else "latest"
    memo_key = ("live_authority", rpc_url, contract.lower(), selector, block_repr)
    if memo is not None and memo_key in memo:
        _bump_resolve_counter(outer, "live_getter_memo_hits")
        # ``block`` is threaded here too: the memo key already pins the height, so
        # a hit must reproduce the fresh read's payload byte-for-byte, including
        # ``observed_at_block``.
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
    # The RAW address is memoized, not a collapsed sentinel: zero and burn are
    # different answers and the memo must not be the place they merge.
    if memo is not None:
        memo[memo_key] = addr
    return _live_authority_result(addr, selector, contract, block if isinstance(block, int) else None)


def _live_resolve_authority_slot(
    ctx: EvaluationContext | None,
    slot: str | None,
) -> CapabilityExpr | None:
    """Resolve ``msg.sender == <getter-less slot reader>`` by reading the raw
    storage slot live.

    Two getter-less authority shapes use this. (1) An internal accessor that
    ``sload``s a *constant* slot (Governable ``_pendingGovernor`` reads
    ``keccak256("LRTSquare.pending.governor")``) — a ``view_call`` operand. (2) A
    *named* address state var declared without ``public`` (ether.fi
    ``MembershipNFT.membershipManager``) — a ``state_variable`` operand whose slot
    is its sequential layout position. In both the static stage attaches the slot
    and this reads it with ``eth_getStorageAt`` against the runtime address — the
    proxy when the job is proxy-linked, so the *live* value is seen rather than a
    standalone impl's empty storage.

    Mirrors :func:`_live_resolve_authority`'s contract: ``finite_set([addr],
    exact)`` for a non-zero slot, ``finite_set([], exact)`` with
    ``slot_read_zero`` for a confirmed-zero slot, a ``lower_bound``
    ``owner_read_burn_address`` for ``0x…dEaD``, a labeled ``lower_bound`` when
    the read was attempted but unreadable, or ``None`` when nothing could be
    attempted. Every outcome carries the read (slot, contract, and
    ``observed_at_block`` when the read was pinned) in its trace.

    The confirmed-zero outcome reports only what was read. It previously carried
    ``empty_by_design`` from a DEFAULT ARGUMENT — a label asserting the gate is an
    intentional accept-side ceiling, applied to any caller that did not opt out,
    on a set with no trace and no block to check it against. Classifying the
    emptiness is the caller's job and rests on the accessor's ``pending`` prefix,
    i.e. an identifier: :func:`_pending_ceiling_capability` owns that claim and
    discloses its basis."""
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
        # See :func:`_live_authority_result` — a burned slot is not a proven
        # "nobody", so it never reaches the exact/enumerable shape.
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
    """Read an authority through the first of ``selectors`` that gives a concrete
    answer.

    ``bases`` names, per candidate, WHY that selector was tried — the compiler's
    ABI rule (``abi_auto_getter``), an accessor-NAME match
    (``deunderscore_convention`` / ``standard_namespaced_accessor`` /
    ``slot_name_keyword``), or the operand's own recorded selector
    (``callee_selector``). The winning candidate's basis is stamped into the
    returned capability's trace, so a published principal that rests on an
    identifier says so on the wire instead of looking as evidenced as one the ABI
    forced. Only ``abi_auto_getter`` is stronger than the name-matched arms; those
    are mutually UNORDERED — an ERC-7201-anchored accessor name is still a name,
    and nothing measured establishes it as better evidence that the accessor
    returns the authority than the 3-name convention is.

    Short-circuits only on a *resolved* read (``membership_quality == "exact"`` —
    a real address, or a confirmed renounced/zero), so a literal getter that
    reverts still falls through to the canonical/slot getter behind it (the #4
    internal-accessor and #6 slot-constant fallbacks both depend on this: their
    first candidate reverts on purpose). When every candidate was attempted but
    unreadable, returns the last labeled ``lower_bound`` empty (carrying
    ``unreadable_revert`` / ``unreadable_empty``). Returns ``None`` only when
    nothing was attempted (no candidate selector, no reachable RPC) so the caller
    can label the placeholder ``not_read``."""
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
    """Selector for the public getter behind a nullary *internal* authority
    accessor, or ``None`` (fail-closed) for anything else.

    A custom authority gate often reads its principal through an internal helper
    rather than the public getter: Governable's ``onlyGovernor`` lowers to
    ``msg.sender == _governor()``, where ``_governor()`` is ``internal`` and has
    no external selector (calling it reverts). The leading-underscore ⇄ public
    convention (``_governor()``→``governor()``, ``_owner()``→``owner()``) is
    shared across OZ / Solady / Solmate / Governable, so the de-underscored
    getter reads the same value.

    Scoped to the canonical authority getters (``owner`` / ``governor`` /
    ``authority``, optionally ``pending``-prefixed): an arbitrary ``_x()`` is left
    fail-closed, since resolving it to whatever public ``x()`` returns would risk
    a *wrong* controller — worse than a missing one for this tool."""
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
    """Canonical public authority-getter selector for an OZ-v5 namespaced-storage
    OWNERSHIP accessor, or ``None`` (fail-closed).

    OZ-v5 keeps ownership in an ERC-7201 namespaced struct, so a caller-equality
    gate that lowers through ``owner()`` inlines to a ``view_call`` of the
    PRIVATE accessor that ``sload``s the namespace (CumulativeMerkleDrop overrides
    ``owner()`` to ``defaultAdmin()`` → ``_getAccessControlDefaultAdminRulesStorage()``).
    That accessor has no external selector, so reading it reverts; the canonical
    public ``owner()`` reads the same root. Anchored to the known ownership
    accessors by EXACT name (via the shared OZ-v5 recognition table) so an
    arbitrary ``_get<X>Storage()`` — the L1BaseSyncPool namespace, the parametric
    ``_getAccessControlStorage()`` role-admin root — is never rerouted here."""
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
    """True iff the leaf tests membership of a keyed set — the shape in which a
    ``bytes32`` constant operand may be a set KEY rather than a storage-layout
    pointer.

    Deliberately WIDER than the static plane's admission rule
    (``summaries._operand_is_role_key``, which admits the in-contract
    ``mapping_membership`` shape only — a cross-contract ``external_set``
    descriptor names the callee from the CALLER's declared interface, which is
    not a proven property of the deployed callee). Only the direction matters,
    and it is safe in this direction: here the predicate WITHHOLDS a slot-locator
    reroute, so over-matching costs a resolution that would have been published,
    never a wrong address. The static plane MINTS a fact, so it must be strict."""
    if not isinstance(leaf, Mapping):
        return False
    if leaf.get("kind") not in ("membership", "external_bool"):
        return False
    descriptor = leaf.get("set_descriptor")
    return isinstance(descriptor, Mapping) and descriptor.get("kind") in ("mapping_membership", "external_set")


def _canonical_authority_selector_for_slot(name: str | None, leaf: Mapping[str, Any] | None = None) -> str | None:
    """Canonical public authority-getter selector for a storage-slot-constant
    operand, or ``None`` when the operand doesn't denote one (fail-closed).

    Solady ``_OWNER_SLOT`` / OZ-v5 ``OwnableStorageLocation`` /
    ``_GOVERNOR_SLOT`` name a *slot locator*, not a getter — reading
    ``<slot>()`` reverts. The contract's canonical public getter
    (``owner()``/``governor()``/``authority()``) reads that same slot.

    Two gates, structure first: a leaf that tests keyed-set membership names a role
    KEY, and resolving a role key through ``owner()``/``governor()`` would publish
    a real address as the authorized caller of a role-gated function. That refusal
    does not consult the identifier, so it holds for a role constant whose name
    happens to carry a slot-locator suffix. The surviving
    :func:`_is_storage_layout_constant` gate only narrows further, keeping ordinary
    address state vars — which resolve through their own auto-getter — out."""
    if not isinstance(name, str) or not name:
        return None
    if _leaf_is_keyed_set_membership(leaf):
        return None
    from services.static.contract_analysis_pipeline.tracking import _is_storage_layout_constant

    if not _is_storage_layout_constant(name):
        return None
    lowered = name.lower()
    matched = {selector for keyword, selector in _SLOT_KEYWORD_TO_GETTER if keyword in lowered}
    # A locator naming two different roles (``AuthorityOwnableStorageLocation``)
    # gives no basis for preferring either; picking the first would publish one
    # real address where the other is equally supported. Refuse instead.
    if len(matched) != 1:
        return None
    return next(iter(matched))


# Authority roles whose ``pending`` half names an accept-side 2-step transfer:
# ``pendingGovernor`` (Governable claimGovernance), ``pendingDefaultAdmin`` /
# ``pendingAdmin`` (OZ AccessControlDefaultAdminRules acceptDefaultAdminTransfer),
# ``pendingOwner`` (OZ Ownable2Step). Matched exactly after the ``pending``
# prefix is stripped, so only these flip to empty-by-design.
_PENDING_AUTHORITY_BASENAMES = frozenset({"owner", "governor", "authority", "admin", "defaultadmin"})


def _pending_authority_base(name: str | None) -> str | None:
    """The authority role behind a ``pending``-prefixed accessor name, or
    ``None``. ``_pendingGovernor`` → ``governor``; ``_pendingDefaultAdmin`` →
    ``defaultadmin``; a non-``pending`` name (plain ``owner``) → ``None``."""
    if not isinstance(name, str):
        return None
    bare = name.lstrip("_").lower()
    if not bare.startswith("pending"):
        return None
    base = bare[len("pending") :]
    return base if base in _PENDING_AUTHORITY_BASENAMES else None


def _pending_ceiling_capability(op: dict[str, Any], read_outcome: CapabilityExpr | None) -> CapabilityExpr:
    """The accept-side ceiling, carrying the evidence it actually rests on.

    The verdict itself is unchanged, but it is NOT read-confirmed: it is reached
    precisely when nothing could be read (the pending getter reverted, returned
    empty, or — for the OZ struct member — does not exist). What identifies the
    gate as the accept half of a 2-step handover is the accessor's ``pending``
    prefix, i.e. an identifier. The trace records that basis and which read
    outcome preceded it, so a consumer can tell this ``resolved_empty`` apart
    from one a live zero-read confirmed."""
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
    """True when an equality operand reads the *pending* half of a 2-step
    authority transfer — the accept-side gate (``claimGovernance`` /
    ``acceptDefaultAdminTransfer``) that is uncallable until a transfer is
    queued. Covers both shapes seen on-chain: an internal ``_pendingGovernor()``
    accessor (``view_call``) and an OZ ``_pendingDefaultAdmin.newAdmin`` storage
    struct member (``state_variable``). Keyed on the ``pending`` prefix so a plain
    ``owner()`` / ``governor()`` gate is never caught."""
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
    """``msg.sender == <mapping>[<param>]`` — resolve the parameter-keyed authority
    mapping to the set of its VALUES (claim #3 group C).

    L1BaseSyncPool gates ``onMessageReceived`` on ``msg.sender == receivers[originEid]``,
    a ``mapping(uint32 => address)`` keyed by a function parameter. The authorized
    caller is whichever receiver the (caller-chosen) eid maps to, so the principal is
    the mapping's value set — there is no single getter to read. Fold those values
    from the mapping's setter events (``ReceiverSet``) on the runtime address (the
    proxy when proxy-linked, so the *live* receivers are seen rather than a standalone
    impl's empty storage). Emit a ``finite_set`` of the folded receivers; when no
    event source is reachable, no setter spec exists, or the live mapping folds empty,
    emit an ``external_check_only`` query interface rather than a phantom "nobody"
    (mirrors :func:`_resolve_view_key_membership`'s ``view_key_membership_unresolved``).
    ``lower_bound`` because event replay is a lower bound on the live value set."""
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
        # No event source reachable, or the live mapping folded no receivers (e.g. a
        # standalone impl whose receivers were set on the proxy): an honest query
        # interface, never a fabricated empty principal set.
        return _unresolved("param_keyed_mapping_unresolved")
    return CapabilityExpr.finite_set(
        values,
        quality="lower_bound",
        confidence="partial",
        trace=[{"step": "param_keyed_mapping_enumeration", "mapping": mapping_name, "contract": contract.lower()}],
    )


def _enumerate_param_keyed_mapping_values(contract: str, writer_specs: list[dict[str, Any]], outer: Any) -> list[str]:
    """Fold the deduped non-zero address VALUE set of a parameter-keyed mapping from
    its ``set``-direction setter events via on-demand replay. Returns an empty list
    when no event source is reachable (no hypersync token / injected client), the
    scan errors, or the mapping folds empty — the caller surfaces all three as an
    external check. The hypersync client / module are read from ``outer.meta`` so a
    test can seed the event source without replacing the enumerator (the wire is the
    stub seam, mirroring ``rpc_request``)."""
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
        # ctx.chain_id is required (inv. 6); without a chain there is nothing to
        # scan — return empty rather than defaulting the scan to mainnet.
        return []
    _bump_resolve_counter(outer, "mapping_value_scans")
    from services.resolution.creation_block_floor import resolve_scan_floor

    # No floor → DEFER: skip the live scan (return empty, surfaced as the gated
    # external check) rather than scan from genesis.
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
            # inv. 11: one cache-key token format everywhere (decimal-string chain
            # id). ``enumerate_mapping_values_sync`` re-normalizes via the same
            # helper, so mainnet ("1") is byte-identical to the prior ``str(1)``.
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
    """Does the CALLER choose the lookup key of this arg-taking view call?
    With recorded ``callee_args`` (registry-built trees), some arg must
    derive from a parameter or the caller itself — constant/state-derived
    keys (``roleAdmin(ROLE)``) are fixed authority lookups, not
    caller-chosen rows. Compiled trees don't record args; there the derived
    view_call fold (``predicates._derived_view_call_source``) fires only
    when a parameter flows into the value, so the absence of recorded args
    IS the parameter-keyed evidence."""
    args = op.get("callee_args")
    if not args:
        return True
    return any((arg or {}).get("source") in ("parameter", "msg_sender", "tx_origin", "root_caller") for arg in args)
