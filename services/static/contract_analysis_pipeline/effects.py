"""Build the semantic ``effects`` artifact for a contract.

Walks Slither IR for every externally-callable function on a contract
and emits a typed record describing the function's *effects*: state
writes, external calls, delegatecalls, contract creations, and
selfdestructs — including those reached transitively through internal
calls. The artifact is the semantic sink/effect carrier for downstream
consumers (``cross_contract.py``, ``tracking.py``,
``effective_permissions.py``).

Why a separate artifact (vs. extending ``predicate_trees``):
``predicate_trees`` deliberately omits *unguarded* functions
(``predicate_artifacts.py:44``) — the resolver treats absence as
"public / unguarded". For sink/effect discovery we want a record per
externally-callable function regardless of guard structure, so a
publicly callable sensitive action (e.g. unprotected ``mint``) is
still surfaced to the policy stage.

Function inclusion:
  * external/public functions: included.
  * constructor: skipped (matches ``predicate_artifacts._is_externally_callable``;
    constructor effects are tracked elsewhere).
  * fallback / receive: INCLUDED. They have real effect semantics —
    receive can hold ETH; fallback often delegatecalls. The
    predicate-tree builder skips them because their "guard" semantics
    are unusual, but that's not a reason to drop them from sink
    discovery.
  * internal / private: never appear directly; their effects are
    surfaced through their external callers via transitive walk.

Plane-0 facts (this artifact is the machine-checkable substrate a later
claims plane reads):
  * every sink carries an ``origin`` — ``body`` for the function's own
    logic, ``guard`` for anything reached only through a modifier. A
    modifier's auth call (``auth.canCall``) is a guard fact, not an
    effect, so it never drives a label.
  * ``state_writes`` records each write at ``var`` / ``member`` /
    ``assembly_slot`` granularity with a ``hygiene_class`` marking the
    non-role writes (constants, ``*StorageLocation`` slot pseudo-vars,
    reentrancy guards, view-function ghost writes).
  * ``value_flows`` records asset movement with a ``from == address(this)``
    direction correction and native ``transfer``/``send`` sinks.
"""

from __future__ import annotations

import re
from typing import Any, TypedDict, cast
from weakref import WeakKeyDictionary

from eth_utils.crypto import keccak
from typing_extensions import NotRequired

from .provenance import ProvenanceEngine, is_top
from .shared import _all_state_variables
from .summaries import (
    _action_summary,
    _effect_labels,
    _resolve_cast_head,
)
from .token_slots import derive_token_slots

SCHEMA_VERSION = "semantic-3"


class SinkRecord(TypedDict):
    """One sink reachable from a given external function. ``id`` is a
    stable cross-reference; ``function`` is the *originating* external
    function (the entry-point), not the unit where the IR lives — that
    way consumers can group sinks by entry without re-walking
    internal calls. ``origin`` is ``body`` unless the sink is reachable
    only through a modifier (``guard``)."""

    id: str
    function: str
    kind: str  # state_write | external_call | delegatecall | contract_creation | selfdestruct
    target: str
    selector: str | None
    origin: str  # body | guard


class StateWriteFact(TypedDict):
    """A single state write, richer than the ``state_write`` sink: it
    carries member granularity (``accountantState.isPaused`` vs.
    ``accountantState.payoutAddress``) and a hygiene class. Role-fact
    consumers must skip the non-``normal`` classes; they stay recorded as
    raw writes regardless."""

    var: str
    declared_type: str
    member_path: list[str]
    granularity: str  # var | member | assembly_slot
    hygiene_class: str  # normal | constant | storage_location_pseudo | reentrancy_guard | view_writer
    origin: str  # body | guard


class KindTier(TypedDict):
    """A lattice classification with the tier at which it was witnessed.

    ``tier`` is ``dispositive_ast`` (scoring Tier 1) when the classified SSA
    operand is *directly* a StateVariable / parameter / ``msg.sender`` / literal
    — a definitive AST fact — and ``static_trace`` (scoring Tier 2) when it was
    recovered through the SSA provenance trace (casts, member reads). The
    ``indeterminate`` kind always carries ``static_trace``: it is an inference
    conclusion (TOP / empty / cross-branch MIX), never a dispositive fact."""

    kind: str
    tier: str  # dispositive_ast | static_trace


class ValueFlow(TypedDict):
    """A value movement fact. ``direction`` is corrected for
    ``from == address(this)`` (a ``transferFrom`` whose sender is the
    contract itself flows *out*, not *in*).

    ``target_kind`` / ``amount_kind`` classify *where the funds go* and *how
    much can leave* — the theft-vs-routing discriminators. They are the union
    of every contributing IR site's classification collapsed to a single
    unambiguous origin (or ``indeterminate`` on any MIX), so a caller-chosen
    destination and an immutable one no longer produce identical witnesses."""

    kind: str  # callee_erc20_selector | native_transfer_send | low_level_value_call
    selector: str | None
    # ``in`` / ``out`` are the entry contract's OWN value moves, and each is
    # earned: ``out`` needs the payer to be this contract, ``in`` needs the payee
    # to be. ``value_router`` is a move the entry only CAUSED — a call into an
    # in-unit contract whose body moves the funds (a router forwarding into a
    # vault), or a pull between two third parties (a fee the caller pays straight
    # to a bridge endpoint). The entry is neither source nor sink, so it is kept
    # distinct from in/out and never drives an asset-direction label. Read
    # ``from_is_self`` to tell an outbound route from an inbound one.
    direction: str  # in | out | value_router
    from_is_self: bool
    origin: str  # body | guard
    # target_kind ∈ {immutable, constant, storage_no_setter, storage_setter,
    #   param, msg_sender, caller_controlled, self, token_owner, several,
    #   indeterminate}
    # several: the contributing sites resolved to more than one distinct kind,
    #   each itself resolved — see ``target_kinds`` for the members, and take the
    #   worst one. Never a licence to pick the most favourable member. The
    #   members are NOT alternatives: they may be exclusive branches or may all
    #   execute in one call (see :func:`_fold_sites`).
    target_kind: NotRequired[KindTier]
    # amount_kind ∈ {msg_value, param, whole_balance, bounded_by_storage,
    #   fixed_constant, balance_delta, capped_by_balance, param_derived,
    #   token_identity, caller_supplied, indeterminate}
    # caller_supplied: every branch of the amount is a quantity the caller chose —
    #   an ABI argument or the ETH attached to the call. Carries no slot, because
    #   the msg.value branch has none.
    # token_identity: the sink's ABI proves this slot names WHICH token moves,
    #   not how much (ERC-721). Exactly one non-fungible token moves; the slot is
    #   never published as ``amount_param_index``.
    # capped_by_balance: provably ≤ this contract's own balance — the minimum of
    #   address(this).balance and some other value (a real upper bound / mitigation).
    # param_derived: see :func:`_call_amount_origin` — the amount IS an external
    #   call's return value and a caller-supplied entry parameter is among that
    #   call's arguments. NOT a bound, NOT proof of caller control.
    amount_kind: NotRequired[KindTier]
    # The DISTINCT per-IR-site classifications behind the folded kind above,
    # first-seen order, deduplicated by meaning (the ``(kind, tier)`` pair).
    # Present ONLY when the fold lost information — i.e. the sites disagreed —
    # so a consumer reading the fold alone is never contradicted, and a
    # single-site flow carries no redundant copy. A function sending to two
    # separately-resolved destinations therefore publishes both instead of
    # only the scalar their union folds to.
    #
    # Honesty: a site that is itself ``indeterminate`` appears in the list as
    # such — the list explains the fold, it never launders it. So this key being
    # present means the fold is either ``several`` — every member below is
    # resolved and they ARE the whole set — or ``indeterminate``, where at
    # least one member is not and the list is therefore a partial explanation
    # rather than a closed set of possibilities.
    target_kinds: NotRequired[list[KindTier]]
    # ``target_kinds`` for the amount lattice, same discipline.
    amount_kinds: NotRequired[list[KindTier]]
    # Positional index of the ENTRY function's parameter the destination
    # resolves to. Present ONLY when ``target_kind`` is ``param`` and every
    # contributing site agrees on that one parameter slot; a struct member or
    # array element of a parameter never emits one (the value is not the whole
    # argument). Consumers plant a probe address in that ABI slot, so a guessed
    # index would probe the wrong argument — absent means "do not guess".
    target_param_index: NotRequired[int]
    # Positional index of the ENTRY function's parameter carrying the AMOUNT,
    # under exactly the ``target_param_index`` discipline: present only when
    # ``amount_kind`` is ``param`` — or ``param_derived``, where it is the slot
    # of the caller input that FED the conversion, not of the amount itself
    # (which is a call result and occupies no ABI slot) — and every contributing
    # site agreed on the slot.
    # This is the dispositive answer to "which argument is the quantity", which a
    # prober needs before it substitutes a nonzero value — a quantity written into
    # an id/index/deadline argument is how a probe reverts on its own input.
    amount_param_index: NotRequired[int]


class EffectInfo(TypedDict):
    function: str
    selector: str
    abi_signature: str
    sinks: list[SinkRecord]
    state_writes: list[StateWriteFact]
    value_flows: list[ValueFlow]
    effects: list[str]
    effect_labels: list[str]
    effect_targets: list[str]
    action_summary: str
    writer_selectors: list[str]
    # True for a selector-bearing external/public, non-view, non-pure entry
    # point (the ABI mutability surface). False for views/pure and for
    # fallback/receive (no selector). The policy stage uses this to surface a
    # state-changing entry point that produced no sink (e.g. an inline-assembly
    # writer) as an honest unsupported row.
    state_changing: bool
    # Declared parameter names, positionally aligned with ``abi_signature``'s
    # types (empty string where the source declared none). The prober reads them
    # to tell a quantity argument from an id/index/deadline before substituting a
    # value; the name is the only place that role is written down for a parameter
    # no gate and no value flow mentions.
    parameter_names: list[str]
    # ABI payability. A probe that attaches ``msg.value`` to a NON-payable target
    # reverts with EMPTY data before the body runs, so the attempt witnesses
    # nothing and the prober skips it.
    payable: bool
    # True when at least one sink on this function originated from inline
    # assembly (sstore/delegatecall lowered to a SolidityCall IR). The gate
    # guarding such a write may itself be inline assembly and therefore
    # invisible to the predicate pipeline, so the policy stage keeps these
    # fail-closed (unsupported) rather than projecting public.
    assembly_state_access: bool


class TokenSlotEntry(TypedDict):
    """Storage base slot of a token-precondition mapping, keyed to the VIEW
    getter that reads it back. Consumed by the effects stage to seed
    balance/allowance/shares/ownership on an anvil fork (see ``token_slots``)."""

    getter: str  # canonical signature of a direct-read view getter (read-back anchor)
    role: str  # balance | allowance | shares | owner
    key_kind: str  # address | address_address | uint256
    base_slot: str  # 0x-padded 32-byte base slot of the mapping variable
    derivation: str  # storage_layout | oz_v5_namespaced
    variable: str | None


class TokenSlots(TypedDict):
    entries: list[TokenSlotEntry]


class EffectsArtifact(TypedDict):
    schema_version: str
    contract_name: str | None
    functions: dict[str, EffectInfo]
    token_slots: NotRequired[TokenSlots]


# ERC-20 pull/send selectors used for value-flow direction facts. ``pull``
# selectors take a ``from`` first argument, so their direction depends on
# whether that argument is ``address(this)``.
_ERC20_PULL_SELECTORS = frozenset(
    {
        "0x23b872dd",  # transferFrom(address,address,uint256)
        "0x42842e0e",  # safeTransferFrom(address,address,uint256)
        "0xb88d4fde",  # safeTransferFrom(address,address,uint256,bytes)
    }
)
_ERC20_SEND_SELECTORS = frozenset(
    {
        "0xa9059cbb",  # transfer(address,uint256)
        "0x423f6cef",  # safeTransfer(address,uint256)
    }
)

# Pull selectors ERC-20 does not define at all — they are ERC-721's, so their
# trailing ``uint256`` is a token IDENTITY and never a quantity. The selector is
# the whole proof: ERC-20 has no ``safeTransferFrom`` in any form, so no token
# can answer these with fungible semantics. (``0x23b872dd`` is deliberately NOT
# here: both standards define ``transferFrom(address,address,uint256)``, and the
# selector alone cannot say which one a callee implements.)
_ERC721_IDENTITY_SELECTORS = frozenset(
    {
        "0x42842e0e",  # safeTransferFrom(address,address,uint256)
        "0xb88d4fde",  # safeTransferFrom(address,address,uint256,bytes)
    }
)

# The amount classification for those: one non-fungible token moves, and the slot
# that would carry "how much" carries WHICH instead. Naming it is what stops a
# consumer reading the id as a quantity — and what keeps the slot out of
# ``amount_param_index``, which a prober fills with a probe amount.
_TOKEN_IDENTITY_AMOUNT = ("token_identity", "dispositive_ast")

# The pull selector BOTH standards define. Its trailing ``uint256`` is a quantity
# under ERC-20 and a token id under ERC-721, and the selector cannot say which —
# so it earns neither the identity kind above nor the zero-amount suppression a
# proven quantity earns.
_AMBIGUOUS_PULL_SELECTOR = "0x23b872dd"

# The specific labels an ``external_contract_call`` fact defers to.
_SPECIFIC_EFFECT_LABELS = frozenset(
    {
        "external_contract_call",
        "arbitrary_external_call",
        "asset_send",
        "asset_pull",
        "mint",
        "burn",
        "authority_update",
        "hook_update",
        "ownership_transfer",
        "role_management",
        "pause_toggle",
        "implementation_update",
        "timelock_operation",
        "contract_deployment",
        "delegatecall_execution",
        "selfdestruct_capability",
    }
)


# ---------------------------------------------------------------------------
# Function inclusion (mirrors predicate_artifacts._is_externally_callable but
# keeps fallback/receive — see module docstring).
# ---------------------------------------------------------------------------


def _is_fallback_or_receive(fn: Any) -> bool:
    if getattr(fn, "is_fallback", False) or getattr(fn, "is_receive", False):
        return True
    return (getattr(fn, "name", "") or "") in ("fallback", "receive")


def _is_externally_observable(fn: Any) -> bool:
    """External/public OR fallback/receive. Skips constructor and
    internal/private functions."""
    if getattr(fn, "is_constructor", False) or (getattr(fn, "name", "") or "") == "constructor":
        return False
    if _is_fallback_or_receive(fn):
        return True
    visibility = getattr(fn, "visibility", None)
    return visibility in ("external", "public")


def _is_state_changing_entry_point(fn: Any) -> bool:
    """A selector-bearing external/public, non-view, non-pure function — the
    ABI mutability surface. Excludes fallback/receive (no selector) and
    view/pure reads."""
    if _is_fallback_or_receive(fn):
        return False
    if getattr(fn, "visibility", None) not in ("external", "public"):
        return False
    return not (getattr(fn, "view", False) or getattr(fn, "pure", False))


def _is_view_or_pure(fn: Any) -> bool:
    return bool(getattr(fn, "view", False) or getattr(fn, "pure", False))


# ---------------------------------------------------------------------------
# Sink discovery (transitive across internal calls).
# ---------------------------------------------------------------------------


def _node_irs(node: Any) -> list[Any]:
    return list(getattr(node, "irs", []) or [])


def _function_full_name(fn: Any) -> str:
    name = getattr(fn, "full_name", None) or getattr(fn, "name", None) or "<anonymous>"
    return str(name)


def _selector_for(signature: str | None) -> str | None:
    """Compute keccak256[:4] of a canonical ``name(types)`` signature.
    Returns ``None`` if the signature isn't in canonical form.

    Note this is a *string* test: Slither renders a fallback's ``full_name`` as
    ``"fallback()"``, which is canonical-looking and hashes happily. Callers
    passing a function's own name must go through :func:`_own_selector`."""
    if not signature or "(" not in signature or ")" not in signature:
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _own_selector(fn: Any) -> str | None:
    """The 4-byte selector a caller would put in ``msg.sig`` to reach ``fn`` —
    ``None`` for ``fallback`` / ``receive``, which have none by construction.

    ``keccak("fallback()")[:4] = 0x552079dc`` and ``keccak("receive()")[:4] =
    0xa3e76c0f`` are not dispatches: no caller can send them, and a contract
    that did define ``function fallback()`` would own that selector instead.
    ``db/effect_cache.py`` already fixes the empty string as the sentinel for
    this case; this is that convention, not a second one."""
    if _is_fallback_or_receive(fn):
        return None
    return _selector_for(_function_full_name(fn))


def _sink_id(function_name: str, kind: str, target: str, idx: int) -> str:
    """Stable, idx-disambiguated ID. The ``idx`` keeps multiple sinks
    of the same (kind, target) on one function distinct (e.g. two
    state_write sinks to the same var from different branches).

    Format is ``<function>:sink<idx>:<kind>:<target>`` so callers can
    reference individual sinks without relying on source order alone."""
    return f"{function_name}:sink{idx}:{kind}:{target}"


def _is_modifier_call(ir: Any) -> bool:
    """True iff ``ir`` is an InternalCall that dispatches a modifier body.
    Everything reached through it is guard-origin, not a real effect."""
    if getattr(ir, "is_modifier_call", False):
        return True
    callee = getattr(ir, "function", None)
    return type(callee).__name__ == "Modifier"


def _node_kind_state_writes(node: Any) -> list[str]:
    """Return the names of state variables written at this node."""
    names: list[str] = []
    for variable in getattr(node, "state_variables_written", []) or []:
        name = getattr(variable, "name", "") or ""
        if name:
            names.append(name)
    return names


def _callee_signature(ir: Any) -> str | None:
    fn = getattr(ir, "function", None)
    # A direct high-level call to a resolved sibling joins on selector against
    # that sibling's OWN canonical selector (``cross_contract`` derivation 1), so
    # lower user-defined parameter types here too — contract/interface → address,
    # enum → uint<N>, struct → tuple. The string ``full_name`` keeps names like
    # ``addAsset(ERC20)`` or ``send(MessagingParams,address)`` whose keccak is not
    # the real EVM selector, and once the callee side is canonical the join would
    # silently drop such a call. A LibraryCall's callee is a library internal with
    # no external selector and nothing joins against it, so it keeps the string
    # form (its selector is notional and ubiquitous — not worth churning).
    if type(ir).__name__ == "HighLevelCall" and fn is not None:
        from .predicate_artifacts import _canonical_signature

        canonical = _canonical_signature(fn)
        if canonical:
            return canonical
    for attr in ("full_name", "signature_str"):
        value = getattr(fn, attr, None)
        if isinstance(value, str) and "(" in value and value.endswith(")"):
            return value.rsplit(".", 1)[-1]
    value = getattr(ir, "function_name", None)
    if isinstance(value, str) and "(" in value and value.endswith(")"):
        return value.rsplit(".", 1)[-1]
    return None


def _classify_node_irs(node: Any) -> list[tuple[str, str, str | None]]:
    """Classify the non-state-write sinks at a node. Returns a list of
    ``(kind, target, selector)`` triples.

    State writes are handled separately — Slither's
    ``node.state_variables_written`` is more reliable than walking IR
    assignments by hand."""
    out: list[tuple[str, str, str | None]] = []
    # Non-SSA def map, node-local: the cast IRs defining an inline-cast receiver
    # (``IERC20(address(eETH)).safeTransferFrom`` emits both TypeConversions and
    # the call in one node) live here, letting the head resolve past the temporary.
    def_by_id = {id(lv): ir for ir in _node_irs(node) if (lv := getattr(ir, "lvalue", None)) is not None}
    for ir in _node_irs(node):
        op = type(ir).__name__
        if op == "NewContract":
            target = getattr(ir, "contract_name", None) or str(getattr(ir, "contract_created", "")) or "unknown"
            out.append(("contract_creation", str(target), None))
        elif op in ("HighLevelCall", "LibraryCall"):
            function_name = getattr(ir, "function_name", None) or "call"
            selector = _selector_for(_callee_signature(ir))
            # A LibraryCall's real receiver is its first argument; ``destination``
            # is the library contract itself.
            if op == "LibraryCall":
                arguments = list(getattr(ir, "arguments", []) or [])
                head = arguments[0] if arguments else getattr(ir, "destination", None)
            else:
                head = getattr(ir, "destination", None)
            resolved = _resolve_cast_head(head, def_by_id)
            destination_name = getattr(resolved, "name", None) or str(resolved) or "unknown"
            out.append(("external_call", f"{destination_name}.{function_name}", selector))
        elif op == "LowLevelCall":
            target = getattr(getattr(ir, "destination", None), "name", None) or str(
                getattr(ir, "destination", None) or "unknown"
            )
            function_name = str(getattr(ir, "function_name", "") or "")
            if function_name == "delegatecall":
                out.append(("delegatecall", str(target), None))
            else:
                out.append(("external_call", f"{target}.{function_name or 'call'}", None))
        elif op == "SolidityCall":
            function_name = getattr(getattr(ir, "function", None), "name", "") or ""
            arguments = list(getattr(ir, "arguments", []) or [])
            if function_name.startswith("selfdestruct("):
                out.append(("selfdestruct", "selfdestruct", None))
            elif function_name.startswith("sstore("):
                # Inline-assembly storage write. Slither does not populate
                # node.state_variables_written for assembly, so this is the
                # only place the write is visible. Key the sink by the slot
                # literal/expr; slot->named-var resolution is a separate concern.
                slot = str(arguments[0]) if arguments else "unknown"
                out.append(("state_write", f"assembly_storage:{slot}", None))
            elif function_name.startswith("delegatecall("):
                # Inline-assembly delegatecall, e.g. an EIP-1967 proxy fallback.
                # Signature: delegatecall(gas, addr, inOff, inLen, outOff, outLen).
                target = str(arguments[1]) if len(arguments) > 1 else "assembly_delegatecall"
                out.append(("delegatecall", f"assembly_delegatecall:{target}", None))
    return out


def _walk_unit_for_sinks(
    unit: Any,
    visited: set[Any],
    origin: str,
) -> list[tuple[str, str, str | None, str]]:
    """Recursively gather ``(kind, target, selector, origin)`` sink tuples
    from ``unit`` and any internal/library/modifier callees. ``origin``
    flips to ``guard`` the moment the walk steps through a modifier call and
    stays there for the rest of that subtree. De-dup happens at the caller
    level so distinct indices are preserved."""
    unit_key = getattr(unit, "canonical_name", None) or getattr(unit, "full_name", None) or id(unit)
    if unit_key in visited:
        return []
    visited.add(unit_key)

    found: list[tuple[str, str, str | None, str]] = []
    for node in getattr(unit, "nodes", []) or []:
        for var_name in _node_kind_state_writes(node):
            found.append(("state_write", var_name, None, origin))
        for kind, target, selector in _classify_node_irs(node):
            found.append((kind, target, selector, origin))
        # Recurse into internal/library callees so transitive writes
        # surface on the entry-point's record.
        for ir in _node_irs(node):
            op = type(ir).__name__
            if op not in ("InternalCall", "LibraryCall"):
                continue
            callee = getattr(ir, "function", None)
            if callee is None or not getattr(callee, "nodes", None):
                continue
            child_origin = "guard" if (origin == "guard" or _is_modifier_call(ir)) else "body"
            found.extend(_walk_unit_for_sinks(callee, visited, child_origin))
    return found


def _build_sink_records(function: Any) -> list[SinkRecord]:
    """One sink per (kind, target) pair we discover, transitively
    deduped while preserving order. A sink reachable through both the body
    and a guard keeps ``origin=body`` (a real effect wins). The selector
    field is per-sink: only ``external_call`` sinks carry one, and only
    when Slither exposes the called function's canonical signature."""
    function_name = _function_full_name(function)
    quads = _walk_unit_for_sinks(function, set(), "body")

    out: list[SinkRecord] = []
    index: dict[tuple[str, str, str | None], int] = {}
    for kind, target, selector, origin in quads:
        key = (kind, target, selector)
        if key in index:
            if origin == "body":
                out[index[key]]["origin"] = "body"
            continue
        idx = len(out)
        record: SinkRecord = {
            "id": _sink_id(function_name, kind, target, idx),
            "function": function_name,
            "kind": kind,
            "target": target,
            "selector": selector,
            "origin": origin,
        }
        index[key] = idx
        out.append(record)
    return out


# ---------------------------------------------------------------------------
# State-write facts (member paths + hygiene classes).
# ---------------------------------------------------------------------------


def _struct_member_types(state_variables: list[Any]) -> dict[str, dict[str, str]]:
    """``{var_name: {member_name: declared_type}}`` for struct-typed state
    vars, read from Slither's structure ``elems``."""
    out: dict[str, dict[str, str]] = {}
    for variable in state_variables:
        declared = getattr(variable, "type", None)
        structure = getattr(declared, "type", None)
        elems = getattr(structure, "elems", None)
        if isinstance(elems, dict):
            name = getattr(variable, "name", "") or ""
            out[name] = {member: str(getattr(value, "type", "") or "") for member, value in elems.items()}
    return out


def _transitive_member_writes(function: Any, wanted: set[str]) -> dict[str, set[str]]:
    """``{var_name: {member}}`` — member-level writes into the ``wanted``
    base state vars, tracked by pairing a ``Member`` IR (``$.member``) with
    the ``Assignment`` that writes the reference it produced. Walks the same
    internal/library/modifier callees as sink discovery."""
    out: dict[str, set[str]] = {}
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        key = id(unit)
        if key in visited:
            return
        visited.add(key)
        ref_to_pair: dict[int, tuple[str, str]] = {}
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                op = type(ir).__name__
                if op == "Member":
                    base = getattr(ir, "variable_left", None)
                    base_name = getattr(base, "name", None)
                    member = getattr(ir, "variable_right", None)
                    member_name = getattr(member, "name", None) or str(member)
                    lvalue = getattr(ir, "lvalue", None)
                    if isinstance(base_name, str) and base_name in wanted and lvalue is not None:
                        ref_to_pair[id(lvalue)] = (base_name, str(member_name))
                elif op == "Assignment":
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is not None and id(lvalue) in ref_to_pair:
                        base_name, member_name = ref_to_pair[id(lvalue)]
                        out.setdefault(base_name, set()).add(member_name)
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                    continue
                callee = getattr(ir, "function", None)
                if callee is not None and getattr(callee, "nodes", None):
                    walk(callee)

    walk(function)
    return out


_SLOT_POINTER_CONSTANTS: WeakKeyDictionary[Any, frozenset[str]] = WeakKeyDictionary()


def _units_of(contract: Any) -> list[Any]:
    """Every code unit whose IR belongs to ``contract`` — functions plus
    modifiers, the two places Slither lowers a body into nodes."""
    return [*(getattr(contract, "functions", []) or []), *(getattr(contract, "modifiers", []) or [])]


def _collect_slot_pointer_constants(contract: Any) -> frozenset[str]:
    """Constant state vars PROVEN by the lowered IR to denote a storage SLOT.

    Two assembly shapes, both facts of the IR rather than of the identifier:

    * ``assembly { $.slot := C }`` lowers to an ``Assignment`` that binds a
      *storage-location* local (``is_storage``) from the constant — the ERC-7201
      namespaced-struct form (OZ v5 ``_getXStorage()``).
    * ``assembly { sstore(C, v) }`` lowers to an ``Assignment`` whose *lvalue*
      IS the constant. Solidity forbids assigning to a constant, so outside the
      synthetic constant-initializer unit (``is_constructor_variables``) this can
      only be the constant used as a slot number — the Solady / EIP-1967 form.

    Those same two shapes are why Slither attributes a "write" to the constant at
    all, so the set is exactly the population this classification has to judge.
    An ordinary ``bytes32`` constant (a role id, a keccak'd domain separator)
    reaches neither shape and stays a plain ``constant``."""
    cached = _SLOT_POINTER_CONSTANTS.get(contract)
    if cached is not None:
        return cached
    constants = {
        name
        for variable in _all_state_variables(contract)
        if bool(getattr(variable, "is_constant", False)) and (name := getattr(variable, "name", "") or "")
    }
    found: set[str] = set()
    if constants:
        for unit in _units_of(contract):
            initializer = bool(getattr(unit, "is_constructor_variables", False))
            for node in getattr(unit, "nodes", []) or []:
                for ir in _node_irs(node):
                    if type(ir).__name__ != "Assignment":
                        continue
                    lvalue = getattr(ir, "lvalue", None)
                    rvalue = getattr(ir, "rvalue", None)
                    if bool(getattr(lvalue, "is_storage", False)):
                        rname = getattr(rvalue, "name", "") or ""
                        if rname in constants:
                            found.add(rname)
                    if initializer:
                        continue
                    lname = getattr(lvalue, "name", "") or ""
                    if lname in constants:
                        found.add(lname)
    result = frozenset(found)
    _SLOT_POINTER_CONSTANTS[contract] = result
    return result


_REENTRANCY_GUARDS: WeakKeyDictionary[Any, frozenset[str]] = WeakKeyDictionary()

# Bounds the transitive walk for the set/restore shape. Guard helpers are one or
# two hops (``nonReentrant`` -> ``_nonReentrantBefore`` -> ``_reentrancyGuardStorage``);
# the ``seen`` set already guarantees termination.
_GUARD_WALK_DEPTH = 6


def _nodes_state_writes(nodes: list[Any], seen: set[int], depth: int) -> set[str]:
    """State-var names written by ``nodes``, following internal/library callees
    (OZ v5 splits the guard's set and restore into helper calls)."""
    names: set[str] = set()
    for node in nodes:
        names.update(_node_kind_state_writes(node))
        if depth >= _GUARD_WALK_DEPTH:
            continue
        for ir in _node_irs(node):
            if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                continue
            callee = getattr(ir, "function", None)
            key = id(callee)
            if callee is None or key in seen or not getattr(callee, "nodes", None):
                continue
            names |= _nodes_state_writes(list(callee.nodes), seen | {key}, depth + 1)
    return names


def _nodes_around_placeholder(modifier: Any) -> tuple[list[Any], list[Any]] | None:
    """``(pre, post)`` node lists split at the modifier's ``_;`` placeholder, or
    ``None`` when the modifier has no placeholder."""
    nodes = list(getattr(modifier, "nodes", []) or [])
    for index, node in enumerate(nodes):
        if str(getattr(node, "type", "")).endswith("PLACEHOLDER"):
            return (nodes[:index], nodes[index + 1 :])
    return None


def _collect_reentrancy_guard_vars(contract: Any) -> frozenset[str]:
    """State vars PROVEN by the IR to be reentrancy guards: written on BOTH
    sides of a modifier's ``_;`` placeholder.

    Set-at-entry / restore-at-exit around the wrapped body is the defining shape
    of a guard and of nothing else — an authority pointer, a pause latch or an
    accounting balance is never restored to its prior value as the call unwinds.
    The walk follows internal/library callees, so the OZ form
    (``nonReentrant`` -> ``_nonReentrantBefore()`` / ``_nonReentrantAfter()``)
    is recognized as well as the inline Solmate/OZ-v4 form."""
    cached = _REENTRANCY_GUARDS.get(contract)
    if cached is not None:
        return cached
    guards: set[str] = set()
    for modifier in getattr(contract, "modifiers", []) or []:
        split = _nodes_around_placeholder(modifier)
        if split is None:
            continue
        pre, post = split
        guards |= _nodes_state_writes(pre, set(), 0) & _nodes_state_writes(post, set(), 0)
    result = frozenset(guards)
    _REENTRANCY_GUARDS[contract] = result
    return result


# Suppress-only name fallback for reentrancy guards. ``reentrancy_guard`` is a
# pure SUPPRESSOR — no consumer reads it to admit a fact, they only require
# ``normal`` — so an extra name-driven hit can withhold a fact but can never
# publish one, and the invariant "never fail toward an assertion" holds in the
# direction that matters. It stays because :func:`_collect_reentrancy_guard_vars`
# only sees the modifier form: a guard set and restored inline in a function body
# has no placeholder to split on, and letting a ``bool`` one through would put it
# in front of the pause-latch matcher as a flag some gate reverts on.
_REENTRANCY_GUARD_NAMES = frozenset(
    {"_status", "_reentrancyguard", "_reentrancystatus", "reentrancylock", "_locked", "locked", "_lock"}
)


def _is_reentrancy_guard_var(variable: Any, guards: frozenset[str]) -> bool:
    name = getattr(variable, "name", "") or ""
    if not name:
        return False
    if name in guards:
        return True
    low = name.lower()
    return "reentran" in low or low in _REENTRANCY_GUARD_NAMES


def _hygiene_class_for_var(variable: Any, function: Any, contract: Any) -> str:
    """Classify a write for role-fact hygiene. A view/pure function that
    "writes" is a Slither attribution ghost (OZ v5 namespaced getters); a
    constant proven to be an assembly slot locator is a pseudo-var, not the
    value it points at; reentrancy guards are control noise. All of these must
    be excluded from role facts but remain raw writes."""
    if _is_view_or_pure(function):
        return "view_writer"
    if variable is None:
        return "normal"
    name = getattr(variable, "name", "") or ""
    if bool(getattr(variable, "is_constant", False)):
        if contract is not None and name in _collect_slot_pointer_constants(contract):
            return "storage_location_pseudo"
        return "constant"
    guards = _collect_reentrancy_guard_vars(contract) if contract is not None else frozenset()
    if _is_reentrancy_guard_var(variable, guards):
        return "reentrancy_guard"
    return "normal"


def _state_write_facts(function: Any, sinks: list[SinkRecord]) -> list[StateWriteFact]:
    """Project the ``state_write`` sinks into richer facts: member
    granularity for struct writes, declared types, and hygiene classes."""
    contract = getattr(function, "contract", None)
    state_variables = _all_state_variables(contract) if contract is not None else []
    by_name = {getattr(variable, "name", ""): variable for variable in state_variables}
    member_types = _struct_member_types(state_variables)

    write_sinks = [s for s in sinks if s["kind"] == "state_write"]
    wanted = {s["target"] for s in write_sinks if not s["target"].startswith("assembly_storage:")}
    member_writes = _transitive_member_writes(function, wanted) if wanted else {}

    facts: list[StateWriteFact] = []
    for sink in write_sinks:
        target = sink["target"]
        origin = sink.get("origin", "body")
        if target.startswith("assembly_storage:"):
            facts.append(
                {
                    "var": target,
                    "declared_type": "",
                    "member_path": [],
                    "granularity": "assembly_slot",
                    "hygiene_class": "view_writer" if _is_view_or_pure(function) else "normal",
                    "origin": origin,
                }
            )
            continue
        variable = by_name.get(target)
        hygiene = _hygiene_class_for_var(variable, function, contract)
        declared_type = str(getattr(variable, "type", "") or "")
        members = member_writes.get(target)
        if members:
            for member in sorted(members):
                facts.append(
                    {
                        "var": target,
                        "declared_type": member_types.get(target, {}).get(member) or declared_type,
                        "member_path": [member],
                        "granularity": "member",
                        "hygiene_class": hygiene,
                        "origin": origin,
                    }
                )
        else:
            facts.append(
                {
                    "var": target,
                    "declared_type": declared_type,
                    "member_path": [],
                    "granularity": "var",
                    "hygiene_class": hygiene,
                    "origin": origin,
                }
            )
    return facts


# ---------------------------------------------------------------------------
# Value-flow facts (direction correction + native transfer/send sinks).
# ---------------------------------------------------------------------------


def _arg_is_address_this(arg: Any, this_ids: set[int], this_names: set[str]) -> bool:
    if arg is None:
        return False
    if getattr(arg, "name", None) == "this":
        return True
    if id(arg) in this_ids:
        return True
    name = getattr(arg, "name", None)
    return isinstance(name, str) and name in this_names


def _base_name(name: Any) -> str | None:
    """Strip Slither's SSA version suffix (``dest_1`` -> ``dest``). The
    provenance engine keys locals by their *base* name, so version suffixes
    must be normalized before a set-membership test against it."""
    if not isinstance(name, str):
        return None
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


# Contract-level setter set: state vars written by any non-constructor function
# body, as Slither attributes writes. A setter's *existence* is a dispositive
# fact. Its *absence* is only a sound proof that a non-immutable var cannot be
# redirected post-deploy when the scan is DISPOSITIVELY COMPLETE — i.e. Slither
# attributed every write in the contract's code. Two blind spots break that
# precondition and are checked by ``_setter_scan_complete``: a raw/computed-slot
# ``sstore`` (Slither attributes ``x.slot`` writes to ``x`` but not
# ``sstore(0, …)`` / keccak-slot writes), and any ``delegatecall`` (foreign code
# can write any slot as this contract). When the scan is incomplete, "no setter"
# degrades to ``indeterminate`` — never a proven-negative "fixed destination".
# A third blind spot — storage-pointer aliasing — is resolved separately by
# ``_aliased_storage_writes``: a state var written only through a callee taking a
# ``storage`` reference (``using X for`` / library / internal storage-lib idiom)
# is not attributed by ``all_state_variables_written`` either. We follow the
# aliasing to attribute the write back to its origin var (a real setter), and
# only fall back to indeterminate for the aliases we genuinely cannot resolve.
# Memoized per contract for the build pass.
_SETTER_VARS: WeakKeyDictionary[Any, set[str]] = WeakKeyDictionary()
_SETTER_SCAN_COMPLETE: WeakKeyDictionary[Any, bool] = WeakKeyDictionary()
_ALIASED_WRITES: WeakKeyDictionary[Any, tuple[set[str], set[str], bool]] = WeakKeyDictionary()

# Recursion depth for following a storage reference through forwarding callees.
_STORAGE_ALIAS_DEPTH = 6


def _setter_state_vars(contract: Any) -> set[str]:
    cached = _SETTER_VARS.get(contract)
    if cached is not None:
        return cached
    setters: set[str] = set()
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False):
            continue
        try:
            written = fn.all_state_variables_written()
        except Exception:  # pragma: no cover - slither edge
            written = []
        for var in written or []:
            name = getattr(var, "name", None)
            if name:
                setters.add(name)
    # Storage-pointer-aliased writes Slither did not attribute, resolved back to
    # their origin state var — these are real, redirecting setters.
    setters |= _aliased_storage_writes(contract)[0]
    _SETTER_VARS[contract] = setters
    return setters


def _arg_is_param(arg: Any, param: Any) -> bool:
    if arg is param:
        return True
    pname = getattr(param, "name", None)
    return bool(pname) and getattr(arg, "name", None) == pname


def _storage_param_write_status(callee: Any, param: Any, depth: int = 0, seen: set[int] | None = None) -> str:
    """Whether ``callee`` writes through its storage-reference parameter
    ``param`` — directly (``param.field = …`` / ``param[…] = …``, which puts
    ``param`` in the callee's ``variables_written``) or transitively (forwarding
    ``param`` into another storage-writing callee). Returns ``writes`` /
    ``reads_only`` / ``unresolved`` (callee body absent — cannot decide)."""
    if callee is None or not getattr(callee, "nodes", None):
        return "unresolved"
    if depth > _STORAGE_ALIAS_DEPTH:
        return "unresolved"
    seen = seen if seen is not None else set()
    if id(callee) in seen:
        # A recursion cycle: we cannot see whether the write happens down the
        # recursive tail. Fail toward unresolved (-> indeterminate), never
        # reads_only — that would let a genuinely-redirected var read as a
        # proven-fixed "no setter".
        return "unresolved"
    seen.add(id(callee))
    pname = getattr(param, "name", None)
    for written in getattr(callee, "variables_written", []) or []:
        if written is param or (pname and getattr(written, "name", None) == pname):
            return "writes"
    status = "reads_only"
    for node in getattr(callee, "nodes", []) or []:
        for ir in _node_irs(node):
            if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                continue
            sub = getattr(ir, "function", None)
            subparams = list(getattr(sub, "parameters", []) or [])
            for sub_param, arg in zip(subparams, getattr(ir, "arguments", []) or []):
                if not getattr(sub_param, "is_storage", False) or not _arg_is_param(arg, param):
                    continue
                result = _storage_param_write_status(sub, sub_param, depth + 1, seen)
                if result == "writes":
                    return "writes"
                if result == "unresolved":
                    status = "unresolved"
    return status


def _resolve_storage_origin(arg: Any, function: Any, seen: set[str] | None = None) -> str | None:
    """The origin state-variable NAME a storage-reference argument aliases, or
    ``None`` when it cannot be tied to a single declared state var. Handles a
    direct state var and a local storage pointer assigned from a state var or a
    member/index of one (``Box storage b = box;`` / ``= boxes[k];``). A pointer
    sourced from a call return is unresolvable — ``None``."""
    from slither.core.variables.state_variable import StateVariable  # type: ignore[import]

    if isinstance(arg, StateVariable):
        return getattr(arg, "name", None)
    aname = getattr(arg, "name", None)
    if not aname:
        return None
    seen = seen if seen is not None else set()
    if aname in seen:
        return None
    seen.add(aname)
    for node in getattr(function, "nodes", []) or []:
        for ir in _node_irs(node):
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is None or getattr(lvalue, "name", None) != aname:
                continue
            tn = type(ir).__name__
            if tn == "Assignment":
                return _resolve_storage_origin(getattr(ir, "rvalue", None), function, seen)
            if tn in ("Member", "Index"):
                base = getattr(ir, "variable_left", None)
                if isinstance(base, StateVariable):
                    return getattr(base, "name", None)
                return _resolve_storage_origin(base, function, seen)
            return None  # call-sourced / cast / other — not a single state var
    return None


def _aliased_storage_writes(contract: Any) -> tuple[set[str], set[str], bool]:
    """Resolve storage-pointer aliasing the attributed-write scan misses.

    Returns ``(resolved_setters, indeterminate_vars, contract_unresolvable)``:
    * ``resolved_setters`` — origin state vars written through a storage-ref
      alias that resolved to a definite variable: real setters (-> storage_setter).
    * ``indeterminate_vars`` — origin vars aliased into a callee whose
      write-through status couldn't be decided; their no-setter proof is unsound
      so they degrade to indeterminate (not storage_no_setter).
    * ``contract_unresolvable`` — a write-through alias whose origin var itself
      couldn't be resolved (unknown which var was redirected): no no-setter proof
      in the contract is sound, so the whole scan is incomplete.
    """
    cached = _ALIASED_WRITES.get(contract)
    if cached is not None:
        return cached
    resolved: set[str] = set()
    indeterminate: set[str] = set()
    contract_unresolvable = False
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False):
            continue
        for node in getattr(fn, "nodes", []) or []:
            for ir in _node_irs(node):
                if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                    continue
                callee = getattr(ir, "function", None)
                params = list(getattr(callee, "parameters", []) or [])
                for param, arg in zip(params, getattr(ir, "arguments", []) or []):
                    if not getattr(param, "is_storage", False):
                        continue
                    status = _storage_param_write_status(callee, param)
                    if status == "reads_only":
                        continue
                    origin = _resolve_storage_origin(arg, fn)
                    if origin is None:
                        contract_unresolvable = True
                    elif status == "writes":
                        resolved.add(origin)
                    else:  # "unresolved" — might write, cannot decide for this origin
                        indeterminate.add(origin)
    result = (resolved, indeterminate, contract_unresolvable)
    _ALIASED_WRITES[contract] = result
    return result


def _setter_scan_complete(contract: Any) -> bool:
    """True iff Slither's write attribution is exhaustive for this contract, so
    the *absence* of a setter is dispositive. False when a value could be
    written through a channel the attributed-write scan cannot see:

    * an unattributed assembly ``sstore`` — Slither lowers ``sstore(x.slot, …)``
      to an attributed write of ``x`` (no ``sstore`` IR survives), so a residual
      ``SolidityCall sstore(...)`` IR is exactly the raw-numeric / computed-slot
      write it could not attribute;
    * a ``delegatecall`` / ``callcode`` — foreign code executes in this
      contract's storage context and may write any slot;
    * a storage-pointer alias written through a callee whose ORIGIN state var
      could not be resolved (``_aliased_storage_writes`` third element) — some
      unknown var was redirected.

    Modifiers are scanned too (assembly can live in a guard body). Memoized."""
    cached = _SETTER_SCAN_COMPLETE.get(contract)
    if cached is not None:
        return cached
    if _aliased_storage_writes(contract)[2]:
        _SETTER_SCAN_COMPLETE[contract] = False
        return False
    units = list(getattr(contract, "functions", []) or []) + list(getattr(contract, "modifiers", []) or [])
    complete = True
    for unit in units:
        if not complete:
            break
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                tn = type(ir).__name__
                if tn == "LowLevelCall":
                    if getattr(ir, "function_name", None) in ("delegatecall", "callcode"):
                        complete = False
                        break
                elif tn == "SolidityCall":
                    name = getattr(getattr(ir, "function", None), "name", "") or ""
                    if name.startswith(("sstore(", "delegatecall(", "callcode(")):
                        complete = False
                        break
            if not complete:
                break
    _SETTER_SCAN_COMPLETE[contract] = complete
    return complete


class _UnitCtx:
    """Per-walked-unit classification context for value-flow destinations and
    amounts. Carries the unit's provenance map plus the two soundness guards:

    * ``merged`` — base names of LOCAL variables that a Phi merges across
      branches. The engine keys locals by base name, so two branch versions of
      ``d`` (``d = cond ? who : feeSink``) collapse to whichever assignment was
      processed last — silently discarding the other origin. Any destination
      that reaches such a base is forced ``indeterminate`` rather than trusting
      the collapsed value. (State-variable entrypoint Phis are excluded: their
      incoming versions are the same origin, not a cross-branch merge.)
    * ``nested`` — True when the unit is an internal callee, not the entry
      point. A ``parameter`` origin inside a callee is not self-evidently
      caller-directed: the entry may forward a fixed state var OR a
      caller-chosen argument into it. But the value-flow walk is rooted at ONE
      external entry, so the argument forwarded at each call site along that
      single path is unambiguous. ``param_bindings`` carries that forwarded
      origin (see below); a nested ``parameter`` is resolved through it to the
      entry-rooted kind, and only degrades to ``indeterminate`` when the
      binding is missing, unresolvable, or divergent across call sites. A state
      var / ``msg.sender`` / constant is contract-global and stays trustworthy
      across the internal-call boundary regardless.
    * ``param_bindings`` — for a nested unit, maps each of the unit's formal
      parameter base names to the *neutral origin* (see ``_arg_origin``) the
      entry-rooted walk forwarded into it at this call site: an entry parameter,
      ``msg.sender``, ``tx.origin``, ``address(this)``, a constant, or a named
      state variable. ``None`` on the entry itself (its own parameters ARE the
      caller-directed origin). Threaded down ``walk`` per call site; a helper
      reached from two sites with divergent bindings is re-walked so the
      cross-site fold collapses the disagreement to ``indeterminate``.
    * ``param_index_bindings`` — the positional half of ``param_bindings``: for a
      nested unit, the ENTRY parameter INDEX each formal binds to, present only
      for the formals whose argument resolved to one unambiguous entry parameter
      (never for a struct member / array element of one). The origin alone says
      *a* parameter; addressing an ABI argument slot needs *which*. Threaded and
      re-walked exactly like ``param_bindings``, so two call sites forwarding
      different parameter positions disagree at the fold instead of one winning."""

    def __init__(
        self,
        bundle: _EngineBundle,
        state_vars_by_name: dict[str, Any],
        setters: set[str],
        alias_indeterminate: set[str],
        setter_scan_complete: bool,
        nested: bool,
        param_bindings: dict[str, tuple[str, ...]] | None = None,
        param_index_bindings: dict[str, int] | None = None,
    ) -> None:
        # Context-independent, shared across every entry that reaches this unit.
        self.engine = bundle.engine
        self.param_names = bundle.param_names
        self.merged = bundle.merged
        self.def_by_id = bundle.def_by_id
        self.param_indexes = bundle.param_indexes
        # Contract-level (constant within a contract) + the per-context nested flag.
        self.state_vars_by_name = state_vars_by_name
        self.setters = setters
        self.alias_indeterminate = alias_indeterminate
        self.setter_scan_complete = setter_scan_complete
        self.nested = nested
        self.param_bindings = param_bindings
        self.param_index_bindings = param_index_bindings


class _EngineBundle:
    """The context-independent provenance artifacts for one function: the SSA
    ``ProvenanceEngine`` (run to fixed point), formal-parameter base names, the
    Phi-merged local bases, and the SSA def-use index. All are pure functions of
    the function's own IR — identical whichever entry point reaches it — so the
    bundle is memoized per function across the whole build pass. Only the
    per-context ``nested`` interpretation lives on ``_UnitCtx``."""

    __slots__ = ("engine", "param_names", "merged", "def_by_id", "param_indexes")

    def __init__(
        self,
        engine: ProvenanceEngine,
        param_names: set[str],
        merged: set[str],
        def_by_id: dict[int, Any],
        param_indexes: dict[str, int],
    ) -> None:
        self.engine = engine
        self.param_names = param_names
        self.merged = merged
        self.def_by_id = def_by_id
        self.param_indexes = param_indexes


# Per-function memo of the context-independent bundle, keyed by the Slither
# function object (weak so it dies with the Slither instance). Collapses the
# prior O(entries × helpers) engine rebuilds to one run per function per pass.
_ENGINE_BUNDLE: WeakKeyDictionary[Any, _EngineBundle] = WeakKeyDictionary()


def _param_indexes_of(unit: Any) -> dict[str, int]:
    """``formal parameter base name -> positional index``. A name that repeats
    (shadowing, an unnamed formal reusing the empty name) is DROPPED: the index
    is used to address an ABI argument slot, so an ambiguous name must resolve to
    nothing rather than to the first match."""
    indexes: dict[str, int] = {}
    ambiguous: set[str] = set()
    for position, param in enumerate(getattr(unit, "parameters", []) or []):
        base = _base_name(getattr(param, "name", None))
        if not base:
            continue
        if base in indexes:
            ambiguous.add(base)
            continue
        indexes[base] = position
    for name in ambiguous:
        indexes.pop(name, None)
    return indexes


def _engine_bundle_for(unit: Any) -> _EngineBundle:
    cached = _ENGINE_BUNDLE.get(unit)
    if cached is not None:
        return cached
    from slither.core.cfg.node import NodeType  # type: ignore[import]
    from slither.core.variables.local_variable import LocalVariable  # type: ignore[import]
    from slither.slithir.operations import Phi  # type: ignore[import]

    engine = ProvenanceEngine(unit)
    engine.run()
    param_names = {
        base for param in getattr(unit, "parameters", []) or [] if (base := _base_name(getattr(param, "name", None)))
    }
    param_indexes = _param_indexes_of(unit)
    merged: set[str] = set()
    def_by_id: dict[int, Any] = {}
    for node in getattr(unit, "nodes", []) or []:
        # An ENTRYPOINT-node Phi is a parameter-binding phi (Slither's
        # interprocedural SSA linking a callee param to its caller argument), NOT
        # an intra-function cross-branch merge. Counting it as "merged" would
        # spuriously force every forwarded-param destination in an internal
        # helper to indeterminate. A genuine reassignment merge lives at an
        # ENDIF/other body node and is still caught.
        is_entrypoint = getattr(node, "type", None) == NodeType.ENTRYPOINT
        for ir in getattr(node, "irs_ssa", ()) or ():
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is not None:
                def_by_id[id(lvalue)] = ir
            if isinstance(ir, Phi) and not is_entrypoint:
                nsv = getattr(lvalue, "non_ssa_version", None) or lvalue
                if isinstance(nsv, LocalVariable):
                    base = _base_name(getattr(lvalue, "name", None))
                    if base:
                        merged.add(base)
    bundle = _EngineBundle(engine, param_names, merged, def_by_id, param_indexes)
    try:
        _ENGINE_BUNDLE[unit] = bundle
    except TypeError:  # pragma: no cover — unit not weak-referenceable
        pass
    return bundle


def _build_unit_ctx(
    unit: Any,
    is_entry: bool,
    state_vars_by_name: dict[str, Any],
    setters: set[str],
    alias_indeterminate: set[str],
    setter_scan_complete: bool,
    param_bindings: dict[str, tuple[str, ...]] | None = None,
    param_index_bindings: dict[str, int] | None = None,
) -> _UnitCtx:
    return _UnitCtx(
        _engine_bundle_for(unit),
        state_vars_by_name,
        setters,
        alias_indeterminate,
        setter_scan_complete,
        not is_entry,
        param_bindings,
        param_index_bindings,
    )


def _ir_source_operands(ir: Any) -> list[Any]:
    """The value operands an IR derives its lvalue from — the edges of the
    def-use backward walk used by ``_reaches_merged_local``."""
    tn = type(ir).__name__
    if tn == "TypeConversion":
        return [getattr(ir, "variable", None)]
    if tn == "Assignment":
        return [getattr(ir, "rvalue", None)]
    if tn == "Phi":
        return list(getattr(ir, "rvalues", ()) or [])
    if tn == "Unpack":
        return [getattr(ir, "tuple", None) or getattr(ir, "rvalue", None)]
    if tn == "Unary":
        return [getattr(ir, "rvalue", None)]
    if tn == "Binary":
        return [getattr(ir, "variable_left", None), getattr(ir, "variable_right", None)]
    if tn == "Member":
        # ``s.field`` — the field access carries the base local's identity, so a
        # destination read off a branch-reassigned struct local must reach it.
        return [getattr(ir, "variable_left", None)]
    if tn == "Index":
        # ``arr[k]`` — both the base and the key select the element; a merge in
        # either makes the destination element ambiguous.
        return [getattr(ir, "variable_left", None), getattr(ir, "variable_right", None)]
    return []


def _reaches_merged_local(value: Any, ctx: _UnitCtx) -> bool:
    if value is None or not ctx.merged:
        return False
    seen: set[int] = set()
    stack: list[Any] = [value]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        if _base_name(getattr(v, "name", None)) in ctx.merged:
            return True
        ir = ctx.def_by_id.get(id(v))
        if ir is not None:
            stack.extend(_ir_source_operands(ir))
    return False


# How deep to chase nested merges when deciding whether every branch of a value
# is caller-supplied. Reassignment chains are a hop or two (`if native: amount =
# msg.value`); past that the answer is "we did not prove it", which is the safe
# direction anyway.
_MERGE_RESOLVE_DEPTH = 4


def _phi_of(value: Any, ctx: _UnitCtx) -> Any:
    """The Phi IR that defines ``value``, or ``None``. Walks copy edges only, so
    the returned merge IS this value's definition rather than one of its inputs'."""
    seen: set[int] = set()
    stack: list[Any] = [value]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "Phi":
            return ir
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
    return None


# Neutral-origin tags that ARE a caller-chosen quantity, for the merge proof
# below. ``param`` is an entry parameter; ``caller_supplied`` is an already-proven
# merge of them, so a two-hop forward composes.
_CALLER_SUPPLIED_TAGS = ("param", "caller_supplied")


def _is_caller_supplied_leaf(value: Any, ctx: _UnitCtx) -> bool:
    """True when ``value`` IS a caller-chosen quantity: the ETH attached to the
    call, or a formal parameter that the caller-directed origin actually reaches.

    The parameter half is NOT the bare AST test it looks like. On the entry, a
    formal IS the caller's argument. In a NESTED unit it is only whatever the
    caller bound to it, and the caller may well have forwarded a state variable —
    so the formal is resolved through ``param_bindings`` exactly as
    :func:`_single_param_origin` resolves it. Reading a nested formal as
    self-evidently caller-supplied published ``caller_supplied`` for
    ``_helper(feeAmount)`` merged with ``msg.value``: an assertion that the caller
    picks the magnitude, on a branch where the magnitude is storage they cannot
    influence. A missing binding fails closed."""
    if value is None:
        return False
    from slither.core.declarations.solidity_variables import SolidityVariable  # type: ignore[import]

    if isinstance(value, SolidityVariable) and str(getattr(value, "name", "")) == "msg.value":
        return True
    base = _base_name(getattr(value, "name", None))
    if not base or base not in ctx.param_names:
        return False
    if not ctx.nested:
        return True
    if ctx.param_bindings is None:
        return False
    return ctx.param_bindings.get(base, ("indeterminate",))[0] in _CALLER_SUPPLIED_TAGS


def _merged_caller_supplied(value: Any, ctx: _UnitCtx, depth: int = 0) -> bool:
    """True when EVERY branch of a merged value is caller-supplied.

    ``function deposit(IERC20 asset, uint256 amount) payable`` that does
    ``if (asset == native) amount = msg.value;`` merges an ABI argument with the
    attached ETH. Both are the caller's number, so the merge is not the absence of
    an answer — it is a disjunction whose members agree on the only thing an
    amount kind claims. Collapsing it to ``indeterminate`` published "we traced
    nothing" about a quantity the caller picks outright.

    Deliberately NOT a slot claim: one branch has no ABI slot at all, so no
    ``amount_param_index`` follows from this (see :func:`_fold_param_index`).
    Anything the walk cannot prove caller-supplied — a storage read, a call
    result, a nested merge past the depth bound — fails the whole conjunction, so
    the answer degrades to ``indeterminate`` rather than to a guessed member."""
    if depth > _MERGE_RESOLVE_DEPTH:
        return False
    phi = _phi_of(value, ctx)
    if phi is None:
        return False
    inputs = list(getattr(phi, "rvalues", None) or [])
    if not inputs:
        return False
    for rvalue in inputs:
        if _is_caller_supplied_leaf(rvalue, ctx):
            continue
        resolved, _ir = _resolve_copies(rvalue, ctx.def_by_id)
        if _is_caller_supplied_leaf(resolved, ctx):
            continue
        if _merged_caller_supplied(rvalue, ctx, depth + 1):
            continue
        return False
    return True


def _operand_is_direct(value: Any, param_names: set[str]) -> bool:
    """True when the operand is a definitive AST leaf (Tier-1 dispositive): a
    StateVariable, a Solidity built-in (``msg.sender``/``msg.value``), a literal
    constant, or a formal-parameter read with no intervening cast/computation.
    Temporaries/references (cast results, computed values) are Tier-2 traces."""
    if value is None:
        return False
    tn = type(value).__name__
    if "Temporary" in tn or "Reference" in tn or "Tuple" in tn:
        return False
    from slither.core.declarations.solidity_variables import SolidityVariable  # type: ignore[import]
    from slither.core.variables.state_variable import StateVariable  # type: ignore[import]
    from slither.slithir.variables import Constant  # type: ignore[import]

    if isinstance(value, (StateVariable, SolidityVariable, Constant)):
        return True
    if isinstance(getattr(value, "non_ssa_version", None), StateVariable):
        return True
    base = _base_name(getattr(value, "name", None))
    return bool(base) and base in param_names


def _state_var_target_kind(name: str, ctx: _UnitCtx) -> str:
    var = ctx.state_vars_by_name.get(name)
    if var is None:
        return "indeterminate"
    if getattr(var, "is_constant", False):
        return "constant"
    if getattr(var, "is_immutable", False):
        return "immutable"
    if name in ctx.setters:
        return "storage_setter"
    if name in ctx.alias_indeterminate:
        # Aliased into a callee we could not decide writes-through — the
        # no-setter proof for this specific var is unsound.
        return "indeterminate"
    # No attributed setter. Only a *complete* scan makes that a proven negative
    # ("fixed destination"); an assembly-sstore/delegatecall/unresolved-alias
    # blind spot leaves it unknown — never assert immutability we could not prove.
    return "storage_no_setter" if ctx.setter_scan_complete else "indeterminate"


# A ``neutral origin`` is the entry-rooted source of a value forwarded across an
# internal-call boundary, independent of whether the value is used as a
# destination or an amount. One of: ``("param",)`` (an entry parameter, the
# caller-directed origin), ``("msg_sender",)``, ``("caller_controlled",)``
# (tx.origin), ``("self",)`` (address(this)), ``("constant",)``,
# ``("state_variable", name)``, or ``("indeterminate",)``. ``_arg_origin``
# computes it for a call-site argument (chaining through the caller's own
# bindings); ``_origin_to_*_kind`` translates it back into the destination /
# amount lattice at the use site.


def _single_param_origin(source: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """The neutral origin one ``parameter`` source resolves to. On the entry its
    own parameter IS the caller-directed origin → ``("param",)``. In a nested
    callee look it up in the forwarded ``param_bindings``; a missing binding →
    ``("indeterminate",)``."""
    if not ctx.nested:
        return ("param",)
    if ctx.param_bindings is None:
        return ("indeterminate",)
    base = _base_name(source.parameter_name) if source.parameter_name else None
    return ctx.param_bindings.get(base, ("indeterminate",)) if base else ("indeterminate",)


def _source_neutral_origin(source: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """One provenance source → its neutral origin. A ``parameter`` chains through
    the entry-rooted binding (``_single_param_origin``); every other kind maps to
    a contract-global origin. Anything not a clean single origin (view/external
    call, block context, signature recovery) → ``("indeterminate",)``.

    This is what neutralizes Slither's entrypoint-Phi parameter binding: a nested
    forwarded param carries BOTH its own ``parameter`` seed AND the caller's
    argument source unioned in by the entry Phi. Resolving every source to a
    neutral origin and demanding they AGREE turns a consistent echo into that one
    origin, and any cross-site contamination into ``indeterminate``."""
    kind = source.kind
    if kind == "parameter":
        return _single_param_origin(source, ctx)
    if kind == "msg_sender":
        return ("msg_sender",)
    if kind == "tx_origin":
        # The transaction origin (an EOA the caller controls) — a proven
        # caller-directed destination, theft-shaped like msg_sender/param, but a
        # distinct address fact so it is not folded into msg_sender.
        return ("caller_controlled",)
    if kind == "self_address":
        return ("self",)
    if kind == "constant":
        # Carry the literal so a provably-zero value call can be recognized as a
        # non-flow. Classification only reads ``origin[0]`` so the extra element
        # is inert for the target/amount lattice.
        return ("constant", source.constant_value or "")
    if kind == "state_variable":
        return ("state_variable", source.state_variable_name) if source.state_variable_name else ("indeterminate",)
    # view_call, external_call, block_context, signature_recovery, top.
    return ("indeterminate",)


def _arg_origin(operand: Any, ctx: _UnitCtx, depth: int = 0) -> tuple[str, ...]:
    """The neutral origin a single call-site argument forwards, resolved in the
    caller's entry-rooted context. Every meaningful source resolves to a neutral
    origin and they must AGREE; any merge / unresolvable / multi-origin shape →
    ``("indeterminate",)`` — never a guessed member.

    A directly-read nested parameter takes the same entrypoint-Phi echo-drop the
    use-site classifiers take (``_forwarded_param_sources``): forwarding a
    parameter ONWARD through a second helper must resolve exactly as reading it
    at the send site would, or a two-hop forward through a helper that other
    entries also call (Lido ``claimWithdrawalsTo`` → ``_claim`` → ``_sendValue``,
    where ``_claim``'s Phi carries the sibling entries' ``msg.sender``) loses its
    binding to a phantom disagreement."""
    if operand is None:
        return ("indeterminate",)
    # An element read forwarded as an argument (``_execute(targets[i], …)``)
    # carries its ROOT base's origin — same rule, and same key-blindness, as
    # classifying it at a send site.
    elem = _element_origin(operand, ctx)
    if elem is not None:
        return elem
    if _reaches_merged_local(operand, ctx):
        # A merge whose every branch is caller-supplied is a known disjunction,
        # not an unknown. It resolves ONLY on the amount side: two caller-chosen
        # QUANTITIES agree on what an amount kind asserts, whereas two caller-
        # chosen DESTINATIONS are two different addresses and must stay
        # indeterminate — which is what ``_origin_to_target_kind`` does with this
        # tag, having no case for it.
        return ("caller_supplied",) if _merged_caller_supplied(operand, ctx) else ("indeterminate",)
    # The AMOUNT vocabulary, deliberately, even though this binding also feeds
    # destination resolution in the callee. ``param_derived`` is the one tag it
    # adds, and ``_origin_to_target_kind`` has no case for it, so a destination
    # resolved through this binding lands on ``indeterminate`` — bit-identical to
    # what the narrower call had already produced for the same operand. What it
    # buys is the amount side: ``vault.exit(to, asset, shareAmount.mulDivDown(
    # rate, ONE), …)`` forwards a scaled caller input, and refusing to name it
    # here made every ERC-4626-style redemption's amount ``indeterminate`` at the
    # sink, one hop from a fact we hold.
    call = _call_origin(operand, ctx, amount=True, depth=depth)
    if call is not None:
        return call
    srcs = ctx.engine._sources_for_value(operand)
    if not srcs or is_top(srcs):
        return ("indeterminate",)
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        origins = {_single_param_origin(s, ctx) for s in forwarded}
    else:
        origins = {_source_neutral_origin(s, ctx) for s in srcs if s.kind != "computed"}
    if len(origins) == 1 and ("indeterminate",) not in origins:
        return next(iter(origins))
    return ("indeterminate",)


def _source_param_index(source: Any, ctx: _UnitCtx) -> int | None:
    """The ENTRY parameter index one provenance source resolves to — the
    positional twin of ``_single_param_origin``. ``None`` for every source that
    is not a parameter reaching one unambiguous entry parameter."""
    if source.kind != "parameter":
        return None
    base = _base_name(source.parameter_name) if source.parameter_name else None
    if not base:
        return None
    if not ctx.nested:
        return ctx.param_indexes.get(base)
    return ctx.param_index_bindings.get(base) if ctx.param_index_bindings else None


def _reads_element(operand: Any, ctx: _UnitCtx) -> bool:
    """True when the operand's value is read THROUGH an array/mapping/struct
    access (``a[k]``, ``s.field``, ``map[k].field``).

    Such a destination is not an ABI argument slot even when its root is a
    parameter: planting a probe address would mean rewriting a field inside an
    encoded struct/array. Index emission bails on this shape entirely — the
    ``target_kind`` (``param`` for a calldata-struct root, the base var's
    mutability for a storage root) is unaffected."""
    seen: set[int] = set()
    stack: list[Any] = [operand]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn in ("Index", "Member"):
            return True
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
    return False


def _operand_param_index(operand: Any, ctx: _UnitCtx) -> int | None:
    """The ENTRY parameter index an operand resolves to — the positional twin of
    ``_arg_origin``, and the ONLY producer of ``target_param_index``.

    Emits an index only when EVERY source the origin resolution considered is a
    parameter binding onto the SAME entry parameter, so the operand is that whole
    argument and nothing else. Element reads, merged locals, computed mixes,
    missing bindings and non-parameter origins all yield ``None`` — the caller
    must then plant no probe rather than address a guessed slot."""
    if operand is None or _reads_element(operand, ctx) or _reaches_merged_local(operand, ctx):
        return None
    srcs = ctx.engine._sources_for_value(operand)
    if not srcs or is_top(srcs):
        return None
    forwarded = _forwarded_param_sources(srcs, ctx)
    considered = forwarded if forwarded is not None else [s for s in srcs if s.kind != "computed"]
    if not considered:
        return None
    indexes = {_source_param_index(s, ctx) for s in considered}
    if len(indexes) != 1:
        return None
    return next(iter(indexes))


def _is_zero_literal(value: str) -> bool:
    try:
        return int(value, 0) == 0
    except (TypeError, ValueError):
        return False


def _amount_is_provably_zero(operand: Any, ctx: _UnitCtx) -> bool:
    """True when a value-call's ``call_value`` provably resolves to constant zero,
    threading the caller binding (OZ ``SafeERC20`` routes token transfers through
    ``Address.functionCallWithValue(token, data, 0)`` — a ``.call{value: value}``
    whose ``value`` param is bound to the literal ``0``). A zero-value call moves
    no ETH, so it is not a value-out flow and must not fold with a real send."""
    origin = _arg_origin(operand, ctx)
    return origin[0] == "constant" and len(origin) > 1 and _is_zero_literal(origin[1])


def _origin_to_target_kind(origin: tuple[str, ...], ctx: _UnitCtx) -> str:
    tag = origin[0]
    if tag == "param":
        return "param"
    if tag == "msg_sender":
        return "msg_sender"
    if tag == "caller_controlled":
        return "caller_controlled"
    if tag == "self":
        return "self"
    if tag == "constant":
        return "constant"
    if tag == "token_owner":
        return "token_owner"
    if tag == "state_variable":
        return _state_var_target_kind(origin[1], ctx)
    return "indeterminate"


def _is_derivation(computed_kind: str | None) -> bool:
    """True for a ``computed`` tag produced by arithmetic on other operands
    (``BinaryType.SUBTRACTION`` / ``UnaryType.*``) — as opposed to a tag that
    merely names the value read (``msg.value``, ``balance(address)``,
    ``member.<field>``)."""
    return computed_kind is not None and computed_kind.startswith(("BinaryType.", "UnaryType."))


def _is_subtraction(computed_kind: str | None) -> bool:
    """True for the one arithmetic op that makes a balance read a DELTA. A
    comparison (``Math.min``'s ``a < b``) or a scaling (``balance / 2``) is not a
    delta and must not borrow the name."""
    return computed_kind == "BinaryType.SUBTRACTION"


def _origin_to_amount_kind(origin: tuple[str, ...]) -> str:
    tag = origin[0]
    if tag == "param":
        return "param"
    if tag == "constant":
        return "fixed_constant"
    if tag == "state_variable":
        return "bounded_by_storage"
    if tag == "param_derived":
        return "param_derived"
    if tag == "caller_supplied":
        return "caller_supplied"
    # An address origin (msg.sender / tx.origin / self) forwarded as an amount is
    # not a meaningful value bound — stay indeterminate rather than invent one.
    return "indeterminate"


# Element-root origins we classify from. A storage root gives the base var's
# mutability, a parameter root gives ``param`` (an element of a caller-supplied
# array/struct is still caller-chosen), a constant root is fixed. Any other root
# (``address(this)`` — some solc versions lower ``address(this).balance`` to a
# Member — an unresolved local, a merged base) is NOT an element classification;
# the caller falls through to the source-set path instead.
_ELEMENT_ROOT_TAGS = ("param", "state_variable", "constant")

_ELEMENT_WALK_DEFS = ("TypeConversion", "Assignment", "Index", "Member")


def _single_phi_input(var: Any, ctx: _UnitCtx) -> Any:
    """The one distinct predecessor of ``var`` when its SSA def is a SINGLE-input
    body Phi — pure renaming, not a merge (a storage-pointer local given a fresh
    version because the body wrote through it). ``None`` for a non-Phi def, a
    genuine multi-input merge (must NOT be followed to either arm), or an
    ENTRYPOINT parameter-binding Phi (Slither's interprocedural SSA link — following
    it would cross into the caller's SSA and strip a forwarded parameter of the
    binding the nested classifiers resolve it through)."""
    from slither.core.cfg.node import NodeType  # type: ignore[import]

    ir = ctx.def_by_id.get(id(var))
    if ir is None or type(ir).__name__ != "Phi":
        return None
    if getattr(getattr(ir, "node", None), "type", None) == NodeType.ENTRYPOINT:
        return None
    rvals = {id(rv): rv for rv in (getattr(ir, "rvalues", None) or []) if rv is not None and id(rv) != id(var)}
    return next(iter(rvals.values())) if len(rvals) == 1 else None


def _element_root_origins(operand: Any, ctx: _UnitCtx) -> set[tuple[str, ...]] | None:
    """If ``operand`` reads an array/mapping/struct element (``a[k]`` /
    ``s.field`` / ``map[k].field``, possibly via a storage-pointer local
    ``Req storage rq = _requests[id]; rq.recipient``), the set of neutral origins
    of the access's ROOT base. ``None`` when it is not such an access.

    This is a POSITIVE structural test on the operand's def-use chain — an
    ``Index`` / ``Member`` op — so it distinguishes a genuine element read from
    the source-set-identical shape a forwarded param produces via the entrypoint
    Phi (which has no Index/Member IR). The KEY is deliberately ignored: every
    element of one base shares that base's origin, so the base alone decides the
    kind and a caller-chosen (or loop-merged) index cannot upgrade or degrade it."""
    from slither.core.variables.state_variable import StateVariable  # type: ignore[import]

    seen: set[int] = set()
    stack: list[Any] = [operand]
    origins: set[tuple[str, ...]] = set()
    found_access = False
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        if isinstance(v, StateVariable) or isinstance(getattr(v, "non_ssa_version", None), StateVariable):
            # A bare state-var read only counts as an element base when it was
            # reached THROUGH an Index/Member (found_access) — a whole-var
            # destination stays a plain state_variable classification.
            continue
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
        elif tn == "Phi":
            # A single-input Phi is pure SSA renaming — a storage-pointer local
            # (``Bid storage bid = bids[id]``) given a fresh version because the
            # body wrote through it (``bid.isActive = false``). Follow it so the
            # aliased element resolves to the same root a direct read would. A
            # multi-input Phi is a genuine merge and ends this branch; the caller
            # then falls through to the merged-local guard rather than picking one
            # arm. (Reached only for a Phi in the def chain, not a Phi BASE — that
            # case is routed at the Index/Member handler below.)
            nxt = _single_phi_input(v, ctx)
            if nxt is not None:
                stack.append(nxt)
        elif tn in ("Index", "Member"):
            found_access = True
            base = getattr(ir, "variable_left", None)
            base_nsv = getattr(base, "non_ssa_version", None)
            base_var = (
                base if isinstance(base, StateVariable) else base_nsv if isinstance(base_nsv, StateVariable) else None
            )
            if base_var is not None:
                if base_var.name:
                    origins.add(("state_variable", base_var.name))
            elif type(ctx.def_by_id.get(id(base))).__name__ in _ELEMENT_WALK_DEFS or _single_phi_input(base, ctx):
                # A nested access (map[k].field), an aliasing local, or a
                # single-input-Phi storage pointer (``bid.amount`` where ``bid``
                # was SSA-renamed by a write through it) — keep walking to the root
                # rather than reading the intermediate reference's base∪key source
                # union. A multi-input Phi base is NOT walked here; it falls to the
                # ``_arg_origin`` resolution below, exactly as before.
                stack.append(base)
            else:
                # A parameter / merged / unresolvable root: resolve it exactly as
                # a forwarded call-site argument would be (binding-chained, with
                # the merged-local guard).
                origins.add(_arg_origin(base, ctx))
        # An unknown def (call return, etc.) ends this branch.
    return origins if (found_access and origins) else None


def _element_origin(operand: Any, ctx: _UnitCtx) -> tuple[str, ...] | None:
    """The neutral origin an element read takes from its ROOT base — NEVER from
    the caller-supplied key. ``None`` when the operand is not an element read, or
    when its root is not one we classify from (``address(this)``, a merged or
    unresolvable base). The caller then falls through to the source-set path,
    where the merged-local guard still applies — and that guard is also what
    catches a >1-root walk, since two roots require a Phi between them."""
    roots = _element_root_origins(operand, ctx)
    if roots is None or len(roots) != 1:
        return None
    root = next(iter(roots))
    return root if root[0] in _ELEMENT_ROOT_TAGS else None


# ERC-721 ``ownerOf(uint256)``. A destination read back from it is the CURRENT
# owner of the token id the caller passed: the caller chooses the id, the token's
# transfer history chooses the address. That is neither a caller-supplied
# argument (``param`` — the caller cannot name the payee) nor a fixed or
# admin-settable one (``storage_*`` — no setter redirects it), so it gets its own
# kind rather than being folded into a neighbour it would misdescribe.
_TOKEN_OWNER_SELECTOR = "0x6352211e"

# Def-chain edges that preserve "this value IS that call's return value".
_CALL_WALK_DEFS = ("TypeConversion", "Assignment")
_CALL_IR_OPS = ("InternalCall", "LibraryCall", "HighLevelCall")


def _call_standard_origin(ir: Any) -> tuple[str, ...]:
    """The neutral origin a recognized STANDARD callee returns. An unrecognized
    callee is ``("indeterminate",)`` — a return value we cannot name, NOT a value
    to keep resolving from the callee's internals."""
    if _selector_for(_callee_signature(ir)) == _TOKEN_OWNER_SELECTOR:
        return ("token_owner",)
    return ("indeterminate",)


def _call_param_argument_indexes(ir: Any, ctx: _UnitCtx) -> set[int]:
    """The distinct ENTRY parameter slots this call's ARGUMENTS resolve to.

    Each argument goes through :func:`_operand_param_index`, so an argument
    counts only when it IS one whole unambiguous entry parameter — an element
    read, a merged local, a computed mix and a non-parameter origin all
    contribute nothing."""
    out: set[int] = set()
    for arg in getattr(ir, "arguments", None) or []:
        index = _operand_param_index(arg, ctx)
        if index is not None:
            out.add(index)
    return out


def _call_amount_origin(ir: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """The neutral origin of an AMOUNT read back from a call, which can name one
    shape the destination lattice has no use for: ``param_derived``.

    ``param_derived`` claims EXACTLY this and nothing more, and every consumer
    must read it that way:

    - It is NOT a bound. The callee's rate is state we cannot see and it can
      move arbitrarily, so this kind must never be treated as an upper bound
      nor credited as a mitigation.
    - It is NOT proof of caller control. We cannot see inside the callee, so we
      cannot prove it honors its argument; it must not be read as "the caller
      determines the magnitude".
    - It IS: the amount is an external call's return value, and a caller-supplied
      entry parameter was among that call's arguments — the caller supplied an
      input, an external contract scaled it.

    The shape is ubiquitous (``transfer(receiver, convertToAssets(shares))`` in
    every ERC-4626-style redemption, ``unwrap`` on a rebasing wrapper), and
    collapsing it to ``indeterminate`` made it indistinguishable from "we traced
    nothing". A recognized standard callee still wins: naming what the callee
    returns is strictly more informative than naming what fed it."""
    standard = _call_standard_origin(ir)
    if standard[0] != "indeterminate":
        return standard
    return ("param_derived",) if _call_param_argument_indexes(ir, ctx) else ("indeterminate",)


# Call ops whose callee runs against the CALLER's own contract storage, so the
# caller's state-variable context classifies the callee's body correctly. An
# ``InternalCall`` is the same contract by definition; a library's functions are
# inlined (internal) or delegatecalled (external), and both read the caller's
# storage. A ``HighLevelCall`` is deliberately absent — its callee's state
# variables belong to a DIFFERENT contract, and reusing this context there would
# classify one contract's mutability as another's.
_SAME_CONTEXT_CALL_OPS = ("InternalCall", "LibraryCall")

# Depth bound on chasing helper returns through helpers. Real getter chains are a
# hop or two (``_governorIndirect`` -> ``_governor`` -> the state var); past that
# the answer degrades to "not proven", which is the safe direction.
_RETURN_ORIGIN_DEPTH = 4

# Re-entrancy guard for :func:`_callee_return_origin`. Resolving a helper's
# return value re-enters the general origin machinery, which can reach the same
# helper again (directly recursive, or mutually so through a second helper), and
# the recursion has no natural base case. A module-level set is sound here
# because the whole static build pass is single-threaded, and it is always
# cleared in a ``finally``.
_RETURN_ORIGIN_ACTIVE: set[int] = set()


def _return_values(callee: Any) -> list[Any] | None:
    """The single value each of ``callee``'s ``return`` statements yields, or
    ``None`` when the shape is not one this can reason about.

    ``None`` for a callee with no explicit return at all (it yields the type's
    zero value, which is not an origin), and for any return carrying a number of
    values other than one — a tuple return gives no way to say WHICH member
    reached the sink, and guessing a member is the failure mode this whole
    module is built to avoid."""
    values: list[Any] = []
    for node in getattr(callee, "nodes", []) or []:
        # ``irs_ssa``, NOT ``irs``: every lookup the returned operand then feeds
        # (the def-use index, the provenance engine) is keyed on the SSA objects,
        # so a non-SSA twin of the same variable resolves to nothing. It fails
        # quietly, and only for values whose SSA identity carries the answer — a
        # returned state variable resolves by name either way, a returned call
        # result does not.
        for ir in getattr(node, "irs_ssa", ()) or ():
            if type(ir).__name__ != "Return":
                continue
            operands = list(getattr(ir, "values", None) or [])
            if len(operands) != 1:
                return None
            values.append(operands[0])
    return values or None


def _callee_return_origin(ir: Any, ctx: _UnitCtx, depth: int) -> tuple[str, ...] | None:
    """The neutral origin of the value an in-contract helper RETURNS, or ``None``.

    The lattice already threads a caller's arguments INTO a helper, so a
    destination or amount passed down resolves interprocedurally. Nothing carried
    the answer back OUT, so ``_send(_governor(), amount)`` published
    ``indeterminate`` for a destination the contract states plainly — an
    admin-settable state variable, which is exactly the redirectable-vs-fixed
    distinction a scorer reads. The shape recurs on every diamond-storage getter
    and ``_calculate*`` helper.

    The callee is classified in its OWN context, with the call site's arguments
    bound exactly as ``walk`` binds them, so a helper that returns one of its
    parameters resolves to whatever the caller passed — including ``param``, when
    the caller passed a caller-chosen address. That is a finding, not a leak: the
    destination really is caller-named.

    Every ``return`` must agree on one resolved origin. Two returns naming
    different origins is a genuine disagreement the caller cannot see through
    (``if (flag) return governor; return treasury;``), and picking either member
    would assert a destination the code does not commit to.

    An ELEMENT read is refused outright, and that refusal is the whole safety
    argument. ``function beneficiaryOf(uint256 id) { return _owners[id]; }``
    resolves, by the element rule, to the mutability of the BASE variable — and
    ``_owners`` has no setter function, so the base reads ``storage_no_setter``,
    i.e. *provably fixed*. The destination is nothing of the sort: the caller
    picks the key, and a different key is a different address. Publishing it as
    fixed is the worst over-claim this module can make — it is the benign end of
    the redirectability axis, and §4.2 promotes it to ``immutable_fixed`` on the
    verdict. The base's mutability is simply not a statement about any one entry,
    which is exactly why a keyed lookup earns a named kind only where a published
    standard says what it means (``ownerOf`` -> ``token_owner``) and is otherwise
    left unresolved."""
    if depth > _RETURN_ORIGIN_DEPTH or type(ir).__name__ not in _SAME_CONTEXT_CALL_OPS:
        return None
    callee = getattr(ir, "function", None)
    if callee is None or not getattr(callee, "nodes", None):
        return None
    key = id(callee)
    if key in _RETURN_ORIGIN_ACTIVE:
        return None
    values = _return_values(callee)
    if values is None:
        return None
    bindings, index_bindings = _bindings_for_call(ir, callee, ctx)
    callee_ctx = _build_unit_ctx(
        callee,
        False,
        ctx.state_vars_by_name,
        ctx.setters,
        ctx.alias_indeterminate,
        ctx.setter_scan_complete,
        bindings,
        index_bindings,
    )
    _RETURN_ORIGIN_ACTIVE.add(key)
    try:
        if any(_element_origin(value, callee_ctx) is not None for value in values):
            return None
        origins = {_arg_origin(value, callee_ctx, depth + 1) for value in values}
    finally:
        _RETURN_ORIGIN_ACTIVE.discard(key)
    if len(origins) != 1:
        return None
    origin = next(iter(origins))
    return None if origin[0] == "indeterminate" else origin


def _call_irs(operand: Any, ctx: _UnitCtx) -> list[Any]:
    """Every call IR ``operand`` IS the return value of, walking casts/copies
    only — the def-chain edges that preserve that identity."""
    seen: set[int] = set()
    stack: list[Any] = [operand]
    irs: list[Any] = []
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
        elif tn in _CALL_IR_OPS:
            irs.append(ir)
        # An unknown def (a Phi, a binary op) ends this branch.
    return irs


def _param_derived_index(operand: Any, ctx: _UnitCtx) -> int | None:
    """The ENTRY parameter slot of the caller INPUT that fed a ``param_derived``
    amount's conversion — NOT the slot of the amount itself (the amount is a call
    return value and occupies no ABI slot).

    Emitted only when exactly ONE call produced the operand and its arguments
    identify exactly ONE unambiguous entry parameter. Two distinct entry params
    feeding the call keep the KIND (it is still param-derived) but emit no index:
    a prober plants a value in the slot, so a guessed one is worse than none."""
    irs = _call_irs(operand, ctx)
    if len(irs) != 1:
        return None
    indexes = _call_param_argument_indexes(irs[0], ctx)
    return next(iter(indexes)) if len(indexes) == 1 else None


def _one_call_origin(ir: Any, ctx: _UnitCtx, *, amount: bool, depth: int) -> tuple[str, ...]:
    """The neutral origin of ONE call's return value, best evidence first.

    1. A recognized STANDARD callee (``ownerOf``) — a published contract, so it
       beats anything read off a body.
    2. What an in-contract helper's body actually RETURNS
       (:func:`_callee_return_origin`). A traced origin outranks
       ``param_derived`` below, which only says a caller input went in somewhere.
    3. The amount-only ``param_derived`` fallback, then ``indeterminate``.

    The order matters in one direction only: step 2 can never turn an
    ``indeterminate`` into a wrong answer, because it declines unless every
    ``return`` agrees on one resolved origin."""
    standard = _call_standard_origin(ir)
    if standard[0] != "indeterminate":
        return standard
    traced = _callee_return_origin(ir, ctx, depth)
    if traced is not None:
        return traced
    return _call_amount_origin(ir, ctx) if amount else standard


def _call_origin(operand: Any, ctx: _UnitCtx, *, amount: bool = False, depth: int = 0) -> tuple[str, ...] | None:
    """The neutral origin of an operand that IS a call's return value. ``None``
    only when the operand does not resolve — through casts/copies alone — to
    exactly one call, in which case the caller falls through to the source set.

    ``amount`` opts into the amount-only vocabulary (:func:`_call_amount_origin`);
    destination resolution is unaffected, so ``param_derived`` can never reach
    :func:`_origin_to_target_kind`.

    A POSITIVE test on the def-use chain, not on the source set, for two reasons.
    A set-membership test would fire on a value merely TAINTED by the call
    (``ownerOf(id) ^ salt``) rather than one that IS its result. And going the
    other way, the source set of a DIRECTLY-READ nested parameter can carry a
    call tag as a Slither entrypoint-Phi echo from a sibling call site — blocking
    on that would degrade a perfectly resolvable forwarded parameter.

    Answering here is what keeps ``_forwarded_param_sources`` honest for call
    results. ``_handle_internal_call`` sets its lvalue to the callee's return
    sources UNIONED with the call tag, so ``ownerOf(id)`` carries
    ``{view_call, state_variable _owners, parameter id}`` — where the parameter
    is the mapping KEY, not the value. Falling through to the source set there
    lets the drop-the-rest shortcut pick ``param`` out of a real union and report
    a token-owner payout as a caller-chosen destination."""
    origins: set[tuple[str, ...] | None] = {
        _one_call_origin(ir, ctx, amount=amount, depth=depth) for ir in _call_irs(operand, ctx)
    }
    # Two calls reaching one operand require a Phi between them, so >1 origin is
    # a merge and must not resolve to either member.
    if len(origins) != 1:
        return ("indeterminate",) if origins else None
    return next(iter(origins))


def _element_kind(operand: Any, ctx: _UnitCtx, *, amount: bool) -> str | None:
    """An element read's destination/amount kind. A storage root yields the base
    var's mutability (``storage_setter`` / ``storage_no_setter`` /
    ``bounded_by_storage``) and can never become ``param``; a caller-supplied
    array/struct root yields ``param``."""
    origin = _element_origin(operand, ctx)
    if origin is None:
        return None
    return _origin_to_amount_kind(origin) if amount else _origin_to_target_kind(origin, ctx)


def _forwarded_param_sources(srcs: Any, ctx: _UnitCtx) -> list[Any] | None:
    """In a nested callee reached through a DIRECT forwarded read, the
    ``parameter`` sources whose bindings are the authoritative single-entry-path
    origin — or ``None`` when the drop-the-rest shortcut is not sound and the
    caller must use the all-sources-agree path instead.

    The other non-parameter sources present alongside a *directly-read* nested
    parameter can only be Slither entrypoint-Phi echoes (the parameter's
    interprocedural binding from OTHER call sites / entries) — a genuine in-body
    second origin needs a body Phi, already caught by ``_reaches_merged_local``.
    So for a direct read those echoes are safely dropped and the binding decides.

    But a ``computed`` operand (``Binary`` / ``Member`` / ``Unary`` / ``Length`` /
    ``SolidityCall`` attach a ``computed`` wrapper alongside ALL of their operand
    sources) can combine the forwarded parameter with a genuine co-origin and no
    Phi — ``dest = uint160(to) ^ uint160(owner)``. Dropping the co-origin there
    would guess the ``param`` member of a real union and make the nested
    classification MORE specific than the byte-identical entry-level code (which
    sees ``{parameter, state_variable}`` and yields indeterminate). So a computed
    operand returns ``None`` and falls through to the agreement path, where the
    disagreement correctly yields indeterminate while a computed-but-single-origin
    shape (a struct-member read of a forwarded param) still recovers.

    A CALL RESULT is the same trap without a ``computed`` wrapper to mark it, but
    it is intercepted upstream by ``_call_origin`` rather than here: the source
    set alone cannot tell a call the operand IS from a call tag echoed onto a
    forwarded parameter by a sibling call site."""
    if not ctx.nested:
        return None
    if any(s.kind == "computed" for s in srcs):
        return None
    params = [s for s in srcs if s.kind == "parameter"]
    return params or None


def _target_kind_from_sources(srcs: Any, ctx: _UnitCtx) -> str:
    if not srcs or is_top(srcs):
        return "indeterminate"
    # ``computed`` is a wrapper tag Binary/Member ops attach alongside the real
    # operand sources; it is never itself a destination origin. Every real source
    # resolves to a neutral origin (a nested forwarded ``parameter`` through its
    # binding); a single agreeing origin classifies, any MIX -> indeterminate.
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        kinds = {_origin_to_target_kind(_single_param_origin(s, ctx), ctx) for s in forwarded}
    else:
        kinds = {_origin_to_target_kind(_source_neutral_origin(s, ctx), ctx) for s in srcs if s.kind != "computed"}
    if len(kinds) == 1 and "indeterminate" not in kinds:
        return next(iter(kinds))
    return "indeterminate"


def _amount_kind_from_sources(srcs: Any, ctx: _UnitCtx) -> str:
    if not srcs or is_top(srcs):
        return "indeterminate"
    computed_kinds = {s.computed_kind for s in srcs if s.kind == "computed"}
    has_value = any(c == "msg.value" for c in computed_kinds)
    has_balance = any(c and "balance" in c for c in computed_kinds)
    if has_balance and not has_value and any(_is_derivation(c) for c in computed_kinds):
        # Arithmetic ON a balance read. Subtraction is a DELTA
        # (``address(this).balance - prevBalance``, ``balance - locked``) and gets
        # named; any other derivation (``balance / 2``) has no bound we can name.
        # Either way the OTHER operand must not win alone: reporting
        # ``balance - locked`` as ``bounded_by_storage``, or ``balance / 2`` as
        # ``fixed_constant``, credits that operand with bounding an amount that
        # actually tracks the balance. This runs ahead of the meaningful-source
        # split precisely because that operand is usually the only non-``computed``
        # source and would otherwise be the whole answer.
        return "balance_delta" if any(_is_subtraction(c) for c in computed_kinds) else "indeterminate"
    meaningful = {s.kind for s in srcs} - {"computed"}
    if not meaningful:
        # Pure computed: only ``msg.value`` and a bare ``address(this).balance``
        # read are unambiguous amount origins; hash/mixed tags stay indeterminate.
        if has_value and not has_balance:
            # A msg.value derivation (``msg.value - fee``) is still bounded by
            # what the caller attached to THIS call, so the label does not
            # over-claim the way a bare balance read would.
            return "msg_value"
        if has_balance and not has_value:
            # ``whole_balance`` asserts the send can drain everything the contract
            # holds — true only of a bare READ, and every derivation is gone by here.
            return "whole_balance"
        return "indeterminate"
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        kinds = {_origin_to_amount_kind(_single_param_origin(s, ctx)) for s in forwarded}
    else:
        kinds = {_origin_to_amount_kind(_source_neutral_origin(s, ctx)) for s in srcs if s.kind != "computed"}
    if len(kinds) == 1 and "indeterminate" not in kinds:
        return next(iter(kinds))
    return "indeterminate"


# Inequalities under which a ``cond ? A : B`` returns the SMALLER operand — the
# shape a hand-written or library ``min`` compiles to. ``<``/``<=`` return the
# then-value when it is the left (smaller) operand; ``>``/``>=`` return it when it
# is the right one.
_MIN_LT_OPS = ("BinaryType.LESS", "BinaryType.LESS_EQUAL")
_MIN_GT_OPS = ("BinaryType.GREATER", "BinaryType.GREATER_EQUAL")


def _resolve_copies(value: Any, def_by_id: dict[int, Any]) -> tuple[Any, Any]:
    """Follow copy edges (``TypeConversion`` cast, ``Assignment``) from ``value``
    to the value that actually defines it. Returns ``(value, defining_ir)`` where
    ``defining_ir`` is ``None`` for a leaf (param / constant / state var / call
    argument with no def in this map). A pure identity walk — it never crosses a
    Phi merge or a computation, so the returned value IS the input, just renamed."""
    seen: set[int] = set()
    v = value
    while v is not None and id(v) not in seen:
        seen.add(id(v))
        ir = def_by_id.get(id(v))
        if ir is None:
            return v, None
        tn = type(ir).__name__
        if tn == "TypeConversion":
            v = getattr(ir, "variable", None)
        elif tn == "Assignment":
            v = getattr(ir, "rvalue", None)
        else:
            return v, ir
    return v, None


def _is_self_balance_read(value: Any, ctx: _UnitCtx) -> bool:
    """``value`` (through casts/copies) IS ``address(this).balance`` — the
    ``SOLIDITY_CALL balance(address)`` built-in whose sole argument resolves to the
    ``this`` Solidity variable. An arbitrary ``other.balance`` reads a foreign
    balance and must NOT qualify, so the argument identity is checked."""
    from slither.core.declarations.solidity_variables import SolidityVariable  # type: ignore[import]

    _, ir = _resolve_copies(value, ctx.def_by_id)
    if ir is None or type(ir).__name__ != "SolidityCall":
        return False
    name = getattr(getattr(ir, "function", None), "name", "") or ""
    if "balance" not in name:
        return False
    args = getattr(ir, "arguments", None) or []
    if len(args) != 1:
        return False
    base, _ = _resolve_copies(args[0], ctx.def_by_id)
    return isinstance(base, SolidityVariable) and getattr(base, "name", None) == "this"


def _fn_def_by_id(fn: Any) -> dict[int, Any]:
    """A ``def_by_id`` map for an ARBITRARY function's SSA — needed to inspect a
    call's callee body, which lives outside the entry unit's own map."""
    out: dict[int, Any] = {}
    for node in getattr(fn, "nodes", ()) or ():
        for ir in getattr(node, "irs_ssa", ()) or ():
            lv = getattr(ir, "lvalue", None)
            if lv is not None:
                out[id(lv)] = ir
    return out


def _branch_return_value(node: Any) -> Any:
    """The single value a straight-line branch returns, or ``None`` when the arm is
    not a simple ``return <expr>`` (it splits/merges or returns a tuple)."""
    seen: set[int] = set()
    cur = node
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        for ir in getattr(cur, "irs_ssa", ()) or ():
            if type(ir).__name__ == "Return":
                vals = getattr(ir, "values", None) or []
                return vals[0] if len(vals) == 1 else None
        sons = getattr(cur, "sons", None) or []
        cur = sons[0] if len(sons) == 1 else None
    return None


def _callee_is_two_arg_min(fn: Any) -> bool:
    """PROVE ``fn`` computes the minimum of its two arguments — returns ``arg_i``
    when ``arg_i < arg_j`` else ``arg_j`` (the smaller). Keyed on the body's SHAPE,
    never its name: exactly one comparison IF over the two parameters, each arm
    returning one parameter, the smaller taken on the corresponding branch. Any
    other shape (a max, three args, a computed result) fails to ``False``."""
    from slither.core.cfg.node import NodeType  # type: ignore[import]

    params = getattr(fn, "parameters", None) or []
    if len(params) != 2:
        return False
    d = _fn_def_by_id(fn)
    candidates: list[tuple[Any, Any]] = []
    for node in getattr(fn, "nodes", ()) or ():
        if getattr(node, "type", None) != NodeType.IF:
            continue
        for ir in getattr(node, "irs_ssa", ()) or ():
            if type(ir).__name__ == "Binary" and str(getattr(ir, "type", "")) in (_MIN_LT_OPS + _MIN_GT_OPS):
                candidates.append((node, ir))
    if len(candidates) != 1:
        return False
    cif, cmp = candidates[0]
    tv = _branch_return_value(getattr(cif, "son_true", None))
    fv = _branch_return_value(getattr(cif, "son_false", None))
    if tv is None or fv is None:
        return False

    def pidx(v: Any) -> int | None:
        rv, _ = _resolve_copies(v, d)
        nsv = getattr(rv, "non_ssa_version", None) or rv
        for i, p in enumerate(params):
            if p is nsv:
                return i
        return None

    li, ri = pidx(cmp.variable_left), pidx(cmp.variable_right)
    ti, fi = pidx(tv), pidx(fv)
    if None in (li, ri, ti, fi) or {li, ri} != {0, 1}:
        return False
    op = str(getattr(cmp, "type", ""))
    if op in _MIN_LT_OPS:  # A < B -> take A (left) when smaller
        return ti == li and fi == ri
    return ti == ri and fi == li  # A > B -> take B (right) when smaller


def _capped_ternary(operand: Any, ctx: _UnitCtx) -> bool:
    """Form 1: a hand-written ``contractBalance < X ? contractBalance : X`` lowered
    to a 2-input Phi over branch assignments, controlled by an inequality IF, where
    the construct returns the SMALLER value and one compared operand is the
    self-balance read. ``min(self_balance, X) <= self_balance``."""
    from slither.core.cfg.node import NodeType  # type: ignore[import]

    phi = ctx.def_by_id.get(id(operand))
    if phi is None or type(phi).__name__ != "Phi":
        return False
    inputs = list({id(rv): rv for rv in (getattr(phi, "rvalues", None) or []) if rv is not None}.values())
    if len(inputs) != 2:
        return False
    branch: dict[int, tuple[Any, Any]] = {}
    for p in inputs:
        d = ctx.def_by_id.get(id(p))
        if d is None or type(d).__name__ != "Assignment":
            return False
        branch[id(p)] = (getattr(d, "node", None), getattr(d, "rvalue", None))
    branch_nodes = {id(n) for n, _ in branch.values() if n is not None}
    if len(branch_nodes) != 2:
        return False
    endif = getattr(phi, "node", None)
    fn = getattr(endif, "node_function", None) or getattr(endif, "function", None)
    if fn is None:
        return False
    cif = None
    for node in getattr(fn, "nodes", ()) or ():
        if getattr(node, "type", None) != NodeType.IF:
            continue
        st, sf = getattr(node, "son_true", None), getattr(node, "son_false", None)
        if st is not None and sf is not None and {id(st), id(sf)} == branch_nodes:
            cif = node
            break
    if cif is None:
        return False
    cmp = next(
        (
            ir
            for ir in getattr(cif, "irs_ssa", ()) or ()
            if type(ir).__name__ == "Binary" and str(getattr(ir, "type", "")) in (_MIN_LT_OPS + _MIN_GT_OPS)
        ),
        None,
    )
    if cmp is None:
        return False
    st = getattr(cif, "son_true", None)
    # Map each branch's assigned value to the true/false side of the condition.
    tv = fv = None
    for _, (node, val) in branch.items():
        if st is not None and id(node) == id(st):
            tv = val
        else:
            fv = val
    if tv is None or fv is None:
        return False

    def canon(v: Any) -> int:
        rv, _ = _resolve_copies(v, ctx.def_by_id)
        return id(rv)

    lc, rc, tc, fc = canon(cmp.variable_left), canon(cmp.variable_right), canon(tv), canon(fv)
    op = str(getattr(cmp, "type", ""))
    is_min = (op in _MIN_LT_OPS and tc == lc and fc == rc) or (op in _MIN_GT_OPS and tc == rc and fc == lc)
    if not is_min:
        return False
    return _is_self_balance_read(cmp.variable_left, ctx) or _is_self_balance_read(cmp.variable_right, ctx)


def _capped_min_call(operand: Any, ctx: _UnitCtx) -> bool:
    """Form 2: ``operand`` is the result of a 2-argument ``min`` call (a library or
    internal function PROVEN to return the smaller argument) one of whose arguments
    is the self-balance read. ``min(self_balance, X) <= self_balance``."""
    _, ir = _resolve_copies(operand, ctx.def_by_id)
    if ir is None or type(ir).__name__ not in ("LibraryCall", "InternalCall"):
        return False
    fn = getattr(ir, "function", None)
    if fn is None or not _callee_is_two_arg_min(fn):
        return False
    args = getattr(ir, "arguments", None) or []
    if len(args) != 2:
        return False
    return any(_is_self_balance_read(a, ctx) for a in args)


def _is_capped_by_balance(operand: Any, ctx: _UnitCtx) -> bool:
    """An amount provably ``<= address(this).balance``: the minimum of the
    contract's own balance and some other value. Recognized in the two forms a min
    compiles to (a hand-written ternary, a min-call). Fails to ``False`` on any
    doubt — a MAX, a foreign balance, more than two inputs — so the caller stays
    ``indeterminate`` rather than over-claiming a bound."""
    return _capped_ternary(operand, ctx) or _capped_min_call(operand, ctx)


def _classify_site(operand: Any, ctx: _UnitCtx, *, amount: bool) -> tuple[str, str]:
    """Classify one destination/amount operand at one IR site -> (kind, tier).

    The load-bearing fallback: any operand that could be a collapsed
    cross-branch merge (``_reaches_merged_local``) is ``indeterminate`` — we
    never project a concrete kind the engine's base-name keying might have
    silently picked from an ambiguous set."""
    if operand is None:
        return ("indeterminate", "static_trace")
    # An array/mapping/struct element is classified by its ROOT base, detected
    # positively from the operand IR so it is not confused with a forwarded
    # parameter (source-set-identical via the entrypoint Phi). This runs BEFORE
    # the merged-local guard because the guard also walks the element KEY, and a
    # loop-merged index (``targets[i]``) says nothing about the destination's
    # kind — every element of the base shares its origin. A merged BASE is still
    # caught: the root resolves through ``_arg_origin``, which applies the guard.
    elem = _element_kind(operand, ctx, amount=amount)
    if elem is not None:
        return (elem, "static_trace")
    # An amount that is provably ``min(address(this).balance, X)`` is bounded by
    # the contract's own balance. This runs BEFORE the merged-local guard because
    # the ternary form (Form 1) IS a cross-branch Phi merge the guard would fold to
    # indeterminate, and before the source path because the min-call form (Form 2)
    # otherwise declines there. Amount-only: a destination has no such bound.
    if amount and _is_capped_by_balance(operand, ctx):
        return ("capped_by_balance", "static_trace")
    if _reaches_merged_local(operand, ctx):
        return ("indeterminate", "static_trace")
    # A call's return value classifies from the callee's standard identity, or
    # from what an in-contract helper's body provably returns — a trace through
    # the call either way, never a dispositive AST read.
    call = _call_origin(operand, ctx, amount=amount)
    if call is not None:
        kind = _origin_to_amount_kind(call) if amount else _origin_to_target_kind(call, ctx)
        return (kind, "static_trace")
    srcs = ctx.engine._sources_for_value(operand)
    kind = _amount_kind_from_sources(srcs, ctx) if amount else _target_kind_from_sources(srcs, ctx)
    if kind == "indeterminate":
        return ("indeterminate", "static_trace")
    # A ``parameter`` operand resolved inside a nested callee was recovered by
    # threading the caller's binding across the internal-call boundary — a trace,
    # not a dispositive AST fact at the entry. State-var / msg.sender reads are
    # contract-global and stay dispositive regardless of nesting.
    forwarded_param = ctx.nested and any(s.kind == "parameter" for s in srcs)
    direct = _operand_is_direct(operand, ctx.param_names) and not forwarded_param
    tier = "dispositive_ast" if direct else "static_trace"
    return (kind, tier)


def _fold_sites(sites: list[tuple[str, str]]) -> KindTier | None:
    """Collapse every contributing IR site's (kind, tier) to one classification.
    Tier is the weaker of the contributing sites — one traced site makes the
    whole a ``static_trace``.

    Three outcomes, and the middle one is the point:

    * sites AGREE on one resolved kind — that kind.
    * sites DISAGREE but every member is itself resolved — ``several``. The
      function has several destinations (or several amounts) and we know what
      each of them is; saying ``indeterminate`` there claimed we had traced
      nothing, on flows where we had traced everything. A scorer reading the
      scalar alone would score a function that pays a caller-named address and a
      fixed one identically to a function nothing is known about.
    * any member is itself ``indeterminate`` — ``indeterminate``. One unresolved
      site means the set of destinations is not closed, so the members cannot be
      published as the whole of it.

    The name is deliberately quantitative and says nothing about control flow:
    ``several`` is a set, not a sequence and not a disjunction. The sites may be
    mutually exclusive branches or may all execute in one call, and nothing here
    distinguishes those — a withdrawal that pays the user and then sweeps the
    remainder to a pool makes BOTH moves in the same invocation. A consumer must
    read ``target_kinds``/``amount_kinds`` and take the WORST member — one
    caller-chosen site in the set means the caller can name a destination on some
    path, which is the whole question."""
    if not sites:
        return None
    kinds = {kind for kind, _ in sites}
    tier = "static_trace" if any(t == "static_trace" for _, t in sites) else "dispositive_ast"
    if len(kinds) == 1:
        kind = next(iter(kinds))
        return {"kind": kind, "tier": "static_trace" if kind == "indeterminate" else tier}
    if "indeterminate" in kinds:
        return {"kind": "indeterminate", "tier": "static_trace"}
    return {"kind": "several", "tier": tier}


def _site_breakdown(sites: list[tuple[str, str]]) -> list[KindTier] | None:
    """The distinct site classifications behind a fold, or ``None`` when the
    fold is already the whole answer.

    ``_fold_sites`` must keep returning one scalar (a scorer reads it), but a
    function with two separately-resolved destinations then publishes only
    ``indeterminate`` — we would be hiding an answer we hold. This publishes the
    contributing sites alongside it, deduplicated by MEANING (the ``(kind,
    tier)`` pair, so provenance is not flattened either) in first-seen order.

    Emitted only when the sites disagree on the KIND, which is exactly when
    ``_fold_sites`` gives up its answer; sites agreeing on a kind are already
    fully described by the fold (which carries their weaker tier), so publishing
    "msg_sender, msg_sender" there would be noise on a flow nothing was hidden
    from. An ``indeterminate`` site stays in the list — the breakdown says why
    the fold is what it is, it never makes it look more resolved.

    Size needs no cap: both lattices are finite closed vocabularies and dedup is
    by lattice member × tier, so the list is bounded by that product (≤20 target,
    ≤14 amount entries) no matter how many IR sites a function has."""
    if len({kind for kind, _ in sites}) < 2:
        return None
    ordered: list[KindTier] = []
    seen: set[tuple[str, str]] = set()
    for kind, tier in sites:
        if (kind, tier) in seen:
            continue
        seen.add((kind, tier))
        ordered.append({"kind": kind, "tier": tier})
    return ordered


# Re-walk insurance: bounds interprocedural recursion when a helper is reached
# with many distinct forwarded-binding signatures (a wide call DAG). Real helper
# chains are a handful of hops deep; a cutoff only drops sends past a depth no
# real destination reaches, in the safe direction (a missing flow, never a
# guessed one). The per-(unit, bindings) ``visited`` set already guarantees
# termination — this is belt-and-suspenders against pathological blow-up.
_VALUE_WALK_DEPTH_CAP = 128


# The token-first safe-transfer library idiom (Solmate / Solady ``SafeTransferLib``,
# OZ ``SafeERC20``): the token is the FIRST argument, so the ``(to, amount)`` /
# ``(from, to, amount)`` slots are shifted one right of the bare ERC-20 selectors.
# Their own canonical signatures — ``safeTransfer(ERC20,address,uint256)`` /
# ``safeTransferFrom(ERC20,address,address,uint256)`` — hash to selectors NOT in
# the bare ERC-20 sets, and Slither lowers them to ``LibraryCall`` (or, when the
# helper is a plain internal, ``InternalCall``), so the value move is invisible to
# the selector scan. What identifies the shape is the ERC-20 selector the callee
# BODY provably issues (below), never the callee's identifier — and only where
# that body issues it in a form the value-flow walk cannot resolve for itself, so
# the recognizer covers the walk's blind spot instead of competing with it.
_ERC20_TRANSFER_SELECTOR = _selector_for("transfer(address,uint256)")
_ERC20_TRANSFER_FROM_SELECTOR = _selector_for("transferFrom(address,address,uint256)")

# How far into the callee to look for the issued selector. Solmate/Solady build
# it in the helper's own assembly and OZ SafeERC20 builds it in the helper's own
# ``abi.encodeCall``, so one extra hop only covers a thin wrapper; going deeper
# would start attributing a nested helper's transfer to an unrelated caller.
_TOKEN_FIRST_BODY_DEPTH = 1


# Fixed-size byte types (``bytes1`` … ``bytes32``). A constant of one of these is
# a numeric word: the compiler folded a ``.selector`` member or an assembly
# literal into it. ``string`` and ``bytes`` (dynamic) are excluded — a revert
# message is also handed back as a Python ``str``, and only the DECLARED type
# separates the two.
_FIXED_BYTES_TYPE = re.compile(r"bytes([1-9]|[12][0-9]|3[0-2])$")


def _selector_of_constant(operand: Any) -> str | None:
    """The 4-byte selector a constant operand denotes, or ``None``.

    Two encodings, both pure value facts:
    ``abi.encodeWithSelector(token.transfer.selector, …)`` folds to a ``bytes4``
    constant equal to the selector; the assembly form
    ``mstore(ptr, 0xa9059cbb00…00)`` folds to a 32-byte word carrying the
    selector left-aligned in its top four bytes and zeros below.

    A ``bytesN`` constant's value arrives as a DECIMAL STRING rather than an
    ``int``, so the numeric word has to be read back through the declared type —
    which is also what keeps a revert-message ``string`` (identically a Python
    ``str``) from being read as a selector. Rejecting the string form outright is
    what made the OZ ``SafeERC20`` idiom, whose selector comes from exactly this
    fold, invisible to the recognizer."""
    value = getattr(operand, "value", None)
    if isinstance(value, str) and _FIXED_BYTES_TYPE.fullmatch(str(getattr(operand, "type", "") or "")):
        try:
            value = int(value)
        except ValueError:
            return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    if value < 1 << 32:
        return f"0x{value:08x}"
    if value >> 224 and not value & ((1 << 224) - 1):
        return f"0x{value >> 224:08x}"
    return None


def _selector_of_member_access(ir: Any) -> str | None:
    """The selector behind ``<var>.<fn>`` on a contract/interface-typed variable
    (``abi.encodeCall(token.transfer, …)``), or ``None``.

    The member name is resolved against the DECLARED type's own function list —
    the compiler's binding — and the selector comes from that declaration's
    canonical signature. An overloaded or unresolvable member yields ``None``."""
    if type(ir).__name__ != "Member":
        return None
    member = getattr(getattr(ir, "variable_right", None), "value", None)
    if not isinstance(member, str) or not member:
        return None
    declared = getattr(getattr(ir, "variable_left", None), "type", None)
    target = getattr(declared, "type", None)
    candidates = [fn for fn in (getattr(target, "functions", None) or []) if (getattr(fn, "name", "") or "") == member]
    if len(candidates) != 1:
        return None
    return _selector_for(_function_full_name(candidates[0]))


def _ir_operands(ir: Any) -> list[Any]:
    """Every value operand of one IR, flattening the argument tuples
    ``abi.encodeCall`` nests."""
    operands: list[Any] = []
    for attr in ("rvalue", "variable", "variable_left", "variable_right"):
        value = getattr(ir, attr, None)
        if value is not None:
            operands.append(value)
    for argument in getattr(ir, "arguments", None) or []:
        operands.extend(argument if isinstance(argument, (list, tuple)) else [argument])
    return operands


# The EVM call opcodes, as Slither names them on a ``SolidityCall``. These are
# language builtins, not user identifiers, so keying on them is a published-spec
# fact of the same kind as a selector. Solmate/Solady build their calldata in
# assembly and dispatch it with a raw ``call``, which reaches the IR as one of
# these rather than as a Low/HighLevelCall.
_EVM_CALL_OPCODES = ("call", "staticcall", "delegatecall", "callcode")


# How deep to look for the DISPATCH, as opposed to the selector. Deliberately
# deeper than ``_TOKEN_FIRST_BODY_DEPTH``: that cap bounds selector ATTRIBUTION,
# where reaching further would start crediting a nested helper's transfer to an
# unrelated caller. "Does this call tree ever dispatch a call at all" carries no
# such risk — it only ever REFUSES evidence — and OZ's SafeERC20 puts three hops
# between the two (``safeTransfer`` builds the calldata, ``_callOptionalReturn``
# forwards it, ``Address.functionCall`` makes the call).
_DISPATCH_SEARCH_DEPTH = 5


def _dispatches_a_call(unit: Any, seen: frozenset[int], depth: int) -> bool:
    """Whether ``unit`` or a helper it calls ever dispatches an actual call."""
    if unit is None or depth > _DISPATCH_SEARCH_DEPTH:
        return False
    for node in getattr(unit, "nodes", []) or []:
        for ir in _node_irs(node):
            op = type(ir).__name__
            if op in ("HighLevelCall", "LowLevelCall") or _is_evm_call_opcode(ir):
                return True
            if op in ("InternalCall", "LibraryCall"):
                callee = getattr(ir, "function", None)
                key = id(callee)
                if callee is not None and key not in seen and getattr(callee, "nodes", None):
                    if _dispatches_a_call(callee, seen | {key}, depth + 1):
                        return True
    return False


def _is_evm_call_opcode(ir: Any) -> bool:
    if type(ir).__name__ != "SolidityCall":
        return False
    name = str(getattr(getattr(ir, "function", None), "name", "") or "")
    return name.split("(", 1)[0] in _EVM_CALL_OPCODES


def _erc20_selectors_issued(unit: Any, seen: frozenset[int], depth: int) -> tuple[set[str], set[str]]:
    """``(issued, walk_visible)`` — the bare ERC-20 move selectors ``unit``'s body
    provably issues, and the subset it issues in a form the value-flow walk can
    resolve on its own."""
    found, visible, _ = _erc20_selector_evidence(unit, seen, depth)
    return found, visible


def _erc20_selector_evidence(unit: Any, seen: frozenset[int], depth: int) -> tuple[set[str], set[str], bool]:
    """``(issued, walk_visible, dispatches)`` for one unit and the helpers it calls.

    Evidence is a resolved external call whose canonical signature IS an ERC-20
    move, a selector VALUE the body materializes (assembly literal or
    ``abi.encodeWithSelector`` constant), or a member access the compiler bound
    to an ERC-20 declaration (``abi.encodeCall``). None of it reads an identifier
    of the unit itself.

    Only the FIRST form is walk-visible: a resolved ``HighLevelCall`` to
    ``transfer``/``transferFrom`` is a site the ordinary recursion already
    classifies when it descends into this unit. The other two are the whole
    reason the recognizer exists — a selector built in assembly or handed to a
    low-level ``.call`` moves tokens with no IR the walk can see. Keeping them
    apart is what lets the recognizer fire on a same-contract helper without ever
    displacing, or double-counting, a move the walk already resolves.

    A MATERIALIZED selector counts only if the body actually DISPATCHES a call —
    mentioning a selector is not issuing one. A deny-list
    (``require(sel != IERC20.transfer.selector)``) and a timelock that builds
    calldata to store for later both materialize the constant while moving
    nothing, and both would otherwise publish a fabricated ``flow.out``.

    ``dispatches`` is TRANSITIVE, and it has to be: OZ's ``SafeERC20.safeTransfer``
    materializes the selector in its own frame (``abi.encodeCall``) and hands it
    to ``_callOptionalReturn``, which is where the ``.call`` actually happens.
    Judging each frame alone therefore threw the evidence away exactly on the
    most common safe-transfer library in existence."""
    found: set[str] = set()
    visible: set[str] = set()
    if unit is None or depth > _TOKEN_FIRST_BODY_DEPTH:
        return found, visible, False
    wanted = {_ERC20_TRANSFER_SELECTOR, _ERC20_TRANSFER_FROM_SELECTOR}
    materialized: set[str] = set()
    dispatches = False
    for node in getattr(unit, "nodes", []) or []:
        for ir in _node_irs(node):
            op = type(ir).__name__
            if op == "HighLevelCall":
                called = _selector_for(_callee_signature(ir))
                if called in wanted:
                    found.add(str(called))
                    visible.add(str(called))
            for operand in _ir_operands(ir):
                selector = _selector_of_constant(operand)
                if selector in wanted:
                    materialized.add(str(selector))
            member = _selector_of_member_access(ir)
            if member in wanted:
                materialized.add(str(member))
            if op in ("InternalCall", "LibraryCall"):
                callee = getattr(ir, "function", None)
                key = id(callee)
                if callee is not None and key not in seen and getattr(callee, "nodes", None):
                    child_found, child_visible, child_dispatches = _erc20_selector_evidence(
                        callee, seen | {key}, depth + 1
                    )
                    found |= child_found
                    visible |= child_visible
                    dispatches = dispatches or child_dispatches
    if materialized and (dispatches or _dispatches_a_call(unit, frozenset({id(unit)}), 0)):
        found |= materialized
        dispatches = True
    return found, visible, dispatches


def _token_first_transfer(ir: Any) -> tuple[str, ...] | None:
    """Classify a token-first library/internal transfer call, or ``None``.

    Returns ``("send", to, amount)`` for ``<helper>(<Token>, to, amount)`` and
    ``("pull", from, to, amount)`` for ``<helper>(<Token>, from, to, amount)`` —
    the operands being the call-site arguments in the SHIFTED positions.

    Two independent facts must agree, and neither is the helper's name. The
    callee's body must provably issue exactly ONE bare ERC-20 move selector,
    which is what picks send vs pull; a body issuing both (or neither) is
    ``None``. The trailing argument types must then match that selector's ABI
    tail, which discriminates the token-first form from the bare
    ``transfer(address,uint256)`` / ``transferFrom(address,address,uint256)``
    (2 / 3 args) the selector scan already handles, and from ERC-721
    ``safeTransferFrom(...,bytes)`` (a ``bytes`` tail). With the token occupying
    the leading slot, the remaining formals are the only type-consistent
    carriers of the ABI tail the callee forwards.

    A callee that issues the selector through a RESOLVED call is not recognized
    here at all: the ordinary recursion descends into it and classifies that site
    itself, so firing would double-count the move — two sites on one flow key,
    folding a resolvable destination to ``indeterminate``. The recognizer is for
    the moves the walk is BLIND to, and nothing else.

    NOT applied to an ``InternalCall``, and the reason is the argument this whole
    function does NOT make: it reads ``to``/``amount`` off the CALL SITE without
    proving the callee forwards them into the selector's slots. For a library
    that assumption is close to definitional — a library holds no mutable storage
    to redirect through, and the token-first wrappers exist precisely to forward.
    An arbitrary same-contract helper matching ``f(T, address, uint256)`` is a
    different animal:

        function _settle(IERC20 token, address to, uint256 amount) internal {
            address dest = payoutOverride[to];      // anyone may set this
            if (dest == address(0)) dest = to;
            SafeTransferLib.safeTransfer(token, dest, amount);
        }

    Reading ``_settle(token, treasury, amount)`` at the call site published
    ``target_kind: immutable`` at ``dispositive_ast`` — and §4.2 promoted it to
    ``immutable_fixed``, a PROVABLY-UNREDIRECTABLE destination — for a payout any
    caller can repoint. The walk reaches the library call inside ``_settle``
    anyway and classifies ``dest`` honestly, so nothing is lost by declining
    here."""
    callee = getattr(ir, "function", None)
    if callee is None or not getattr(callee, "nodes", None):
        return None
    signature = _callee_signature(ir)
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    inner = signature[signature.index("(") + 1 : -1]
    types = [t.strip() for t in inner.split(",")] if inner else []
    args = list(getattr(ir, "arguments", []) or [])
    issued, walk_visible = _erc20_selectors_issued(callee, frozenset({id(callee)}), 0)
    if len(issued) != 1 or walk_visible:
        return None
    selector = next(iter(issued))
    if selector == _ERC20_TRANSFER_SELECTOR and types[1:] == ["address", "uint256"] and len(args) >= 3:
        return ("send", args[1], args[2])
    if selector == _ERC20_TRANSFER_FROM_SELECTOR and types[1:] == ["address", "address", "uint256"] and len(args) >= 4:
        return ("pull", args[1], args[2], args[3])
    return None


def _bindings_for_call(ir: Any, callee: Any, ctx: _UnitCtx) -> tuple[dict[str, tuple[str, ...]], dict[str, int]]:
    """The param→neutral-origin map forwarded at one internal/library call site,
    resolved in the caller's ``ctx``, plus its param→entry-parameter-INDEX half.
    Each callee formal parameter binds to the entry-rooted origin of its
    positional argument (``_arg_origin``), chaining through the caller's own
    bindings so a multi-hop forward stays exact. The index map carries only the
    formals whose argument is one whole entry parameter."""
    bindings: dict[str, tuple[str, ...]] = {}
    index_bindings: dict[str, int] = {}
    args = list(getattr(ir, "arguments", []) or [])
    for param, arg in zip(getattr(callee, "parameters", []) or [], args):
        base = _base_name(getattr(param, "name", None))
        if not base:
            continue
        bindings[base] = _arg_origin(arg, ctx)
        index = _operand_param_index(arg, ctx)
        if index is not None:
            index_bindings[base] = index
    return bindings, index_bindings


def _value_flow_facts(function: Any, *, zero_value_sinks: set[str] | None = None) -> list[ValueFlow]:
    """Value movement facts, transitively. ``transferFrom`` whose ``from``
    is ``address(this)`` flows *out*; native ``transfer``/``send`` are value
    sinks Slither lowers to their own IR op (not a low-level call).

    ``zero_value_sinks`` collects the flow KINDS this walk reached and dropped
    because their amount is provably zero. Absence of a flow is otherwise
    indistinguishable from never having looked, and the label plane needs the
    difference: only a site the walk saw, resolved through its caller's
    bindings, and proved moves nothing can retract a claim.

    Each flow additionally carries ``target_kind`` (where the funds go) and
    ``amount_kind`` (how much can leave), classified by reusing the SSA
    ``ProvenanceEngine`` per unit. Every IR site contributing to a flow is
    classified and the results are folded per flow key, so distinct
    destinations across branches/sites collapse to ``indeterminate`` instead of
    the first-seen winner — with the contributing sites published alongside as
    ``target_kinds``/``amount_kinds`` when they disagreed."""
    flows: list[ValueFlow] = []
    # Value moves found while CROSSED into a callee contract (``value_router``
    # direction). Collected apart and appended after the primary walk so the
    # same-contract flow list stays in its exact prior order — the parity
    # guarantee — with routed flows strictly after it.
    router_flows: list[ValueFlow] = []
    seen: set[tuple[str, str | None, str, bool, str]] = set()
    # Keyed by (unit id, forwarded-binding signature, crossed): a helper reached
    # with the SAME bindings is deduped, but one reached with DIVERGENT bindings
    # across call sites is re-walked so the cross-site fold collapses to
    # indeterminate. ``crossed`` is part of the identity so a routed walk of a
    # unit can never suppress (or be suppressed by) a same-contract walk of it —
    # the two classify against different contract contexts.
    visited: set[tuple[int, Any, Any, bool]] = set()
    target_sites: dict[tuple[str, str | None, str, bool, str], list[tuple[str, str]]] = {}
    amount_sites: dict[tuple[str, str | None, str, bool, str], list[tuple[str, str]]] = {}
    target_indexes: dict[tuple[str, str | None, str, bool, str], list[int | None]] = {}
    amount_indexes: dict[tuple[str, str | None, str, bool, str], list[int | None]] = {}

    entry_contract = getattr(function, "contract", None)
    # Per-contract classification context (state vars + the setter/alias/scan
    # soundness guards), memoized by contract identity for this build pass. The
    # ENTRY's contract classifies every same-contract unit exactly as before;
    # crossing a HighLevelCall rebuilds it for the CALLEE's contract so
    # ``address(this)``, state-var mutability, and self-detection are read against
    # the contract whose body is actually running, not the router's.
    ctx_tuple_cache: dict[int, tuple[dict[str, Any], set[str], set[str], bool]] = {}

    def contract_ctx_tuple(contract: Any) -> tuple[dict[str, Any], set[str], set[str], bool]:
        cache_key = id(contract)
        cached = ctx_tuple_cache.get(cache_key)
        if cached is not None:
            return cached
        state_vars_by_name: dict[str, Any] = {
            getattr(v, "name", "") or "": v for v in (_all_state_variables(contract) if contract is not None else [])
        }
        setters = _setter_state_vars(contract) if contract is not None else set()
        alias_indeterminate = _aliased_storage_writes(contract)[1] if contract is not None else set()
        scan_complete = _setter_scan_complete(contract) if contract is not None else False
        result = (state_vars_by_name, setters, alias_indeterminate, scan_complete)
        ctx_tuple_cache[cache_key] = result
        return result

    def unit_ctx(
        unit: Any,
        is_entry: bool,
        param_bindings: dict[str, tuple[str, ...]] | None,
        param_index_bindings: dict[str, int] | None,
        class_contract: Any,
    ) -> _UnitCtx:
        # Fresh per (unit, bindings); the expensive per-unit ProvenanceEngine is
        # memoized inside ``_engine_bundle_for``, so this wrapper is cheap.
        state_vars_by_name, setters, alias_indeterminate, scan_complete = contract_ctx_tuple(class_contract)
        return _build_unit_ctx(
            unit,
            is_entry,
            state_vars_by_name,
            setters,
            alias_indeterminate,
            scan_complete,
            param_bindings,
            param_index_bindings,
        )

    def add(
        flow: ValueFlow,
        target: Any,
        amount: Any,
        ctx: _UnitCtx,
        crossed: bool,
        amount_override: tuple[str, str] | None = None,
        identity_possible: bool = False,
        routed_unless_sink_is_self: bool = False,
    ) -> None:
        # A move of a provably-zero amount moves nothing — ``transfer(to, 0)``
        # transfers no tokens, and a router handing a callee a literal ``0`` (which
        # the callee then guards with ``if (amount > 0)``) causes no transfer at
        # all. Publishing one names an outflow that CANNOT execute, and the site
        # would additionally fold with any real send on the same key and collapse a
        # resolved destination to ``indeterminate``. Suppressed for every sink kind,
        # because the fact is about the value and not about the call shape.
        #
        # Never applied under ``amount_override``: that slot is a token IDENTITY,
        # and token id 0 is an ordinary NFT. The same reasoning has to reach the
        # AMBIGUOUS selector, which is where the ambiguity actually lives — both
        # ERC-20 and ERC-721 define ``transferFrom(address,address,uint256)``, so
        # a literal ``0`` there is either a zero quantity (moves nothing) or token
        # id 0 (moves an NFT) and nothing in the selector says which. Dropping the
        # site deleted a real transfer, and worse, silently shrank the member set
        # a ``several`` fold then asserts is COMPLETE.
        if _amount_is_provably_zero(amount, ctx):
            if amount_override is not None:
                pass
            elif identity_possible:
                # The move stands, but the amount does NOT: calling a literal
                # zero here ``fixed_constant`` asserts the ERC-20 reading of a
                # slot we just said the selector cannot disambiguate.
                amount_override = ("indeterminate", "static_trace")
            else:
                if zero_value_sinks is not None:
                    zero_value_sinks.add(str(flow["kind"]))
                return
        target_site = _classify_site(target, ctx, amount=False)
        # ``in`` says the funds landed HERE, and only a destination resolved to
        # this contract proves that. A pull whose ``from`` is someone else and
        # whose ``to`` is someone else is a move between two third parties that
        # this function merely caused — the entry is neither source nor sink,
        # which is what ``value_router`` already means. Publishing ``in`` there
        # claimed value entered a contract it never touched (a fee paid by the
        # caller straight to a bridge endpoint reads as a deposit into the
        # bridger). An unresolved destination lands here too: it is not proof the
        # funds arrive, and the weaker routed fact does not assert that they do.
        if routed_unless_sink_is_self and target_site[0] != "self":
            flow = {**flow, "direction": "value_router"}
        key = (flow["kind"], flow["selector"], flow["direction"], flow["from_is_self"], flow["origin"])
        target_sites.setdefault(key, []).append(target_site)
        # ``amount_override`` is for a sink whose trailing slot the ABI proves is
        # not a quantity at all: tracing its provenance would answer a question
        # nobody asked and publish the answer under the name "amount".
        amount_site = amount_override or _classify_site(amount, ctx, amount=True)
        amount_sites.setdefault(key, []).append(amount_site)
        target_indexes.setdefault(key, []).append(_operand_param_index(target, ctx))
        # A ``param_derived`` amount is a call RESULT, so the slot to publish is
        # the one feeding the call, resolved from its arguments instead.
        amount_indexes.setdefault(key, []).append(
            _param_derived_index(amount, ctx)
            if amount_site[0] == "param_derived"
            else _operand_param_index(amount, ctx)
        )
        if key in seen:
            return
        seen.add(key)
        (router_flows if crossed else flows).append(flow)

    def walk(
        unit: Any,
        origin: str,
        is_entry: bool,
        param_bindings: dict[str, tuple[str, ...]] | None,
        param_index_bindings: dict[str, int] | None,
        depth: int,
        crossed: bool,
        class_contract: Any,
    ) -> None:
        sig = None if param_bindings is None else frozenset(param_bindings.items())
        # The index half is part of the identity: two sites can forward the same
        # origins from DIFFERENT parameter positions, and deduping those would
        # let the first-walked site's index stand for both.
        index_sig = None if param_index_bindings is None else frozenset(param_index_bindings.items())
        key = (id(unit), sig, index_sig, crossed)
        if key in visited or depth > _VALUE_WALK_DEPTH_CAP:
            return
        visited.add(key)
        ctx: _UnitCtx | None = None  # built lazily only if the unit moves value or forwards args

        def context() -> _UnitCtx:
            nonlocal ctx
            if ctx is None:
                ctx = unit_ctx(unit, is_entry, param_bindings, param_index_bindings, class_contract)
            return ctx

        # A move found across a contract boundary is the ROUTER's effect on a
        # DIFFERENT contract, not the entry's own in/out — it is tagged
        # ``value_router`` regardless of the site's native direction.
        def direction_of(native: str) -> str:
            return "value_router" if crossed else native

        this_ids: set[int] = set()
        this_names: set[str] = set()
        for node in getattr(unit, "nodes", []) or []:
            for ir in getattr(node, "irs_ssa", ()) or ():
                if type(ir).__name__ != "TypeConversion":
                    continue
                source = getattr(ir, "variable", None)
                if getattr(source, "name", None) == "this":
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is not None:
                        this_ids.add(id(lvalue))
                        name = getattr(lvalue, "name", None)
                        if isinstance(name, str):
                            this_names.add(name)

        for node in getattr(unit, "nodes", []) or []:
            for ir in getattr(node, "irs_ssa", ()) or ():
                op = type(ir).__name__
                if op in ("Transfer", "Send"):
                    add(
                        {
                            "kind": "native_transfer_send",
                            "selector": None,
                            "direction": direction_of("out"),
                            "from_is_self": True,
                            "origin": origin,
                        },
                        getattr(ir, "destination", None),
                        getattr(ir, "call_value", None),
                        context(),
                        crossed,
                    )
                elif op == "HighLevelCall":
                    selector = _selector_for(_callee_signature(ir))
                    arguments = list(getattr(ir, "arguments", []) or [])
                    if selector in _ERC20_PULL_SELECTORS:
                        from_arg = arguments[0] if arguments else None
                        from_self = _arg_is_address_this(from_arg, this_ids, this_names)
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": direction_of("out" if from_self else "in"),
                                "from_is_self": from_self,
                                "origin": origin,
                            },
                            arguments[1] if len(arguments) > 1 else None,  # to
                            arguments[2] if len(arguments) > 2 else None,  # amount
                            context(),
                            crossed,
                            _TOKEN_IDENTITY_AMOUNT if selector in _ERC721_IDENTITY_SELECTORS else None,
                            identity_possible=selector == _AMBIGUOUS_PULL_SELECTOR,
                            routed_unless_sink_is_self=not from_self,
                        )
                    elif selector in _ERC20_SEND_SELECTORS:
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": direction_of("out"),
                                "from_is_self": True,
                                "origin": origin,
                            },
                            arguments[0] if arguments else None,  # to
                            arguments[1] if len(arguments) > 1 else None,  # amount
                            context(),
                            crossed,
                        )
                elif op == "LowLevelCall" and "value:" in str(ir):
                    # A provably-zero value call (OZ SafeERC20's
                    # ``functionCallWithValue(token, data, 0)``) moves no ETH; it is
                    # dropped by ``add``'s zero-amount guard along with every other
                    # sink kind.
                    add(
                        {
                            "kind": "low_level_value_call",
                            "selector": None,
                            "direction": direction_of("out"),
                            "from_is_self": True,
                            "origin": origin,
                        },
                        getattr(ir, "destination", None),
                        getattr(ir, "call_value", None),
                        context(),
                        crossed,
                    )
                # A token-first library/internal transfer (SafeTransferLib /
                # SafeERC20) whose value move is invisible to the selector scan and
                # to the assembly-only callee body. Recognized on the contract's
                # OWN body as well as across a boundary: a contract that reaches
                # for one of these libraries instead of calling ``transfer``
                # directly moves exactly as much value, and publishing nothing for
                # it said "this function moves no funds" about functions that
                # provably do. ``direction_of`` gives the same-contract case its
                # true direction; only a move made across a boundary is routed.
                token_first = _token_first_transfer(ir) if op in ("HighLevelCall", "LibraryCall") else None
                if token_first is not None:
                    selector = _selector_for(_callee_signature(ir))
                    if token_first[0] == "send":
                        _kind, to_arg, amount_arg = token_first
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": direction_of("out"),
                                "from_is_self": True,
                                "origin": origin,
                            },
                            to_arg,
                            amount_arg,
                            context(),
                            crossed,
                        )
                    else:  # pull
                        _kind, from_arg, to_arg, amount_arg = token_first
                        from_self = _arg_is_address_this(from_arg, this_ids, this_names)
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": direction_of("out" if from_self else "in"),
                                "from_is_self": from_self,
                                "origin": origin,
                            },
                            to_arg,
                            amount_arg,
                            context(),
                            crossed,
                            routed_unless_sink_is_self=not from_self,
                        )
                if op in ("InternalCall", "LibraryCall"):
                    # Descend even into a callee the recognizer just classified.
                    # It cannot double-count: the recognizer only fires when the
                    # callee issues its ERC-20 selector in a form the walk CANNOT
                    # resolve (assembly / ``abi.encodeCall``), which reaches the
                    # walk as a value-less ``LowLevelCall`` and produces no flow.
                    # Skipping the descent instead deleted every OTHER move in
                    # that body — a native ``transfer``, an ERC-721 send, a second
                    # token — from a helper the recognizer happened to match. The
                    # dual-asset payout helper (``if (token == 0) to.call{value:}``
                    # else ``safeTransfer``) lost its whole ETH branch, taking
                    # ``has_native_payout`` with it and silently disabling the
                    # prober's contract-balance seeding.
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        child_origin = "guard" if (origin == "guard" or _is_modifier_call(ir)) else "body"
                        child_bindings, child_index_bindings = _bindings_for_call(ir, callee, context())
                        # Internal/library calls stay within the SAME contract
                        # context (and same ``crossed`` state) as their caller.
                        walk(
                            callee,
                            child_origin,
                            False,
                            child_bindings,
                            child_index_bindings,
                            depth + 1,
                            crossed,
                            class_contract,
                        )
                elif op == "HighLevelCall":
                    # Route into a RESOLVED in-unit callee that is not itself one
                    # of the already-handled direct value ops — a function whose
                    # BODY moves value (``BoringVault.enter``/``exit``). Crossing
                    # sets ``crossed`` and rebases the classification context onto
                    # the callee's own contract.
                    selector = _selector_for(_callee_signature(ir))
                    is_direct_value = (
                        selector in _ERC20_PULL_SELECTORS
                        or selector in _ERC20_SEND_SELECTORS
                        or _token_first_transfer(ir) is not None
                    )
                    callee = getattr(ir, "function", None)
                    if not is_direct_value and callee is not None and getattr(callee, "nodes", None):
                        child_origin = "guard" if origin == "guard" else "body"
                        child_bindings, child_index_bindings = _bindings_for_call(ir, callee, context())
                        walk(
                            callee,
                            child_origin,
                            False,
                            child_bindings,
                            child_index_bindings,
                            depth + 1,
                            True,
                            getattr(callee, "contract", None),
                        )

    walk(function, "body", True, None, None, 0, False, entry_contract)
    # Routed flows come strictly after the same-contract flows, preserving the
    # exact prior ordering of the latter.
    flows.extend(router_flows)
    for flow in flows:
        key = (flow["kind"], flow["selector"], flow["direction"], flow["from_is_self"], flow["origin"])
        target = _fold_sites(target_sites.get(key, []))
        amount = _fold_sites(amount_sites.get(key, []))
        if target is not None:
            flow["target_kind"] = target
            breakdown = _site_breakdown(target_sites.get(key, []))
            if breakdown is not None:
                flow["target_kinds"] = breakdown
            index = _fold_param_index(target, target_indexes.get(key, []))
            if index is not None:
                flow["target_param_index"] = index
        if amount is not None:
            flow["amount_kind"] = amount
            breakdown = _site_breakdown(amount_sites.get(key, []))
            if breakdown is not None:
                flow["amount_kinds"] = breakdown
            index = _fold_param_index(amount, amount_indexes.get(key, []))
            if index is not None:
                flow["amount_param_index"] = index
    return flows


def _fold_param_index(kind: KindTier, indexes: list[int | None]) -> int | None:
    """The one entry-parameter slot every contributing site resolved to.

    Requires the folded kind to BE ``param`` (so the value is an entry parameter
    at all) and every site to have resolved the same index. A site that resolved
    none, or two sites resolving different positions, yields ``None``: the flow
    still has a ``param`` origin, we just cannot say which slot.

    ``param_derived`` (amounts only) qualifies under the same discipline, with
    the index meaning the slot of the caller INPUT that fed the conversion rather
    than the slot of the value itself — see :func:`_param_derived_index`."""
    if kind["kind"] not in ("param", "param_derived") or not indexes:
        return None
    distinct = set(indexes)
    if len(distinct) != 1:
        return None
    return next(iter(distinct))


# ---------------------------------------------------------------------------
# Effects + labels + writer selectors per function.
# ---------------------------------------------------------------------------


def _effect_targets_from_sinks(sinks: list[SinkRecord]) -> list[str]:
    """Compatibility display targets sourced from the sink list.

    State writes and external-call dotted targets both remain here because
    API/UI consumers already render this field. Semantic consumers should
    read ``sinks`` and selectors directly.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    for sink in sinks:
        if sink["kind"] == "state_write" and sink["target"] not in seen_set:
            seen.append(sink["target"])
            seen_set.add(sink["target"])
        elif sink["kind"] == "external_call" and sink["target"] not in seen_set:
            # Kept for API/UI compatibility; label inference reads the
            # selector-bearing sink records instead.
            seen.append(sink["target"])
            seen_set.add(sink["target"])
    return seen


def _writer_selectors_for(function: Any, sinks: list[SinkRecord]) -> list[str]:
    """For a state-write function, its own selector is the relevant
    writer selector (HyperSync replays this function to attribute the
    write). Returns a list because some pipelines accumulate multiple
    selectors per logical writer (overloads)."""
    has_state_write = any(s["kind"] == "state_write" for s in sinks)
    if not has_state_write:
        return []
    selector = _own_selector(function)
    if selector is None:
        return []
    return [selector]


def _reconcile_value_flow_labels(
    labels: list[str], value_flows: list[ValueFlow], zero_value_sinks: set[str] | None = None
) -> list[str]:
    """Correct asset-direction labels from the value-flow facts. Native
    transfer/send is an outbound value sink Slither's low-level scan misses;
    a ``transferFrom`` whose ``from`` is ``address(this)`` was mis-read as a
    pull. Only body-origin flows count. ``value_router`` flows are excluded: they
    are a callee's move, not the entry's own asset direction, so they must not add
    ``asset_send``/``asset_pull`` to the router."""
    body = [vf for vf in value_flows if vf["origin"] != "guard"]
    body_flows = [vf for vf in body if vf["direction"] != "value_router"]

    def _is_erc20_pull(vf: ValueFlow) -> bool:
        return vf["kind"] == "callee_erc20_selector" and vf["selector"] in _ERC20_PULL_SELECTORS

    # Plane 0 maps a pull SELECTOR straight to ``asset_pull``, which reads the
    # call and not the destination. When every pull this function makes is one it
    # merely caused between two other parties, nothing arrived here and the label
    # has to come off — otherwise the row still says "fund-in" and the summary
    # still reads "Pulls assets into the contract" about a contract the funds
    # never touched. Removal only, and only on positive evidence: a routed flow
    # never ADDS a direction label, and a function with no flow facts keeps
    # whatever the selector scan said, because silence is not evidence.
    if any(_is_erc20_pull(vf) and vf["direction"] == "value_router" for vf in body) and not any(
        _is_erc20_pull(vf) for vf in body_flows
    ):
        labels = [lbl for lbl in labels if lbl != "asset_pull"]

    # Plane 0 mints ``asset_send`` from ANY ``.call{value: v}`` it can reach
    # through an internal call, without looking at v. OZ's
    # ``Address.functionCallWithValue(target, data, 0)`` sits at the bottom of
    # every SafeERC20 call, so a function whose only "value move" is an approval
    # published "sends assets out of the contract" — with no flow fact under it,
    # because the walk had already proved the same site moves nothing. That proof
    # is what retracts the label; it is available precisely because the walk
    # resolves the callee's ``value`` parameter through the caller's binding,
    # which the Plane-0 string scan cannot do. Only when no outbound flow
    # survives: a function that both approves and pays keeps the label from the
    # payment.
    if "low_level_value_call" in (zero_value_sinks or ()) and not any(vf["direction"] == "out" for vf in body_flows):
        labels = [lbl for lbl in labels if lbl != "asset_send"]

    if not body_flows:
        return labels

    if any(vf["kind"] == "native_transfer_send" for vf in body_flows):
        labels = [lbl for lbl in labels if lbl != "hook_update"]
        if "asset_send" not in labels:
            labels.append("asset_send")

    pull_from_self = any(_is_erc20_pull(vf) and vf["from_is_self"] for vf in body_flows)
    genuine_pull = any(_is_erc20_pull(vf) and not vf["from_is_self"] for vf in body_flows)
    if pull_from_self and not genuine_pull and "asset_pull" in labels:
        labels = [lbl for lbl in labels if lbl != "asset_pull"]
        if "asset_send" not in labels:
            labels.append("asset_send")
    return labels


def _effect_info_for_function(function: Any) -> EffectInfo:
    sinks = _build_sink_records(function)
    state_writes = _state_write_facts(function, sinks)
    zero_value_sinks: set[str] = set()
    value_flows = _value_flow_facts(function, zero_value_sinks=zero_value_sinks)
    effects: list[str] = []

    # Guard-origin sinks (a modifier's own auth call, a reentrancy latch) are
    # facts, not effects: they never drive a label, a display target, or a
    # summary. They stay in ``sinks`` with ``origin=guard``.
    body_sinks = [s for s in sinks if s["origin"] != "guard"]

    # ``effect_targets`` remains a compatibility display field. Semantic
    # consumers should read ``sinks`` and selectors instead.
    effect_targets = _effect_targets_from_sinks(body_sinks)

    # _effect_labels takes a synthetic graph-entry analog. Capability
    # reachability (delegatecall_execution, selfdestruct_capability,
    # contract_deployment) keys on ``sink_kinds`` over *all* sinks — a
    # delegatecall reachable only through a proxy's ``ifAdmin`` modifier is
    # still reachable. The external-call/asset layer reads the body-only sink
    # list, so a modifier's own auth call can't drive an effect label.
    sink_kinds = sorted({s["kind"] for s in sinks})
    effect_context = {
        "effects": list(effects),
        "effect_targets": list(effect_targets),
        "sink_kinds": sink_kinds,
        "sinks": list(body_sinks),
    }
    labels = _effect_labels(function, effect_context)
    labels = _reconcile_value_flow_labels(labels, value_flows, zero_value_sinks)
    # Functions with body external_call sinks but no specific (mint/burn/asset/etc)
    # label get ``external_contract_call`` directly from the sink shape. AFTER the
    # reconcile, so a function whose only specific label the flow facts just
    # disproved falls back to the generic sink fact rather than to nothing.
    has_external_call = any(s["kind"] == "external_call" for s in body_sinks)
    if has_external_call and not any(lbl in _SPECIFIC_EFFECT_LABELS for lbl in labels):
        labels.append("external_contract_call")
    summary = _action_summary(labels, list(effect_targets))

    signature = _function_full_name(function)
    # "" is the no-selector sentinel (fallback/receive), matching the
    # ``effect_verdicts`` identity key in ``db/effect_cache.py``.
    selector = _own_selector(function) or ""
    return {
        "function": signature,
        "selector": selector,
        "abi_signature": signature,
        "sinks": sinks,
        "state_writes": state_writes,
        "value_flows": value_flows,
        "effects": list(effects),
        "effect_labels": list(labels),
        # Includes both state-write var names and external-call dotted
        # targets for label/summary rendering. Tracking.py reads ``sinks``
        # directly to enumerate state_write writers.
        "effect_targets": list(effect_targets),
        "action_summary": summary,
        "writer_selectors": _writer_selectors_for(function, sinks),
        "state_changing": _is_state_changing_entry_point(function),
        "parameter_names": [str(getattr(p, "name", "") or "") for p in (getattr(function, "parameters", None) or [])],
        "payable": bool(getattr(function, "payable", False)),
        "assembly_state_access": any(
            s["kind"] in ("state_write", "delegatecall")
            and (s["target"].startswith("assembly_storage:") or s["target"].startswith("assembly_delegatecall:"))
            for s in sinks
        ),
    }


# ---------------------------------------------------------------------------
# Top-level entry.
# ---------------------------------------------------------------------------


def _record_prefers(new_info: EffectInfo, new_fn: Any, old_info: EffectInfo, old_fn: Any) -> bool:
    """Should ``new_info`` replace ``old_info`` for the same signature?

    Two functions can share a ``full_name`` — a concrete implementation and
    an inherited interface/abstract re-declaration (0 nodes). Keying the dict
    by ``full_name`` alone lets the 0-node record clobber the real one and
    blank its sinks (EigenLayer StrategyManager ``pause``). Prefer the
    implemented body, then the one carrying more sinks."""
    new_impl = bool(getattr(new_fn, "is_implemented", False)) and bool(getattr(new_fn, "nodes", None))
    old_impl = bool(getattr(old_fn, "is_implemented", False)) and bool(getattr(old_fn, "nodes", None))
    if new_impl != old_impl:
        return new_impl
    return len(new_info["sinks"]) > len(old_info["sinks"])


def build_effects(contract: Any) -> EffectsArtifact:
    """Return the ``effects`` artifact for ``contract``: one
    ``EffectInfo`` per externally-observable function (external,
    public, fallback, receive)."""
    functions: dict[str, EffectInfo] = {}
    chosen_fn: dict[str, Any] = {}
    for fn in getattr(contract, "functions", []) or []:
        if not _is_externally_observable(fn):
            continue
        info = _effect_info_for_function(fn)
        signature = info["function"]
        existing = functions.get(signature)
        if existing is None or _record_prefers(info, fn, existing, chosen_fn[signature]):
            functions[signature] = info
            chosen_fn[signature] = fn

    artifact: EffectsArtifact = {
        "schema_version": SCHEMA_VERSION,
        "contract_name": getattr(contract, "name", None),
        "functions": functions,
    }
    token_slots = derive_token_slots(contract)
    if token_slots is not None:
        artifact["token_slots"] = cast("TokenSlots", token_slots)
    return artifact
