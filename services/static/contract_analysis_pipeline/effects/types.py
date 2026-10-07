"""Typed schema of the effects artifact, plus the ERC-20/721 selector data tables."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from typing_extensions import NotRequired

from ..record_ordering import OrderingWitness

SCHEMA_VERSION = "semantic-3"


class ReceiverDescriptor(TypedDict):
    """Structural identity of an ``external_call`` receiver (``asset.safeTransferFrom`` -> ``asset``): whether the
    caller chose it, whether it is this unit's storage, and, where the compiler minted one, its getter selector.
    Read off the declaring AST node, never the name.

    ``binding`` uses ``isinstance``, not ``visibility``: a ``LocalVariable`` reports the same visibility and mutability
    as an internal state variable. ``mutability``, ``visibility`` and ``auto_getter_selector`` exist only for state
    variables.

    ``mutability`` is the declaration class, not whether a writer exists (that is ``target_kind``).
    ``immutable_in_implementation`` because an ``immutable`` lives in the implementation's bytecode, not the proxy
    address.
    """

    binding: str
    # ``entry_point`` | ``internal_helper`` (parameters only). A helper's formal has no ABI slot, so only
    # ``entry_point`` can carry an index or prove the caller named it.
    param_scope: str | None
    param_index: int | None
    mutability: str | None
    visibility: str | None
    # Only for public state variables with a nullary getter; see :func:`_auto_getter_selector`.
    auto_getter_selector: str | None
    # Display and joins only, never a resolution basis.
    variable: str | None
    # ``caller_named`` | ``contract_state_unresolved`` | ``not_determined``. About the receiver, not the asset: a
    # library-math call's receiver can be a ``uint256``.
    receiver_provenance: str
    # Diagnostic for ``not_determined`` (conflicting sites vs unresolved head).
    not_determined_reason: NotRequired[str]


class SinkRecord(TypedDict):
    """One sink reachable from an external function.

    ``function`` is the originating entry point, not where the IR lives; ``origin`` is ``guard`` when only reachable
    through a modifier.
    """

    id: str
    function: str
    kind: str  # state_write | external_call | delegatecall | contract_creation | selfdestruct
    target: str
    selector: str | None
    origin: str  # body | guard
    # High-level/library call sinks only; absent elsewhere, which fails preconditions like ``not_determined``.
    receiver: NotRequired[ReceiverDescriptor]
    # Library call sinks only: the library function's Slither spelling. Text, never hashed: the receiver doesn't
    # answer the library's selector, so ``selector`` is ``None``.
    library_signature: NotRequired[str]
    # Library call sinks only, and only when proven: the library function and all it reaches make no external call, so
    # its receiver is never called. Absent is not determined.
    library_makes_no_call: NotRequired[bool]


class StateWriteFact(TypedDict):
    """A state write with member granularity and a hygiene class; role-fact consumers skip non-``normal`` classes."""

    var: str
    declared_type: str
    member_path: list[str]
    granularity: str  # var | member | assembly_slot
    hygiene_class: str  # normal | constant | storage_location_pseudo | reentrancy_guard | view_writer
    origin: str  # body | guard


class KindTier(TypedDict):
    """A lattice kind with its witness tier: ``dispositive_ast`` when the operand is directly a state variable,
    parameter, ``msg.sender`` or literal; ``static_trace`` when recovered through the SSA trace. ``indeterminate``
    is always ``static_trace``.
    """

    kind: str
    tier: str  # dispositive_ast | static_trace


class ValueFlow(TypedDict):
    """A value movement.

    ``direction`` is corrected for ``from == address(this)``. ``target_kind``/``amount_kind`` classify where funds go
    and how much can leave, folded across all IR sites.
    """

    kind: str  # callee_erc20_selector | native_transfer_send | low_level_value_call
    selector: str | None
    # Bare names of the token-first library functions carrying the move (``safeTransfer``); their call sinks have no
    # selector, so a consumer finds the carrier by name.
    library_callees: NotRequired[list[str]]
    # ``in``/``out`` are this contract's own moves (it is payer or payee). ``value_router`` is a move the entry only
    # caused (a router into a vault, or a pull between third parties) and never drives a direction label;
    # ``from_is_self`` says which way.
    direction: str  # in | out | value_router
    from_is_self: bool
    origin: str  # body | guard
    # ``several``: sites resolved to different kinds, listed in ``target_kinds``; take the worst. Not alternatives: they
    # may all execute in one call.
    target_kind: NotRequired[KindTier]
    # ``caller_supplied``: every branch is a caller-chosen quantity (argument or attached ETH); no slot.
    # ``token_identity``: the slot names which token moves (ERC-721), never an amount. ``capped_by_balance``: provably
    # at most this contract's balance. ``param_derived``: see :func:`_call_amount_origin`.
    amount_kind: NotRequired[KindTier]
    # Distinct per-site ``(kind, tier)`` classifications, present only when sites disagreed. Indeterminate sites are
    # listed, so the list is closed under ``several`` and partial under ``indeterminate``.
    target_kinds: NotRequired[list[KindTier]]
    amount_kinds: NotRequired[list[KindTier]]
    # Entry parameter index of the destination, only when ``target_kind`` is ``param`` and every site agrees on one
    # whole argument. Probers plant an address there, so absent means don't guess.
    target_param_index: NotRequired[int]
    # Entry parameter index of the amount, same rules; for ``param_derived``, the slot of the input that fed the
    # conversion. Probers need it to avoid writing a quantity into an id or deadline.
    amount_param_index: NotRequired[int]
    # ``value_router`` only: ``{selector, callee}`` of each call carrying the routed move (sorted). The flow's own
    # selector is the callee's inner transfer, so this is the only identity a gate walk can join on. Absence can only
    # block a proof, never mint one.
    router_ops: NotRequired[list[dict[str, str | None]]]
    # The destination state variable, only when every site named the same declaration (compared canonically). Never for
    # elements. Joins and display only.
    target_variable: NotRequired[str]
    # Canonical ``Contract.var`` declarations when sites named several; present exactly where ``target_variable`` isn't.
    target_variables: NotRequired[list[str]]
    # In-unit writers of ``target_variable``: a floor, not the closed set. ``[]`` only under ``storage_no_setter``;
    # absent when no signature was attributed.
    target_writer_signatures: NotRequired[list[str]]
    # False when a blind spot (assembly sstore, delegatecall, unresolved alias) made attribution non-exhaustive; always
    # published with the writer list.
    target_writer_scan_complete: NotRequired[bool]
    # Why the writer list is absent. Opposite risks: ``declaration_initialiser_only`` is effectively fixed;
    # ``alias_unattributed`` is a real, unknown writer.
    target_writer_absent_reason: NotRequired[str]
    # Always ``not_determined``: one compilation unit can't know the deployed address's full write surface (proxies,
    # sibling implementations).
    writer_surface_closed: NotRequired[Literal["not_determined"]]
    # The canonical storage record the amount is read from, only for ``bounded_by_storage`` when all sites agree. Names
    # the cell, not a bound.
    amount_record_variable: NotRequired[str]
    # The member path and per-key-level origins (``param``/``msg_sender``/``indeterminate``) with entry slots. ``param``
    # only with a proven slot. Absent on site disagreement, never read as empty.
    amount_record_member_path: NotRequired[list[str]]
    amount_record_key_kinds: NotRequired[list[str]]
    amount_record_key_param_indexes: NotRequired[list[int | None]]
    # Distinct declarations when sites named several; the ``target_variables`` discipline.
    amount_record_variables: NotRequired[list[str]]
    # W2: does a clearing write to the amount's record precede every external call? Present only where the amount names
    # a record.
    record_ordering: NotRequired[OrderingWitness]


class EffectInfo(TypedDict):
    effect_scopes: NotRequired[list[dict[str, Any]]]
    function: str
    # Hashed from ``abi_signature``; ``""`` for fallback/receive, ``None`` when the signature can't be lowered.
    selector: str | None
    # Canonical ABI types; ``function`` keeps Slither's spelling.
    abi_signature: str | None
    sinks: list[SinkRecord]
    state_writes: list[StateWriteFact]
    value_flows: list[ValueFlow]
    effects: list[str]
    effect_labels: list[str]
    effect_targets: list[str]
    action_summary: str
    writer_selectors: list[str] | None
    # A selector-bearing, non-view, non-pure entry point; lets policy surface state-changing functions with no sink as
    # unsupported.
    state_changing: bool
    # Declared parameter names aligned with ``abi_signature`` ("" if unnamed); probers use them to tell quantities from
    # ids and deadlines.
    parameter_names: list[str]
    # Probes attaching ``msg.value`` to a non-payable function revert before the body runs.
    payable: bool
    # A sink came from inline assembly, whose guard may also be assembly and invisible, so policy keeps it fail-closed.
    assembly_state_access: bool


class TokenSlotEntry(TypedDict):
    """Base slot of a token-precondition mapping keyed to its view getter, used to seed balances on an anvil fork."""

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


# Pull selectors take ``from`` first, so direction depends on it being ``address(this)``.
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

# ERC-721-only pull selectors: the trailing ``uint256`` is a token id. ``0x23b872dd`` is excluded (both standards define
# ``transferFrom``).
_ERC721_IDENTITY_SELECTORS = frozenset(
    {
        "0x42842e0e",  # safeTransferFrom(address,address,uint256)
        "0xb88d4fde",  # safeTransferFrom(address,address,uint256,bytes)
    }
)

# Keeps an id out of ``amount_param_index``, which probers fill with an amount.
_TOKEN_IDENTITY_AMOUNT = ("token_identity", "dispositive_ast")

# Defined by both standards, so it gets neither the identity kind nor zero-amount suppression.
_AMBIGUOUS_PULL_SELECTOR = "0x23b872dd"

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
