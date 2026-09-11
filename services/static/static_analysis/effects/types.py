"""Typed schema of the effects artifact, plus the ERC-20/721 selector data tables."""

from __future__ import annotations

from typing import Literal, TypedDict

from typing_extensions import NotRequired

from ..record_ordering import OrderingWitness

SCHEMA_VERSION = "semantic-3"


class ReceiverDescriptor(TypedDict):
    """The STRUCTURAL identity of an ``external_call`` sink's receiver — the
    object whose method is invoked (``asset.safeTransferFrom`` → ``asset``).

    The sink's ``target`` string carries the receiver's identifier and nothing
    else, so a consumer holding only that has a NAME. This descriptor answers
    what the name cannot: whether the caller chose the receiver, whether it is
    this unit's storage, and — only where the compiler itself minted one — the
    selector of the getter that reads it. Every field is read off the declaring
    AST node; none is inferred from the identifier.

    ``binding`` is decided by ``isinstance``, never by ``visibility``: a
    Slither ``LocalVariable`` answers ``visibility == "internal"``,
    ``is_immutable is False`` and ``is_constant is False`` exactly as an
    internal state variable does, so visibility is a silent false-positive
    discriminator (a formal parameter would read as storage). ``mutability``,
    ``visibility`` and ``auto_getter_selector`` are therefore populated ONLY
    under ``isinstance(resolved, StateVariable)``; a ``SolidityVariable``
    raises ``AttributeError`` on all three and is refused before they are read.

    ``mutability`` is a DECLARATION CLASS, not a write-surface finding:
    ``mutable`` means "declared plain storage in this compilation unit", NOT
    "a writer exists" — that question is answered by the value-flow lattice's
    ``target_kind``/``target_writer_signatures``, on its own evidence.
    ``immutable_in_implementation`` is spelled the long way on purpose: an
    ``immutable`` is inlined into the IMPLEMENTATION's bytecode, so behind a
    proxy it is not an invariant of the address a consumer prices against.
    """

    # parameter | state_variable | local | not_determined
    binding: str
    # entry_point | internal_helper — parameter bindings only, else None. A
    # nested helper's formal is NOT an ABI slot (the sink walk is transitive),
    # so only ``entry_point`` can carry an index or prove the CALLER named it.
    param_scope: str | None
    param_index: int | None
    # constant | immutable_in_implementation | mutable — state variables only.
    mutability: str | None
    visibility: str | None
    # keccak4 of the compiler-minted auto-getter's signature. Emitted only for
    # a public state variable whose getter takes NO arguments; see
    # :func:`_auto_getter_selector` for why the type — not the name — licenses it.
    auto_getter_selector: str | None
    # The AST identifier, for display and for joining to source. NEVER a
    # resolution basis: ``variable + "()"`` is the inv.2 shape this descriptor
    # exists to replace.
    variable: str | None
    # caller_named | contract_state_unresolved | not_determined.
    #
    # It names where the RECEIVER came from, and asserts nothing about the
    # receiver being an asset — a library-math call binds a ``uint256`` quantity
    # as its receiver, and 7 of the 20 caller-named rows on the corpus are
    # exactly that shape. Reading it as "the asset is caller-named" beside
    # ``param_index`` would state a coherent-looking falsehood: on
    # ``redeem(address to, IERC20 withdrawAsset, uint256 shareAmount)`` the
    # published index is 2 and the asset is in slot 1. Hence the field is named
    # for the receiver, not for the asset.
    receiver_provenance: str
    # Diagnostic, present only when ``binding`` is ``not_determined``, so that
    # "the sites conflicted" and "the head never resolved" stop being the same
    # published value. Carries no consumption obligation.
    not_determined_reason: NotRequired[str]


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
    # High-level/library call sinks only — the arm where the receiver is
    # resolved past its casts. A low-level call's destination never goes
    # through that resolution, and a non-call sink has no receiver at all, so
    # the key stays ABSENT there: absent means "never computed", which fails
    # every downstream precondition exactly as ``not_determined`` does.
    receiver: NotRequired[ReceiverDescriptor]


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
    # ``value_router`` flows only: the identity of every call that CARRIES the
    # routed move — the body call the walk crossed to find it (``vault.exit``),
    # or, for a boundary-less routed pull, the pull op itself. Each entry is
    # ``{"selector": canonical-selector-or-None, "callee": bare-name-or-None}``,
    # sorted for determinism. The flow's own ``selector`` names the CALLEE's
    # inner transfer, which is not a call the entry body makes, so without this
    # record a routed move has no identity a mandatory-gate walk can join a
    # leaf against. Consumers treat exactly these ops as "the described
    # effect's own revert surface"; ABSENCE of the record makes nothing
    # transparent — an unrecorded router identity can only block a negative
    # proof, never mint one.
    router_ops: NotRequired[list[dict[str, str | None]]]
    # The AST identifier of the state variable the destination resolves to,
    # published only when ``target_kind`` is one of the state-variable kinds and
    # every contributing site named the same DECLARATION — compared on the
    # canonical ``Contract.var``, not on the bare identifier, because two
    # contracts in one call graph may each declare ``recipient`` with separate
    # setters and separate values. A mapping/array element never emits one (the
    # element is not its base). Identity for a join and for display — never a
    # resolution basis.
    target_variable: NotRequired[str]
    # The distinct declarations when the sites named more than one, CANONICAL
    # (``Contract.var``) because bare names cannot tell them apart — which is
    # exactly why the list exists. Present precisely where ``target_variable``
    # is absent for that reason, so a consumer can never read one member as the
    # whole.
    target_variables: NotRequired[list[str]]
    # The signatures WITHIN THE ANALYSED COMPILATION UNIT that write
    # ``target_variable``. A floor: "redirectable at least by these writers'
    # principals", never the closed set — see ``writer_surface_closed``.
    # ``[]`` is the earned negative that ``storage_no_setter`` already asserts
    # (scan complete, no writer found); the key is ABSENT when no signature was
    # attributed, which is a different thing and must not be read as ``[]``.
    target_writer_signatures: NotRequired[list[str]]
    # The soundness gate for the line above, published in the SAME dict and at
    # the same time so the payload can never travel without it. False means a
    # blind spot (assembly ``sstore``, delegatecall, unresolved alias) made the
    # write attribution non-exhaustive.
    target_writer_scan_complete: NotRequired[bool]
    # Which absence ``target_writer_signatures`` is, when it is absent and the
    # kind did not earn ``[]``. The two carry OPPOSITE risk:
    # ``declaration_initialiser_only`` — the only attributed write is the
    # declaration-site initialiser Slither synthesises, so the destination is
    # effectively fixed short of an upgrade; ``alias_unattributed`` — a real
    # write reaches it through a storage-pointer alias this pass could not
    # attribute to a signature, so it may be redirectable and by whom is
    # unknown. Diagnostic: it explains an absence, it never licenses a positive.
    target_writer_absent_reason: NotRequired[str]
    # Whether the writer set is the WHOLE write surface at the deployed address.
    # Always ``not_determined``: this stage analyses ONE compilation unit, while
    # the runtime address may be a proxy (upgrade-extensible write surface) or
    # one of several implementations (a sibling's writers are outside the unit).
    # Deciding it needs a resolution-plane writer that knows the deployment is
    # neither, which is why the type is a single literal rather than a bool.
    writer_surface_closed: NotRequired[Literal["not_determined"]]
    # The storage RECORD the amount is read out of, published only when
    # ``amount_kind`` is ``bounded_by_storage`` and every contributing site
    # resolved the SAME declaration — canonical (``Contract.var``), because two
    # contracts in one call graph may each declare ``bids`` and a bare name
    # cannot tell them apart. This names the cell, not a bound: it says which
    # record a guard would have to be shown to gate, and says nothing about who
    # may read or write it.
    amount_record_variable: NotRequired[str]
    # The struct member inside that record the amount reads (``[]`` for a scalar
    # mapping), and the origin of each index level that selected the cell —
    # ``param`` / ``msg_sender`` / ``indeterminate``, the first index level
    # first — with the ENTRY parameter slot of each level beside it (``null``
    # where the key is not one whole entry argument). ``param`` is earned: it
    # rides only where the slot beside it is proven, so a key the caller merely
    # DERIVED (``bids[a + b]``, ``bids[uint128(id)]``) reads as indeterminate
    # rather than as a cell the caller named. Each list rides only where every
    # contributing site agreed on it: absence is a site disagreement, and a
    # consumer must read it as "not determined", never as an empty path.
    amount_record_member_path: NotRequired[list[str]]
    amount_record_key_kinds: NotRequired[list[str]]
    amount_record_key_param_indexes: NotRequired[list[int | None]]
    # The distinct declarations when the sites named more than one — present
    # precisely where ``amount_record_variable`` is absent for that reason, so
    # one member can never be read as the whole. Exactly the
    # ``target_variables`` discipline.
    amount_record_variables: NotRequired[list[str]]
    # W2: does a clearing write to the record this amount came out of
    # must-precede every external call? Three-valued, computed by
    # ``record_ordering``. Present only where the amount NAMES a record — the
    # ordering question does not exist otherwise, and absence is never a
    # refusal.
    record_ordering: NotRequired[OrderingWitness]


class EffectInfo(TypedDict):
    function: str
    selector: str
    abi_signature: str
    sinks: list[SinkRecord]
    state_writes: list[StateWriteFact]
    value_flows: list[ValueFlow]
    effects: list[str]
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
    # Written by ``attach_claims_to_effects`` even when ``functions`` is empty.
    # Its presence proves the claims plane completed; per-function ``claims``
    # keys cannot carry that fact for a contract with no observable functions.
    claims_schema_version: NotRequired[str]
    claim_analyses: NotRequired[dict[str, object]]
    claim_diagnostics: NotRequired[list[dict[str, object]]]


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
