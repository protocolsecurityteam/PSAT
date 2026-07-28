"""Per-class calldata + entry-point synthesis (EFFECTS_RESOLUTION_SPEC §4.1–§4.5).

Turns the STATIC facts a candidate already carries — ABI param types, sinks,
state writes, value-flow taint, predicate trees, resolved principals — into the
concrete probe inputs each recipe needs. Pure over the DB/artifact reads it does:
no RPC, no fork, no wire of its own, so the whole surface is testable against
recorded fixtures.

Every synthesizer returns ``None`` when the facts are too thin to build an
honest probe. That is the load-bearing property: a recipe fed guessed calldata
would mint a witness for a call the contract never actually performs, and §8's
fail-closed discipline only holds if the inputs are real. Thin facts ⇒ no plan
⇒ the class stays ``unknown``.

A class emitting NO plans across a whole protocol is a normal outcome, not a
symptom. Measured on etherfi (2026-07-21): value-out and supply produced zero
plans over all 265 candidates, because every value-moving function there already
carries a ``flow.out`` claim and §6's cascade selects BLANK-claim functions only.
The fact plumbing is fine — those functions do carry ``direction: "out"`` in the
effects artifact; they are simply already explained. This is §6.2 working as
designed: as the claims matchers grow, the simulation workload shrinks.

Decision points are deliberately concentrated and named so the live-validation
loop can adjust them without re-deriving the module:

* :data:`ARG_AMOUNT` — the numeric filler for value-carrying params (1 wei, the
  amount that slips under real rate limiters; measured 2026-07-21).
* :data:`SENTINEL_ADDRESS` — the attacker identity substituted at a taint index.
* :func:`_arg_values` — the address/uint/other substitution policy.
* :data:`NEUTRAL_CALLER` — the identity a blast-radius probe uses when the entry
  point has no resolved principal.
* :func:`read_max_pause_duration` — inv. 10: the bound is READ off the latch's
  own guard leaf, never hardcoded and never scraped from source text.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from weakref import WeakKeyDictionary

from eth_utils.crypto import keccak
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import EffectiveFunction, FunctionPrincipal
from db.queue import get_artifact
from services.effects.anvil import EntryPoint, ForkFixture
from services.effects.config import (
    DURATION_BOUND_GUARD_CONSTANT,
    DURATION_BOUND_NO_TIME_REFERENCE,
    DURATION_BOUND_NOT_DETERMINED,
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    SHAPE_IMMUTABLE_FIXED,
    SHAPE_STORAGE_DETERMINED,
)
from services.effects.seeding import SEED_UNIT_DECIMALS
from services.effects.selection import AssetHolding, Candidate
from services.policy.effective_permissions import _abi_signature
from services.resolution.differential_probe import (
    _default_value_for_type,
    _is_address_type,
    _parse_arg_types,
)

logger = logging.getLogger(__name__)

# The attacker identity substituted at a taint-identified address param (§4.2).
SENTINEL_ADDRESS = "0x" + "ee" * 20

# Caller for a blast-radius entry point with no resolved principal — a plain
# identity, kept distinct from the sentinel so a transfer landing on the attacker
# can never be confused with one landing on a prober.
NEUTRAL_CALLER = "0x" + "11" * 20

# Numeric filler for value-carrying params. 1 (wei / smallest unit) rather than 0
# because a zero-amount transfer moves nothing observable, and rather than a large
# amount because real contracts gate on rate limiters and balances — a 1-wei call
# is the one that got through on the 2026-07-21 live run.
ARG_AMOUNT = 1

# Filler for an integer param whose role is an ID / index, not a quantity.
# Deliberately equal to :data:`ARG_AMOUNT` and NEVER scaled by token decimals:
# the seeded retry raises the AMOUNT to one whole unit, and one whole unit
# substituted into a token id is what made every claim/redeem probe revert on its
# own argument (``ERC721: invalid token ID``, measured 2026-07-22). It also has to
# equal the key :func:`_seed_fixture_for_role` writes an ownership seed at, or the
# seeded owner would sit at a token id no probe ever asks about.
ARG_IDENTIFIER = 1

ROLE_AMOUNT = "amount"
ROLE_IDENTIFIER = "identifier"

# Roles for an ADDRESS parameter. ``ROLE_RECIPIENT`` is where the principal
# belongs (it is what makes a payout observable); ``ROLE_TOKEN`` is a slot the
# principal must NEVER occupy — a token/asset argument is dereferenced as a
# contract, so an EOA there reverts the call before any effect (measured:
# ``BoringVault.enter``'s ``asset`` slot, ``TRANSFER_FROM_FAILED``, 8/8 supply
# probes, 2026-07-25 run).
ROLE_RECIPIENT = "recipient"
ROLE_TOKEN = "token"

# Balance handed to every impersonated entry-point caller on the fork so gas can
# never masquerade as a pause revert.
FIXTURE_BALANCE_WEI = 10**19

# Token balance / allowance / shares seeded into a prober's slot so a
# balance/allowance precondition can never make an entry point revert pre-pause
# (which the diff would misread as "the pause froze it"). A clean power of two far
# above ARG_AMOUNT (the 1-unit transfer/mint amount) so amount args always clear
# the check, and far below 2**256 so a ``balance + amount`` path cannot overflow.
SEED_AMOUNT = 2**128

# Upper sanity bound for a pause duration read out of a guard constant: a value
# above this is not a freeze window (it is a chain-id, an amount, a role hash).
_MAX_PLAUSIBLE_DURATION_S = 365 * 24 * 3600


_AUTHORITY_ROLES = ("caller_authority", "delegated_authority")


# ---------------------------------------------------------------------------
# Plan inputs — one dataclass per effect class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValueOutPlanInputs:
    """§4.2 inputs: call F as the resolved principal, plus a sentinel variant that
    puts the attacker identity at the taint-identified address param."""

    contract_address: str
    principal: str
    calldata: str
    gate_ref: str
    taint_param_reaches_sink: bool = False
    sentinel_address: str | None = None
    sentinel_calldata: str | None = None
    # §5b downstream value-reach: the protocol's witnessed value-holders the recipe
    # measures against, and the acting deployment's own balance floor.
    value_holders: tuple[AssetHolding, ...] = ()
    acting_balance_usd: float = 0.0
    protocol_tvl_usd: float | None = None
    # Input-asset seeding: candidate getters naming the asset F pulls, and the
    # whole-unit calldata the SEEDED retry uses. Empty ⇒ no retry, today's probe.
    input_token_hints: tuple[str, ...] = ()
    # Address slots proved to carry a TOKEN. They hold no principal; the seeded
    # retry writes a resolved token address into each, or leaves them at the
    # encoder's default and records why.
    token_param_indexes: tuple[int, ...] = ()
    seeded_calldata: Mapping[int, str] = field(default_factory=dict)
    seeded_sentinel_calldata: Mapping[int, str] = field(default_factory=dict)
    # ABI payability of F, or ``None`` on an artifact that predates the fact.
    # ``False`` suppresses the ``msg.value`` retry, which such a target rejects
    # with an empty revert before its body runs.
    target_payable: bool | None = None
    # Static says F sends native ETH out of the CONTRACT's own balance, so a
    # contract-balance seed could unblock it (see ``has_native_payout``).
    native_payout: bool = False
    # The destination shape static PROVES for every out-flow of F, or ``None``
    # (see :func:`static_destination_shape`). The recipe uses it only where the
    # sentinel did not already prove ``caller_arbitrary``.
    static_shape: str | None = None
    # An argument the effect depends on was left at the encoder's default (see
    # :class:`ProbeArgs`). A call that RAN and observed nothing on such inputs is
    # a fact about the arguments, not about F — so the recipe must name it as one
    # and it must never enter the code-plane behaviour cache.
    inputs_vacuous: bool = False
    # ERC-20 analogue of the native ``contract_balance`` seed: assets the acting
    # deployment PROVABLY holds (§16.6-A), so a payout the contract's live balance
    # cannot cover can be reached by seeding the CONTRACT's own token balance. A
    # verdict proven under it is a CAPABILITY claim (would move IF funded) and
    # carries the same weaker ``contract_balance_seeded`` qualifier.
    contract_holdings: tuple[str, ...] = ()


@dataclass(frozen=True)
class SupplyPlanInputs:
    """§4.5 inputs: the recipe reads ``totalSupply`` around a call to F made as
    the resolved principal."""

    token_address: str
    principal: str
    mint_calldata: str
    gate_ref: str
    taint_param_reaches_sink: bool = False
    sentinel_address: str | None = None
    sentinel_calldata: str | None = None
    # Input-asset seeding — see :class:`ValueOutPlanInputs`.
    input_token_hints: tuple[str, ...] = ()
    token_param_indexes: tuple[int, ...] = ()
    seeded_calldata: Mapping[int, str] = field(default_factory=dict)
    seeded_sentinel_calldata: Mapping[int, str] = field(default_factory=dict)
    target_payable: bool | None = None
    native_payout: bool = False
    # See :class:`ValueOutPlanInputs`.
    inputs_vacuous: bool = False
    # See :class:`ValueOutPlanInputs`.
    contract_holdings: tuple[str, ...] = ()
    # NO ``static_shape``. The supply recipe reads a destination shape only to
    # collect a §9 discrepancy and discards the shape itself, and the supply
    # DIRECTIONS (``mint``/``burn``) are a legacy ``semantic_control`` vocabulary
    # the effects artifact never emits — so threading one here computed nothing
    # and then dropped it.


@dataclass(frozen=True)
class TimelockPlanInputs:
    """§9.5 Tier-2 inputs: schedule an operation, advance past the delay, execute
    it — the sequence Tier 1 cannot reach, because ``eth_simulateV1`` issues one
    block with no ``blockOverrides`` and so can never satisfy a
    ``block.timestamp`` gate.

    The scheduled operation and the executed one must be the SAME tuple: OZ's
    ``execute`` recomputes the operation id from its own arguments
    (``hashOperation(target, value, payload, predecessor, salt)``), so nothing
    here has to hash anything — it only has to encode the same values twice, once
    with the delay appended.

    The delay is the only argument not knowable offline. It is the contract's own
    ``getMinDelay()``, read on the fork (``delay_calldata``) because OZ rejects a
    schedule below it and the value is per-deployment."""

    contract_address: str
    principal: str
    execute_calldata: str
    schedule_selector: str
    schedule_signature: str
    # The shared tuple, by parameter index, with the trailing delay left out.
    schedule_arguments: Mapping[int, Any]
    delay_index: int
    # Validated at synthesis, so a plan always has a call to make. Also the
    # honest input when the delay cannot be read: the contract's own check
    # rejects a zero delay, and the recipe records that revert verbatim.
    schedule_calldata_zero: str
    # ``getMinDelay()`` — read, never assumed (§0.0.2).
    delay_calldata: str
    gate_ref: str
    sentinel_address: str | None = None
    # The asset the value witness is read against, or ``None`` when the timelock
    # provably holds nothing to move. That absence is a FACT about the contract,
    # and the recipe reports it as its own reason rather than as "moved nothing".
    witness_token: str | None = None
    witness_calldata: str | None = None
    fixtures: tuple[ForkFixture, ...] = ()

    def schedule_calldata(self, delay: int) -> str:
        subs = dict(self.schedule_arguments)
        subs[self.delay_index] = int(delay)
        return encode_calldata(self.schedule_selector, self.schedule_signature, substitutions=subs) or (
            self.schedule_calldata_zero
        )


@dataclass(frozen=True)
class AuthorityPlanInputs:
    """§4.4 inputs: ``probe_calldata`` exercises the gate G that F mutates;
    ``mutate_calldata`` is the call to F itself."""

    contract_address: str
    principal: str
    mutate_calldata: str
    probe_calldata: str
    probe_function: str
    gate_ref: str


@dataclass(frozen=True)
class PausePlanInputs:
    """§4.1 inputs. ``predicted_guard_set`` is static's set — the SCORED
    denominator; ``entry_points`` are the probes we could actually synthesize for
    it (a subset), and the observed blast radius stays a lower bound."""

    contract_address: str
    principal: str
    pause_calldata: str
    entry_points: tuple[EntryPoint, ...]
    predicted_guard_set: tuple[str, ...]
    max_pause_duration: int | None
    gate_ref: str
    fixtures: tuple[ForkFixture, ...] = ()
    # Which of the three ``DURATION_BOUND_*`` states produced
    # ``max_pause_duration``. ``None`` there is two different facts — the latch
    # cannot expire, or we could not find its window — and only this field tells
    # them apart. Defaulted to ``not_determined`` so a caller that omits it can
    # never assert the indefinite reading by accident.
    duration_bound_source: str = DURATION_BOUND_NOT_DETERMINED


@dataclass(frozen=True)
class CandidatePlanInputs:
    """Everything the prober can build for one candidate. Any field may be
    ``None`` — that class simply gets no plan."""

    value_out: ValueOutPlanInputs | None = None
    supply: SupplyPlanInputs | None = None
    authority: AuthorityPlanInputs | None = None
    pause: PausePlanInputs | None = None
    timelock: TimelockPlanInputs | None = None


# ---------------------------------------------------------------------------
# Fact loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContractFacts:
    """The static artifacts for one deployment, indexed for synthesis."""

    address: str
    job_id: Any
    # effects artifact ``functions``: full_name -> EffectInfo.
    effects: Mapping[str, Any] = field(default_factory=dict)
    # predicate_trees ``trees``: full_name -> guard tree.
    trees: Mapping[str, Any] = field(default_factory=dict)
    canonical_signatures: Mapping[str, str] = field(default_factory=dict)
    # contract_analysis semantic value_flows (the shape carrying ``is_parameter``).
    legacy_value_flows: Mapping[str, list[dict[str, Any]]] = field(default_factory=dict)
    by_selector: Mapping[str, str] = field(default_factory=dict)
    # effects artifact ``token_slots.entries`` — mapping base slots (balance,
    # allowance, shares, owner) the pause recipe seeds so a token precondition
    # cannot hide an entry point from the blast-radius diff. ABSENT on older
    # artifacts, in which case seeding is skipped and behavior is unchanged.
    token_slots: tuple[Mapping[str, Any], ...] = ()

    def canonical_signature(self, full_name: str) -> str:
        return self.canonical_signatures.get(full_name) or _abi_signature(full_name)


@dataclass(frozen=True)
class FunctionFacts:
    """One resolved function of a :class:`ContractFacts`."""

    full_name: str
    selector: str
    canonical_signature: str
    effect_info: Mapping[str, Any]
    tree: Any
    legacy_value_flows: tuple[dict[str, Any], ...]


# Per-session memo so a protocol's many candidates on one contract read the
# artifacts once. Weak on the Session so it dies with the unit of work.
_FACTS_CACHE: "WeakKeyDictionary[Session, dict[str, ContractFacts | None]]" = WeakKeyDictionary()


def load_contract_facts(session: Session, address: str) -> ContractFacts | None:
    """Load + index the static artifacts backing ``address``.

    Semantic artifacts live on the IMPLEMENTATION job for a proxy, so the lookup
    hops through ``find_analysis_job_for_address``. Returns ``None`` when there is
    no effects artifact — synthesis without sinks/param types is guesswork."""
    cache = _FACTS_CACHE.setdefault(session, {})
    key = (address or "").lower()
    if key in cache:
        return cache[key]
    facts = _load_contract_facts_uncached(session, key)
    cache[key] = facts
    return facts


def _load_contract_facts_uncached(session: Session, address: str) -> ContractFacts | None:
    from services.resolution.capability_resolver import find_analysis_job_for_address

    try:
        lookup = find_analysis_job_for_address(session, address, required_artifact="effects", completed_only=False)
    except Exception:
        logger.debug("effects calldata: analysis-job lookup failed for %s", address, exc_info=True)
        return None
    if lookup is None:
        return None
    job_id = lookup.analysis_job.id

    effects_art = get_artifact(session, job_id, "effects")
    functions = effects_art.get("functions") if isinstance(effects_art, dict) else None
    if not isinstance(functions, dict) or not functions:
        return None

    trees_art = get_artifact(session, job_id, "predicate_trees")
    trees_art = trees_art if isinstance(trees_art, dict) else {}
    raw_trees = trees_art.get("trees")
    trees: dict[str, Any] = raw_trees if isinstance(raw_trees, dict) else {}
    canonical = {
        str(name): str(sig)
        for name, sig in (trees_art.get("canonical_signatures") or {}).items()
        if isinstance(sig, str) and "(" in sig and sig.endswith(")")
    }

    analysis = get_artifact(session, job_id, "contract_analysis")
    legacy_flows = _legacy_value_flow_map(analysis)

    raw_slots = effects_art.get("token_slots") if isinstance(effects_art, dict) else None
    slot_entries = raw_slots.get("entries") if isinstance(raw_slots, dict) else None
    token_slots = tuple(e for e in slot_entries if isinstance(e, dict)) if isinstance(slot_entries, list) else ()

    by_selector: dict[str, str] = {}
    for full_name, info in functions.items():
        if not isinstance(info, dict):
            continue
        artifact_selector = info.get("selector")
        if isinstance(artifact_selector, str) and artifact_selector.startswith("0x"):
            by_selector.setdefault(artifact_selector.lower(), str(full_name))
        # The canonical selector wins: the artifact's own value is derived from the
        # Slither full_name, which is lossy for contract/enum/struct params.
        sig = canonical.get(str(full_name)) or _abi_signature(str(full_name))
        computed = _selector_of(sig)
        if computed:
            by_selector[computed] = str(full_name)

    return ContractFacts(
        address=address,
        job_id=job_id,
        effects=functions,
        trees=trees,
        canonical_signatures=canonical,
        legacy_value_flows=legacy_flows,
        by_selector=by_selector,
        token_slots=token_slots,
    )


def _legacy_value_flow_map(analysis: Any) -> dict[str, list[dict[str, Any]]]:
    """``full_name -> value_flows`` from ``contract_analysis`` — the ONLY shape
    carrying ``is_parameter`` (the effects artifact's own value_flows do not)."""
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(analysis, dict):
        return out
    semantic = analysis.get("semantic_control")
    entries = semantic.get("semantic_functions") if isinstance(semantic, dict) else None
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("function")
        flows = entry.get("value_flows")
        if isinstance(name, str) and isinstance(flows, list):
            out[name] = [f for f in flows if isinstance(f, dict)]
    return out


def facts_for_name(facts: ContractFacts, full_name: str) -> FunctionFacts | None:
    """The static facts of one function by its artifact ``full_name`` — the
    selector-free form :func:`resolve_function` needs for a candidate. ``None``
    when the artifact has no record (fail closed)."""
    info = facts.effects.get(full_name)
    if not isinstance(info, dict):
        return None
    sig = facts.canonical_signature(full_name)
    selector = _selector_of(sig)
    return FunctionFacts(
        full_name=full_name,
        selector=selector or "",
        canonical_signature=sig,
        effect_info=info,
        tree=facts.trees.get(full_name),
        legacy_value_flows=tuple(facts.legacy_value_flows.get(full_name, ())),
    )


def resolve_function(facts: ContractFacts, selector: str | None) -> FunctionFacts | None:
    """Resolve a candidate's selector to its static facts. ``None`` when the
    selector is absent or unknown to the artifact (fail closed)."""
    if not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        return None
    full_name = facts.by_selector.get(selector.lower())
    if not full_name:
        return None
    info = facts.effects.get(full_name)
    if not isinstance(info, dict):
        return None
    return FunctionFacts(
        full_name=full_name,
        selector=selector.lower(),
        canonical_signature=facts.canonical_signature(full_name),
        effect_info=info,
        tree=facts.trees.get(full_name),
        legacy_value_flows=tuple(facts.legacy_value_flows.get(full_name, ())),
    )


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def encode_calldata(
    selector: str,
    canonical_signature: str | None,
    *,
    substitutions: Mapping[int, Any] | None = None,
) -> str | None:
    """``selector ++ abi.encode(args)`` with per-index overrides.

    Argument defaults and type parsing come from ``differential_probe`` (one
    encoder for the codebase); this wrapper adds positional substitution for any
    type, which the effect probes need (an amount, a recipient, a sentinel).
    Returns ``None`` — never raises — when the signature is unparseable or a value
    does not encode, so callers fail closed."""
    if not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        return None
    types = _parse_arg_types(canonical_signature)
    if types is None:
        return None
    subs = {int(k): v for k, v in (substitutions or {}).items()}
    try:
        from eth_abi.abi import encode as abi_encode

        values = [subs[i] if i in subs else _default_value_for_type(t) for i, t in enumerate(types)]
        encoded = abi_encode(types, values).hex() if types else ""
    except Exception:
        return None
    return selector + encoded


_INTEGER_TYPE = re.compile(r"u?int\d*")
_ARRAY_TYPE = re.compile(r"^(?P<element>.+)\[(?P<size>\d*)\]$")


def _array_shape(type_str: str) -> tuple[str, int | None] | None:
    """``(element_type, fixed_length)`` for an ABI array, ``None`` for a scalar.
    ``fixed_length`` is ``None`` on a dynamic array."""
    match = _ARRAY_TYPE.match(type_str.strip())
    if match is None:
        return None
    size = match.group("size")
    return match.group("element").strip(), (int(size) if size else None)


def _element_type(type_str: str) -> str:
    """The type a substitution has to satisfy for this slot: the element type of
    an array, the type itself otherwise. A parameter's ROLE belongs to what it
    carries, not to its arity — ``uint256[] amounts`` is as much a quantity slot
    as ``uint256 amount``."""
    shape = _array_shape(type_str)
    return shape[0] if shape is not None else type_str.strip()


# Word vocabulary for the ROLE of an integer parameter. Both sets are semantic,
# not protocol-specific: a name is split into words and classified by what the
# word MEANS in ABI usage, so ``assetAmount``/``_amount``/``wad`` are quantities
# and ``tokenId``/``requestId``/``index``/``deadline`` are not, on any contract.
_AMOUNT_WORDS = frozenset(
    {"amount", "amounts", "value", "values", "qty", "quantity", "share", "shares", "wad", "fee", "fees", "assets"}
)
# Names that denote a HANDLE to something the contract stores — a token id, a
# queue position. These take the small id filler, which is also the key the
# ownership seed writes at (:func:`_seed_fixture_for_role`), so a probe and its
# seed agree on which entry they mean.
_IDENTIFIER_WORDS = frozenset({"id", "ids", "index", "indexes", "indices", "idx", "key", "position", "slot"})
# Names that are demonstrably NOT quantities but are no kind of handle either: a
# clock value, a replay counter, a version. There is no honest filler for these —
# a made-up deadline is a guess about the chain's time — so they take the
# encoder's zero and the contract's own check decides.
_NON_QUANTITY_WORDS = frozenset(
    {"deadline", "timestamp", "expiry", "expiration", "nonce", "epoch", "round", "version", "salt"}
)
# Split on separators AND camelCase humps: ``assetAmount`` → asset, amount.
_NAME_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _name_words(name: str) -> set[str]:
    return {word.lower() for word in _NAME_SPLIT.split(name or "") if word}


def _declared_param_names(fn: "FunctionFacts", count: int) -> list[str]:
    """Declared parameter names by position, best-effort.

    Two sources, both from the static plane: the effects artifact's own
    ``parameter_names`` (complete, but absent on artifacts written before it
    existed), and the predicate trees, which record ``parameter_name`` beside
    ``parameter_index`` for every parameter some gate reads. The tree fills gaps
    on an older artifact; an unnamed slot stays the empty string, which classifies
    as no evidence rather than as a guess."""
    raw = fn.effect_info.get("parameter_names")
    names = [str(n) for n in raw] if isinstance(raw, list) and len(raw) == count else [""] * count
    for name, idx in _param_index_by_name(fn.tree).items():
        if 0 <= idx < count and not names[idx]:
            names[idx] = name
    return names


def _lattice_amount_indexes(fn: "FunctionFacts", types: Sequence[str], directions: frozenset[str] | None) -> set[int]:
    """Parameter slots the static flow lattice resolved as the AMOUNT of a value
    flow — the dispositive "this argument is the quantity" fact (§4.2 mirror of
    :func:`_lattice_taint_index`). Absent on artifacts predating the field.

    ``param_derived`` counts alongside ``param``: its index is the slot of the
    caller input the contract converted into the amount (``transfer(receiver,
    convertToAssets(shares))`` — the ``shares`` slot), which is exactly the slot a
    probe must fill for the redemption to move anything. It says nothing about
    how much leaves, and nothing here reads it that way."""
    out: set[int] = set()
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if directions is not None and str(flow.get("direction")) not in directions:
            continue
        kind = flow.get("amount_kind")
        kind_name = kind.get("kind") if isinstance(kind, dict) else None
        index = flow.get("amount_param_index")
        if kind_name not in ("param", "param_derived") or not isinstance(index, int) or isinstance(index, bool):
            continue
        if 0 <= index < len(types) and _INTEGER_TYPE.fullmatch(_element_type(types[index])):
            out.add(index)
    return out


def integer_param_roles(
    fn: "FunctionFacts", types: Sequence[str], directions: frozenset[str] | None = None
) -> dict[int, str]:
    """``index -> ROLE_AMOUNT | ROLE_IDENTIFIER`` for the integer params whose role
    the static plane can actually name. An index ABSENT from the result has no
    evidence either way and takes NO substitution.

    That absence is the point. The previous policy pushed the probe amount into
    every integer slot, so a redemption's ``requestId`` and a swap's ``deadline``
    received a quantity — the seeded retry escalated that to one whole token unit
    and the call reverted on its own input before reaching any effect. A probe
    argument nobody can justify is better left at the encoder's zero: the call
    still runs, and a revert that follows is the contract's, not the prober's."""
    lattice = _lattice_amount_indexes(fn, types, directions)
    names = _declared_param_names(fn, len(types))
    roles: dict[int, str] = {}
    for idx, type_str in enumerate(types):
        if not _INTEGER_TYPE.fullmatch(_element_type(type_str)):
            continue
        words = _name_words(names[idx])
        # The two negative vocabularies are checked FIRST and beat every other
        # signal: writing a quantity into a slot that is not one is the failure
        # being fixed, so an ambiguous name fails away from the amount.
        if words & _IDENTIFIER_WORDS:
            roles[idx] = ROLE_IDENTIFIER
        elif words & _NON_QUANTITY_WORDS:
            continue
        elif idx in lattice or words & _AMOUNT_WORDS:
            roles[idx] = ROLE_AMOUNT
    return roles


# Word vocabulary for the ROLE of an ADDRESS parameter, same mechanism-first
# shape as the integer one: split the declared name into words and classify by
# what the word MEANS in ABI usage. ``asset``/``depositAsset``/``tokenIn`` name a
# contract the function dereferences; ``to``/``receiver``/``beneficiary`` name
# somewhere value lands.
_TOKEN_WORDS = frozenset({"token", "tokens", "asset", "collateral", "underlying", "currency", "erc20", "erc721", "nft"})
_RECIPIENT_WORDS = frozenset({"to", "recipient", "receiver", "beneficiary", "destination", "dst", "payee", "refund"})

# Method names, from the ERC-20/721 ABI and the two ubiquitous wrapper libraries
# over it, that only ever appear on a TOKEN. A body sink calling one of these on
# a parameter proves that parameter is a token, whatever it is named — the
# selector-keyed :data:`_PULL_SELECTORS` cannot see it, because a library wrapper
# (``SafeTransferLib.safeTransferFrom(ERC20,...)``) has a selector of its own.
_TOKEN_METHOD_WORDS = frozenset(
    {
        "transfer",
        "transferfrom",
        "safetransfer",
        "safetransferfrom",
        "approve",
        "safeapprove",
        "increaseallowance",
        "decreaseallowance",
        "balanceof",
        "allowance",
        "burn",
        "burnfrom",
        "mint",
        "permit",
    }
)


def _token_method_targets(fn: "FunctionFacts") -> set[str]:
    """Dotted-target HEADS of body sinks calling a token-only method
    (``asset.safeTransferFrom`` ⇒ ``asset``). The head is either a declared
    parameter or a state variable; the caller decides which it is looking at."""
    heads: set[str] = set()
    for sink in fn.effect_info.get("sinks") or []:
        if not isinstance(sink, dict) or sink.get("kind") != "external_call" or sink.get("origin") != "body":
            continue
        target = str(sink.get("target") or "")
        head, _, method = target.rpartition(".")
        if head and method.lower() in _TOKEN_METHOD_WORDS:
            heads.add(head)
    return heads


def address_param_roles(
    fn: "FunctionFacts", types: Sequence[str], directions: frozenset[str] | None = None
) -> dict[int, str]:
    """``index -> ROLE_RECIPIENT | ROLE_TOKEN`` for the address params whose role
    the static plane can name. An index ABSENT from the result keeps the probe's
    default (the acting principal).

    The ROLE_TOKEN half is what this exists for. The encoder used to write the
    principal into every address arg, so a deposit-shaped function received an
    EOA where it expected an ERC-20 and reverted on its own first line — the
    whole gated-deposit population landed ``unknown`` with no backing witness. A
    token slot therefore takes no principal; the seeded retry writes a REAL token
    there (:func:`substitute_address_arg`) or the slot stays at the encoder's
    default and the resulting revert is the contract's, not the prober's.

    ROLE_RECIPIENT is a veto, not a substitution change: it already gets the
    principal. It exists so a name carrying BOTH vocabularies, or a slot the
    value-flow lattice resolved as the payout destination, can never be demoted
    to a token slot and lose the identity that makes the payout observable."""
    names = _declared_param_names(fn, len(types))
    lattice_target = _lattice_taint_index(fn, types, directions) if directions is not None else None
    called_on = _token_method_targets(fn)
    roles: dict[int, str] = {}
    for idx, type_str in enumerate(types):
        if not _is_address_type(type_str.strip()):
            continue
        name = names[idx]
        words = _name_words(name)
        is_recipient = bool(words & _RECIPIENT_WORDS) or idx == lattice_target
        is_token = bool(words & _TOKEN_WORDS) or (bool(name) and name in called_on)
        # Both vocabularies on one name is no evidence at all: demoting a payout
        # destination to a token slot costs the observation the probe exists for.
        if is_recipient:
            roles[idx] = ROLE_RECIPIENT
        elif is_token:
            roles[idx] = ROLE_TOKEN
    return roles


def substitute_address_arg(calldata: str, index: int, address: str) -> str | None:
    """Rewrite top-level argument ``index`` of an encoded call to ``address``.

    An ``address`` is a static ABI type, so its head word IS its value and lives
    at a fixed offset whatever follows it — the rewrite is exact, and it is done
    here rather than by re-encoding because the identity of the token is only
    known on the wire (the seeder resolves it), while the calldata is built
    offline. Returns ``None`` when the calldata is too short for that slot or the
    address is malformed, so the caller fails closed."""
    if not isinstance(calldata, str) or not calldata.startswith("0x") or index < 0:
        return None
    body = calldata[2:]
    start = 8 + index * 64
    if len(body) < start + 64:
        return None
    raw = address[2:] if address.startswith("0x") else address
    if len(raw) != 40:
        return None
    try:
        int(raw, 16)
    except ValueError:
        return None
    return "0x" + body[:start] + raw.rjust(64, "0").lower() + body[start + 64 :]


def _arg_values(
    types: Sequence[str],
    *,
    identity: str | None,
    amount: int,
    integer_roles: Mapping[int, str] | None = None,
    executor: "ExecutorCall | None" = None,
) -> "ProbeArgs":
    """The substitution policy for a value-moving probe: address params get the
    caller identity (so a mint/transfer has a real recipient); an integer param
    takes ``amount`` only where :func:`integer_param_roles` proved it is a
    quantity, the small id filler where it proved an identifier, and the encoder's
    default where the role is unproven.

    A token slot gets the identity here too, and it is deliberate that it stays
    that way until a REAL token is known. Measured on the three etherfi
    BoringVaults (2026-07-25, mainnet fork): ``enter`` with the encoder's default
    ``address(0)`` in its ``asset`` slot SUCCEEDS — a call to a codeless address
    is a no-op success inside ``SafeTransferLib`` — and mints shares against a
    pull that never happened. That is a fabricated ``supply.mint`` with a
    fabricated "no inflow", i.e. exactly the witness this stage must never
    produce. The identity keeps the slot occupied by something the probe never
    claims is a token; the seeded retry then writes a proven one
    (:func:`substitute_address_arg`), and the recipe withholds the backing
    witness entirely when it could not.

    An ARRAY parameter is encoded at length ONE, its element carrying whatever the
    scalar policy proves for the element type. The encoder's own default for a
    dynamic array is empty, and an empty array is a loop body that never runs: the
    batch form of a function then executes, moves nothing, and publishes — and
    CACHES — "this function moves no value" about a body no probe ever entered. A
    length-1 array whose element is itself unproven is not a witness either, but
    it is an honest attempt that the contract's own check gets to reject.

    An ``executor`` (:func:`executor_call`) overrides its own two slots with the
    inner call it synthesized, and SUPPRESSES the integer roles: every remaining
    numeric argument of an arbitrary-call executor is a per-call native value, a
    gas budget or an operation mode, and the probe can prove the contract can
    satisfy none of them. Zero is both the encoder's default and the only value
    that asks the executor to forward the call and nothing else — a quantity there
    would make the vault attach ETH it does not hold and revert the very call this
    synthesis exists to observe.

    Slots the policy could NOT fill are reported as :attr:`ProbeArgs.vacuous` —
    see that class for why one predicate covers both mechanisms."""
    roles = {} if executor is not None else (integer_roles or {})
    overrides = executor.values if executor is not None else {}
    executor_slots = set(executor.slots) if executor is not None else set()
    subs: dict[int, Any] = {}
    vacuous: list[int] = []
    for idx, type_str in enumerate(types):
        shape = _array_shape(type_str)
        value = overrides.get(idx)
        if value is None:
            value = _scalar_arg_value(
                shape[0] if shape else type_str, idx, identity=identity, amount=amount, roles=roles
            )
        if value is None:
            # A slot of the forwarded call the synthesis could not build is vacuous
            # whatever its type: an executor handed empty calldata calls nothing,
            # and "called nothing, moved nothing" is not a fact about F. The
            # executor's OTHER zeros are not vacuous — they are the deliberate
            # "forward this call and nothing else" the synthesis chose.
            if idx in executor_slots:
                vacuous.append(idx)
            elif executor is None and (shape is not None or _INTEGER_TYPE.fullmatch(type_str.strip())):
                vacuous.append(idx)
        if shape is None:
            if value is not None:
                subs[idx] = value
            continue
        element, length = shape
        if value is None:
            try:
                value = _default_value_for_type(element)
            except Exception:
                # An element type the encoder can build no value for at all —
                # leaving the slot to the encoder is the only honest option.
                continue
        subs[idx] = [value] * (1 if length is None else length)
    return ProbeArgs(substitutions=subs, vacuous=tuple(vacuous))


@dataclass(frozen=True)
class ProbeArgs:
    """An encoded argument vector, plus the slots the policy could not fill.

    ``vacuous`` is ONE predicate, not two detectors that would drift apart: *an
    argument the effect depends on was left at the encoder's default*. It covers
    an integer whose role never resolved (a zero-amount call that mints nothing
    and moves nothing), an array whose element is unproven (a loop that runs over
    filler), and a forwarded-call slot with no inner call to put in it. All three
    produce the same false statement downstream — the call RAN and observed
    nothing, which reads as a structural fact about the function while being a
    fact about the arguments this prober chose.

    It is a FACT rather than a guess: the synthesizer knows the ABI types and
    which roles it resolved, so it knows exactly which slots it filled. The
    consumer's job is to keep such a non-observation out of the behaviour cache —
    a code-plane cache entry travels to bytecode twins that were never probed."""

    substitutions: dict[int, Any]
    vacuous: tuple[int, ...] = ()


def _scalar_arg_value(
    type_str: str,
    index: int,
    *,
    identity: str | None,
    amount: int,
    roles: Mapping[int, str],
) -> Any | None:
    """The value :func:`_arg_values` PROVES for one scalar slot, or ``None`` when
    it proves nothing and the encoder's own default has to stand."""
    t = type_str.strip()
    if _is_address_type(t):
        return identity.lower() if identity else None
    if _INTEGER_TYPE.fullmatch(t):
        role = roles.get(index)
        if role == ROLE_AMOUNT:
            return amount
        if role == ROLE_IDENTIFIER:
            return ARG_IDENTIFIER
    return None


# §4.2 executor synthesis. ``exec.arbitrary`` is the static claim for "this
# function forwards a caller-supplied destination together with a caller-supplied
# calldata blob", proven off the IR read set of a body call op; its witness names
# the two PARAMETERS. ``low_level_value_call`` + a ``param`` destination is the
# flow lattice making the first half of the same statement.
_EXEC_ARBITRARY_CLAIM = "exec.arbitrary"
_LOW_LEVEL_CALL_KIND = "low_level_value_call"
# transfer(address,uint256) — the ERC-20 standard, not a name guess.
_ERC20_TRANSFER_SELECTOR = "0xa9059cbb"


@dataclass(frozen=True)
class ExecutorCall:
    """An inner call synthesized for an arbitrary-call executor.

    ``slots`` is ``(destination_index, calldata_index)`` — the two parameters
    static proved carry the forwarded call. ``values`` holds the scalar value for
    each of those slots, and is EMPTY when the acting deployment holds no asset to
    build an inner call from: the shape is still known (so the encoder can say the
    payload slot was left at its default), but nothing is claimed about it."""

    slots: tuple[int, int]
    values: Mapping[int, Any] = field(default_factory=dict)


def _forwards_param_destination(fn: "FunctionFacts") -> bool:
    """Does the flow lattice say a low-level call in F's body sends to a
    destination the CALLER named? The index need not have resolved — a loop over
    an array of targets leaves the slot unnamed while still proving the kind."""
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("kind")) != _LOW_LEVEL_CALL_KIND:
            continue
        kind = flow.get("target_kind")
        if isinstance(kind, dict) and kind.get("kind") == "param":
            return True
    return False


def _named_executor_slots(fn: "FunctionFacts", types: Sequence[str]) -> tuple[int, int] | None:
    """The two slots the ``exec.arbitrary`` witness PROVES, when both name a
    parameter of the right shape.

    A name counts only when its ``*_kind`` is ``param`` — i.e. the IR put that
    parameter in the call's destination / calldata operand position. The other
    kinds publish no name, and a witness written before those kinds existed
    carries a name with no kind at all: that is an unread question, not a proof,
    so it falls through to the ABI-uniqueness reasoning below exactly as a
    ``not_determined`` would."""
    names = _declared_param_names(fn, len(types))
    for claim in fn.effect_info.get("claims") or []:
        if not isinstance(claim, dict) or claim.get("claim_id") != _EXEC_ARBITRARY_CLAIM:
            continue
        witness = claim.get("witness")
        if not isinstance(witness, dict):
            continue
        if witness.get("destination_kind") != "param" or witness.get("calldata_kind") != "param":
            continue
        destination, payload = witness.get("destination_param"), witness.get("calldata_param")
        if not isinstance(destination, str) or not isinstance(payload, str) or not destination or not payload:
            continue
        try:
            dest_idx, data_idx = names.index(destination), names.index(payload)
        except ValueError:
            continue
        if _executor_slot_shapes_agree(types, dest_idx, data_idx):
            return dest_idx, data_idx
    return None


def _executor_slot_shapes_agree(types: Sequence[str], destination: int, payload: int) -> bool:
    """A destination and a payload describe ONE forwarded call only if they have
    the same arity: two scalars, or two arrays walked in step."""
    dest_shape, data_shape = _array_shape(types[destination]), _array_shape(types[payload])
    if (dest_shape is None) != (data_shape is None):
        return False
    return _is_address_type(_element_type(types[destination])) and _element_type(types[payload]) == "bytes"


def _unique_executor_slots(types: Sequence[str]) -> tuple[int, int] | None:
    """The only destination/payload pair the ABI admits, or ``None``.

    Read alone this proves nothing — it is used only where static has ALREADY
    proven the function forwards a caller-named destination, to say WHICH slots
    carry it. Ambiguity yields nothing rather than a positional guess: an executor
    whose destination the probe picked wrong simply reverts, but one whose payload
    slot the probe picked wrong could write a transfer into an argument that is
    not calldata at all."""
    scalar_dest = [i for i, t in enumerate(types) if _is_address_type(t)]
    scalar_data = [i for i, t in enumerate(types) if t.strip() == "bytes"]
    array_dest = [i for i, t in enumerate(types) if t.strip() == "address[]"]
    array_data = [i for i, t in enumerate(types) if t.strip() == "bytes[]"]
    if len(scalar_dest) == 1 and len(scalar_data) == 1 and not array_dest and not array_data:
        return scalar_dest[0], scalar_data[0]
    if len(array_dest) == 1 and len(array_data) == 1 and not scalar_dest and not scalar_data:
        return array_dest[0], array_data[0]
    return None


def executor_call(
    fn: "FunctionFacts", types: Sequence[str], *, held_tokens: Sequence[str], recipient: str
) -> ExecutorCall | None:
    """The inner call to synthesize for an arbitrary-call executor, or ``None``
    when F is not one.

    An executor forwards caller-supplied calldata to a caller-supplied target, so
    the encoder's default leaves it calling nothing with nothing: the probe
    executes, moves no value, and that non-observation gets published — and cached
    — about a function that is by construction able to move everything the
    contract holds. What it takes to observe the real behaviour is one honest
    inner call, and the only honest one is an ERC-20 transfer of an asset the
    acting deployment PROVABLY holds (``contract_balances``, richest first). The
    asset never comes from a list of known tokens: on the next protocol that list
    is empty and the probe would be back to sending nothing.

    Soundness is the argument the stage already makes for token-arg substitution:
    a probe input is a CANDIDATE, not a claim. Writing an address and a payload
    into calldata witnesses nothing by itself — the witness is the ``Transfer``
    the execution actually emitted, and if F does not forward the payload the call
    simply reverts."""
    slots = _named_executor_slots(fn, types)
    if slots is None:
        slots = _unique_executor_slots(types) if _forwards_param_destination(fn) else None
    if slots is None:
        return None
    destination, payload = slots
    token = next((t for t in held_tokens if isinstance(t, str) and _RESOLVED_ADDRESS.match(t)), None)
    inner = _erc20_transfer_calldata(recipient, ARG_AMOUNT)
    if token is None or inner is None:
        return ExecutorCall(slots=slots)
    return ExecutorCall(slots=slots, values={destination: token.lower(), payload: inner})


def _erc20_transfer_calldata(recipient: str, amount: int) -> bytes | None:
    """``transfer(recipient, amount)``, or ``None`` on an unencodable recipient."""
    try:
        from eth_abi.abi import encode as abi_encode

        return bytes.fromhex(_ERC20_TRANSFER_SELECTOR[2:]) + abi_encode(["address", "uint256"], [recipient, amount])
    except Exception:
        return None


# Flow kinds that move NATIVE ETH out of the contract's OWN balance (as opposed
# to an ERC-20 selector call, which moves a token the contract holds). A function
# with one of these is the only shape a contract-balance seed could unblock.
_NATIVE_OUT_KINDS = frozenset({"native_transfer_send", "low_level_value_call"})


def has_native_payout(fn: "FunctionFacts") -> bool:
    """Does static say F sends native ETH out of the contract's own balance?

    Gates the contract-balance seeding attempt, which is the most synthetic
    override the stage makes: without this the attempt would fire on every
    reverting probe and buy nothing on the ones whose revert has no funding
    cause."""
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("direction")) in _OUT_DIRECTIONS and str(flow.get("kind")) in _NATIVE_OUT_KINDS:
            return True
    return False


# Destination kinds that PROVE a fixed destination: the value is baked into the
# code, or lives in storage the static plane completed a setter scan over and
# found nothing that could repoint it.
_FIXED_TARGET_KINDS = frozenset({"immutable", "constant", "storage_no_setter"})
# Redirectable, but only by whoever holds the setter — an admin fact, not a
# caller one.
_ADMIN_TARGET_KIND = "storage_setter"


def _target_member_kinds(flow: Mapping[str, Any]) -> list[str]:
    """The destination kinds one flow asserts. ``several`` expands to its members
    — the fold names them precisely so a consumer can take the worst — and any
    flow whose kind cannot be read yields ``[""]``, which no rule below accepts."""
    kind = flow.get("target_kind")
    name = kind.get("kind") if isinstance(kind, dict) else None
    if name != "several":
        return [name if isinstance(name, str) else ""]
    entries = flow.get("target_kinds") or []
    members = [k.get("kind") if isinstance(k, dict) else None for k in entries]
    # An entry we cannot read contributes ``""``, which no rule accepts, rather
    # than being dropped. Silently skipping it would let a partly-unreadable
    # disjunction be judged on the members that happened to parse — the one place
    # in this predicate that could fail OPEN.
    return [str(m) if isinstance(m, str) else "" for m in members] or [""]


def static_destination_shape(fn: "FunctionFacts", directions: frozenset[str]) -> str | None:
    """The §4.2 destination shape static PROVES for F, or ``None``.

    A universal, and it has to be earned across EVERY out-flow the function has:
    one site paying a caller-named address makes the function caller-redirectable
    no matter how fixed its other sites are. So the rule is a conjunction —
    every flow fixed ⇒ ``immutable_fixed``; every flow fixed-or-admin-settable
    with at least one admin ⇒ ``storage_determined``; anything else ⇒ no claim,
    and the sentinel is left to decide.

    Returning ``None`` is not a failure mode, it is the common case: ``param``,
    ``msg_sender``, ``self``, ``token_owner`` and ``indeterminate`` all yield it.
    Over-claiming here is the dangerous direction — calling an attacker-
    redirectable destination fixed is a false reassurance about the exact bit
    this stage exists to establish — so the predicate never generalizes from a
    subset of the sites.

    A landed sentinel still outranks this (see ``_resolve_destination_shape``):
    an EXISTENTIAL proof that the caller can redirect the funds beats a universal
    argued from the source, which is the correct precedence when they conflict."""
    # ROUTED flows count toward the conjunction even though the probe does not
    # measure them. The claim being made is "this function cannot send funds to a
    # destination the caller names", and a routed payout does exactly that — the
    # money leaves a contract this entry calls, at an address the caller chose.
    # Quantifying only over ``out``/``eth_out`` let a router publish
    # ``immutable_fixed`` off a fee transfer to a treasury while forwarding the
    # principal to ``vault.exit(to, …)``. The sentinel cannot catch it either: it
    # reads transfers out of THIS contract, and a routed payout is emitted by the
    # callee.
    considered = set(directions) | {"value_router"}
    kinds: list[str] = []
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("direction")) not in considered:
            continue
        kinds.extend(_target_member_kinds(flow))
    if not kinds:
        return None
    if all(k in _FIXED_TARGET_KINDS for k in kinds):
        return SHAPE_IMMUTABLE_FIXED
    if all(k in _FIXED_TARGET_KINDS or k == _ADMIN_TARGET_KIND for k in kinds):
        return SHAPE_STORAGE_DETERMINED
    return None


def function_payable(fn: "FunctionFacts") -> bool | None:
    """ABI payability of F, or ``None`` when the artifact predates the fact.
    Tri-state on purpose: only a recorded ``False`` may suppress a probe attempt —
    an absent fact leaves the attempt exactly as it is today."""
    value = fn.effect_info.get("payable")
    return value if isinstance(value, bool) else None


def _selector_of(signature: str) -> str | None:
    """The 4-byte selector, or ``None`` when ``signature`` is not a fully lowered
    ABI signature. A residual user-defined type name means the hash is not a
    dispatch value, and a probe keyed on it would call the wrong function."""
    from services.static.contract_analysis_pipeline.predicate_artifacts import is_canonical_abi_signature

    if not signature or not is_canonical_abi_signature(signature):
        return None
    return "0x" + keccak(text=signature)[:4].hex()


# ---------------------------------------------------------------------------
# Predicate-tree walking (mirrors ``claims.matchers._facts._mandatory_operands``)
# ---------------------------------------------------------------------------


def _mandatory_leaves(tree: Any) -> Iterator[dict[str, Any]]:
    """Leaves reachable with every ancestor a conjunction — the operand's value
    can force a revert with no ``OR`` escape. Same separator the claims plane uses
    to distinguish a real gate from a branch-mode selector."""

    def walk(node: Any, mandatory: bool) -> Iterator[dict[str, Any]]:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf")
            if mandatory and isinstance(leaf, dict):
                yield leaf
            return
        child_mandatory = mandatory and node.get("op") != "OR"
        for child in node.get("children") or []:
            yield from walk(child, child_mandatory)

    yield from walk(tree, True)


def _all_leaves(tree: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _all_leaves(child)


def _operands(leaf: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [op for op in (leaf.get("operands") or []) if isinstance(op, dict)]


def _mandatory_state_pairs(tree: Any) -> set[tuple[str, str | None]]:
    out: set[tuple[str, str | None]] = set()
    for leaf in _mandatory_leaves(tree):
        for op in _operands(leaf):
            name = op.get("state_variable_name")
            if not name:
                continue
            member_path = op.get("member_path") or []
            out.add((str(name), str(member_path[0]) if member_path else None))
    return out


def guarded_functions(trees: Mapping[str, Any], pairs: Iterable[tuple[str, str | None]]) -> list[str]:
    """Every function whose MANDATORY gate reads one of ``pairs`` — static's
    predicted guard set (the §4.1 scored denominator).

    Matching is on the state-variable NAME; ``member_path`` is a refinement that
    is NOT required to agree. It cannot be: an ERC-7201 latch is recorded as a
    write to the slot var with an EMPTY member path (``PAUSABLE_STORAGE_SLOT``)
    while the read operand carries ``member_path=["paused"]``, so a strict pair
    match returns an empty guard set for every namespaced-storage pause. Var-level
    matching over-includes at worst, which only widens the probe set — the
    observed radius stays a lower bound and the scored denominator is unchanged.
    """
    wanted_vars = {var for var, _member in pairs}
    if not wanted_vars:
        return []
    return sorted(name for name, tree in trees.items() if _mandatory_state_vars(tree) & wanted_vars)


def _mandatory_state_vars(tree: Any) -> set[str]:
    return {var for var, _member in _mandatory_state_pairs(tree)}


def _param_index_by_name(tree: Any) -> dict[str, int]:
    """``param name -> positional index`` recovered from predicate-tree leaf
    operands (the only place the static plane records both). Absent ⇒ the caller
    fails closed rather than guessing a slot."""
    out: dict[str, int] = {}
    for leaf in _all_leaves(tree):
        for op in _operands(leaf):
            name = op.get("parameter_name")
            idx = op.get("parameter_index")
            if isinstance(name, str) and isinstance(idx, int) and idx >= 0:
                out.setdefault(name.lower(), idx)
    return out


def _authority_roles(tree: Any) -> set[str]:
    return {
        str(leaf.get("authority_role")) for leaf in _all_leaves(tree) if isinstance(leaf.get("authority_role"), str)
    }


def _gate_ref(tree: Any) -> str:
    """A gate STRUCTURE descriptor (inv. 12) — authority roles, never an address.

    ``gate:none`` is emitted for a tree-less function, which covers BOTH a
    proven-ungated one and one whose real gate the static plane could not lower
    (``guard_extraction_uncertain`` and the rest of the tree-less residue) — so
    it is not on its own a claim that no gate exists. It never has to be: the
    other half of the cache identity is the kernel ``behavior_hash``, which is
    the whole metadata-stripped runtime bytecode (§7 item 2, immutables masked).
    The gate lives inside that bytecode, so two rows can share a ``gate:none``
    only when their code — and therefore their gate — is identical, and masking
    an immutable authority erases the ADDRESS a gate compares against, never the
    comparison. ``tests/test_effects_hashing.py`` pins that.

    The consumers of an absent role (the §4.4 gate-moving pick, the §4.1 pauser
    probe) each fail closed to a probe that is not synthesized, so a gate that
    did not lower costs recall, never a widened verdict.
    """
    roles = sorted(_authority_roles(tree))
    return "gate:" + ("+".join(roles) if roles else "none")


# ---------------------------------------------------------------------------
# §4.2 value-out / §4.5 supply
# ---------------------------------------------------------------------------

_OUT_DIRECTIONS = frozenset({"out", "eth_out"})
_SUPPLY_DIRECTIONS = frozenset({"mint", "burn"})
# Directions the SUPPLY plan reads its lattice facts through, which are not the
# directions that make the class applicable. ``mint``/``burn`` is a legacy
# ``semantic_control`` vocabulary the effects artifact never emits as a flow
# DIRECTION — measured over the 80 frozen artifacts, every non-guard flow is
# ``out`` (97), ``value_router`` (38) or ``in`` (33), and none is mint/burn — so
# filtering the lattice by it rejected every flow and left the whole class with no
# amount index, no taint index and no lattice recipient, running on the name
# vocabulary alone. A mint/burn function's own value movement is recorded by the
# lattice as the inbound pull it takes (``in``) or the outbound payout it makes
# (``out``); that is where its quantity and its recipient live. Applicability is
# still decided by :data:`_SUPPLY_DIRECTIONS`, which is read off ``effect_labels``
# — those DO carry mint/burn.
_SUPPLY_LATTICE_DIRECTIONS = frozenset({"in", "out"})


def _flow_directions(fn: FunctionFacts) -> set[str]:
    dirs = {str(f.get("direction")) for f in fn.legacy_value_flows if f.get("direction")}
    for flow in fn.effect_info.get("value_flows") or []:
        if isinstance(flow, dict) and flow.get("origin") != "guard" and flow.get("direction"):
            dirs.add(str(flow["direction"]))
    return dirs


def _lattice_taint_index(fn: FunctionFacts, types: Sequence[str], directions: frozenset[str]) -> int | None:
    """The recipient slot the static flow lattice resolved for a value-out flow.

    The lattice emits ``target_param_index`` only for a destination that IS one
    whole entry parameter (``target_kind == "param"``, agreed by every
    contributing site) — which is what a sentinel needs, and what the name-based
    path below cannot reach for a payout recipient that no gate mentions. Flows
    disagreeing on the slot yield nothing rather than a picked winner."""
    found: set[int] = set()
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("direction")) not in directions:
            continue
        index = flow.get("target_param_index")
        kind = flow.get("target_kind")
        kind_name = kind.get("kind") if isinstance(kind, dict) else None
        if kind_name != "param" or not isinstance(index, int) or isinstance(index, bool):
            continue
        found.add(index)
    if len(found) != 1:
        return None
    index = next(iter(found))
    return index if 0 <= index < len(types) and _is_address_type(types[index]) else None


def _taint_index(fn: FunctionFacts, types: Sequence[str], directions: frozenset[str]) -> int | None:
    """Positional index of the address param the value-flow taint says the caller
    controls. ``None`` (⇒ no sentinel probe) when the taint is absent, the param
    name cannot be mapped to a slot, or that slot is not address-typed."""
    lattice_index = _lattice_taint_index(fn, types, directions)
    if lattice_index is not None:
        return lattice_index
    names = [
        str(f.get("token_var"))
        for f in fn.legacy_value_flows
        if f.get("is_parameter") and str(f.get("direction")) in directions and f.get("token_var")
    ]
    if not names:
        return None
    index_by_name = _param_index_by_name(fn.tree)
    for name in names:
        idx = index_by_name.get(name.lower())
        if idx is not None and 0 <= idx < len(types) and _is_address_type(types[idx]):
            return idx
    return None


@dataclass(frozen=True)
class _ProbeInputs:
    """What §4.2 and §4.5 both need out of one synthesis pass."""

    calldata: str
    taint_param_reaches_sink: bool
    sentinel_calldata: str | None
    token_param_indexes: tuple[int, ...]
    inputs_vacuous: bool


def _value_probe_inputs(
    fn: FunctionFacts, principal: str, directions: frozenset[str], held_tokens: Sequence[str] = ()
) -> _ProbeInputs | None:
    """The probe inputs shared by §4.2 and §4.5."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return None
    roles = integer_param_roles(fn, types, directions)
    addr_roles = address_param_roles(fn, types, directions)
    executor = executor_call(fn, types, held_tokens=held_tokens, recipient=principal)
    base = _arg_values(types, identity=principal, amount=ARG_AMOUNT, integer_roles=roles, executor=executor)
    calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=base.substitutions)
    if calldata is None:
        return None
    taint_idx = _taint_index(fn, types, directions)
    sentinel_calldata = None
    if executor is not None and executor.values:
        # The executor owns its own sentinel variant, and it supersedes the taint
        # slot: what the caller redirects here is the DESTINATION INSIDE the
        # payload, so the sentinel has to be written there. A sentinel in the
        # target slot would only prove the executor can call the sentinel, which
        # is not the same claim as the funds landing on it.
        sentinel_exec = executor_call(fn, types, held_tokens=held_tokens, recipient=SENTINEL_ADDRESS)
        if sentinel_exec is not None and sentinel_exec.values:
            sentinel_subs = _arg_values(
                types, identity=principal, amount=ARG_AMOUNT, integer_roles=roles, executor=sentinel_exec
            ).substitutions
            sentinel_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=sentinel_subs)
    elif taint_idx is not None:
        sentinel_subs = dict(base.substitutions)
        sentinel_subs[taint_idx] = SENTINEL_ADDRESS
        sentinel_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=sentinel_subs)
    tokens = tuple(sorted(idx for idx, role in addr_roles.items() if role == ROLE_TOKEN))
    return _ProbeInputs(
        calldata=calldata,
        taint_param_reaches_sink=taint_idx is not None,
        sentinel_calldata=sentinel_calldata,
        token_param_indexes=tokens,
        inputs_vacuous=bool(base.vacuous),
    )


def synthesize_value_out(candidate: Candidate, fn: FunctionFacts) -> ValueOutPlanInputs | None:
    """§4.2. Applicable when static says the function moves value OUT. A gated
    function needs a resolved principal — a probe from the zero address only ever
    proves that the gate rejected it — but a PUBLIC function has no principal to
    resolve, so it is probed from :data:`NEUTRAL_CALLER`, an arbitrary non-zero
    identity that is a valid, productive probe of a permissionless mover."""
    if not _flow_directions(fn) & _OUT_DIRECTIONS:
        return None
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        if not candidate.authority_public:
            return None
        principal = NEUTRAL_CALLER
    built = _value_probe_inputs(fn, principal, frozenset(_OUT_DIRECTIONS), candidate.input_token_addresses)
    if built is None:
        return None
    calldata, sentinel_calldata = built.calldata, built.sentinel_calldata
    token_params = built.token_param_indexes
    seeded, seeded_sentinel = _seeded_probe_calldata(
        fn, principal, frozenset(_OUT_DIRECTIONS), candidate.input_token_addresses
    )
    return ValueOutPlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        calldata=calldata,
        gate_ref=_gate_ref(fn.tree),
        taint_param_reaches_sink=built.taint_param_reaches_sink,
        sentinel_address=SENTINEL_ADDRESS if sentinel_calldata else None,
        sentinel_calldata=sentinel_calldata,
        value_holders=candidate.value_holders,
        acting_balance_usd=candidate.acting_balance_usd,
        protocol_tvl_usd=candidate.protocol_tvl_usd,
        input_token_hints=input_token_hints(fn, token_addresses=_token_arg_candidates(candidate, token_params)),
        token_param_indexes=token_params,
        seeded_calldata=seeded,
        seeded_sentinel_calldata=seeded_sentinel if sentinel_calldata else {},
        target_payable=function_payable(fn),
        native_payout=has_native_payout(fn),
        static_shape=static_destination_shape(fn, frozenset(_OUT_DIRECTIONS)),
        inputs_vacuous=built.inputs_vacuous,
        # Measured holdings only (§0.0.2) — the seed derives its token from what
        # the deployment provably holds, never a hardcoded asset.
        contract_holdings=tuple(candidate.input_token_addresses),
    )


def synthesize_supply(candidate: Candidate, fn: FunctionFacts) -> SupplyPlanInputs | None:
    """§4.5. Applicable when static says the function mints or burns."""
    labels = {str(lbl) for lbl in (fn.effect_info.get("effect_labels") or [])}
    if not (_flow_directions(fn) & _SUPPLY_DIRECTIONS or labels & _SUPPLY_DIRECTIONS):
        return None
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        if not candidate.authority_public:
            return None
        principal = NEUTRAL_CALLER
    built = _value_probe_inputs(fn, principal, _SUPPLY_LATTICE_DIRECTIONS, candidate.input_token_addresses)
    if built is None:
        return None
    calldata, sentinel_calldata = built.calldata, built.sentinel_calldata
    token_params = built.token_param_indexes
    seeded, seeded_sentinel = _seeded_probe_calldata(
        fn, principal, _SUPPLY_LATTICE_DIRECTIONS, candidate.input_token_addresses
    )
    return SupplyPlanInputs(
        # The candidate's own probe target. A candidate that is not an ERC-20
        # simply fails the pre-read and lands ``unknown`` — that is the honest
        # answer, not an error to engineer around.
        token_address=candidate.probe_target,
        principal=principal,
        mint_calldata=calldata,
        gate_ref=_gate_ref(fn.tree),
        taint_param_reaches_sink=built.taint_param_reaches_sink,
        sentinel_address=SENTINEL_ADDRESS if sentinel_calldata else None,
        sentinel_calldata=sentinel_calldata,
        input_token_hints=input_token_hints(fn, token_addresses=_token_arg_candidates(candidate, token_params)),
        token_param_indexes=token_params,
        seeded_calldata=seeded,
        seeded_sentinel_calldata=seeded_sentinel if sentinel_calldata else {},
        target_payable=function_payable(fn),
        native_payout=has_native_payout(fn),
        inputs_vacuous=built.inputs_vacuous,
        contract_holdings=tuple(candidate.input_token_addresses),
    )


# The zero-arg getter for a delayed executor's own minimum delay. A canonical
# signature, not a name guess, and the value is READ rather than assumed: OZ
# rejects a schedule below it, and it is per-deployment (measured 432000s and
# 864000s on the two mainnet timelocks this corpus carries).
_MIN_DELAY_SIGNATURE = "getMinDelay()"
# ERC-20 balanceOf(address) — the published standard, used to read the witness.
_ERC20_BALANCE_OF_SIGNATURE = "balanceOf(address)"


def _schedule_sibling(facts: ContractFacts, fn: FunctionFacts, types: Sequence[str]) -> tuple[str, str] | None:
    """``(selector, signature)`` of the function that SCHEDULES what ``fn``
    executes, or ``None``.

    Found by ABI shape rather than by name: the scheduling half of a delayed
    executor takes the executed tuple plus a trailing ``uint256`` delay. Both
    arities fall out of the same rule, and a contract exposing two such siblings
    yields nothing rather than a pick."""
    wanted = [t.strip() for t in types] + ["uint256"]
    found: list[tuple[str, str]] = []
    for name in facts.effects:
        signature = facts.canonical_signature(name)
        if signature == fn.canonical_signature:
            continue
        candidate_types = _parse_arg_types(signature)
        if candidate_types is None or [t.strip() for t in candidate_types] != wanted:
            continue
        selector = _selector_of(signature)
        if selector is not None:
            found.append((selector, signature))
    return found[0] if len(found) == 1 else None


def _dual_role_principal(session: Session, candidate: Candidate, schedule_selector: str) -> str | None:
    """The address that can drive BOTH halves of the sequence.

    Scheduling and executing are separately gated (OZ's ``PROPOSER_ROLE`` and
    ``EXECUTOR_ROLE``), so the probe needs a principal the resolution plane put
    behind both. Preferring the intersection is what keeps this honest: the
    alternative — writing the role into storage so the gate passes — is exactly
    what §9.3 forbids, because such a probe reverts on the gate, not on a missing
    asset. When the two do not intersect we still probe as the executor and let
    the contract reject the schedule, which the recipe records verbatim."""
    principals = [p.lower() for p in candidate.principal_addresses if isinstance(p, str) and p]
    scheduler = _principals_by_selector(session, candidate.contract_id).get(schedule_selector.lower())
    if scheduler and scheduler.lower() in principals:
        return scheduler.lower()
    return principals[0] if principals else None


def _probe_salt(candidate: Candidate) -> bytes:
    """A deterministic per-(function, contract) operation salt, derived exactly as
    the differential probe derives its identities so a replay reuses it. Its only
    job is to keep the probe's operation distinct from one the timelock already
    has pending — a collision would revert the schedule for a reason that has
    nothing to do with the capability under test."""
    return keccak(text=f"timelock-probe:{candidate.selector or ''}:{candidate.contract_address}")


def synthesize_timelock(
    session: Session, candidate: Candidate, facts: ContractFacts, fn: FunctionFacts
) -> TimelockPlanInputs | None:
    """§9.5. Applicable when F is a proven arbitrary-call executor whose contract
    also exposes the scheduling half and its own minimum delay.

    The operation scheduled is an ERC-20 transfer to the sentinel of an asset the
    timelock PROVABLY holds. Where it holds nothing — the normal case, since a
    timelock holds authority rather than funds — the operation is a bare call to
    the sentinel: still an operation the proposer chose, which proves the delayed
    execution path runs, while the value question is answered honestly by the
    recipe as "there was no asset to witness" rather than as "moved nothing"."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return None
    executor = executor_call(fn, types, held_tokens=candidate.input_token_addresses, recipient=SENTINEL_ADDRESS)
    if executor is None:
        return None
    sibling = _schedule_sibling(facts, fn, types)
    if sibling is None:
        return None
    schedule_selector, schedule_signature = sibling
    if _MIN_DELAY_SIGNATURE not in facts.effects:
        return None
    delay_calldata = encode_calldata(_selector_of(_MIN_DELAY_SIGNATURE) or "", _MIN_DELAY_SIGNATURE)
    if delay_calldata is None:
        return None
    principal = _dual_role_principal(session, candidate, schedule_selector)
    if not principal:
        # A probe from an address behind neither role only ever proves the gate
        # rejected it — the same rule the value-out plan applies.
        return None

    destination, payload = executor.slots
    witness_token = executor.values.get(destination)
    target = witness_token if witness_token is not None else SENTINEL_ADDRESS
    inner = executor.values.get(payload, b"")
    salt_index = max((i for i, t in enumerate(types) if t.strip() == "bytes32"), default=-1)
    arguments: dict[int, Any] = {}
    for idx, type_str in enumerate(types):
        shape = _array_shape(type_str)
        if idx == destination:
            value: Any = target
        elif idx == payload:
            value = inner
        elif idx == salt_index:
            value = _probe_salt(candidate)
        else:
            # Everything else takes the encoder's own zero: the per-call native
            # value the timelock does not hold, and the predecessor that OZ reads
            # as "this operation depends on nothing".
            try:
                value = _default_value_for_type(shape[0] if shape else type_str)
            except Exception:
                return None
        arguments[idx] = [value] if shape else value

    execute_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=arguments)
    schedule_zero = encode_calldata(schedule_selector, schedule_signature, substitutions={**arguments, len(types): 0})
    if execute_calldata is None or schedule_zero is None:
        return None
    witness_calldata = (
        encode_calldata(
            _selector_of(_ERC20_BALANCE_OF_SIGNATURE) or "",
            _ERC20_BALANCE_OF_SIGNATURE,
            substitutions={0: SENTINEL_ADDRESS},
        )
        if witness_token is not None
        else None
    )
    return TimelockPlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        execute_calldata=execute_calldata,
        schedule_selector=schedule_selector,
        schedule_signature=schedule_signature,
        schedule_arguments=arguments,
        delay_index=len(types),
        schedule_calldata_zero=schedule_zero,
        delay_calldata=delay_calldata,
        gate_ref=_gate_ref(fn.tree),
        sentinel_address=SENTINEL_ADDRESS,
        witness_token=witness_token if isinstance(witness_token, str) else None,
        witness_calldata=witness_calldata,
        # Gas only: an impersonated proposer that cannot pay would revert the
        # schedule for a reason that is the harness's, not the contract's.
        fixtures=(ForkFixture(kind="set_balance", address=principal, value=hex(FIXTURE_BALANCE_WEI)),),
    )


def _token_arg_candidates(candidate: Candidate, token_params: Sequence[int]) -> tuple[str, ...]:
    """Assets the acting deployment PROVABLY holds, offered only to a function
    that actually has a token parameter.

    They exist because a caller-supplied token slot has no getter behind it: the
    identity has to come from somewhere, and the only honest "somewhere" is real
    on-chain state. ``contract_balances`` is a measurement of this deployment at
    this block, ordered by USD, and :func:`selection.select_candidates` keeps only
    the PRICED entries — an unpriced holding is usually an airdropped spam token,
    and a mint witnessed against one would read as backed while being worthless.

    A candidate that the function does not accept can only make the call revert.
    It can never invent a witness: backing is counted from Transfers the
    execution EMITTED, and writing an address into calldata emits nothing."""
    return tuple(candidate.input_token_addresses) if token_params else ()


def _seeded_probe_calldata(
    fn: FunctionFacts, principal: str, directions: frozenset[str], held_tokens: Sequence[str] = ()
) -> tuple[dict[int, str], dict[int, str]]:
    """``(base, sentinel)`` whole-unit calldata for the seeded retry, keyed by
    token decimals. Empty dicts when the signature will not encode — the probe
    then simply never retries."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return {}, {}
    executor = executor_call(fn, types, held_tokens=held_tokens, recipient=principal)
    base = seeded_calldata(fn, principal, directions=directions, executor=executor)
    if executor is not None and executor.values:
        # The retry has to keep the synthesized inner call. Falling back to the
        # plain vector here would re-send the empty payload whenever the first
        # probe reverted, and the verdict is read off whichever call executed.
        sentinel_exec = executor_call(fn, types, held_tokens=held_tokens, recipient=SENTINEL_ADDRESS)
        return base, seeded_calldata(fn, principal, directions=directions, executor=sentinel_exec)
    taint_idx = _taint_index(fn, types, directions)
    sentinel = (
        seeded_calldata(fn, principal, sentinel_index=taint_idx, directions=directions) if taint_idx is not None else {}
    )
    return base, sentinel


# ---------------------------------------------------------------------------
# §4.4 authority-change
# ---------------------------------------------------------------------------


def _normal_state_pairs(fn: FunctionFacts) -> set[tuple[str, str | None]]:
    """``(var, member)`` pairs F writes, restricted to the hygiene class the
    role-fact consumers trust (a reentrancy latch or a constant is not an effect)
    and to body-origin writes.

    Same reason as :func:`_latch_pairs`: a guard-origin entry is the modifier's
    own bookkeeping read on F's gate, not an effect F causes, so it must not be
    taken as "the state F mutates" when picking a gate target. Narrower surface
    than the pause case — ``hygiene_class`` already excludes ``reentrancy_guard``
    — and measured impact on the etherfi candidate set was zero (10 candidates
    carry a guard-origin ``normal`` write; none of them selected a different gate
    target). Kept anyway: an unsound input path that today's data happens not to
    trip is how a wrong verdict reaches a protocol nobody sampled."""
    pairs: set[tuple[str, str | None]] = set()
    for write in fn.effect_info.get("state_writes") or []:
        if not isinstance(write, dict) or write.get("hygiene_class") != "normal":
            continue
        if write.get("origin") != "body":
            continue
        var = write.get("var")
        if not var:
            continue
        member_path = write.get("member_path") or []
        pairs.add((str(var), str(member_path[0]) if member_path else None))
    return pairs


def _authority_gate_target(facts: ContractFacts, fn: FunctionFacts) -> str | None:
    """A function G whose MANDATORY, caller-authority gate reads state that F
    writes — i.e. the gate F can move. Deterministic (sorted) pick; ``None`` when
    no such G exists."""
    written = _normal_state_pairs(fn)
    if not written:
        return None
    for name in sorted(facts.trees):
        if name == fn.full_name:
            continue
        tree = facts.trees[name]
        if not _authority_roles(tree) & set(_AUTHORITY_ROLES):
            continue
        # Var-level, for the same member-path reason as ``guarded_functions``.
        if _mandatory_state_vars(tree) & {var for var, _member in written}:
            return name
    return None


def synthesize_authority(candidate: Candidate, facts: ContractFacts, fn: FunctionFacts) -> AuthorityPlanInputs | None:
    """§4.4. Applicable when F writes state that some other function reads as a
    mandatory caller-authority gate. The mutation keeps encoder defaults — we do
    not guess a grantee; the recipe only opens on a gate that opens to ALL the
    random identities, so a guessed one could never help."""
    target = _authority_gate_target(facts, fn)
    if target is None:
        return None
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        return None
    probe_sig = facts.canonical_signature(target)
    probe_selector = _selector_of(probe_sig)
    if not probe_selector:
        return None
    mutate = encode_calldata(fn.selector, fn.canonical_signature)
    probe = encode_calldata(probe_selector, probe_sig)
    if mutate is None or probe is None:
        return None
    return AuthorityPlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        mutate_calldata=mutate,
        probe_calldata=probe,
        probe_function=target,
        gate_ref=_gate_ref(fn.tree),
    )


# ---------------------------------------------------------------------------
# §4.1 pause (Tier 2)
# ---------------------------------------------------------------------------


def _claim_latch_pairs(session: Session, function_id: int) -> set[tuple[str, str | None]]:
    """Latch ``(var, member)`` pairs from a persisted ``pause.set`` claim witness.
    Usually empty — the §6 cascade selects BLANK-claim functions — so this is the
    corroborating path, not the primary one."""
    from services.effects.prefetch import get_prefetch

    pf = get_prefetch(session)
    if pf is not None and function_id in pf.function_ids:
        claims = pf.claims_by_function.get(function_id)
    else:
        claims = session.execute(
            select(EffectiveFunction.claims).where(EffectiveFunction.id == function_id)
        ).scalar_one_or_none()
    out: set[tuple[str, str | None]] = set()
    if not isinstance(claims, list):
        return out
    for claim in claims:
        if not isinstance(claim, dict) or claim.get("claim_id") != "pause.set":
            continue
        witness = claim.get("witness")
        if not isinstance(witness, dict) or witness.get("kind") != "pause_flag":
            continue
        for flag in witness.get("flags") or []:
            if isinstance(flag, dict) and flag.get("var"):
                member = flag.get("member")
                out.add((str(flag["var"]), str(member) if member else None))
    return out


def _latch_pairs(fn: FunctionFacts) -> set[tuple[str, str | None]]:
    """State writes with the shape a freeze latch has.

    A plain ``bool`` flag is the classic form; an ERC-7201 namespaced latch is
    recorded as a write to the ``bytes32`` slot pseudo-variable with hygiene class
    ``storage_location_pseudo`` and an empty member path, so it must be admitted
    too — that is the only fact tying the writer to the latch.

    ``origin == "body"`` is REQUIRED. A ``guard``-origin entry is the latch being
    READ by this function's own ``whenNotPaused`` modifier, not written by it — so
    on a namespaced contract every guarded function records the very same var and
    hygiene class as the pauser. Admitting those makes each of a pause's VICTIMS
    look like a pauser and puts them on the most expensive tier (measured: 141
    Tier-2 plans instead of 98 on the real candidate set) to probe functions that
    definitionally cannot flip the latch. ``_effect_targets_from_sinks`` filters
    to body-origin sinks for exactly this reason."""
    pairs: set[tuple[str, str | None]] = set()
    for write in fn.effect_info.get("state_writes") or []:
        if not isinstance(write, dict):
            continue
        if write.get("origin") != "body":
            continue
        hygiene = str(write.get("hygiene_class") or "")
        declared = str(write.get("declared_type") or "")
        latch_shaped = (hygiene == "normal" and "bool" in declared) or hygiene == "storage_location_pseudo"
        if not latch_shaped:
            continue
        var = write.get("var")
        if not var:
            continue
        member_path = write.get("member_path") or []
        pairs.add((str(var), str(member_path[0]) if member_path else None))
    return pairs


def _principals_by_selector(session: Session, contract_id: int) -> dict[str, str]:
    from services.effects.prefetch import get_prefetch

    pf = get_prefetch(session)
    if pf is not None and contract_id in pf.contract_ids:
        return dict(pf.principals_by_selector_by_contract.get(contract_id, {}))
    # ORDER BY is load-bearing, not cosmetic: a selector with two principals
    # resolves to whichever row arrives first under ``setdefault``, so an
    # unordered read makes the ``from_addr`` we simulate with depend on the plan
    # path (and on Postgres' row order). Matches ``prefetch.install_prefetch``
    # exactly so batched and unbatched planning simulate the same call.
    rows = session.execute(
        select(EffectiveFunction.selector, FunctionPrincipal.address)
        .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(EffectiveFunction.contract_id == contract_id)
        .order_by(EffectiveFunction.id, FunctionPrincipal.address)
    ).all()
    out: dict[str, str] = {}
    for selector, address in rows:
        if isinstance(selector, str) and isinstance(address, str):
            out.setdefault(selector.lower(), address.lower())
    return out


def _compared_operands(leaf: Mapping[str, Any]) -> list[dict[str, Any]]:
    """A leaf's operands UNION the additive sub-operands it absorbed.

    A Solidity comparison holds two operands, and the pause-window question needs
    three facts (the clock, the latch, the offset) — so before
    ``absorbed_operands`` existed this reader's positive branch was unreachable
    from any compiled source (ledger L-16, measured over 11 guard shapes).
    ``absorbed_operands`` is the sibling list the leaf builder now records; taking
    the union here is the whole widening.

    Trees persisted before that field simply have no key, and this reads them
    exactly as it did: absent ⇒ the old two-operand answer. What that answer may
    NOT be used for is a conclusion drawn from an operand's ABSENCE — see
    :func:`_absorption_recorded`, which is the positive marker that separates
    "this comparison read nothing more" from "we do not know what it read".
    """
    absorbed = leaf.get("absorbed_operands")
    extra = [op for op in absorbed if isinstance(op, dict)] if isinstance(absorbed, list) else []
    return [*_operands(leaf), *extra]


# Root-node marker stamped by ``predicate_artifacts.build_predicate_artifacts`` on
# every tree built by a builder that records absorbed operands
# (``predicates._stamp_absorbed_operands``). Duplicated as a literal for the same
# reason ``"op"``/``"leaf"`` are: the effects plane reads static's persisted JSON and
# does not import the static package.
_OPERAND_ABSORPTION_RECORDED = "recorded"


# Operand sources that stand for an expression whose CONTENTS were not recorded, so
# the operand may be HIDING a clock read:
#   * ``computed`` — any arithmetic / hash / encode result the absorption recorder did
#     not decompose (it handles ``+``/``-`` one level deep and nothing else).
#   * ``top`` — provenance saturation.
#   * ``view_call`` / ``external_call`` — an operand that names a CALLEE the recorder
#     never entered. Reading time through a helper is the mainstream idiom, not a
#     curiosity: ``_blockTimestamp()`` in Uniswap V3's pool, ``clock()`` in OZ
#     Governor, ``oracle.nowSeconds()`` on any time oracle. Reproduced from compiled
#     Solidity: ``require(!frozen || _clock() > unpauseAt)`` records
#     ``{view_call _clock(), state_variable unpauseAt}`` and no ``block_context``
#     operand appears anywhere in the tree, so "no clock here" was a false proof about
#     a freeze that demonstrably expires.
# None of these may be read as "this operand is not a clock". The named, decomposed
# sources are deliberately absent from this set: ``state_variable``, ``constant``,
# ``parameter``, ``msg_sender``/``tx_origin``/``signature_recovery``,
# ``self_address``, ``block_context``. Each is a fact the builder resolved and none
# is an unentered expression — a stored timestamp or a caller-supplied deadline is
# not a clock (no passage of time changes it without a transaction).
_OPAQUE_OPERAND_SOURCES = frozenset({"computed", "top", "view_call", "external_call"})


def _absorption_recorded(tree: Any) -> bool:
    """Whether this tree's operand lists are known-complete for the additive shape.

    An operand list is LOSSY by construction: a comparison leaf holds two slots, so
    ``block.timestamp - pausedUntil < 2592000`` records ``{pausedUntil, 2592000}``
    and the clock is simply gone. ``absorbed_operands`` is what recovers it — but a
    MISSING ``absorbed_operands`` has two meanings, and only this marker tells them
    apart:

    * marker present ⇒ the builder ran the absorption recorder over every
      comparison in this tree, so no key means the comparison read no additive
      sub-expression. An operand's absence is then evidence.
    * marker ABSENT ⇒ the tree was built before the widening (every
      ``contract_materializations.predicate_trees`` row in the database is such a
      tree, and an R5 bump does not re-run the static stage). An operand's absence
      says nothing at all, so no conclusion may be drawn FROM it.

    That distinction is load-bearing for exactly one caller: the
    ``no_time_reference`` state of :func:`_duration_from_trees` is a claim that no
    leaf reading the latch touches a clock — a proof BY ABSENCE, and the most
    severe freeze statement this system makes. Reproduced on compiled source:
    ``require(block.timestamp - pausedUntil < 2592000)`` reads as
    ``(2592000, "guard_constant")`` from a tree built at this HEAD and, with
    ``absorbed_operands`` stripped to the persisted shape, as PROVEN INDEFINITE —
    the same source, the opposite answer, in the severe direction.
    """
    return isinstance(tree, dict) and tree.get("operand_absorption") == _OPERAND_ABSORPTION_RECORDED


def _duration_from_trees(trees: Mapping[str, Any], latch_vars: set[str]) -> tuple[int | None, str]:
    """The latch's freeze window and HOW it was established.

    A guard leaf that compares ``block.timestamp`` against a constant offset of the
    latch IS that latch's window (``guard_constant``). Scoped to the latch because
    a contract can carry two latches with different semantics (one indefinite, one
    timed) and the wrong constant is a wrong witness, not a rounding error.

    ``no_time_reference`` is the PROOF of an indefinite latch: some guard leaf DOES
    read the latch (so the gate was lowered and we are looking at it) and no leaf
    reading it touches a clock, so no passage of time can lift the freeze — a plain
    ``bool frozen`` gate. A latch no lowered leaf reads at all is
    ``not_determined``, never indefinite: that is the tree-absent case, and it is
    the governing rule of this whole effort — absence of a proven bound is not
    proof that no bound exists. ``not_determined`` is likewise the honest answer
    for the shape this reader cannot resolve: the guard DOES compare the latch
    against ``block.timestamp`` (so the latch is timed and the freeze does expire)
    but the window itself is not in the code — etherfi's ``PausableUntil`` stores
    it (``$.pauseUntilDuration``, bounded by ``MIN``/``MAX_PAUSE_DURATION`` inside
    a different function's guard), so only a live read of that state or a
    cross-function derivation could name it. All 4 proven ``freeze_pause``
    verdicts in the local corpus are that shape, and every one of them published
    ``null`` — rendered as "indefinite latch (no self-recovery bound)" on the
    function inspector, about a latch called ``pauseUntil``.

    ``no_time_reference`` IS A PROOF BY ABSENCE, so it carries two preconditions
    beyond the leaf-local one, and neither is optional. Both are asked of the WHOLE
    gate tree that reads the latch, never of the latch-reading leaf alone: a
    leaf-local reading of "no clock here" was unsound in both directions a real
    compiler produces, and a leaf-local reading of "nothing unread here" is unsound
    for exactly the same reason — the clock and the latch end up in sibling leaves.

    1. A SIBLING LEAF MAY HOLD THE CLOCK. Solidity lowers ``||``/``&&`` into
       separate leaves, so ``require(!frozen || block.timestamp > unpauseAt)``
       yields one leaf holding ``{frozen}`` and another holding
       ``{timestamp, unpauseAt}``. No leaf holds both, and the freeze
       demonstrably expires. This is not an edge case: :func:`_latch_pairs` admits
       only ``bool``-typed writes (or the ERC-7201 pseudo-slot) and a ``bool``
       cannot be compared against ``block.timestamp`` in ANY leaf, so for the whole
       two-variable timed-pause family (``bool paused`` + ``uint pauseExpiry``) the
       leaf-local answers were only ``not_determined`` or proven-most-severe. So
       the clock is looked for across the WHOLE gate tree that reads the latch: a
       clock anywhere in it means time may lift this freeze, and the honest state
       is ``not_determined``. Deliberately conservative — a pure conjunction
       ``!frozen && block.timestamp > x`` genuinely IS indefinite and is demoted
       too, because a tree walk cannot tell a lowered disjunction from a lowered
       conjunction and the cost of being wrong is asymmetric.
    2. THE OPERAND LISTS MUST BE KNOWN-COMPLETE (:func:`_absorption_recorded`). A
       pre-widening tree drops the clock out of ``block.timestamp - pausedUntil <
       2592000`` entirely, so its absence proves nothing. Every persisted tree in
       the database is such a tree, which is why this state has ZERO realised rows
       locally: it is reachable by construction and test-covered (the compiled
       ``TimedLatch`` corpus fixture), and it will start being realised when the
       static stage next re-runs. That is the honest reading of a lower bound, not
       a dead branch. The marker's promise is bounded in the same way the recorder
       is — ADDITIVE, one level deep, and it never enters a callee — so an OPAQUE
       operand (:data:`_OPAQUE_OPERAND_SOURCES`) ANYWHERE in a latch-reading tree
       denies the proof too. Two shapes, both compiled: ``block.timestamp / 2 >
       pausedUntil`` records ``{computed, pausedUntil}`` (the recorder does not
       decompose a quotient, so the clock is inside an operand nobody read), and
       ``require(!frozen || _clock() > unpauseAt)`` — reading time through an
       internal view helper or a time oracle, the Uniswap-V3 / OZ-Governor idiom —
       records ``{view_call _clock(), unpauseAt}`` in the SIBLING leaf with no
       ``block_context`` operand anywhere, so rule 1 does not see it either. Scoping
       this to the tree rather than the leaf is what makes the two rules symmetric:
       both ask "could this tree be hiding a clock from me", and neither may be
       answered from the two slots of one comparison.

       THE RECALL COST IS LARGE AND IS THE POINT, so it is stated rather than
       discovered later. A tree here is a whole FUNCTION's lowered guard set, so an
       unrelated leaf makes the whole tree opaque: SafeMath ``add``/``sub``, an
       ``allowance()`` read, ``toTypedDataHash``, an internal helper's return.
       Projected over the 75 local materializations with the marker force-stamped
       (nothing persisted carries it yet, so the realised delta today is 0 either
       way): of the 16 latches the static plane names, 9 reached the proven state
       before and 1 does after; treating every compared state variable as a
       hypothetical latch, 379 reached it before and 149 after. Every move is OFF the
       proven state and none onto it, which is the only direction this reader is
       allowed to be wrong in — a false "most severe freeze there is" is a claim
       about a contract, ``not_determined`` is a claim about our evidence. Nothing in
       the demoted set showed a plausible hidden clock, and the reader cannot tell
       that from a real one: ``oracle.isExpired()`` is an ``external_bool`` leaf that
       hides the entire time check, which is why the test cannot be narrowed to
       ordering comparisons. Same conservatism as rule 1, one order louder.

    When several plausible constants are in scope the MAX is taken: the value is
    consumed as a severity reducer, so the longest candidate window is the least
    mitigating reading of ambiguous evidence.
    """
    best: int | None = None
    saw_latch_guard = False
    saw_timed_latch_guard = False
    clock_in_a_latch_tree = False
    latch_read_from_lossy_tree = False
    for tree in trees.values():
        tree_reads_latch = False
        tree_reads_clock = False
        tree_holds_opaque_operand = False
        for leaf in _all_leaves(tree):
            operands = _compared_operands(leaf)
            leaf_reads_clock = any(op.get("block_context_kind") == "timestamp" for op in operands)
            tree_reads_clock = tree_reads_clock or leaf_reads_clock
            if any(op.get("source") in _OPAQUE_OPERAND_SOURCES for op in operands):
                tree_holds_opaque_operand = True
            if not any(str(op.get("state_variable_name") or "") in latch_vars for op in operands):
                continue
            tree_reads_latch = True
            saw_latch_guard = True
            if not leaf_reads_clock:
                continue
            saw_timed_latch_guard = True
            for op in operands:
                value = _parse_int(op.get("constant_value"))
                if value is not None and 0 < value <= _MAX_PLAUSIBLE_DURATION_S:
                    best = value if best is None else max(best, value)
        if tree_reads_latch and tree_reads_clock:
            clock_in_a_latch_tree = True
        if tree_reads_latch and (not _absorption_recorded(tree) or tree_holds_opaque_operand):
            latch_read_from_lossy_tree = True
    if best is not None:
        # A resolved window is positive evidence: all three facts were present in one
        # leaf's union, which no lossy list can fake, so neither precondition above
        # applies to it.
        return best, DURATION_BOUND_GUARD_CONSTANT
    if saw_timed_latch_guard or not saw_latch_guard:
        return None, DURATION_BOUND_NOT_DETERMINED
    if clock_in_a_latch_tree or latch_read_from_lossy_tree:
        return None, DURATION_BOUND_NOT_DETERMINED
    return None, DURATION_BOUND_NO_TIME_REFERENCE


def _parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def read_max_pause_duration(facts: ContractFacts, latch_vars: set[str]) -> tuple[int | None, str]:
    """Inv. 10: the pause bound is READ, never hardcoded — and it is per-LATCH.
    Returns ``(seconds_or_None, source)`` where ``source`` is one of the three
    ``DURATION_BOUND_*`` states; the pair is the whole point (R1), because
    ``None`` alone cannot say whether the latch has no window or whether we
    failed to find one.

    A contract can hold an indefinite latch and a timed one at once; the writer
    function pins which. An indefinite latch legitimately yields ``None`` (the
    recipe then skips the auto-expiry probe and records no duration bound), and
    emitting the timed latch's constant for it would be a false witness.

    ONE source, and it is the IR: a constant that the latch's own guard leaf
    compares ``block.timestamp`` against IS that latch's window
    (:func:`_duration_from_trees`). There used to be a source-text fallback that
    scraped ``constant`` declarations whose NAME contained PAUSE/FREEZE out of
    every file mentioning the latch. That is identifier matching, and the value it
    produced did not stay in the transcript: it reaches the claim witness as
    ``duration_bound_seconds``, where the documented scorer contract
    (``claims_bridge._observed_summary``) reads a bound as a severity REDUCER. A
    cooldown, a minimum, or an unrelated timer picked up by the name pattern would
    therefore have discounted an indefinite freeze. No bound is the correct and
    conservative output — but "no bound" and "no bound FOUND" are different facts
    and the returned ``source`` is what keeps them apart. The old contract
    ("``duration_bound_seconds is None`` + ``auto_expiry is None`` means indefinite
    latch, most severe") was false on every row that had it: the corpus's four
    proven rows are all ``pauseUntil`` — a latch that expires — and they published
    exactly that pair.

    What is deliberately NOT read here, stated so the gap is not mistaken for an
    oversight: etherfi's window lives in ``$.pauseUntilDuration``, a storage value
    with a public getter, bounded by ``MIN_PAUSE_DURATION``/``MAX_PAUSE_DURATION``
    inside ``setPauseUntilDuration``'s own guard. Reading it means either a live
    ``eth_call`` (a per-deployment observation — it would belong in the state-plane
    residue, never in the code-plane ``details`` this value rides) or a
    cross-function derivation the static plane does not record (the latch write's
    assigned-expression origins are not in the effects artifact). Selecting the
    getter by NAME is the identifier matching this docstring already refuses. So
    the honest published state for that shape is ``not_determined``, and the fork
    still cross-checks any bound this reader DOES find by warping past it."""
    return _duration_from_trees(facts.trees, latch_vars)


def _state_changing_functions(facts: ContractFacts) -> list[str]:
    return sorted(name for name, info in facts.effects.items() if isinstance(info, dict) and info.get("state_changing"))


def _entry_point_for(
    facts: ContractFacts, name: str, principals: Mapping[str, str], *, caller_override: str | None = None
) -> EntryPoint | None:
    """One blast-radius probe. ``from_addr`` is THAT function's own resolved
    principal — a contract-wide caller would be rejected by every gated entry
    point pre-pause, collapsing the observed radius to nothing. A function with no
    resolved principal is still probed, from a neutral identity: it may be public,
    and skipping it could only lose a witness.

    ``caller_override`` forces a specific caller (the §1 A2 pauser-identity probe):
    a predicted victim whose OWN principal could not be resolved is additionally
    probed from the pause principal, so a gate the neutral caller can't pass is
    still exercised by a caller that can."""
    sig = facts.canonical_signature(name)
    selector = _selector_of(sig)
    types = _parse_arg_types(sig)
    if not selector or types is None:
        return None
    caller = caller_override or principals.get(selector, NEUTRAL_CALLER)
    # Any direction: a blast-radius probe is not scoped to one value flow, it just
    # needs each argument to carry a value the role evidence justifies.
    probe_fn = facts_for_name(facts, name)
    roles = integer_param_roles(probe_fn, types) if probe_fn is not None else {}
    calldata = encode_calldata(
        selector,
        sig,
        substitutions=_arg_values(types, identity=caller, amount=ARG_AMOUNT, integer_roles=roles).substitutions,
    )
    if calldata is None:
        return None
    # Gas only: the caller must be able to pay, or an out-of-gas revert pre-pause
    # would look like the pause froze this point.
    fixtures = (ForkFixture(kind="set_balance", address=caller, value=hex(FIXTURE_BALANCE_WEI)),)
    return EntryPoint(key=name, calldata=calldata, from_addr=caller, fixtures=fixtures)


def _pauser_identity_probes(
    facts: ContractFacts, predicted: Sequence[str], principals: Mapping[str, str], pauser: str
) -> list[EntryPoint]:
    """§1 A2 follow-up (cause a): a PREDICTED pause victim whose own caller could not
    be resolved is probed from ``NEUTRAL_CALLER`` and rejected by its auth gate
    pre-pause, hiding any freeze from the diff (bucket B / unresolved-victim cause).
    Add a second probe of each such victim from the PAUSE principal — often the ops
    multisig, which reaches many gated functions.

    Same ``EntryPoint`` key ⇒ the succeeding-set unions the identities: a victim
    counts as succeeding if EITHER caller reaches it pre-pause, and enters the
    observed blast only when it reverts under BOTH post-pause. So this can only ADD
    witnessed freezes, never manufacture one — the observed radius stays a sound
    lower bound.

    Scoped tightly so it adds probes only where they can help: (1) the PREDICTED set
    only (never the probe-everything fallback); (2) victims behind a CALLER-authority
    gate — a pause-only or permissionless victim is already reachable by the neutral
    caller, so a pauser probe there is pure redundant cost; (3) victims whose own
    principal could not be resolved (a resolved one already probes as itself)."""
    resolved = set(principals)
    probes: list[EntryPoint] = []
    for name in predicted:
        tree = facts.trees.get(name)
        # Only a caller-authority gate can hide a victim from the neutral caller.
        if not (_authority_roles(tree) & set(_AUTHORITY_ROLES)):
            continue
        selector = _selector_of(facts.canonical_signature(name))
        if not selector or selector in resolved:
            continue
        ep = _entry_point_for(facts, name, principals, caller_override=pauser)
        if ep is not None:
            probes.append(ep)
    return probes


# ---------------------------------------------------------------------------
# Token-precondition seeding (§4.1 blast-radius honesty)
# ---------------------------------------------------------------------------


def _word_hex(value: int) -> str:
    """A 32-byte big-endian EVM word as ``0x`` + 64 hex."""
    return "0x" + format(value & (2**256 - 1), "064x")


def _mapping_entry_slot(base_slot: str, keys: Sequence[int]) -> str | None:
    """Storage slot of a (possibly nested) mapping entry, folding keys OUTERMOST
    first: ``m[k1][k2] = keccak(pad32(k2) ++ keccak(pad32(k1) ++ base))``. ``keys``
    is ``[k1, k2, ...]`` in declaration order. ``None`` when ``base_slot`` is not a
    parseable ≤32-byte word."""
    try:
        raw = base_slot[2:] if base_slot.lower().startswith("0x") else base_slot
        slot = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(slot) > 32:
        return None
    slot = slot.rjust(32, b"\x00")
    for key in keys:
        slot = keccak(key.to_bytes(32, "big") + slot)
    return "0x" + slot.hex()


def _seed_fixture_for_role(entry: Mapping[str, Any], caller: str, target: str) -> ForkFixture | None:
    """One read-back-verified storage fixture seeding ``caller``'s precondition for
    a single token_slots ``entry`` on ``target`` (the state-bearing deployment).
    ``None`` on any malformed field or role/kind mismatch — a dropped seed only
    shrinks the observed lower bound, never manufactures a witness."""
    role = entry.get("role")
    key_kind = entry.get("key_kind")
    base_slot = entry.get("base_slot")
    getter = entry.get("getter")
    if not isinstance(base_slot, str) or not isinstance(getter, str):
        logger.debug("effects calldata: token_slots entry missing base_slot/getter: %r", entry)
        return None
    getter_selector = _selector_of(getter)
    if getter_selector is None:
        logger.debug("effects calldata: token_slots getter not a canonical signature: %r", getter)
        return None

    caller = caller.lower()
    try:
        caller_key = int(caller, 16)
    except ValueError:
        logger.debug("effects calldata: token_slots caller not an address: %r", caller)
        return None

    # The synthesizer substitutes identity=caller for every address arg (see
    # ``_arg_values``), so in a probe an allowance is m[owner=caller][spender=caller];
    # an id-shaped uint arg carries ARG_IDENTIFIER, so a uint-keyed owner mapping is
    # read at exactly that token id — the seeds MUST match those keys.
    if role in ("balance", "shares") and key_kind == "address":
        keys, subs, value = [caller_key], {0: caller}, _word_hex(SEED_AMOUNT)
    elif role == "allowance" and key_kind == "address_address":
        keys, subs, value = [caller_key, caller_key], {0: caller, 1: caller}, _word_hex(SEED_AMOUNT)
    elif role == "owner" and key_kind == "uint256":
        # The stored word IS the caller: ownerOf(tokenId) must return the prober.
        keys, subs, value = [ARG_IDENTIFIER], {0: ARG_IDENTIFIER}, _word_hex(caller_key)
    else:
        logger.debug("effects calldata: token_slots role/kind unsupported: role=%r kind=%r", role, key_kind)
        return None

    slot = _mapping_entry_slot(base_slot, keys)
    verify_calldata = encode_calldata(getter_selector, getter, substitutions=subs)
    if slot is None or verify_calldata is None:
        logger.debug("effects calldata: token_slots slot/getter unencodable: %r", entry)
        return None
    return ForkFixture(
        kind="set_storage_at",
        address=target,
        value=value,
        slot=slot,
        verify_to=target,
        verify_calldata=verify_calldata,
        verify_expected=value,
    )


def _token_seed_fixtures(
    token_slots: Sequence[Mapping[str, Any]], callers: Sequence[str], target: str
) -> tuple[ForkFixture, ...]:
    """Seed each distinct prober's token preconditions on ``target``. Deterministic
    over (entry order, sorted callers).

    An ``owner`` seed is emitted for the FIRST caller only: its slot is keyed by
    the tokenId (``ARG_AMOUNT``), not the caller, so per-caller seeds would all
    write the same slot last-writer-wins — leaving every earlier caller's probe
    precondition silently unmet while its read-back transcript said ok. One
    deterministic owner keeps the transcript truthful; other callers' NFT entry
    points stay invisible to the diff, which only shrinks the observed lower
    bound."""
    fixtures: list[ForkFixture] = []
    for entry in token_slots:
        entry_callers = callers[:1] if entry.get("role") == "owner" else callers
        for caller in entry_callers:
            fx = _seed_fixture_for_role(entry, caller, target)
            if fx is not None:
                fixtures.append(fx)
    return tuple(fixtures)


# ---------------------------------------------------------------------------
# Input-asset seeding (§4.2 / §4.5 preconditions) — Tier 1
# ---------------------------------------------------------------------------

# Directions whose asset the ACTING PRINCIPAL must already hold for the call to
# get past its first line: a pull (``in``) and a burn of the caller's own
# holding. An ``out`` flow is what the function produces, never its precondition.
_INPUT_DIRECTIONS = frozenset({"in", "burn"})

# ERC-20/721 selectors that PULL from the caller. A body sink bearing one of
# these names the input asset in its dotted target (``eETH.transferFrom``).
_PULL_SELECTORS = frozenset(
    {
        "0x23b872dd",  # transferFrom(address,address,uint256)
        "0x42842e0e",  # safeTransferFrom(address,address,uint256)
        "0xb88d4fde",  # safeTransferFrom(address,address,uint256,bytes)
        "0x9dc29fac",  # burn(address,uint256)
        "0x79cc6790",  # burnFrom(address,uint256)
    }
)

# View selectors that only ever READ a per-holder token balance, so a body sink
# bearing one names the input asset in its dotted head just as a PULL selector
# does — a share-accounted wrap reads ``eETH.shares(caller)`` before it moves the
# asset, and that read is the only NAMED head when the transfer itself is
# library-wrapped behind a temporary. Selector-keyed, not name-keyed:
# ``shares(address)`` shares its selector with ``PaymentSplitter.shares``, so this
# is a hint source only, never a token-role assertion (see ``_TOKEN_METHOD_WORDS``
# which deliberately excludes ``shares`` for that reason).
_TOKEN_READ_SELECTORS = frozenset(
    {
        "0xce7c2ac2",  # shares(address)
        "0xf5eb42dc",  # sharesOf(address)
        "0x70a08231",  # balanceOf(address)
    }
)

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A token hint that is already an address needs no getter call to resolve.
_RESOLVED_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Zero-arg getter every ERC-4626 vault must expose for its input asset. A
# standard, not a name guess — and a wrong candidate can only fail to unblock the
# call, never fabricate an inflow.
_ERC4626_ASSET_GETTER = "asset()"

# The probe target itself, as a token-hint sentinel: a withdrawal/unwrap burns
# the caller's holding of the very contract under probe.
SELF_TOKEN_HINT = "__self__"


def input_token_hints(fn: FunctionFacts, *, token_addresses: Sequence[str] = ()) -> tuple[str, ...]:
    """Candidate input assets for the seeded retry, most specific first, plus
    :data:`SELF_TOKEN_HINT` last. An entry is either a zero-arg getter signature
    to call on the probe target or an already-resolved token ADDRESS.

    Getter sources, no name invention: the dotted target of a body sink carrying
    an ERC-20 PULL selector (``eETH.transferFrom`` ⇒ ``eETH()``); the dotted
    target of a body sink calling a token-only METHOD, which is how a
    library-wrapped pull surfaces (``nativeWrapper.safeApprove`` ⇒
    ``nativeWrapper()``, whose selector belongs to the library, not to ERC-20);
    and the ``token_var`` of a ``contract_analysis`` value flow whose direction is
    a pull or burn. A head that is a declared PARAMETER names no getter — there is
    no state variable behind it — which is what ``token_addresses`` is for: the
    caller supplies the assets the acting deployment provably holds, and
    :func:`substitute_address_arg` writes one of them into that parameter.

    These are CANDIDATES, not claims. Identity is settled on the wire (the getter
    must return an address whose storage read-back confirms a balance mapping),
    and the verdict is settled by an observed transfer — a wrong candidate simply
    leaves the call reverting exactly as it does today."""
    names: list[str] = []
    params = set(_declared_param_names(fn, len(_parse_arg_types(fn.canonical_signature) or ())))

    def _add(raw: Any) -> None:
        name = str(raw or "").strip()
        # A Slither synthetic (``TMP_1127``/``REF_5``/``TUPLE_2``) is not a getter:
        # it is an unresolved cast/index temporary, and calling it as ``TMP_1127()``
        # seeds nothing. Static resolution now recovers the state var behind most
        # of these; whatever survives here (a mapping element, a computed value) has
        # no getter to name and is dropped rather than emitted as junk.
        if name.startswith(("TMP_", "REF_", "TUPLE_")):
            return
        # A parameter is not a getter: the value lives in calldata, not storage.
        if name and name not in params and _IDENTIFIER.match(name) and name not in names:
            names.append(name)

    for sink in fn.effect_info.get("sinks") or []:
        if not isinstance(sink, dict) or sink.get("kind") != "external_call" or sink.get("origin") != "body":
            continue
        if str(sink.get("selector") or "").lower() not in (_PULL_SELECTORS | _TOKEN_READ_SELECTORS):
            continue
        _add(str(sink.get("target") or "").split(".")[0])
    for head in sorted(_token_method_targets(fn)):
        _add(head)
    for flow in fn.legacy_value_flows:
        if str(flow.get("direction")) not in _INPUT_DIRECTIONS or flow.get("is_parameter"):
            continue
        _add(flow.get("token_var"))

    hints = [f"{name}()" for name in names]
    hints.append(_ERC4626_ASSET_GETTER)
    hints.extend(addr.lower() for addr in token_addresses if _RESOLVED_ADDRESS.match(addr or ""))
    hints.append(SELF_TOKEN_HINT)
    return tuple(dict.fromkeys(hints))


def seeded_calldata(
    fn: FunctionFacts,
    principal: str,
    *,
    sentinel_index: int | None = None,
    directions: frozenset[str] | None = None,
    executor: "ExecutorCall | None" = None,
) -> dict[int, str]:
    """``token decimals -> calldata`` for the SEEDED retry of a value/supply probe.

    The unseeded probe sends :data:`ARG_AMOUNT` (1 unit) — the amount that slips
    under rate limiters when the caller already holds the asset. Once the input is
    seeded that amount becomes the new failure mode: a conversion rounds 1 unit to
    a zero-sized mint (measured: ``WeETH.wrap(1)`` reverts on
    ``require(weEthAmount > 0)``), which is a non-observation, not a witness. So
    the seeded retry sends ONE WHOLE UNIT of the input token, pre-encoded per
    common token scale because the encoder runs offline and the decimals are only
    known once the discovery block has read them back.

    ``sentinel_index`` re-points the taint-identified address param at the
    attacker sentinel, so a seeded sentinel probe keeps its meaning."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return {}
    roles = integer_param_roles(fn, types, directions)
    out: dict[int, str] = {}
    for decimals in SEED_UNIT_DECIMALS:
        subs = dict(
            _arg_values(
                types, identity=principal, amount=10**decimals, integer_roles=roles, executor=executor
            ).substitutions
        )
        if sentinel_index is not None:
            if not (0 <= sentinel_index < len(types)):
                return {}
            subs[sentinel_index] = SENTINEL_ADDRESS
        encoded = encode_calldata(fn.selector, fn.canonical_signature, substitutions=subs)
        if encoded is None:
            return {}
        out[decimals] = encoded
    return out


def synthesize_pause(
    session: Session, candidate: Candidate, facts: ContractFacts, fn: FunctionFacts
) -> PausePlanInputs | None:
    """§4.1. Applicable when F writes a latch-shaped state variable.

    ``predicted_guard_set`` is static's read-set for that latch and remains the
    SCORED denominator even when empty. The entry points PROBED are a separate
    thing: when static predicts nothing (no trees for the readers, an
    unsupported guard leaf), we fall back to probing every state-changing entry
    point rather than skipping the class. The observed radius is a lower bound
    either way, and an observed member static did not predict is routed as the
    §9 ``observed_guard_not_predicted`` vocabulary-growth discrepancy — which is
    exactly what that channel is for."""
    latch = _claim_latch_pairs(session, candidate.function_id) or _latch_pairs(fn)
    if not latch:
        return None
    latch_vars = {var for var, _member in latch}
    predicted = [name for name in guarded_functions(facts.trees, latch) if name != fn.full_name]
    probe_names = predicted or [name for name in _state_changing_functions(facts) if name != fn.full_name]
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        return None
    pause_calldata = encode_calldata(fn.selector, fn.canonical_signature)
    if pause_calldata is None:
        return None

    principals = _principals_by_selector(session, candidate.contract_id)
    entry_points = [ep for ep in (_entry_point_for(facts, name, principals) for name in probe_names) if ep is not None]
    if not entry_points:
        return None
    # cause (a) recovery: also probe each predicted victim that has no resolved
    # principal from the pause principal, so a freeze a foreign caller can't reach
    # pre-pause is still witnessed. Only over the PREDICTED set (not the fallback),
    # union semantics keep the observed radius a sound lower bound.
    entry_points = [*entry_points, *_pauser_identity_probes(facts, predicted, principals, principal)]

    # The pause principal needs gas of its own; the per-entry-point fixtures cover
    # the probers. Kept flat here so the recipe applies one list, while each
    # EntryPoint still carries its own for inspection. Token-precondition seeds
    # (balance/allowance/shares/owner) go here too, one per distinct prober, so a
    # token check can never hide an entry point from the diff; each carries its own
    # getter read-back and lands on the state-bearing deployment, never the impl.
    # The seeds are visible to the pause tx itself (a pause gated on the
    # principal's token stake succeeds on the fork regardless of live holdings) —
    # same gate-relative semantics as the ETH balance seed above (inv. 12: the
    # verdict binds the gate structure, not the principal's current funding).
    callers = sorted({ep.from_addr for ep in entry_points if ep.from_addr})
    token_fixtures = _token_seed_fixtures(facts.token_slots, callers, candidate.probe_target)
    fixtures = (ForkFixture(kind="set_balance", address=principal, value=hex(FIXTURE_BALANCE_WEI)), *token_fixtures)
    duration, duration_source = read_max_pause_duration(facts, latch_vars)
    return PausePlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        pause_calldata=pause_calldata,
        entry_points=tuple(entry_points),
        predicted_guard_set=tuple(predicted),
        max_pause_duration=duration,
        duration_bound_source=duration_source,
        gate_ref=_gate_ref(fn.tree),
        fixtures=fixtures,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def synthesize(session: Session, candidate: Candidate) -> CandidatePlanInputs:
    """Build every plan input derivable for ``candidate``. Missing facts yield an
    all-``None`` bundle, never a guess.

    Note the deliberate split: FACTS are read from the code-bearing address (the
    semantic artifacts live on the implementation's job), while every PROBE the
    facts produce targets ``candidate.probe_target`` (the deployment)."""
    facts = load_contract_facts(session, candidate.contract_address)
    if facts is None:
        return CandidatePlanInputs()
    fn = resolve_function(facts, candidate.selector)
    if fn is None:
        return CandidatePlanInputs()
    # §5c: a blank candidate (restrict_families is None) is synthesized for every
    # class; a claim-enrolled candidate only for the value/supply families it was
    # re-enrolled for, so already-explained functions are not re-simulated whole.
    allow = candidate.restrict_families

    def _allowed(family: str) -> bool:
        return allow is None or family in allow

    return CandidatePlanInputs(
        value_out=synthesize_value_out(candidate, fn) if _allowed(EFFECT_CLASS_VALUE_OUT) else None,
        supply=synthesize_supply(candidate, fn) if _allowed(EFFECT_CLASS_SUPPLY) else None,
        authority=synthesize_authority(candidate, facts, fn) if _allowed(EFFECT_CLASS_AUTHORITY_CHANGE) else None,
        pause=synthesize_pause(session, candidate, facts, fn) if _allowed(EFFECT_CLASS_FREEZE_PAUSE) else None,
        # A delayed executor is a value_out question the Tier-1 seam cannot ask.
        timelock=synthesize_timelock(session, candidate, facts, fn) if _allowed(EFFECT_CLASS_VALUE_OUT) else None,
    )


__all__ = [
    "ARG_AMOUNT",
    "ARG_IDENTIFIER",
    "ROLE_AMOUNT",
    "ROLE_IDENTIFIER",
    "ROLE_RECIPIENT",
    "ROLE_TOKEN",
    "NEUTRAL_CALLER",
    "SENTINEL_ADDRESS",
    "FIXTURE_BALANCE_WEI",
    "SEED_AMOUNT",
    "AuthorityPlanInputs",
    "CandidatePlanInputs",
    "ContractFacts",
    "ExecutorCall",
    "FunctionFacts",
    "ProbeArgs",
    "PausePlanInputs",
    "SupplyPlanInputs",
    "TimelockPlanInputs",
    "ValueOutPlanInputs",
    "address_param_roles",
    "encode_calldata",
    "executor_call",
    "facts_for_name",
    "function_payable",
    "guarded_functions",
    "has_native_payout",
    "integer_param_roles",
    "load_contract_facts",
    "read_max_pause_duration",
    "resolve_function",
    "substitute_address_arg",
    "synthesize",
    "synthesize_authority",
    "synthesize_pause",
    "synthesize_supply",
    "synthesize_timelock",
    "synthesize_value_out",
]
