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
* :func:`read_max_pause_duration` — inv. 10: the bound is READ (trees, then
  source), never hardcoded, and scoped to the LATCH the function writes.
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
from db.queue import get_artifact, get_source_files
from services.effects.anvil import EntryPoint, ForkFixture
from services.effects.config import (
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
)
from services.effects.seeding import SEED_UNIT_DECIMALS
from services.effects.selection import Candidate
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
    value_holders: tuple[tuple[str, float], ...] = ()
    acting_balance_usd: float = 0.0
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


@dataclass(frozen=True)
class CandidatePlanInputs:
    """Everything the prober can build for one candidate. Any field may be
    ``None`` — that class simply gets no plan."""

    value_out: ValueOutPlanInputs | None = None
    supply: SupplyPlanInputs | None = None
    authority: AuthorityPlanInputs | None = None
    pause: PausePlanInputs | None = None


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

# Word vocabulary for the ROLE of an integer parameter. Both sets are semantic,
# not protocol-specific: a name is split into words and classified by what the
# word MEANS in ABI usage, so ``assetAmount``/``_amount``/``wad`` are quantities
# and ``tokenId``/``requestId``/``index``/``deadline`` are not, on any contract.
_AMOUNT_WORDS = frozenset(
    {"amount", "amounts", "value", "values", "qty", "quantity", "shares", "wad", "fee", "fees", "assets"}
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
    :func:`_lattice_taint_index`). Absent on artifacts predating the field."""
    out: set[int] = set()
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if directions is not None and str(flow.get("direction")) not in directions:
            continue
        kind = flow.get("amount_kind")
        kind_name = kind.get("kind") if isinstance(kind, dict) else None
        index = flow.get("amount_param_index")
        if kind_name != "param" or not isinstance(index, int) or isinstance(index, bool):
            continue
        if 0 <= index < len(types) and _INTEGER_TYPE.fullmatch(types[index].strip()):
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
        if not _INTEGER_TYPE.fullmatch(type_str.strip()):
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
) -> dict[int, Any]:
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
    witness entirely when it could not."""
    roles = integer_roles or {}
    subs: dict[int, Any] = {}
    for idx, type_str in enumerate(types):
        t = type_str.strip()
        if _is_address_type(t):
            if identity:
                subs[idx] = identity.lower()
        elif _INTEGER_TYPE.fullmatch(t):
            role = roles.get(idx)
            if role == ROLE_AMOUNT:
                subs[idx] = amount
            elif role == ROLE_IDENTIFIER:
                subs[idx] = ARG_IDENTIFIER
    return subs


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


def function_payable(fn: "FunctionFacts") -> bool | None:
    """ABI payability of F, or ``None`` when the artifact predates the fact.
    Tri-state on purpose: only a recorded ``False`` may suppress a probe attempt —
    an absent fact leaves the attempt exactly as it is today."""
    value = fn.effect_info.get("payable")
    return value if isinstance(value, bool) else None


def _selector_of(signature: str) -> str | None:
    if not signature or "(" not in signature or not signature.endswith(")"):
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
    """A gate STRUCTURE descriptor (inv. 12) — authority roles, never an address."""
    roles = sorted(_authority_roles(tree))
    return "gate:" + ("+".join(roles) if roles else "none")


# ---------------------------------------------------------------------------
# §4.2 value-out / §4.5 supply
# ---------------------------------------------------------------------------

_OUT_DIRECTIONS = frozenset({"out", "eth_out"})
_SUPPLY_DIRECTIONS = frozenset({"mint", "burn"})


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


def _value_probe_inputs(
    fn: FunctionFacts, principal: str, directions: frozenset[str]
) -> tuple[str, bool, str | None, tuple[int, ...]] | None:
    """``(calldata, taint_flag, sentinel_calldata, token_param_indexes)`` shared by
    §4.2 and §4.5."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return None
    roles = integer_param_roles(fn, types, directions)
    addr_roles = address_param_roles(fn, types, directions)
    base_subs = _arg_values(types, identity=principal, amount=ARG_AMOUNT, integer_roles=roles)
    calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=base_subs)
    if calldata is None:
        return None
    taint_idx = _taint_index(fn, types, directions)
    sentinel_calldata = None
    if taint_idx is not None:
        sentinel_subs = dict(base_subs)
        sentinel_subs[taint_idx] = SENTINEL_ADDRESS
        sentinel_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=sentinel_subs)
    tokens = tuple(sorted(idx for idx, role in addr_roles.items() if role == ROLE_TOKEN))
    return calldata, taint_idx is not None, sentinel_calldata, tokens


def synthesize_value_out(candidate: Candidate, fn: FunctionFacts) -> ValueOutPlanInputs | None:
    """§4.2. Applicable when static says the function moves value OUT. Requires a
    resolved principal — a probe from the zero address only ever proves that the
    gate rejected it."""
    if not _flow_directions(fn) & _OUT_DIRECTIONS:
        return None
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        return None
    built = _value_probe_inputs(fn, principal, frozenset(_OUT_DIRECTIONS))
    if built is None:
        return None
    calldata, tainted, sentinel_calldata, token_params = built
    seeded, seeded_sentinel = _seeded_probe_calldata(fn, principal, frozenset(_OUT_DIRECTIONS))
    return ValueOutPlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        calldata=calldata,
        gate_ref=_gate_ref(fn.tree),
        taint_param_reaches_sink=tainted,
        sentinel_address=SENTINEL_ADDRESS if sentinel_calldata else None,
        sentinel_calldata=sentinel_calldata,
        value_holders=candidate.value_holders,
        acting_balance_usd=candidate.acting_balance_usd,
        input_token_hints=input_token_hints(fn, token_addresses=_token_arg_candidates(candidate, token_params)),
        token_param_indexes=token_params,
        seeded_calldata=seeded,
        seeded_sentinel_calldata=seeded_sentinel if sentinel_calldata else {},
        target_payable=function_payable(fn),
        native_payout=has_native_payout(fn),
    )


def synthesize_supply(candidate: Candidate, fn: FunctionFacts) -> SupplyPlanInputs | None:
    """§4.5. Applicable when static says the function mints or burns."""
    labels = {str(lbl) for lbl in (fn.effect_info.get("effect_labels") or [])}
    if not (_flow_directions(fn) & _SUPPLY_DIRECTIONS or labels & _SUPPLY_DIRECTIONS):
        return None
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        return None
    built = _value_probe_inputs(fn, principal, frozenset(_SUPPLY_DIRECTIONS))
    if built is None:
        return None
    calldata, tainted, sentinel_calldata, token_params = built
    seeded, seeded_sentinel = _seeded_probe_calldata(fn, principal, frozenset(_SUPPLY_DIRECTIONS))
    return SupplyPlanInputs(
        # The candidate's own probe target. A candidate that is not an ERC-20
        # simply fails the pre-read and lands ``unknown`` — that is the honest
        # answer, not an error to engineer around.
        token_address=candidate.probe_target,
        principal=principal,
        mint_calldata=calldata,
        gate_ref=_gate_ref(fn.tree),
        taint_param_reaches_sink=tainted,
        sentinel_address=SENTINEL_ADDRESS if sentinel_calldata else None,
        sentinel_calldata=sentinel_calldata,
        input_token_hints=input_token_hints(fn, token_addresses=_token_arg_candidates(candidate, token_params)),
        token_param_indexes=token_params,
        seeded_calldata=seeded,
        seeded_sentinel_calldata=seeded_sentinel if sentinel_calldata else {},
        target_payable=function_payable(fn),
        native_payout=has_native_payout(fn),
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
    fn: FunctionFacts, principal: str, directions: frozenset[str]
) -> tuple[dict[int, str], dict[int, str]]:
    """``(base, sentinel)`` whole-unit calldata for the seeded retry, keyed by
    token decimals. Empty dicts when the signature will not encode — the probe
    then simply never retries."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return {}, {}
    base = seeded_calldata(fn, principal, directions=directions)
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


def _duration_from_trees(trees: Mapping[str, Any], latch_vars: set[str]) -> int | None:
    """A guard leaf that compares ``block.timestamp`` against a constant AND reads
    the latch itself IS that latch's freeze window. Scoped to the latch because a
    contract can carry two latches with different semantics (one indefinite, one
    timed) and the wrong constant is a wrong witness, not a rounding error."""
    best: int | None = None
    for tree in trees.values():
        for leaf in _all_leaves(tree):
            operands = _operands(leaf)
            if not any(op.get("block_context_kind") == "timestamp" for op in operands):
                continue
            if not any(str(op.get("state_variable_name") or "") in latch_vars for op in operands):
                continue
            for op in operands:
                value = _parse_int(op.get("constant_value"))
                if value is not None and 0 < value <= _MAX_PLAUSIBLE_DURATION_S:
                    best = value if best is None else max(best, value)
    return best


_TIME_UNITS = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800}
_CONST_DECL = re.compile(r"constant\s+([A-Za-z0-9_]*(?:PAUSE|Pause|FREEZE|Freeze)[A-Za-z0-9_]*)\s*=\s*([^;]+);")


def _duration_from_source(session: Session, job_id: Any, latch_vars: set[str]) -> int | None:
    """Read the declared bound out of the Solidity source (inv. 10 — the VALUE
    always comes from the contract).

    Scoped to the files that DECLARE this latch, which is what keeps a contract's
    indefinite latch from inheriting the timed latch's constant: the two live in
    different units, and only the timed one declares a duration. The MAX of the
    duration constants in that unit is taken because the live window is whatever
    state or a MIN fallback says, always ≤ the declared MAX — so warping by it is
    a sound upper bound for the auto-expiry probe. A flattened source that puts
    both latches in one file would over-read; that degrades to a longer warp, not
    a wrong latch."""
    if not latch_vars:
        return None
    try:
        sources = get_source_files(session, job_id)
    except Exception:
        logger.debug("effects calldata: source read failed for job %s", job_id, exc_info=True)
        return None
    best: int | None = None
    for content in sources.values():
        text = content or ""
        if not any(var in text for var in latch_vars):
            continue
        for _name, expr in _CONST_DECL.findall(text):
            value = _eval_time_expr(expr)
            if value is not None and 0 < value <= _MAX_PLAUSIBLE_DURATION_S:
                best = value if best is None else max(best, value)
    return best


def _eval_time_expr(expr: str) -> int | None:
    """Evaluate a Solidity duration literal: ``30 days``, ``7 * 24 hours``, ``3600``.
    Anything richer returns ``None`` (⇒ no auto-expiry probe)."""
    text = expr.strip().replace("_", "")
    unit = 1
    for name, mult in _TIME_UNITS.items():
        if re.search(rf"\b{name}\b", text):
            unit = mult
            text = re.sub(rf"\b{name}\b", "", text)
            break
    factors = [p.strip() for p in text.split("*") if p.strip()]
    if not factors:
        return None
    total = 1
    for factor in factors:
        value = _parse_int(factor)
        if value is None:
            return None
        total *= value
    return total * unit


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


def read_max_pause_duration(session: Session, facts: ContractFacts, latch_vars: set[str]) -> int | None:
    """Inv. 10: the pause bound is READ, never hardcoded — and it is per-LATCH.

    A contract can hold an indefinite latch and a timed one at once; the writer
    function pins which. An indefinite latch legitimately yields ``None`` (the
    recipe then skips the auto-expiry probe and records no duration bound), and
    emitting the timed latch's constant for it would be a false witness."""
    return _duration_from_trees(facts.trees, latch_vars) or _duration_from_source(session, facts.job_id, latch_vars)


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
        selector, sig, substitutions=_arg_values(types, identity=caller, amount=ARG_AMOUNT, integer_roles=roles)
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
        # A parameter is not a getter: the value lives in calldata, not storage.
        if name and name not in params and _IDENTIFIER.match(name) and name not in names:
            names.append(name)

    for sink in fn.effect_info.get("sinks") or []:
        if not isinstance(sink, dict) or sink.get("kind") != "external_call" or sink.get("origin") != "body":
            continue
        if str(sink.get("selector") or "").lower() not in _PULL_SELECTORS:
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
        subs = _arg_values(types, identity=principal, amount=10**decimals, integer_roles=roles)
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
    return PausePlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        pause_calldata=pause_calldata,
        entry_points=tuple(entry_points),
        predicted_guard_set=tuple(predicted),
        max_pause_duration=read_max_pause_duration(session, facts, latch_vars),
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
    "FunctionFacts",
    "PausePlanInputs",
    "SupplyPlanInputs",
    "ValueOutPlanInputs",
    "address_param_roles",
    "encode_calldata",
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
    "synthesize_value_out",
]
