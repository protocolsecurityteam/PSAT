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

# Balance handed to every impersonated entry-point caller on the fork so gas can
# never masquerade as a pause revert.
FIXTURE_BALANCE_WEI = 10**19

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


def _arg_values(types: Sequence[str], *, identity: str | None, amount: int) -> dict[int, Any]:
    """The substitution policy for a value-moving probe: address params get the
    caller identity (so a mint/transfer has a real recipient), integer params get
    ``amount`` (nonzero, so a delta is observable), everything else keeps the
    encoder's default. Deliberately blunt — a live-validation adjustment point."""
    subs: dict[int, Any] = {}
    for idx, type_str in enumerate(types):
        t = type_str.strip()
        if _is_address_type(t):
            if identity:
                subs[idx] = identity.lower()
        elif re.fullmatch(r"u?int\d*", t):
            subs[idx] = amount
    return subs


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


def _taint_index(fn: FunctionFacts, types: Sequence[str], directions: frozenset[str]) -> int | None:
    """Positional index of the address param the value-flow taint says the caller
    controls. ``None`` (⇒ no sentinel probe) when the taint is absent, the param
    name cannot be mapped to a slot, or that slot is not address-typed."""
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
) -> tuple[str, bool, str | None] | None:
    """``(calldata, taint_flag, sentinel_calldata)`` shared by §4.2 and §4.5."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return None
    base_subs = _arg_values(types, identity=principal, amount=ARG_AMOUNT)
    calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=base_subs)
    if calldata is None:
        return None
    taint_idx = _taint_index(fn, types, directions)
    sentinel_calldata = None
    if taint_idx is not None:
        sentinel_subs = dict(base_subs)
        sentinel_subs[taint_idx] = SENTINEL_ADDRESS
        sentinel_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=sentinel_subs)
    return calldata, taint_idx is not None, sentinel_calldata


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
    calldata, tainted, sentinel_calldata = built
    return ValueOutPlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        calldata=calldata,
        gate_ref=_gate_ref(fn.tree),
        taint_param_reaches_sink=tainted,
        sentinel_address=SENTINEL_ADDRESS if sentinel_calldata else None,
        sentinel_calldata=sentinel_calldata,
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
    calldata, tainted, sentinel_calldata = built
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
    )


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
    rows = session.execute(
        select(EffectiveFunction.selector, FunctionPrincipal.address)
        .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(EffectiveFunction.contract_id == contract_id)
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


def _entry_point_for(facts: ContractFacts, name: str, principals: Mapping[str, str]) -> EntryPoint | None:
    """One blast-radius probe. ``from_addr`` is THAT function's own resolved
    principal — a contract-wide caller would be rejected by every gated entry
    point pre-pause, collapsing the observed radius to nothing. A function with no
    resolved principal is still probed, from a neutral identity: it may be public,
    and skipping it could only lose a witness."""
    sig = facts.canonical_signature(name)
    selector = _selector_of(sig)
    types = _parse_arg_types(sig)
    if not selector or types is None:
        return None
    caller = principals.get(selector, NEUTRAL_CALLER)
    calldata = encode_calldata(selector, sig, substitutions=_arg_values(types, identity=caller, amount=ARG_AMOUNT))
    if calldata is None:
        return None
    # Gas only: the caller must be able to pay, or an out-of-gas revert pre-pause
    # would look like the pause froze this point.
    fixtures = (ForkFixture(kind="set_balance", address=caller, value=hex(FIXTURE_BALANCE_WEI)),)
    return EntryPoint(key=name, calldata=calldata, from_addr=caller, fixtures=fixtures)


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

    # The pause principal needs gas of its own; the per-entry-point fixtures cover
    # the probers. Kept flat here so the recipe applies one list, while each
    # EntryPoint still carries its own for inspection.
    fixtures = (ForkFixture(kind="set_balance", address=principal, value=hex(FIXTURE_BALANCE_WEI)),)
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
    return CandidatePlanInputs(
        value_out=synthesize_value_out(candidate, fn),
        supply=synthesize_supply(candidate, fn),
        authority=synthesize_authority(candidate, facts, fn),
        pause=synthesize_pause(session, candidate, facts, fn),
    )


__all__ = [
    "ARG_AMOUNT",
    "NEUTRAL_CALLER",
    "SENTINEL_ADDRESS",
    "FIXTURE_BALANCE_WEI",
    "AuthorityPlanInputs",
    "CandidatePlanInputs",
    "ContractFacts",
    "FunctionFacts",
    "PausePlanInputs",
    "SupplyPlanInputs",
    "ValueOutPlanInputs",
    "encode_calldata",
    "guarded_functions",
    "load_contract_facts",
    "read_max_pause_duration",
    "resolve_function",
    "synthesize",
    "synthesize_authority",
    "synthesize_pause",
    "synthesize_supply",
    "synthesize_value_out",
]
