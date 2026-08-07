"""Layer 1 — one job's planes to per-function signal rows. Pure and read-only.

The distiller answers one question per (function, capability): **what did the
pipeline PROVE about this function's behaviour?** It resolves nothing across
contracts — principals travel as ``function_principals`` references and value as
``<chain>::<address>`` entity keys — because MAX-per-entity, principal units and
subsumption are only decidable with the whole protocol in hand, and a signal
that had already resolved its own value would make them undecidable.

Three-state is preserved verbatim. Every undetermined witness reaches its signal
through :func:`not_determined_signal_defaults` or an explicit
:meth:`Tri.not_determined`, never through a default value or a missing key. The
severity axis in particular is either built up from proven components starting
at zero (``pause.set``) or a capability-class constant refined only downward by
mitigating witnesses (everything else) — it is never escalated by the ABSENCE of
a constraint witness, which is why an unread delegatecall/exec destination
yields ``severity = not_determined`` and the row never enters the grade.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring import constants as K
from services.scoring.schema import (
    NOT_DETERMINED,
    FunctionSignal,
    PrincipalRef,
    Tri,
    coalesce_chain,
    entity_key,
    not_determined_signal_defaults,
)
from utils import execution_record as EX
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import (
    DESTINATION_FREE_CLAIMS,
    DESTINATION_SHAPE_NOT_APPLICABLE,
    DESTINATION_STATE_CONSTRAINED_PROVEN,
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_UNCONSTRAINED_PROVEN,
    MAGNITUDE_STATE_PROVEN_FLOOR,
    MAGNITUDE_STATE_PROVEN_UPPER_BOUND,
    NO_SELECTOR,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_OPEN,
    OPENNESS_RESTRICTED,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    REACH_GATE_LICENSED,
    REACH_GATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    VALUE_BOUND_EXACT,
    VALUE_BOUND_FLOOR,
    VALUE_BOUND_NOT_DETERMINED,
    VALUE_STATE_NOT_DETERMINED,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
    WITNESS_TIER_BEHAVIORAL_OBSERVED,
    WITNESS_TIER_IDIOM_STRUCTURAL,
    WITNESS_TIER_NOT_DETERMINED,
    WITNESS_TIER_POLICY_DERIVED,
    WITNESS_TIER_STANDARD_EXACT,
)

logger = logging.getLogger(__name__)

# Gate envelopes every signal carries, so the fold can read them without a
# ``dict.get`` default standing in for an unread witness.
COMMON_GATES = ("exact_empty_credit", "latch_witness", "reach_magnitude_usd")
FLOW_GATES = (
    "token_identity",
    "asset_class",
    "input_seeded",
    "contract_balance_seeded",
    "amount_capped_by_balance",
    "asset_identity",
)
PAUSE_SET_GATES = ("pause_effective", "freeze_recovery_principals", "freeze_coverage_fraction")
DESTINATION_GATES = ("destination_basis",)

_TIER_TOKENS = {
    "behavioral_observed": WITNESS_TIER_BEHAVIORAL_OBSERVED,
    "standard_exact": WITNESS_TIER_STANDARD_EXACT,
    "idiom_structural": WITNESS_TIER_IDIOM_STRUCTURAL,
    "policy_derived": WITNESS_TIER_POLICY_DERIVED,
}
# Strongest first. Used only to pick the signal's descriptive tier; the gates
# that matter (a behavioural existence proof, a policy_derived block) are
# applied per claim entry where they arise.
_TIER_RANK = (
    WITNESS_TIER_BEHAVIORAL_OBSERVED,
    WITNESS_TIER_STANDARD_EXACT,
    WITNESS_TIER_IDIOM_STRUCTURAL,
    WITNESS_TIER_POLICY_DERIVED,
    WITNESS_TIER_NOT_DETERMINED,
)

# The Solmate role mutators by SELECTOR, never by name. The escalation these
# license asserts that the registry's owner can grant itself any role, and
# ``setUserRole(bytes32)`` on an unrelated contract is not
# ``setUserRole(address,uint8,bool)`` — a name match would let any homonym earn
# the escalation. Keccak-4 of the canonical signatures.
_SOLMATE_MUTATOR_SELECTORS: dict[str, str] = {
    "0x67aff484": "setUserRole(address,uint8,bool)",
    "0x0ea9b75b": "setRoleCapability(uint8,bytes4,bool)",
    "0x4b5159da": "setPublicCapability(bytes4,bool)",
}
_TIMELOCK_ENTRYPOINTS = frozenset({"schedule", "scheduleBatch", "execute", "executeBatch"})

# The witness tiers a REPOINT may be admitted on, as an allowlist. A repoint adds
# a foreign entity to a reach set, so the tier that named it has to be one this
# scorer can vouch for. Stated positively on purpose: a denylist of
# ``policy_derived`` admits every tier nobody classified, and an absent or
# unrecognised ``tier`` token resolves to ``not_determined`` — a witness that
# proved nothing would have been the easiest of all to pass.
REPOINT_ADMISSIBLE_TIERS = frozenset(
    {WITNESS_TIER_BEHAVIORAL_OBSERVED, WITNESS_TIER_STANDARD_EXACT, WITNESS_TIER_IDIOM_STRUCTURAL}
)


def _f(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _proven_number(state: str, value: float) -> Tri[float]:
    """A numeric gate envelope, checked to BE a number at construction.

    The envelope's payload is free-form JSONB with no CHECK behind it, so the
    only place its type can be established is where it is minted. A string that
    happens to compare and multiply — ``"1e12"`` — would otherwise travel to the
    value axis and charge a trillion dollars nobody witnessed.
    """
    number = _f(value)
    if number is None:
        raise ValueError(f"numeric gate payload must be a finite number, got {value!r}")
    return Tri.proven(state, number)


def _is_true(value: Any) -> bool:
    """A JSON truth that is *witnessed* true, never a truthy default."""
    return value is True or str(value).lower() == "true"


def _lower(value: Any) -> str:
    return str(value or "").lower()


@dataclass
class _ContractFacts:
    """Everything the distiller reads once per contract."""

    contract_id: int
    protocol_id: int
    chain: str
    address: str
    functions: list[Any]
    principals: dict[int, list[Any]] = field(default_factory=dict)
    verdicts: dict[int, list[Any]] = field(default_factory=dict)
    solmate_mutators: set[str] = field(default_factory=set)
    registry_owner: dict[str, Any] | None = None
    pause_unset_principals: list[dict[str, Any]] = field(default_factory=list)
    licensed_reach_entities: list[dict[str, Any]] = field(default_factory=list)
    asset_identity: dict[str, Any] = field(default_factory=dict)
    # Every entity key this protocol's own ``contracts`` rows name, chain-scoped.
    # A reach key that names nothing in here names nothing this document can
    # answer for, and charging it would both invent reach and spend exposure room
    # belonging to an entity in the perimeter.
    protocol_entities: set[str] = field(default_factory=set)
    # How to read a stored transcript, for a verdict whose ``observed_residue``
    # predates the execution record. ``None`` is the in-memory feeding mode with
    # no session to read from, which reads as "not derivable here", never as
    # "there is no execution".
    transcripts: _TranscriptReader | None = None


def distill_job_signals(session: Session, job: Any) -> dict[int, list[FunctionSignal]]:
    """One job's planes → its contracts' signal rows, grouped by ``contract_id``.

    Grouped by ``contract_id`` and never by ``(contract_id, deployment_address)``:
    the replace that persists these rows is scoped by contract alone, so a
    contract whose functions appear at two deployment addresses must arrive in
    ONE group or the second call would delete the first's rows.
    """
    from db.models import Contract

    contracts = session.query(Contract).filter(Contract.job_id == job.id).order_by(Contract.id).all()
    out: dict[int, list[FunctionSignal]] = {}
    for contract in contracts:
        if contract.protocol_id is None:
            continue
        out[contract.id] = distill_contract_signals(session, contract, job_id=job.id)
    return out


def distill_contract_signals(session: Session, contract: Any, *, job_id: Any) -> list[FunctionSignal]:
    """Every signal for one contract. The unit both feeding modes share."""
    facts = _load_contract_facts(session, contract, job_id=job_id)
    signals: list[FunctionSignal] = []
    for func in facts.functions:
        signals.extend(_signals_for_function(facts, func, job_id=job_id))
    signals.sort(key=lambda s: (s.deployment_address, s.selector, s.claim_id))
    return signals


# ---------------------------------------------------------------- plane reads


# Transcript bodies, keyed by the ``(job_id, artifact_name)`` a pointer resolves
# to. An artifact body is immutable once written — the key is the identity of a
# stored object, not of a mutable row — so caching it across contracts inside one
# score run cannot make the fold read two different answers to one question
# (inv. 11). Cleared by :func:`clear_transcript_cache` for tests that stand up a
# fresh bucket under the same keys.
_TRANSCRIPT_CACHE: dict[tuple[str, str], Any] = {}


def clear_transcript_cache() -> None:
    """Drop the process-level transcript cache. For tests, which reuse keys."""
    _TRANSCRIPT_CACHE.clear()


class _TranscriptReader:
    """Reads the execution behind a verdict out of the transcript it points at.

    The record belongs on ``effect_verdicts.observed_residue`` and is written
    there at production time. Every verdict produced before that write existed
    carries none — which is not a statement that no call was made, because the
    transcript the verdict already points at holds that call verbatim. This
    reader recovers it, so a figure that CAN name its execution does, and the
    typed refusal is reserved for the ones that genuinely cannot.

    The database is not written. Nothing here backfills; the derivation happens
    on the read path and is discarded with the score run.

    Every failure to reach the body is its own typed reason, and they are not
    interchangeable: an artifact row that does not exist, a row naming no
    storage key, and a transport error are three different things to a reader
    deciding whether to look again.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def execution(self, *, transcript_ptr: Any, effect_verdict_id: int | None) -> EX.ProvingExecution:
        parts = EX.pointer_parts(transcript_ptr)
        if parts is None:
            return EX.not_determined(
                EX.REASON_PTR_UNRESOLVABLE,
                transcript_ptr=transcript_ptr if isinstance(transcript_ptr, str) else None,
                effect_verdict_id=effect_verdict_id,
            )
        blob = self._body(parts)
        if isinstance(blob, str):
            return EX.not_determined(blob, transcript_ptr=transcript_ptr, effect_verdict_id=effect_verdict_id)
        return EX.from_transcript(blob, transcript_ptr=transcript_ptr, effect_verdict_id=effect_verdict_id)

    def _body(self, parts: tuple[str, str]) -> Any:
        """The transcript body, or the typed reason token it could not be read."""
        if parts in _TRANSCRIPT_CACHE:
            return _TRANSCRIPT_CACHE[parts]
        from db.models import Artifact
        from db.queue import _artifact_row_to_value
        from db.storage import StorageKeyAbsent, StorageKeyMissing

        job_id, name = parts
        try:
            row = self._session.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == name).one_or_none()
            if row is None:
                body: Any = EX.REASON_TRANSCRIPT_UNSTORED
            else:
                # The STORED key, never a constructed one: the prefix is per-job
                # on this data (345 keys under one, 34 under another) and a
                # reader that builds the key would miss a third of the corpus and
                # report it as absence.
                body = _artifact_row_to_value(row)
        except StorageKeyAbsent:
            body = EX.REASON_STORAGE_KEY_MISSING
        except StorageKeyMissing:
            body = EX.REASON_TRANSCRIPT_UNSTORED
        except Exception:
            # A transport failure says nothing about the call, so it is its own
            # reason and invites a retry rather than asserting an absence.
            logger.warning("transcript body unreadable for %s::%s", job_id, name, exc_info=True)
            body = EX.REASON_FETCH_FAILED
        _TRANSCRIPT_CACHE[parts] = body
        return body


def _load_contract_facts(session: Session, contract: Any, *, job_id: Any) -> _ContractFacts:
    from db.models import ControlGraphNode, ControllerValue, EffectiveFunction, EffectVerdict, FunctionPrincipal

    chain = coalesce_chain(contract.chain)
    address = _lower(contract.address)
    functions = (
        session.query(EffectiveFunction)
        .filter(EffectiveFunction.contract_id == contract.id)
        .order_by(EffectiveFunction.id)
        .all()
    )
    facts = _ContractFacts(
        contract_id=contract.id,
        protocol_id=contract.protocol_id,
        chain=chain,
        address=address,
        functions=functions,
        transcripts=_TranscriptReader(session),
    )
    function_ids = [f.id for f in functions]
    if function_ids:
        principals: dict[int, list[Any]] = defaultdict(list)
        rows = (
            session.query(FunctionPrincipal)
            .filter(FunctionPrincipal.function_id.in_(function_ids))
            .order_by(FunctionPrincipal.function_id, FunctionPrincipal.address, FunctionPrincipal.id)
            .all()
        )
        for row in rows:
            principals[row.function_id].append(row)
        facts.principals = dict(principals)

        verdicts: dict[int, list[Any]] = defaultdict(list)
        for row in (
            session.query(EffectVerdict)
            .filter(EffectVerdict.function_id.in_(function_ids))
            .order_by(EffectVerdict.function_id, EffectVerdict.id)
            .all()
        ):
            if row.function_id is not None:
                verdicts[row.function_id].append(row)
        facts.verdicts = dict(verdicts)

    facts.solmate_mutators = {
        _SOLMATE_MUTATOR_SELECTORS[_lower(f.selector)]
        for f in functions
        if _lower(f.selector) in _SOLMATE_MUTATOR_SELECTORS
    }
    facts.registry_owner = _registry_owner(
        session.query(ControllerValue)
        .filter(ControllerValue.contract_id == contract.id)
        .order_by(ControllerValue.source, ControllerValue.id)
        .all()
    )
    facts.pause_unset_principals = _pause_unset_principals(facts)

    from sqlalchemy import func as _sql_func

    from db.models import Contract as _Contract

    facts.protocol_entities = {
        entity_key(coalesce_chain(row_chain), row_address)
        for row_address, row_chain in session.query(_Contract.address, _Contract.chain)
        .filter(_Contract.protocol_id == contract.protocol_id)
        .order_by(_Contract.id)
        .all()
    }

    # The backlink node is written AT THE GATING CONTRACT'S ADDRESS, on the gated
    # contract's graph, and its payload names the gated contract. So the node
    # that licenses THIS contract is the one whose own address is this contract —
    # matching instead on the payload address selects the nodes whose gated
    # contract is this one, which is the node's own contract every time and
    # licenses this contract to reach itself. Protocol-scoped: another protocol's
    # backlink names an entity outside this perimeter, and charging its value
    # here would both invent reach and consume exposure room that belongs to this
    # protocol's own entities.
    backlinks = (
        session.query(ControlGraphNode)
        .join(_Contract, _Contract.id == ControlGraphNode.contract_id)
        .filter(
            _Contract.protocol_id == contract.protocol_id,
            _sql_func.lower(ControlGraphNode.address) == address,
        )
        .order_by(ControlGraphNode.id)
        .all()
    )
    facts.licensed_reach_entities = _licensed_reach_entities(session, backlinks, address, chain)
    facts.asset_identity = _asset_identity(session, job_id)
    return facts


def _registry_owner(controller_values: list[Any]) -> dict[str, Any] | None:
    """The Solmate registry's owner, and only where the authority is proven zero.

    ``eth_call_impl_fallback`` reads are excluded: implementation storage reads
    as zero, so an owner sourced from one witnesses nothing about the proxy.
    """
    zero_authority = False
    owner: dict[str, Any] | None = None
    for row in controller_values:
        provenance = getattr(row, "authority_provenance", None)
        if row.source == "authority" and row.resolved_type == "zero" and provenance == "caller_gate":
            zero_authority = True
        if (
            row.source == "owner"
            and row.resolved_type in ("safe", "timelock")
            and provenance == "caller_gate"
            and getattr(row, "observed_via", None) == "eth_call"
        ):
            value = _lower(row.value)
            if value.startswith("0x") and len(value) == 42:
                owner = {"address": value, "resolved_type": row.resolved_type, "block": row.block_number}
    return owner if (zero_authority and owner) else None


def _pause_unset_principals(facts: _ContractFacts) -> list[dict[str, Any]]:
    """The recovery key sets on this contract, as references for the fold."""
    seen: dict[str, dict[str, Any]] = {}
    for func in facts.functions:
        if not _claim_ids(func).intersection({"pause.unset"}):
            continue
        for principal in facts.principals.get(func.id, []):
            address = _lower(principal.address)
            seen.setdefault(
                address,
                {
                    "address": address,
                    "chain": facts.chain,
                    "function_principal_id": principal.id,
                    "resolved_type": principal.resolved_type,
                },
            )
    return [seen[a] for a in sorted(seen)]


def _function_is_self_gated(facts: _ContractFacts, func: Any) -> bool:
    """Whether THIS function's own resolved gate is the contract itself.

    Keyed on the function being scored, never on a same-named sibling: a
    self-gated ``grantRole`` says nothing about who can call the function that
    sets the delay, and crediting one from the other hands every other path on
    the contract a pass it never earned.
    """
    principals = facts.principals.get(func.id, [])
    return bool(principals) and all(_lower(p.address) == facts.address for p in principals)


def _licensed_reach_entities(session: Session, backlinks: list[Any], address: str, chain: str) -> list[dict[str, Any]]:
    """Entities whose value this contract's gated functions may be charged with.

    The backlink is a REACHABILITY licence and nothing else: it never types the
    contract it names, it supplies no magnitude, and a mismatch is not an earned
    negative — the mismatch payload is byte-identical to the never-read one, so
    only the proven ``true`` arm is consumable and everything else stays
    ``not_determined``.

    ``backlinks`` are the nodes written AT this contract's address. The payload's
    ``gated_contract_address`` must name the contract the node belongs to, which
    is what makes the pair a licence rather than two unrelated facts sharing a
    row. A licence onto this contract itself is dropped: it names no entity the
    reach did not already hold.
    """
    from db.models import Contract

    out: dict[str, dict[str, Any]] = {}
    for node in backlinks:
        details = node.details if isinstance(node.details, dict) else {}
        backlink = details.get("gated_contract_backlink")
        if not isinstance(backlink, dict):
            continue
        if backlink.get("declared_vault_matches_gated_contract") is not True:
            continue
        anchor = session.get(Contract, node.contract_id)
        if anchor is None or anchor.protocol_id is None:
            continue
        if _lower(backlink.get("gated_contract_address")) != _lower(anchor.address):
            # The payload names a contract other than the one whose graph the
            # node sits on. Two facts in one row is not a licence.
            continue
        anchor_chain = coalesce_chain(anchor.chain)
        if anchor_chain != chain:
            # A licence is per chain; charging across one would alias two
            # deployments that share an address.
            continue
        key = entity_key(anchor_chain, anchor.address)
        if key == entity_key(chain, address):
            continue
        out.setdefault(
            key,
            {
                "entity_key": key,
                "probe_block": backlink.get("probe_block"),
                "backlink_getter": backlink.get("backlink_getter"),
            },
        )
    return [out[k] for k in sorted(out)]


def _asset_identity(session: Session, job_id: Any) -> dict[str, Any]:
    """``flow_asset_addresses`` receivers, keyed by (deployment, selector).

    Absence means the plane did not run for this job — ``not_determined``, never
    a proven-empty asset set.
    """
    if job_id is None:
        return {}
    from db.queue import get_artifact

    payload = get_artifact(session, job_id, "flow_asset_addresses")
    if not isinstance(payload, dict):
        return {}
    receivers = payload.get("receivers")
    if not isinstance(receivers, list):
        return {}
    out: dict[str, Any] = {}
    for receiver in receivers:
        if not isinstance(receiver, dict):
            continue
        selector = receiver.get("asset_getter_selector")
        if not selector:
            continue
        out[str(selector)] = receiver
    return out


# ---------------------------------------------------------------- claim reads


def _claims(func: Any) -> list[dict[str, Any]]:
    raw = func.claims
    if not isinstance(raw, list):
        return []
    return [c for c in raw if isinstance(c, dict)]


def _claim_ids(func: Any) -> set[str]:
    return {str(c.get("claim_id")) for c in _claims(func) if c.get("claim_id")}


def _tier(claim: dict[str, Any]) -> str:
    return _TIER_TOKENS.get(str(claim.get("tier")), WITNESS_TIER_NOT_DETERMINED)


def _best_tier(tiers: set[str]) -> str:
    for tier in _TIER_RANK:
        if tier in tiers:
            return tier
    return WITNESS_TIER_NOT_DETERMINED


def _target_kinds(flow: dict[str, Any]) -> list[str | None]:
    """A ``several`` target expands to its members; an unreadable member fails closed."""
    target = flow.get("target_kind") or {}
    kind = target.get("kind")
    if kind != "several":
        return [kind]
    members = flow.get("target_kinds") or target.get("kinds") or []
    out: list[str | None] = []
    for member in members:
        if isinstance(member, dict):
            out.append(str(member["kind"]) if member.get("kind") else None)
        elif member:
            out.append(str(member))
    return out or [None]


def _static_destination_shape(claims: list[dict[str, Any]]) -> tuple[str | None, str]:
    """Replay of the static lattice over every out-flow of the function.

    Three rules, each of which fails OPEN if skipped: ``several`` reduces to its
    worst member; ``value_router`` flows are inside the conjunction; and a
    ``flow.out``/``value_router`` claim with no ``flows`` key BLOCKS — silence is
    not evidence. ``policy_derived`` blocks for the same reason.
    """
    considered: list[dict[str, Any]] = []
    for claim in claims:
        claim_id = str(claim.get("claim_id"))
        if claim_id not in ("flow.out", "value_router"):
            continue
        if claim.get("tier") == "policy_derived":
            return None, "blocked_policy_derived"
        witness = claim.get("witness") or {}
        flows = witness.get("flows")
        if flows is None:
            return None, "blocked_no_flows"
        # ``direction`` lives on the WITNESS. Read off a flow entry it is always
        # absent, which silently empties the conjunction.
        direction = str(witness.get("direction") or ("value_router" if claim_id == "value_router" else "out"))
        if direction not in ("out", "eth_out", "value_router"):
            continue
        considered.extend(f for f in flows if isinstance(f, dict))
    if not considered:
        return None, "no_out_flows"
    kinds: set[str | None] = set()
    for flow in considered:
        kinds.update(_target_kinds(flow))
    if None in kinds:
        return None, "unreadable_target_kind"
    known = {str(k) for k in kinds}
    if known <= K.FIXED_TARGET_KINDS:
        return "immutable_fixed", "static_conjunction"
    if known <= (K.FIXED_TARGET_KINDS | {K.ADMIN_TARGET_KIND}):
        return "storage_determined", "static_conjunction_admin"
    return None, "not_fixed"


def _amount_kinds(claims: list[dict[str, Any]]) -> set[str]:
    kinds: set[str] = set()
    for claim in claims:
        if str(claim.get("claim_id")) != "flow.out":
            continue
        for flow in (claim.get("witness") or {}).get("flows") or []:
            if not isinstance(flow, dict):
                continue
            kind = (flow.get("amount_kind") or {}).get("kind")
            if kind == "several":
                kinds.update(str(m) for m in (flow.get("amount_kinds") or []) if m)
            elif kind:
                kinds.add(str(kind))
    return kinds


def _flow_asset_class(claims: list[dict[str, Any]]) -> str | None:
    """native / ERC-20 partition of the out-flows, gated on ``from_is_self``.

    An absent ``from_is_self`` is not "this contract is the source": defaulting
    it true would mint a positive fact from a missing key on the gate that
    decides whether the per-asset value substitution runs at all.
    """
    native = erc20 = other = False
    for claim in claims:
        if str(claim.get("claim_id")) != "flow.out":
            continue
        for flow in (claim.get("witness") or {}).get("flows") or []:
            if not isinstance(flow, dict) or flow.get("from_is_self") is not True:
                continue
            kind = flow.get("kind")
            if kind in K.NATIVE_FLOW_KINDS:
                native = True
            elif kind in K.ERC20_FLOW_KINDS:
                erc20 = True
            elif kind:
                other = True
    if other or (native and erc20):
        return "mixed"
    if native:
        return "native_only"
    if erc20:
        return "erc20_only"
    return None


# ---------------------------------------------------------------- destination


@dataclass(frozen=True)
class _Destination:
    tri: Tri[str]
    severity: float | None
    basis: str
    notes: tuple[str, ...] = ()


_UNDETERMINED_DESTINATION = _Destination(tri=Tri[str].not_determined(), severity=None, basis=NOT_DETERMINED)


def _exec_destination(claim_id: str, witness: dict[str, Any]) -> _Destination:
    """The delegatecall/exec destination, and what it licenses.

    An ``indeterminate`` / ``unresolved_operand`` / ``not_determined``
    destination is NOT ``destination_unconstrained``. It fails to
    ``not_determined`` and yields no severity, so the row never enters the grade
    — absence of a resolved constraint is never proof the destination is open.
    """
    destination = witness.get("destination") or {}
    target_kind = destination.get("target_kind") or witness.get("destination_kind")
    constraint = witness.get("destination_constraint") or {}
    state = constraint.get("state")

    if target_kind == "self":
        if state == "unconstrained_proven":
            # Two witnesses that cannot both be true: a destination fixed at
            # ``address(this)`` and a destination proven unconstrained. A
            # contradiction is not evidence for either side, and resolving it to
            # the benign arm would let one forged half buy the 0.0 severity.
            return _Destination(
                tri=Tri[str].not_determined(),
                severity=None,
                basis="destination_witness_contradiction(self+unconstrained_proven)",
                notes=("destination_witnesses_contradict",),
            )
        # Keyed on the target kind, never on the constraint state alone: a
        # ``constrained`` state says a guard exists, not that the destination is
        # this contract.
        severity = (
            K.DEST_SEVERITY_DELEGATECALL_SELF if claim_id == "delegatecall.execute" else K.DEST_SEVERITY_EXEC_SELF
        )
        # Only a literal self-binding corroborates self-ness. ``destination_operand``
        # says the guard is bound to the operand, which is equally true of an
        # operand that is not this contract, so it corroborates nothing here.
        corroborated = constraint.get("binding") in ("literal_self", "self") or constraint.get("guard") in (
            "literal_self",
            "self",
        )
        notes = ("destination_self_corroborated_by_literal",) if corroborated else ()
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, "self"),
            severity=severity,
            basis="destination_self_proven",
            notes=notes,
        )
    if target_kind == K.ADMIN_TARGET_KIND:
        return _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis="destination_storage_setter_deferred",
            notes=("destination_redirectable_by_unresolved_setter",),
        )
    if state == "constrained":
        guard = constraint.get("guard")
        if guard == "hash_commitment" and constraint.get("pins") is True:
            return _Destination(
                tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, "constrained:hash_commitment+pins"),
                severity=K.DEST_SEVERITY_HASH_COMMITMENT_PINS,
                basis="constrained:hash_commitment+pins",
            )
        if guard == "external_call_revert":
            return _Destination(
                tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, "constrained:external_call_revert"),
                severity=K.DEST_SEVERITY_EXTERNAL_CALL_REVERT,
                basis="constrained:external_call_revert",
                notes=("constraint_only_as_strong_as_external_contract",),
            )
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, f"constrained:{guard or 'unspecified'}"),
            severity=K.DEST_SEVERITY_CONSTRAINED_OTHER,
            basis=f"constrained:{guard or 'unspecified'}",
        )
    if state == "unconstrained_proven":
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_UNCONSTRAINED_PROVEN, "unconstrained_proven"),
            severity=K.DEST_SEVERITY_UNCONSTRAINED,
            basis="destination_unconstrained_proven",
        )
    return _UNDETERMINED_DESTINATION


def _flow_destination(claim: dict[str, Any], all_claims: list[dict[str, Any]]) -> _Destination:
    """The out-flow destination: fork shape first, static lattice second."""
    witness = claim.get("witness") or {}
    observed = witness.get("observed") or {}
    proved_by = observed.get("shape_proved_by")
    shape = observed.get("destination_shape") if proved_by in ("simulation", "static") else None
    basis = f"fork:{proved_by}" if shape else ""
    if shape is None:
        static_shape, static_reason = _static_destination_shape(all_claims)
        shape = static_shape
        basis = f"static_lattice:{static_reason}"

    if shape == "caller_arbitrary":
        if _tier(claim) != WITNESS_TIER_BEHAVIORAL_OBSERVED:
            # An existential needs a behavioural existence proof; without one
            # the escalation is withheld rather than assumed.
            return _Destination(
                tri=Tri[str].not_determined(),
                severity=None,
                basis="caller_arbitrary_without_behavioural_proof",
                notes=("caller_arbitrary_escalation_withheld",),
            )
        constraint_state = None
        for flow in witness.get("flows") or []:
            if isinstance(flow, dict):
                constraint_state = (flow.get("target_constraint") or {}).get("state") or constraint_state
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_UNCONSTRAINED_PROVEN, "caller_arbitrary"),
            severity=K.FLOW_SEVERITY_CALLER_ARBITRARY,
            basis=(
                "caller_arbitrary+unconstrained_proven"
                if constraint_state == "unconstrained_proven"
                else "caller_arbitrary_proven"
            ),
            notes=(f"target_constraint={constraint_state or 'absent'}",),
        )
    if shape == "immutable_fixed":
        return _Destination(
            tri=Tri.proven(DESTINATION_STATE_CONSTRAINED_PROVEN, "immutable_fixed"),
            severity=K.FLOW_SEVERITY_FIXED_DESTINATION,
            basis=basis or "immutable_fixed_proven",
            notes=("fixed_destination_conditional_on_upgrade_authority",),
        )
    if shape == "storage_determined":
        return _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis="destination_storage_determined_deferred",
            notes=("destination_redirectable_by_unresolved_setter",),
        )
    return _Destination(tri=Tri[str].not_determined(), severity=None, basis=basis or NOT_DETERMINED)


_DESTINATION_MEET_RANK = {
    DESTINATION_STATE_UNCONSTRAINED_PROVEN: 0,
    DESTINATION_STATE_CONSTRAINED_PROVEN: 1,
    DESTINATION_STATE_NOT_APPLICABLE: 2,
}


def _meet_destinations(parts: list[_Destination]) -> _Destination:
    """The MEET over every site: one unread destination makes the fold unread.

    Never last-wins. A function whose second delegatecall site could not be
    resolved has an unread destination as a whole, and the proven first site
    cannot vouch for it.
    """
    if not parts:
        return _UNDETERMINED_DESTINATION
    if any(not part.tri.is_determined for part in parts):
        undetermined = next(part for part in parts if not part.tri.is_determined)
        notes = tuple(sorted({n for part in parts for n in part.notes}))
        return _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis=undetermined.basis,
            notes=notes,
        )
    worst = min(parts, key=lambda p: (_DESTINATION_MEET_RANK[p.tri.state], -(p.severity or 0.0), p.basis))
    return _Destination(
        tri=worst.tri,
        severity=max((p.severity for p in parts if p.severity is not None), default=None),
        basis=worst.basis,
        notes=tuple(sorted({n for part in parts for n in part.notes})),
    )


# ---------------------------------------------------------------- reach/value


@dataclass(frozen=True)
class _Reach:
    state: str
    bound: str
    entity_keys: tuple[str, ...]
    basis: str
    magnitude: Tri[float]
    notes: tuple[str, ...] = ()


def _no_reach(basis: str, notes: tuple[str, ...] = ()) -> _Reach:
    return _Reach(
        state=VALUE_STATE_NOT_DETERMINED,
        bound=VALUE_BOUND_NOT_DETERMINED,
        entity_keys=(),
        basis=basis,
        magnitude=Tri[float].not_determined(),
        notes=notes,
    )


def _flow_reach(observed: dict[str, Any], facts: _ContractFacts, acting_key: str) -> _Reach:
    """The magnitude a flow is PROVEN to reach, and whose value it is."""
    reach_determined = _is_true(observed.get("reach_determined"))
    value_usd = _f(observed.get("observed_reach_value_usd")) if reach_determined else None
    holders = [_lower(h) for h in (observed.get("observed_reach_holders") or []) if h]

    if reach_determined and value_usd is not None:
        keys = tuple(sorted({entity_key(facts.chain, h) for h in holders}))
        if value_usd > 0.0 and not keys:
            # A proven magnitude whose HOLDER was never named belongs to an
            # entity this signal cannot identify. Attributing it to the analysed
            # deployment is the entity misattribution the register measures in
            # dollars, so the magnitude is published as unattributed instead.
            return _no_reach("observed_reach_value_usd_without_holder(not_determined)", ("reach_holder_not_named",))
        if value_usd <= 0.0 and not holders:
            return _Reach(
                state=VALUE_STATE_PROVEN_NO_REACH,
                bound=VALUE_BOUND_NOT_DETERMINED,
                entity_keys=(),
                basis="observed_reach_value_usd=0(proven)",
                magnitude=Tri[float].not_determined(),
            )
        return _Reach(
            state=VALUE_STATE_PROVEN_REACH,
            # The ENTITY-SET bound, and it is exact here: ``keys`` is every
            # holder the observation named, not a floor over them. A different
            # axis from the magnitude state below, which grades the DOLLARS.
            bound=VALUE_BOUND_EXACT,
            entity_keys=keys,
            basis="observed_reach_value_usd(fork-proven)",
            # F4. This is the ATTRIBUTION path: the probe moved a compile-time
            # constant amount and ``recipes._add_reach`` credited the holder's
            # ENTIRE priced balance for the pair, discarding the transferred
            # value. Nothing here witnesses that the call moves that balance, so
            # the figure is an upper bound on what one call moves — exactness is
            # unearnable in principle on this path. It is not re-pointed at
            # ``proven_floor`` either: that state's prose means "at least this
            # much", and this figure bounds the opposite direction.
            magnitude=_proven_number(MAGNITUDE_STATE_PROVEN_UPPER_BOUND, value_usd),
            notes=("reach_holder_is_not_this_entity",) if holders and acting_key not in keys else (),
        )

    gated = _is_true(observed.get("reach_indeterminate"))
    if "observed_reach_floor_usd" in observed:
        floor = _f(observed.get("observed_reach_floor_usd"))
        if gated and floor is not None and floor > 0.0:
            return _Reach(
                state=VALUE_STATE_PROVEN_REACH,
                bound=VALUE_BOUND_FLOOR,
                entity_keys=(acting_key,),
                basis="observed_reach_floor_usd(>= floor, reach_indeterminate)",
                magnitude=_proven_number(MAGNITUDE_STATE_PROVEN_FLOOR, floor),
            )
        # A 0.0 floor is "no proven bound": an all-unpriced sheet sums to the
        # same zero as a proven-empty one, and an ungated floor is not the
        # registered shape at all.
        return _no_reach(
            "observed_reach_floor_usd_zero(not_determined)" if gated else "observed_reach_floor_usd_ungated",
            ("reach_floor_not_a_bound",),
        )
    if gated:
        # The key's own ABSENCE is the third state: no balance row existed for
        # the acting deployment, so there is no floor to state.
        return _no_reach("observed_reach_floor_absent(not_determined)", ("reach_floor_absent",))

    priced = _f(observed.get("observed_reach_priced_usd"))
    if priced is not None:
        priced_holders = [_lower(h) for h in (observed.get("observed_reach_priced_holders") or []) if h]
        keys = tuple(sorted({entity_key(facts.chain, h) for h in priced_holders})) or (acting_key,)
        return _Reach(
            state=VALUE_STATE_PROVEN_REACH,
            bound=VALUE_BOUND_FLOOR,
            entity_keys=keys,
            basis="observed_reach_priced_usd(>= floor)",
            magnitude=_proven_number(MAGNITUDE_STATE_PROVEN_FLOOR, priced),
            notes=("reach_partially_priced",),
        )
    if _is_true(observed.get("contract_balance_seeded")):
        # The contract's own balance was overridden before the payout, so the
        # verdict proves a code capability, not an outflow of present treasury.
        return _no_reach("contract_balance_seeded(not_determined)", ("reach_seeded_balance_only",))
    return _no_reach("reach_not_witnessed(not_determined)")


def _proving_execution_gate(facts: _ContractFacts, func: Any, entries: list[dict[str, Any]]) -> Tri[dict[str, Any]]:
    """The execution that proved this signal's magnitude, as a gate envelope.

    The gate answers a question the distiller can ALWAYS answer — "does a
    persisted execution record exist for this signal?" — which is why both of its
    states are proven. The record's own three-state answer to the different
    question ("what execution proved this figure?") rides inside the payload,
    together with the typed reason where there is none. It has to be spelled that
    way round: a ``Tri.not_determined()`` envelope may carry no value at all, so
    routing the negative through it would delete the reason, and a reader could
    not tell a row that predates the record from a transcript that failed to
    store.

    Read off the claim witness the effects→claims bridge projects wherever the
    record is persisted — that is the cheap path and the one every future verdict
    takes. Where the residue carries none, the verdict's own transcript is read
    (:class:`_TranscriptReader`), because the call IS in there and "not written
    to the column" is not "not determined". Every verdict in the reference corpus
    predates the write, so the fallback is the whole of the corpus's coverage
    today and the fast path is the whole of it tomorrow. A fault reaching the
    transcript keeps its own reason and is NOT collapsed into the residue's.

    Which entry is read is :func:`_cited_verdict_entry`'s decision and NOT this
    function's, so the execution published here and the ``effect_verdict_id`` the
    signal publishes are the same row by construction rather than by two
    independent scans that happen to agree. They did not agree before: this
    function took the FIRST verdict-bearing entry and the signal took the LAST,
    which on a claim carrying two would have paired one verdict's dollars with
    another's caller — the failure ``_destination_magnitudes`` forbids one file
    over. (No signal in the reference corpus carries two, so the disagreement was
    latent; a comment asserting an invariant the code did not hold is the part
    that was live.)
    """
    entry = _cited_verdict_entry(entries)
    if entry is None:
        return Tri.proven(EX.GATE_STATE_NOT_RECORDED, EX.not_determined(EX.REASON_NO_VERDICT).as_json())
    witness = entry.get("witness") or {}
    verdict_id = int(witness["effect_verdict_id"])
    verdict = next((v for v in facts.verdicts.get(func.id, []) if v.id == verdict_id), None)
    if verdict is None:
        record = EX.not_determined(EX.REASON_VERDICT_NOT_LOCATED, effect_verdict_id=verdict_id)
    else:
        observed = witness.get("observed") or {}
        transcript_ptr = getattr(verdict, "transcript_ptr", None)
        record = EX.from_residue(
            observed.get(PROVING_EXECUTION_KEY),
            transcript_ptr=transcript_ptr,
            effect_verdict_id=verdict_id,
        )
        if not record.is_recorded and facts.transcripts is not None:
            record = facts.transcripts.execution(transcript_ptr=transcript_ptr, effect_verdict_id=verdict_id)
    state = EX.GATE_STATE_RECORDED if record.is_recorded else EX.GATE_STATE_NOT_RECORDED
    return Tri.proven(state, record.as_json())


def _verdict_bearing_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every claim entry naming an effect verdict, in stored order."""
    return [e for e in entries if ((e.get("witness") or {}).get("effect_verdict_id")) is not None]


def _cited_verdict_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The ONE entry whose verdict this signal is about, or ``None``.

    The LAST verdict-bearing entry, which is the rule the published
    ``effect_verdict_id`` already used — preserved rather than replaced, because
    changing which verdict a signal cites is a claim change and this seam exists
    to remove a disagreement, not to introduce one.

    A claim carrying TWO verdicts is a genuine ambiguity and is disclosed at the
    call site rather than resolved silently here: the rule below is stored order,
    which is not evidence about which verdict the claim is really about.
    """
    bearing = _verdict_bearing_entries(entries)
    return bearing[-1] if bearing else None


def _repointed_entities(
    entry: dict[str, Any], facts: _ContractFacts
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Entities the witness itself names as where the value is / what is affected.

    A repoint adds a foreign entity to a reach set, which is the same act as the
    backlink licence one screen up — and it was performed with none of that
    function's checks: no protocol, no chain, no existence, and no check that the
    witness naming the entity is a witness that proved anything about value.

    Three admissions, each earned:

    * The witness must be a VALUE witness, and that is tested as an ALLOWLIST of
      the tiers that are one (``REPOINT_ADMISSIBLE_TIERS``). A denylist of
      ``policy_derived`` would admit every tier nobody has classified — including
      the ``not_determined`` an absent or unrecognised ``tier`` token falls to,
      which is precisely a witness that proved nothing. A ``policy_derived``
      claim is a static inference — the ``configures`` producer's own docstring
      concedes that "the written set-var stands in for the spec's 'read by the
      hook fn'" — and an inference about what a function configures is not
      evidence about where value sits.
    * The named address must be a contract of THIS protocol on THIS chain, the
      same three checks :func:`_licensed_reach_entities` makes.
    * The burn address is never an entity. It is the graph's single largest
      fan-out and the sentinel every renunciation writes.

    A repoint never supplies a magnitude and never upgrades ``value_state``:
    naming a callee proves a call, not that value moves. Refusals are returned
    rather than dropped, so a reach this scorer declined is visible on the signal
    instead of being absent from it.
    """
    from services.scoring.planes import is_zero_key

    witness = entry.get("witness") or {}
    keys: list[str] = []
    bases: list[str] = []
    refused: list[dict[str, Any]] = []
    tier = _tier(entry)
    for field_name, basis in (("callee", "witness.callee"), ("configures", "witness.configures")):
        named = witness.get(field_name)
        if not named:
            continue
        key = entity_key(facts.chain, named)
        if tier == WITNESS_TIER_POLICY_DERIVED:
            why = "witness_tier_policy_derived(a static inference, not a value witness)"
        elif tier not in REPOINT_ADMISSIBLE_TIERS:
            why = f"witness_tier_not_determined({tier}; no tier token this scorer can vouch for)"
        elif is_zero_key(key):
            why = "zero_address_is_a_burn_sentinel_not_an_entity"
        elif key not in facts.protocol_entities:
            why = "named_entity_is_not_a_contract_of_this_protocol_on_this_chain"
        else:
            keys.append(key)
            bases.append(basis)
            continue
        refused.append({"entity_key": key, "basis": basis, "witness_tier": tier, "why": why})
    return keys, bases, refused


# ---------------------------------------------------------------- the signals


def _signals_for_function(facts: _ContractFacts, func: Any, *, job_id: Any) -> list[FunctionSignal]:
    claims = _claims(func)
    if not claims:
        return []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for claim in claims:
        claim_id = claim.get("claim_id")
        if claim_id:
            grouped[str(claim_id)].append(claim)

    # The register's own entity rule: the runtime address is
    # ``effective_functions.deployment_address`` falling back to
    # ``contracts.address``. The fallback is licensed there because a row with no
    # deployment address IS analysed at the contract's own address.
    deployment_address = _lower(func.deployment_address) if func.deployment_address else facts.address
    acting_key = entity_key(facts.chain, deployment_address)
    openness = _openness(func)
    principals = facts.principals.get(func.id, [])
    exact_empty, exact_empty_notes = _exact_empty_gate(func, principals)
    latch = _latch_gate(func)

    signals: list[FunctionSignal] = []
    for claim_id in sorted(grouped):
        signals.append(
            _build_signal(
                facts,
                func,
                claim_id=claim_id,
                entries=grouped[claim_id],
                all_claims=claims,
                deployment_address=deployment_address,
                acting_key=acting_key,
                openness=openness,
                principals=principals,
                exact_empty=exact_empty,
                exact_empty_notes=exact_empty_notes,
                latch=latch,
                job_id=job_id,
            )
        )
    return signals


def _openness(func: Any) -> str:
    value = func.authority_openness
    if value in (OPENNESS_OPEN, OPENNESS_RESTRICTED, OPENNESS_NOT_DETERMINED):
        return str(value)
    # NULL predates the column and cannot be read as any of the three; the
    # boolean sibling merges "restricted" with "unread" and is not consulted.
    return OPENNESS_NOT_DETERMINED


def _exact_empty_gate(func: Any, principals: list[Any]) -> tuple[Tri[dict[str, Any]], set[str]]:
    """The SERVED earned-negative gate. Never re-derived here (B16.3).

    The withheld arm is disclosed rather than dropped: a function whose caller
    set is an empty ``finite_set`` that did not earn the credit is neither
    unreachable nor reachable, and its shortfall names which witness is missing.
    """
    from services.policy.capability_surface import exact_empty_credit

    capability = func.capability_expr
    if not isinstance(capability, dict):
        return Tri[dict[str, Any]].not_determined(), set()
    verdict = exact_empty_credit(capability)
    if verdict.get("verdict") == "earned" and not principals:
        return Tri.proven("earned", verdict), set()
    notes: set[str] = set()
    if verdict.get("verdict") == "not_determined" and capability.get("members") == []:
        notes.add("empty_caller_set_not_earned")
    return Tri[dict[str, Any]].not_determined(), notes


def _latch_gate(func: Any) -> Tri[dict[str, Any]]:
    """A ``one_shot`` latch witness, if the resolver published one.

    ``consumed`` is a mutable now-fact — re-openable by the upgrade authority of
    the proxy it was read at — so it is carried as an annotation whose strength
    is tied to that authority, never as a permanent credit.
    """
    conditions = func.conditions
    if not isinstance(conditions, list):
        return Tri[dict[str, Any]].not_determined()
    for condition in conditions:
        if not isinstance(condition, dict) or condition.get("kind") != "one_shot":
            continue
        witness = condition.get("latch_witness")
        if not isinstance(witness, dict) or not witness.get("probe_block"):
            # Absent, or read at no reproducible height: the weakest branch.
            continue
        return Tri.proven(
            "witnessed",
            {
                "latch_state": condition.get("latch_state"),
                "latch_basis": witness.get("latch_basis"),
                "probe_block": witness.get("probe_block"),
                "probe_address": witness.get("probe_address"),
                "slot": witness.get("slot"),
                "reopenable_by": "the upgrade authority of the probed proxy",
            },
        )
    return Tri[dict[str, Any]].not_determined()


def _build_signal(
    facts: _ContractFacts,
    func: Any,
    *,
    claim_id: str,
    entries: list[dict[str, Any]],
    all_claims: list[dict[str, Any]],
    deployment_address: str,
    acting_key: str,
    openness: str,
    principals: list[Any],
    exact_empty: Tri[dict[str, Any]],
    exact_empty_notes: set[str],
    latch: Tri[dict[str, Any]],
    job_id: Any,
) -> FunctionSignal:
    fields: dict[str, Any] = not_determined_signal_defaults()
    notes: set[str] = set()
    citations: list[dict[str, Any]] = []
    gates: dict[str, Any] = {
        "exact_empty_credit": exact_empty.to_json(),
        "latch_witness": latch.to_json(),
        "reach_magnitude_usd": Tri[float].not_determined().to_json(),
    }

    notes.update(exact_empty_notes)
    fields["witness_tier"] = _best_tier({_tier(entry) for entry in entries})

    # --- destination -------------------------------------------------------
    destination = _UNDETERMINED_DESTINATION
    if claim_id in ("delegatecall.execute", "exec.arbitrary"):
        destination = _meet_destinations([_exec_destination(claim_id, e.get("witness") or {}) for e in entries])
        gates["destination_basis"] = Tri.proven("basis", destination.basis).to_json()
    elif claim_id == "flow.out":
        destination = _meet_destinations([_flow_destination(e, all_claims) for e in entries])
        gates["destination_basis"] = Tri.proven("basis", destination.basis).to_json()
    elif claim_id in DESTINATION_FREE_CLAIMS:
        destination = _Destination(
            tri=Tri.proven(DESTINATION_STATE_NOT_APPLICABLE, DESTINATION_SHAPE_NOT_APPLICABLE),
            severity=None,
            basis="not_applicable",
        )
    else:
        # Not in the bearing tuple is not the same as destination-free. A claim
        # this scorer has no destination model for publishes not_determined:
        # stamping "there is no destination here" from the absence of a rule is
        # the same absence-as-a-witness move in a quieter place.
        destination = _Destination(
            tri=Tri[str].not_determined(),
            severity=None,
            basis="destination_model_absent(not_determined)",
        )
    fields["destination"] = destination.tri
    notes.update(destination.notes)

    if claim_id == "flow.out" and not destination.tri.is_determined:
        for verdict in facts.verdicts.get(func.id, []):
            if verdict.verdict != "proven" or not verdict.concrete_destination:
                continue
            # Gated on ``shape_proved_by``: with no proven shape this is one
            # destination from one probe — an existential, which cannot prove a
            # fixed destination and does not enter the grade.
            citations.append(
                {
                    "field": "effect_verdicts.concrete_destination",
                    "value": _lower(verdict.concrete_destination),
                    "gate": "shape_proved_by=none",
                    "reading": "existential; observed on the witnessed path only",
                }
            )
            notes.add("concrete_destination_existential_not_a_fixed_destination")

    # --- severity ----------------------------------------------------------
    severity, severity_basis, severity_notes = _severity(
        facts,
        func,
        claim_id=claim_id,
        entries=entries,
        destination=destination,
        openness=openness,
        deployment_address=deployment_address,
        self_gated=_function_is_self_gated(facts, func),
    )
    fields["severity"] = severity
    fields["severity_basis"] = severity_basis
    notes.update(severity_notes)

    # --- authority / principals -------------------------------------------
    fields["authority_openness"] = openness
    if openness == OPENNESS_OPEN:
        fields["principal_state"] = PRINCIPAL_STATE_NONE_REQUIRED
        fields["principal_refs"] = ()
    elif principals:
        fields["principal_state"] = PRINCIPAL_STATE_ENUMERATED
        fields["principal_refs"] = tuple(
            PrincipalRef(function_principal_id=p.id, chain=facts.chain, address=_lower(p.address)) for p in principals
        )
    else:
        fields["principal_state"] = PRINCIPAL_STATE_NOT_DETERMINED
        fields["principal_refs"] = ()
        if severity.state == SEVERITY_STATE_PROVEN:
            notes.add("restricted_privileged_no_principal")

    # --- reach gate --------------------------------------------------------
    licensed = facts.licensed_reach_entities
    fields["reach_gate_state"] = REACH_GATE_LICENSED if licensed else REACH_GATE_NOT_DETERMINED
    if licensed:
        citations.append({"field": "gated_contract_backlink", "value": licensed})

    # --- value -------------------------------------------------------------
    reach = _reach_for_claim(
        facts,
        claim_id=claim_id,
        entries=entries,
        acting_key=acting_key,
        gates=gates,
        citations=citations,
    )
    extra_keys: list[str] = []
    if reach.state == VALUE_STATE_PROVEN_REACH and licensed:
        extra_keys = [entry["entity_key"] for entry in licensed]
    if licensed:
        # ``licensed`` is a fact about the GATE — this contract is the gating
        # contract of those vaults — and it is stamped whatever this signal's own
        # reach turned out to be. The licence is consumed as a reach key only
        # where the signal ALSO proved reach; on every other signal the state
        # names a witness that was cited and not spent, and reading it as a
        # consumed reach key is the laundering this field was corrected to stop.
        citations.append(
            {
                "field": "reach_gate_state",
                "value": REACH_GATE_LICENSED,
                "licensed_keys_cited": len(licensed),
                "licensed_keys_consumed": len(extra_keys),
                "reading": (
                    "licensed names the gate witness, not a consumed reach key: the keys are "
                    "added to this signal's reach only where the signal proved reach of its own"
                ),
            }
        )
    keys = tuple(sorted(set(reach.entity_keys) | set(extra_keys)))
    fields["value_state"] = reach.state
    fields["value_bound"] = reach.bound
    fields["value_entity_keys"] = keys if reach.state == VALUE_STATE_PROVEN_REACH else ()
    fields["value_basis"] = reach.basis
    gates["reach_magnitude_usd"] = reach.magnitude.to_json()
    # F6: the execution that PROVED the figure above, carried BESIDE it. The two
    # travel together or the fold publishes a number with no account of the call
    # it came from — which is what every consumer of this magnitude has had until
    # now, because the caller exists only inside the transcript blob.
    gates[PROVING_EXECUTION_KEY] = _proving_execution_gate(facts, func, entries).to_json()
    notes.update(reach.notes)

    # --- claim-scoped gates -------------------------------------------------
    if claim_id == "flow.out":
        gates.update(_flow_gates(facts, entries, all_claims))
    if claim_id == "pause.set":
        gates.update(_pause_gates(facts, func, entries))

    # ONE rule, read once, so the signal's own citation and the execution record
    # in ``gate_inputs`` name the same verdict by construction. Every
    # verdict-bearing entry still travels as a citation below — the ambiguity is
    # disclosed, not collapsed — and a claim naming more than one says so in its
    # notes rather than letting stored order settle it in silence.
    cited = _cited_verdict_entry(entries)
    if cited is not None:
        fields["effect_verdict_id"] = int((cited.get("witness") or {})["effect_verdict_id"])
    if len(_verdict_bearing_entries(entries)) > 1:
        notes.add("multiple_effect_verdicts_on_one_claim")
    for entry in entries:
        witness = entry.get("witness") or {}
        verdict_id = witness.get("effect_verdict_id")
        if verdict_id is not None:
            verdict = next((v for v in facts.verdicts.get(func.id, []) if v.id == int(verdict_id)), None)
            # inv.9: a published verdict carries its transcript pointer, or is
            # published WITHOUT a traceability claim — never as "no transcript".
            citations.append(
                {
                    "field": "claims[].witness.effect_verdict_id",
                    "value": int(verdict_id),
                    "transcript_ptr": (verdict.transcript_ptr if verdict is not None else None) or NOT_DETERMINED,
                    "verdict": verdict.verdict if verdict is not None else NOT_DETERMINED,
                }
            )
        observed = witness.get("observed") or {}
        if observed.get("block_number") is not None:
            citations.append(
                {
                    "field": "observed.block_number",
                    "value": observed.get("block_number"),
                    "block_source": observed.get("block_source"),
                }
            )
    if isinstance(func.authority_roles, list) and func.authority_roles:
        citations.append(
            {
                "field": "effective_functions.authority_roles",
                "value": [r.get("role") for r in func.authority_roles if isinstance(r, dict)],
                "note": "role ids are meaningful only per registry; cited, never keyed on",
            }
        )

    fields["gate_inputs"] = gates
    fields["citations"] = tuple(citations)
    fields["witness_notes"] = tuple(sorted(notes))

    return FunctionSignal(
        job_id=job_id,
        protocol_id=facts.protocol_id,
        contract_id=facts.contract_id,
        chain=facts.chain,
        deployment_address=deployment_address,
        function_name=str(func.function_name),
        claim_id=claim_id,
        selector=str(func.selector or NO_SELECTOR),
        function_id=func.id,
        **fields,
    )


def _reach_for_claim(
    facts: _ContractFacts,
    *,
    claim_id: str,
    entries: list[dict[str, Any]],
    acting_key: str,
    gates: dict[str, Any],
    citations: list[dict[str, Any]],
) -> _Reach:
    if claim_id == "flow.out":
        best: _Reach | None = None
        for entry in entries:
            observed = (entry.get("witness") or {}).get("observed") or {}
            candidate = _flow_reach(observed, facts, acting_key)
            if best is None or _reach_rank(candidate) > _reach_rank(best):
                best = candidate
        reach = best or _no_reach("reach_not_witnessed(not_determined)")
        for entry in entries:
            keys, bases, refused = _repointed_entities(entry, facts)
            _cite_refused_repoints(refused, citations)
            if keys and reach.state == VALUE_STATE_PROVEN_REACH:
                reach = _Reach(
                    state=reach.state,
                    bound=reach.bound,
                    entity_keys=tuple(sorted(set(reach.entity_keys) | set(keys))),
                    basis=reach.basis + "+" + ",".join(bases),
                    # The magnitude the flow witness proved, unchanged. A repoint
                    # widens WHERE that one call's value may sit; it does not
                    # multiply the call, and the per-call cap holds the sum of
                    # the widened key set to the figure the witness proved.
                    magnitude=reach.magnitude,
                    notes=reach.notes + ("reach_repointed_by_witness",),
                )
                citations.append({"field": bases[0], "value": keys})
        return reach

    if claim_id == "pause.set":
        # FIELDS §5: the value membership is GATED on the fork proof that the
        # latch takes effect. Charging an entity whose latch is unproven is the
        # balance-sheet error, so an unproven latch reaches nothing.
        effective = any(
            _is_true(((e.get("witness") or {}).get("observed") or {}).get("pause_effective")) for e in entries
        )
        if not effective:
            return _no_reach("pause_effective_not_witnessed(not_determined)", ("freeze_effectiveness_not_determined",))
        return _Reach(
            state=VALUE_STATE_PROVEN_REACH,
            bound=VALUE_BOUND_FLOOR,
            entity_keys=(acting_key,),
            basis="value_held_at_frozen_entity(pause_effective)",
            magnitude=Tri[float].not_determined(),
            notes=("freeze_immobilised_fraction_not_determined",),
        )

    repointed: list[str] = []
    bases: list[str] = []
    for entry in entries:
        keys, entry_bases, refused = _repointed_entities(entry, facts)
        _cite_refused_repoints(refused, citations)
        repointed.extend(keys)
        bases.extend(entry_bases)
    if claim_id not in K.BASE_SEVERITY:
        # A named callee is not a capability. Reading the repoint as one is what
        # promoted six ``flow.in`` rows from capability_not_scored to
        # proven_reach purely because a witness named an address — an upgrade of
        # the reach STATE out of a fact about call structure.
        return _no_reach("capability_not_scored(not_determined)")
    keys = tuple(sorted({acting_key, *repointed}))
    basis = "acting_entity" + ("+" + ",".join(sorted(set(bases))) if bases else "")
    return _Reach(
        state=VALUE_STATE_PROVEN_REACH,
        bound=VALUE_BOUND_FLOOR,
        entity_keys=keys,
        basis=basis,
        magnitude=Tri[float].not_determined(),
    )


def _cite_refused_repoints(refused: list[dict[str, Any]], citations: list[dict[str, Any]]) -> None:
    """A declined repoint is published, never absent.

    An admitted repoint travels as a citation; a refused one that travelled as
    nothing would be indistinguishable from a witness that named no entity at
    all, and the two are opposite facts about how much reach this row is not
    claiming.
    """
    for entry in refused:
        citations.append(
            {"field": entry["basis"], "value": entry["entity_key"], "admitted": False, "why": entry["why"]}
        )


def _reach_rank(reach: _Reach) -> tuple[int, int]:
    state_rank = {VALUE_STATE_PROVEN_REACH: 2, VALUE_STATE_PROVEN_NO_REACH: 1, VALUE_STATE_NOT_DETERMINED: 0}
    bound_rank = {VALUE_BOUND_EXACT: 2, VALUE_BOUND_FLOOR: 1, VALUE_BOUND_NOT_DETERMINED: 0}
    return state_rank[reach.state], bound_rank[reach.bound]


def _flow_gates(
    facts: _ContractFacts, entries: list[dict[str, Any]], all_claims: list[dict[str, Any]]
) -> dict[str, Any]:
    amount_kinds = _amount_kinds(all_claims)
    asset_class = _flow_asset_class(all_claims)
    observed_blocks = [(e.get("witness") or {}).get("observed") or {} for e in entries]
    identity = _token_identity(facts, entries)
    return {
        # ``token_identity`` proves exactly one NON-FUNGIBLE token moves, which
        # forbids pricing the row off a fungible balance sheet.
        "token_identity": (
            Tri.proven("proven", True) if "token_identity" in amount_kinds else Tri[bool].not_determined()
        ).to_json(),
        "asset_class": (Tri.proven("proven", asset_class) if asset_class else Tri[str].not_determined()).to_json(),
        "input_seeded": (
            Tri.proven("proven", True)
            if any(_is_true(o.get("input_seeded")) for o in observed_blocks)
            else Tri[bool].not_determined()
        ).to_json(),
        "contract_balance_seeded": (
            Tri.proven("proven", True)
            if any(_is_true(o.get("contract_balance_seeded")) for o in observed_blocks)
            else Tri[bool].not_determined()
        ).to_json(),
        "amount_capped_by_balance": (
            Tri.proven("proven", True) if "capped_by_balance" in amount_kinds else Tri[bool].not_determined()
        ).to_json(),
        "asset_identity": identity.to_json(),
    }


def _token_identity(facts: _ContractFacts, entries: list[dict[str, Any]]) -> Tri[dict[str, Any]]:
    """The W2 pricing precondition: is the moved asset's identity decidable?

    Satisfied only by a state-variable receiver whose address RESOLVED with a
    non-``not_determined`` invariant. A caller-named receiver fails it — a
    demotion, in the honest direction — and an absent plane is ``not_determined``
    because the plane did not run, never "no asset".
    """
    if not facts.asset_identity:
        return Tri[dict[str, Any]].not_determined()
    for entry in entries:
        witness = entry.get("witness") or {}
        for sink_id, receiver in sorted((witness.get("sink_receivers") or {}).items()):
            if not isinstance(receiver, dict):
                continue
            if receiver.get("receiver_provenance") != "contract_state_unresolved":
                continue
            selector = receiver.get("auto_getter_selector")
            resolved = facts.asset_identity.get(str(selector)) if selector else None
            if not isinstance(resolved, dict):
                continue
            if resolved.get("asset_address_status") != "resolved":
                continue
            if resolved.get("asset_identity_invariant") in (None, NOT_DETERMINED):
                continue
            return Tri.proven(
                "resolved",
                {
                    "sink_id": sink_id,
                    "asset_address": resolved.get("asset_address"),
                    "observed_at_block": resolved.get("observed_at_block"),
                    "asset_identity_invariant": resolved.get("asset_identity_invariant"),
                },
            )
    return Tri[dict[str, Any]].not_determined()


def _pause_gates(facts: _ContractFacts, func: Any, entries: list[dict[str, Any]]) -> dict[str, Any]:
    observed_blocks = [(e.get("witness") or {}).get("observed") or {} for e in entries]
    effective = any(_is_true(o.get("pause_effective")) for o in observed_blocks)
    blast: list[str] = []
    for observed in observed_blocks:
        blast.extend(str(x) for x in (observed.get("observed_blast_radius") or []))
    recovery = facts.pause_unset_principals
    return {
        "pause_effective": (Tri.proven("proven", True) if effective else Tri[bool].not_determined()).to_json(),
        "freeze_recovery_principals": (
            Tri.proven("enumerated", recovery) if recovery else Tri[list].not_determined()
        ).to_json(),
        # A count ratio over function names is a COVERAGE fraction, never a
        # fraction of dollars; it is cited and never multiplied into value.
        "freeze_coverage_fraction": (
            Tri.proven("observed_blast_radius", sorted(set(blast))) if blast else Tri[list].not_determined()
        ).to_json(),
    }


def _severity(
    facts: _ContractFacts,
    func: Any,
    *,
    claim_id: str,
    entries: list[dict[str, Any]],
    destination: _Destination,
    openness: str,
    deployment_address: str,
    self_gated: bool = False,
) -> tuple[Tri[float], tuple[str, ...], set[str]]:
    notes: set[str] = set()

    if claim_id in K.UNMODELLED_CLAIMS:
        notes.add("claim_type_not_scored")
        return Tri[float].not_determined(), (), notes
    if claim_id in K.PRODUCT_CLAIMS:
        # ``claim_id`` does not prove permissionlessness, so a not_determined
        # openness is not product and is surfaced rather than dropped.
        if openness == OPENNESS_NOT_DETERMINED:
            notes.add("product_claim_reachability_unproven")
        else:
            notes.add("product_surface")
        return Tri[float].not_determined(), (), notes
    if claim_id not in K.BASE_SEVERITY:
        notes.add("capability_has_no_severity_model")
        return Tri[float].not_determined(), (), notes

    if claim_id in K.DESTINATION_BEARING_SEVERITY:
        if destination.severity is None:
            notes.add("destination_not_determined_row_withheld")
            return Tri[float].not_determined(), (), notes
        return Tri.proven(SEVERITY_STATE_PROVEN, destination.severity), (destination.basis,), notes

    if claim_id == "pause.set":
        return _pause_severity(entries, notes)

    base = K.BASE_SEVERITY[claim_id]
    basis = ["capability_class_base"]

    if claim_id == "ownership.transfer":
        if any((e.get("witness") or {}).get("standard") == "default_admin_rules" for e in entries):
            base = min(base, K.OWNERSHIP_DEFAULT_ADMIN_RULES)
            basis.append("default_admin_rules_enforced_delay")
    elif claim_id == "authority.replace":
        owner = facts.registry_owner
        if owner and facts.solmate_mutators:
            # Escalation gated on POSITIVE proof: an owner resolves AND the role
            # mutators it would need are present on this contract.
            base = K.DEST_SEVERITY_UNCONSTRAINED
            basis.append("registry_owner_self_grant_escalation")
            notes.add("owner_may_grant_itself_any_role_on_this_registry")
        elif owner:
            notes.add("registry_escalation_mutators_unverified")
    elif claim_id == "timelock.set_delay":
        # No credit either way. "Every resolved principal is the contract itself"
        # is "no other caller RESOLVED", and the principal enumeration is a proven
        # LOWER BOUND on the caller set — the one thing it can never witness is
        # that the set is closed. The observation is published; the severity does
        # not move on it.
        notes.add("delay_gate_self_gated_lower_bound" if self_gated else "delay_change_gate_not_self_gated")

    return Tri.proven(SEVERITY_STATE_PROVEN, base), tuple(basis), notes


def _pause_severity(entries: list[dict[str, Any]], notes: set[str]) -> tuple[Tri[float], tuple[str, ...], set[str]]:
    """Built up from zero, from proven components only.

    The proven existence of a freeze capability is the first and unconditional
    component; a proven auto-expiry refines it downward. The sustainable-freeze
    component is added by the fold, and only where key-set dependence is PROVEN.
    Every undetermined recovery question — no recovery claim, an unresolved
    recovery principal, an unread freezing key set — leaves this rung exactly
    where it is, in either direction.
    """
    severity = K.BASE_SEVERITY["pause.set"] + K.FREEZE_CAPABILITY_PROVEN
    basis = ["freeze_capability_proven"]
    for entry in entries:
        observed = (entry.get("witness") or {}).get("observed") or {}
        bound = _f(observed.get("duration_bound_seconds"))
        if observed.get("auto_expiry") is True and bound is not None and bound <= K.FREEZE_AUTO_EXPIRY_MAX_SECONDS:
            severity = min(severity, K.FREEZE_AUTO_EXPIRY)
            basis.append("auto_expiry_witnessed")
        elif observed.get("auto_expiry") is False:
            # The fork CONTRADICTED the static constant. Recorded; no witness
            # sets the size of a raise, so none is taken.
            notes.add("fork_contradicted_static_duration_bound")
    return Tri.proven(SEVERITY_STATE_PROVEN, severity), tuple(basis), notes


__all__ = ["distill_contract_signals", "distill_job_signals"]
