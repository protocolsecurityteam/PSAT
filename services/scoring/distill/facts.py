"""Per-contract fact loading, the execution-transcript reader, and the distiller entry points."""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.schema import (
    FunctionSignal,
    Tri,
    coalesce_chain,
    entity_key,
)
from utils import execution_record as EX
from utils.logging import record_degraded, record_stage_metric
from utils.scoring_status import (
    WITNESS_TIER_BEHAVIORAL_OBSERVED,
    WITNESS_TIER_IDIOM_STRUCTURAL,
    WITNESS_TIER_STANDARD_EXACT,
)

from .claims import _claim_ids
from .self_service import _PROVENANCE_CALLER_GATE

logger = logging.getLogger("services.scoring.distill")

# Why the flow-asset plane produced no receiver map for a contract. A closed
# vocabulary: the token is published on every refusal the empty map causes, so
# "the producer stopped writing the artifact" and "the body is not the shape
# this reader knows" stop spelling the same thing in the document.
ASSET_IDENTITY_LOADED = "loaded"
ASSET_IDENTITY_JOB_ABSENT = "job_absent"
ASSET_IDENTITY_ARTIFACT_ABSENT = "artifact_absent"
ASSET_IDENTITY_ARTIFACT_MALFORMED = "artifact_malformed"
ASSET_IDENTITY_NO_RECEIVERS = "no_receivers"

# The W2 precondition's refusal arms, each naming the conjunct that failed.
# Ordered by how far the walk got, so a signal that reached the invariant check
# reports that rather than the coarser miss some other entry took.
W2_PLANE_ABSENT = "asset_identity_plane_absent"
W2_NO_STATE_VAR_RECEIVER = "no_state_var_receiver"
W2_SELECTOR_UNRESOLVED = "selector_unresolved"
W2_STATUS_NOT_RESOLVED = "status_not_resolved"
W2_INVARIANT_NOT_DETERMINED = "invariant_not_determined"
_W2_ARM_RANK = (
    W2_NO_STATE_VAR_RECEIVER,
    W2_SELECTOR_UNRESOLVED,
    W2_STATUS_NOT_RESOLVED,
    W2_INVARIANT_NOT_DETERMINED,
)

# How many orphaned contract ids one WARNING carries. A job can hold thousands;
# the count is the fact and the ids are the sample that makes it actionable.
_ORPHAN_SAMPLE = 20

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
    # Why ``asset_identity`` is empty, from the closed vocabulary above. An empty
    # map with no reason is the collapse this field exists to stop.
    asset_identity_state: str = ASSET_IDENTITY_JOB_ABSENT
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
    orphaned: list[int] = []
    for contract in contracts:
        if contract.protocol_id is None:
            # A contract with no protocol has no document to be scored into. It
            # is a known orphaning class rather than a routine skip, so it is
            # counted where the job can see it instead of vanishing here.
            orphaned.append(int(contract.id))
            continue
        out[contract.id] = distill_contract_signals(session, contract, job_id=job.id)
    record_stage_metric("score_signal_contracts_skipped_null_protocol", len(orphaned))
    if orphaned:
        logger.warning(
            "score signals skipped for %d contract(s) with no protocol_id",
            len(orphaned),
            extra={
                "contracts_skipped": len(orphaned),
                "contracts_total": len(contracts),
                "contract_ids": orphaned[:_ORPHAN_SAMPLE],
            },
        )
    return out


def distill_contract_signals(session: Session, contract: Any, *, job_id: Any) -> list[FunctionSignal]:
    """Every signal for one contract. The unit both feeding modes share."""
    from .signals import _signals_for_function

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
        except Exception as exc:
            # A transport failure says nothing about the call, so it is its own
            # reason and invites a retry rather than asserting an absence.
            # ``transcript_job_id`` rather than ``job_id``: the transcript's job
            # is not always the job this read runs under, and the formatter
            # would drop a ``job_id`` key the ambient context already bound.
            logger.warning(
                "transcript body unreadable",
                extra={"transcript_job_id": str(job_id), "artifact_name": name, "exc_type": type(exc).__name__},
            )
            record_degraded(
                phase="score_signal_transcript_read",
                exc=exc,
                context={"transcript_job_id": str(job_id), "artifact_name": name},
            )
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
    facts.asset_identity, facts.asset_identity_state = _asset_identity(session, job_id)
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
        if row.source == "authority" and row.resolved_type == "zero" and provenance == _PROVENANCE_CALLER_GATE:
            zero_authority = True
        if (
            row.source == "owner"
            and row.resolved_type in ("safe", "timelock")
            and provenance == _PROVENANCE_CALLER_GATE
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


def _asset_identity(session: Session, job_id: Any) -> tuple[dict[str, Any], str]:
    """``flow_asset_addresses`` receivers by selector, and WHY the map is empty.

    Absence means the plane did not run for this job — ``not_determined``, never
    a proven-empty asset set. The three ways an empty map arises are not one
    fact: no job to read from, an artifact that was never written, and a body
    whose shape this reader does not recognise are different questions to
    whoever is deciding whether to look again. They are named apart and the
    token travels onto every refusal the empty map causes.
    """
    if job_id is None:
        return {}, ASSET_IDENTITY_JOB_ABSENT
    from db.queue import get_artifact

    payload = get_artifact(session, job_id, "flow_asset_addresses")
    if payload is None:
        return {}, ASSET_IDENTITY_ARTIFACT_ABSENT
    if not isinstance(payload, dict):
        return {}, ASSET_IDENTITY_ARTIFACT_MALFORMED
    receivers = payload.get("receivers")
    if not isinstance(receivers, list):
        return {}, ASSET_IDENTITY_ARTIFACT_MALFORMED
    out: dict[str, Any] = {}
    malformed = 0
    for receiver in receivers:
        if not isinstance(receiver, dict):
            malformed += 1
            continue
        selector = receiver.get("asset_getter_selector")
        if not selector:
            malformed += 1
            continue
        out[str(selector)] = receiver
    if out:
        return out, ASSET_IDENTITY_LOADED
    return {}, ASSET_IDENTITY_ARTIFACT_MALFORMED if malformed else ASSET_IDENTITY_NO_RECEIVERS
