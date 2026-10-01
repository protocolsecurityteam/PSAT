"""Per-contract fact loading, the execution-transcript reader, and the distiller entry points."""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from collections.abc import Iterable
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

# Why the flow-asset plane produced no receiver map; published on every refusal it causes.
ASSET_IDENTITY_LOADED = "loaded"
ASSET_IDENTITY_JOB_ABSENT = "job_absent"
ASSET_IDENTITY_ARTIFACT_ABSENT = "artifact_absent"
ASSET_IDENTITY_ARTIFACT_MALFORMED = "artifact_malformed"
ASSET_IDENTITY_NO_RECEIVERS = "no_receivers"

# W2 precondition refusals, ordered by how far the walk got so the furthest one is reported.
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

_ORPHAN_SAMPLE = 20

# So the fold never reads a ``dict.get`` default in place of a witness.
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


# By selector, not name, so homonyms like ``setUserRole(bytes32)`` can't earn the escalation.
_SOLMATE_MUTATOR_SELECTORS: dict[str, str] = {
    "0x67aff484": "setUserRole(address,uint8,bool)",
    "0x0ea9b75b": "setRoleCapability(uint8,bytes4,bool)",
    "0x4b5159da": "setPublicCapability(bytes4,bool)",
}
_TIMELOCK_ENTRYPOINTS = frozenset({"schedule", "scheduleBatch", "execute", "executeBatch"})

# Allowlist, not denylist: an absent or unknown tier resolves to ``not_determined`` and must not pass.
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
    """A numeric gate envelope, type-checked at construction: the JSONB payload is unchecked and a string "1e12"
    would still multiply.
    """
    number = _f(value)
    if number is None:
        raise ValueError(f"numeric gate payload must be a finite number, got {value!r}")
    return Tri.proven(state, number)


def _is_true(value: Any) -> bool:
    return value is True or str(value).lower() == "true"


def _lower(value: Any) -> str:
    return str(value or "").lower()


@dataclass
class _ContractFacts:
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
    # Reason from the vocabulary above.
    asset_identity_state: str = ASSET_IDENTITY_JOB_ABSENT
    # Protocol entity keys; a reach key outside this set names nothing this document can answer for.
    protocol_entities: set[str] = field(default_factory=set)
    # Recovers executions for verdicts predating the record. ``None`` (in-memory mode) means "not derivable here", not
    # "no execution".
    transcripts: _TranscriptReader | None = None


def distill_job_signals(
    session: Session, job: Any, *, contract_ids: Iterable[int] | None = None
) -> dict[int, list[FunctionSignal]]:
    """One job's planes to its contracts' signal rows, grouped by ``contract_id``.

    Grouped by contract alone because the persisting replace is contract-scoped; splitting by deployment address would
    make the second call delete the first's rows.

    Targeted effects recovery owns no contracts via Job.id; its explicit contract IDs select whole contracts, still
    restricted to the job's protocol.
    """
    from db.models import Contract

    query = session.query(Contract)
    if contract_ids is None:
        contracts = query.filter(Contract.job_id == job.id).order_by(Contract.id).all()
    else:
        requested = {int(contract_id) for contract_id in contract_ids}
        if job.protocol_id is None:
            raise ValueError("targeted signal distillation requires a protocol")
        contracts = (
            query.filter(Contract.id.in_(requested), Contract.protocol_id == job.protocol_id)
            .order_by(Contract.id)
            .all()
        )
        if {contract.id for contract in contracts} != requested:
            raise ValueError("targeted signal contracts must exist in the recovery job's protocol")
    out: dict[int, list[FunctionSignal]] = {}
    orphaned: list[int] = []
    for contract in contracts:
        if contract.protocol_id is None:
            # Counted rather than skipped: a protocol-less contract is a known orphaning class.
            orphaned.append(int(contract.id))
            continue
        if contract_ids is None:
            out[contract.id] = distill_contract_signals(session, contract, job_id=job.id)
        else:
            out[contract.id] = distill_contract_signals(
                session,
                contract,
                job_id=job.id,
                facts_job_id=contract.job_id or job.id,
            )
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


def distill_contract_signals(
    session: Session, contract: Any, *, job_id: Any, facts_job_id: Any = None
) -> list[FunctionSignal]:
    from .signals import _signals_for_function

    # Recovery reruns effects only; flow-asset artifacts belong to the original job.
    facts = _load_contract_facts(session, contract, job_id=facts_job_id or job_id)
    signals: list[FunctionSignal] = []
    for func in facts.functions:
        signals.extend(_signals_for_function(facts, func, job_id=job_id))
    signals.sort(key=lambda s: (s.deployment_address, s.selector, s.claim_id))
    return signals


# Artifact bodies are immutable, so caching by ``(job_id, artifact_name)`` can't give two answers. Tests clear
# it via :func:`clear_transcript_cache`.
_TRANSCRIPT_CACHE: dict[tuple[str, str], Any] = {}


def clear_transcript_cache() -> None:
    _TRANSCRIPT_CACHE.clear()


class _TranscriptReader:
    """Reads the execution behind a verdict out of the transcript it points at.

    Verdicts written before ``observed_residue`` carried the record still have the call in their transcript; this
    recovers it on the read path without writing the DB. Missing row, missing storage key and transport errors are
    distinct reasons.
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
                # Use the stored key: prefixes vary per job, and a constructed key would miss a third of the corpus.
                body = _artifact_row_to_value(row)
        except StorageKeyAbsent:
            body = EX.REASON_STORAGE_KEY_MISSING
        except StorageKeyMissing:
            body = EX.REASON_TRANSCRIPT_UNSTORED
        except Exception as exc:
            # A transport failure is its own, retryable reason. Logged as ``transcript_job_id`` because the ambient
            # ``job_id`` may differ and the formatter would drop a duplicate key.
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

    # The backlink node sits at the gating contract's address on the gated contract's graph, so match on the node's own
    # address; matching the payload would license the contract to reach itself. Protocol-scoped so other protocols'
    # entities aren't charged.
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
    """The Solmate registry's owner, only where the authority is proven zero.

    ``eth_call_impl_fallback`` reads are excluded: implementation storage reads as zero.
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
    """Whether this function's own resolved gate is the contract itself. Never read off a same-named sibling."""
    principals = facts.principals.get(func.id, [])
    return bool(principals) and all(_lower(p.address) == facts.address for p in principals)


def _licensed_reach_entities(session: Session, backlinks: list[Any], address: str, chain: str) -> list[dict[str, Any]]:
    """Entities whose value this contract's gated functions may be charged with.

    A reachability licence only: no typing, no magnitude, and a mismatch is not a negative (its payload matches the
    never-read one), so only proven ``true`` counts. The payload's ``gated_contract_address`` must name the node's own
    contract; self-licences are dropped.
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
            # Payload names a different contract: two facts, not a licence.
            continue
        anchor_chain = coalesce_chain(anchor.chain)
        if anchor_chain != chain:
            # Licences are per chain; crossing would alias same-address deployments.
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
    """``flow_asset_addresses`` receivers by selector, and why the map is empty.

    Absence is ``not_determined``, never a proven-empty set. No job, no artifact and an unrecognised body are distinct
    reasons carried onto every refusal.
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
