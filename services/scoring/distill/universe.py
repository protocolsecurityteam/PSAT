"""The protocol's discovered address universe (P4)."""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from utils.logging import record_degraded

logger = logging.getLogger(__name__)

# --- the protocol's discovered address universe (P4) --------------------------
# Every 20-byte address this protocol's own analysis has ever named. It exists
# for exactly one predicate: a balance-sheet token ABSENT from it is a token
# nothing in the protocol's code, dependencies, control graph, signals, effects,
# events or positions refers to.
#
# It is assembled HERE, in distill, and never in the value plane: the literal arm
# reads source artifacts out of object storage, and object-storage I/O inside the
# scorer's planes would break the fold's read-only-DB invariant. The fold
# RECEIVES the universe and does not build one.
_ADDRESS_LITERAL = re.compile(r"0x[0-9a-fA-F]{40}")


@dataclass(frozen=True)
class ProtocolUniverse:
    """The addresses this protocol's discovery has named, CHAIN-BLIND.

    ``addresses`` is flat and lowercased with no chain dimension, and that is a
    ruling rather than a simplification. Chain-scoping this set was measured on
    the reference corpus to falsely condemn $3,272,829.37 of real holdings —
    optimism's contracts carry no dependency, control-graph or signal rows at
    all, so a chain-scoped universe there is nearly empty — while buying no
    extra condemnation on the chain where the mass-distribution readings
    actually are. 5.28% of the set carries no chain attribution in the schema at
    all, and absence of an attribution is not proof of absence from a chain, so
    an address discovered anywhere is admitted everywhere.

    ``sources`` counts the DISTINCT addresses each source contributed (meter:
    address), before the union, so a source that contributes nothing is visible
    as a zero rather than as an absence.
    """

    addresses: frozenset[str]
    sources: dict[str, int]
    basis: str


def _literal_addresses(text: str) -> set[str]:
    return {match.group(0).lower() for match in _ADDRESS_LITERAL.finditer(text)}


def load_protocol_universe(session: Session, protocol_id: int) -> ProtocolUniverse | None:
    """Every address this protocol's discovery names, or ``None``.

    ``None`` is the fail-closed answer and it means exactly one thing: a source
    artifact could not be read, so the universe would be a SHORT one. A short
    universe is not a smaller claim — the predicate it feeds condemns what is
    ABSENT — so a missing arm makes the predicate condemn MORE, and the only
    safe response to an unreadable body is to build no universe at all and let
    every disposition refuse.

    The literal arm was measured on the reference corpus to spare 0 balance-sheet
    tokens that no other source already spares (24 distinct literals, 7 of them
    new to the universe): it is cheap and harmless rather than load-bearing,
    which corrects SHEET_OBSERVATION_SPEC.md §10.3's premise that omitting it
    fails open. It is kept because a token a contract's own source names is a
    token the protocol refers to, and that is the claim P4 makes.

    OPEN PERF ITEM, registered rather than fixed: that arm reads every source
    body of every job the protocol owns out of object storage on EVERY score —
    measured at **26.5 s per score** on the reference corpus (4,131 bodies), and
    it is the dominant cost of assembling this universe. Not cached here because
    a cache is a correctness surface, not a speed one: the shape it would take is
    a per-``(job_id, artifact digest)`` memo of the extracted ADDRESS LITERALS
    (a few hundred bytes) rather than of the bodies, keyed on something that
    changes when the artifact changes, so a stale entry cannot silently shorten
    the universe — and a short universe condemns MORE, which is why an
    invalidation bug here is a correctness bug and has to be designed as one.
    """
    # ``func`` is a local name throughout this module (an effective_function
    # row), so SQLAlchemy's is imported under its own.
    from sqlalchemy import func as sql_func
    from sqlalchemy import select, tuple_

    from db.models import (
        Contract,
        ContractDependency,
        ControlGraphEdge,
        ControlGraphNode,
        ControllerValue,
        DAppInteraction,
        EffectiveFunction,
        EffectVerdict,
        FunctionPrincipal,
        FunctionScoreSignal,
        IndexedEventLog,
        Job,
        MonitoredContract,
        PrincipalLabel,
        RestakingPosition,
    )
    from db.queue import get_source_files
    from utils.chains import UnknownChainError, chain_by_name

    # The contract population: the protocol's OWN rows, plus every contract
    # reachable through a job the protocol owns. The second arm is not
    # redundant — a discovery job's contracts carry ``protocol_id`` only once
    # they are attributed, and the addresses they name are the protocol's
    # references either way.
    job_ids = session.execute(select(Job.id).where(Job.protocol_id == protocol_id)).scalars().all()
    contracts = (
        session.execute(
            select(Contract).where(
                (Contract.protocol_id == protocol_id) | (Contract.job_id.in_(job_ids) if job_ids else False)
            )
        )
        .scalars()
        .all()
    )
    contract_ids = [contract.id for contract in contracts]
    source_jobs = sorted(
        {str(contract.job_id) for contract in contracts if contract.job_id} | {str(j) for j in job_ids}
    )

    sources: dict[str, set[str]] = defaultdict(set)

    def add(source: str, *values: Any) -> None:
        """Every 20-byte literal in each value, whatever shape carries it.

        The detail/witness blobs are read too, and deliberately: an address the
        analysis recorded inside a resolution record is an address this
        protocol's discovery named, which is exactly the claim P4 makes. The
        direction of the error also decides it — a source omitted here makes the
        universe SHORTER, and a shorter universe condemns MORE.
        """
        for value in values:
            if value is None:
                continue
            text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
            sources[source] |= _literal_addresses(text)

    for contract in contracts:
        add(
            "contracts",
            contract.address,
            contract.implementation,
            contract.beacon,
            contract.admin,
            contract.deployer,
            contract.secondary_implementations,
        )
    sources.setdefault("contracts", set())

    def rows(stmt: Any) -> list[Any]:
        return list(session.execute(stmt).all()) if contract_ids else []

    for row in rows(
        select(
            ContractDependency.dependency_address, ContractDependency.implementation, ContractDependency.admin
        ).where(ContractDependency.contract_id.in_(contract_ids))
    ):
        add("contract_dependencies", *row)
    sources.setdefault("contract_dependencies", set())

    for row in rows(
        select(ControlGraphNode.deployment_address, ControlGraphNode.address, ControlGraphNode.details).where(
            ControlGraphNode.contract_id.in_(contract_ids)
        )
    ):
        add("control_graph", *row)
    for row in rows(
        select(ControlGraphEdge.deployment_address, ControlGraphEdge.label, ControlGraphEdge.notes).where(
            ControlGraphEdge.contract_id.in_(contract_ids)
        )
    ):
        add("control_graph", *row)
    for row in rows(
        select(ControllerValue.deployment_address, ControllerValue.value, ControllerValue.details).where(
            ControllerValue.contract_id.in_(contract_ids)
        )
    ):
        add("control_graph", *row)
    for row in rows(
        select(
            PrincipalLabel.deployment_address, PrincipalLabel.address, PrincipalLabel.labels, PrincipalLabel.details
        ).where(PrincipalLabel.contract_id.in_(contract_ids))
    ):
        add("control_graph", *row)
    sources.setdefault("control_graph", set())

    for row in rows(
        select(FunctionPrincipal.address, FunctionPrincipal.details)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .where(EffectiveFunction.contract_id.in_(contract_ids))
    ):
        add("function_principals", *row)
    for row in rows(
        select(
            FunctionScoreSignal.deployment_address,
            FunctionScoreSignal.value_entity_keys,
            FunctionScoreSignal.gate_inputs,
        ).where(FunctionScoreSignal.contract_id.in_(contract_ids))
    ):
        add("function_principals", *row)
    sources.setdefault("function_principals", set())

    for row in rows(
        select(
            EffectVerdict.contract_address,
            EffectVerdict.concrete_destination,
            EffectVerdict.witness,
            EffectVerdict.observed_residue,
        )
        .join(EffectiveFunction, EffectiveFunction.id == EffectVerdict.function_id)
        .where(EffectiveFunction.contract_id.in_(contract_ids))
    ):
        add("effect_verdicts", *row)
    sources.setdefault("effect_verdicts", set())

    for row in session.execute(
        select(DAppInteraction.to_address).where(DAppInteraction.protocol_id == protocol_id)
    ).all():
        add("dapp_interactions", *row)
    sources.setdefault("dapp_interactions", set())

    # EMITTERS ONLY. The counterparty arm of ``indexed_event_logs`` — the
    # addresses inside a log's topics — is 1,844,985 addresses on this corpus,
    # 300x the core universe and essentially every user EOA that ever touched the
    # protocol. Admitting it would spare every token any user ever held, which is
    # not what "the protocol refers to this address" means. The exclusion is
    # stated in ``basis`` so a consumer reads the scope of the claim rather than
    # inferring it.
    enrolled = session.execute(
        select(MonitoredContract.address, MonitoredContract.chain).where(MonitoredContract.protocol_id == protocol_id)
    ).all()
    add("monitored_event_emitters", *[address for address, _ in enrolled])
    pairs: list[tuple[int, str]] = []
    for address, chain in enrolled:
        try:
            pairs.append((int(chain_by_name(str(chain)).chain_id), str(address or "").lower()))
        except (UnknownChainError, ValueError, TypeError):
            # A monitored row whose chain name maps to no id. Its address is
            # already admitted above; only the log lookup is skipped, and a
            # guessed chain id would ask a different chain's question.
            continue
    if pairs:
        for row in session.execute(
            select(IndexedEventLog.event_address)
            .where(tuple_(IndexedEventLog.chain_id, sql_func.lower(IndexedEventLog.event_address)).in_(pairs))
            .distinct()
        ).all():
            add("monitored_event_emitters", *row)
    sources.setdefault("monitored_event_emitters", set())

    for row in session.execute(
        select(RestakingPosition.node_address, RestakingPosition.eigenpod)
        .where(RestakingPosition.protocol_id == protocol_id)
        .distinct()
    ).all():
        add("restaking_positions", *row)
    sources.setdefault("restaking_positions", set())

    literals: set[str] = set()
    for job_id in source_jobs:
        try:
            bodies = get_source_files(session, job_id)
        except RuntimeError as exc:
            # Fail closed, whole-universe. A partial read would build a SHORT
            # universe, and a short universe condemns MORE.
            #
            # Caught at ``RuntimeError`` because that is the widest thing this
            # call answers an unread body with, and every narrower one is a
            # subclass: the content-incomplete pair (``StorageContentAbsent`` /
            # ``StorageContentNotDetermined``, both ``db.storage.StorageError``)
            # AND the bare ``RuntimeError`` a row with a storage key raises when
            # object storage is not configured at all. The last one used to
            # escape and abort the score, which is the one direction this
            # function may not take: an unconfigured deployment must condemn
            # nothing, not fail the fold.
            #
            # Logged at the return because the whole universe is now ``None`` and
            # every downstream disposition turns off — published numbers move,
            # and nothing else in the process says so.
            logger.warning(
                "protocol universe fail-closed: source bodies unreadable, no universe built",
                extra={
                    "protocol_id": protocol_id,
                    # Not ``job_id``: the formatter keeps the ambient job bound
                    # by the context and would drop this one silently.
                    "source_job_id": str(job_id),
                    "source_jobs": len(source_jobs),
                    "exc_type": type(exc).__name__,
                },
            )
            record_degraded(
                phase="protocol_universe_source_read",
                exc=exc,
                context={"protocol_id": protocol_id, "source_job_id": str(job_id)},
            )
            return None
        for body in bodies.values():
            literals |= _literal_addresses(body)
    sources["source_artifact_literals"] = literals

    addresses = frozenset().union(*sources.values()) if sources else frozenset()
    return ProtocolUniverse(
        addresses=addresses,
        sources={name: len(values) for name, values in sorted(sources.items())},
        basis=(
            f"every 20-byte address named by protocol {protocol_id}'s discovery, over "
            f"{len(contracts)} contracts (contracts.protocol_id plus contracts reachable through a "
            "job the protocol owns), assembled CHAIN-BLIND from contracts, contract_dependencies, "
            "the control graph (nodes/edges/controller_values/principal_labels), function_principals, "
            "effect_verdicts, dapp_interactions, monitored-contract event EMITTERS, "
            "restaking_positions and source-artifact address literals read from object storage. "
            "The indexed_event_logs COUNTERPARTY arm is excluded — it is every address that ever "
            "appeared in a log topic, i.e. every user EOA, and membership there is not a "
            "protocol reference. Absence from this set is a floor over what the protocol refers "
            "to and never a proof that it refers to nothing else, which is why it is only ever "
            "one conjunct of a disposition"
        ),
    )
