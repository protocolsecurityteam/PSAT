"""Per-function payload for ``/api/company/{name}/functions``."""

from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from db.models import ControlGraphNode, ControllerValue, EffectiveFunction
from services.governance.principals import _build_company_function_entry

from .entity_keys import _entity_chain, _entity_key
from .jobs import (
    CompanyNotFound,
    _secondary_impl_contracts,
    _time_phase,
    prefetch_contracts,
    resolve_company_jobs,
    resolve_implementation_contracts,
)
from .prefetch import terminal_walk_by_entity
from .principals import _build_principal_lookup, _principal_lookup_for_chain
from .runtime_scope import (
    RuntimeKey,
    code_id,
    entry_key,
    principal_classification,
    runtime_key,
    scoped_rows,
    scoped_walks,
    with_classification,
)

logger = logging.getLogger("services.aggregations.company_overview")


def build_functions_for_protocol(session: Session, name: str) -> dict[str, list[dict[str, Any]]]:
    """``{"<chain>::<address>": [function_entries]}`` for the protocol.

    Split from ``build_company_overview`` because the ``effective_functions`` query (~2 MB on ether.fi) would block the
    main /company TTFB; the frontend fetches it in parallel.
    """
    timings_ms: dict[str, int] = {}
    start = time.monotonic()

    with _time_phase(timings_ms, "resolve_jobs"):
        protocol_row, jobs = resolve_company_jobs(session, name)
    if not jobs:
        raise CompanyNotFound(name)
    with _time_phase(timings_ms, "prefetch_contracts"):
        contracts_by_job_id = prefetch_contracts(session, jobs)
    with _time_phase(timings_ms, "resolve_implementation_contracts"):
        impl_job_by_entity, contracts_by_job_id = resolve_implementation_contracts(session, jobs, contracts_by_job_id)

    # Secondary impls are absorbed into their proxy node (mirrors canvas dedup); composite keys so a same-address
    # standalone on another chain survives.
    secondary_impl_entities = {
        _entity_key(cr.chain, s)
        for cr in contracts_by_job_id.values()
        if cr is not None and cr.is_proxy
        for s in ([cr.implementation] if cr.implementation else []) + (cr.secondary_implementations or [])
    }

    # Proxy -> its impl plus secondary impls; plain contract -> itself. Composite keys keep CREATE2 twins' analyses
    # separate.
    entity_key_to_ef_cids: dict[str, list[RuntimeKey]] = {}
    entity_metadata_keys: dict[str, list[RuntimeKey]] = {}
    for job in jobs:
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("proxy_address"):
            continue
        if not job.address:
            continue
        contract_row = contracts_by_job_id.get(job.id)
        entity_chain = contract_row.chain if contract_row else None
        if _entity_key(entity_chain, job.address) in secondary_impl_entities and not (
            contract_row and contract_row.is_proxy
        ):
            continue
        impl_addr = contract_row.implementation if (contract_row and contract_row.is_proxy) else None
        impl_job = impl_job_by_entity.get(_entity_key(entity_chain, impl_addr)) if impl_addr else None
        impl_contract = contracts_by_job_id.get(impl_job.id) if impl_job else None
        primary_cid = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)
        cids = [primary_cid] if primary_cid is not None else []
        cids += [
            sc.id
            for sc in _secondary_impl_contracts(contract_row, impl_job_by_entity, contracts_by_job_id)
            if sc.id != primary_cid
        ]
        if cids:
            entity = _entity_key(entity_chain, job.address)
            entity_key_to_ef_cids[entity] = [entry_key(cid, contract_row) for cid in cids]
            entity_metadata_keys[entity] = list(
                dict.fromkeys(
                    [
                        *entity_key_to_ef_cids[entity],
                        *([contract_row.id] if contract_row else []),
                    ]
                )
            )

    relevant_cids = {code_id(key) for keys in entity_key_to_ef_cids.values() for key in keys}
    ef_rows_by_cid: dict[RuntimeKey, list[EffectiveFunction]] = {}
    if relevant_cids:
        with _time_phase(timings_ms, "effective_functions"):
            ef_row_count = 0
            for ef in session.execute(
                select(EffectiveFunction)
                .where(EffectiveFunction.contract_id.in_(list(relevant_cids)))
                .options(selectinload(EffectiveFunction.principals))
            ).scalars():
                ef_rows_by_cid.setdefault(runtime_key(ef.contract_id, ef.deployment_address), []).append(ef)
                ef_row_count += 1

    relevant_contract_ids: set[int] = {c.id for c in contracts_by_job_id.values() if c is not None}
    controller_values_by_cid: dict[RuntimeKey, list[ControllerValue]] = {}
    cgn_by_cid: dict[RuntimeKey, list[ControlGraphNode]] = {}
    terminal_walk: dict[RuntimeKey, dict[str, dict[str, Any]]] = {}
    if relevant_contract_ids:
        id_list = list(relevant_contract_ids)
        with _time_phase(timings_ms, "principal_lookup_inputs"):
            for cv in session.execute(
                select(ControllerValue).where(ControllerValue.contract_id.in_(id_list))
            ).scalars():
                controller_values_by_cid.setdefault(runtime_key(cv.contract_id, cv.deployment_address), []).append(cv)
            for n in session.execute(
                select(ControlGraphNode).where(ControlGraphNode.contract_id.in_(id_list))
            ).scalars():
                cgn_by_cid.setdefault(runtime_key(n.contract_id, n.deployment_address), []).append(n)
            # ``InspectorCard`` renders ``terminalControllerNote`` from this payload, so wire it here as well as in
            # ``build_governance_view``.
            terminal_walk, _rows = terminal_walk_by_entity(session, id_list)

    classification = principal_classification(contracts_by_job_id, controller_values_by_cid, cgn_by_cid)
    out: dict[str, list[dict[str, Any]]] = {}
    with _time_phase(timings_ms, "serialize"):
        for key, ef_cids in entity_key_to_ef_cids.items():
            chain = _entity_chain(key)
            metadata_keys = entity_metadata_keys[key]
            principal_lookup = _build_principal_lookup(
                contracts_by_job_id,
                scoped_rows(controller_values_by_cid, metadata_keys),
                scoped_rows(cgn_by_cid, metadata_keys),
                scoped_walks(terminal_walk, metadata_keys),
            )
            chain_lookup = _principal_lookup_for_chain(with_classification(principal_lookup, classification), chain)
            ef_rows = [ef for cid in ef_cids for ef in ef_rows_by_cid.get(cid, [])]
            out[key] = [
                _build_company_function_entry(
                    ef, ef.principals or [], principal_lookup=chain_lookup, include_capability_expr=False
                )
                for ef in ef_rows
            ]

    total_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "Functions payload built: company=%s contracts=%d functions=%d total_ms=%d",
        name,
        len(out),
        sum(len(v) for v in out.values()),
        total_ms,
        extra={
            "phase": "build_functions_for_protocol",
            "duration_ms": total_ms,
            "company": name,
            "contract_count": len(out),
            "function_count": sum(len(v) for v in out.values()),
            "timings_ms": timings_ms,
        },
    )
    return out
