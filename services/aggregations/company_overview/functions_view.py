"""Per-function payload for ``/api/company/{name}/functions``."""

from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from db.jsonb import jsonb_has_payload
from db.models import ControlGraphNode, ControllerValue, EffectiveFunction, PrincipalLabel
from services.governance.principals import _build_company_function_entry

from .entity_keys import _entity_key
from .jobs import (
    CompanyNotFound,
    _secondary_impl_contracts,
    _time_phase,
    prefetch_contracts,
    resolve_company_jobs,
    resolve_implementation_contracts,
)
from .principals import _build_principal_lookup

logger = logging.getLogger("services.aggregations.company_overview")


def build_functions_for_protocol(session: Session, name: str) -> dict[str, list[dict[str, Any]]]:
    """Return ``{"<chain>::<address>": [function_entries]}`` for every contract
    in the protocol, keyed by the composite entity token (:func:`_entity_key`,
    mirroring the frontend's ``entityKey``).

    Split out of ``build_company_overview`` so the heavy
    ``effective_functions`` query (1469 rows × per-function principal
    expansion, 120-290ms + 2.13 MB of payload on ether.fi) doesn't block
    the main /company TTFB and JSON parse. The frontend mounts the
    Surface canvas off the lighter main payload and fetches this in
    parallel; the function inspector renders a loading state until it
    lands.
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

    # Entities that are a secondary impl of some proxy are absorbed into that
    # proxy node (their functions surface there), so they get no standalone
    # entry — mirrors the canvas dedup for split-proxy admin impls. Keyed by the
    # composite entity token (the secondary is on its proxy's chain) so a
    # same-address standalone on another chain isn't suppressed.
    secondary_impl_entities = {
        _entity_key(cr.chain, s)
        for cr in contracts_by_job_id.values()
        if cr is not None and cr.is_proxy
        for s in (cr.secondary_implementations or [])
    }

    # Map each job's (chain, address) to the contract_ids whose EF rows it
    # should show — for a proxy: its EIP-1967 impl plus any split-proxy secondary
    # impls; for a plain contract: its own row. The key is the composite entity
    # token so a CREATE2 twin at the same address on two chains keeps each
    # chain's own analysis instead of collapsing last-wins.
    entity_key_to_ef_cids: dict[str, list[int]] = {}
    for job in jobs:
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("proxy_address"):
            continue
        if not job.address:
            continue
        contract_row = contracts_by_job_id.get(job.id)
        entity_chain = contract_row.chain if contract_row else None
        if _entity_key(entity_chain, job.address) in secondary_impl_entities:
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
            entity_key_to_ef_cids[_entity_key(entity_chain, job.address)] = cids

    relevant_cids = {cid for cids in entity_key_to_ef_cids.values() for cid in cids}
    ef_rows_by_cid: dict[int, list[EffectiveFunction]] = {}
    if relevant_cids:
        with _time_phase(timings_ms, "effective_functions"):
            ef_row_count = 0
            for ef in session.execute(
                select(EffectiveFunction)
                .where(EffectiveFunction.contract_id.in_(list(relevant_cids)))
                .options(selectinload(EffectiveFunction.principals))
            ).scalars():
                ef_rows_by_cid.setdefault(ef.contract_id, []).append(ef)
                ef_row_count += 1

    # Reuse the same principal_lookup the main path builds so labels and
    # resolved_type carry through to per-function principal entries.
    relevant_contract_ids: set[int] = {c.id for c in contracts_by_job_id.values() if c is not None}
    controller_values_by_cid: dict[int, list[ControllerValue]] = {}
    cgn_by_cid: dict[int, list[ControlGraphNode]] = {}
    terminal_walk_by_address: dict[str, dict[str, Any]] = {}
    if relevant_contract_ids:
        id_list = list(relevant_contract_ids)
        with _time_phase(timings_ms, "principal_lookup_inputs"):
            for cv in session.execute(
                select(ControllerValue).where(ControllerValue.contract_id.in_(id_list))
            ).scalars():
                controller_values_by_cid.setdefault(cv.contract_id, []).append(cv)
            for n in session.execute(
                select(ControlGraphNode).where(ControlGraphNode.contract_id.in_(id_list))
            ).scalars():
                cgn_by_cid.setdefault(n.contract_id, []).append(n)
            # Same terminal-walk forwarding as the main path: the per-function
            # principal payload built below is what ``InspectorCard`` renders
            # ``terminalControllerNote`` from, so wiring only ``build_governance_view``
            # would connect the plane on one endpoint and leave it dark on the other.
            for address, details in session.execute(
                select(PrincipalLabel.address, PrincipalLabel.details).where(
                    PrincipalLabel.contract_id.in_(id_list),
                    jsonb_has_payload(PrincipalLabel.details),
                    PrincipalLabel.details.has_key("terminal_principal"),
                )
            ).all():
                record = (details or {}).get("terminal_principal")
                if isinstance(record, dict) and address:
                    terminal_walk_by_address.setdefault(address.lower(), record)
    principal_lookup = _build_principal_lookup(
        contracts_by_job_id, controller_values_by_cid, cgn_by_cid, terminal_walk_by_address
    )

    out: dict[str, list[dict[str, Any]]] = {}
    with _time_phase(timings_ms, "serialize"):
        for key, ef_cids in entity_key_to_ef_cids.items():
            ef_rows = [ef for cid in ef_cids for ef in ef_rows_by_cid.get(cid, [])]
            out[key] = [
                _build_company_function_entry(ef, ef.principals or [], principal_lookup=principal_lookup)
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
