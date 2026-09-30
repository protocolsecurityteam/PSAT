"""Per-analysis detail payload for ``/api/analyses/{run_name}``. Returns ``None`` for the caller to map to 404."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from db.models import (
    Contract,
    ControllerValue,
    EffectiveFunction,
    Job,
    JobStatus,
    PrincipalLabel,
)

# One patch point for tests.
from routers import deps
from services.aggregations.action_summary import describe_action
from services.policy.capability_surface import capability_currency, exact_empty_credit

logger = logging.getLogger(__name__)


def _principal_label_payload(row: PrincipalLabel) -> dict[str, Any]:
    """One ``principal_labels`` row with two assertions narrowed.

    ``confidence`` is published as ``naming_rule``: it is the naming branch, returning ``high`` for both verified Safe
    signers and the final fallback, and can't express "not determined". Real confidence needs on-chain verification
    wiring this consumer doesn't own.

    ``label`` equals ``display_name`` on every observed row, so it's published only when they differ.
    """
    out: dict[str, Any] = {
        "address": row.address,
        "display_name": row.display_name,
        "resolved_type": row.resolved_type,
        "labels": list(row.labels or []),
        # Never omitted: key-absence marks a pre-rename payload.
        "naming_rule": row.confidence,
        "details": row.details or {},
        "graph_context": list(row.graph_context or []),
    }
    if row.label is not None and row.label != row.display_name:
        out["label"] = row.label
    return out


def _artifacts_or_degrade(
    session: Session,
    job_id: Any,
    not_determined: dict[str, str],
    proven_absent: dict[str, str],
) -> dict[str, Any]:
    """``get_all_artifacts`` for a page that may render partially, naming what didn't load:
    ``artifacts_not_determined`` (bucket couldn't be asked; may resolve) vs ``artifacts_body_absent`` (bucket
    answered; never will).

    No SPA consumer: the SPA reads per-artifact endpoints, which carry the same states in ``X-PSAT-Artifact-State``. The
    maps stay for API consumers.
    """
    try:
        return deps.get_all_artifacts(session, job_id)
    except deps.StorageContentIncomplete as exc:
        logger.error(
            "analysis detail for job %s is missing %d artifact bodies (%d not determined, %d proven absent)",
            job_id,
            len(exc.not_determined) + len(exc.proven_absent),
            len(exc.not_determined),
            len(exc.proven_absent),
        )
        not_determined.update(exc.not_determined)
        proven_absent.update(exc.proven_absent)
        return dict(exc.values or {})


def build_analysis_detail(session: Session, run_name: str) -> dict[str, Any] | None:
    stmt = select(Job).where(Job.name == run_name).order_by(Job.updated_at.desc()).limit(1)
    job = session.execute(stmt).scalar_one_or_none()
    if job is None:
        try:
            job = session.get(Job, run_name)
        except Exception:
            session.rollback()
    if job is None:
        job = session.execute(
            select(Job)
            .where(
                Job.address == run_name,
                Job.status == JobStatus.completed,
                Job.request["effects_resume_work_id"].astext.is_(None),
            )
            .order_by(Job.updated_at.desc())
            .limit(1)
        ).scalar_one_or_none()
    if job is None:
        return None

    not_determined: dict[str, str] = {}
    body_absent: dict[str, str] = {}
    all_artifacts = _artifacts_or_degrade(session, job.id, not_determined, body_absent)

    # ``copy_static_cache`` may have reassigned the Contract row to a newer job; chain-scoped.
    contract_row = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
    if contract_row is None and job.address:
        fallback_stmt = select(Contract).where(Contract.address == job.address.lower())
        job_chain = job.request.get("chain") if isinstance(job.request, dict) else None
        if job_chain:
            fallback_stmt = fallback_stmt.where(Contract.chain == job_chain)
        contract_row = session.execute(fallback_stmt.limit(1)).scalar_one_or_none()

    def _company_for(j: Job) -> str | None:
        seen: set[str] = set()
        current: Job | None = j
        while current is not None:
            if current.company:
                return current.company
            req = current.request if isinstance(current.request, dict) else {}
            parent_id = req.get("parent_job_id")
            if not isinstance(parent_id, str) or parent_id in seen:
                return None
            seen.add(parent_id)
            current = session.get(Job, parent_id)
        return None

    payload: dict[str, Any] = {
        "run_name": job.name or str(job.id),
        "job_id": str(job.id),
        "address": job.address,
        "contract_id": contract_row.id if contract_row else None,
        "company": _company_for(job),
        "deployer": contract_row.deployer if contract_row else None,
        "available_artifacts": sorted(all_artifacts.keys()),
    }

    for artifact_name in (
        "contract_analysis",
        "control_snapshot",
        "dependencies",
        "resolved_control_graph",
        "dependency_graph_viz",
        "upgrade_history",
        "principal_history",
        "predicate_trees",
    ):
        if artifact_name in all_artifacts and isinstance(all_artifacts[artifact_name], dict):
            payload[artifact_name] = all_artifacts[artifact_name]

    # Resolved lazily; a capability-resolution failure must not fail the whole response.
    if "predicate_trees" in all_artifacts and job.address:
        try:
            from services.resolution.capability_resolver import resolve_contract_capabilities

            # Scope by (job_id, chain) so another chain's controller rows don't leak in.
            req_chain = job.request.get("chain") if isinstance(job.request, dict) else None
            chain = (contract_row.chain if contract_row and contract_row.chain else None) or req_chain
            from db.models import derive_job_chain_id

            chain_id = getattr(job, "chain_id", None)
            if not isinstance(chain_id, int):
                chain_id = derive_job_chain_id(chain if isinstance(chain, str) else req_chain, job.address)
                assert chain_id is not None
            semantic_caps = resolve_contract_capabilities(
                session,
                address=job.address.lower(),
                chain_id=chain_id,
                job_id=job.id,
                chain=chain if isinstance(chain, str) else None,
            )
            if semantic_caps is not None:
                payload["semantic_capabilities"] = semantic_caps
        except Exception as exc:
            logger.warning(
                "semantic capability resolution failed for job %s; omitting capability enrichment: %s",
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )

    if contract_row:
        _populate_from_contract(session, payload, contract_row)

    request = job.request if isinstance(job.request, dict) else {}
    proxy_address = request.get("proxy_address")
    if proxy_address:
        proxy_stmt = (
            select(Job)
            .where(Job.address == proxy_address, Job.request["effects_resume_work_id"].astext.is_(None))
            .order_by(Job.updated_at.desc())
            .limit(1)
        )
        proxy_job = session.execute(proxy_stmt).scalar_one_or_none()
        if proxy_job:
            proxy_artifacts = _artifacts_or_degrade(session, proxy_job.id, not_determined, body_absent)
            for fallback_name in ("upgrade_history", "dependency_graph_viz", "dependencies"):
                if fallback_name in payload:
                    continue
                fallback = proxy_artifacts.get(fallback_name)
                if isinstance(fallback, dict):
                    payload[fallback_name] = fallback
    payload["proxy_address"] = proxy_address

    is_proxy = contract_row.is_proxy if contract_row else False
    impl_addr = contract_row.implementation if contract_row else None
    if is_proxy and impl_addr:
        impl_stmt = (
            select(Job)
            .where(Job.address == impl_addr, Job.request["effects_resume_work_id"].astext.is_(None))
            .order_by(Job.updated_at.desc())
            .limit(1)
        )
        impl_job = session.execute(impl_stmt).scalar_one_or_none()
        if impl_job:
            _inherit_from_impl(session, payload, job, impl_job, impl_addr, not_determined, body_absent)

    if isinstance(all_artifacts.get("contract_analysis"), dict):
        subject = all_artifacts["contract_analysis"].get("subject", {})
        payload["contract_name"] = subject.get("name", payload["run_name"])
        payload["summary"] = all_artifacts["contract_analysis"].get("summary")

    # Synthesis fallback mirroring the per-artifact upgrade_history endpoint; runs last, only for proxies (UpgradeEvent
    # rows only exist for them).
    if "upgrade_history" not in payload and contract_row is not None and getattr(contract_row, "is_proxy", False):
        from services.discovery.upgrade_history import synthesize_from_events

        synthesized = synthesize_from_events(session, contract_row)
        if synthesized:
            payload["upgrade_history"] = synthesized

    if not_determined:
        # Row exists but the bucket couldn't be asked; without this the SPA reads absence as never produced.
        payload["artifacts_not_determined"] = dict(sorted(not_determined.items()))
    if body_absent:
        # Bucket says the object is gone; re-asking won't change it.
        payload["artifacts_body_absent"] = dict(sorted(body_absent.items()))

    return payload


def _populate_from_contract(session: Session, payload: dict[str, Any], contract_row: Contract) -> None:
    ef_rows = list(
        session.execute(
            select(EffectiveFunction)
            .where(EffectiveFunction.contract_id == contract_row.id)
            .options(selectinload(EffectiveFunction.principals))
        ).scalars()
    )

    index_head = _index_frontier(session, contract_row)
    ef_list = _serialize_effective_functions(ef_rows, index_head=index_head)
    if ef_list:
        payload["effective_permissions"] = {
            "functions": ef_list,
            "contract_name": contract_row.contract_name,
            "contract_address": contract_row.address,
        }
        if "effective_permissions" not in payload.get("available_artifacts", []):
            payload["available_artifacts"] = sorted(
                set(payload.get("available_artifacts", [])) | {"effective_permissions"}
            )

    pl_rows = (
        session.execute(select(PrincipalLabel).where(PrincipalLabel.contract_id == contract_row.id)).scalars().all()
    )
    if pl_rows:
        payload["principal_labels"] = {
            "principals": [_principal_label_payload(p) for p in pl_rows],
            "contract_name": contract_row.contract_name,
            "contract_address": contract_row.address,
        }

    if "control_snapshot" not in payload:
        cv_rows = (
            session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract_row.id))
            .scalars()
            .all()
        )
        if cv_rows:
            payload["control_snapshot"] = _build_control_snapshot(contract_row, cv_rows)

    if "resolved_control_graph" not in payload:
        from db.models import ControlGraphEdge, ControlGraphNode

        cgn_rows = (
            session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id == contract_row.id))
            .scalars()
            .all()
        )
        cge_rows = (
            session.execute(select(ControlGraphEdge).where(ControlGraphEdge.contract_id == contract_row.id))
            .scalars()
            .all()
        )
        if cgn_rows:
            payload["resolved_control_graph"] = _build_control_graph(contract_row.address, cgn_rows, cge_rows)


def _index_frontier(session: Session, contract_row: Contract) -> int | None:
    """The event index's own frontier for this chain; ``None`` keeps currency ``not_determined`` rather than
    inventing a head.
    """
    from db.models import IndexedEventCursor
    from utils.chains import UnknownChainError, chain_by_name

    try:
        chain_id = chain_by_name(contract_row.chain or "ethereum").chain_id
    except (UnknownChainError, AttributeError):
        return None
    return session.execute(
        select(func.max(IndexedEventCursor.last_indexed_block)).where(IndexedEventCursor.chain_id == chain_id)
    ).scalar()


def _serialize_effective_functions(
    ef_rows: list[EffectiveFunction], *, index_head: int | None = None
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ef in ef_rows:
        direct_owner = None
        controller_principals: list[dict[str, Any]] = []
        signature_witnesses: list[dict[str, Any]] = []
        for fp in ef.principals or []:
            principal_dict = {
                "address": fp.address,
                "resolved_type": fp.resolved_type,
                "source_controller_id": fp.origin,
                "principal_type": fp.principal_type,
                "details": fp.details or {},
            }
            if fp.principal_type == "direct_owner" and direct_owner is None:
                direct_owner = principal_dict
            elif fp.principal_type == "signature_witness":
                signature_witnesses.append(principal_dict)
            else:
                controller_principals.append(principal_dict)
        _action_summary_text, _action_summary_kind, _action_summary_note = describe_action(
            ef.action_summary, getattr(ef, "claims", None), ef.effect_labels
        )
        entry: dict[str, Any] = {
            "function": ef.abi_signature or ef.function_name,
            "selector": ef.selector,
            "effect_labels": list(ef.effect_labels or []),
            "effect_targets": list(ef.effect_targets or []),
            "claims": list(getattr(ef, "claims", None) or []),
            # Reconciled against the structured planes; see services/aggregations/action_summary.
            "action_summary": _action_summary_text,
            "action_summary_kind": _action_summary_kind,
            "action_summary_note": _action_summary_note,
            "authority_public": ef.authority_public,
            # NULL on pre-column rows, passed through so it's distinguishable from the resolver's 'not_determined'.
            "authority_openness": getattr(ef, "authority_openness", None),
            "controllers": [{"principals": controller_principals}] if controller_principals else [],
            # Non-empty = witnessed, ``None`` = role-gated with role undetermined, ``[]`` = proven not role-gated. ``or
            # []`` would fold the middle into the last.
            "authority_roles": _authority_roles_state(ef.authority_roles),
            "direct_owner": direct_owner,
            "signature_witnesses": signature_witnesses,
        }
        capability_expr = getattr(ef, "capability_expr", None)
        if capability_expr is not None:
            entry["capability_expr"] = capability_expr
            entry["capability_currency"] = capability_currency(capability_expr, index_head=index_head)
            # Served beside the payload it gates: ``exact + members == []`` alone can't tell read-confirmed empty from
            # provenance-less.
            entry["exact_empty_credit"] = exact_empty_credit(capability_expr)
        conditions = getattr(ef, "conditions", None)
        if conditions is not None:
            entry["conditions"] = conditions
        status = getattr(ef, "status", None)
        if status is not None:
            entry["status"] = status
        out.append(entry)
    return out


def _authority_roles_state(column: Any) -> Any:
    """A non-empty list with no object members is unreadable, not a witnessed requirement: serve ``None``, matching
    ``services/governance/principals.py``.
    """
    if isinstance(column, list) and column and not any(isinstance(grant, dict) for grant in column):
        return None
    return column


def _build_control_snapshot(contract_row: Contract, cv_rows: Sequence[ControllerValue]) -> dict[str, Any]:
    return {
        "contract_name": contract_row.contract_name,
        "contract_address": contract_row.address,
        "controller_values": {
            cv.controller_id: {
                "value": cv.value,
                "resolved_type": cv.resolved_type,
                "source": cv.source,
                "block_number": cv.block_number,
                "observed_via": cv.observed_via,
                "details": cv.details or {},
            }
            for cv in cv_rows
        },
    }


def _build_control_graph(root_address: str, cgn_rows, cge_rows) -> dict[str, Any]:
    return {
        "root_contract_address": root_address,
        "nodes": [
            {
                "id": f"address:{n.address}",
                "address": n.address,
                "node_type": n.node_type,
                "resolved_type": n.resolved_type,
                "label": n.label,
                "contract_name": n.contract_name,
                "depth": n.depth,
                "analyzed": n.analyzed,
                # ``analyzed=false`` covers four populations; this says which, ``null`` for pre-column rows.
                "analysis_state": n.analysis_state,
                "graph_max_depth": n.graph_max_depth,
                "details": n.details or {},
            }
            for n in cgn_rows
        ],
        "edges": [
            {
                "from_id": e.from_node_id,
                "to_id": e.to_node_id,
                "relation": e.relation,
                "label": e.label,
                "source_controller_id": e.source_controller_id,
                "notes": list(e.notes or []),
            }
            for e in cge_rows
        ],
    }


def _inherit_from_impl(
    session: Session,
    payload: dict[str, Any],
    job: Job,
    impl_job: Job,
    impl_addr: str,
    not_determined: dict[str, str] | None = None,
    body_absent: dict[str, str] | None = None,
) -> None:
    impl_artifacts = _artifacts_or_degrade(
        session,
        impl_job.id,
        not_determined if not_determined is not None else {},
        body_absent if body_absent is not None else {},
    )
    for fallback_name in (
        "contract_analysis",
        "control_snapshot",
        "resolved_control_graph",
        "effective_permissions",
        "principal_labels",
        "principal_history",
    ):
        if fallback_name not in payload:
            val = impl_artifacts.get(fallback_name)
            if val is not None:
                payload[fallback_name] = val

    impl_c = session.execute(select(Contract).where(Contract.job_id == impl_job.id).limit(1)).scalar_one_or_none()
    if impl_c:
        if "effective_permissions" not in payload:
            impl_efs = list(
                session.execute(
                    select(EffectiveFunction)
                    .where(EffectiveFunction.contract_id == impl_c.id)
                    .options(selectinload(EffectiveFunction.principals))
                ).scalars()
            )
            if impl_efs:
                payload["effective_permissions"] = {
                    "functions": _serialize_effective_functions(impl_efs, index_head=_index_frontier(session, impl_c)),
                    "contract_name": impl_c.contract_name,
                    "contract_address": impl_c.address,
                }

        if "control_snapshot" not in payload:
            impl_cvs = (
                session.execute(select(ControllerValue).where(ControllerValue.contract_id == impl_c.id)).scalars().all()
            )
            if impl_cvs:
                payload["control_snapshot"] = _build_control_snapshot(impl_c, impl_cvs)

        if "resolved_control_graph" not in payload:
            from db.models import ControlGraphEdge, ControlGraphNode

            impl_cgn = (
                session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id == impl_c.id))
                .scalars()
                .all()
            )
            impl_cge = (
                session.execute(select(ControlGraphEdge).where(ControlGraphEdge.contract_id == impl_c.id))
                .scalars()
                .all()
            )
            if impl_cgn:
                payload["resolved_control_graph"] = _build_control_graph(impl_c.address, impl_cgn, impl_cge)

        if "principal_labels" not in payload:
            impl_pls = (
                session.execute(select(PrincipalLabel).where(PrincipalLabel.contract_id == impl_c.id)).scalars().all()
            )
            if impl_pls:
                payload["principal_labels"] = {
                    "principals": [_principal_label_payload(p) for p in impl_pls],
                }

        if "contract_name" not in payload and impl_c.contract_name:
            payload["contract_name"] = impl_c.contract_name
        if "summary" not in payload and impl_c.summary:
            payload["summary"] = {
                "control_model": impl_c.summary.control_model,
                "is_upgradeable": impl_c.summary.is_upgradeable,
                "is_pausable": impl_c.summary.is_pausable,
                "has_timelock": impl_c.summary.has_timelock,
                "standards": list(impl_c.summary.standards or []),
            }

    payload["proxy_address"] = payload.get("proxy_address") or job.address
    payload["implementation_address"] = impl_addr
