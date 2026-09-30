"""Fold ``FunctionPrincipal`` typing + intrinsic config back into ``control_graph_nodes``.

The resolution walk only classifies addresses it reaches structurally, so a principal controlling a contract only via
per-function authority (a multisig calling ``EtherFiTimelock.cancel``) stays ``unknown`` in CGN. The policy stage
classifies it live into FP. The classifier is deterministic, so FP is simply more complete, but nothing propagated it
back to CGN readers (enrollment, chat, the canvas).

Type and config travel together: a ``safe`` node with no ``owners`` renders as a signerless multisig. Protocol-wide
because a principal's unknown nodes live on the contracts it governs while its FP rows sit on the timelock it calls.

Only ``unknown``/NULL types are upgraded, only to governance types; config merges with ``setdefault``. Idempotent and
convergent. :func:`materialize_fp_principal_nodes` is the INSERT half.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from typing import Any, cast

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db.deployment import deployment_scope
from db.models import (
    EDGE_RELATION_CAPABILITY_PRINCIPAL,
    Contract,
    ControlGraphEdge,
    ControlGraphNode,
    EffectiveFunction,
    FunctionPrincipal,
)
from db.queue import _mainnet_coalesced_chain
from schemas.control_tracking import ResolvedControllerType, coerce_resolved_controller_type
from services.aggregations.company_overview.entity_keys import _coalesce_chain
from services.discovery.perimeter import (
    CONTROL_GRAPH_BASIS_KEY,
    FP_MATERIALIZATION_BASIS,
    ZERO_ADDRESS,
    FpMaterializationResult,
    new_fp_materialization_result,
)
from utils.chains import chain_enabled

logger = logging.getLogger(__name__)

# EOA/contract are excluded: not monitored controllers, and the canvas keeps any principal type.
_RECONCILABLE_TYPES: tuple[ResolvedControllerType, ...] = ("safe", "timelock", "proxy_admin")

# Safe > Timelock > proxy admin, as in ``primary_controller``.
_TYPE_PRIORITY: dict[ResolvedControllerType, int] = {"safe": 3, "timelock": 2, "proxy_admin": 1}

# Relationship keys (conditions, trace, membership_quality) describe a per-function edge, not the address.
_INTRINSIC_DETAIL_KEYS = ("owners", "threshold", "delay", "delay_seconds", "min_delay")


def _chain_key(chain: str | None) -> str:
    """NULL/blank chain is legacy mainnet, keyed with ``ethereum``."""
    return _coalesce_chain(chain)


def _coherent_analysis_state(node: Any) -> str | None:
    """The ``analysis_state`` the walk (``recursive._analysis_state``) would stamp on the current type, so an
    upgraded node doesn't claim to be a Safe with undetermined analyzability. NULL ``graph_max_depth`` can't
    justify ``beyond_depth_horizon``, so the column stays NULL.
    """
    # Lazy: avoids the resolution↔policy package cycle.
    from services.resolution.recursive import _analysis_state

    max_depth = node.graph_max_depth if isinstance(node.graph_max_depth, int) else (node.depth or 0) + 1
    walk_node = {
        "analyzed": bool(node.analyzed),
        "details": node.details if isinstance(node.details, dict) else {},
        "resolved_type": node.resolved_type,
        "depth": node.depth or 0,
    }
    return _analysis_state(cast(Any, walk_node), max_depth)


def _merge_intrinsic(into: dict[str, Any], src: Mapping[str, Any]) -> None:
    """Longest ``owners``; first non-null scalar otherwise."""
    for key in _INTRINSIC_DETAIL_KEYS:
        value = src.get(key)
        if value is None:
            continue
        if key == "owners":
            if not isinstance(value, list) or not value:
                continue
            existing = into.get("owners")
            if not isinstance(existing, list) or len(value) > len(existing):
                into["owners"] = value
        else:
            into.setdefault(key, value)


def reconcile_control_graph_types(session: Session, contract_ids: Sequence[int]) -> int:
    """Fold FP typing + config into CGN for *contract_ids*. Returns rows changed. Idempotent."""
    if not contract_ids:
        return 0

    # Keyed by chain: the same address is a distinct principal per chain and control never crosses chains.
    rows_by_key: dict[tuple[str, str], list[tuple[ResolvedControllerType, dict[str, Any]]]] = {}
    for chain, addr, resolved_type, details in session.execute(
        select(
            Contract.chain,
            func.lower(FunctionPrincipal.address),
            FunctionPrincipal.resolved_type,
            FunctionPrincipal.details,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .join(Contract, Contract.id == EffectiveFunction.contract_id)
        .where(
            EffectiveFunction.contract_id.in_(contract_ids),
            FunctionPrincipal.address.is_not(None),
            FunctionPrincipal.resolved_type.in_(_RECONCILABLE_TYPES),
        )
    ).all():
        if not addr or not resolved_type:
            continue
        key = (_chain_key(chain), addr)
        rows_by_key.setdefault(key, []).append(
            (coerce_resolved_controller_type(resolved_type), details if isinstance(details, dict) else {})
        )

    def _priority(rt: ResolvedControllerType) -> int:
        return _TYPE_PRIORITY.get(rt, 0)

    best_by_key: dict[tuple[str, str], ResolvedControllerType] = {}
    intrinsic_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for key, rows in rows_by_key.items():
        typed_rows: list[ResolvedControllerType] = [rt for rt, _ in rows]
        best = max(typed_rows, key=_priority)
        best_by_key[key] = best
        # Only from the winning type's rows, so a Safe's owners never land on a timelock.
        intrinsic: dict[str, Any] = {}
        for rtype, det in rows:
            if rtype == best:
                _merge_intrinsic(intrinsic, det)
        if intrinsic:
            intrinsic_by_key[key] = intrinsic

    if not best_by_key:
        return 0

    # Includes already-governance-typed nodes so re-runs backfill config. CGN has no chain column; it comes from the
    # parent Contract.
    cgn_rows = session.execute(
        select(ControlGraphNode, Contract.chain)
        .join(Contract, Contract.id == ControlGraphNode.contract_id)
        .where(
            ControlGraphNode.contract_id.in_(contract_ids),
            func.lower(ControlGraphNode.address).in_([addr for _, addr in best_by_key]),
            or_(
                ControlGraphNode.resolved_type.is_(None),
                ControlGraphNode.resolved_type == "unknown",
                ControlGraphNode.resolved_type.in_(_RECONCILABLE_TYPES),
            ),
        )
    ).all()

    updated = 0
    for node, node_chain in cgn_rows:
        key = (_chain_key(node_chain), (node.address or "").lower())
        new_type = best_by_key.get(key)
        if not new_type:
            continue
        changed = False

        # Never overwrite a concrete type.
        if node.resolved_type in (None, "unknown") and new_type != node.resolved_type:
            node.resolved_type = new_type
            changed = True

        # Only onto a matching type, without clobbering. JSONB isn't MutableDict, so reassign.
        node_intrinsic = intrinsic_by_key.get(key)
        if node_intrinsic and node.resolved_type == new_type:
            current = dict(node.details) if isinstance(node.details, dict) else {}
            missing = {k: v for k, v in node_intrinsic.items() if k not in current}
            if missing:
                node.details = {**current, **missing}
                changed = True

        # Stamp what the walk would now derive, only onto NULL; a determined state is never overwritten.
        if node.resolved_type == new_type and node.analysis_state is None:
            derived_state = _coherent_analysis_state(node)
            if derived_state is not None:
                node.analysis_state = derived_state
                changed = True

        if changed:
            updated += 1

    return updated


# Max nodes one ``(contract, deployment)`` anchor may mint per pass.
#
# A hard cap with a permanent tail, not a delay: each job rewrites the scope before minting, so nothing minted survives
# for ``existing_node`` to find, and ``sorted(candidates)`` drops the same tail every pass. At 16, one PR-161 anchor
# lost 11 addresses permanently.
#
# 64 is 2x the observed per-anchor max (31), so no live tail; a backstop and a named model choice, not a corpus-derived
# number. Cuts are recorded as ``budget_exhausted`` in ``omitted[]`` and must be read as a loss.
FP_MATERIALIZE_LIMIT = int(os.getenv("PSAT_FP_MATERIALIZE_LIMIT", "64"))


def _address_node_id(address: str) -> str:
    """``address:0x…`` node ids.

    Duplicated from ``services.resolution.recursive`` to avoid the package cycle; edges join on it, so it must not
    drift.
    """
    return f"address:{address.lower()}"


def materialize_fp_principal_nodes(
    session: Session,
    *,
    contract_id: int,
    deployment_address: str | None,
    budget: int | None = FP_MATERIALIZE_LIMIT,
    result: FpMaterializationResult | None = None,
) -> tuple[FpMaterializationResult, list[dict[str, Any]]]:
    """Mint the ``control_graph_nodes`` rows ``function_principals`` implies.

    FP was terminal: graph ingress is only via ``authority_roles`` / ``controllers`` principals, and
    ``reconcile_control_graph_types`` is UPDATE-only. On PR-161 that hid 73 addresses (34% of FP rows), 72 with no
    ``contracts`` row at all. The defect was reading "role not determined" as "principal does not exist".

    A minted node asserts only that the address is a resolved principal of a gated function on the anchor. ``analyzed``
    False, ``analysis_state`` / ``graph_max_depth`` / ``contract_name`` NULL, no invented config (reconcile folds it
    from FP ``details``).

    Mints nodes, never jobs: ``safe``/``eoa`` mint ``node_type='principal'``, which ``queue_discovered_contracts``
    rejects.

    Idempotence key: ``(chain, lower(address), contract_id, deployment_scope)``, never name/label/origin (``origin`` is
    constant). ``replace_control_graph_rows`` wipes the scope, so the strategy is re-mint by ordering: this runs after
    the job's last rewrite. Budget-cut nodes are lost (see ``FP_MATERIALIZE_LIMIT``).

    Returns ``(ledger, minted_node_payloads)``; payloads are not written into ``resolved_control_graph``, which is the
    walk's output.

    Commits per mint before the ledger records it: the ledger is persisted from the caller's ``finally``, possibly on a
    fresh session, so a later rollback must not leave it naming rows that don't exist.
    """
    # Lazy: avoids the resolution↔policy package cycle.
    from services.resolution.recursive import ANALYZABLE_TYPES

    if result is None:
        result = new_fp_materialization_result(budget=budget)

    def _omit(address: str, reason: str) -> None:
        result["omitted"].append({"address": address, "reason": reason})
        logger.info(
            "FP materialization omitted a candidate",
            extra={
                "address": address,
                "reason": reason,
                "site": result["site"],
                "contract_id": contract_id,
            },
        )

    def _out(address: str, reason: str) -> None:
        result["out_of_population"].append({"address": address, "reason": reason})

    contract = session.get(Contract, contract_id)
    # NULL is legacy mainnet. An absent contract has no chain; its candidates fail closed.
    chain = _mainnet_coalesced_chain(contract.chain) if contract is not None else None
    # A blank address would mint an edge from ``address:``.
    anchor_address = ((contract.address or "").lower() or None) if contract is not None else None

    # Stable order so budget cuts and the ledger are reproducible.
    rows = session.execute(
        select(
            func.lower(FunctionPrincipal.address),
            FunctionPrincipal.resolved_type,
            FunctionPrincipal.origin,
            FunctionPrincipal.principal_type,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .where(
            EffectiveFunction.contract_id == contract_id,
            deployment_scope(EffectiveFunction.deployment_address, deployment_address),
            FunctionPrincipal.address.is_not(None),
        )
        .order_by(func.lower(FunctionPrincipal.address), FunctionPrincipal.id)
    ).all()

    candidates: dict[str, dict[str, Any]] = {}
    for address, resolved_type, origin, principal_type in rows:
        addr = (address or "").lower()
        agg = candidates.setdefault(
            addr,
            {"types": set(), "origins": set(), "principal_types": set(), "functions": 0},
        )
        agg["functions"] += 1
        agg["types"].add(resolved_type)
        if origin:
            agg["origins"].add(origin)
        if principal_type:
            agg["principal_types"].add(principal_type)

    existing = {
        (a or "").lower()
        for (a,) in session.execute(
            select(ControlGraphNode.address).where(
                ControlGraphNode.contract_id == contract_id,
                deployment_scope(ControlGraphNode.deployment_address, deployment_address),
            )
        ).all()
    }

    # No anchor node means no witnessed depth; NULL, not a guess.
    anchor_depth = None
    if anchor_address is not None:
        anchor_depth = (
            session.execute(
                select(ControlGraphNode.depth).where(
                    ControlGraphNode.contract_id == contract_id,
                    deployment_scope(ControlGraphNode.deployment_address, deployment_address),
                    func.lower(ControlGraphNode.address) == anchor_address,
                )
            )
            .scalars()
            .first()
        )
    minted_depth = anchor_depth + 1 if isinstance(anchor_depth, int) else None

    payloads: list[dict[str, Any]] = []
    for addr in sorted(candidates):
        agg = candidates[addr]
        if not addr.startswith("0x") or len(addr) != 42:
            _out(addr, "invalid_address")
            continue
        if addr == ZERO_ADDRESS:
            _out(addr, "zero_address")
            continue
        if contract is None or chain is None or anchor_address is None:
            # Never write a node whose chain we can't name.
            _out(addr, "no_contract_anchor")
            continue
        if addr == anchor_address:
            _out(addr, "anchor_contract")
            continue
        types = {t for t in agg["types"] if t}
        if not types:
            _out(addr, "resolved_type_not_determined")
            continue
        if len(types) > 1:
            # Two FP types for one principal at one anchor; picking one would mint an unproven type. 0 of 413 corpus
            # pairs.
            _out(addr, "resolved_type_conflict")
            continue
        if addr in existing:
            _out(addr, "existing_node")
            continue
        if not chain_enabled(chain):
            _omit(addr, "chain_not_enabled")
            continue
        if budget is not None and result["budget_used"] >= budget:
            _omit(addr, "budget_exhausted")
            continue

        resolved_type = types.pop()
        node_type = "contract" if resolved_type in ANALYZABLE_TYPES else "principal"
        details: dict[str, Any] = {
            CONTROL_GRAPH_BASIS_KEY: FP_MATERIALIZATION_BASIS,
            "fp_function_count": agg["functions"],
            "fp_origins": sorted(agg["origins"]),
            "fp_principal_types": sorted(agg["principal_types"]),
        }
        session.add(
            ControlGraphNode(
                contract_id=contract_id,
                deployment_address=deployment_address,
                address=addr,
                node_type=node_type,
                resolved_type=resolved_type,
                # ``Job.name`` and display sites fall back to the label, so any constant would become the principal's
                # identity.
                label=None,
                contract_name=None,
                depth=minted_depth,
                analyzed=False,
                analysis_state=None,
                graph_max_depth=None,
                details=details,
            )
        )
        session.add(
            ControlGraphEdge(
                contract_id=contract_id,
                deployment_address=deployment_address,
                from_node_id=_address_node_id(anchor_address),
                to_node_id=_address_node_id(addr),
                relation=EDGE_RELATION_CAPABILITY_PRINCIPAL,
                label=None,
                source_controller_id=None,
                notes=[f"functions={agg['functions']}"],
            )
        )

        # Commit before the ledger records the mint (see docstring).
        session.commit()

        # Spent only at the committed INSERT.
        result["budget_used"] += 1
        result["minted"].append(
            {
                "address": addr,
                "node_type": node_type,
                "resolved_type": resolved_type,
                "contract_id": contract_id,
                "deployment_address": deployment_address,
                "fp_function_count": agg["functions"],
            }
        )
        payloads.append(
            {
                "id": _address_node_id(addr),
                "address": addr,
                "node_type": node_type,
                "resolved_type": resolved_type,
                "label": None,
                "contract_name": None,
                "depth": minted_depth,
                "analyzed": False,
                "analysis_state": None,
                "details": details,
                "artifacts": {},
            }
        )
        if node_type == "contract":
            result["queued"].append({"address": addr, "resolved_type": resolved_type})
        else:
            # Minted, never a job (``not_contract_node``); recorded so both ledgers agree.
            _out(addr, "not_analyzable_type")

    # Only on loop exit; a raise leaves the prefix incomplete.
    result["walked"] = True
    return result, payloads
