from __future__ import annotations

import contextvars
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from sqlalchemy import and_, exists, func, or_, select, text
from sqlalchemy.orm import Session, aliased

from db.jsonb import jsonb_has_payload
from db.models import (
    Contract,
    ContractBalanceFetch,
    ContractBalanceLatest,
    ControlGraphEdge,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    PrincipalLabel,
    UpgradeEvent,
)
from services.scoring.planes import MAPPING_ENUMERATION_STATUS

from .jobs import _time_phase
from .principals import _PRINCIPAL_TYPES_SQL, _SETTLED_CONTROLLER_TYPES, _claim_ids_list, _principal_lookup_type

logger = logging.getLogger("services.aggregations.company_overview")


# Fan-out stays under half the pool so one /api/company leaves room for sibling requests; capped at 4 since beyond that
# the DB is the bottleneck.
#   prod (pool=5):  (5 - 1) // 2 = 2 workers + 1 request session
#   dev  (pool=15): min(4, 7) = 4 workers + 1
_DB_POOL_SIZE = int(os.environ.get("PSAT_DB_POOL_SIZE", "5"))
_DB_MAX_OVERFLOW = int(os.environ.get("PSAT_DB_MAX_OVERFLOW", "10"))
_PREFETCH_MAX_WORKERS = max(1, min(4, (_DB_POOL_SIZE + _DB_MAX_OVERFLOW - 1) // 2))


def _prefetch_child_tables(
    session: Session,
    contract_ids: set[int],
    *,
    max_workers: int = _PREFETCH_MAX_WORKERS,
) -> dict[str, dict[int, Any]]:
    """Pre-load every per-contract child row used downstream.

    Full EffectiveFunction rows are served lazily by /functions; ``ef_effects`` and ``fp_governance_rows`` are the
    narrow projections used here.

    ``controller_values`` runs first because its principal set feeds the CGN/CGE predicate; the rest fan out on threads,
    each with its own Session. Tests pass ``max_workers=1``.
    """
    out: dict[str, dict[int, Any]] = {
        "controller_values": {},
        "ef_effects": {},
        "fp_governance_rows": {},
        "fp_in_contract_principals": {},
        "fp_all_addrs": {},
        "fp_function_detail": {},
        "upgrade_events_count": {},
        "upgrade_events_last": {},
        "balances": {},
        "balance_fetches": {},
        "cgn": {},
        "cge": {},
        "terminal_walk": {},
    }
    if not contract_ids:
        return out

    id_list = list(contract_ids)
    timings_ms: dict[str, int] = {}
    counts: dict[str, int] = {}

    with _time_phase(timings_ms, "controller_values"):
        cv_rows = 0
        for cv in session.execute(select(ControllerValue).where(ControllerValue.contract_id.in_(id_list))).scalars():
            out["controller_values"].setdefault(cv.contract_id, []).append(cv)
            cv_rows += 1
        counts["controller_values"] = cv_rows

    # Push ``_trim_control_graph`` into SQL (ether.fi otherwise loads ~15K rows to drop most). The SQL filter must be a
    # superset of the Python trim, which uses post-lookup types; the trim remains as a final pass.
    cv_principal_addrs_lc: set[str] = set()
    for cv_list in out["controller_values"].values():
        for cv in cv_list:
            value = cv.value
            if not value or not value.startswith("0x"):
                continue
            details_dict = cv.details if isinstance(cv.details, dict) else {}
            if _principal_lookup_type(cv.resolved_type, details_dict):
                cv_principal_addrs_lc.add(value.lower())

    contract_addr_subq = (
        select(func.lower(Contract.address))
        .where(Contract.id.in_(id_list), Contract.address.is_not(None))
        .scalar_subquery()
    )
    edge_source_addr_subq = (
        select(func.lower(func.replace(ControlGraphEdge.from_node_id, "address:", "")))
        .where(ControlGraphEdge.contract_id.in_(id_list))
        .distinct()
        .scalar_subquery()
    )
    # Separate aliases: sharing one let the inner subquery shadow the correlated outer reference.
    cgn_principal_lookup = aliased(ControlGraphNode, name="cgn_principal_lookup")
    cge_target_cgn = aliased(ControlGraphNode, name="cge_target_cgn")
    # ``jsonb_has_payload``, not a null test: a Python ``None`` is stored as jsonb null, which passes the test.
    cgn_principal_addr_subq = (
        select(func.lower(cgn_principal_lookup.address))
        .where(
            cgn_principal_lookup.contract_id.in_(id_list),
            or_(
                cgn_principal_lookup.resolved_type.in_(_PRINCIPAL_TYPES_SQL),
                and_(
                    jsonb_has_payload(cgn_principal_lookup.details),
                    or_(
                        cgn_principal_lookup.details.has_key("delay"),
                        cgn_principal_lookup.details.has_key("delay_seconds"),
                        cgn_principal_lookup.details.has_key("min_delay"),
                    ),
                ),
            ),
        )
        .distinct()
        .scalar_subquery()
    )

    def _node_keep_predicate(node_ref: Any) -> Any:
        clauses = [
            node_ref.resolved_type.in_(_PRINCIPAL_TYPES_SQL),
            func.lower(node_ref.address).in_(contract_addr_subq),
            func.lower(node_ref.address).in_(cgn_principal_addr_subq),
            func.lower(node_ref.address).in_(edge_source_addr_subq),
            and_(
                jsonb_has_payload(node_ref.details),
                or_(
                    node_ref.details.has_key("delay"),
                    node_ref.details.has_key("delay_seconds"),
                    node_ref.details.has_key("min_delay"),
                ),
            ),
        ]
        if cv_principal_addrs_lc:
            clauses.append(func.lower(node_ref.address).in_(list(cv_principal_addrs_lc)))
        return or_(*clauses)

    def _ef_effects(s: Session) -> tuple[dict[int, list[dict[str, list[str]]]], int]:
        # One record per function so claims-vs-legacy stays per-function.
        local: dict[int, list[dict[str, list[str]]]] = {}
        rows = 0
        for cid, labels, claims in s.execute(
            select(
                EffectiveFunction.contract_id,
                EffectiveFunction.effect_labels,
                EffectiveFunction.claims,
            ).where(EffectiveFunction.contract_id.in_(id_list))
        ).all():
            local.setdefault(cid, []).append({"labels": list(labels or []), "claims": _claim_ids_list(claims)})
            rows += 1
        return local, rows

    def _fp_governance(s: Session) -> tuple[dict[int, list[dict[str, Any]]], int]:
        local: dict[int, list[dict[str, Any]]] = {}
        rows = 0
        for row in s.execute(
            select(
                EffectiveFunction.contract_id,
                FunctionPrincipal.address,
                FunctionPrincipal.resolved_type,
                FunctionPrincipal.details,
            )
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(
                EffectiveFunction.contract_id.in_(id_list),
                FunctionPrincipal.resolved_type.in_(sorted(_SETTLED_CONTROLLER_TYPES)),
            )
        ).all():
            cid, address, resolved_type, details = row
            local.setdefault(cid, []).append(
                {
                    "address": address,
                    "resolved_type": resolved_type,
                    "details": details,
                }
            )
            rows += 1
        return local, rows

    def _fp_in_contract_principals(s: Session) -> tuple[dict[int, set[str]], int]:
        """Per-contract in-protocol addresses with call authority on some EffectiveFunction.

        Replaces the CGN walk, which surfaced transitively composed tokens as principals. ``signature_witness`` excluded
        (a signer isn't a caller); NULL type included for legacy rows.
        """
        local: dict[int, set[str]] = {}
        rows = 0
        for cid, addr in s.execute(
            select(
                EffectiveFunction.contract_id,
                func.lower(FunctionPrincipal.address),
            )
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(
                EffectiveFunction.contract_id.in_(id_list),
                FunctionPrincipal.address.is_not(None),
                func.lower(FunctionPrincipal.address).in_(contract_addr_subq),
                or_(
                    FunctionPrincipal.principal_type != "signature_witness",
                    FunctionPrincipal.principal_type.is_(None),
                ),
            )
            .distinct()
        ).all():
            if not addr:
                continue
            local.setdefault(cid, set()).add(addr)
            rows += 1
        return local, rows

    def _fp_all_addrs(s: Session) -> tuple[dict[int, set[str]], int]:
        """Every FP address per contract, unfiltered, for ``primary_controller`` (``_fp_in_contract_principals``
        filters out the Safes/EOAs it needs). ``signature_witness`` excluded.
        """
        local: dict[int, set[str]] = {}
        rows = 0
        for cid, addr in s.execute(
            select(
                EffectiveFunction.contract_id,
                func.lower(FunctionPrincipal.address),
            )
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(
                EffectiveFunction.contract_id.in_(id_list),
                FunctionPrincipal.address.is_not(None),
                or_(
                    FunctionPrincipal.principal_type != "signature_witness",
                    FunctionPrincipal.principal_type.is_(None),
                ),
            )
            .distinct()
        ).all():
            if not addr:
                continue
            local.setdefault(cid, set()).add(addr)
            rows += 1
        return local, rows

    def _fp_function_detail(s: Session) -> tuple[dict[int, list[dict[str, Any]]], int]:
        """Per-function ``{function, callers, claims}`` for the co-controller rule and per-controller capability
        detail. ``signature_witness`` excluded.
        """
        by_ef: dict[int, dict[str, Any]] = {}
        rows = 0
        for cid, ef_id, fname, claims, addr in s.execute(
            select(
                EffectiveFunction.contract_id,
                EffectiveFunction.id,
                EffectiveFunction.function_name,
                EffectiveFunction.claims,
                func.lower(FunctionPrincipal.address),
            )
            .join(FunctionPrincipal, FunctionPrincipal.function_id == EffectiveFunction.id)
            .where(
                EffectiveFunction.contract_id.in_(id_list),
                FunctionPrincipal.address.is_not(None),
                or_(
                    FunctionPrincipal.principal_type != "signature_witness",
                    FunctionPrincipal.principal_type.is_(None),
                ),
            )
        ).all():
            if not addr:
                continue
            entry = by_ef.get(ef_id)
            if entry is None:
                entry = {
                    "contract_id": cid,
                    "function": fname,
                    "claims": _claim_ids_list(claims),
                    "callers": set(),
                }
                by_ef[ef_id] = entry
            entry["callers"].add(addr)
            rows += 1
        local: dict[int, list[dict[str, Any]]] = {}
        for entry in by_ef.values():
            local.setdefault(entry["contract_id"], []).append(
                {
                    "function": entry["function"],
                    "claims": entry["claims"],
                    "callers": entry["callers"],
                }
            )
        return local, rows

    def _upgrade_count(s: Session) -> tuple[dict[int, dict[str, Any]], int]:
        """Upgrade actions per contract, not Upgraded logs, with the basis.

        Distinct ``tx_hash`` (one tx can emit several ``Upgraded``); NULL-tx poll rows each count. A proxy's own
        deployment emits ``Upgraded``; ``upgrade_action_counts`` excludes only proven deployments and never publishes a
        post-exclusion zero as proven.
        """
        from services.discovery.upgrade_history import upgrade_action_counts

        local: dict[int, dict[str, Any]] = upgrade_action_counts(s, id_list)
        return local, len(local)

    def _upgrade_last(s: Session) -> tuple[dict[int, dict[str, Any]], int]:
        """Block and timestamp from the same last row (two MAXes can name different events).

        Order mirrors services/chat/data.py: timestamp, block NULLS FIRST, id.
        """
        local: dict[int, dict[str, Any]] = {}
        for cid, last_block, last_ts in s.execute(
            select(
                UpgradeEvent.contract_id,
                UpgradeEvent.block_number,
                UpgradeEvent.timestamp,
            )
            .where(UpgradeEvent.contract_id.in_(id_list))
            .order_by(
                UpgradeEvent.contract_id,
                UpgradeEvent.timestamp.desc().nullslast(),
                UpgradeEvent.block_number.desc().nullsfirst(),
                UpgradeEvent.id.desc(),
            )
            .distinct(UpgradeEvent.contract_id)
        ).all():
            local[cid] = {"block": last_block, "timestamp": last_ts}
        return local, len(local)

    def _balances(s: Session) -> tuple[dict[int, list[Any]], int]:
        # Base table is insert-only and holds every cycle.
        local: dict[int, list[Any]] = {}
        rows = 0
        for b in s.execute(
            select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id.in_(id_list))
        ).scalars():
            # NULL ``contract_id`` rows can't match ``IN``; this map is contract-keyed and a ``None`` bucket would be
            # unreachable.
            cid = b.contract_id
            if cid is None:
                continue
            local.setdefault(cid, []).append(b)
            rows += 1
        return local, rows

    def _balance_fetches(s: Session) -> tuple[dict[int, Any], int]:
        """``fetch id -> fetch row``. The fetch carries the only truncation witness and the read chain."""
        local: dict[int, Any] = {}
        rows = 0
        # Scalar rows avoid loading the huge typed_assets and lazy loads. Keep every referenced id: native and token
        # rows may cite different fetches.
        referenced = select(ContractBalanceLatest.fetch_id).where(
            ContractBalanceLatest.contract_id.in_(id_list),
            ContractBalanceLatest.fetch_id.is_not(None),
        )
        for f in s.execute(
            select(
                ContractBalanceFetch.id,
                ContractBalanceFetch.chain_id,
                ContractBalanceFetch.asset_set_status,
                ContractBalanceFetch.asset_set_source,
            ).where(ContractBalanceFetch.contract_id.in_(id_list), ContractBalanceFetch.id.in_(referenced))
        ):
            local[f.id] = f
            rows += 1
        return local, rows

    def _cgn(s: Session) -> tuple[dict[int, list[ControlGraphNode]], int]:
        local: dict[int, list[ControlGraphNode]] = {}
        rows = 0
        for n in s.execute(
            select(ControlGraphNode).where(
                ControlGraphNode.contract_id.in_(id_list),
                or_(
                    _node_keep_predicate(ControlGraphNode),
                    # An errored replay can leave the node sourcing no edge; its status is still read. The canvas trim
                    # drops it again, so edges are unaffected.
                    and_(
                        jsonb_has_payload(ControlGraphNode.details),
                        ControlGraphNode.details.has_key(MAPPING_ENUMERATION_STATUS),
                    ),
                ),
            )
        ).scalars():
            local.setdefault(n.contract_id, []).append(n)
            rows += 1
        return local, rows

    def _terminal_walk(s: Session) -> tuple[dict[str, dict[str, Any]], int]:
        """``{address: terminal_principal}`` from ``principal_labels`` (the only place it's persisted), for
        ``terminalControllerNote``.

        Keyed by bare address like the rest of ``principal_lookup``, which has no chain column; a two-chain protocol
        could cross-annotate in principle (not observed). Fixing that is a producer schema change.
        """
        local: dict[str, dict[str, Any]] = {}
        rows = 0
        for address, details in s.execute(
            select(PrincipalLabel.address, PrincipalLabel.details).where(
                PrincipalLabel.contract_id.in_(id_list),
                jsonb_has_payload(PrincipalLabel.details),
                PrincipalLabel.details.has_key("terminal_principal"),
            )
        ).all():
            record = (details or {}).get("terminal_principal")
            if not isinstance(record, dict) or not address:
                continue
            local.setdefault(address.lower(), record)
            rows += 1
        return local, rows

    def _cge(s: Session) -> tuple[dict[int, list[ControlGraphEdge]], int]:
        # Drop an edge iff its target has a CGN row in this contract the keep-clause drops.
        keep_edge_clause = ~exists().where(
            and_(
                cge_target_cgn.contract_id == ControlGraphEdge.contract_id,
                func.lower(cge_target_cgn.address)
                == func.lower(func.replace(ControlGraphEdge.to_node_id, "address:", "")),
                ~_node_keep_predicate(cge_target_cgn),
            )
        )
        local: dict[int, list[ControlGraphEdge]] = {}
        rows = 0
        for e in s.execute(
            select(ControlGraphEdge).where(ControlGraphEdge.contract_id.in_(id_list), keep_edge_clause)
        ).scalars():
            local.setdefault(e.contract_id, []).append(e)
            rows += 1
        return local, rows

    # Slowest stage first so it starts immediately under bounded workers.
    parallel_stages: list[tuple[str, str, Callable[[Session], tuple[Any, int]]]] = [
        ("control_graph_edges", "cge", _cge),
        ("control_graph_nodes", "cgn", _cgn),
        ("balances", "balances", _balances),
        ("balance_fetches", "balance_fetches", _balance_fetches),
        ("ef_effects", "ef_effects", _ef_effects),
        ("fp_governance_rows", "fp_governance_rows", _fp_governance),
        ("fp_in_contract_principals", "fp_in_contract_principals", _fp_in_contract_principals),
        ("fp_all_addrs", "fp_all_addrs", _fp_all_addrs),
        ("fp_function_detail", "fp_function_detail", _fp_function_detail),
        ("upgrade_events_count", "upgrade_events_count", _upgrade_count),
        ("upgrade_events_last", "upgrade_events_last", _upgrade_last),
        ("terminal_walk", "terminal_walk", _terminal_walk),
    ]

    engine = session.get_bind()

    def _run_stage(
        timing_key: str, out_key: str, runner: Callable[[Session], tuple[Any, int]]
    ) -> tuple[str, str, Any, int, int]:
        start = time.monotonic()
        with Session(bind=engine, expire_on_commit=False) as s:
            if snapshot := session.info.get("company_page_snapshot"):
                s.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                s.execute(text("SET TRANSACTION SNAPSHOT :snapshot"), {"snapshot": snapshot})
                s.execute(text("SET LOCAL statement_timeout = '25s'"))
            data, rows = runner(s)
        return timing_key, out_key, data, rows, int((time.monotonic() - start) * 1000)

    parallel_wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futures = [ex.submit(contextvars.copy_context().run, _run_stage, tk, ok, fn) for tk, ok, fn in parallel_stages]
        for fut in as_completed(futures):
            timing_key, out_key, data, rows, ms = fut.result()
            out[out_key] = data
            timings_ms[timing_key] = ms
            counts[timing_key] = rows
    parallel_wall_ms = int((time.monotonic() - parallel_wall_start) * 1000)

    total_ms = sum(timings_ms.values())
    logger.info(
        "Prefetched per-contract child tables: contracts=%d total_ms=%d parallel_wall_ms=%d",
        len(contract_ids),
        total_ms,
        parallel_wall_ms,
        extra={
            "phase": "prefetch_child_tables",
            "duration_ms": total_ms,
            "parallel_wall_ms": parallel_wall_ms,
            "contract_count": len(contract_ids),
            "timings_ms": timings_ms,
            "row_counts": counts,
        },
    )
    return out
