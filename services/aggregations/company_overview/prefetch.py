"""Batched prefetch of every per-contract child table used downstream."""

from __future__ import annotations

import contextvars
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from sqlalchemy import and_, exists, func, or_, select
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

from .jobs import _time_phase
from .principals import _PRINCIPAL_TYPES_SQL, _SETTLED_CONTROLLER_TYPES, _claim_ids_list, _principal_lookup_type

logger = logging.getLogger("services.aggregations.company_overview")


# Read the pool sizing from the same env vars db.models reads, rather than
# importing the (private) constants. The fan-out cap derives from
# pool_size + max_overflow so prod (deploy/start_workers.sh tightens to 2+3=5) and
# dev (5+10=15) both stay below ~half the pool: one in-flight /api/company
# never claims more than ~half the engine's connections, leaving room for
# /functions, /audit_coverage, etc. on the same worker process. The hard
# ceiling of 4 caps perf returns since beyond that the SQL planner and the
# DB CPU become the bottleneck, not concurrency.
#   prod (pool=5):  (5 - 1) // 2 = 2 workers + 1 request session = 3/5
#   dev  (pool=15): min(4, (15-1)//2 = 7) = 4 workers + 1 = 5/15
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

    The full ``EffectiveFunction`` rows (and their FunctionPrincipal
    children) are no longer loaded on this path — they're served by
    ``/api/company/{name}/functions`` and fetched lazily by the frontend.
    Two narrow projections replace the heavy row+selectinload pair:

    * ``ef_effects`` — ``{contract_id: list[list[str]]}`` of per-function
      ``effect_labels`` arrays. Drives the contract entry's
      ``value_effects`` / ``capabilities`` / ``role`` fields.
    * ``fp_governance_rows`` — non-contract principals (safe/timelock/
      eoa/proxy_admin) from ``function_principals``, joined back to
      ``contract_id``. Drives the third-pass principal backfill in
      ``_build_flows_and_principals`` (function-only principals like the
      EtherFiTimelock Safe).

    ``controller_values`` runs first on the request session because the
    ``cv_principal_addrs_lc`` set it produces is needed in the CGN/CGE
    keep-predicate. The remaining stages fan out over a per-request
    ``ThreadPoolExecutor`` — sync SQLAlchemy releases the GIL inside the
    DB driver so threads give genuine wall-time parallelism. Each task
    opens its own ``Session`` on the same engine because Session is not
    thread-safe; ``max_workers`` is derived from the engine pool size so
    a single request never claims more than ~half the pool (see the
    ``_PREFETCH_MAX_WORKERS`` comment above for the math). Tests pass
    ``max_workers=1`` to validate the sequential path against the
    parallel merge.
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

    # The control_graph queries push the _trim_control_graph rule into the
    # WHERE clause. Without the prefilter, ether.fi loads ~7.1 K CGN + ~8.5 K
    # CGE rows just to drop ~78% / ~66% of them at serialization time. The
    # filter must be a strict superset of the Python trim because the trim
    # uses the *post-lookup* node type, so addresses whose CGN.resolved_type
    # is non-principal but whose principal_lookup entry upgrades them
    # (analyzed contracts, CV principals, cross-contract CGN principals,
    # timelock-delay details) must still be loaded. _trim_control_graph is
    # kept as a final no-op-on-the-happy-path pass that handles the cases
    # where SQL keeps more than Python would (cross-contract edge sources,
    # JSONB delay keys with non-positive values).
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
    # Distinct aliases for the two roles the CGN table plays inside the
    # control_graph queries:
    #   * ``cgn_principal_lookup`` — the inner subquery that returns every
    #     address with a principal-typed or timelock-delay CGN row anywhere
    #     in the batch. Drives the cross-contract lookup upgrade case.
    #   * ``cge_target_cgn`` — the correlated CGN reference inside the CGE
    #     NOT EXISTS, joined to the edge's target.
    # Sharing one alias caused inner subquery references to shadow the outer
    # correlated reference inside the CGE query, which Postgres tolerates
    # but reads as a footgun.
    cgn_principal_lookup = aliased(ControlGraphNode, name="cgn_principal_lookup")
    cge_target_cgn = aliased(ControlGraphNode, name="cge_target_cgn")
    # ``jsonb_has_payload``, not a SQL null test, on both timelock-delay clauses
    # here and in ``_node_keep_predicate``: a JSONB column written from a Python
    # ``None`` holds the jsonb scalar null, which passes a null test. The
    # ``has_key`` checks that follow are false on that value, so the pair reads
    # as one contradictory row rather than a node with no resolved details.
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
        # Per function: legacy labels (drive value_effects) + Plane-1 claim_ids
        # (drive the capability chips, claims-first). One record per function so
        # the claims-vs-legacy choice stays per-function through aggregation.
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
        """Per-contract set of in-protocol-contract addresses that hold
        call authority on at least one ``EffectiveFunction``.

        Replaces the bare ``ControlGraphNode`` walk that previously drove
        in-contract ``type=principal`` flows. CGN rows include the full
        recursive graph (transitive lineage like
        ``WithdrawalQueueERC721 -> WstETH -> Lido stETH``), so emitting a
        principal flow for every in-protocol CGN match falsely surfaced
        tokens that EtherFi composes with as principals controlling
        EtherFi contracts. ``FunctionPrincipal`` is the authoritative
        per-function access-control record — an address only appears here
        if the capability resolver determined it can actually call a
        function.

        ``signature_witness`` is excluded because a signer of a message
        is not a caller. NULL ``principal_type`` is included so legacy
        rows pre-dating the typed writer still count.
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
        """Per-contract set of every FP address (lower-cased), no contract
        filter. Drives ``services.governance.primary_controller`` which
        needs to ask "is this non-contract principal (Safe/Timelock/EOA/
        proxy_admin) in FP for any function on this contract?".

        ``_fp_in_contract_principals`` intersects with the in-protocol
        contract set so it can't answer that question — by construction
        it filters out the very addresses (Safes / EOAs) we want to
        check. ``signature_witness`` rows are excluded for the same
        reason as there: signers of a message aren't callers.
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
        """Per-contract, per-function ``{"function": str, "callers": set,
        "labels": set, "claims": list[claim_id]}``. Drives two things:

        * the co-controller rule in
          :func:`services.governance.primary_controller.assign_co_controllers`,
          which keeps a non-primary principal only when it holds authority on a
          function that is privileged (a strong effect label) or tightly gated
          (few authorized callers) — separating a real guardian/admin from a
          permissionless caller (``createBid``, shared by dozens of bidders);
        * the per-(controller, contract) capability detail surfaced on the
          canvas (which concrete functions / effect categories each controller
          can actually call), so a relationship reads as "pause · recover"
          rather than a generic "controlled". ``function_name`` is carried for
          that — effect labels alone are too coarse (``setCapacity`` is only
          ``external_contract_call``).

        ``signature_witness`` rows are excluded for the same reason as the
        sibling FP projections: a signer of a message isn't a caller."""
        by_ef: dict[int, dict[str, Any]] = {}
        rows = 0
        for cid, ef_id, fname, labels, claims, addr in s.execute(
            select(
                EffectiveFunction.contract_id,
                EffectiveFunction.id,
                EffectiveFunction.function_name,
                EffectiveFunction.effect_labels,
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
                    "labels": set(labels or ()),
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
                    "labels": entry["labels"],
                    "claims": entry["claims"],
                    "callers": entry["callers"],
                }
            )
        return local, rows

    def _upgrade_count(s: Session) -> tuple[dict[int, dict[str, Any]], int]:
        """Upgrade ACTIONS per contract, not Upgraded logs — with the basis.

        The payload's ``upgrade_count`` renders as literal "N upgrades" text,
        so the unit must be exercises of upgrade authority. Distinct
        ``tx_hash`` is the honest cardinality the persisted rows can support:
        one transaction can emit several ``Upgraded`` logs against the same
        proxy (a within-tx swap-and-restore emits two), and counting distinct
        *resting-implementation changes* instead would need old→new impl
        continuity, which ``old_impl`` (NULL on every backfill-written row)
        cannot give. Rows with NULL ``tx_hash`` (the poll writer detects a slot
        change without a tx) are each their own observed upgrade: they cannot
        be grouped by transaction, and folding them together would undercount.

        What the distinct-tx count still could not see is that **a proxy's own
        deployment emits ``Upgraded``**, so its creation was published as an
        upgrade. ``upgrade_action_counts`` excludes an event only where the
        deployment is PROVEN (see ``services/discovery/upgrade_history.py``),
        leaves every unproven one counted, and refuses to publish a
        post-exclusion zero as a proven zero. The sidecar carries the basis so
        a consumer can see the coverage behind the number rather than reading
        it as complete.
        """
        from services.discovery.upgrade_history import upgrade_action_counts

        local: dict[int, dict[str, Any]] = upgrade_action_counts(s, id_list)
        return local, len(local)

    def _upgrade_last(s: Session) -> tuple[dict[int, dict[str, Any]], int]:
        """Block + timestamp of THE last upgrade event — one row, both fields.

        Formerly two independent ``MAX`` aggregates over the same group, which
        can name two different events the moment a poll-detected row (NULL
        ``block_number`` by design) coexists with a block-carrying one. The
        published pair describes "the last upgrade", so both halves must come
        from the same qualifying row. Ordering mirrors the chat plane's
        documented total order (services/chat/data.py): timestamp leads
        because every writer sets it; block NULLS FIRST under DESC so a
        poll-detected latest row wins over an older block-carrying one; ``id``
        makes the order total.
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
        # ``contract_balances_latest``, not the base table: both writers are
        # insert-only now, so the base table carries every past cycle and this
        # would list the same holding once per refresh.
        local: dict[int, list[Any]] = {}
        rows = 0
        for b in s.execute(
            select(ContractBalanceLatest).where(ContractBalanceLatest.contract_id.in_(id_list))
        ).scalars():
            # An entity-keyed reading — ``contract_id`` NULL, the class the balance
            # record grew when identity moved off the contracts table — cannot reach
            # this loop: ``contract_id IN (id_list)`` evaluates to NULL for a NULL
            # key, never to true. The narrowing states that instead of widening a
            # CONTRACT-keyed map to admit a ``None`` bucket, which is the shape that
            # matters here: every consumer reads this map as
            # ``balances_by_cid.get(contract.id)``, so a row filed under ``None``
            # would be stored, counted, and unreachable by anything that looks.
            # This plane answers for contracts; entity sheets are read elsewhere.
            cid = b.contract_id
            if cid is None:
                continue
            local.setdefault(cid, []).append(b)
            rows += 1
        return local, rows

    def _balance_fetches(s: Session) -> tuple[dict[int, Any], int]:
        """``fetch id -> the fetch row``, for the fetches the latest rows came from.

        Keyed by fetch id because that is what ``contract_balances_latest.fetch_id``
        names. The fetch carries the ONLY truncation witness there is
        (``asset_set_status == at_page_cap``) plus the chain the read was issued on;
        neither is derivable from the stored rows.
        """
        local: dict[int, Any] = {}
        rows = 0
        for f in s.execute(select(ContractBalanceFetch).where(ContractBalanceFetch.contract_id.in_(id_list))).scalars():
            local[f.id] = f
            rows += 1
        return local, rows

    def _cgn(s: Session) -> tuple[dict[int, list[ControlGraphNode]], int]:
        local: dict[int, list[ControlGraphNode]] = {}
        rows = 0
        for n in s.execute(
            select(ControlGraphNode).where(
                ControlGraphNode.contract_id.in_(id_list),
                _node_keep_predicate(ControlGraphNode),
            )
        ).scalars():
            local.setdefault(n.contract_id, []).append(n)
            rows += 1
        return local, rows

    def _terminal_walk(s: Session) -> tuple[dict[str, dict[str, Any]], int]:
        """``{lower(address): terminal_principal record}`` from ``principal_labels``.

        The terminal-controller walk (``services/governance/principals.resolve_terminal_principal``)
        is persisted ONLY on ``principal_labels.details`` — 1,556 rows written, and
        the one consumer that handles its whole status vocabulary correctly,
        ``claimsVocab.terminalControllerNote``, could never receive it because
        ``_build_principal_lookup`` never joined the table. A permanently
        disconnected plane, not a rare shape.

        Keyed by address, not by ``(contract_id, address)``: the walk answers "what
        ultimately controls THIS address", and the local corpus has 0 addresses
        whose record differs between the subject contracts that recorded it (22
        distinct addresses across 180 rows). A narrow projection with the jsonb
        ``has_key`` filter in the WHERE clause, so contracts with no walk cost
        nothing.

        CHAIN SCOPE, stated rather than claimed: the read is scoped by
        ``contract_id`` (chain-scoped through ``contracts.chain``) but the returned
        MAP is keyed by a bare lowercase address, which is the pre-existing shape of
        the whole ``principal_lookup`` plane — ``principal_labels`` /
        ``control_graph_nodes`` / ``controller_values`` carry no chain column at all,
        and ``_build_principal_lookup`` already merges every source into one
        bare-address dict. So a protocol spanning two chains could in
        principle have one chain's walk annotate the other's node. Not realised: the
        control/policy plane is 100% ethereum, and 0 addresses carry differing
        records. Closing it means giving that plane a chain key, which is a
        producer-side schema change, not a consumer split.
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
        # Drop an edge iff there exists a CGN row at its target address in
        # the same contract that the keep-clause would not retain — i.e., a
        # Python-trim-dropped node. Targets outside this contract's CGN are
        # always kept (no CGN row means no dropped row).
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

    # (timing_key, out_key, runner). Order matters under bounded max_workers:
    # the slowest stage gets submitted first so it lands on an idle worker
    # immediately and runs alongside the queue of shorter stages.
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
            data, rows = runner(s)
        return timing_key, out_key, data, rows, int((time.monotonic() - start) * 1000)

    parallel_wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        # Per-submission context copy so each prefetch stage's log lines carry
        # the caller's trace_id instead of running under an empty context.
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
