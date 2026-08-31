"""Recursively resolve contract control chains into a reusable graph artifact."""

from __future__ import annotations

import copy
import logging
import os
import re
import tempfile
import threading
from collections import deque
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from typing_extensions import NotRequired, TypedDict

from db.models import (
    EDGE_RELATION_CONTROLLER_VALUE,
    EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED,
    EDGE_RELATION_EXTERNAL_CALL_TARGET,
)
from db.storage import StorageContentIncomplete, StorageUnavailable
from schemas.observations import (
    ObservationBatch,
    ObservationPlan,
    ResolvedControllerType,
    coerce_resolved_controller_type,
)
from schemas.resolution_graph import (
    ResolutionEdge,
    ResolutionGraph,
    ResolutionNode,
    ResolutionNodeKind,
    ResolutionRelation,
    ResolutionState,
)
from schemas.static_facts import ControllerProvenance, StaticFacts
from services.discovery.classifier import ClassificationIncompleteError
from services.discovery.fetch import fetch, scaffold
from services.static.static_analysis.core import collect_static_inputs
from services.static.static_analysis.mapping_events import WriterEventSpec
from utils.logging import record_degraded, record_stage_metric, stage_metrics_var

from .observation_plan import build_observation_plan
from .tracking import (
    classify_resolved_address,
    classify_resolved_address_with_status,
    observe_controllers,
    probe_declared_vault_backlink,
)

logger = logging.getLogger(__name__)


class UnresolvedProxyError(RuntimeError):
    """Raised when a proxy classification has no resolvable single implementation.

    Covers EIP-2535 diamonds, beacon proxies whose ``implementation()`` failed,
    and short-bytecode ``unknown`` proxies with no probe target. Analyzing the
    delegatecall shell yields an empty guard set that downstream renders as
    permissionless, so the materialization fails closed and the BFS records a
    degraded, un-analyzed node instead.
    """


ANALYZABLE_TYPES = {"contract", "timelock", "proxy_admin"}
DEFAULT_RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))

# Tied to the schema vocabulary: pyright rejects these lines if the members
# leave ``ControllerProvenance``, so the comparisons below cannot drift.
_PROVENANCE_CALL_TARGET: ControllerProvenance = "call_target"
_PROVENANCE_CALLER_GATE: ControllerProvenance = "caller_gate"


def _coerce_resolved_type(value: object) -> ResolvedControllerType:
    """A ``resolved_type`` that was never determined must surface as the
    vocabulary's not-determined token (``"unknown"``), never as a fabricated
    concrete one.

    ``str(payload.get("resolved_type", "unknown"))`` only defaults on an
    ABSENT key; a key PRESENT with value ``None`` reaches ``str(None)`` and
    mints the literal ``"None"`` — a token in no vocabulary
    (``schemas.observations.ResolvedControllerType``) that is truthy and
    ``!= "unknown"``, so every downstream three-way branch reads it as a
    concrete, determined type. The literal string ``"None"`` is likewise
    coerced: it can arrive from a previously stored graph (the policy-stage
    refresh pre-seeds from the persisted artifact) and means the same absence.
    Any other out-of-vocabulary token is the same class of undetermined input
    — nothing downstream can act on a type it does not know — so membership in
    ``RESOLVED_CONTROLLER_TYPES`` is the earned bar for a concrete answer.
    """
    return coerce_resolved_controller_type(value)


_MATERIALIZE_METRIC_LOCK = threading.Lock()


def _bump_materialize_metric(key: str) -> None:
    """Thread-safe +1 to a stage metric from the parallel materialize fan-out.
    ``record_stage_metric`` overwrites, but the build-vs-cache-hit fold needs an
    increment — and ``_materialize_with_cross_process_cache`` runs inside the
    ``parallel_map`` worker threads, which inherit ``stage_metrics_var`` via
    copy_context — so guard the read-modify-write. A cache-hit-rate collapse
    here is the canonical cause of a resolution stage silently multiplying its
    forge/Slither spend run-over-run. No-op outside a worker job context."""
    _bump_stage_metric(key)


def _bump_stage_metric(key: str, n: int = 1) -> None:
    """Thread-safe ``+n`` to a per-job stage metric. ``record_stage_metric``
    overwrites, but the BFS fan-out (and the per-contract mapping/proxy folds)
    need an increment across contracts and worker threads, which inherit
    ``stage_metrics_var`` via copy_context. No-op outside a worker job context."""
    metrics = stage_metrics_var.get()
    if metrics is None:
        return
    with _MATERIALIZE_METRIC_LOCK:
        metrics[key] = metrics.get(key, 0) + n


class LoadedArtifacts(TypedDict):
    """Per-contract artifact bundle emitted by ``resolve_control_graph`` and persisted by the worker as DB artifacts.

    Fields are ``Mapping`` (not the strict stage TypedDicts) because a bundle
    has two provenances: the root's in-memory freshly-built documents, and
    nested bundles hydrated from persisted JSONB rows (unverified shapes).
    Every consumer reads via ``.get()`` anyway; the strict types live at the
    producers (``build_observation_plan`` / ``observe_controllers``).
    """

    static_facts: Mapping[str, Any]
    observation_plan: Mapping[str, Any]
    snapshot: Mapping[str, Any]
    predicate_trees: NotRequired[dict[str, Any] | None]
    permission_index: NotRequired[Mapping[str, Any] | None]


class PendingContract(TypedDict):
    address: str
    depth: int
    artifacts: NotRequired[LoadedArtifacts]


class RolePrincipalAccumulator(TypedDict):
    address: str
    resolved_type: ResolvedControllerType
    details: dict[str, object]
    roles: set[int]
    functions: set[str]


class RolePrincipal(TypedDict):
    address: str
    resolved_type: ResolvedControllerType
    details: dict[str, object]
    roles: list[int]
    functions: list[str]


def _address_node_id(address: str) -> str:
    return f"address:{address.lower()}"


def _sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_")
    return cleaned or "contract"


def _workspace_name(contract_name: str, address: str, prefix: str) -> str:
    return f"{_sanitize_name(prefix)}_{_sanitize_name(contract_name)}_{address.lower()[2:10]}"


def _contract_name_for_address(address: str, chain_id: int) -> str | None:
    try:
        result = fetch(address, chain_id=chain_id)
    except Exception:
        return None
    if not isinstance(result, dict):
        return None
    # ``or ""`` not a ``.get`` default: a key PRESENT with ``None`` would reach
    # ``str(None)`` and fabricate the name "None" (same shape as the
    # ``resolved_type`` bug ``_coerce_resolved_type`` guards).
    name = str(result.get("ContractName") or "").strip()
    return name or None


def _build_permission_index(
    static_facts: Mapping[str, Any],
    snapshot: ObservationBatch,
) -> dict[str, Any] | None:
    """Compute the effective-permissions payload for nested resolution."""
    # Function-scope import: the module-level form is the back-edge of the
    # policy↔resolution package cycle (policy.__init__ → permission_index
    # → capability_surface → permissionless_shapes → resolution.__init__ →
    # here), which import-crashes any process that touches services.policy
    # first — policy_worker died on boot and took the whole worker pool with
    # it (deploy/start_workers.sh exits on first death).
    from services.policy.permission_index import build_permission_index

    try:
        return cast(
            dict,
            build_permission_index(
                static_facts,
                target_snapshot=cast(dict, snapshot),
                principal_resolution={"status": "no_authority", "reason": "No non-zero authority found"},
            ),
        )
    except Exception as exc:
        # A nested contract whose effective-permissions build fails silently drops
        # its role principals from the graph (consumed below in
        # ``_role_principals_from_permission_index``). Was debug-only — surface
        # it as a degraded breadcrumb so the gap is visible in stage_errors.
        # ``or ""`` before ``str``: a subject with ``address: None`` must fall
        # through to "<unknown>", not read as the truthy string "None".
        address = str((static_facts.get("subject") or {}).get("address") or "") or "<unknown>"
        record_degraded(
            phase="recursive_permission_index",
            exc=exc,
            context={"address": address},
        )
        logger.warning(
            "Recursive resolve: permission_index build failed for %s: %s",
            address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return None


def _build_static_artifacts(
    effective_address: str,
    workspace_prefix: str,
    *,
    chain_id: int,
) -> tuple[str, StaticFacts, ObservationPlan, dict[str, Any] | None]:
    """Run the expensive forge+Slither+predicate pipeline for *effective_address*.

    Returns ``(contract_name, static_facts, observation_plan, predicate_trees)``.
    ``effects`` is also produced by the predicate pipeline but is not
    plumbed back here: the recursive resolver doesn't consume it, and
    the policy stage reads the per-job ``effects`` artifact written by
    the static worker (propagated across same-bytecode jobs by
    ``copy_static_cache``), so the materialization cache has no
    consumer for it.

    Pulled out of ``_materialize_contract_artifacts`` so the cross-process
    cache can call this exact closure when it needs to populate the
    persistent row. The tempdir is cleaned up at function exit.
    """
    result = fetch(effective_address, chain_id=chain_id)
    contract_name = str(result.get("ContractName") or "Contract")
    project_name = _workspace_name(contract_name, effective_address, workspace_prefix)

    with tempfile.TemporaryDirectory(prefix=f"psat_{workspace_prefix}_") as tmp:
        project_dir = Path(tmp) / project_name
        scaffold(effective_address, result, project_dir)
        static_facts, predicate_trees, _effects = collect_static_inputs(project_dir)

    plan = build_observation_plan(static_facts)
    return contract_name, static_facts, plan, predicate_trees


def _chain_name_for_materialization(chain_id: int) -> str:
    """Canonical chain name used as the ``contract_materializations`` cache key
    component. Mainnet (``chain_id=1``) resolves to ``"ethereum"`` so mainnet
    cache keys are unchanged. An unregistered id fails loud: the old
    ``PSAT_DEFAULT_CHAIN`` env fallback is gone, so a bad chain_id can no longer
    key an L2's artifacts under mainnet."""
    from utils.chains import require_chain

    return require_chain(chain_id, context="materialization chain name").name


def _widen_built(
    built: tuple[str, StaticFacts, ObservationPlan, dict[str, Any] | None],
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Widen a fresh build to the mixed-provenance materialize shape.

    The cross-process cache serves both fresh builds (typed at the producer)
    and persisted JSONB rows (shape unverified), so its tuple stays wide; the
    fresh arm is only ever widened, never the reverse.
    """
    name, static_facts, plan, predicate_trees = built
    return name, cast("dict[str, Any]", static_facts), cast("dict[str, Any]", plan), predicate_trees


def _materialize_with_cross_process_cache(
    *,
    effective_address: str,
    bytecode_keccak: str | None,
    workspace_prefix: str,
    chain: str | None = None,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Consult the persistent contract_materializations table; build on miss.

    Returns ``(contract_name, static_facts, observation_plan, predicate_trees)``.
    ``predicate_trees`` round-trips through the cache so mapping-writer
    enumeration stays functional on cache hits (pre-c1d2e3f4a5b6 the
    builder dropped it and downstream silently disabled enumeration).

    Falls back to a direct ``_build_static_artifacts`` call when:
      * ``bytecode_keccak`` is None (we have nothing to key on);
      * the DB layer raises (e.g., the table doesn't exist in a
        fixture-isolated test, or the DB is unreachable).
    """
    # Chain threaded from the job/contract (via ``_chain_name_for_materialization``
    # at the walk entry). A chainless call is a data bug: fail loud
    # rather than defaulting to mainnet via the old PSAT_DEFAULT_CHAIN env read.
    from utils.chains import require_chain

    build_chain_id = require_chain(chain=chain, context="contract materialization").chain_id

    if not bytecode_keccak:
        _bump_materialize_metric("materialize_builds")
        return _widen_built(_build_static_artifacts(effective_address, workspace_prefix, chain_id=build_chain_id))

    try:
        from db import contract_materializations as cm
    except Exception as exc:
        logger.debug("contract_materializations unavailable, falling back to direct build: %s", exc)
        _bump_materialize_metric("materialize_builds")
        return _widen_built(_build_static_artifacts(effective_address, workspace_prefix, chain_id=build_chain_id))

    if not cm.is_enabled():
        # Operator-controlled kill switch (PSAT_CONTRACT_MATERIALIZATIONS=0)
        # for prod incidents. Bypasses the persistent layer entirely so a
        # broken table or hot-spot lock contention can't fail-stop the
        # pipeline.
        _bump_materialize_metric("materialize_builds")
        return _widen_built(_build_static_artifacts(effective_address, workspace_prefix, chain_id=build_chain_id))

    built = {"ran": False}

    def _builder() -> Mapping[str, Any]:
        built["ran"] = True
        _bump_materialize_metric("materialize_builds")
        name, static_facts, plan, predicate_trees = _build_static_artifacts(
            effective_address, workspace_prefix, chain_id=build_chain_id
        )
        return {
            "contract_name": name,
            "static_facts": static_facts,
            "observation_plan": plan,
            "predicate_trees": predicate_trees,
        }

    def _source_hash_fn() -> str | None:
        # Cross-chain code-plane reuse key. ``get_source`` is
        # in-memory + PG cached, so on the build path this shares the fetch
        # ``_build_static_artifacts`` makes; on a keccak hit it is never called.
        from services.discovery.fetch import source_content_hash

        result = fetch(effective_address, chain_id=build_chain_id)
        return source_content_hash(result)

    try:
        row = cm.materialize_or_wait(
            chain=chain,
            address=effective_address,
            bytecode_keccak=bytecode_keccak,
            builder=_builder,
            source_hash_fn=_source_hash_fn,
        )
    except Exception as exc:
        # ``materialize_or_wait`` re-raises the builder's exception. If
        # the failure was *inside* the builder, propagating preserves the
        # existing behaviour of letting the resolution stage handle its
        # own retry/terminal classification. If the failure was in the
        # DB layer (lock acquisition, schema absent), fall back so we
        # don't fail-stop the whole pipeline on a cache outage.
        if _is_builder_exception(exc):
            raise
        record_degraded(
            phase="materialize_or_wait",
            exc=exc,
            context={"chain": chain, "address": effective_address},
        )
        logger.warning("contract_materializations.materialize_or_wait failed, falling back: %s", exc)
        _bump_materialize_metric("materialize_builds")
        return _widen_built(_build_static_artifacts(effective_address, workspace_prefix, chain_id=build_chain_id))

    if not built["ran"]:
        # materialize_or_wait returned without invoking our builder — served from
        # the persistent cache (or a sibling process built it); either way this
        # process did not pay the forge/Slither cost.
        _bump_materialize_metric("materialize_cache_hits")

    # ``hydrate_*`` transparently reads from blob storage when the row's
    # ``*_blob_key`` is set or falls back to inline JSONB (rows written
    # before blob storage was enabled, or when storage was unconfigured).
    # The blob path's ``json.loads`` already returns a
    # fresh dict per call, but the inline path returns the SQLAlchemy
    # JSONB-cached dict, so the deepcopy is still required to avoid
    # downstream mutations leaking back into the ORM identity map.
    #
    # ``StorageContentIncomplete`` propagates deliberately, all the way out of
    # ``resolve_control_graph`` (``_materialize_for_pending`` re-raises it rather
    # than degrading the contract; the worker's classifier calls the
    # not-determined subclass transient so the stage re-runs, and the
    # proven-absent one terminal so it does not re-ask an answered question).
    # ``or {}`` below is therefore only ever
    # applied to a *proven* absence — a row that stored nothing. If the payload
    # merely could not be read, an empty static_facts here means "this contract has
    # no functions, no plan and no predicate trees", and that verdict is what
    # the effects probe is seeded from and what gets cached under the witness
    # schema version. A retried stage can still become right; a witness built
    # on {} is already wrong and cached.
    static_facts = copy.deepcopy(cm.hydrate_static_facts(row) or {})
    plan = copy.deepcopy(cm.hydrate_observation_plan(row) or {})
    # ``predicate_trees`` is absent on rows written before the
    # c1d2e3f4a5b6 migration; hydrate returns None in that case and
    # ``_mapping_writer_specs_from_predicate_trees`` short-circuits.
    predicate_trees_cached = cm.hydrate_predicate_trees(row)
    predicate_trees = copy.deepcopy(predicate_trees_cached) if predicate_trees_cached else None
    contract_name = row.contract_name or "Contract"
    return contract_name, static_facts, plan, predicate_trees


def _is_builder_exception(exc: BaseException) -> bool:
    """Did *exc* originate inside the materialization builder
    rather than the DB cache layer?

    Builder exceptions are anything raised by ``fetch`` / ``scaffold`` /
    ``collect_static_facts`` — broadly Etherscan / Slither errors.
    DB-layer errors are SQLAlchemy / psycopg2 exceptions. We can't
    cleanly distinguish without a type sniff; treat anything from the
    sqlalchemy module as a DB-layer error and let other exceptions
    propagate.
    """
    mod = type(exc).__module__ or ""
    return not (mod.startswith("sqlalchemy") or mod.startswith("psycopg2"))


def _materialize_contract_artifacts(
    address: str,
    rpc_url: str,
    *,
    workspace_prefix: str,
    chain: str | None = None,
    chain_id: int | None = None,
) -> LoadedArtifacts:
    """Build static_facts + plan + snapshot + effective permissions in memory (tempdir cleaned up before return)."""
    # Proxy check — analyze the implementation but read storage from the proxy.
    effective_address = address
    snapshot_address = address

    # Classify in its OWN try so a generic classify hiccup degrades to
    # "analyze the address as-is" (historical behavior). The retarget /
    # fail-closed decision runs OUTSIDE this except — otherwise the
    # ``UnresolvedProxyError`` raise below would be swallowed into a silent
    # shell static_facts. ``ClassificationIncompleteError`` (proxy-slot read
    # failure) is propagated, not swallowed, for the same reason.
    classification: dict | None = None
    try:
        from services.discovery.classifier import classify_single

        classification = classify_single(address, rpc_url, chain_id=chain_id)
    except ClassificationIncompleteError:
        # #121: the proxy-detection slots could not be read (transient RPC).
        # Refuse to analyze this address as a confident clean contract; propagate
        # so the BFS records a degraded, un-analyzed node and the worker retries
        # when the RPC heals.
        raise
    except Exception as exc:
        logger.debug("Recursive resolve: proxy check failed for %s: %s", address, exc)

    if classification is not None and classification.get("type") == "proxy":
        impl = classification.get("implementation")
        if impl:
            # Per-contract redirect (one per nested proxy in the BFS); was the
            # single loudest INFO in recursive output. DEBUG per-iteration + a
            # folded ``proxies_redirected`` count for the lifecycle signal.
            logger.debug(
                "Recursive resolve: proxy redirect to impl",
                extra={"address": address, "implementation": impl},
            )
            _bump_stage_metric("proxies_redirected")
            effective_address = impl
        else:
            # #122: a proxy with no resolvable single implementation — an
            # eip2535 diamond, a beacon whose ``implementation()`` failed, or a
            # short-bytecode ``unknown`` proxy with no probe target. The address
            # is a delegatecall shell with no business logic; analyzing it yields
            # an empty guard set that downstream renders as permissionless. Fail
            # closed: refuse the shell and let the BFS record a degraded,
            # un-analyzed node (facet-union recall is a separate follow-up).
            _bump_stage_metric("proxies_unresolved")
            raise UnresolvedProxyError(
                f"proxy {address} (type={classification.get('proxy_type')}) implementation "
                "unresolved; refusing to analyze the proxy shell"
            )

    # Resolve bytecode_keccak so the persistent contract_materializations
    # row is keyed on byte-exact code match: identical-bytecode contracts
    # at different addresses share one row.
    bytecode_keccak: str | None = None
    try:
        from services.clients.rpc import get_code_with_keccak

        _code, bytecode_keccak = get_code_with_keccak(rpc_url, effective_address)
    except Exception as exc:
        logger.debug("Recursive resolve: get_code_with_keccak failed for %s: %s", effective_address, exc)

    # Cross-process cache: consult contract_materializations before paying
    # the forge+Slither cost. Two impl jobs in the same protocol — or a
    # re-run of a previously-analysed protocol on a different day — hit
    # this layer and skip the build. The advisory-lock-coalescing inside
    # ``materialize_or_wait`` ensures concurrent same-bytecode requests
    # across processes only run the builder once; the loser blocks on the
    # lock and reads the result.
    contract_name, static_facts, plan, predicate_trees = _materialize_with_cross_process_cache(
        effective_address=effective_address,
        bytecode_keccak=bytecode_keccak,
        workspace_prefix=workspace_prefix,
        chain=chain,
    )
    # Address-mismatch retarget: when the persistent row was populated for
    # a different address that shares this bytecode, the cached
    # plan["contract_address"] points at the OTHER address. Stamp it for
    # THIS call so observe_controllers reads from the right contract.
    if isinstance(static_facts.get("subject"), dict):
        static_facts["subject"]["address"] = effective_address
    plan["contract_address"] = effective_address
    if snapshot_address != effective_address:
        plan = {**plan, "contract_address": snapshot_address}

    snapshot = observe_controllers(cast(ObservationPlan, plan), rpc_url, chain_id=chain_id)
    permission_index = _build_permission_index(static_facts, snapshot)

    return {
        "static_facts": static_facts,
        "observation_plan": plan,
        "snapshot": snapshot,
        "predicate_trees": predicate_trees,
        "permission_index": permission_index,
    }


def _analysis_state(node: ResolutionNode, max_depth: int) -> ResolutionState | None:
    """Why this node is (or is not) analysed.

    Derived once at the end of the walk because this is the only place that
    holds ``max_depth`` alongside every node.

    Returns ``None`` — not determined — for an analyzable contract inside the
    horizon that is nonetheless unanalysed with no recorded failure. That
    combination is not known to be reachable, and inventing a value for it
    would be exactly the error this field exists to remove.
    """
    if node.get("analysis_state") == "analyzed":
        return "analyzed"
    if node.get("analysis_state") == "attempt_failed":
        return "attempt_failed"
    details = node.get("details")
    if isinstance(details, dict) and details.get("materialize_error"):
        return "attempt_failed"
    resolved_type = node.get("resolved_type")
    if resolved_type in ANALYZABLE_TYPES:
        if int(node.get("depth") or 0) > max_depth:
            return "beyond_depth_horizon"
        return None
    if resolved_type and resolved_type not in {"unknown", "None"}:
        # ``not_analyzable``, not ``not_a_contract``: the test is membership of
        # ANALYZABLE_TYPES, and the largest population outside it is Gnosis
        # Safes (230 of the local corpus's 1,236), which ARE contracts. The old
        # token stated something literally false about every one of them.
        #
        # ``"None"`` is excluded alongside ``"unknown"``: it is ``str(None)``,
        # a not-determined type that leaked through an unguarded
        # stringification (producers now coerce it via ``_coerce_resolved_type``,
        # but a stored graph from before that fix can still carry the token
        # into this recomputation via the policy refresh's pre-seed).
        # ``not_analyzable`` is a positive claim — "static_facts was never
        # applicable" — and an undetermined type proves no such thing.
        return "not_analyzable"
    return None


def _resolved_type_rank(resolved_type: str | None) -> int:
    """How much a ``resolved_type`` claims. A more specific answer may replace a
    vaguer one; the reverse is a loss of information.

    ``"contract"`` is the GENERIC answer — "there is code here" — and every
    analysed node was previously stamped with it unconditionally, so an address
    already classified ``timelock`` (carrying its ``delay``) was overwritten the
    moment the walk analysed it. Whether the type survived came down to walk
    order: it did only when the node happened to be re-ensured as a controller
    of a LATER-processed contract. 41 of the local corpus's 47 timelock nodes
    survived that way; the rest read ``contract``.

    Equal ranks keep last-write-wins, which is the pre-existing behaviour for
    two specific classifications of the same address.
    """
    if not resolved_type:
        return -1
    if resolved_type == "unknown":
        return 0
    if resolved_type == "contract":
        return 1
    return 2


def _ensure_node(
    nodes: dict[str, ResolutionNode],
    *,
    address: str,
    resolved_type: ResolvedControllerType,
    label: str,
    depth: int,
    node_type: ResolutionNodeKind,
    contract_name: str | None = None,
    analysis_state: ResolutionState | None = None,
    details: dict[str, object] | None = None,
    artifacts: dict[str, str] | None = None,
) -> str:
    normalized = address.lower()
    node_id = _address_node_id(normalized)
    current = nodes.get(node_id)
    payload: ResolutionNode = {
        "id": node_id,
        "address": normalized,
        "node_type": node_type,
        "resolved_type": resolved_type,
        "label": label,
        "contract_name": contract_name,
        "depth": depth,
        "analysis_state": analysis_state,
        "details": details or {},
        "artifacts": artifacts or {},
    }
    if current is None:
        nodes[node_id] = payload
        return node_id

    current["depth"] = min(current.get("depth", depth), depth)
    if contract_name:
        current["contract_name"] = contract_name
    if analysis_state == "analyzed":
        current["analysis_state"] = "analyzed"
        current["node_type"] = "contract"
    elif analysis_state == "attempt_failed" and current.get("analysis_state") != "analyzed":
        current["analysis_state"] = "attempt_failed"
    if _resolved_type_rank(resolved_type) >= _resolved_type_rank(current.get("resolved_type")):
        current["resolved_type"] = resolved_type
    if label:
        current["label"] = label
    if details:
        merged_details = dict(current.get("details", {}))
        merged_details.update(details)
        current["details"] = merged_details
    if artifacts:
        merged_artifacts = dict(current.get("artifacts", {}))
        merged_artifacts.update(artifacts)
        current["artifacts"] = merged_artifacts
    return node_id


def _edge_key(edge: ResolutionEdge) -> tuple:
    relation = edge["relation"]
    # Nested holder edges often appear via multiple upstream controller paths; keep one edge and merge notes.
    if relation in {"safe_owner", "timelock_owner", "proxy_admin_owner"}:
        return (
            edge["from_id"],
            edge["to_id"],
            relation,
            edge.get("label"),
        )
    return (
        edge["from_id"],
        edge["to_id"],
        relation,
        edge.get("label"),
        edge.get("source_controller_id"),
    )


def _add_edge(edges: dict[tuple, ResolutionEdge], edge: ResolutionEdge) -> None:
    key = _edge_key(edge)
    if key in edges:
        existing_notes = set(edges[key].get("notes", []))
        existing_notes.update(edge.get("notes", []))
        edges[key]["notes"] = sorted(existing_notes)
        return
    edges[key] = edge


def _nested_principals_for_details(
    resolved_type: ResolvedControllerType, details: dict[str, object]
) -> list[tuple[str, ResolutionRelation, str]]:
    principals: list[tuple[str, ResolutionRelation, str]] = []
    if resolved_type == "safe":
        owners = details.get("owners")
        for owner in owners if isinstance(owners, list) else []:
            if isinstance(owner, str) and owner.startswith("0x"):
                principals.append((owner.lower(), "safe_owner", "safe owner"))
    elif resolved_type == "timelock":
        owner = details.get("owner")
        if isinstance(owner, str) and owner.startswith("0x"):
            principals.append((owner.lower(), "timelock_owner", "timelock owner"))
    elif resolved_type == "proxy_admin":
        owner = details.get("owner")
        if isinstance(owner, str) and owner.startswith("0x"):
            principals.append((owner.lower(), "proxy_admin_owner", "proxy admin owner"))
    return principals


#: Provenance marker (``services/policy/capability_surface.py``) identifying a
#: principal the POLICY stage projected from a witnessed role grant. Read off the
#: persisted ``details`` a named code path wrote — never off ``label``.
ROLE_GRANT_SOURCE = "semantic_capability:role_grant"


def _maybe_probe_backlink(
    rpc_url: str,
    *,
    principal_address: str,
    gated_contract_address: str,
    details: Mapping[str, Any],
    node_type: str,
    chain_id: int | None,
) -> dict[str, Any] | None:
    """The ``vault()`` back-link witness for a role-granted CONTRACT principal.

    Fired on provenance, not on a name: only for a node whose ``details.source``
    is the role-grant marker and which resolved to an analyzable contract, so the
    ~88 plain-principal and non-role-grant nodes pay nothing. A raise here must
    not fail the walk — the witness is optional and its absence is honest.
    """
    if node_type != "contract" or details.get("source") != ROLE_GRANT_SOURCE:
        return None
    if not gated_contract_address or principal_address == gated_contract_address:
        return None
    try:
        return probe_declared_vault_backlink(
            rpc_url,
            principal_address,
            gated_contract_address,
            chain_id=chain_id,
        )
    except Exception as exc:
        logger.debug("recursive: back-link probe failed for %s: %s", principal_address, exc)
        return None


def _safe_role_int(role: Any) -> int | None:
    """Coerce a role identifier to int, returning None for non-int shapes.

    Role-name strings and Condition-mapping shapes cannot be represented
    in the recursive resolver's ``set[int]`` accumulator; callers must skip
    those grants entirely.
    """
    try:
        return int(role)
    except (TypeError, ValueError):
        return None


def _role_principals_from_permission_index(permission_index: Mapping[str, Any]) -> list[RolePrincipal]:
    principals: dict[str, RolePrincipalAccumulator] = {}
    for function in permission_index.get("functions", []):
        if not isinstance(function, dict):
            continue
        function_signature = str(function.get("function") or "")
        # ``or []``, not ``get(..., [])``: the key is now PRESENT with value
        # ``None`` on a role-gated function whose role identity is not
        # determined, and a dict default only fires on an
        # ABSENT key — so the plain default would iterate None and raise.
        # Not-determined contributes no role principals, exactly as [] did.
        for role_grant in function.get("authority_roles") or []:
            if not isinstance(role_grant, dict):
                continue
            role = _safe_role_int(role_grant.get("role"))
            if role is None:
                logger.debug(
                    "recursive: skipping non-int role %r on %s",
                    role,
                    function_signature,
                )
                continue
            for principal in role_grant.get("principals", []):
                if not isinstance(principal, dict):
                    continue
                address = str(principal.get("address", "")).lower()
                if not address.startswith("0x"):
                    continue
                details_raw = principal.get("details", {})
                details = dict(details_raw) if isinstance(details_raw, dict) else {}
                payload = principals.setdefault(
                    address,
                    {
                        "address": address,
                        "resolved_type": _coerce_resolved_type(principal.get("resolved_type")),
                        "details": details,
                        "roles": set(),
                        "functions": set(),
                    },
                )
                payload["roles"].add(role)
                if function_signature:
                    payload["functions"].add(function_signature)
                if payload.get("resolved_type") in {None, "", "unknown"} and principal.get("resolved_type"):
                    payload["resolved_type"] = _coerce_resolved_type(principal.get("resolved_type"))
                merged_details = dict(payload["details"])
                merged_details.update(details)
                payload["details"] = merged_details

        for controller in function.get("controllers", []):
            if not isinstance(controller, dict):
                continue
            controller_label = str(controller.get("label") or controller.get("source") or "controller")
            for principal in controller.get("principals", []):
                if not isinstance(principal, dict):
                    continue
                address = str(principal.get("address", "")).lower()
                if not address.startswith("0x"):
                    continue
                details_raw = principal.get("details", {})
                details = dict(details_raw) if isinstance(details_raw, dict) else {}
                payload = principals.setdefault(
                    address,
                    {
                        "address": address,
                        "resolved_type": _coerce_resolved_type(principal.get("resolved_type")),
                        "details": details,
                        "roles": set(),
                        "functions": set(),
                    },
                )
                if function_signature:
                    payload["functions"].add(function_signature)
                if payload.get("resolved_type") in {None, "", "unknown"} and principal.get("resolved_type"):
                    payload["resolved_type"] = _coerce_resolved_type(principal.get("resolved_type"))
                merged_details = dict(payload["details"])
                merged_details.update(details)
                merged_details.setdefault("controller_label", controller_label)
                payload["details"] = merged_details

    serialized: list[RolePrincipal] = []
    for payload in principals.values():
        serialized.append(
            {
                "address": payload["address"],
                "resolved_type": payload["resolved_type"],
                "details": dict(payload["details"]),
                "roles": sorted(payload["roles"]),
                "functions": sorted(payload["functions"]),
            }
        )
    return sorted(serialized, key=lambda item: str(item["address"]))


# Only these leaf roles prove that being IN the mapping confers authority;
# same set as the static plane's caller-gate promotion (`_AUTHORITY_LEAF_ROLES`
# in services/static/static_analysis/tracking.py).
_MAPPING_HARVEST_AUTHORITY_ROLES = frozenset({"caller_authority", "delegated_authority"})


def _mapping_leaf_confers_authority(leaf: Mapping[str, Any]) -> bool:
    """Does *leaf* prove that membership in its mapping CONFERS authority?

    The harvest publishes every enumerated member as a ``mapping_member``
    control edge — a member of CONTROL_EDGE_RELATIONS, i.e. a scorer input and
    a published control claim — so it must not out-claim the leaf the static
    plane lowered. Three discriminators, all read from that same leaf:

    - ``authority_role``: only an authority-bearing role qualifies. A
      ``business`` membership read (a duplicate-registration guard, an
      accounting map) says nothing about who controls the contract. An ABSENT
      role is a pre-schema tree — not-determined, so no authority is earned
      and nothing is harvested from it.
    - polarity: ``operator == "falsy"`` means the gate passes when the caller
      is NOT in the set (a denylist, an already-enrolled guard). Members of
      such a set are the blocked population, the exact opposite of
      authorities.
    - ``confidence``: an explicit ``"low"`` from the static plane disqualifies
      (today unreachable for authority roles — ``_derive_confidence`` floors
      them at medium — but the harvest must not depend on that staying true).
      Absent confidence is not lowered evidence and does not disqualify on
      its own.
    """
    if leaf.get("authority_role") not in _MAPPING_HARVEST_AUTHORITY_ROLES:
        return False
    if leaf.get("operator") == "falsy":
        return False
    if leaf.get("confidence") == "low":
        return False
    return True


def _mapping_writer_specs_from_predicate_trees(predicate_trees: Mapping[str, Any] | None) -> list[WriterEventSpec]:
    if not isinstance(predicate_trees, Mapping):
        return []
    tree_maps = [
        tree_map
        for tree_map in (predicate_trees.get("trees"), predicate_trees.get("check_trees"))
        if isinstance(tree_map, Mapping)
    ]
    if not tree_maps:
        return []

    specs: list[WriterEventSpec] = []
    seen: set[tuple[Any, ...]] = set()

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") != "LEAF":
            for child in node.get("children") or []:
                visit(child)
            return

        leaf = node.get("leaf")
        if not isinstance(leaf, dict):
            return
        if not _mapping_leaf_confers_authority(leaf):
            return
        descriptor = leaf.get("set_descriptor")
        if not isinstance(descriptor, dict):
            return
        storage_var = descriptor.get("storage_var")
        for hint in descriptor.get("enumeration_hint") or []:
            if not isinstance(hint, dict) or hint.get("direction") not in {"add", "remove"}:
                continue
            mapping_name = hint.get("mapping_name")
            if not isinstance(mapping_name, str) or not mapping_name:
                mapping_name = storage_var if isinstance(storage_var, str) else ""
            if not mapping_name:
                continue
            event_signature = hint.get("event_signature")
            event_name = hint.get("event_name")
            key_position = hint.get("key_position")
            if not isinstance(event_signature, str) or not isinstance(event_name, str):
                continue
            if not isinstance(key_position, int):
                continue
            identity = (
                mapping_name,
                event_signature,
                hint.get("direction"),
                key_position,
                hint.get("value_position"),
            )
            if identity in seen:
                continue
            seen.add(identity)
            specs.append(
                cast(
                    WriterEventSpec,
                    {
                        "mapping_name": mapping_name,
                        "event_signature": event_signature,
                        "event_name": event_name,
                        "key_position": key_position,
                        "indexed_positions": list(hint.get("indexed_positions") or []),
                        "direction": hint.get("direction"),
                        "writer_function": hint.get("writer_function") or "",
                        "value_position": hint.get("value_position"),
                    },
                )
            )

    for tree_map in tree_maps:
        for tree in tree_map.values():
            visit(tree)
    return specs


def _replay_mapping_principals(
    *,
    address: str,
    mapping_specs: list[WriterEventSpec],
    contract_node_id: str,
    depth: int,
    nodes: dict[str, ResolutionNode],
    edges: dict[tuple, ResolutionEdge],
    chain_id: int,
) -> str:
    """Replay mapping-writer events for *address* into principal nodes/edges,
    returning the enumeration status.

    FLOOR-or-DEFER: a contract emits no events before it exists, so flooring the
    replay at its deploy block returns the identical principal set without the
    genesis walk that 429-storms HyperSync. When the floor is unknown we DEFER
    (skip the live scan, status ``deferred_no_floor``) rather than walk from 0 —
    these ACL/authority addresses are enrolled+backfilled, so the principal set
    materializes on a later policy pass instead of stranding the function.
    """
    hypersync_token = os.getenv("ENVIO_API_TOKEN") or ""
    logger.info(
        "mapping_enumerator: writer-event specs collected",
        extra={
            "address": address,
            "spec_count": len(mapping_specs),
            "token": "present" if hypersync_token else "missing",
        },
    )
    if not hypersync_token:
        return "skipped"

    from services.resolution.creation_block_floor import resolve_scan_floor

    scan_floor = resolve_scan_floor(address, chain_id)
    if scan_floor is None:
        logger.info(
            "mapping_enumerator: deferring replay (no scan floor resolved)",
            extra={"address": address, "decision": "deferred_no_floor"},
        )
        return "deferred_no_floor"

    from services.resolution.mapping_enumerator import enumerate_mapping_allowlist_sync

    try:
        result = enumerate_mapping_allowlist_sync(
            address,
            mapping_specs,
            # The scan URL is derived from the walk's chain, not a mainnet
            # default. Mainnet ("1") is byte-identical to the prior chain-less call.
            chain=str(chain_id),
            bearer_token=hypersync_token,
            from_block=scan_floor,
        )
    except Exception as exc:
        # Bounds are inside enumerate_mapping_allowlist; raises here are
        # unexpected (auth, hypersync load, etc).
        record_degraded(phase="mapping_enumerator", exc=exc, context={"address": address})
        logger.warning(
            "mapping_enumerator UNEXPECTED FAILURE for %s: %s — treating as truncated",
            address,
            exc,
        )
        return "error"

    enumerated = list(result["principals"])
    enumeration_status = result["status"]
    if enumeration_status != "complete":
        # A truncated/errored scan returns a partial present-set: authorized
        # addresses past the bound are silently absent. Surface it as a degraded
        # breadcrumb + a chartable count, not just a WARNING line.
        record_degraded(
            phase="mapping_enum_incomplete",
            exc=RuntimeError(f"mapping enumeration {enumeration_status}"),
            context={
                "address": address,
                "status": enumeration_status,
                "pages_fetched": result["pages_fetched"],
                "last_block_scanned": result["last_block_scanned"],
            },
        )
        _bump_stage_metric("mapping_enum_incomplete")
        logger.warning(
            "mapping_enumerator: incomplete enumeration (principal set may be missing entries)",
            extra={
                "address": address,
                "enumeration_status": enumeration_status,
                "pages_fetched": result["pages_fetched"],
                "last_block_scanned": result["last_block_scanned"],
            },
        )
    logger.info(
        "mapping_enumerator: enumeration complete",
        extra={"address": address, "principals": len(enumerated), "enumeration_status": enumeration_status},
    )

    for principal in enumerated:
        member_addr = principal["address"]
        if member_addr.lower() == address.lower():
            # A contract enumerated as a member of its OWN mapping (e.g. a
            # timelock granting itself a Solady `_roles` role) is real on-chain
            # state, but as a control edge it is degenerate: X->X asserts
            # nothing, yet the raw graph plane serves it verbatim through the
            # static_facts-detail API, and the _ensure_node call below would merge
            # principal fields (controller_label/mapping_name/...) onto the
            # contract's own node and clobber its label with the mapping name.
            # Skip the self edge. (The value closure and the Surface
            # indirect-path index each drop self loops on their own.)
            logger.debug(
                "mapping_enumerator: skipping self-membership edge",
                extra={"address": address, "mapping_name": principal["mapping_name"]},
            )
            continue
        _ensure_node(
            nodes,
            address=member_addr,
            resolved_type="unknown",
            label=principal["mapping_name"],
            depth=depth + 1,
            node_type="principal",
            details={
                "address": member_addr,
                "controller_label": principal["mapping_name"],
                "mapping_name": principal["mapping_name"],
                "last_seen_block": principal["last_seen_block"],
                "direction_history": principal["direction_history"],
            },
        )
        _add_edge(
            edges,
            {
                "from_id": contract_node_id,
                "to_id": _address_node_id(member_addr),
                "relation": "mapping_member",
                "label": principal["mapping_name"],
                "source_controller_id": f"mapping:{principal['mapping_name']}",
                "notes": [],
            },
        )
    return enumeration_status


def _maybe_queue_address(
    queue: deque[PendingContract], queued: set[str], address: str, depth: int, max_depth: int
) -> None:
    if address in queued or depth > max_depth:
        return
    queue.append({"address": address, "depth": depth})
    queued.add(address)


def _add_nested_principals(
    *,
    nodes: dict[str, ResolutionNode],
    edges: dict[tuple, ResolutionEdge],
    queue: deque[PendingContract],
    queued: set[str],
    rpc_url: str,
    from_node_id: str,
    source_controller_id: str | None,
    resolved_type: ResolvedControllerType,
    details: dict[str, object],
    depth: int,
    max_depth: int,
    classify_fn: Any | None = None,
    chain_id: int | None = None,
) -> None:
    for nested_address, relation, label in _nested_principals_for_details(resolved_type, details):
        classify = classify_fn or (lambda addr: classify_resolved_address(rpc_url, addr, chain_id=chain_id))
        nested_type, nested_details = classify(nested_address)
        nested_node_type = "contract" if nested_type in ANALYZABLE_TYPES else "principal"
        nested_node_id = _ensure_node(
            nodes,
            address=nested_address,
            resolved_type=nested_type,
            label=label,
            depth=depth + 1,
            node_type=nested_node_type,
            details=nested_details,
        )
        _add_edge(
            edges,
            {
                "from_id": from_node_id,
                "to_id": nested_node_id,
                "relation": relation,
                "label": label,
                "source_controller_id": source_controller_id,
                "notes": [],
            },
        )
        if nested_type in ANALYZABLE_TYPES:
            _maybe_queue_address(queue, queued, nested_address, depth + 1, max_depth)


def resolve_control_graph(
    *,
    root_artifacts: LoadedArtifacts,
    rpc_url: str,
    chain_id: int,
    max_depth: int = DEFAULT_RECURSION_MAX_DEPTH,
    workspace_prefix: str = "recursive",
    materialized_contracts_override: dict[str, LoadedArtifacts] | None = None,
    classify_cache: dict[str, tuple[str, dict[str, object]]] | None = None,
    initial_graph: ResolutionGraph | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> tuple[ResolutionGraph, dict[str, LoadedArtifacts]]:
    """BFS the control chain.

    Returns ``(graph, materialized_contracts_by_address)``; classify_cache is mutated in place.

    ``chain_id`` is required: it scopes the two chain-sensitive reads
    inside the walk — the ``contract_materializations`` cache key (via the
    chain's canonical name) and the mapping-writer replay's scan floor. A
    chainless walk can no longer run as mainnet; callers thread the job's chain."""
    chain_name = _chain_name_for_materialization(chain_id)
    root_analysis = root_artifacts["static_facts"]
    root_subject = root_analysis.get("subject", {})
    root_address = str(root_subject.get("address", "")).lower()

    queue: deque[PendingContract] = deque(
        [
            {
                "address": root_address,
                "depth": 0,
                "artifacts": root_artifacts,
            }
        ]
    )
    queued = {root_address}
    processed: set[str] = set()
    _classify_cache: dict[str, tuple[str, dict[str, object]]] = classify_cache if classify_cache is not None else {}
    materialized_contracts: dict[str, LoadedArtifacts] = dict(materialized_contracts_override or {})

    classify_stats: dict[str, int] = {"hits": 0, "misses": 0}

    def _cached_classify(addr: str) -> tuple[ResolvedControllerType, dict[str, object]]:
        key = addr.lower()
        if key in _classify_cache:
            classify_stats["hits"] += 1
            kind, details = _classify_cache[key]
            # The cache may be pre-seeded from a persisted artifact, so a read
            # is not a proven vocabulary member until coerced.
            return _coerce_resolved_type(kind), details
        classify_stats["misses"] += 1
        kind, details, cacheable = classify_resolved_address_with_status(rpc_url, addr, chain_id=chain_id)
        # Skip caching transient RPC errors — otherwise a "contract" fallback gets cemented in the persisted
        # classified_addresses artifact.
        if cacheable:
            _classify_cache[key] = (kind, details)
        return kind, details

    nodes: dict[str, ResolutionNode] = {}
    edges: dict[tuple, ResolutionEdge] = {}

    # Pre-seed the graph from a prior walk so the policy refresh path skips re-analyzing already-processed nested
    # contracts.
    if initial_graph is not None:
        for node in initial_graph.get("nodes", []):
            if not isinstance(node, dict):
                continue
            node_id = node.get("id")
            if isinstance(node_id, str):
                seeded = dict(node)
                # A stored graph written before the ``str(None)`` guard can
                # carry the fabricated ``"None"`` type; coerce it back to the
                # not-determined token at the boundary so it can neither win a
                # ``_resolved_type_rank`` merge nor read as a concrete type.
                seeded["resolved_type"] = _coerce_resolved_type(seeded.get("resolved_type"))
                nodes[node_id] = cast(ResolutionNode, seeded)
        for edge in initial_graph.get("edges", []):
            if not isinstance(edge, dict):
                continue
            edges[_edge_key(cast(ResolutionEdge, edge))] = cast(ResolutionEdge, dict(edge))
        # Mark already-analyzed nested contracts as processed; the root must re-walk so freshly-computed role principals
        # get projected.
        for node in initial_graph.get("nodes", []):
            if not isinstance(node, dict) or node.get("analysis_state") != "analyzed":
                continue
            node_address = (node.get("details") or {}).get("address")
            if isinstance(node_address, str):
                addr = node_address.lower()
                if addr and addr != root_address:
                    processed.add(addr)

    from services.concurrency import parallel_map

    def _materialize_for_pending(pending: PendingContract) -> tuple[LoadedArtifacts | None, BaseException | None]:
        """Materialize one pending contract's artifacts. Returns
        ``(artifacts, error)`` so the caller wires the success and error
        branches deterministically on the main thread.

        Storage failing to answer is the one case that does NOT come back as an
        error tuple. Every other materialize failure is a fact about the
        contract or its compile, and the caller degrades that contract to
        ``attempt_failed`` and walks on. An unreadable bucket is a fact about
        us: the static_facts may exist and simply be out of reach, the same outage
        hits every sibling in the level, and degrading would let the whole walk
        return normally so nothing above ever re-runs. Propagating is what makes
        the stage retryable (``workers/retry_policy`` classifies both storage
        types below as transient), and a retry is the only thing that can turn
        not-determined into a fact.
        """
        address = pending["address"]
        preloaded = pending.get("artifacts")
        if preloaded is not None:
            return preloaded, None
        if address in materialized_contracts:
            return materialized_contracts[address], None
        try:
            artifacts = _materialize_contract_artifacts(
                address,
                rpc_url,
                workspace_prefix=workspace_prefix,
                chain=chain_name,
                chain_id=chain_id,
            )
            return artifacts, None
        except (StorageContentIncomplete, StorageUnavailable):
            raise
        except Exception as exc:
            return None, exc

    _levels = 0
    while queue:
        # BFS guarantees ``queue`` is depth-ordered. Drain every pending entry
        # at the current minimum depth into one level so they materialize
        # concurrently; new entries appended during wiring land at a strictly
        # greater depth and roll into the next iteration.
        target_depth = queue[0]["depth"]
        level_pending: list[PendingContract] = []
        while queue and queue[0]["depth"] == target_depth:
            entry = queue.popleft()
            if entry["address"] in processed or entry["depth"] > max_depth:
                continue
            level_pending.append(entry)

        if not level_pending:
            continue

        _levels += 1
        logger.info(
            "recursive level depth=%d contracts=%d",
            target_depth,
            len(level_pending),
            extra={"phase": "recursive_level", "depth": target_depth, "level_size": len(level_pending)},
        )

        # Parallel materialization. ``_materialize_contract_artifacts``
        # consults ``contract_materializations`` (cheap on a hit) and runs
        # Slither + ``forge build`` in a fresh tempdir on a miss. The miss
        # path is **CPU-bound** (Slither's IR build + solc + foundry compile
        # are not GIL-friendly), so the cap has to track host vCPU count
        # rather than the I/O-bound RPC fan-out ceiling — running
        # ``max_workers=8`` on a shared-cpu-2x VM thrashes the load average
        # to >5 and wedges sibling workers (observed on psat-pr-60 at
        # 2026-05-02). Default 2 matches the smallest worker VM size;
        # bumpable via env for performance-2x / shared-cpu-4x.
        materialize_fanout = max(1, int(os.getenv("PSAT_RESOLUTION_MATERIALIZE_FANOUT", "2")))
        materialized = parallel_map(
            _materialize_for_pending,
            level_pending,
            max_workers=materialize_fanout,
            heartbeat=heartbeat,
        )

        for pending, (_pending, outcome) in zip(level_pending, materialized):
            if isinstance(outcome, BaseException):
                # ``_materialize_for_pending`` converts every failure it is
                # entitled to answer for into ``(None, exc)``. What arrives
                # here is either a genuine bug or storage declining to answer,
                # which it re-raises on purpose. Both must leave this function:
                # the walk cannot describe a graph it could not read, and the
                # stage above is what retries.
                raise outcome
            artifacts, mat_exc = outcome
            address = pending["address"]
            depth = pending["depth"]

            if mat_exc is not None or artifacts is None:
                err_text = str(mat_exc) if mat_exc is not None else "no artifacts produced"
                contract_name = _contract_name_for_address(address, chain_id)
                record_degraded(
                    phase="recursive_materialize",
                    exc=mat_exc if mat_exc is not None else RuntimeError(err_text),
                    context={"address": address, "depth": depth},
                )
                logger.warning(
                    "Recursive resolve: failed to materialize nested contract %s at depth %s: %s",
                    address,
                    depth,
                    err_text,
                )
                _ensure_node(
                    nodes,
                    address=address,
                    resolved_type="contract",
                    label=contract_name or address,
                    depth=depth,
                    node_type="contract",
                    analysis_state="attempt_failed",
                    contract_name=contract_name,
                    details={"address": address, "materialize_error": err_text},
                )
                processed.add(address)
                continue

            if address not in materialized_contracts:
                materialized_contracts[address] = artifacts

            processed.add(address)
            static_facts = artifacts["static_facts"]
            snapshot = artifacts["snapshot"]
            permission_index = artifacts.get("permission_index")
            subject = static_facts.get("subject", {})
            contract_name = str(subject.get("name") or address)
            # The classifier's answer, not a hardcoded "contract". A timelock
            # that is itself analysed used to lose its type AND its ``delay``
            # here: EtherFiTimelock's own node read ``resolved_type=contract``
            # with no delay, and that delay is a credit-bearing scoring input.
            # ``_cached_classify`` is the same memo the controller/principal
            # wiring already uses, so a nested contract reached as someone's
            # controller is a cache hit; a root costs one classification.
            analyzed_type, analyzed_details = _cached_classify(address)
            node_details: dict[str, object] = {"address": address}
            if analyzed_type in {"", "unknown"}:
                # Classification did not answer. "contract" is what we DO know
                # (the artifacts materialized), and it is the generic rank, so
                # it cannot overwrite a specific type set elsewhere.
                analyzed_type = "contract"
            else:
                node_details.update(analyzed_details)
            contract_node_id = _ensure_node(
                nodes,
                address=address,
                resolved_type=analyzed_type,
                label=contract_name,
                depth=depth,
                node_type="contract",
                contract_name=contract_name,
                analysis_state="analyzed",
                details=node_details,
                artifacts={"data_key": f"recursive:{address.lower()}"},
            )

            # Replay semantic mapping-writer event hints into principal nodes;
            # bounded enumeration surfaces truncation via the `status` field.
            mapping_specs = _mapping_writer_specs_from_predicate_trees(artifacts.get("predicate_trees"))
            if mapping_specs:
                enumeration_status = _replay_mapping_principals(
                    address=address,
                    mapping_specs=mapping_specs,
                    contract_node_id=contract_node_id,
                    depth=depth,
                    nodes=nodes,
                    edges=edges,
                    chain_id=chain_id,
                )
                # Surface enumeration status on the node so downstream stages can flag incomplete allowlists.
                if contract_node_id in nodes:
                    nodes[contract_node_id]["details"]["mapping_enumeration_status"] = enumeration_status

            for controller_id, controller_value in snapshot.get("controller_values", {}).items():
                controller_address = str(controller_value.get("value", "")).lower()
                if not controller_address.startswith("0x") or len(controller_address) != 42:
                    continue
                resolved_type = _coerce_resolved_type(controller_value.get("resolved_type"))
                details = dict(controller_value.get("details", {}))
                controller_label = str(controller_value.get("source") or controller_id)
                controller_node_type = "contract" if resolved_type in ANALYZABLE_TYPES else "principal"
                controller_node_id = _ensure_node(
                    nodes,
                    address=controller_address,
                    resolved_type=resolved_type,
                    label=controller_label,
                    depth=depth + 1,
                    node_type=controller_node_type,
                    details=details,
                )
                # A slot the contract only CALLS is not a controller of it.
                # Provenance ABSENT is the third state and gets the third
                # relation: neither question was answered, so the address was
                # enrolled from a predicate tree without ever being shown to
                # gate a caller. ``controller_value`` would assert an authority
                # nothing proved (one widening of the enrolled-target set minted
                # 37 such targets in a single merge — pure constants like
                # HUNDRED_PERCENT_IN_BPS, non-authority mappings like _balances,
                # 28 of them surviving the primitive-scalar skip);
                # ``external_call_target`` would assert the opposite unproven
                # fact. The unattributed relation keeps the edge visible and
                # moves no authority.
                #
                # This is NOT the forbidden demotion of a proven authority to a
                # mere callee: that rule protects an authority that was actually
                # established. Here the not-determined input reaches a
                # not-determined relation.
                provenance = controller_value.get("authority_provenance")
                if provenance == _PROVENANCE_CALL_TARGET:
                    relation = EDGE_RELATION_EXTERNAL_CALL_TARGET
                elif provenance == _PROVENANCE_CALLER_GATE:
                    relation = EDGE_RELATION_CONTROLLER_VALUE
                else:
                    relation = EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED
                _add_edge(
                    edges,
                    {
                        "from_id": contract_node_id,
                        "to_id": controller_node_id,
                        "relation": relation,
                        "label": controller_label,
                        "source_controller_id": controller_id,
                        "notes": [
                            f"resolved_type={resolved_type}",
                            f"authority_provenance={provenance or 'not_determined'}",
                        ],
                    },
                )

                if resolved_type in ANALYZABLE_TYPES:
                    _maybe_queue_address(queue, queued, controller_address, depth + 1, max_depth)

                _add_nested_principals(
                    nodes=nodes,
                    edges=edges,
                    queue=queue,
                    queued=queued,
                    depth=depth,
                    rpc_url=rpc_url,
                    from_node_id=controller_node_id,
                    source_controller_id=controller_id,
                    resolved_type=resolved_type,
                    details=details,
                    max_depth=max_depth,
                    classify_fn=_cached_classify,
                    chain_id=chain_id,
                )

            for principal_value in _role_principals_from_permission_index(permission_index or {}):
                principal_address = str(principal_value["address"]).lower()
                if principal_address == address:
                    continue
                resolved_type = _coerce_resolved_type(principal_value.get("resolved_type"))
                details = dict(principal_value["details"])
                if resolved_type == "unknown":
                    resolved_type, classified_details = _cached_classify(principal_address)
                    merged_details = dict(details)
                    merged_details.update(classified_details)
                    details = merged_details

                node_type = "contract" if resolved_type in ANALYZABLE_TYPES else "principal"
                backlink = _maybe_probe_backlink(
                    rpc_url,
                    principal_address=principal_address,
                    gated_contract_address=address,
                    details=details,
                    node_type=node_type,
                    chain_id=chain_id,
                )
                if backlink is not None:
                    details = {**details, "gated_contract_backlink": backlink}
                principal_node_id = _ensure_node(
                    nodes,
                    address=principal_address,
                    resolved_type=resolved_type,
                    label="role principal",
                    depth=depth + 1,
                    node_type=node_type,
                    details=details,
                )
                roles = principal_value["roles"]
                functions = principal_value["functions"]
                _add_edge(
                    edges,
                    {
                        "from_id": contract_node_id,
                        "to_id": principal_node_id,
                        "relation": "role_principal",
                        "label": f"roles {','.join(str(role) for role in roles)}" if roles else "role principal",
                        "source_controller_id": None,
                        "notes": [f"functions={len(functions)}", *(f"role={role}" for role in roles)],
                    },
                )
                if resolved_type in ANALYZABLE_TYPES:
                    _maybe_queue_address(queue, queued, principal_address, depth + 1, max_depth)
                _add_nested_principals(
                    nodes=nodes,
                    edges=edges,
                    queue=queue,
                    queued=queued,
                    rpc_url=rpc_url,
                    from_node_id=principal_node_id,
                    source_controller_id=None,
                    resolved_type=resolved_type,
                    details=details,
                    depth=depth + 1,
                    max_depth=max_depth,
                    classify_fn=_cached_classify,
                    chain_id=chain_id,
                )

    # Aggregate profile for the BFS orchestration. The per-contract static cost
    # is already visible via the nested ``pipeline_profile`` lines; this surfaces
    # the orchestration shape (levels walked, contracts processed, classify cache
    # effectiveness) that was previously opaque inside the ``recursive_graph``
    # phase. ``record_stage_metric`` is a no-op outside a worker job context.
    _mat_metrics = stage_metrics_var.get() or {}
    _mat_builds = _mat_metrics.get("materialize_builds", 0)
    _mat_hits = _mat_metrics.get("materialize_cache_hits", 0)
    logger.info(
        "recursive graph profile: levels=%d processed=%d builds=%d cache_hits=%d "
        "classify_hits=%d classify_misses=%d nodes=%d edges=%d",
        _levels,
        len(processed),
        _mat_builds,
        _mat_hits,
        classify_stats["hits"],
        classify_stats["misses"],
        len(nodes),
        len(edges),
        extra={
            "profile_kind": "recursive_profile",
            "levels": _levels,
            "processed": len(processed),
            "materialize_builds": _mat_builds,
            "materialize_cache_hits": _mat_hits,
            "classify_hits": classify_stats["hits"],
            "classify_misses": classify_stats["misses"],
            "nodes": len(nodes),
            "edges": len(edges),
        },
    )
    record_stage_metric("recursive_levels", _levels)
    record_stage_metric("recursive_classify_hits", classify_stats["hits"])
    record_stage_metric("recursive_classify_misses", classify_stats["misses"])

    for _node in nodes.values():
        _node["analysis_state"] = _analysis_state(_node, max_depth)

    graph: ResolutionGraph = {
        "schema_version": "0.1",
        "root_contract_address": root_address,
        "max_depth": max_depth,
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges.values(), key=lambda item: (item["from_id"], item["relation"], item["to_id"])),
    }
    return graph, materialized_contracts
