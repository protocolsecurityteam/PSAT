"""Reconcile ``control_graph_nodes`` typing + intrinsic config from ``FunctionPrincipal``.

The pipeline types a governance principal (Safe / Timelock / proxy admin)
in two places, at two stages:

* The **resolution stage** writes ``control_graph_nodes.resolved_type`` from
  its graph walk, and — for the safes/timelocks it reaches — the intrinsic
  config that defines them (a safe's ``owners`` / ``threshold``, a timelock's
  ``delay``). The walk only runs the on-chain classifier on addresses it
  reaches structurally, so a principal that controls a contract *only* through
  per-function authority — e.g. a multisig that calls ``EtherFiTimelock.cancel``
  but appears nowhere in the storage-slot graph — is left ``unknown`` with no
  intrinsic config at all.
* The **policy stage** writes ``function_principals.resolved_type`` with a
  *live* ``classify_resolved_address`` fallback for cache misses, so the same
  address comes out ``safe`` / ``timelock`` / ``proxy_admin`` — and that
  classifier returns the intrinsic config (``owners`` / ``threshold`` / delay)
  in the same call, stored on ``function_principals.details``.

The classifier is deterministic and address-only, so the policy stage's answer
is simply more complete — not a different opinion. But it never propagates back
to ``control_graph_nodes``, so every consumer that reads CGN (monitoring
enrollment's candidate walk, the chat context layer, the Surface canvas) can see
a stale ``unknown`` for an address the system has already classified.

This pass closes that gap protocol-wide. It folds back **both** halves of the
classifier's answer — the type *and* the intrinsic config that justifies it.
Folding the type alone would leave a node asserting ``safe`` with no ``owners``,
a state the resolution stage never produces; the Surface principal builder then
reads that owner-less node and renders a multisig with no signers. The config
travels with the type so a reconciled node is indistinguishable from a
structurally-resolved one. It must be protocol-wide rather than per-contract
because a principal's ``unknown`` CGN nodes live on the contracts it *governs*,
while its FP authority sits on a different contract (the timelock it calls) — a
per-contract write-back would miss most of them.

Only ``unknown`` / NULL types are upgraded, and only to the governance principal
types (Safe / Timelock / proxy admin) that downstream views treat as
principals; a concrete graph-walk type is never overwritten, and EOAs/plain
contracts are left alone so this can't reshape unrelated Surface nodes.
Intrinsic keys are merged with ``setdefault`` semantics onto nodes whose type
already matches the folded one, so a structurally-resolved node's own config is
never clobbered. Because a node already carrying both type and config is left
untouched, re-running on already-typed rows backfills config a prior
(type-only) reconcile left missing — and converges: a second run changes
nothing.

That pass is UPDATE-only, and :func:`materialize_fp_principal_nodes` below is
the INSERT half it always lacked — see that function's docstring for the defect
it closes.
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
from schemas.observations import ResolvedControllerType, coerce_resolved_controller_type
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

# FP ``resolved_type`` values folded back into CGN. These spellings are shared
# with the CGN vocabulary verbatim. EOA / contract are intentionally excluded:
# they're not monitored controllers and writing them would surface unrelated
# nodes on the Surface canvas (whose node-keep filter admits any principal type).
_RECONCILABLE_TYPES: tuple[ResolvedControllerType, ...] = ("safe", "timelock", "proxy_admin")

# Tie-break when one address holds more than one FP type across functions:
# prefer the higher-authority kind (a Safe that also looks like a proxy admin
# is a Safe). Matches the Safe > Timelock > proxy admin precedence used by
# ``services.governance.primary_controller``.
_TYPE_PRIORITY: dict[ResolvedControllerType, int] = {"safe": 3, "timelock": 2, "proxy_admin": 1}

# Intrinsic principal-config keys that travel WITH the type — the classifier
# returns them in the same call (a safe's signer set + threshold, a timelock's
# delay). Relationship-specific FP keys (``conditions`` / ``trace`` /
# ``confidence`` / ``source`` / ``membership_quality``) are deliberately
# excluded: they describe a per-function authority edge, not the principal
# address, and carry no meaning on a CGN node.
_INTRINSIC_DETAIL_KEYS = ("owners", "threshold", "delay", "delay_seconds", "min_delay")


def _chain_key(chain: str | None) -> str:
    """Normalize a contract's chain-name for keying: a NULL/blank chain is a
    legacy mainnet row, folded to the same key as an explicit ``ethereum`` so
    the two never split a mainnet principal across two buckets."""
    return _coalesce_chain(chain)


def _coherent_analysis_state(node: Any) -> str | None:
    """The ``analysis_state`` the resolution walk itself would stamp on this
    node's CURRENT ``resolved_type`` — the single source of truth is
    ``services.resolution.recursive._analysis_state``, applied to the row's own
    fields.

    Used after a type upgrade so the pair stays coherent: the walk left
    ``analysis_state`` NULL because the type was ``unknown`` at walk time, and
    folding in ``safe`` without revisiting the state leaves a row that types an
    address as a Safe while claiming its analyzability was never determined.

    ``graph_max_depth`` NULL suppresses the depth comparison by
    using an unreachable horizon: without the walk's recorded horizon we cannot
    honestly claim ``beyond_depth_horizon``, and the fallthrough for analyzable
    types is ``None`` — which leaves the column NULL, not a guess.
    """
    # Lazy import: module-level would re-create the resolution↔policy package
    # cycle this file's callers already tiptoe around.
    from services.resolution.recursive import _analysis_state

    max_depth = node.graph_max_depth if isinstance(node.graph_max_depth, int) else (node.depth or 0) + 1
    walk_node = {
        "analysis_state": node.analysis_state,
        "details": node.details if isinstance(node.details, dict) else {},
        "resolved_type": node.resolved_type,
        "depth": node.depth or 0,
    }
    return _analysis_state(cast(Any, walk_node), max_depth)


def _merge_intrinsic(into: dict[str, Any], src: Mapping[str, Any]) -> None:
    """Fold intrinsic principal-config keys from *src* into *into*, keeping the
    most complete value: the longest ``owners`` list, the first non-null scalar
    for everything else."""
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
    """Fold authoritative FunctionPrincipal typing + intrinsic config into CGN.

    *contract_ids* — the protocol's analyzed contract ids (the same set the
    caller enrolls). Both the FP read and the CGN write are scoped to it.

    Returns the number of ``control_graph_nodes`` rows changed (a type upgrade,
    a config backfill, or both, counts once). Idempotent.
    """
    if not contract_ids:
        return 0

    # Per (chain, address): every (type, details) the protocol's FP rows assign
    # it, so we can pick the best type AND pull intrinsic config from the rows of
    # that type. Keyed by chain too — the same address is a distinct principal on
    # each chain (a Safe on ethereum, a Timelock on base), and control edges never
    # cross chains (inv. 15), so a per-address fold would let one chain's higher-
    # priority type overwrite the twin's node on another chain.
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
        # The SQL filter above guarantees membership; the coercion carries the
        # proof to the type level without a cast.
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
        # Intrinsic config comes only from the rows of the winning type — a
        # safe's owners must not bleed onto a timelock-typed write, and vice
        # versa.
        intrinsic: dict[str, Any] = {}
        for rtype, det in rows:
            if rtype == best:
                _merge_intrinsic(intrinsic, det)
        if intrinsic:
            intrinsic_by_key[key] = intrinsic

    if not best_by_key:
        return 0

    # Load the nodes for these addresses that are either still untyped OR
    # already one of the governance types — the latter lets a re-run backfill
    # intrinsic config onto rows a prior type-only reconcile already upgraded.
    # ControlGraphNode has no chain column; the chain comes from the node's own
    # parent Contract, so join it in and key the fold lookup on (chain, address).
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

        # Type upgrade: only fill unknown/NULL, never overwrite a concrete type.
        if node.resolved_type in (None, "unknown") and new_type != node.resolved_type:
            node.resolved_type = new_type
            changed = True

        # Intrinsic-config fold: add owners/threshold/delay onto a node whose
        # type matches the folded one (so we never attach a safe's owners to a
        # timelock), without clobbering config the resolution stage already
        # wrote. JSONB isn't a MutableDict, so reassign to mark it dirty.
        node_intrinsic = intrinsic_by_key.get(key)
        if node_intrinsic and node.resolved_type == new_type:
            current = dict(node.details) if isinstance(node.details, dict) else {}
            missing = {k: v for k, v in node_intrinsic.items() if k not in current}
            if missing:
                node.details = {**current, **missing}
                changed = True

        # analysis_state coherence: the walk stamped NULL ("not determined")
        # while the type was ``unknown``; once this pass types the node, the
        # pair ('safe', NULL) reads "typed as a Safe, analyzability not
        # determined" — a claim the same row refutes. Stamp exactly what the
        # walk would now derive from the row's own fields, and only onto NULL:
        # a determined state ('analyzed', 'attempt_failed', ...) is never
        # overwritten. Also heals rows a prior type-only reconcile already
        # upgraded (type unchanged this run, state still NULL). For analyzable
        # upgrades (timelock / proxy_admin) the derivation returns None and the
        # column honestly stays NULL. Converges: a second run changes nothing.
        if node.resolved_type == new_type and node.analysis_state is None:
            derived_state = _coherent_analysis_state(node)
            if derived_state is not None:
                node.analysis_state = derived_state
                changed = True

        if changed:
            updated += 1

    return updated


#: How many nodes ONE ``(contract, deployment)`` anchor may mint per pass.
#:
#: **A HARD CAP WITH A PERMANENT TAIL, not a delay.** An earlier draft of this
#: constant claimed a cut candidate would be picked up by the next pass, because
#: ``existing_node`` is checked before the budget. That is FALSE in production
#: and the sequence is what refutes it: every job rewrites this
#: ``(contract, deployment)`` scope wholesale (resolution stage, then the policy
#: stage) BEFORE the mint runs, so no minted row survives into the next pass for
#: ``existing_node`` to find. The candidate order is ``sorted(candidates)``, so
#: each pass re-mints the same lexicographic prefix and drops the same tail —
#: permanently, until the cap is raised. Replayed 3 jobs deep on the PR-161
#: corpus at a cap of 16: one anchor over budget (27 candidates), 11 addresses
#: permanently invisible, 2 of them contract-typed job candidates appearing at
#: no other anchor (0xc4922d64…, 0xfd78ee91…) — a residual of 35 rather than
#: 37. The boundary is inclusive of the cap slot: rank 16 mints, because the
#: budget gate only bites after the 16th insert.
#:
#: The default is therefore sized to leave NO LIVE TAIL rather than to be a
#: tuning knob: 64 is 2x the observed per-anchor maximum of 31 distinct
#: principals (0 of 83 corpus anchors exceed it; 2 exceed 16). It is a BACKSTOP
#: against a pathological anchor, and a NAMED MODEL CHOICE — no number here is
#: claimed to be derived from the corpus, which is also why it is not pinned at
#: 31 or 32. Fan-out is bounded elsewhere and unchanged: ``PERIMETER_SPAWN_LIMIT``
#: (8) caps jobs per policy refresh and ``PERIMETER_SPAWN_DEPTH_CAP`` (2) caps
#: generations; this cap bounds ROW growth only, and minting costs no RPC.
#:
#: Lowering it re-introduces a permanent tail. Every cut still lands in
#: ``omitted[]`` with ``budget_exhausted``, so the tail is always named — but it
#: must be read as a loss, not a queue.
FP_MATERIALIZE_LIMIT = int(os.getenv("PSAT_FP_MATERIALIZE_LIMIT", "64"))


def _address_node_id(address: str) -> str:
    """The graph's node-id convention, ``address:0x…``.

    Mirrors ``services.resolution.recursive._address_node_id`` verbatim and is
    duplicated rather than imported for the same reason every other symbol in
    this module is lazily imported from there: a module-level import re-creates
    the resolution↔policy package cycle. It is the identity
    ``control_graph_edges.from_node_id`` / ``to_node_id`` are joined on
    (``services.effects.selection._NODE_PREFIX``), so it must not drift.
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

    ``function_principals`` was a TERMINAL plane: nothing converted an FP row
    into a node. The graph's only two principal ingresses are
    ``authority_roles[].principals`` and ``controllers[].principals``, and an
    address in neither could never enter the graph — so every node-driven spawn
    path was structurally blind to it, and :func:`reconcile_control_graph_types`
    (the one FP→CGN fold) is UPDATE-only and can never re-admit it. On the
    PR-161 corpus that hid 73 addresses / 411 of 1,200 FP rows (34.3%) across 43
    of 93 contracts, including an EtherFiTimelock with 53 rows and a monitored
    Safe with 127; 72 of the 73 have no ``contracts`` row at all, so raising the
    discovery ``analyze_limit`` could not reach the class. Each upstream refusal
    was witness-correct — a ``_ROLE_DISSOLVING_TRACE_STEPS`` trace leaves
    ``authority_roles`` JSON null, and ``authority_roles == []`` means authority
    that is not role-keyed. The defect was reading "role not determined" as
    "principal does not exist".

    **What a minted node asserts, and only this:** the FP row proves this
    address is a resolved principal of a gated function on the anchor contract.
    Everything else stays not-determined — ``analysis_state`` is NULL
    (never stamped; stamping ``analyzed`` would make
    the perimeter spawn on a node no walk ever produced), ``graph_max_depth`` is
    NULL because no walk horizon covered this node, ``contract_name`` is NULL,
    and no intrinsic config (a safe's owners, a timelock's delay) is invented
    here — :func:`reconcile_control_graph_types` folds that in from the FP row's
    own ``details`` on its next run, which is where that witness already lives.

    **This mints NODES; it creates no jobs.** Job eligibility stays entirely
    with ``queue_discovered_contracts``'s gates. Because ``safe`` and ``eoa``
    are not in ``ANALYZABLE_TYPES`` they mint ``node_type='principal'``, which
    that walker rejects as ``not_contract_node`` — node yes, job never — and
    this ledger records the same fact from the mint side as
    ``not_analyzable_type``.

    **Idempotence key:** ``(chain, lower(address), contract_id,
    deployment_scope(deployment_address))``. Never the name, label or origin —
    ``origin`` is a single constant on 1,200/1,200 corpus rows and would key
    nothing. The ``existing_node`` arm it drives dedups against whatever nodes
    the scope currently holds — the walk's own, and this pass's earlier work
    within one transaction. It does NOT carry state across jobs: the rewrite
    below empties the scope first. See ``FP_MATERIALIZE_LIMIT`` for what that
    means for a budget cut.

    **Rewrite survival.** ``replace_control_graph_rows`` deletes wholesale
    within exactly this ``(contract_id, deployment)`` scope, so a minted row
    cannot be made durable against it. The strategy is therefore RE-MINT, made
    sound by ORDERING rather than by hope: the caller runs this strictly after
    the last rewrite that can occur in the job's stage sequence (the policy
    stage's rewrite, which itself runs after the resolution stage's), and the
    pass is idempotent, so a rewrite from any later re-analysis is always
    followed by another mint. A wiped node is never a silently lost one — but a
    node the BUDGET cut is, because the wipe also destroys the record that would
    let a later pass resume. See ``FP_MATERIALIZE_LIMIT``.

    *deployment_address* is the caller's own scope value — the same one it
    passes to ``replace_control_graph_rows`` — so the mint scope, the rewrite
    scope and the FP read scope are one scope by construction.

    Returns ``(ledger, minted_node_payloads)``. The payloads are graph-shaped
    node dicts for the caller to hand to ``queue_discovered_contracts``; they
    are deliberately NOT written into the persisted ``resolution_graph``
    artifact, which is the walk's output and must not acquire nodes no walk
    produced.

    **Commits per mint, and the ledger is written only after the commit.** Not a
    style choice: the ledger is persisted from the caller's ``finally``, on a
    FRESH session when the primary one is poisoned, so a rollback after the loop
    would publish ``minted[]`` and ``budget_used`` naming rows that do not
    exist — a positive fact about a row nothing wrote. ``queue_discovered_contracts``
    commits after each ``create_job`` for exactly this reason, and the claimed
    equivalence with it requires the same boundary here.
    """
    # Lazy: module-level would re-create the resolution↔policy package cycle
    # this file's callers already tiptoe around.
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
    # Mainnet-coalesced: a legacy NULL chain is a mainnet row (inv. 15), and
    # coalescing it here is what keeps a mainnet anchor from being read as a
    # chain we cannot name. An ABSENT contract is not coalesced to anything —
    # there is no chain to claim, so every candidate fails closed below.
    chain = _mainnet_coalesced_chain(contract.chain) if contract is not None else None
    # ``or None`` deliberately: a blank ``Contract.address`` is no anchor at all,
    # and letting it through would mint an edge from the node id ``address:`` —
    # an identity no node has. Absent and blank fail the same way.
    anchor_address = ((contract.address or "").lower() or None) if contract is not None else None

    # Every FP row in this scope, ordered so a budget cut drains in a stable
    # sequence across passes and the ledger is byte-reproducible.
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

    # Depth is the anchor contract's own node depth + 1. Absent that node we
    # have no witnessed depth for it, so the minted node's depth stays NULL
    # (not determined) rather than being guessed at 0 or 1.
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
            # No anchor contract => no chain. A node with a chain we cannot name
            # is exactly the row this pass must never write.
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
            # The FP plane holds two types for one principal at one anchor and
            # never resolved them. Picking one would mint a type nothing proved;
            # 0 of the corpus's 413 (anchor, address) PAIRS — across 83 anchors
            # — reach this, and a first occurrence should surface as a refusal,
            # not as a coin flip.
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
                # NULL, deliberately. A label is display copy, and this plane
                # has none to witness — but ``Job.name`` and the overview's
                # display sites fall back to it, so any constant here would be
                # published as the principal's IDENTITY on every spawned child.
                # ``resolved_type`` already carries the only noun that is proven.
                label=None,
                contract_name=None,
                depth=minted_depth,
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

        # Commit BEFORE the ledger records the mint. The ledger is persisted
        # from the caller's ``finally``, on a fresh session if this one is
        # poisoned, so recording first would let a rollback publish a row that
        # does not exist.
        session.commit()

        # Budget is spent HERE and only here — at the committed INSERT — so
        # every earlier gate provably consumes none of it.
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
                "analysis_state": None,
                "details": details,
                "artifacts": {},
            }
        )
        if node_type == "contract":
            result["queued"].append({"address": addr, "resolved_type": resolved_type})
        else:
            # Minted, and structurally never a job: the walker's
            # ``node_type == 'contract'`` gate rejects it as
            # ``not_contract_node``. Recorded rather than skipped so the two
            # ledgers agree from both sides.
            _out(addr, "not_analyzable_type")

    # Loop exit, and only loop exit: every candidate now sits in exactly one
    # disposition. A raise above leaves the prefix marked incomplete.
    result["walked"] = True
    return result, payloads
