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
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db.models import Contract, ControlGraphNode, EffectiveFunction, FunctionPrincipal

# FP ``resolved_type`` values folded back into CGN. These spellings are shared
# with the CGN vocabulary verbatim. EOA / contract are intentionally excluded:
# they're not monitored controllers and writing them would surface unrelated
# nodes on the Surface canvas (whose node-keep filter admits any principal type).
_RECONCILABLE_TYPES = ("safe", "timelock", "proxy_admin")

# Tie-break when one address holds more than one FP type across functions:
# prefer the higher-authority kind (a Safe that also looks like a proxy admin
# is a Safe). Matches the Safe > Timelock > proxy admin precedence used by
# ``services.governance.primary_controller``.
_TYPE_PRIORITY = {"safe": 3, "timelock": 2, "proxy_admin": 1}

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
    # Lazy import: the canonical coalesce lives in the aggregation layer and
    # must stay the single source of the NULL≡ethereum convention.
    from services.aggregations.company_overview import _coalesce_chain

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

    ``graph_max_depth`` NULL (legacy rows) suppresses the depth comparison by
    using an unreachable horizon: without the walk's recorded horizon we cannot
    honestly claim ``beyond_depth_horizon``, and the fallthrough for analyzable
    types is ``None`` — which leaves the column NULL, not a guess.
    """
    # Lazy import: module-level would re-create the resolution↔policy package
    # cycle this file's callers already tiptoe around.
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
    rows_by_key: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = {}
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
        rows_by_key.setdefault(key, []).append((resolved_type, details if isinstance(details, dict) else {}))

    best_by_key: dict[tuple[str, str], str] = {}
    intrinsic_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for key, rows in rows_by_key.items():
        best = max((rt for rt, _ in rows), key=lambda rt: _TYPE_PRIORITY.get(rt, 0))
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
