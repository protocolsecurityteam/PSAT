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
* The **policy stage** writes ``function_principals.resolved_type`` with
  ``classify_resolved_address`` for policy principals, so the same
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
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db.models import ControlGraphNode, EffectiveFunction, FunctionPrincipal

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

    # Per address: every (type, details) the protocol's FP rows assign it, so we
    # can pick the best type AND pull intrinsic config from the rows of that type.
    rows_by_addr: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for addr, resolved_type, details in session.execute(
        select(
            func.lower(FunctionPrincipal.address),
            FunctionPrincipal.resolved_type,
            FunctionPrincipal.details,
        )
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .where(
            EffectiveFunction.contract_id.in_(contract_ids),
            FunctionPrincipal.address.is_not(None),
            FunctionPrincipal.resolved_type.in_(_RECONCILABLE_TYPES),
        )
    ).all():
        if not addr or not resolved_type:
            continue
        rows_by_addr.setdefault(addr, []).append((resolved_type, details if isinstance(details, dict) else {}))

    best_by_addr: dict[str, str] = {}
    intrinsic_by_addr: dict[str, dict[str, Any]] = {}
    for addr, rows in rows_by_addr.items():
        best = max((rt for rt, _ in rows), key=lambda rt: _TYPE_PRIORITY.get(rt, 0))
        best_by_addr[addr] = best
        # Intrinsic config comes only from the rows of the winning type — a
        # safe's owners must not bleed onto a timelock-typed write, and vice
        # versa.
        intrinsic: dict[str, Any] = {}
        for rtype, det in rows:
            if rtype == best:
                _merge_intrinsic(intrinsic, det)
        if intrinsic:
            intrinsic_by_addr[addr] = intrinsic

    if not best_by_addr:
        return 0

    # Load the nodes for these addresses that are either still untyped OR
    # already one of the governance types — the latter lets a re-run backfill
    # intrinsic config onto rows a prior type-only reconcile already upgraded.
    cgn_rows = (
        session.execute(
            select(ControlGraphNode).where(
                ControlGraphNode.contract_id.in_(contract_ids),
                func.lower(ControlGraphNode.address).in_(list(best_by_addr.keys())),
                or_(
                    ControlGraphNode.resolved_type.is_(None),
                    ControlGraphNode.resolved_type == "unknown",
                    ControlGraphNode.resolved_type.in_(_RECONCILABLE_TYPES),
                ),
            )
        )
        .scalars()
        .all()
    )

    updated = 0
    for node in cgn_rows:
        key = (node.address or "").lower()
        new_type = best_by_addr.get(key)
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
        node_intrinsic = intrinsic_by_addr.get(key)
        if node_intrinsic and node.resolved_type == new_type:
            current = dict(node.details) if isinstance(node.details, dict) else {}
            missing = {k: v for k, v in node_intrinsic.items() if k not in current}
            if missing:
                node.details = {**current, **missing}
                changed = True

        if changed:
            updated += 1

    return updated
