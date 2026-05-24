"""Reconcile ``control_graph_nodes.resolved_type`` from ``FunctionPrincipal``.

The pipeline types a governance principal (Safe / Timelock / proxy admin)
in two places, at two stages:

* The **resolution stage** writes ``control_graph_nodes.resolved_type`` from
  its graph walk. The walk only runs the on-chain classifier on addresses it
  reaches structurally, so a principal that controls a contract *only* through
  per-function authority — e.g. a multisig that calls ``EtherFiTimelock.cancel``
  but appears nowhere in the storage-slot graph — is left ``unknown``.
* The **policy stage** writes ``function_principals.resolved_type`` with a
  *live* ``classify_resolved_address`` fallback for cache misses, so the same
  address comes out ``safe`` / ``timelock`` / ``proxy_admin``.

The classifier is deterministic and address-only, so the policy stage's answer
is simply more complete — not a different opinion. But it never propagates back
to ``control_graph_nodes``, so every consumer that reads CGN typing (monitoring
enrollment's candidate walk, the chat context layer, the Surface canvas) can see
a stale ``unknown`` for an address the system has already classified.

This pass closes that gap protocol-wide: it folds the authoritative FP typing
back into CGN. It must be protocol-wide rather than per-contract because a
principal's ``unknown`` CGN nodes live on the contracts it *governs*, while its
FP authority sits on a different contract (the timelock it calls) — a
per-contract write-back would miss most of them.

Only ``unknown`` / NULL rows are upgraded, and only to the governance principal
types (Safe / Timelock / proxy admin) that downstream views treat as
principals; a concrete graph-walk type is never overwritten, and EOAs/plain
contracts are left alone so this can't reshape unrelated Surface nodes. The
operation is idempotent — once converged a re-run upgrades nothing.
"""

from __future__ import annotations

from collections.abc import Sequence

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


def reconcile_control_graph_types(session: Session, contract_ids: Sequence[int]) -> int:
    """Upgrade ``unknown`` CGN node types from FunctionPrincipal typing.

    *contract_ids* — the protocol's analyzed contract ids (the same set the
    caller enrolls). Both the FP read and the CGN write are scoped to it.

    Returns the number of ``control_graph_nodes`` rows updated. Idempotent.
    """
    if not contract_ids:
        return 0

    # Best concrete governance type per address, across all of the protocol's
    # function principals.
    best_by_addr: dict[str, str] = {}
    for addr, resolved_type in session.execute(
        select(func.lower(FunctionPrincipal.address), FunctionPrincipal.resolved_type)
        .join(EffectiveFunction, EffectiveFunction.id == FunctionPrincipal.function_id)
        .where(
            EffectiveFunction.contract_id.in_(contract_ids),
            FunctionPrincipal.address.is_not(None),
            FunctionPrincipal.resolved_type.in_(_RECONCILABLE_TYPES),
        )
        .distinct()
    ).all():
        if not addr or not resolved_type:
            continue
        current = best_by_addr.get(addr)
        if current is None or _TYPE_PRIORITY.get(resolved_type, 0) > _TYPE_PRIORITY.get(current, 0):
            best_by_addr[addr] = resolved_type

    if not best_by_addr:
        return 0

    updated = 0
    cgn_rows = (
        session.execute(
            select(ControlGraphNode).where(
                ControlGraphNode.contract_id.in_(contract_ids),
                or_(
                    ControlGraphNode.resolved_type.is_(None),
                    ControlGraphNode.resolved_type == "unknown",
                ),
            )
        )
        .scalars()
        .all()
    )
    for node in cgn_rows:
        new_type = best_by_addr.get((node.address or "").lower())
        if new_type and new_type != node.resolved_type:
            node.resolved_type = new_type
            updated += 1

    return updated
