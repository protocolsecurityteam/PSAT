"""Cross-plane vocabulary: micro-helpers and the edge-scope grammar."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from services.scoring.schema import coalesce_chain
from utils.balance_status import TYPED_PER_ID_BASES

NATIVE_ASSET = "native"

ZERO_ADDRESS = "0x" + "0" * 40

# Control relations that carry authority. ``safe_owner`` is excluded (one owner
# does not satisfy k-of-n) and ``controller_value_unattributed`` is excluded
# (real principals whose authority RELATION was never established — a confidence
# item, not an edge).
CONTROL_RELATIONS = ("controller_value", "role_principal", "mapping_member")


def typed_receipt_is_resolved(entry: Any) -> bool:
    """Whether one ERC-721/1155 receipt's CURRENT holding is a resolved zero.

    The receipt itself is immutable evidence that a typed token once ARRIVED;
    what decides an empty sheet is whether it is still held. Exactly one shape
    resolves it: the quantity was readable AND it read zero — the token arrived
    and provably left. Everything else refuses, and the two failing shapes are
    different facts: an unreadable quantity (ERC-1155 has no
    ``balanceOf(address)`` at all, so the call reverts) is not determined, and a
    readable NON-zero one is a held item this plane cannot price. Neither may
    stand behind "holds nothing".

    A quantity read PER TOKEN ID carries one more condition, derived from the
    record rather than trusted: summing an id inventory is an all-quantifier over
    it, so it says nothing at all unless the record also says the inventory is
    whole. A per-id zero over a PREFIX of the ids is the shape that would publish
    "holds nothing" over ids nobody read, so it is refused here as well as at the
    producer — the published claim derives from the carrier's own fields.
    """
    if not isinstance(entry, dict):
        return False
    if entry.get("quantity_readable") is not True:
        return False
    if entry.get("quantity_basis") in TYPED_PER_ID_BASES and entry.get("ids_complete") is not True:
        return False
    try:
        return float(str(entry.get("quantity"))) == 0.0
    except (TypeError, ValueError):
        return False


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# The presentation rounding this plane applies to dollar figures. Six decimals
# tames float-sum noise on figures a consumer reads, and that is all it is for —
# so it is not allowed to change what the figure PROVES. A determined non-zero
# holding rounded to 0.0 stops being a number and starts being an absence, which
# is a different claim about the entity than the one that was measured; below the
# rounding's own resolution the unrounded figure is therefore what stands.
_PRESENTATION_DECIMALS = 6


def _round_presented(value: float) -> float:
    """Round for presentation, never onto zero."""
    rounded = round(value, _PRESENTATION_DECIMALS)
    return rounded if rounded != 0.0 or value == 0.0 else value


def _chain_name(chain_id: int | None) -> str | None:
    if chain_id is None:
        return None
    from utils.chains import UnknownChainError, chain_by_id

    try:
        return coalesce_chain(chain_by_id(int(chain_id)).name)
    except (UnknownChainError, ValueError, TypeError):
        return None


# What an edge's label is allowed to say. A ``role_principal`` label carries the
# role numbers the principal holds ("roles 12", "roles 14,16") or, on 55 of 285,
# the bare relation restatement "role principal" and no role at all. Most other
# labels name a state variable ("owner", "hook", "_roles"), but not all of them
# do: ``controller_value_unattributed`` carries dotted access paths
# ("accountantState.payoutAddress", "fee.treasury"), ``safe_owner`` carries the
# constant "safe owner", and ``capability_principal`` carries no label. Anything
# that is not a role set and not a single identifier is ``not_determined`` — the
# parser earns the state-variable reading rather than assuming it. No label in
# any corpus carries a selector, so an edge never names the function it licenses
# — that join lives in function_principals, not here.
SCOPE_ROLES = "roles"
SCOPE_STATE_VAR = "state_var"
SCOPE_NOT_DETERMINED = "not_determined"

# What produced an edge. ``contracts.admin`` is a column, not a graph row: it
# carries no relation, no label and no id, so it is named by its origin rather
# than given an invented relation.
EDGE_WITNESS_CONTROL_GRAPH = "control_graph_edges"
EDGE_WITNESS_ADMIN_COLUMN = "contracts.admin"
# ``contracts.beacon`` is the same kind of witness as ``contracts.admin`` — a
# column populated by the same slot read, present in no edge table — and it
# carries its own name rather than borrowing admin's, because a consumer that
# wants to know which witness produced a hop must be able to tell them apart.
# Consumers branch on THIS value; ``relation is None`` is a property both share
# and is not a witness.
EDGE_WITNESS_BEACON_COLUMN = "contracts.beacon"

_ROLES_LABEL = re.compile(r"^roles\s+(\d+(?:\s*,\s*\d+)*)$")
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


@dataclass(frozen=True)
class EdgeScope:
    """What an edge's label says its authority is scoped TO.

    Three-valued by construction. A label that names neither a role set nor a
    state variable — the 55 ``role principal`` edges that restate their own
    relation and name no role — is ``not_determined``, never an empty scope: an
    empty scope reads as "licenses nothing", and these edges license something
    nobody wrote down.
    """

    kind: str
    roles: tuple[int, ...] = ()
    state_var: str | None = None
    label: str | None = None

    @property
    def is_determined(self) -> bool:
        return self.kind != SCOPE_NOT_DETERMINED


ROLE_SCOPED_RELATIONS = ("role_principal",)


def parse_edge_scope(label: str | None, relation: str | None = None) -> EdgeScope:
    """The scope an edge label proves, or ``not_determined``.

    The relation decides which readings are AVAILABLE, not which one wins. On a
    ``role_principal`` edge the only positive answer is a role set: the relation
    is the assertion "this principal holds a role", so a label that names no role
    has not named a state variable either, and reading a bare identifier there as
    one fabricated a variable (``state_var="roles"`` on the literal label
    ``roles``) that no source declares and no consumer could check.

    There is deliberately NO relation-restatement branch. One existed to stop a
    single-token label equal to its own relation ("controller_value" on a
    ``controller_value`` edge) from being read as a variable of that name. It
    decided nothing: DB-wide the only labels equal to their relation are the
    multi-word "role principal" and "safe owner", which fail the identifier check
    on their own, and no single-token case exists. What it did carry was an
    inversion hazard — a relation named after a real getter (``authority``) would
    have suppressed the 100 genuine ``authority`` state-var labels the same day
    it was introduced, silently, with no count anywhere. A rule that decides
    nothing and can invert is deleted rather than documented; the role case it
    was covering is now decided by the relation gate above, structurally.
    """
    text = str(label or "").strip()
    if not text:
        return EdgeScope(SCOPE_NOT_DETERMINED)
    match = _ROLES_LABEL.match(text)
    if match:
        return EdgeScope(SCOPE_ROLES, roles=tuple(sorted({int(n) for n in match.group(1).split(",")})), label=text)
    if relation in ROLE_SCOPED_RELATIONS:
        return EdgeScope(SCOPE_NOT_DETERMINED, label=text)
    if _IDENTIFIER.match(text):
        return EdgeScope(SCOPE_STATE_VAR, state_var=text, label=text)
    return EdgeScope(SCOPE_NOT_DETERMINED, label=text)


def is_zero_key(key: str) -> bool:
    """The burn sentinel, at either end of an edge or as a reach key.

    One helper for every refusal of it — the closure loader here, the reach keys
    and the walk in ``fold`` — so the rule cannot drift between the plane that
    builds the graph and the fold that walks it.
    """
    return key.endswith("::" + ZERO_ADDRESS)
