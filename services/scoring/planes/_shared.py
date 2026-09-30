"""Cross-plane vocabulary: micro-helpers and the edge-scope grammar."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from services.scoring.schema import coalesce_chain
from utils.balance_status import TYPED_PER_ID_BASES

NATIVE_ASSET = "native"

ZERO_ADDRESS = "0x" + "0" * 40

# Authority-carrying relations. ``safe_owner`` is excluded (one owner doesn't meet k-of-n), as is
# ``controller_value_unattributed`` (principals whose authority relation was never established).
CONTROL_RELATIONS = ("controller_value", "role_principal", "mapping_member")


def typed_receipt_is_resolved(entry: Any) -> bool:
    """Whether one ERC-721/1155 receipt's current holding is a resolved zero: the quantity was readable and read
    zero.

    An unreadable quantity (ERC-1155 has no ``balanceOf(address)``) is not determined; a non-zero one is a held item. A
    per-token-id reading also needs the record to say the id inventory is whole.
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


# Presentation rounding for float noise only; it must not change what a figure proves.
_PRESENTATION_DECIMALS = 6


def _round_presented(value: float) -> float:
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


# What an edge label may say: role numbers (``roles 12``), a single state-variable identifier, or neither (``role
# principal`` restatements, dotted paths, ``safe owner``, no label), which is ``not_determined``. No label names a
# selector; that join lives in ``function_principals``.
SCOPE_ROLES = "roles"
SCOPE_STATE_VAR = "state_var"
SCOPE_NOT_DETERMINED = "not_determined"

# ``contracts.admin`` is a column, not a graph row, so it is named by origin.
EDGE_WITNESS_CONTROL_GRAPH = "control_graph_edges"
EDGE_WITNESS_ADMIN_COLUMN = "contracts.admin"
# Same kind of column witness as admin, with its own name so consumers can tell which produced a hop.
EDGE_WITNESS_BEACON_COLUMN = "contracts.beacon"

_ROLES_LABEL = re.compile(r"^roles\s+(\d+(?:\s*,\s*\d+)*)$")
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


@dataclass(frozen=True)
class EdgeScope:
    """What an edge label says its authority is scoped to.

    A label naming neither roles nor a state variable is ``not_determined``, never an empty scope (which would read as
    licensing nothing).
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

    The relation decides which readings are available: on ``role_principal`` only a role set counts (reading ``roles``
    as a variable fabricated one). No relation-restatement branch: it decided nothing and could have silently suppressed
    real ``authority`` labels.
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
    """The burn sentinel, one helper for every refusal so plane and fold can't drift."""
    return key.endswith("::" + ZERO_ADDRESS)
