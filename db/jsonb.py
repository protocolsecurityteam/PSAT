"""Three-state predicates for JSONB columns.

A JSONB column has three distinguishable states, and SQL's null test only
separates one of them:

* **unset** — SQL NULL. Nothing was ever written to this column.
* **written-null** — the jsonb scalar ``null``. A writer *did* run and recorded
  "no value". SQLAlchemy's ``JSONB`` type renders a Python ``None`` this way by
  default (``none_as_null=False``), so this is what almost every write of a
  ``None`` payload actually produces.
* **payload** — an object, array, string, number or boolean.

``col is not None`` in an ORM filter compiles to a SQL null test, which is true
for **both** written-null and payload. Every "does this row carry evidence?"
filter written that way is therefore inflated by the written-null rows, and the
inflation is invisible from Python because psycopg2 decodes the jsonb scalar
``null`` to the same ``None`` as SQL NULL.

Measured on the local production-shaped DB (2026-07-27), payload rows vs. rows
passing the SQL null test:

===================================== ========== ==========
column                                null test  payload
===================================== ========== ==========
``artifacts.data``                          5770          0
``effective_functions.conditions``          1773        993
``job_dependencies.cycle_path``              100          5
``contract_materializations.analysis``        76          1
===================================== ========== ==========

Use :func:`jsonb_state` when the three states are different facts to the
consumer (they usually are: "the writer recorded an absence" is evidence,
"the column was never written" is not). Use :func:`jsonb_has_payload` for the
common filter that only wants rows carrying a payload.
"""

from typing import Any

from sqlalchemy import ColumnElement, func

# ``jsonb_typeof`` returns SQL NULL for a SQL-NULL column and the string
# ``'null'`` for the jsonb scalar null. Coalescing to a value that is not a
# jsonb type name keeps the three states separable in one expression without
# dragging three-valued logic into every caller.
JSONB_UNSET = "unset"
JSONB_WRITTEN_NULL = "null"

# The states that mean "this column carries no payload".
JSONB_EMPTY_STATES = (JSONB_UNSET, JSONB_WRITTEN_NULL)


def jsonb_state(col: Any) -> ColumnElement[str]:
    """The column's state as a non-nullable string.

    One of ``'unset'`` (SQL NULL), ``'null'`` (the jsonb scalar null a writer
    stored for a ``None`` payload), or a jsonb type name — ``'object'``,
    ``'array'``, ``'string'``, ``'number'``, ``'boolean'``.
    """
    return func.coalesce(func.jsonb_typeof(col), JSONB_UNSET)


def jsonb_has_payload(col: Any) -> ColumnElement[bool]:
    """True only when the column holds a real jsonb value.

    This is what a SQL null test is almost always reaching for. It excludes
    both empty states, so it is a strictly narrower filter — never wider.
    """
    return jsonb_state(col).notin_(JSONB_EMPTY_STATES)


def jsonb_written_null(col: Any) -> ColumnElement[bool]:
    """True when a writer stored the jsonb scalar null (a recorded absence)."""
    return func.jsonb_typeof(col) == JSONB_WRITTEN_NULL


def jsonb_unset(col: Any) -> ColumnElement[bool]:
    """True when the column was never written (SQL NULL)."""
    return col.is_(None)
