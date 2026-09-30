"""Three-state predicates for JSONB columns.

* unset: SQL NULL, never written.
* written-null: the jsonb scalar ``null``; a writer ran and recorded no value. SQLAlchemy's ``JSONB`` writes a
  Python ``None`` this way by default.
* payload: an object, array, string, number or boolean.

``col is not None`` compiles to a SQL null test, which is true for both written-null and payload, and psycopg2
decodes both nulls to ``None``, so the inflation is invisible from Python. Measured on the local DB (2026-07-27):

===================================== ========== ==========
column                                null test  payload
===================================== ========== ==========
``artifacts.data``                          5770          0
``effective_functions.conditions``          1773        993
``job_dependencies.cycle_path``              100          5
``contract_materializations.analysis``        76          1
===================================== ========== ==========

Use :func:`jsonb_state` when the states mean different things, :func:`jsonb_has_payload` to keep only payload rows.
"""

from typing import Any

from sqlalchemy import ColumnElement, func

# ``jsonb_typeof`` is SQL NULL for SQL NULL and ``'null'`` for the jsonb scalar; coalescing to a non-type name keeps all
# three separable.
JSONB_UNSET = "unset"
JSONB_WRITTEN_NULL = "null"

JSONB_EMPTY_STATES = (JSONB_UNSET, JSONB_WRITTEN_NULL)


def jsonb_state(col: Any) -> ColumnElement[str]:
    """The column's state as a non-null string: ``'unset'``, ``'null'``, or a jsonb type name."""
    return func.coalesce(func.jsonb_typeof(col), JSONB_UNSET)


def jsonb_has_payload(col: Any) -> ColumnElement[bool]:
    """True only for a real jsonb value; strictly narrower than a SQL null test."""
    return jsonb_state(col).notin_(JSONB_EMPTY_STATES)
