"""Document the two authority columns on effective_functions

``authority_openness`` carries a column comment; ``authority_roles`` and
``authority_public`` -- the two columns whose states a consumer actually gets
wrong -- carry none. The most fold-prone column in the table was the one left
undocumented, and it cost a published contradiction: ``/api/company/{name}/
functions`` served ``[]`` on 324 ether.fi rows whose column holds the jsonb
``null``, while ``/api/analyses/{job}`` served ``null`` for the same rows.

Two facts a reader cannot recover from the schema alone, both now written down:

* ``authority_roles``' ``[]`` is the NEGATION of its ``null`` ("proven not
  role-gated" vs "role-gated, role not determined"), so the usual
  ``authority_roles or []`` erases the middle state rather than widening it.
* the ``null`` is the JSONB SCALAR ``null``, not SQL NULL. ``mapped_column(JSONB)``
  without ``none_as_null`` renders a Python ``None`` as ``'null'::jsonb``, so
  ``WHERE authority_roles IS NULL`` matches 0 rows on a table with 379
  undetermined ones -- an empty result that reads as "nothing is undetermined".
  ``jsonb_typeof(authority_roles) = 'null'`` is the test.

``authority_public`` gets the pairing note: its ``false`` merges a witnessed
caller restriction with an undetermined authority, which is why
``authority_openness`` exists beside it.

Comments only -- no column, type, nullability or data changes. The matching
``comment=`` kwargs land on ``db/models.py`` in the same commit so
``alembic check`` (CI's schema-drift gate, which diffs the built database
against ``Base.metadata`` and reports comment mismatches as ``modify_comment``)
stays clean in both directions.

Revision ID: d3f1a86c204b
Revises: a7e4c2b81f05
Create Date: 2026-07-28

"""

from collections.abc import Sequence

from alembic import op

revision: str = "d3f1a86c204b"
down_revision: str | Sequence[str] | None = "a7e4c2b81f05"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_COMMENTS: tuple[tuple[str, str], ...] = (
    (
        "authority_public",
        "TWO states over a three-state fact: true = a public path was earned; "
        "false merges 'a caller restriction was witnessed' with 'the authority "
        "could not be determined at all'. Read authority_openness for the split "
        "-- this column alone cannot tell a gated function from an unread one.",
    ),
    (
        "authority_roles",
        "Three states, and [] is the NEGATION of null, not a coarsening of it: a "
        "non-empty list is a witnessed (role, principals) requirement; null is "
        "role-gated with the role NOT determined; [] is proven not role-gated. "
        "The null is the JSONB SCALAR null, not SQL NULL -- 'WHERE authority_roles "
        "IS NULL' matches 0 of the 379 undetermined rows; test "
        "jsonb_typeof(authority_roles) = 'null' (see db/jsonb.py).",
    ),
)


def upgrade() -> None:
    for column, comment in _COMMENTS:
        literal = "'" + comment.replace("'", "''") + "'"
        op.execute(f"COMMENT ON COLUMN effective_functions.{column} IS {literal}")


def downgrade() -> None:
    for column, _comment in _COMMENTS:
        op.execute(f"COMMENT ON COLUMN effective_functions.{column} IS NULL")
