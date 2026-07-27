"""effective_functions.authority_openness — split the authority_public bool

Revision ID: c4b81e2a90fd
Revises: b3d0e51a7c46
Create Date: 2026-07-28

``effective_functions.authority_public`` is ``bool NOT NULL``. Its ``False`` is
three different answers:

* the capability resolved a caller RESTRICTION — principal rows exist, or the
  set was witnessed empty (``resolved_empty``): a fact about the contract;
* the capability could NOT be determined — ``unsupported`` (extraction failed,
  guard seen but not lowered), ``external_check_only`` (a probe interface, no
  enumeration), an irreducible AND/OR residual: a fact about OUR analysis;
* everything else — not determined for want of a resolver run at all.

The middle case is the one the column erases: the algebra can already say
``external_check_only``, and the column gives it the same value a fully
resolved gated function gets. A scorer asking "is this function's authority
known?" cannot answer from this column.

``authority_openness`` carries the three states explicitly:

* ``open``           — a public path was EARNED (⇔ ``authority_public`` true);
* ``restricted``     — a caller restriction was witnessed (principal rows, or a
                       witnessed-empty set);
* ``not_determined`` — no public path and no witnessed caller set.

Additive, nullable, and deliberately **not** backfilled. Deriving it for the
existing 1,773 rows would require re-deciding each row's capability shape, and
a row written before this column existed genuinely does not carry the
distinction — NULL is the honest "the writer that produced this row could not
say" and must never be read as any of the three values. Rows acquire values on
the next policy run.

``authority_public`` is kept: it is exactly ``authority_openness == 'open'``
once populated, and every existing reader (selection.py's candidate query, the
analysis-detail and governance payloads, the frontend guard badges) would break
mid-deploy without it.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "c4b81e2a90fd"
down_revision: Union[str, Sequence[str], None] = "b3d0e51a7c46"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "effective_functions",
        sa.Column(
            "authority_openness",
            sa.String(20),
            nullable=True,
            comment=(
                "Three-state authority verdict: 'open' (a public path was earned), "
                "'restricted' (a caller restriction was witnessed), 'not_determined' "
                "(no public path and no witnessed caller set). NULL = written before "
                "this column existed; never read it as any of the three."
            ),
        ),
    )


def downgrade() -> None:
    op.drop_column("effective_functions", "authority_openness")
