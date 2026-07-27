"""control_graph_nodes.analysis_state + graph_max_depth — split the analyzed bool

Revision ID: b3d0e51a7c46
Revises: a1f7c30b62d9
Create Date: 2026-07-27

``control_graph_nodes.analyzed`` is ``bool NOT NULL``. Its ``False`` is four
different populations:

* a principal (EOA / Safe / zero address) that was never a candidate for
  analysis — its absence says nothing adverse;
* a contract whose materialization was attempted and FAILED — a fact about the
  contract;
* an analyzable contract the BFS never reached because its depth exceeded the
  walk's ``max_depth`` — a fact about OUR walk, not the address;
* everything else — not determined.

The third was not even derivable from the row: ``max_depth`` lived only in the
``resolved_control_graph`` artifact and was dropped on projection, so ``depth``
alone could not say whether a node was cut off by the horizon.

Both columns are additive, nullable, and deliberately **not** backfilled. The
existing 2,506 rows were written by a walk whose horizon this migration cannot
recover, so NULL is the honest "not determined" and must not be read as any of
the four values. Rows acquire values on the next resolution run.

``analyzed`` is kept: it is exactly ``analysis_state == 'analyzed'`` once
populated, and removing it would break readers mid-deploy.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b3d0e51a7c46"
down_revision: Union[str, Sequence[str], None] = "a1f7c30b62d9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("control_graph_nodes", sa.Column("analysis_state", sa.String(length=32), nullable=True))
    op.add_column("control_graph_nodes", sa.Column("graph_max_depth", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("control_graph_nodes", "graph_max_depth")
    op.drop_column("control_graph_nodes", "analysis_state")
