"""add job_dependencies table

Revision ID: 8c1f4b9e7a23
Revises: a3b4c5d6e7f8
Create Date: 2026-05-04 21:00:00.000000

Durable cross-job dependency edges so a depender stage can be gated on
the provider's predicate-pipeline progress. When A's predicate trees
reference a state-variable-resolved external contract B (e.g. EtherFi's
``upgradeTo`` calls into ``roleRegistry.onlyProtocolUpgrader``), the
resolution worker emits an edge ``(A, B, required_stage=policy)``. The
``claim_job`` queue gate skips A while any row with ``status='pending'``
exists for ``A.id``. ``BaseWorker._satisfy_dependencies`` flips rows
to ``satisfied`` when B advances past ``required_stage`` and to
``degraded`` when B terminally fails (dependents short-circuit to
``external_check_only`` rather than block forever).

Schema notes:
  - ``UNIQUE (depender_job_id, provider_chain, provider_address,
    required_stage)`` is the edge identity. Re-running the resolution
    stage uses ``ON CONFLICT DO NOTHING``.
  - ``ix_job_dep_provider`` powers the satisfy-on-advance scan
    (one provider job advancing wakes every dependent for that
    (chain, address) at-or-below the new stage).
  - ``ix_job_dep_pending`` is partial on ``status='pending'`` so the
    claim gate's ``NOT EXISTS`` check stays sub-ms even at fleet scale.
  - ``cycle_path`` carries the dep-chain JSON when the new edge would
    close a cycle in the graph; status flips to ``cycle_degraded`` and
    the resolver short-circuits to ``external_check_only``.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "8c1f4b9e7a23"
down_revision: Union[str, Sequence[str], None] = "a3b4c5d6e7f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Mirror of ``JobStage`` from db/models/jobs.py — kept inline so the migration
# is self-contained and survives a future enum addition. ``server_default``
# / runtime values for required_stage are validated by the application.
_JOB_STAGE_ENUM = postgresql.ENUM(
    "discovery",
    "dapp_crawl",
    "defillama_scan",
    "selection",
    "static",
    "resolution",
    "policy",
    "coverage",
    "done",
    name="jobstage",
    create_type=False,  # already created by an earlier migration
)


def upgrade() -> None:
    op.create_table(
        "job_dependencies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "depender_job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider_chain", sa.String(length=50), nullable=True),
        sa.Column("provider_address", sa.String(length=42), nullable=False),
        sa.Column("required_stage", _JOB_STAGE_ENUM, nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("cycle_path", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column("satisfied_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "depender_job_id",
            "provider_chain",
            "provider_address",
            "required_stage",
            name="uq_job_dep_edge",
        ),
    )
    op.create_index(
        "ix_job_dep_provider",
        "job_dependencies",
        ["provider_chain", "provider_address", "required_stage", "status"],
        unique=False,
    )
    op.create_index(
        "ix_job_dep_pending",
        "job_dependencies",
        ["depender_job_id"],
        unique=False,
        postgresql_where=sa.text("status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_index("ix_job_dep_pending", table_name="job_dependencies")
    op.drop_index("ix_job_dep_provider", table_name="job_dependencies")
    op.drop_table("job_dependencies")
