"""role_holder_planes: who a role is PROVEN to include, as a lower bound

Revision ID: e8c2f47a19d3
Revises: a3e7c1d9b840
Create Date: 2026-07-30

The authority plane could name roles and could name principals, but nothing
joined a role to the addresses that hold it. This table does, keyed
``(chain_id, registry_address, role_hash)`` — the hash, never a name.

``holders`` is a LOWER BOUND. Each member was confirmed by a pinned
``hasRole(bytes32,address)`` read; the ``RoleGranted``/``RoleRevoked`` fold only
proposed the candidates. That split is what makes the column sound under a fold
that is incomplete — and it is known to be incomplete, because nothing bounds
the covered range from below (``first_indexed_block`` is witnessed on 0 of 80
cursors) and nothing proves the pages came back whole.

One table, not a parent plus a holders child. A child table would hand a reader
addresses with no exhaustiveness qualifier attached, and it would make the
empty-set constraint below impossible to express.

Eleven CHECKs carry the invariants that code must not be able to route around.
Two are the unit's hard bans:

* ``no_empty_set`` — an empty ``holders`` array is unrepresentable. Absence of a
  proven holder is NULL (not_determined), never ``[]``, because ``[]`` reads as
  "nobody holds this role" and no evidence here supports that.
* ``never_exhaustive`` — ``holder_set_exhaustive`` is pinned to
  ``not_determined``. 0 of the 4 role registries in the corpus implement
  AccessControlEnumerable's getter (``getRoleMemberCount`` and ``getRoleMember``
  both revert; ``supportsInterface(0x5a05180f)`` is false), so under B14 an
  exhaustiveness arm has population 0 and may not be built. A DEFERRAL WITH
  CAUSE — a future unit that finds an enumerable registry, or builds the inverse
  index absence coverage needs, should revisit this constraint deliberately
  rather than assume it was derived.

Every discriminator is NOT NULL, and that is load-bearing rather than tidiness:
a CHECK evaluating to NULL PASSES in Postgres, so a nullable basis column would
let a row satisfy ``never_exhaustive`` and each biconditional by omission.

The residual counters are NULL exactly when ``holders`` is NULL. Populating them
on a withheld row would reconstruct the banned empty set — "N candidates probed,
every read completed, none confirmed" is ``[]`` written in three columns — and
would make an all-false registry distinguishable from an all-reverting one,
which is a diagnosis this plane refuses to publish.

Wave-2 migration chain position 5 of 5 (LAST).

REBASE MARKER: authored with ``down_revision = a3e7c1d9b840`` (U10A) because the
restaking-position revision U10B (``d5b9e0c31f72``) is not present in this
worktree. AT ASSEMBLY, REPOINT ``down_revision`` TO ``d5b9e0c31f72``. Intended
order: c1a4b7e02f18 (U4) -> c4f8a1d92b07 (U8) -> a3e7c1d9b840 (U10A) ->
d5b9e0c31f72 (U10B) -> e8c2f47a19d3 (this).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Inlined rather than imported from ``db.models``: a migration is applied
# history and must keep describing the schema it created, even after the model's
# copy of this predicate changes. "No holder set was published" is BOTH SQL NULL
# and the jsonb scalar ``null`` — a bare ``holders IS NULL`` misses the second,
# which is what a write of a Python None stores unless the column forbids it.
HOLDERS_WITHHELD_SQL = "(holders IS NULL OR jsonb_typeof(holders) = 'null')"

revision: str = "e8c2f47a19d3"
down_revision: Union[str, Sequence[str], None] = "a3e7c1d9b840"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "role_holder_planes",
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("registry_address", sa.String(length=42), nullable=False),
        sa.Column("role_hash", sa.String(length=66), nullable=False),
        # ``none_as_null`` — JSONB otherwise stores Python None as the JSON
        # literal 'null', which is not SQL NULL, and every check below that
        # keys off ``holders IS NULL`` would silently stop discriminating.
        sa.Column("holders", postgresql.JSONB(astext_type=sa.Text(), none_as_null=True), nullable=True),
        sa.Column("holders_basis", sa.String(length=48), nullable=False),
        sa.Column(
            "holder_set_exhaustive",
            sa.String(length=16),
            nullable=False,
            server_default="not_determined",
        ),
        sa.Column("as_of_block", sa.BigInteger(), nullable=True),
        sa.Column("as_of_block_hash", sa.LargeBinary(length=32), nullable=True),
        sa.Column("cursor_first_indexed_block", sa.BigInteger(), nullable=True),
        sa.Column("cursor_first_indexed_block_basis", sa.String(length=32), nullable=False),
        sa.Column("cursor_last_indexed_block", sa.BigInteger(), nullable=True),
        sa.Column("cursor_enrollment_bases", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cursor_page_completeness", sa.String(length=16), nullable=False),
        sa.Column("coverage", sa.String(length=16), nullable=False),
        sa.Column("role_name", sa.String(length=255), nullable=True),
        sa.Column("role_name_basis", sa.String(length=48), nullable=False),
        sa.Column("candidate_count", sa.Integer(), nullable=True),
        sa.Column("unconfirmed_candidate_count", sa.Integer(), nullable=True),
        sa.Column("fold_chain_disagreements", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("chain_id", "registry_address", "role_hash"),
        sa.CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} OR jsonb_typeof(holders) = 'array'",
            name="ck_role_holder_planes_holders_is_array_or_absent",
        ),
        sa.CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} OR jsonb_array_length(holders) > 0",
            name="ck_role_holder_planes_no_empty_set",
        ),
        sa.CheckConstraint(
            "holder_set_exhaustive = 'not_determined'",
            name="ck_role_holder_planes_never_exhaustive",
        ),
        sa.CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (holders_basis = 'not_determined')",
            name="ck_role_holder_planes_basis_matches_holders",
        ),
        sa.CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (as_of_block IS NULL)",
            name="ck_role_holder_planes_block_matches_holders",
        ),
        sa.CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (candidate_count IS NULL)",
            name="ck_role_holder_planes_candidates_match_holders",
        ),
        sa.CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (unconfirmed_candidate_count IS NULL)",
            name="ck_role_holder_planes_unconfirmed_match_holders",
        ),
        sa.CheckConstraint(
            f"NOT {HOLDERS_WITHHELD_SQL} OR coverage = 'partial'",
            name="ck_role_holder_planes_null_holders_are_partial",
        ),
        sa.CheckConstraint(
            "(role_name IS NULL) = (role_name_basis = 'not_determined')",
            name="ck_role_holder_planes_name_matches_basis",
        ),
        sa.CheckConstraint(
            "holders_basis IN ('pinned_has_role_confirmed', 'not_determined')",
            name="ck_role_holder_planes_holders_basis_domain",
        ),
        sa.CheckConstraint(
            "coverage IN ('lower_bound', 'partial')",
            name="ck_role_holder_planes_coverage_domain",
        ),
        sa.CheckConstraint(
            "role_name_basis IN ('keccak_preimage', 'accesscontrol_default_admin_literal', 'not_determined')",
            name="ck_role_holder_planes_name_basis_domain",
        ),
    )


def downgrade() -> None:
    op.drop_table("role_holder_planes")
