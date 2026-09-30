"""Role-holder plane and its refresh log."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Integer,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .balances import (
    DISAGREEMENTS_WITHHELD_SQL,
    HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED,
    HOLDERS_WITHHELD_SQL,
)
from .base import Base


class RoleHolderPlane(Base):
    """Who a ``(chain_id, registry_address, role_hash)`` is proven to include.

    ``holders`` is a lower bound: each member was confirmed by a pinned ``hasRole`` at ``as_of_block``; the event fold
    only proposes. Completeness is published separately as ``holder_set_exhaustive``. The gate lives in the same row as
    the payload so readers can't see addresses without it.

    A proven lower bound publishes holders. "All reads confirmed nobody", "all reads failed" and "cold surface" all
    publish ``holders = NULL`` and are deliberately indistinguishable, since telling them apart would reconstruct the
    banned empty set; the counters are NULL too.
    """

    __tablename__ = "role_holder_planes"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    registry_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    # The only identity; names are decoration. Rows come only from the OZ ``RoleGranted``/``RoleRevoked`` pair; Solady
    # ``RoleSet`` uses a different identity space and mints nothing here.
    role_hash: Mapped[str] = mapped_column(String(66), primary_key=True)
    # NULL = not determined, never "nobody"; an empty array can't be stored. ``none_as_null`` keeps ``None`` from
    # becoming jsonb ``null``, which would defeat the checks.
    holders: Mapped[list[str] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    holders_basis: Mapped[str] = mapped_column(String(48), nullable=False)
    # Pinned to ``not_determined`` by CHECK: no corpus registry implements the enumerable getter. A deferral with cause;
    # ``getRoleMemberCount``/``getRoleMember`` support or a proven inverse index could license a value.
    holder_set_exhaustive: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED
    )
    # The pinned height of every read, and its hash for replay across reorgs.
    as_of_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    as_of_block_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    # Cursor bounds copied for legibility. The lower bound is citable only with basis ``creation_block_minus_one``; an
    # ``explicit_seed`` is stored as NULL + not_determined.
    cursor_first_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursor_first_indexed_block_basis: Mapped[str] = mapped_column(String(32), nullable=False)
    cursor_last_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursor_enrollment_bases: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cursor_page_completeness: Mapped[str] = mapped_column(String(16), nullable=False)
    coverage: Mapped[str] = mapped_column(String(16), nullable=False)
    # NULL = no preimage proven, not "unnamed".
    role_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_name_basis: Mapped[str] = mapped_column(String(48), nullable=False)
    # Proposed candidates and unreadable ones; both NULL exactly when ``holders`` is.
    candidate_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unconfirmed_candidate_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Where the fold and chain disagreed, recorded but never diagnosed (a missed log and a later state change look the
    # same). NULL with ``holders``, since ``[]`` would be an unearned negative on a withheld row. On a published row
    # ``[]`` is earned over the reads that completed.
    fold_chain_disagreements: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        # The hard bans. Discriminators are NOT NULL because a NULL CHECK passes. ``holders`` is withheld or an array,
        # never another JSON type.
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} OR jsonb_typeof(holders) = 'array'",
            name="ck_role_holder_planes_holders_is_array_or_absent",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} OR jsonb_array_length(holders) > 0",
            name="ck_role_holder_planes_no_empty_set",
        ),
        CheckConstraint(
            "holder_set_exhaustive = 'not_determined'",
            name="ck_role_holder_planes_never_exhaustive",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (holders_basis = 'not_determined')",
            name="ck_role_holder_planes_basis_matches_holders",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (as_of_block IS NULL)",
            name="ck_role_holder_planes_block_matches_holders",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (candidate_count IS NULL)",
            name="ck_role_holder_planes_candidates_match_holders",
        ),
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = (unconfirmed_candidate_count IS NULL)",
            name="ck_role_holder_planes_unconfirmed_match_holders",
        ),
        CheckConstraint(
            f"NOT {HOLDERS_WITHHELD_SQL} OR coverage = 'partial'",
            name="ck_role_holder_planes_null_holders_are_partial",
        ),
        # The disagreement log is withheld and published together with the holder set.
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = {DISAGREEMENTS_WITHHELD_SQL}",
            name="ck_role_holder_planes_disagreements_match_holders",
        ),
        CheckConstraint(
            f"{DISAGREEMENTS_WITHHELD_SQL} OR jsonb_typeof(fold_chain_disagreements) = 'array'",
            name="ck_role_holder_planes_disagreements_are_array_or_absent",
        ),
        # A witnessed lower bound and its basis are one fact.
        CheckConstraint(
            "(cursor_first_indexed_block IS NULL) = (cursor_first_indexed_block_basis = 'not_determined')",
            name="ck_role_holder_planes_lower_bound_matches_basis",
        ),
        # ``explicit_seed`` isn't storable: the writer normalizes it to NULL + not_determined.
        CheckConstraint(
            "cursor_first_indexed_block_basis IN ('creation_block_minus_one', 'not_determined')",
            name="ck_role_holder_planes_lower_bound_basis_domain",
        ),
        CheckConstraint(
            "cursor_page_completeness IN ('complete', 'incomplete', 'not_determined')",
            name="ck_role_holder_planes_page_completeness_domain",
        ),
        CheckConstraint(
            "(role_name IS NULL) = (role_name_basis = 'not_determined')",
            name="ck_role_holder_planes_name_matches_basis",
        ),
        CheckConstraint(
            "holders_basis IN ('pinned_has_role_confirmed', 'not_determined')",
            name="ck_role_holder_planes_holders_basis_domain",
        ),
        CheckConstraint(
            "coverage IN ('lower_bound', 'partial')",
            name="ck_role_holder_planes_coverage_domain",
        ),
        CheckConstraint(
            "role_name_basis IN ('keccak_preimage', 'accesscontrol_default_admin_literal', 'not_determined')",
            name="ck_role_holder_planes_name_basis_domain",
        ),
    )


class RoleHolderPlaneRefresh(Base):
    """When ``(chain_id, registry_address)`` was last folded, and the outcome.

    The per-role plane can't tell a registry that proposed nothing from one never processed. This table's three states:
    no row (never refreshed, due); ``no_rows`` (ran, proposed nothing); ``rows_written`` with a count.

    Rows are only written where the AccessControl cursor pair exists, so a closed gate stays due. ``trigger_log_block``
    (highest indexed log at the pass), ``cursors_warm`` and ``refreshed_at`` let a later log, a warming surface or age
    re-select it. Why a floor was withheld is deliberately not recorded (see the plane).
    """

    __tablename__ = "role_holder_plane_refreshes"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    registry_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # NULL = no log indexed at the pass; an observation of the index, not of the chain.
    trigger_log_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursors_warm: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rows_written: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "outcome IN ('no_rows', 'rows_written')",
            name="ck_role_holder_plane_refreshes_outcome_domain",
        ),
        # Count and token are one fact.
        CheckConstraint(
            "(outcome = 'rows_written') = (rows_written > 0)",
            name="ck_role_holder_plane_refreshes_outcome_matches_count",
        ),
        CheckConstraint(
            "rows_written >= 0",
            name="ck_role_holder_plane_refreshes_count_non_negative",
        ),
    )
