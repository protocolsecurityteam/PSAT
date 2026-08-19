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
    """Who a ``(chain_id, registry_address, role_hash)`` is PROVEN to include.

    ``holders`` is a **lower bound**, never a membership set. Every member was
    independently confirmed by a pinned ``hasRole(bytes32,address)`` read at
    ``as_of_block`` — the event fold only proposed the candidates, and a fold
    that is arbitrarily wrong still yields a true lower bound because no member
    rests on it. What the fold's incompleteness costs is completeness, and that
    is published separately and permanently as ``holder_set_exhaustive``.

    The gate travels in the same ROW as the payload. A child holders table was
    rejected for exactly this reason: it would expose addresses to a reader that
    never joined back to the qualifier, and it would make the empty-set check
    below inexpressible.

    Four states a naive schema conflates, kept apart here:

    * a proven lower bound — ``holders`` non-empty, ``holders_basis`` the pinned
      arm, ``as_of_block`` set;
    * every candidate's read completed and confirmed nobody;
    * every candidate's read reverted or failed in transport;
    * the recording surface was cold, so no candidate was even enumerable.

    The last three all publish ``holders = NULL`` and are **deliberately
    indistinguishable at row level**. Telling them apart would reconstruct the
    banned empty set: "N probed, every read completed, none confirmed" is ``[]``
    written in three columns. So the residual counters, which qualify a
    published lower bound, are NULL whenever there is no lower bound to qualify.
    """

    __tablename__ = "role_holder_planes"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    registry_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    # The 32-byte role identity, and the ONLY identity. A name is decoration
    # attached downstream and never keys anything. Rows are minted solely from
    # the OZ AccessControl ``RoleGranted``/``RoleRevoked`` topic pair, so every
    # hash in this column lives in one identity space; Solady's ``RoleSet``
    # carries a ``uint256`` role in a different space and mints no row here.
    role_hash: Mapped[str] = mapped_column(String(66), primary_key=True)
    # NULL means not_determined. It never means "nobody holds this role", and
    # an empty array — which a reader could mistake for that — cannot be stored.
    # ``none_as_null`` is load-bearing: JSONB's default is to store Python None
    # as the JSON literal ``'null'``, which is NOT SQL NULL. Every biconditional
    # below would then read the withheld row as if it carried a holder set, and
    # the checks that make the empty set unrepresentable would not fire.
    holders: Mapped[list[str] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    holders_basis: Mapped[str] = mapped_column(String(48), nullable=False)
    # Pinned to ``not_determined`` by CHECK. 0 of the 4 role registries in the
    # corpus implement the AccessControlEnumerable getter, so under B14 an
    # exhaustiveness arm has population 0 and may not be built. This is a
    # DEFERRAL WITH CAUSE, not a permanent impossibility: a registry that
    # implements ``getRoleMemberCount``/``getRoleMember``, or a proven inverse
    # index over the recording surface, would each license a real value here.
    # A future unit must revisit the constraint deliberately rather than assume
    # it was derived from something weaker.
    holder_set_exhaustive: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED
    )
    # The block every read in ``holders`` was pinned at, plus that block's hash.
    # A membership fact is mutable, so it is meaningless without its height; the
    # hash is what makes the height replayable across a reorg.
    as_of_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    as_of_block_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    # The cursor bounds, copied from ``indexed_event_cursors`` so the candidate
    # source's coverage is legible without a join. The LOWER bound is citable
    # only where U10A witnessed it (basis ``creation_block_minus_one``); an
    # ``explicit_seed`` is a caller's number, not evidence, and lands here as
    # NULL + not_determined.
    cursor_first_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursor_first_indexed_block_basis: Mapped[str] = mapped_column(String(32), nullable=False)
    cursor_last_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursor_enrollment_bases: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cursor_page_completeness: Mapped[str] = mapped_column(String(16), nullable=False)
    coverage: Mapped[str] = mapped_column(String(16), nullable=False)
    # NULL means the key is absent — no preimage was proven. It never means the
    # role is unnamed. ``keccak_preimage`` is a total mathematical fact about
    # the hash, independent of which contract offered the candidate string.
    role_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_name_basis: Mapped[str] = mapped_column(String(48), nullable=False)
    # How many addresses the fold proposed, and how many of those could not be
    # read at all. Both NULL exactly when ``holders`` is NULL (see class doc).
    candidate_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unconfirmed_candidate_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Where the fold and the chain read disagreed, recorded and NEVER diagnosed.
    # ``as_of_block`` sits above the cursor head, so a disagreement cannot be
    # attributed between "the fold missed a log" and "the state changed after
    # the cursor stopped". Permitted keys are fixed by the writer; no key
    # naming a cause may be added.
    #
    # NULL exactly when ``holders`` is, and for the same reason the counters are:
    # an empty list asserts "we looked and found none", which on a withheld row
    # is either untrue (an all-reverting registry read nothing to compare) or
    # suppression (an all-false registry DID observe disagreements). Publishing
    # ``[]`` there would be an unearned negative one column over from the empty
    # set the constraints below make unrepresentable. On a PUBLISHED row ``[]``
    # is earned, and its scope is the candidates whose reads completed —
    # ``unconfirmed_candidate_count`` carries the rest.
    fold_chain_disagreements: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        # The two hard bans, enforced where code cannot route around them.
        # NOT NULL on every discriminator is load-bearing for these: a CHECK
        # that evaluates to NULL PASSES in Postgres, so a nullable column would
        # make each of them satisfiable by omission.
        # ``holders`` is a withheld marker or an array — never a jsonb string,
        # number or object, which would satisfy a naive "is it set?" read while
        # naming no addresses at all.
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
        # The disagreement log travels with the holder set: withheld together,
        # published together. Without this a withheld row could carry ``[]`` —
        # "we looked and found none" over reads that either never happened or
        # are not being published.
        CheckConstraint(
            f"{HOLDERS_WITHHELD_SQL} = {DISAGREEMENTS_WITHHELD_SQL}",
            name="ck_role_holder_planes_disagreements_match_holders",
        ),
        CheckConstraint(
            f"{DISAGREEMENTS_WITHHELD_SQL} OR jsonb_typeof(fold_chain_disagreements) = 'array'",
            name="ck_role_holder_planes_disagreements_are_array_or_absent",
        ),
        # A witnessed lower bound and its basis are one fact. Split, the row can
        # claim a height it cannot cite, or discard a height it proved.
        CheckConstraint(
            "(cursor_first_indexed_block IS NULL) = (cursor_first_indexed_block_basis = 'not_determined')",
            name="ck_role_holder_planes_lower_bound_matches_basis",
        ),
        # ``explicit_seed`` is deliberately NOT in the stored domain: the writer
        # normalises a seed to NULL + not_determined, because a number a caller
        # supplied is not a witness and must not be storable as one.
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
    """When ``(chain_id, registry_address)`` was last folded, and what came of it.

    The plane above is keyed by ROLE, so it cannot answer a question about the
    REGISTRY: a registry whose fold proposed no candidate writes no row there,
    and row-absence in a per-role table is indistinguishable from a registry
    nothing ever ran against. That ambiguity is what this table removes, in
    exactly three states:

    * **never refreshed** — no row here. The registry is due.
    * **refreshed, confirmed nothing** — a row with ``outcome = 'no_rows'``.
      The pass ran; the fold proposed nothing at ``trigger_log_block``. It is
      NOT due again until one of the recorded observations below changes.
    * **refreshed, wrote N** — a row with ``outcome = 'rows_written'`` and
      ``rows_written = N``.

    A row is written only where the AccessControl cursor pair EXISTS. A closed
    gate leaves the registry rowless — "never refreshed" — so it re-selects by
    itself the moment the indexer finishes enrolling it, with no timer to expire
    and no flag to clear.

    The three stored observations are what make the not-due state safe rather
    than a freeze. ``trigger_log_block`` is the highest AccessControl log block
    the registry had indexed at the pass (NULL = none had been), so a later
    grant or revoke re-selects it. ``cursors_warm`` is the pair's
    ``backfill_complete`` conjunction, so a registry folded against a cold
    surface re-selects when the surface goes warm even if no new log lands.
    ``refreshed_at`` bounds the age of the floors themselves, which are
    time-varying facts about deployed state and go stale on their own.

    Nothing here records WHY a floor was withheld, and that is deliberate: the
    plane makes an all-reverting registry and an all-false one indistinguishable
    on purpose, so a refresh trigger that told them apart would reconstruct the
    distinction the plane refuses to publish.
    """

    __tablename__ = "role_holder_plane_refreshes"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    registry_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # NULL means no AccessControl log was indexed for this registry at the pass.
    # An observation of the index, never a claim that none were emitted.
    trigger_log_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    cursors_warm: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rows_written: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "outcome IN ('no_rows', 'rows_written')",
            name="ck_role_holder_plane_refreshes_outcome_domain",
        ),
        # The count and the token are one fact. Split, a pass could record
        # "confirmed nothing" over rows it wrote, which would stop the registry
        # re-selecting on the evidence that it does have roles to track.
        CheckConstraint(
            "(outcome = 'rows_written') = (rows_written > 0)",
            name="ck_role_holder_plane_refreshes_outcome_matches_count",
        ),
        CheckConstraint(
            "rows_written >= 0",
            name="ck_role_holder_plane_refreshes_count_non_negative",
        ),
    )
