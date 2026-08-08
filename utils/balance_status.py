"""Balance-provenance status vocabularies.

A leaf module on purpose. The producer (``utils.etherscan``), the schema
(``db.models``), the writers and the readers must agree on the exact strings,
and a second copy of any of them is a divergence vector. Nothing here imports
anything, so every layer can depend on it.

The governing rule for all of these: a value is published as a positive fact
only when the evidence proves it. Every failure, swallow, revert and
unparseable answer lands on ``fetch_failed`` or ``not_determined`` — never on a
polarity, in either direction.
"""

from __future__ import annotations

# --- native coin -----------------------------------------------------------
# ``proven_zero`` is reachable ONLY from a pinned read, and the schema enforces
# it (``ck_cbf_proven_zero_requires_block``): a zero from an unpinned
# ``tag=latest`` answer is zero at an unrecorded moment, which proves zero at no
# height, and reading it as a proven zero is the exact conflation this closes.
NATIVE_STATUS_PROVEN_ZERO = "proven_zero"
NATIVE_STATUS_PROVEN_NONZERO = "proven_nonzero"
NATIVE_STATUS_FETCH_FAILED = "fetch_failed"
NATIVE_STATUS_NOT_DETERMINED = "not_determined"
NATIVE_STATUSES = (
    NATIVE_STATUS_PROVEN_ZERO,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
)

# --- ERC-20 discovery page -------------------------------------------------
# ``returned_empty`` is a fact about the PAGE, never "this address holds no
# tokens": the endpoint is one page deep and its failure path returns ``[]``.
# There is deliberately no "complete" — a page length can prove the at-cap case
# and never its negation.
ASSET_SET_STATUS_RETURNED_ASSETS = "returned_assets"
ASSET_SET_STATUS_RETURNED_EMPTY = "returned_empty"
ASSET_SET_STATUS_AT_PAGE_CAP = "at_page_cap"
ASSET_SET_STATUS_FETCH_FAILED = "fetch_failed"
ASSET_SET_STATUSES = (
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
)

# --- where the asset set came from ----------------------------------------
# The status above says what the answer WAS; this says whose answer it is, and
# the two together are the whole claim. ``etherscan_pages`` is a third-party
# index: its positive list is a floor (under-indexing only hides assets) and its
# empty list proves nothing about the chain. ``chain_log_sweep`` is the chain's
# own transfer history through a named block, which is the only source from
# which an EMPTY asset set may be published as an earned negative.
ASSET_SET_SOURCE_ETHERSCAN_PAGES = "etherscan_pages"
ASSET_SET_SOURCE_CHAIN_LOG_SWEEP = "chain_log_sweep"
ASSET_SET_SOURCES = (ASSET_SET_SOURCE_ETHERSCAN_PAGES, ASSET_SET_SOURCE_CHAIN_LOG_SWEEP)

# The same question asked of a stored ROW: which mechanism read this quantity.
# The two asset-set sources above are reused verbatim (an ERC-20 row comes from
# one of them), plus the two native shapes — pinned and unpinned are already a
# distinction the native status depends on, and a row that says which one it is
# does not have to be re-derived from a NULL block.
BALANCE_SOURCE_PINNED_NATIVE_READ = "pinned_native_read"
BALANCE_SOURCE_UNPINNED_NATIVE_READ = "unpinned_native_read"
BALANCE_SOURCES = (
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    BALANCE_SOURCE_PINNED_NATIVE_READ,
    BALANCE_SOURCE_UNPINNED_NATIVE_READ,
)

# --- the escalation's own outcome ------------------------------------------
# NULL/absent = no sweep was attempted, which is a third state and not a
# failure. ``failed`` means the scan could not be shown to be whole (a window at
# the bisect floor, a page at the result cap, an unreadable balance): the
# entity's claim ABORTS — a partial asset list is a floor and the sweep exists
# for the upper bound. Only ``completed`` may carry a ``swept_through_block``.
SWEEP_STATUS_COMPLETED = "completed"
SWEEP_STATUS_FAILED = "failed"
SWEEP_STATUSES = (SWEEP_STATUS_COMPLETED, SWEEP_STATUS_FAILED)

# The one string that means "this row class was not observed on this fetch".
# The ``contract_balances_latest`` view and the retention prune both key off it,
# per row class. Same literal in both vocabularies by design.
STATUS_FETCH_FAILED = "fetch_failed"

# --- writer identity -------------------------------------------------------
# A literal at the two call sites, so which loop issued a read is a stored code
# fact instead of the ``fetched_at``-multiplicity heuristic it could only be
# inferred by before.
BALANCE_WRITER_TVL = "tvl"
BALANCE_WRITER_RESOLUTION = "resolution_worker"
BALANCE_WRITERS = (BALANCE_WRITER_TVL, BALANCE_WRITER_RESOLUTION)
