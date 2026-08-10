"""Balance-provenance status vocabularies, and the one money threshold they share.

A leaf module on purpose. The producer (``utils.etherscan``), the schema
(``db.models``), the writers and the readers must agree on the exact strings,
and a second copy of any of them is a divergence vector. Nothing here imports
from the project (``decimal`` is the whole import list), so every layer can
depend on it.

The governing rule for all of these: a value is published as a positive fact
only when the evidence proves it. Every failure, swallow, revert and
unparseable answer lands on ``fetch_failed`` or ``not_determined`` — never on a
polarity, in either direction.
"""

from __future__ import annotations

from decimal import Decimal

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

# --- typed (ERC-721/1155) receipts -----------------------------------------
# What the DELIVERING LOG proved about a typed token's standard — topic0 and
# topic count, never a name or a token list. Kept rather than derived and
# dropped, because it decides which selector can read the holding later and the
# logs it comes from are not stored anywhere.
TYPED_STANDARD_ERC1155 = "erc1155"
TYPED_STANDARD_ERC721 = "erc721"
# A three-topic ``Transfer`` emitter whose ``balanceOf(address)`` returned no
# word. Filed with the typed receipts because it withholds the same
# completeness, but its log carries no id, so there is no per-id read to
# escalate to and its id inventory is settled as EMPTY. Settled, not unknown.
TYPED_STANDARD_TRANSFER_NO_ID = "erc20_transfer_shape"
TYPED_STANDARD_NOT_DETERMINED = "not_determined"
TYPED_STANDARDS = (
    TYPED_STANDARD_ERC1155,
    TYPED_STANDARD_ERC721,
    TYPED_STANDARD_TRANSFER_NO_ID,
    TYPED_STANDARD_NOT_DETERMINED,
)

# WHICH READ produced a typed receipt's published quantity. A quantity with no
# basis is a number with no witness, so the basis is stored beside it — and the
# per-id ones carry a further condition: they are an ALL-QUANTIFIER over an id
# inventory, so they say nothing unless that inventory is whole. The consumer
# checks the pair, which is why the tokens live here rather than in the producer.
TYPED_BASIS_ADDRESS_BALANCE = "balance_of_address"
TYPED_BASIS_PER_ID_BALANCE_OF_BATCH = "balance_of_batch_per_id"
TYPED_BASIS_PER_ID_BALANCE_OF_ID = "balance_of_account_id_per_id"
TYPED_BASIS_PER_ID_OWNER_OF = "owner_of_per_id"
TYPED_PER_ID_BASES = (
    TYPED_BASIS_PER_ID_BALANCE_OF_BATCH,
    TYPED_BASIS_PER_ID_BALANCE_OF_ID,
    TYPED_BASIS_PER_ID_OWNER_OF,
)
TYPED_QUANTITY_BASES = (TYPED_BASIS_ADDRESS_BALANCE, *TYPED_PER_ID_BASES)

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


# --- delivery shape (the disposition evidence plane) -------------------------
# What the chain's own log history says about HOW a (holder, token) balance
# arrived. This is a claim about DELIVERY, never about worth: a token delivered
# by a transaction emitting 400 same-token transfer logs arrived in a mass
# distribution whatever it is worth, and a real token can be airdrop-delivered
# (measured: HEX, uniETH). Nothing in this vocabulary
# may be read, published or renamed as "spam", "scam" or "worthless" — those are
# judgments about value that no receipt witnesses.
#
# THE METER IS LOGS, NOT RECIPIENTS. A fan-out is the number of same-token
# ``Transfer`` LOGS the delivering transaction emitted, counted off its own
# receipt. That is an UPPER BOUND on the distinct recipients it paid — one
# recipient paid twice in one transaction counts twice — and every sentence
# published from this vocabulary says logs for that reason. K is calibrated on
# the log meter (``FAN_OUT_CALIBRATION_CORPUS`` is metered in same-token
# ``Transfer`` logs), so switching the meter to distinct recipients would
# invalidate the calibration rather than refine it.
#
# ``fan_out_all`` is the ALL-QUANTIFIER over every delivery on record: every
# incoming Transfer of that token to that holder arrived in a transaction that
# emitted at least ``fan_out_threshold_k`` same-token transfer logs. It is the
# only positive verdict, and it is earned per delivery.
#
# ``has_direct_delivery`` is the EARNED NEGATIVE: at least one delivery arrived
# in a transaction emitting fewer than K same-token transfer logs, so the
# all-quantifier is false and the pair is not an airdrop-only holding. Kept apart
# from ``not_determined`` because they are closed by different work — nothing
# closes the first (it is settled), and a readable receipt closes the second.
#
# ``not_determined`` is everything else and is FAIL-CLOSED by construction: a
# receipt that could not be read, a scan that aborted, or a balance with no
# incoming Transfer on record at all (a non-conforming token, or a mint this
# scan's topic filter cannot see). Absence of a readable delivery is never read
# as absence of a direct delivery.
DELIVERY_SHAPE_FAN_OUT_ALL = "fan_out_all"
DELIVERY_SHAPE_HAS_DIRECT_DELIVERY = "has_direct_delivery"
DELIVERY_SHAPE_NOT_DETERMINED = "not_determined"
DELIVERY_SHAPES = (
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
)

# How a delivery's fan-out was counted. Stored per delivery so a published
# figure names the mechanism that produced it rather than being trusted.
#
# ``receipt_same_token_transfer_logs`` is the whole claim, and the literal is
# exact: the number is a COUNT OF LOGS in the delivering transaction's receipt
# whose emitter is the same token and whose shape is a 3-topic ``Transfer``.
# It is not a count of distinct recipient addresses — it never was — and the
# name is what a consumer must quote when it publishes the figure.
DELIVERY_FAN_OUT_BASIS_RECEIPT = "receipt_same_token_transfer_logs"
DELIVERY_FAN_OUT_BASIS_UNREADABLE = "receipt_unreadable"
DELIVERY_FAN_OUT_BASES = (DELIVERY_FAN_OUT_BASIS_RECEIPT, DELIVERY_FAN_OUT_BASIS_UNREADABLE)


# --- token / protocol reference (the disposition reference plane) ------------
# Whether a token address is one the protocol's OWN discovery names. Measured by
# the producer against ``services.scoring.distill.load_protocol_universe`` and
# stored so a presentation surface can read the verdict without the 26.5-second
# object-storage assembly that produced it.
#
# ``in_universe`` is the SPARING positive: discovery names this address, so the
# holding is a reference of the protocol's own and no delivery-shape verdict may
# pull it from a sheet.
#
# ``absent_from_universe`` is earned only against a universe that was built
# WHOLE. It is anti-monotone by construction — discovery growing can only turn
# it back into ``in_universe`` — and withdrawal is the safe direction.
#
# ``not_determined`` is the fail-closed answer and it covers a universe that
# could not be assembled at all (a short universe would condemn MORE, never
# less) as well as a token no producer has reached yet. ABSENCE OF A ROW READS
# AS ``not_determined`` at every consumer: nothing may be pulled from a sheet
# because no verdict was stored for it.
TOKEN_REFERENCE_IN_UNIVERSE = "in_universe"
TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE = "absent_from_universe"
TOKEN_REFERENCE_NOT_DETERMINED = "not_determined"
TOKEN_REFERENCE_SHAPES = (
    TOKEN_REFERENCE_IN_UNIVERSE,
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
)


# --- the crumb rule ---------------------------------------------------------
# One cent, and the two filters that consume it treat a holding worth strictly
# LESS than this as a crumb: a figure too small to separate a position from the
# dust an address is sent unasked. At or above it the holding is a position and
# is kept, so the boundary lands on the KEEP side — $0.009 is a crumb, $0.01 is
# money.
#
# It is a RULE, and the point of naming it is that it was not one before. Both
# filters used to test a stored ``usd_value`` against 0, and small figures landed
# there because ``contract_balances.usd_value`` was ``numeric(20,2)``: the column
# rounded to the nearest cent and the predicate read the resulting 0.00 as "no
# price". Widening the column to ``numeric(38,18)`` (``b8d3c5f21a04``) removed
# the rounding, and with it the only thing that had ever implemented any
# threshold — so both populations would have silently taken every crumb back in,
# on no decision by anyone.
#
# The rule is NOT a restatement of what the rounding did, and the difference is
# worth knowing. Postgres rounds half away from zero, so the old cut sat at HALF
# a cent: $0.004 vanished and $0.009 survived as a stored $0.01. A cent is the
# deliberate line, so the readings in [$0.005, $0.01) — which used to be kept by
# being rounded UP into a position — are crumbs now. Exactly $0.01 is unmoved: it
# stored as 0.01 then and is a position now.
#
# Shared rather than duplicated because the two filters answer the SAME question
# about the same column, one in SQL and one in Python, and a divergence between
# them is invisible from either side. It is a ``Decimal`` because the column is
# numeric and the comparison must be exact at the boundary; binary floats put
# 0.01 slightly above itself.
#
# It is NOT a claim about worth: nothing here says a crumb is worthless, spam or
# fake. It says the figure is below the resolution these two consumers act on.
USD_CRUMB_THRESHOLD = Decimal("0.01")
