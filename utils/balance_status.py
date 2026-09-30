"""Balance-provenance status vocabularies.

A leaf module (imports only ``decimal``) so producer, schema, writers and readers share one copy.

A value is published as a positive fact only when evidence proves it; every failure lands on ``fetch_failed`` or
``not_determined``, never on a polarity.
"""

from __future__ import annotations

from decimal import Decimal

STATUS_UNATTEMPTED = "unattempted"

# ``proven_zero`` only from a pinned read (``ck_cbf_proven_zero_requires_block``): an unpinned ``latest`` zero proves
# zero at no height.
NATIVE_STATUS_PROVEN_ZERO = "proven_zero"
NATIVE_STATUS_PROVEN_NONZERO = "proven_nonzero"
NATIVE_STATUS_FETCH_FAILED = "fetch_failed"
NATIVE_STATUS_NOT_DETERMINED = "not_determined"
NATIVE_STATUSES = (
    STATUS_UNATTEMPTED,
    NATIVE_STATUS_PROVEN_ZERO,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
)

# ``returned_empty`` describes the page, never the holdings: the endpoint is one page deep and fails to ``[]``. No
# "complete": page length proves the at-cap case, never its negation.
ASSET_SET_STATUS_RETURNED_ASSETS = "returned_assets"
ASSET_SET_STATUS_RETURNED_EMPTY = "returned_empty"
ASSET_SET_STATUS_AT_PAGE_CAP = "at_page_cap"
ASSET_SET_STATUS_FETCH_FAILED = "fetch_failed"
ASSET_SET_STATUSES = (
    STATUS_UNATTEMPTED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
)

# ``etherscan_pages`` is a third-party index: positive lists are a floor, empty proves nothing. Only ``chain_log_sweep``
# may publish an empty asset set as an earned negative.
ASSET_SET_SOURCE_ETHERSCAN_PAGES = "etherscan_pages"
ASSET_SET_SOURCE_CHAIN_LOG_SWEEP = "chain_log_sweep"
ASSET_SET_SOURCES = (ASSET_SET_SOURCE_ETHERSCAN_PAGES, ASSET_SET_SOURCE_CHAIN_LOG_SWEEP)

# Which mechanism read a stored row's quantity.
BALANCE_SOURCE_PINNED_NATIVE_READ = "pinned_native_read"
BALANCE_SOURCE_UNPINNED_NATIVE_READ = "unpinned_native_read"
BALANCE_SOURCES = (
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    BALANCE_SOURCE_PINNED_NATIVE_READ,
    BALANCE_SOURCE_UNPINNED_NATIVE_READ,
)

# The standard the delivering log proved (topic0 + topic count). Stored because it picks the read selector later and the
# logs aren't kept.
TYPED_STANDARD_ERC1155 = "erc1155"
TYPED_STANDARD_ERC721 = "erc721"
# Three-topic ``Transfer`` whose ``balanceOf(address)`` returned nothing: no id to escalate to, so its id inventory is
# settled EMPTY.
TYPED_STANDARD_TRANSFER_NO_ID = "erc20_transfer_shape"
TYPED_STANDARD_NOT_DETERMINED = "not_determined"
TYPED_STANDARDS = (
    TYPED_STANDARD_ERC1155,
    TYPED_STANDARD_ERC721,
    TYPED_STANDARD_TRANSFER_NO_ID,
    TYPED_STANDARD_NOT_DETERMINED,
)

# Which read produced a typed receipt's quantity. Per-id bases quantify over the id inventory, so the consumer checks
# basis and inventory completeness together.
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

# NULL = no sweep attempted (not a failure). ``failed``: the scan couldn't be shown whole, so the entity's claim aborts.
# Only ``completed`` carries ``swept_through_block``.
SWEEP_STATUS_COMPLETED = "completed"
SWEEP_STATUS_FAILED = "failed"
SWEEP_STATUSES = (SWEEP_STATUS_COMPLETED, SWEEP_STATUS_FAILED)

# "Row class not observed on this fetch"; the latest view and retention prune key off it.
STATUS_FETCH_FAILED = "fetch_failed"

# Which loop issued the read, stored rather than inferred from ``fetched_at`` multiplicity.
BALANCE_WRITER_TVL = "tvl"
BALANCE_WRITER_RESOLUTION = "resolution_worker"
BALANCE_WRITERS = (BALANCE_WRITER_TVL, BALANCE_WRITER_RESOLUTION)


# How a (holder, token) balance was delivered, per the chain's log history. A claim about delivery, never worth: never
# read or publish it as spam/scam/worthless.
#
# The meter is same-token ``Transfer`` LOGS in the delivering tx (an upper bound on recipients); K is calibrated on
# logs, so don't switch to distinct recipients.
#
# ``fan_out_all``: every delivery came in a tx with >= K logs. ``has_direct_delivery``: at least one didn't (earned
# negative). ``not_determined``: fail-closed, including no readable delivery at all.
DELIVERY_SHAPE_FAN_OUT_ALL = "fan_out_all"
DELIVERY_SHAPE_HAS_DIRECT_DELIVERY = "has_direct_delivery"
DELIVERY_SHAPE_NOT_DETERMINED = "not_determined"
DELIVERY_SHAPES = (
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
)

# The figure is a count of logs, not recipients; consumers must quote this name when publishing it.
DELIVERY_FAN_OUT_BASIS_RECEIPT = "receipt_same_token_transfer_logs"
DELIVERY_FAN_OUT_BASIS_UNREADABLE = "receipt_unreadable"
DELIVERY_FAN_OUT_BASES = (DELIVERY_FAN_OUT_BASIS_RECEIPT, DELIVERY_FAN_OUT_BASIS_UNREADABLE)


# Whether the protocol's own discovery names a token (vs ``load_protocol_universe``), stored to skip the slow assembly.
#
# ``absent_from_universe`` only against a universe built whole; discovery growth can only withdraw it. A missing row
# reads as ``not_determined`` everywhere.
TOKEN_REFERENCE_IN_UNIVERSE = "in_universe"
TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE = "absent_from_universe"
TOKEN_REFERENCE_NOT_DETERMINED = "not_determined"
TOKEN_REFERENCE_SHAPES = (
    TOKEN_REFERENCE_IN_UNIVERSE,
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
)


# A holding worth strictly less than one cent is a crumb; $0.01 is kept.
#
# Before ``b8d3c5f21a04`` widened ``usd_value`` from ``numeric(20,2)``, rounding was the only threshold (at half a
# cent); this makes it an explicit rule. Shared by the SQL and Python filters so they can't diverge; ``Decimal`` for an
# exact boundary. Not a claim about worth.
USD_CRUMB_THRESHOLD = Decimal("0.01")

# A partial prefix is a fallback only when no accepted provider rowset exists.
NATIVE_ACCEPTED_STATUSES = (NATIVE_STATUS_PROVEN_ZERO, NATIVE_STATUS_PROVEN_NONZERO, NATIVE_STATUS_NOT_DETERMINED)
ASSET_ACCEPTED_STATUSES = (ASSET_SET_STATUS_RETURNED_ASSETS, ASSET_SET_STATUS_RETURNED_EMPTY)
ASSET_OBSERVED_STATUSES = (*ASSET_ACCEPTED_STATUSES, ASSET_SET_STATUS_AT_PAGE_CAP)


def asset_snapshot_priority(status: str) -> int:
    return 2 if status in ASSET_ACCEPTED_STATUSES else (1 if status == ASSET_SET_STATUS_AT_PAGE_CAP else 0)
