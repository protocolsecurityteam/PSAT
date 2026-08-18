"""Shared balance-read primitives for the two ``contract_balances`` writers.

``services.monitoring.tvl`` and ``workers.resolution_worker`` are the only two
writers of that table (exhaustively swept). They ran different code with
different failure behaviour: one swallowed a native-fetch exception into
``eth_wei = 0`` and left no trace at all, the other returned early and recorded
a degraded phase. Everything they must now do IDENTICALLY lives here, so the
three-state a consumer reads does not depend on which loop happened to write it.

``record_degraded`` is NOT what makes a failure here traceable. It is a no-op
outside ``BaseWorker`` (``utils.logging``; bound only in ``workers.base``), and
the TVL loop runs outside it — relying on it there would pass a mocked test and
persist nothing in production, which is the silent-no-trace shape this unit
exists to close. The discriminator is the PERSISTED provenance column instead,
written by both writers, which is what makes the trace identical rather than
merely similarly-named; the TVL loop's substitute is the house-standard
per-cycle heartbeat plus an unconditional log.

It IS called, from the two swallowed handlers in
:func:`pinned_native_balances`, and for the complementary reason: that function
runs per job under the resolution worker, where a WARNING inside a swallowed
``except`` without it leaves the job's ``stage_errors`` artifact claiming a
clean run. Under the TVL loop the same call is the documented no-op.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from db.models import Contract, ContractBalance, ContractBalanceFetch
from utils.balance_status import (
    NATIVE_STATUS_FETCH_FAILED,
    NATIVE_STATUS_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_NONZERO,
    NATIVE_STATUS_PROVEN_ZERO,
    STATUS_FETCH_FAILED,
)
from utils.logging import record_degraded
from utils.rpc import MULTICALL3_ADDRESS, multicall3_aggregate3, rpc_request, rpc_url_for_chain_id, selector

logger = logging.getLogger(__name__)


def _degraded(exc: BaseException, *, phase: str, **context: Any) -> None:
    """Pair a swallowed WARNING with the job's degraded accumulator.

    A no-op under the TVL loop (no accumulator is bound there); under the
    resolution worker it is what puts the swallow in ``stage_errors``.
    """
    record_degraded(phase=phase, exc=exc, context=context)


@dataclass(frozen=True)
class ObservationSubject:
    """WHO a balance observation is about.

    Two arms, exactly one populated, mirroring the schema's
    ``ck_*_exactly_one_subject_key``: a ``contracts`` row, or an entity that has
    none. The second arm exists because the perimeter the score is computed over
    is wider than the ``contracts`` table: a proven-codeless principal reached
    through the control graph is an entity whose balance sheet is asked about,
    and its only identity is ``(chain, address)``.

    Hashable, and used directly as the key of every per-subject mapping in the
    observation modules — a contract id and an entity key can then never collide
    in one dict, which an int-keyed mapping with negative sentinels could.

    ``address`` is the address a read is ISSUED against and is recorded verbatim
    from the contracts row, which is what a fetch row's ``observed_address``
    has always carried. For the entity arm it is ALSO half of the identity, so
    it is normalised there: two spellings of one address are one subject, and
    the equality that decides which fetch is current has to say so. The entity
    key it is built from is already lower case, so the normalisation restates
    the caller's contract rather than changing it.
    """

    contract_id: int | None
    chain: str | None
    address: str

    @classmethod
    def of_contract(cls, contract: Contract) -> ObservationSubject:
        return cls(contract_id=contract.id, chain=None, address=contract.address)

    @classmethod
    def of_entity(cls, chain: str, address: str) -> ObservationSubject:
        """An entity with no ``contracts`` row. *chain* is the plane's own
        coalesced chain name — the identity the entity key is built from, so a
        record written here and an entity key read there name the same thing.
        """
        return cls(contract_id=None, chain=chain, address=(address or "").lower())

    @property
    def is_entity(self) -> bool:
        return self.contract_id is None

    def filters(self, model: Any) -> list[Any]:
        """The predicate selecting exactly this subject's rows of *model*.

        For a contract subject it is the ``contract_id`` equality every reader
        here used before the entity arm existed — unchanged, so contract-keyed
        behaviour is identical. For an entity subject the ``contract_id IS NULL``
        conjunct is not decoration: without it the entity columns alone would
        also match a contract-keyed row if one ever carried them, and the schema
        CHECK is the only thing standing between those two readings.
        """
        if self.contract_id is not None:
            return [model.contract_id == self.contract_id]
        return [
            model.contract_id.is_(None),
            model.entity_chain == self.chain,
            model.entity_address == self.address,
        ]

    def columns(self) -> dict[str, Any]:
        """The identity columns to write on a new row of either table."""
        if self.contract_id is not None:
            return {"contract_id": self.contract_id, "entity_chain": None, "entity_address": None}
        return {"contract_id": None, "entity_chain": self.chain, "entity_address": self.address}


# Steps back from head before pinning. Same margin the resolver's probe uses, and
# the reason a height can be published at all: the read is issued AT this number,
# so the number is a witness of the read rather than an assumption about when an
# unpinned API answered.
PINNED_FINALITY_MARGIN = 12

# A 32-byte word, hex-encoded with the ``0x`` prefix. Anything else — most
# importantly ``"0x"``, which ``aggregate3`` returns with ``success=True`` for a
# call that returned no data — is NOT a balance. ``int("0x", 16)`` raises but
# ``int("0x0", 16)`` is 0, and a decode that tolerated short returndata would
# mint a ``proven_zero`` out of an empty return: a default standing in for a
# witness.
_WORD_HEX_LEN = 66


def pinned_native_balances(
    addresses: list[str],
    *,
    chain_id: int,
    rpc_url: str | None = None,
) -> tuple[int | None, dict[str, int]]:
    """Read native balances at ONE explicitly pinned height.

    Returns ``(block_number, {address_lower: wei})``. ``block_number`` is
    ``None`` — and the mapping empty — whenever the height or the read could not
    be established. There is no partial success at the block level: without a
    height, nothing read here may be published as a pinned fact, and the caller
    must fall back to the unpinned path where a zero is ``not_determined``.

    An address MISSING from the returned mapping is not a zero. It is "this
    sub-call did not yield a decodable 32-byte word", and the caller must treat
    it as a failed read.

    The block is resolved FIRST and every read is issued at it. Reading at
    ``"latest"`` and stamping a separately-fetched ``eth_blockNumber`` beside the
    answer would assert that the node answered at that head — an assumption, not
    a witness, and the invented-witness failure mode this whole unit is about.
    """
    if not addresses:
        return None, {}
    url = rpc_url or rpc_url_for_chain_id(chain_id)
    # Multicall3 is deployed at the same address on every chain in the registry;
    # a chain without it would surface here as an undecodable result and take the
    # unpinned fallback, which is the safe direction.
    if not url:
        return None, {}
    try:
        head = int(rpc_request(url, "eth_blockNumber", [], retries=1, chain_id=chain_id), 16)
    except Exception as exc:
        # Once per CALL: one per chain in a TVL cycle, but one per contract in
        # the resolution worker, which calls this per job. That second caller is
        # a worker job context, so the swallow is paired with ``record_degraded``
        # — the WARNING alone would leave the job's ``stage_errors`` artifact
        # claiming a clean run.
        _degraded(exc, phase="pinned_native_head", chain_id=chain_id, addresses=len(addresses))
        logger.warning(
            "pinned native balance: head read failed; the chain's holders fall back to the unpinned path",
            extra={
                "chain_id": chain_id,
                "addresses": len(addresses),
                "exc_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return None, {}
    block = max(1, head - PINNED_FINALITY_MARGIN)
    # Derived, never hardcoded, for the reason ``multicall3_aggregate3`` states:
    # a typo in a hand-written selector mints wrong calldata silently.
    sel = selector("getEthBalance(address)")
    ordered = [a.lower() for a in addresses]
    calls = [(MULTICALL3_ADDRESS, sel + a[2:].rjust(64, "0")) for a in ordered]
    try:
        results = multicall3_aggregate3(url, calls, hex(block), chain_id=chain_id)
    except Exception as exc:
        _degraded(exc, phase="pinned_native_read", chain_id=chain_id, block_number=block, addresses=len(addresses))
        logger.warning(
            "pinned native balance: aggregate3 did not answer; the chain's holders fall back to the unpinned path",
            extra={
                "chain_id": chain_id,
                "block_number": block,
                "addresses": len(addresses),
                "exc_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return None, {}
    out: dict[str, int] = {}
    for address, (ok, data) in zip(ordered, results):
        if not ok or not isinstance(data, str) or len(data) != _WORD_HEX_LEN:
            # Includes the ``(True, "0x")`` empty-return shape. Excluded from the
            # mapping, never decoded as 0.
            continue
        try:
            out[address] = int(data, 16)
        except ValueError:
            continue
    return block, out


def native_status_for(*, wei: int | None, pinned: bool, failed: bool) -> str:
    """The one place a native read becomes a status.

    * ``failed`` — the read raised, came back an exception object, or produced no
      decodable word. Nothing is known about the balance.
    * pinned and zero — a proven zero: ``getEthBalance`` returned ``0x0`` AT a
      named height.
    * unpinned and zero — ``not_determined``. Etherscan answers ``tag=latest``
      and its response carries no height, so this is "zero at some unrecorded
      moment", which proves zero at no height. Publishing it as a proven zero is
      the exact conflation B2 names.
    * nonzero — ``proven_nonzero``, on either path. Read it as the PAIR with
      ``block_number``: with a NULL block it means "nonzero at an unrecorded
      height", never an as-of-block fact (see :func:`native_balance_fact`).
    """
    if failed or wei is None:
        return NATIVE_STATUS_FETCH_FAILED
    if wei > 0:
        return NATIVE_STATUS_PROVEN_NONZERO
    return NATIVE_STATUS_PROVEN_ZERO if pinned else NATIVE_STATUS_NOT_DETERMINED


def native_balance_fact(native_status: str, block_number: int | None) -> str:
    """What a ``(native_status, block_number)`` pair actually asserts.

    The status alone is not the fact and must never be consumed alone:
    ``proven_nonzero`` with a NULL block is a real observation with no height,
    and a consumer that read the status by itself would treat it as an
    as-of-block quantity. This is the single helper every consumer of
    ``native_status`` goes through.
    """
    if native_status == NATIVE_STATUS_PROVEN_ZERO:
        # The schema refuses this combination, so it is unreachable through the
        # DB; the branch exists so an in-memory caller cannot construct it either.
        if block_number is None:
            return "not_determined"
        return f"proven_zero_at_block_{block_number}"
    if native_status == NATIVE_STATUS_PROVEN_NONZERO:
        return f"proven_nonzero_at_block_{block_number}" if block_number is not None else "nonzero_at_unrecorded_height"
    if native_status == NATIVE_STATUS_FETCH_FAILED:
        return "not_determined"
    return "not_determined"


def balance_history_depth() -> int:
    """How many fetches per (contract, observed_address) retention keeps.

    Raises on a value below 1. Depth 0 would prune every fetch, and because the
    view's legacy arm shows pre-migration rows whenever no non-failed fetch
    exists, that would RESURRECT the 1,617 legacy rows as current holdings.
    """
    raw = os.getenv("PSAT_BALANCE_HISTORY_DEPTH", "10")
    try:
        depth = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"PSAT_BALANCE_HISTORY_DEPTH must be an integer >= 1, got {raw!r}") from exc
    if depth < 1:
        raise ValueError(f"PSAT_BALANCE_HISTORY_DEPTH must be >= 1, got {depth}")
    return depth


def prune_balance_fetches(session: Session, subject: ObservationSubject, observed_address: str) -> int:
    """Bound insert-only growth without ever deleting a published observation.

    The writers are insert-only now (the destructive per-contract DELETE is
    gone), and the TVL loop runs hourly, so history has to be bounded somewhere.
    It is bounded here, at the write point, by fetch — never by row — so a
    holdings set is only ever dropped whole.

    Two things are kept: the ``depth`` most recent fetches, AND, per row class,
    the most recent NON-FAILED fetch regardless of age. Without the second rule
    ``depth`` consecutive failures would evict the last good fetch and
    CASCADE-delete exactly the rows the view is currently publishing — an
    absence manufactured by a retention policy, which two downstream consumers
    turn into a published ``$0.00``.

    Returns the number of fetch rows deleted.
    """
    depth = balance_history_depth()
    rows = session.execute(
        select(
            ContractBalanceFetch.id,
            ContractBalanceFetch.native_status,
            ContractBalanceFetch.asset_set_status,
        )
        .where(
            *subject.filters(ContractBalanceFetch),
            ContractBalanceFetch.observed_address == observed_address,
        )
        .order_by(ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc())
    ).all()
    if len(rows) <= depth:
        return 0
    keep = {r.id for r in rows[:depth]}
    for status_index in (1, 2):  # native_status, then asset_set_status
        for row in rows:
            if row[status_index] != STATUS_FETCH_FAILED:
                keep.add(row.id)
                break
    doomed = [r.id for r in rows if r.id not in keep]
    if not doomed:
        return 0
    session.query(ContractBalanceFetch).filter(ContractBalanceFetch.id.in_(doomed)).delete(synchronize_session=False)
    return len(doomed)


def winning_asset_fetches(session: Session, protocol_id: int) -> dict[int, ContractBalanceFetch]:
    """Per contract, the fetch whose ERC-20 row set ``contract_balances_latest`` publishes.

    The completeness of a published asset list is a property of THE ROW SET, so
    it must be read from the fetch that owns those rows — not from the latest
    fetch, which may be a later failure. The two differ exactly when they matter:
    a ``fetch_failed`` (or a shorter page) arriving after an ``at_page_cap`` read
    would withdraw the truncation while the truncated-prefix rows are still what
    the view returns and still what a sheet sums. Same rule as the view's ERC-20
    arm — latest non-failed wins — so the two cannot disagree.

    A contract whose asset class has NO non-failed fetch is absent from the
    mapping: nothing current is known about its list, which is a third state and
    not a completeness verdict either way.
    """
    from db.models import Contract

    rows = (
        session.query(ContractBalanceFetch)
        .join(Contract, Contract.id == ContractBalanceFetch.contract_id)
        .filter(
            Contract.protocol_id == protocol_id,
            ContractBalanceFetch.asset_set_status != STATUS_FETCH_FAILED,
        )
        .order_by(
            ContractBalanceFetch.contract_id,
            ContractBalanceFetch.fetched_at.desc(),
            ContractBalanceFetch.id.desc(),
        )
        .all()
    )
    winners: dict[int, ContractBalanceFetch] = {}
    for fetch in rows:
        if fetch.contract_id is not None:
            winners.setdefault(fetch.contract_id, fetch)
    return winners


def winning_entity_asset_fetches(
    session: Session, subjects: list[ObservationSubject]
) -> dict[ObservationSubject, ContractBalanceFetch]:
    """The same question as :func:`winning_asset_fetches`, for entity subjects.

    Same rule — latest non-failed fetch per subject wins the ERC-20 class — asked
    over the OTHER identity arm. It is a separate function rather than a widened
    one because the two are scoped differently and neither scope can stand in for
    the other: a contract's fetches are scoped by ``contracts.protocol_id``, and
    an entity that has no ``contracts`` row carries no protocol at all, so its
    scope is the caller's enumerated perimeter and nothing else. An entity is
    absent from the mapping when nothing non-failed has answered for it, which is
    a third state and not a completeness verdict either way.
    """
    if not subjects:
        return {}
    by_identity = {(s.chain, s.address): s for s in subjects if s.is_entity}
    if not by_identity:
        return {}
    rows = (
        session.query(ContractBalanceFetch)
        .filter(
            ContractBalanceFetch.contract_id.is_(None),
            tuple_(ContractBalanceFetch.entity_chain, ContractBalanceFetch.entity_address).in_(list(by_identity)),
            ContractBalanceFetch.asset_set_status != STATUS_FETCH_FAILED,
        )
        .order_by(
            ContractBalanceFetch.entity_chain,
            ContractBalanceFetch.entity_address,
            ContractBalanceFetch.fetched_at.desc(),
            ContractBalanceFetch.id.desc(),
        )
        .all()
    )
    winners: dict[ObservationSubject, ContractBalanceFetch] = {}
    for fetch in rows:
        if fetch.entity_address is None:
            continue
        subject = by_identity.get((fetch.entity_chain, fetch.entity_address))
        if subject is not None:
            winners.setdefault(subject, fetch)
    return winners


def contracts_missing_current_rows(session: Session, contract_ids: list[int]) -> set[int]:
    """Contracts whose current holdings the view cannot publish for some row class.

    A total built over such a contract is not a measurement of anything, so the
    caller omits it and flags the cycle partial rather than emitting a ``0.0``
    that would enter a headline money figure.

    Two grounds, and the second is an INTEGRITY check rather than an observation:

    1. **No non-failed fetch for a class.** Nothing current is known about it.
    2. **A winning fetch whose ``proven_nonzero`` native class persisted no
       row.** That combination is impossible by construction — the writer only
       stamps ``proven_nonzero`` for a quantity above zero, and writes the row
       in the same transaction — so its presence means the row set was never
       written and the class's status is over-promising. The view keys on the
       status, so without this the row-less fetch would win the class and
       silently withdraw the prior holding while the cycle reported itself
       complete.

    There is deliberately NO analogous asset-class rule. ``returned_assets`` with
    zero persisted rows is legitimately reachable — a page whose every entry is
    zero-balance is dropped by ``get_token_balances_page``'s ``raw_balance > 0``
    filter — so treating it as a violation would flag a real observation. The
    asset class is defended at the writer instead (see ``_fetch_balances``: a
    non-failed class status is a promise its row set was written).

    A contract that has never been fetched at all is NOT in this set: its legacy
    rows are still the best available observation and the view still shows them.
    """
    if not contract_ids:
        return set()
    fetches = session.execute(
        select(
            ContractBalanceFetch.id,
            ContractBalanceFetch.contract_id,
            ContractBalanceFetch.native_status,
            ContractBalanceFetch.asset_set_status,
        )
        .where(ContractBalanceFetch.contract_id.in_(contract_ids))
        .order_by(ContractBalanceFetch.fetched_at.desc(), ContractBalanceFetch.id.desc())
    ).all()
    if not fetches:
        return set()

    # The winning fetch per (contract, class) — the same rule the view applies.
    native_winner: dict[int, tuple[int, str]] = {}
    asset_winner: dict[int, int] = {}
    fetched: set[int] = set()
    for fetch_id, contract_id, native_status, asset_status in fetches:
        fetched.add(contract_id)
        if native_status != STATUS_FETCH_FAILED and contract_id not in native_winner:
            native_winner[contract_id] = (fetch_id, native_status)
        if asset_status != STATUS_FETCH_FAILED and contract_id not in asset_winner:
            asset_winner[contract_id] = fetch_id

    promising = [fid for fid, status in native_winner.values() if status == NATIVE_STATUS_PROVEN_NONZERO]
    with_native_row: set[int] = set()
    if promising:
        with_native_row = {
            fid
            for fid in session.execute(
                select(ContractBalance.fetch_id).where(
                    ContractBalance.fetch_id.in_(promising),
                    ContractBalance.token_address.is_(None),
                )
            )
            .scalars()
            .all()
            if fid is not None
        }

    missing: set[int] = set()
    for contract_id in fetched:
        if contract_id not in native_winner or contract_id not in asset_winner:
            missing.add(contract_id)
            continue
        fetch_id, status = native_winner[contract_id]
        if status == NATIVE_STATUS_PROVEN_NONZERO and fetch_id not in with_native_row:
            missing.add(contract_id)
    return missing


def positive_raw_balance(raw_balance: object) -> bool:
    """Whether a stored ``raw_balance`` witnesses a strictly positive quantity.

    ``raw_balance`` is a varchar (the column stores decimal strings to avoid
    overflow), so this cannot be a SQL comparison: ``>`` would be lexicographic
    and a ``::numeric`` cast raises on any non-numeric legacy value, taking down
    the reading stage instead of skipping the row. Anything unparseable is
    EXCLUDED — the fail-closed direction. Measured on the pre-migration corpus:
    0 of 1617 rows are NULL, empty, zero or non-numeric, so this excludes
    nothing today and exists so a future writer cannot make row existence mean
    "holds this asset" again.
    """
    try:
        return int(str(raw_balance)) > 0
    except (TypeError, ValueError):
        return False


__all__ = [
    "PINNED_FINALITY_MARGIN",
    "ObservationSubject",
    "balance_history_depth",
    "contracts_missing_current_rows",
    "winning_asset_fetches",
    "winning_entity_asset_fetches",
    "native_balance_fact",
    "native_status_for",
    "pinned_native_balances",
    "positive_raw_balance",
    "prune_balance_fetches",
]
