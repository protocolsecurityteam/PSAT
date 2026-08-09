"""The disposition scan: how each unpriced holding ARRIVED, measured on chain.

A THIRD CYCLE PHASE, and its position is load-bearing. The producers already run
read-page → escalate-sweep → write; this phase sits between the escalation and
the write, so it is a reader like the first two and never a second writer of the
balance row. It is deliberately NOT inside ``record_observation``, which is the
one write point: a measurement issued from inside a writer would make the row's
existence and the row's evidence the same event.

WHAT IS MEASURED. For a (chain, holder, token) pair: every ``Transfer`` that
named the holder as recipient inside a stated block range, and for each such
delivering transaction, how many same-token ``Transfer`` LOGS its receipt
carried (the fan-out). The verdict over that set is the all-quantifier in
:func:`services.monitoring.delivery_evidence.verdict_for`, evaluated there and
nowhere else.

THE FAN-OUT METER IS LOGS, NOT DISTINCT RECIPIENTS, and every sentence this
module publishes says so. A log count is an UPPER BOUND on the recipients a
transaction paid — one recipient paid twice in a single transaction contributes
two logs — and K
(:data:`services.monitoring.delivery_evidence.FAN_OUT_THRESHOLD_K`) is
calibrated on the log meter, so re-metering to distinct recipients would
invalidate the calibration rather than sharpen it.

WHAT IS NOT MEASURED, and is therefore never published. A fan-out is a fact
about a transaction, not about a token's worth: a real token can be delivered by
mass distribution, and this corpus contains such tokens. Nothing here names a
token good or bad, and no consumer may rename delivery shape into a judgement
about value.

THE THREE PLACES THIS FAILS CLOSED.

* a window that cannot be proven whole aborts every pair it covered — no
  evidence row at all. A short log page would otherwise become a delivery set
  the all-quantifier ranged over, and a missing delivery is exactly the one that
  would have refuted the positive.
* a delivery whose fan-out could not be METERED (an unreadable receipt, a
  4-topic ERC-721 ``Transfer`` whose third topic is an id rather than a
  quantity, an ERC-1155 delivery the receipt meter is not calibrated for) is
  recorded as an unreadable delivery, never skipped. Skipping it would shrink
  the set the quantifier ranges over; recording it makes the pair
  ``not_determined``, which is the honest answer.
* a holder the request budget did not reach writes nothing. A partial delivery
  set is not a smaller measurement, it is a different claim.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func as _sql_func
from sqlalchemy import or_
from sqlalchemy.orm import Session

from services.monitoring import asset_sweep
from services.monitoring.asset_sweep import (
    TRANSFER_BATCH_TOPIC0,
    TRANSFER_SINGLE_TOPIC0,
    TRANSFER_TOPIC0,
    SweepCost,
    SweepOutcome,
    _addr_from_topic,
    _pad32,
)
from services.monitoring.chain_rpc import chain_id_for
from services.monitoring.delivery_evidence import (
    DELIVERY_ENTRIES_RETAINED,
    FAN_OUT_THRESHOLD_K,
    load_delivery_evidence,
    record_delivery_evidence,
)
from services.resolution.repos.event_logs_rpc import FetchedEventLog, RpcEventLogFetcher
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    DELIVERY_FAN_OUT_BASIS_RECEIPT,
    DELIVERY_FAN_OUT_BASIS_UNREADABLE,
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_IN_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
)
from utils.rpc import get_transaction_receipt

logger = logging.getLogger(__name__)


# Requests one producer cycle's disposition scan may spend, across every chain
# and holder. SEPARATE from ``SWEEP_REQUEST_BUDGET`` on purpose: the sweep earns
# the proven-empty negative, this phase earns a delivery-shape claim, and one
# sharing the other's ceiling would let a wide disposition run starve the sweep
# of the requests its own negative depends on.
DISPOSITION_REQUEST_BUDGET = int(os.getenv("PSAT_DISPOSITION_REQUEST_BUDGET", "5000"))

# Tokens per ``eth_getLogs`` address filter, and holders per recipient-topic
# OR-set. Both are OR-sets inside ONE request, so a batch costs the windows of a
# single pair rather than the windows of every pair in it.
DISPOSITION_TOKEN_BATCH = 40
DISPOSITION_HOLDER_BATCH = 40

# Client-side ceiling for this phase's reads. The module default
# (``JSON_RPC_TIMEOUT_SECONDS``, 10 s) is sized for per-address calls; a
# genesis-to-head window over 40 token addresses is measured at ~13 s of honest
# service time on ethereum, and at the module default it returns as a timeout —
# which the fetcher's bisect path reads as an upstream reject. A scan that was
# only slow must never read as a scan that found nothing.
DISPOSITION_SCAN_TIMEOUT_SECONDS = 60

# Explicit, never ``PSAT_GETLOGS_RESULT_CAP``: that env is the durable indexer's
# builder default and setting it in-process would change the indexer. An
# explicit cap is what turns a page that REACHES it into a reject the fetcher
# bisects; with no cap the truncation branch cannot fire at all and a page cut
# short by an upstream limit reads as "few deliveries", which is precisely the
# direction that would mint a false positive.
DISPOSITION_RESULT_CAP = 40_000

# How many deliveries of ONE (holder, token) pair this phase will meter before
# it abandons the pair. A cost control, not a predicate — and it fails closed:
# an abandoned pair is recorded ``not_determined``, so it can never be disposed.
#
# Calibrated on the same corpus as K, on the delivery-COUNT axis. Mass
# distributions arrive in one or two transactions (21 pairs: sixteen 1-tx, five
# 2-tx, mean 1.238), while an accumulated real position arrives in as many as it
# was accumulated over — the corpus measured 1, 1, 1, 1, 1, 1, 1, 2, 3, 5, 7, 26,
# 29, 69, 282 and 6,110 transactions. 8 sits 4x above the largest observed
# airdrop delivery count and below every heavy real position, so the pairs it
# abandons are the ones a receipt-per-delivery pass cannot afford, and abandoning
# them CORRELATES with the token being real.
#
# Measured cost of not having it: the first live one-shot spent 4,663 receipts on
# ethereum alone and exhausted a 5,000-request budget before base or optimism was
# reached, because it read every delivery of every heavily-accumulated real
# position. This is the abort SHEET_OBSERVATION_SPEC.md §10.3 requires ("a token
# too heavy to scan ABORTS ... fail-closed in the right direction").
#
# What an abandoned pair STORES is a compact marker — a sample of
# ``DELIVERY_ENTRIES_RETAINED`` entries plus the count of the rest, every one of
# them declared unmetered — never one entry per delivery. The record still says
# how many deliveries were seen and that none was metered, which is what holds
# the verdict at not_determined; what it no longer does is put 518,723 entries
# and 40 MB of JSONB into one row, as measured on the reference corpus.
DISPOSITION_MAX_DELIVERIES_PER_PAIR = 8

# Per-chain (max_block_range, min_bisect_span).
#
# Optimism's upstream hard-caps the range: ``eth_getLogs`` there answers
# ``-32012 request exceeded max allowed range: ... up to a 10,000 block range``,
# so 10,000 is not a tuning choice, it is the largest window that gets served.
# Everywhere else the window is sized so a creation-block-to-head range is ONE
# request — measured on ethereum and base, where a single window returned the
# whole history of a 40-token batch. Paging those chains into smaller windows
# would multiply the request count by ~26 (ethereum) and ~50 (base) for
# identical data.
_DEFAULT_SCAN_WINDOW = (1_000_000_000, 10_000)
_CHAIN_SCAN_WINDOW: dict[int, tuple[int, int]] = {
    # optimism: upstream range cap, with one level of bisect headroom below it
    # so a dense window can still be narrowed rather than abandoned outright.
    10: (10_000, 1_000),
}

# ERC-20/721 index ``(from, to)`` so the recipient is topic 2; ERC-1155 indexes
# ``(operator, from, to)`` so it is topic 3. Two passes for that reason, exactly
# as the asset sweep runs two.
_RECIPIENT_TOPIC_ERC20 = 2
_RECIPIENT_TOPIC_ERC1155 = 3

_ERC1155_TOPIC0S = (TRANSFER_SINGLE_TOPIC0, TRANSFER_BATCH_TOPIC0)

# Creation blocks are immutable, so this is a once-per-process memo over a
# once-ever Postgres-cached Etherscan answer.
_CREATION_BLOCK_CACHE: dict[tuple[int, str], int | None] = {}
_CREATION_BLOCK_LOCK = threading.Lock()


@dataclass
class DispositionCost:
    """Real request counts, so the phase's cost can be checked rather than quoted."""

    get_logs: int = 0
    receipts: int = 0
    head_reads: int = 0
    creation_lookups: int = 0

    @property
    def total(self) -> int:
        return self.get_logs + self.receipts + self.head_reads + self.creation_lookups


@dataclass(frozen=True)
class DispositionRequest:
    """One holder account and the tokens on it whose delivery shape is wanted.

    ``holder_address`` is the ACCOUNT the balance was read at, never a folded
    entity key: delivery evidence is stored per account, and an entity that sums
    two accounts must satisfy the predicate at each.

    ``typed_tokens`` is the subset that a typed (ERC-721/1155) receipt was seen
    for. It selects the second recipient-topic pass; it never narrows the first.
    """

    contract_id: int
    chain_id: int
    holder_address: str
    tokens: tuple[str, ...]
    typed_tokens: tuple[str, ...] = ()


class DispositionBudgetExceeded(RuntimeError):
    """The cycle's request ceiling was reached mid-scan.

    A ``RuntimeError`` subclass so the fetcher's bisect-on-reject path treats it
    like any other refusal — except that bisecting spends MORE requests, so the
    check fires again at once on the narrower span and the scan unwinds rather
    than grinding to the floor.
    """


@dataclass(frozen=True)
class _Pair:
    """One (holder, token) measurement, with the window it is measured over."""

    holder: str
    token: str
    from_block: int
    typed: bool


@dataclass
class _Measured:
    """A pair's raw deliveries before the fan-out meter has run over them.

    ``aborted`` is set when a window covering the pair could not be proven
    whole. It is not the same as "no deliveries": one publishes nothing, the
    other publishes ``not_determined``.
    """

    scanned_from_block: int
    deliveries: dict[tuple[str, int | None], dict[str, Any]] = field(default_factory=dict)
    aborted: bool = False


class _DispositionFetcher(RpcEventLogFetcher):
    """This phase's OWN fetcher: explicit cap, own timeout, counted and budgeted.

    Deliberately not the sweep's ``_CountingFetcher`` — that one is metered
    against ``SWEEP_REQUEST_BUDGET``, and borrowing it would spend the sweep's
    ceiling on this phase's windows.
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        chain_id: int,
        cost: DispositionCost,
        budget: int,
        max_block_range: int,
        min_bisect_span: int,
    ) -> None:
        super().__init__(
            rpc_url,
            chain_id=chain_id,
            result_cap=DISPOSITION_RESULT_CAP,
            max_block_range=max_block_range,
            min_bisect_span=min_bisect_span,
            timeout=DISPOSITION_SCAN_TIMEOUT_SECONDS,
        )
        self._cost = cost
        self._budget = budget

    def _fetch_range(self, event_address, topics, from_block, to_block, window_stats=None):  # type: ignore[no-untyped-def]
        if self._cost.total >= self._budget:
            raise DispositionBudgetExceeded(f"disposition request budget of {self._budget} reached")
        self._cost.get_logs += 1
        return super()._fetch_range(event_address, topics, from_block, to_block, window_stats)


def creation_block(holder_address: str, *, chain_id: int, cost: DispositionCost) -> int:
    """The block *holder_address* was deployed in, or 0 when that is unknown.

    Seeding the scan here rather than at genesis is the single largest cost
    factor on a range-capped chain: on optimism, where the upstream serves at
    most 10,000 blocks per request, a genesis-to-head token batch is ~15,500
    requests and a creation-seeded one is ~600.

    0 is the SAFE fallback, not a guess: an address can be sent a token before
    any code is deployed at it, so scanning from earlier than the deployment can
    only ever find more deliveries, and finding more is the direction that
    withdraws a positive rather than manufacturing one.
    """
    key = (int(chain_id), holder_address.lower())
    with _CREATION_BLOCK_LOCK:
        if key in _CREATION_BLOCK_CACHE:
            cached = _CREATION_BLOCK_CACHE[key]
            return 0 if cached is None else cached
    from utils.etherscan import get_contract_creation_block

    cost.creation_lookups += 1
    try:
        block = get_contract_creation_block(holder_address, chain_id=chain_id)
    except Exception as exc:
        logger.info("disposition: creation block lookup failed for %s on chain %s: %s", holder_address, chain_id, exc)
        block = None
    with _CREATION_BLOCK_LOCK:
        _CREATION_BLOCK_CACHE[key] = block
    return 0 if block is None else max(0, int(block))


def clear_creation_block_cache() -> None:
    """Drop the per-process creation-block memo (tests)."""
    with _CREATION_BLOCK_LOCK:
        _CREATION_BLOCK_CACHE.clear()


def is_unpriced(usd_value: Any, raw_balance: Any) -> bool:
    """Whether a holding reading carries no USD figure that stands up.

    ``None`` is the plain not-priced state. A stored 0 alongside a non-zero
    quantity is the same state wearing a number: the writers store 0 where no
    quote resolved, and a zero dollar figure over a non-zero balance is an
    absent price rather than a holding worth nothing.
    """
    if usd_value is None:
        return True
    try:
        priced = float(usd_value)
    except (TypeError, ValueError):
        return True
    if priced != 0.0:
        return False
    try:
        return int(raw_balance or 0) != 0
    except (TypeError, ValueError):
        return True


def disposition_requests(
    session: Session,
    *,
    protocol_id: int,
    contract_ids: set[int] | None = None,
    discovered: Sequence[DispositionRequest] = (),
) -> list[DispositionRequest]:
    """The UNIFORM population, grouped by the ACCOUNT each reading was read at.

    Uniform means every unpriced token reading the protocol currently publishes,
    including the unpriced readings that sit on an otherwise priced sheet —
    those are the most visible ones, and a population narrowed to wholly
    unpriced sheets would leave them annotated by nothing. "Unpriced" is
    :func:`is_unpriced`, which is the one definition of the predicate.

    GROUPED ON ``observed_address``, not on the contract, and the grouping is
    load-bearing in both directions. Readings are facts about the account they
    were read at: 162 of the token rows currently published were read at an
    address other than their contract's own, so a population keyed on
    ``contracts.address`` would scan an account that holds none of them and file
    the evidence where nothing looks for it. In the other direction, a proxy and
    its implementation whose rows share one observed account collapse into a
    single holder here — one scan instead of two, over the account that actually
    received the deliveries.

    ``contract_ids`` narrows the pass to a named subset (the resolution worker's
    single contract); ``None`` is the whole protocol, which is what the hourly
    producer wants. Narrowing by contract still groups by observed account, so a
    scoped request can name an account another contract also reads — which is
    correct: the evidence is the account's, not the contract's.

    ``discovered`` folds in requests built from the CURRENT cycle's page and
    sweep, whose rows are not in the view yet because this phase runs before the
    write. Omitting it costs a newly discovered token one cycle of latency and
    nothing else; the stored evidence accretes either way.

    A contract whose current asset list is ``at_page_cap`` contributes nothing:
    the list is then a prefix of unknown length, so "these are the account's
    unpriced tokens" is a claim the read cannot support, and a population built
    on it would be one too.
    """
    from db.models import Contract, ContractBalanceLatest

    tokens: dict[tuple[int, str], set[str]] = {}
    typed: dict[tuple[int, str], set[str]] = {}
    contract_for: dict[tuple[int, str], int] = {}

    for request in discovered:
        key = (int(request.chain_id), request.holder_address.lower())
        tokens.setdefault(key, set()).update(t.lower() for t in request.tokens)
        typed.setdefault(key, set()).update(t.lower() for t in request.typed_tokens)
        contract_for[key] = min(contract_for.get(key, request.contract_id), request.contract_id)

    capped = _at_page_cap_contract_ids(session, protocol_id=protocol_id, contract_ids=contract_ids)

    query = (
        session.query(
            ContractBalanceLatest.contract_id,
            ContractBalanceLatest.token_address,
            ContractBalanceLatest.observed_address,
            ContractBalanceLatest.usd_value,
            ContractBalanceLatest.raw_balance,
            ContractBalanceLatest.decimals,
            ContractBalanceLatest.source,
            Contract.chain,
        )
        .join(Contract, Contract.id == ContractBalanceLatest.contract_id)
        .filter(
            Contract.protocol_id == protocol_id,
            ContractBalanceLatest.token_address.isnot(None),
            or_(ContractBalanceLatest.usd_value.is_(None), ContractBalanceLatest.usd_value == 0),
        )
    )
    if contract_ids is not None:
        query = query.filter(ContractBalanceLatest.contract_id.in_(contract_ids))

    for contract_id, token_address, observed_address, usd_value, raw_balance, decimals, source, chain in query.all():
        if contract_id in capped:
            continue
        token = (token_address or "").lower()
        if not token or not is_unpriced(usd_value, raw_balance):
            continue
        # A NULL ``observed_address`` is a legacy row whose account was never
        # recorded and cannot be recovered. It is left out rather than assigned
        # to its contract's address: evidence filed under an account the reading
        # may not have come from would answer for a holding it never observed.
        account = (observed_address or "").lower()
        if not account:
            continue
        key = (chain_id_for(chain), account)
        tokens.setdefault(key, set()).add(token)
        contract_for[key] = min(contract_for.get(key, int(contract_id)), int(contract_id))
        # A typed (ERC-721/1155) holding is the one the sweep writes at 0
        # decimals, because its quantity is a COUNT of items. That is what
        # selects the ERC-1155 recipient pass; a token wrongly in the set costs
        # a request and finds nothing, while one wrongly out of it would leave
        # 1155 receipts unmeasured, so the inclusive reading is the safe one.
        if int(decimals or 0) == 0 and source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP:
            typed.setdefault(key, set()).add(token)

    return [
        DispositionRequest(
            contract_id=contract_for.get(key, 0),
            chain_id=key[0],
            holder_address=key[1],
            tokens=tuple(sorted(account_tokens)),
            typed_tokens=tuple(sorted(typed.get(key, set()))),
        )
        for key, account_tokens in sorted(tokens.items())
        if account_tokens
    ]


def _at_page_cap_contract_ids(session: Session, *, protocol_id: int, contract_ids: set[int] | None) -> set[int]:
    """Contracts whose CURRENT ERC-20 asset list is a prefix of unknown length.

    D1 parity: ``at_page_cap`` is the one completeness state that refuses a
    holder outright. Every other state is scoped in the basis string instead,
    because a strict proven-complete gate would have no carriers at all —
    ``returned_assets`` is not_determined by design.
    """
    from db.models import Contract, ContractBalanceFetch, ContractBalanceLatest

    winning = (
        session.query(ContractBalanceLatest.fetch_id)
        .join(Contract, Contract.id == ContractBalanceLatest.contract_id)
        .filter(Contract.protocol_id == protocol_id, ContractBalanceLatest.token_address.isnot(None))
    )
    if contract_ids is not None:
        winning = winning.filter(ContractBalanceLatest.contract_id.in_(contract_ids))
    fetch_ids = {row[0] for row in winning.all() if row[0] is not None}
    if not fetch_ids:
        return set()
    rows = (
        session.query(ContractBalanceFetch.contract_id)
        .filter(
            ContractBalanceFetch.id.in_(fetch_ids),
            ContractBalanceFetch.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP,
        )
        .all()
    )
    return {int(row[0]) for row in rows}


def discovered_request(
    *,
    contract_id: int,
    chain_id: int,
    holder_address: str,
    page: Any,
    sweep: SweepOutcome | None,
) -> DispositionRequest | None:
    """This cycle's page + sweep readings for one account, or ``None``.

    The rows behind these readings are written AFTER this phase runs, so they
    are not in ``contract_balances_latest`` yet. Both are observed at
    ``holder_address`` — the one ``observed_address`` policy in
    ``record_observation`` — so they belong to that account and no other.

    ``None`` when the page is ``at_page_cap``: the same D1-parity refusal
    :func:`disposition_requests` applies to the stored rows.
    """
    if page is not None and getattr(page, "status", None) == ASSET_SET_STATUS_AT_PAGE_CAP:
        return None
    account = holder_address.lower()
    tokens: set[str] = set()
    typed: set[str] = set()
    for row in getattr(page, "rows", None) or []:
        token = (row.get("token_address") or "").lower()
        if token and is_unpriced(row.get("usd_value"), row.get("balance")):
            tokens.add(token)
    if sweep is not None and sweep.status == asset_sweep.SWEEP_COMPLETED:
        # Every sweep-discovered holding is published unpriced by construction —
        # no price source reaches a log-derived asset — so the whole set is in
        # the population, with the zero-quantity discoveries left out: they are
        # not holdings and carry no sheet reading to annotate.
        for asset in sweep.assets:
            if asset.raw_balance is not None and asset.raw_balance > 0:
                tokens.add(asset.token_address.lower())
        for asset in sweep.typed_assets:
            if asset.raw_balance is not None and asset.raw_balance > 0:
                tokens.add(asset.token_address.lower())
                typed.add(asset.token_address.lower())
    if not tokens:
        return None
    return DispositionRequest(
        contract_id=contract_id,
        chain_id=int(chain_id),
        holder_address=account,
        tokens=tuple(sorted(tokens)),
        typed_tokens=tuple(sorted(typed)),
    )


def scan_delivery_shape(
    session: Session,
    requests: Sequence[DispositionRequest],
    *,
    rpc_url_for: Callable[[int], str | None],
    cost: DispositionCost | None = None,
) -> DispositionCost:
    """Measure delivery shape for every requested pair and record what was read.

    Writes evidence through :func:`record_delivery_evidence` and NEVER commits —
    the producer owns the transaction, so the evidence and the balance row it was
    measured beside land or roll back together.

    A pair with stored evidence is scanned FORWARD from its cursor only, which
    is what makes the full-history pass a once-per-pair cost and every later
    cycle a steady-state one.
    """
    cost = cost or DispositionCost()
    if not requests:
        return cost

    by_chain: dict[int, list[DispositionRequest]] = {}
    for request in requests:
        if not request.holder_address or not request.tokens:
            continue
        by_chain.setdefault(int(request.chain_id), []).append(request)
    if not by_chain:
        return cost

    stored = load_delivery_evidence(
        session,
        [(int(r.chain_id), r.holder_address) for group in by_chain.values() for r in group],
    )

    for chain_id in sorted(by_chain):
        chain_requests = by_chain[chain_id]
        rpc_url = rpc_url_for(chain_id)
        if not rpc_url:
            logger.info("disposition: no RPC URL for chain %s; %d holder(s) not scanned", chain_id, len(chain_requests))
            continue
        head_cost = SweepCost()
        head = asset_sweep.sweep_head_block(rpc_url, chain_id=chain_id, cost=head_cost)
        cost.head_reads += head_cost.head_reads
        if head is None:
            logger.info(
                "disposition: head unknown on chain %s; %d holder(s) not scanned", chain_id, len(chain_requests)
            )
            continue
        try:
            _scan_chain(
                session,
                chain_id=chain_id,
                rpc_url=rpc_url,
                head=head,
                requests=chain_requests,
                stored=stored,
                cost=cost,
            )
        except DispositionBudgetExceeded as exc:
            logger.warning(
                "disposition: request budget exhausted on chain %s (%s) — remaining holders were NOT scanned and "
                "wrote NO evidence; cost so far %d getLogs + %d receipts + %d head + %d creation",
                chain_id,
                exc,
                cost.get_logs,
                cost.receipts,
                cost.head_reads,
                cost.creation_lookups,
            )
            break
    return cost


def record_protocol_reference(session: Session, *, protocol_id: int, requests: Sequence[DispositionRequest]) -> int:
    """Store, per token in the population, whether THIS protocol's discovery names it.

    The producer's half of the reference verdict, and the reason it is a producer's
    job at all: the universe comes from
    :func:`services.scoring.distill.load_protocol_universe`, a measured
    26.5-second object-storage assembly that no API path may perform. It is built
    ONCE per cycle here and the answer is written per token, so a presentation
    surface reads a stored verdict instead of re-deriving one it cannot afford.

    ``None`` from the universe loader is FAIL-CLOSED and it is honoured as such:
    every token lands ``not_determined``, never ``absent_from_universe``. A
    universe that could not be built whole is a SHORT universe, and the predicate
    it feeds condemns what is absent — so a short one condemns MORE. Nothing
    downstream may dispose a pair on the strength of an absence from a universe
    nobody assembled.

    Rows are REFRESHED, not accreted (see ``db.models.TokenProtocolReference``):
    the predicate is anti-monotone, so a verdict must be able to withdraw when
    discovery grows.

    Returns the number of tokens written.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from db.models import TokenProtocolReference

    pairs = sorted({(int(request.chain_id), token.lower()) for request in requests for token in request.tokens})
    if not pairs:
        return 0

    from services.scoring.distill import load_protocol_universe

    try:
        universe = load_protocol_universe(session, protocol_id)
    except Exception as exc:
        # Same reading as the loader's own ``None``: an assembly that raised is
        # an assembly that did not happen.
        logger.warning("disposition: protocol universe for %s could not be assembled: %s", protocol_id, exc)
        universe = None

    if universe is None:
        addresses: frozenset[str] = frozenset()
        universe_size = 0
        basis = (
            "protocol reference not determined: the protocol universe could not be assembled whole "
            "(services.scoring.distill.load_protocol_universe returned no universe), and an absence "
            "measured against a short universe condemns more rather than less"
        )
    else:
        addresses = universe.addresses
        universe_size = len(addresses)
        basis = (
            f"protocol reference measured against {universe_size} discovered address(es), chain-blind; {universe.basis}"
        )

    now = _sql_func.now()
    rows = [
        {
            "protocol_id": int(protocol_id),
            "chain_id": chain_id,
            "token_address": token,
            "reference_shape": (
                TOKEN_REFERENCE_NOT_DETERMINED
                if universe is None
                else (TOKEN_REFERENCE_IN_UNIVERSE if token in addresses else TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE)
            ),
            "universe_addresses": universe_size,
            "basis": basis,
            "measured_at": now,
        }
        for chain_id, token in pairs
    ]
    for start in range(0, len(rows), 500):
        chunk = rows[start : start + 500]
        statement = pg_insert(TokenProtocolReference).values(chunk)
        session.execute(
            statement.on_conflict_do_update(
                index_elements=[
                    TokenProtocolReference.protocol_id,
                    TokenProtocolReference.chain_id,
                    TokenProtocolReference.token_address,
                ],
                set_={
                    "reference_shape": statement.excluded.reference_shape,
                    "universe_addresses": statement.excluded.universe_addresses,
                    "basis": statement.excluded.basis,
                    "measured_at": statement.excluded.measured_at,
                },
            )
        )
    return len(rows)


def run_disposition(
    session: Session,
    requests: Sequence[DispositionRequest],
    *,
    rpc_url_for: Callable[[int], str | None],
    protocol_id: int | None = None,
) -> DispositionCost:
    """The phase as a PRODUCER calls it: it can never fail the cycle.

    The balance write is the producer's job and this phase is an annotation
    beside it, so anything raised here is logged and swallowed. The evidence
    table is additive — the absence of a row means only that delivery shape is
    not determined for that pair, which is exactly what a scan that did not run
    established.

    ``protocol_id`` enables the reference pass
    (:func:`record_protocol_reference`). It is optional so a caller with no
    protocol in hand still gets the delivery scan; omitting it writes no
    reference row, which every consumer reads as ``not_determined``.
    """
    cost = DispositionCost()
    if not requests:
        return cost
    if protocol_id is not None:
        try:
            written = record_protocol_reference(session, protocol_id=protocol_id, requests=requests)
        except Exception as exc:
            logger.warning(
                "disposition: protocol reference pass failed for protocol %s; every token stays not_determined: %s",
                protocol_id,
                exc,
            )
        else:
            logger.info("disposition: protocol reference recorded for %d token(s)", written)
    try:
        scan_delivery_shape(session, requests, rpc_url_for=rpc_url_for, cost=cost)
    except Exception as exc:
        logger.warning(
            "disposition scan failed after %d getLogs + %d receipts + %d head + %d creation lookup(s); "
            "balances are unaffected and the pairs stay not_determined: %s",
            cost.get_logs,
            cost.receipts,
            cost.head_reads,
            cost.creation_lookups,
            exc,
        )
        return cost
    logger.info(
        "disposition scan: %d holder account(s), %d getLogs + %d receipts + %d head + %d creation lookup(s)",
        len(requests),
        cost.get_logs,
        cost.receipts,
        cost.head_reads,
        cost.creation_lookups,
    )
    return cost


def disposition_cost_note(cost: DispositionCost) -> str:
    """The phase's real request counts, phrased for a fetch record's basis."""
    return (
        f"disposition scan cost {cost.get_logs} getLogs + {cost.receipts} receipts + "
        f"{cost.head_reads} head + {cost.creation_lookups} creation lookup(s)"
    )


def _scan_chain(
    session: Session,
    *,
    chain_id: int,
    rpc_url: str,
    head: int,
    requests: Sequence[DispositionRequest],
    stored: Mapping[tuple[int, str, str], Any],
    cost: DispositionCost,
) -> None:
    fresh: list[_Pair] = []
    forward: list[_Pair] = []
    # Pairs whose cursor already covers everything there is to read. They are
    # scanned by nothing and cost no request, and they are still PRESENTED to the
    # writer: the basis is re-derived from the row's own extent columns on every
    # pass, so a row is repaired by an ordinary cycle rather than by hand.
    carried: list[_Pair] = []
    for request in requests:
        typed_set = {t.lower() for t in request.typed_tokens}
        for token in {t.lower() for t in request.tokens}:
            fact = stored.get((chain_id, request.holder_address, token))
            if fact is None:
                fresh.append(
                    _Pair(
                        holder=request.holder_address,
                        token=token,
                        from_block=creation_block(request.holder_address, chain_id=chain_id, cost=cost),
                        typed=token in typed_set,
                    )
                )
                continue
            resume = int(fact.measured_through_block) + 1
            pair = _Pair(holder=request.holder_address, token=token, from_block=resume, typed=token in typed_set)
            if resume > head:
                carried.append(pair)
                continue
            forward.append(pair)

    max_block_range, min_bisect_span = _CHAIN_SCAN_WINDOW.get(chain_id, _DEFAULT_SCAN_WINDOW)
    fetcher = _DispositionFetcher(
        rpc_url,
        chain_id=chain_id,
        cost=cost,
        budget=DISPOSITION_REQUEST_BUDGET,
        max_block_range=max_block_range,
        min_bisect_span=min_bisect_span,
    )

    measured: dict[tuple[str, str], _Measured] = {}
    for group in (fresh, forward):
        if group:
            _discover(fetcher, group, chain_id=chain_id, head=head, measured=measured)
    for pair in carried:
        fact = stored.get((chain_id, pair.holder, pair.token))
        measured.setdefault(
            (pair.holder, pair.token),
            _Measured(scanned_from_block=int(fact.scanned_from_block) if fact is not None else pair.from_block),
        )

    _resolve_fan_out(
        session,
        chain_id=chain_id,
        rpc_url=rpc_url,
        head=head,
        measured=measured,
        stored=stored,
        max_block_range=max_block_range,
        cost=cost,
    )


def _discover(
    fetcher: RpcEventLogFetcher,
    pairs: Sequence[_Pair],
    *,
    chain_id: int,
    head: int,
    measured: dict[tuple[str, str], _Measured],
) -> None:
    """Fill *measured* with every delivery the requested pairs received.

    The window start is the EARLIEST start any pair in the batch needs. Starting
    a pair earlier than it asked for is safe in one direction only, and it is
    this one: it can only add deliveries, and an added delivery can only
    withdraw a positive verdict.
    """
    wanted = {(p.holder, p.token) for p in pairs}
    from_block = min(p.from_block for p in pairs)
    for pair in pairs:
        measured.setdefault((pair.holder, pair.token), _Measured(scanned_from_block=from_block))

    holders = sorted({p.holder for p in pairs})
    tokens = sorted({p.token for p in pairs})
    typed_tokens = sorted({p.token for p in pairs if p.typed})

    for holder_batch in _chunks(holders, DISPOSITION_HOLDER_BATCH):
        padded = [_pad32(h) for h in holder_batch]
        for token_batch in _chunks(tokens, DISPOSITION_TOKEN_BATCH):
            _run_pass(
                fetcher,
                event_address=token_batch,
                topics=[[TRANSFER_TOPIC0], None, padded],
                recipient_topic=_RECIPIENT_TOPIC_ERC20,
                from_block=from_block,
                to_block=head,
                wanted=wanted,
                holder_batch=holder_batch,
                token_batch=token_batch,
                measured=measured,
                chain_id=chain_id,
            )
        # ERC-1155's recipient sits in topic 3, so it needs its own pass or the
        # scan sees 1155 sends and misses 1155 RECEIPTS. Inert on today's
        # population (no typed receipt in it), and implemented anyway so a
        # future one is measured rather than silently unmeasured.
        for token_batch in _chunks(typed_tokens, DISPOSITION_TOKEN_BATCH):
            _run_pass(
                fetcher,
                event_address=token_batch,
                topics=[list(_ERC1155_TOPIC0S), None, None, padded],
                recipient_topic=_RECIPIENT_TOPIC_ERC1155,
                from_block=from_block,
                to_block=head,
                wanted=wanted,
                holder_batch=holder_batch,
                token_batch=token_batch,
                measured=measured,
                chain_id=chain_id,
            )


def _run_pass(
    fetcher: RpcEventLogFetcher,
    *,
    event_address: list[str],
    topics: list[Any],
    recipient_topic: int,
    from_block: int,
    to_block: int,
    wanted: set[tuple[str, str]],
    holder_batch: Sequence[str],
    token_batch: Sequence[str],
    measured: dict[tuple[str, str], _Measured],
    chain_id: int,
) -> None:
    if not event_address:
        return
    try:
        logs = fetcher.fetch_logs(
            event_address=list(event_address), topics=topics, from_block=from_block, to_block=to_block
        )
    except DispositionBudgetExceeded:
        raise
    except RuntimeError as exc:
        # The fetcher bisects on reject and on a page that reaches the cap;
        # reaching here means it hit the bisect floor and could not prove the
        # window whole. Every pair the window covered is aborted, because the
        # logs that DID come back cannot be given a completeness they lack.
        logger.info(
            "disposition: window %d-%d on chain %s could not be proven whole; %d holder(s) x %d token(s) aborted: %s",
            from_block,
            to_block,
            chain_id,
            len(holder_batch),
            len(token_batch),
            exc,
        )
        for holder in holder_batch:
            for token in token_batch:
                entry = measured.get((holder, token))
                if entry is not None:
                    entry.aborted = True
        return
    for log in logs:
        _attribute(log, recipient_topic=recipient_topic, wanted=wanted, measured=measured)


def _attribute(
    log: FetchedEventLog,
    *,
    recipient_topic: int,
    wanted: set[tuple[str, str]],
    measured: dict[tuple[str, str], _Measured],
) -> None:
    if len(log.topics) <= recipient_topic:
        return
    holder = _addr_from_topic(log.topics[recipient_topic])
    token = (log.address or "").lower()
    key = (holder, token)
    if key not in wanted:
        return
    entry = measured.get(key)
    if entry is None:
        return
    topic0 = log.topics[0].lower()
    # ERC-20 and ERC-721 share this topic0 and are told apart by topic COUNT: a
    # 721 indexes the token id as a fourth topic. The fan-out meter counts
    # same-token 3-topic transfer LOGS, so a 4-topic delivery is outside what it
    # can measure and is carried as an unreadable delivery rather than dropped.
    meterable = topic0 == TRANSFER_TOPIC0 and len(log.topics) == 3
    entry.deliveries[("0x" + log.tx_hash.hex(), log.log_index)] = {
        "tx": "0x" + log.tx_hash.hex(),
        "block": int(log.block_number),
        "log_index": int(log.log_index),
        "meterable": meterable,
    }


def _resolve_fan_out(
    session: Session,
    *,
    chain_id: int,
    rpc_url: str,
    head: int,
    measured: Mapping[tuple[str, str], _Measured],
    stored: Mapping[tuple[int, str, str], Any],
    max_block_range: int,
    cost: DispositionCost,
) -> None:
    """Meter each delivery, then record the pairs that were measured END TO END.

    Receipts are cached by transaction hash across pairs: one distribution
    emitting 200 same-token transfer logs is read once, not once per recipient
    slot.

    A pair is recorded only when every one of its deliveries was ATTEMPTED. A
    delivery the budget never reached is not an unreadable delivery — the
    difference matters, because an unreadable one is stored evidence of a gap
    while an unreached one is no observation at all, and only the second may
    leave the pair unwritten so a later cycle repeats the whole scan.

    A pair carrying more than :data:`DISPOSITION_MAX_DELIVERIES_PER_PAIR`
    deliveries is ABANDONED before any receipt is read, and it is recorded as a
    COMPACT marker: a bounded sample of entries plus the count of the rest, all
    of them declared unmetered. That is the truth (none was metered) and it
    forces ``not_determined``. Recording rather than skipping is deliberate — it
    stores the fact that the pair was looked at and found too heavy to meter, so
    the next cycle does not re-derive it, and the pair can never be disposed.
    Materialising one entry per delivery instead put 518,723 of them and 40 MB of
    JSONB into a single row on the reference corpus, none of which said anything
    the count and the marker do not.

    Deliveries at or below a stored row's cursor are dropped before any of this:
    a previous pass proved that extent whole, so they are already in the row's
    tally, and re-metering them would spend receipts to double-count evidence.
    """
    receipts: dict[str, dict | None] = {}
    exhausted = False
    for (holder, token), entry in sorted(measured.items()):
        if entry.aborted:
            continue
        deliveries: list[dict[str, Any]] = []
        fact = stored.get((chain_id, holder, token))
        cursor = None if fact is None else int(fact.measured_through_block)
        ordered = [
            record
            for record in sorted(entry.deliveries.values(), key=lambda d: (d["block"], d["log_index"] or 0))
            if cursor is None or int(record["block"]) > cursor
        ]
        elided = 0
        too_heavy = len(ordered) > DISPOSITION_MAX_DELIVERIES_PER_PAIR
        if too_heavy:
            # The pair is abandoned. Keep a bounded sample so the row still shows
            # what an abandoned delivery looks like, and carry the rest as a
            # count — the row must still say how many were seen and that none was
            # metered, which is what keeps the verdict not_determined.
            keep = min(DELIVERY_ENTRIES_RETAINED, len(ordered))
            elided = len(ordered) - keep
            ordered = ordered[:keep]
        for record in ordered:
            if too_heavy:
                deliveries.append(_delivery_entry(record, fan_out=None, basis=DELIVERY_FAN_OUT_BASIS_UNREADABLE))
                continue
            if not record["meterable"]:
                deliveries.append(_delivery_entry(record, fan_out=None, basis=DELIVERY_FAN_OUT_BASIS_UNREADABLE))
                continue
            tx = record["tx"]
            if tx not in receipts:
                if cost.total >= DISPOSITION_REQUEST_BUDGET:
                    exhausted = True
                    break
                cost.receipts += 1
                receipts[tx] = get_transaction_receipt(
                    rpc_url, tx, chain_id=chain_id, timeout=DISPOSITION_SCAN_TIMEOUT_SECONDS
                )
            fan_out = _fan_out(receipts[tx], token=token)
            deliveries.append(
                _delivery_entry(
                    record,
                    fan_out=fan_out,
                    basis=DELIVERY_FAN_OUT_BASIS_UNREADABLE if fan_out is None else DELIVERY_FAN_OUT_BASIS_RECEIPT,
                )
            )
        if exhausted:
            break
        record_delivery_evidence(
            session,
            chain_id=chain_id,
            holder_address=holder,
            token_address=token,
            scanned_from_block=entry.scanned_from_block,
            measured_through_block=head,
            deliveries=deliveries,
            unmetered_elided=elided,
            scan_basis=_scan_basis(chain_id=chain_id, max_block_range=max_block_range),
        )
    if exhausted:
        raise DispositionBudgetExceeded(f"disposition request budget of {DISPOSITION_REQUEST_BUDGET} reached")


def _delivery_entry(record: Mapping[str, Any], *, fan_out: int | None, basis: str) -> dict[str, Any]:
    return {
        "tx": record["tx"],
        "block": int(record["block"]),
        "log_index": record["log_index"],
        "fan_out": fan_out,
        "fan_out_basis": basis,
    }


def _fan_out(receipt: dict | None, *, token: str) -> int | None:
    """Same-token 3-topic ``Transfer`` LOGS in one transaction's receipt, or ``None``.

    A count of LOGS. It is an upper bound on the distinct recipients the
    transaction paid — the same address paid twice contributes two logs — and it
    is deliberately not de-duplicated by recipient: K is calibrated on this
    meter, so a different meter would need a different K.

    ``None`` is returned for a receipt that could not be read or whose ``logs``
    are not a list. It is NOT zero: an unread receipt tells nothing about how
    many transfers the transaction emitted, and zero is a number the caller
    would compare against the threshold.
    """
    if not isinstance(receipt, dict):
        return None
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        return None
    wanted = token.lower()
    count = 0
    for log in logs:
        if not isinstance(log, dict):
            return None
        address = log.get("address")
        topics = log.get("topics")
        if not isinstance(address, str) or not isinstance(topics, list) or not topics:
            continue
        if address.lower() != wanted:
            continue
        if str(topics[0]).lower() == TRANSFER_TOPIC0 and len(topics) == 3:
            count += 1
    return count


def _scan_basis(*, chain_id: int, max_block_range: int) -> str:
    """The METHOD, and only the method: the filter, the windowing, the meter, K.

    Pass-invariant on purpose. It carries no block range — the extent belongs to
    the row and :func:`services.monitoring.delivery_evidence.compose_basis`
    reads it off the row's own columns — and it carries no request count: a cost
    is a fact about one pass while the stored basis is a fact about a claim built
    from many, so cost is logged through :func:`disposition_cost_note` and never
    accreted into the sentence.
    """
    return (
        f"delivery shape per Transfer scan (recipient topic {_RECIPIENT_TOPIC_ERC20} for ERC-20/721, topic "
        f"{_RECIPIENT_TOPIC_ERC1155} for ERC-1155) on chain {chain_id} "
        f"in windows of at most {max_block_range} block(s) at a {DISPOSITION_RESULT_CAP}-log result cap; "
        f"fan-out metered from each delivering transaction's own receipt as same-token 3-topic Transfer LOGS "
        f"(an upper bound on distinct recipients: one recipient paid twice in a transaction counts twice); "
        f"K={FAN_OUT_THRESHOLD_K}"
    )


def _chunks(values: Sequence[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(values), size):
        yield list(values[start : start + size])


__all__ = [
    "DISPOSITION_HOLDER_BATCH",
    "DISPOSITION_REQUEST_BUDGET",
    "DISPOSITION_RESULT_CAP",
    "DISPOSITION_SCAN_TIMEOUT_SECONDS",
    "DISPOSITION_TOKEN_BATCH",
    "DispositionBudgetExceeded",
    "DispositionCost",
    "DispositionRequest",
    "clear_creation_block_cache",
    "creation_block",
    "discovered_request",
    "disposition_cost_note",
    "disposition_requests",
    "is_unpriced",
    "record_protocol_reference",
    "run_disposition",
    "scan_delivery_shape",
]
