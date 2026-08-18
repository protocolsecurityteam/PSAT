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

A SLICE IS NOT A SHORTFALL, and it is the one bounded thing here that DOES
publish. On a range-capped chain a cycle reads a bounded number of windows and
records what it proved over them: the row's extent stops at the slice boundary
and ``caught_up`` says so. That is a whole claim over a smaller range rather than
a partial claim over a larger one — the row IS its extent — and the next cycle
resumes above the cursor. Without it the budget died mid-discovery every hour and
the chain wrote nothing at all, forever.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from sqlalchemy import func as _sql_func
from sqlalchemy import or_
from sqlalchemy.orm import Session

from services.monitoring import asset_sweep, warn_degraded_once
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
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_IN_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
    USD_CRUMB_THRESHOLD,
)
from utils.logging import log_timed_phase
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

# Windows one cycle will page through before it stops and RECORDS what it proved.
#
# Without it a range-capped chain never converges. Optimism serves 10,000 blocks
# per ``eth_getLogs``, so creation-to-head is thousands of pages: the measured
# run spent 4,974 requests there, hit the budget during DISCOVERY — before any
# row was written — and the next hourly cycle repeated it identically, forever.
# A cycle that stops at a slice boundary instead writes rows with
# ``measured_through_block = scan_to`` and ``caught_up = false``, and the next
# one resumes above that cursor. Bounded forward progress replaces an hourly
# no-op.
#
# 2000 windows is 20M blocks per cycle on optimism, which fits the request
# budget with room for the receipts that follow discovery. On a chain whose
# window is 1e9 blocks (ethereum, base) the slice covers every block there is,
# so those chains are untouched.
DISPOSITION_SLICE_WINDOWS = int(os.getenv("PSAT_DISPOSITION_SLICE_WINDOWS", "2000"))

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
    # What the cycle DID, beside what it spent. Whether the corpus is converging
    # is the question this phase exists to answer and a request count cannot:
    # a pass that skipped every pair because nothing moved and a pass that
    # scanned every pair and found nothing cost about the same. Deliberately
    # outside ``total`` — these are outcomes, not requests.
    counts: dict[str, int] = field(default_factory=dict)
    # Degraded external calls, by kind; also the warn-once-then-DEBUG cursor
    # (``warn_degraded_once``) for the failures that repeat per holder.
    degraded: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return self.get_logs + self.receipts + self.head_reads + self.creation_lookups

    def count(self, key: str, n: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + n


@dataclass(frozen=True)
class DispositionRequest:
    """One holder account and the tokens on it whose delivery shape is wanted.

    ``holder_address`` is the ACCOUNT the balance was read at, never a folded
    entity key: delivery evidence is stored per account, and an entity that sums
    two accounts must satisfy the predicate at each.

    ``typed_tokens`` is the subset that a typed (ERC-721/1155) receipt was seen
    for. It selects the second recipient-topic pass; it never narrows the first.

    ``balances`` carries the raw quantity each token was read at THIS cycle, as
    ``(token, raw)`` pairs. It is the scan's skip key and never its evidence: a
    quantity equal to the one the pair was last stamped at is what lets the cycle
    leave the extent alone, because a new delivery necessarily moves it. A token
    absent from the map is a token this cycle read no quantity for, and it is
    scanned rather than skipped.

    ``priced_dust_tokens`` are the tokens carrying a real price BELOW the crumb
    threshold. They order the catch-up queue and nothing else — a priced crumb is
    a holding somebody quoted, so it is more likely to be a token the protocol
    means to hold than one no price source has ever named.
    """

    contract_id: int
    chain_id: int
    holder_address: str
    tokens: tuple[str, ...]
    typed_tokens: tuple[str, ...] = ()
    balances: tuple[tuple[str, str], ...] = ()
    priced_dust_tokens: tuple[str, ...] = ()


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

    ``measured_through`` is the extent this pass may claim for the pair, and it
    is per pair rather than per chain: a scanned pair claims the slice that was
    read, a CARRIED one claims exactly what it already claimed. Advancing a
    carried pair's cursor to the head would widen a published all-quantifier over
    blocks this cycle never read.

    ``caught_up`` is ``None`` for a carried pair — no scan happened, so the
    stored answer stands.
    """

    scanned_from_block: int
    measured_through: int
    caught_up: bool | None = None
    observed_balance_raw: str | None = None
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

    def _fetch_range(self, event_address, topics, from_block, to_block, window_stats=None):
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
        # Degrades the scan to genesis, which on a range-capped chain is ~25x
        # the request cost — so the miss is a WARNING, once per cycle, and the
        # per-holder repeats ride the count.
        warn_degraded_once(
            logger,
            cost.degraded,
            "creation_block_unknown",
            "disposition: creation block lookup failed; the holder is scanned from genesis instead",
            scope=chain_id,
            holder_address=holder_address,
            chain_id=chain_id,
            exc_type=type(exc).__name__,
            error=str(exc),
        )
        block = None
    with _CREATION_BLOCK_LOCK:
        _CREATION_BLOCK_CACHE[key] = block
    return 0 if block is None else max(0, int(block))


def raw_balance_text(value: Any) -> str | None:
    """A quantity in the one spelling the skip key compares in, or ``None``.

    Canonicalised through ``int`` so ``"1000"`` and ``1000`` are the same stamp
    and a re-spelling of an unmoved balance does not read as a delivery. A value
    that will not parse — or that is not a whole quantity, which an ERC-20 raw
    balance never is — is kept verbatim rather than dropped or truncated: it
    still compares equal to itself, which is all the key needs, while truncating
    would collapse two different balances onto one stamp and suppress the scan
    the difference between them should have earned.
    """
    if value is None:
        return None
    try:
        exact = Decimal(str(value))
        whole = int(exact)
    except (ArithmeticError, TypeError, ValueError):
        exact, whole = None, None
    if whole is not None and exact == whole:
        return str(whole)
    text = str(value).strip()
    return text or None


def _is_priced_dust(usd_value: Any) -> bool:
    """A real quote below the crumb threshold — priced, and too small to act on.

    Distinct from ``usd_value is None`` and from the stored 0 the writers use for
    "no price known": both of those are absent prices. Only a positive figure
    under the threshold is a crumb somebody actually quoted.
    """
    if usd_value is None:
        return False
    try:
        priced = Decimal(str(usd_value))
    except (ArithmeticError, TypeError, ValueError):
        return False
    return Decimal(0) < priced < USD_CRUMB_THRESHOLD


def clear_creation_block_cache() -> None:
    """Drop the per-process creation-block memo (tests)."""
    with _CREATION_BLOCK_LOCK:
        _CREATION_BLOCK_CACHE.clear()


def is_unpriced(usd_value: Any, raw_balance: Any) -> bool:
    """Whether a holding reading carries no USD figure this population acts on.

    Three ways to land here, and the third is a rule rather than an absence:

    * ``None`` — the plain not-priced state, and an unparseable cell with it.
    * a stored 0 alongside a non-zero quantity — the same state wearing a
      number: the writers store 0 where no quote resolved, and a zero dollar
      figure over a non-zero balance is an absent price rather than a holding
      worth nothing. A 0 over a ZERO quantity is not that; it is a holding of
      nothing, priced, and it is kept.
    * a figure below :data:`~utils.balance_status.USD_CRUMB_THRESHOLD` — a
      crumb. Priced, real, and too small for this population to tell from the
      dust an address is sent unasked. Strictly below: $0.009 is a crumb,
      $0.01 is a position.

    The crumb arm is explicit because it used to be an accident. Until
    ``usd_value`` widened to ``numeric(38,18)`` a small figure was stored rounded
    to the nearest cent and a resulting 0.00 arrived at the second arm; the
    column, not this predicate, was what excluded it, and the cut it drew sat at
    half a cent rather than at one. The population is now defined by a rule that
    can be changed rather than by a column's scale — see
    :data:`~utils.balance_status.USD_CRUMB_THRESHOLD` for which readings that
    moves.

    :func:`disposition_requests` filters the same rule in SQL before the rows
    reach here; that predicate must stay a superset of this one.
    """
    if usd_value is None:
        return True
    try:
        priced = Decimal(str(usd_value))
    except (ArithmeticError, TypeError, ValueError):
        return True
    if priced >= USD_CRUMB_THRESHOLD:
        return False
    if priced != 0:
        return True
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
    dust: dict[tuple[int, str], set[str]] = {}
    balances: dict[tuple[int, str], dict[str, str]] = {}
    contract_for: dict[tuple[int, str], int] = {}

    for request in discovered:
        key = (int(request.chain_id), request.holder_address.lower())
        tokens.setdefault(key, set()).update(t.lower() for t in request.tokens)
        typed.setdefault(key, set()).update(t.lower() for t in request.typed_tokens)
        dust.setdefault(key, set()).update(t.lower() for t in request.priced_dust_tokens)
        # This cycle's own reading of the account, so it wins over the stored row
        # it is about to replace.
        for token, raw in request.balances:
            balances.setdefault(key, {})[token.lower()] = raw
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
            # The SQL half of :func:`is_unpriced`, and deliberately a SUPERSET of
            # it: everything the predicate can answer True for must survive to
            # reach it. Crumbs are in the set because the crumb rule is a rule
            # now — before the column widened, a figure under half a cent arrived
            # here as a stored 0.00 and this clause could test equality with zero
            # and be right by luck.
            or_(
                ContractBalanceLatest.usd_value.is_(None),
                ContractBalanceLatest.usd_value < USD_CRUMB_THRESHOLD,
            ),
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
        stamp = raw_balance_text(raw_balance)
        if stamp is not None:
            balances.setdefault(key, {}).setdefault(token, stamp)
        if _is_priced_dust(usd_value):
            dust.setdefault(key, set()).add(token)
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
            balances=tuple(sorted(balances.get(key, {}).items())),
            priced_dust_tokens=tuple(sorted(dust.get(key, set()) & account_tokens)),
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
    dust: set[str] = set()
    balances: dict[str, str] = {}
    for row in getattr(page, "rows", None) or []:
        token = (row.get("token_address") or "").lower()
        if token and is_unpriced(row.get("usd_value"), row.get("balance")):
            tokens.add(token)
            stamp = raw_balance_text(row.get("balance"))
            if stamp is not None:
                balances[token] = stamp
            if _is_priced_dust(row.get("usd_value")):
                dust.add(token)
    if sweep is not None and sweep.status == asset_sweep.SWEEP_COMPLETED:
        # Every sweep-discovered holding is published unpriced by construction —
        # no price source reaches a log-derived asset — so the whole set is in
        # the population, with the zero-quantity discoveries left out: they are
        # not holdings and carry no sheet reading to annotate.
        for asset in sweep.assets:
            if asset.raw_balance is not None and asset.raw_balance > 0:
                tokens.add(asset.token_address.lower())
                balances[asset.token_address.lower()] = str(int(asset.raw_balance))
        for asset in sweep.typed_assets:
            if asset.raw_balance is not None and asset.raw_balance > 0:
                tokens.add(asset.token_address.lower())
                typed.add(asset.token_address.lower())
                balances[asset.token_address.lower()] = str(int(asset.raw_balance))
    if not tokens:
        return None
    return DispositionRequest(
        contract_id=contract_id,
        chain_id=int(chain_id),
        holder_address=account,
        tokens=tuple(sorted(tokens)),
        typed_tokens=tuple(sorted(typed)),
        balances=tuple(sorted((token, raw) for token, raw in balances.items() if token in tokens)),
        priced_dust_tokens=tuple(sorted(dust)),
    )


def scan_delivery_shape(
    session: Session,
    requests: Sequence[DispositionRequest],
    *,
    rpc_url_for: Callable[[int], str | None],
    cost: DispositionCost | None = None,
    protocol_id: int | None = None,
) -> DispositionCost:
    """Measure delivery shape for every requested pair and record what was read.

    Writes evidence through :func:`record_delivery_evidence` and NEVER commits —
    the producer owns the transaction, so the evidence and the balance row it was
    measured beside land or roll back together.

    A pair with stored evidence is scanned FORWARD from its cursor only, and
    only when something says there is anything to find (see :func:`_scan_chain`),
    which is what makes the full-history pass a once-per-pair cost and every
    later cycle a steady-state one.

    ``protocol_id`` orders the catch-up queue against
    ``token_protocol_reference`` and nothing else; omitting it costs ordering,
    never a verdict.
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
            logger.warning(
                "disposition: no RPC URL for chain; the chain's holders are not scanned",
                extra={"chain_id": chain_id, "holders": len(chain_requests)},
            )
            cost.count("chains_unscanned")
            continue
        head_cost = SweepCost()
        head = asset_sweep.sweep_head_block(rpc_url, chain_id=chain_id, cost=head_cost)
        cost.head_reads += head_cost.head_reads
        if head is None:
            logger.warning(
                "disposition: head unknown; the chain's holders are not scanned",
                extra={"chain_id": chain_id, "holders": len(chain_requests)},
            )
            cost.count("chains_unscanned")
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
                protocol_id=protocol_id,
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


# --- the universe memo ------------------------------------------------------
# ``load_protocol_universe`` is a measured 26.5-second object-storage assembly.
# The TVL path pays it once per cycle; the resolution worker calls this phase
# once per CONTRACT, so on the reference protocol's ~91 contracts carrying
# unpriced tokens the same universe was assembled ~91 times — ~40 minutes of a
# full re-resolution spent rebuilding one answer.
#
# TTL for the reuse window. Bounded rather than unbounded because the extent key
# below cannot see every row the assembly reads (see ``_protocol_universe``).
#
# CAPPED, and the cap is the same argument the fan-out threshold's is: this
# window bounds how long a verdict may rest on a universe that has since grown,
# and a stale universe is SHORT, which makes the predicate condemn MORE. A
# deployment that could widen it freely could widen the condemning-direction
# staleness of a published claim, which is not a deployment's call to make. The
# env may only NARROW the window; anything above the cap clamps to it, and a
# value that is not a positive number is ignored rather than being allowed to
# disable the bound.
_UNIVERSE_MEMO_TTL_CEILING_SECONDS = 900.0


def _memo_ttl_seconds() -> float:
    raw = os.getenv("PSAT_UNIVERSE_MEMO_TTL_SECONDS")
    if raw is None:
        return _UNIVERSE_MEMO_TTL_CEILING_SECONDS
    try:
        requested = float(raw)
    except (TypeError, ValueError):
        return _UNIVERSE_MEMO_TTL_CEILING_SECONDS
    if requested <= 0:
        return _UNIVERSE_MEMO_TTL_CEILING_SECONDS
    return min(requested, _UNIVERSE_MEMO_TTL_CEILING_SECONDS)


_UNIVERSE_MEMO_TTL_SECONDS = _memo_ttl_seconds()

_UNIVERSE_MEMO_LOCK = threading.Lock()


@dataclass(frozen=True)
class _MemoUniverse:
    """The three fields the reference pass reads off a universe, and nothing else."""

    addresses: frozenset[str]
    sources: dict[str, int]
    basis: str


@dataclass
class _UniverseMemoEntry:
    extent: tuple[tuple[str, ...], tuple[int, ...]]
    addresses: frozenset[str]
    sources: dict[str, int]
    basis: str
    built_at: float
    builds: int = 1
    reuses: int = 0


_UNIVERSE_MEMO: dict[int, _UniverseMemoEntry] = {}


def clear_protocol_universe_memo() -> None:
    """Drop every memoized universe in this process.

    The hook exists for tests and for any caller that wants the next assembly
    measured rather than reused; nothing in the producers calls it, because a
    cycle that wants a fresh universe gets one from the extent key or the TTL.
    """
    with _UNIVERSE_MEMO_LOCK:
        _UNIVERSE_MEMO.clear()


def _discovery_extent(session: Session, protocol_id: int) -> tuple[tuple[str, ...], tuple[int, ...]]:
    """The jobs and contracts a universe for this protocol would be assembled OVER.

    Two indexed id reads, and they mirror ``load_protocol_universe``'s own
    population exactly: the protocol's jobs, the contracts carrying its
    ``protocol_id`` or reachable through one of those jobs, and the jobs THOSE
    contracts name (a contract attributed to this protocol whose job belongs to
    another one still has its source bodies read). Any of these growing widens
    the universe, so all of them are in the key.
    """
    from sqlalchemy import select

    from db.models import Contract, Job

    job_ids = session.execute(select(Job.id).where(Job.protocol_id == protocol_id)).scalars().all()
    rows = session.execute(
        select(Contract.id, Contract.job_id).where(
            (Contract.protocol_id == protocol_id) | (Contract.job_id.in_(job_ids) if job_ids else False)
        )
    ).all()
    jobs = {str(job_id) for job_id in job_ids} | {str(job_id) for _, job_id in rows if job_id}
    return tuple(sorted(jobs)), tuple(sorted(int(cid) for cid, _ in rows))


def _protocol_universe(session: Session, protocol_id: int) -> _MemoUniverse | None:
    """The protocol's address universe, assembled once per process and reused.

    **WHICH WAY THIS ERRS: LARGER.** A served entry is the UNION of every
    universe this process has assembled for the protocol, so a reuse can only add
    addresses and never take one away — and the direction is the whole point,
    because the predicate the universe feeds condemns what is ABSENT. A short
    universe condemns MORE, so an entry that is stale in the short direction is
    the one that could manufacture an ``absent_from_universe`` verdict for a
    token the protocol really does refer to. Two things keep it out:

    * **the extent key.** An entry is served only while the jobs and contracts
      the universe would be assembled over are exactly the ones it WAS assembled
      over (:func:`_discovery_extent`). Discovery widening — a new contract, a
      new job — retires the entry and the next call rebuilds.
    * **the TTL.** The extent key cannot see everything: the control-graph,
      principal, effect-verdict, dApp-interaction, monitored-contract and
      restaking rows are read per contract or per protocol, and a resolution job
      can add addresses to an already-keyed contract without changing the key.
      That residual is bounded by ``_UNIVERSE_MEMO_TTL_SECONDS`` rather than left
      open, and it is a bound on a reuse WINDOW and not a claim that the window
      is safe: ``token_protocol_reference`` is refreshed every cycle, so a
      verdict taken against a stale universe withdraws on the next pass.

    ``None`` — the loader's fail-closed answer — is NEVER cached, and that choice
    is deliberate in the same direction. An unbuildable universe means every
    token lands ``not_determined``; caching it would spend the whole TTL
    condemning nothing, which is safe, but it would also hide a storage blip that
    has since cleared behind an answer nobody re-asked for. Re-asking costs one
    assembly and can only narrow the refusal.

    A raise from the loader propagates: the caller reads it exactly as ``None``,
    and the memo stores nothing either way.
    """
    from services.scoring import distill

    extent = _discovery_extent(session, protocol_id)
    now = time.monotonic()
    with _UNIVERSE_MEMO_LOCK:
        entry = _UNIVERSE_MEMO.get(protocol_id)
        if entry is not None and entry.extent == extent and now - entry.built_at <= _UNIVERSE_MEMO_TTL_SECONDS:
            entry.reuses += 1
            return _MemoUniverse(
                addresses=entry.addresses,
                sources=dict(entry.sources),
                basis=(
                    f"{entry.basis}. Assembled once in this process and reused "
                    f"{entry.reuses} time(s) over an unchanged discovery extent of "
                    f"{len(extent[0])} job(s) and {len(extent[1])} contract(s), within a "
                    f"{_UNIVERSE_MEMO_TTL_SECONDS:.0f}s reuse window; the reused set is the UNION of "
                    "every assembly this process made for the protocol, so reuse can only add an "
                    "address and never withdraw one"
                ),
            )
        previous = entry.addresses if entry is not None else frozenset()

    # Timed: a measured 26.5s object-storage assembly is the single largest
    # unattributed block of a disposition cycle, and the memo above means a
    # cycle that pays it and one that does not otherwise look identical.
    with log_timed_phase(logger, "protocol_universe", protocol_id=protocol_id) as phase:
        universe = distill.load_protocol_universe(session, protocol_id)
        phase["universe_addresses"] = None if universe is None else len(universe.addresses)
    if universe is None:
        return None

    addresses = frozenset(universe.addresses) | previous
    with _UNIVERSE_MEMO_LOCK:
        standing = _UNIVERSE_MEMO.get(protocol_id)
        _UNIVERSE_MEMO[protocol_id] = _UniverseMemoEntry(
            extent=extent,
            # Another thread may have assembled the same protocol while this one
            # was reading object storage. Its addresses are folded in rather than
            # overwritten, for the same reason the union exists at all.
            addresses=addresses | (standing.addresses if standing is not None else frozenset()),
            sources=dict(universe.sources),
            basis=str(universe.basis),
            built_at=now,
            builds=(standing.builds + 1) if standing is not None else 1,
        )
        stored = _UNIVERSE_MEMO[protocol_id]
    return _MemoUniverse(
        addresses=stored.addresses,
        sources=dict(stored.sources),
        basis=(
            str(universe.basis)
            if stored.addresses == frozenset(universe.addresses)
            else (
                f"{universe.basis}. Widened by {len(stored.addresses) - len(universe.addresses)} address(es) this "
                "process assembled for the protocol under an earlier discovery extent — the set carried forward is "
                "the UNION, which can only spare a token and never condemn one"
            )
        ),
    )


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

    **A universe of NO addresses reads the same way, and is refused HERE.** An
    empty set condemns everything absent from it, which is everything. The
    refusal is the writer's own — ``ck_tpr_absence_needs_a_universe`` says the
    same thing at the table, and reaching it is not a defence: this pass runs
    inside a producer that swallows what it raises, so a constraint violation
    would poison the surrounding transaction and take the BALANCE WRITE with it.
    The guard keeps the verdict correct and the write alive.

    Rows are REFRESHED, not accreted (see ``db.models.TokenProtocolReference``):
    the predicate is anti-monotone, so a verdict must be able to withdraw when
    discovery grows. Which is also why an unbuildable or empty universe writes
    ``not_determined`` rows rather than nothing at all — writing nothing would
    leave a previous cycle's ``absent_from_universe`` standing against a universe
    this cycle could not measure.

    Returns the number of tokens written.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from db.models import TokenProtocolReference

    pairs = sorted({(int(request.chain_id), token.lower()) for request in requests for token in request.tokens})
    if not pairs:
        return 0

    try:
        universe = _protocol_universe(session, protocol_id)
    except Exception as exc:
        # Same reading as the loader's own ``None``: an assembly that raised is
        # an assembly that did not happen.
        logger.warning("disposition: protocol universe for %s could not be assembled: %s", protocol_id, exc)
        universe = None

    addresses: frozenset[str] = frozenset() if universe is None else universe.addresses
    universe_size = len(addresses)
    if universe is None:
        basis = (
            "protocol reference not determined: the protocol universe could not be assembled whole "
            "(services.scoring.distill.load_protocol_universe returned no universe), and an absence "
            "measured against a short universe condemns more rather than less"
        )
    elif universe_size == 0:
        basis = (
            "protocol reference not determined: the protocol universe was assembled and named NO address, "
            "and an absence measured against an empty universe condemns every token rather than none; "
            f"{universe.basis}"
        )
    else:
        basis = (
            f"protocol reference measured against {universe_size} discovered address(es), chain-blind; {universe.basis}"
        )

    now = _sql_func.now()
    rows = [
        {
            "protocol_id": int(protocol_id),
            "chain_id": chain_id,
            "token_address": token,
            # ``universe_size == 0`` covers BOTH refusals — the unbuildable
            # universe and the empty one — because they are the same fact to a
            # consumer: no address was available to measure an absence against.
            "reference_shape": (
                TOKEN_REFERENCE_NOT_DETERMINED
                if universe_size == 0
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
    # One timed phase, and its completion line IS the cycle summary: whether the
    # corpus is converging cannot be read off a request count, so the outcome
    # tally (`DispositionCost.counts`) rides the same line as the cost.
    with log_timed_phase(logger, "disposition", holders=len(requests)) as phase:
        if protocol_id is not None:
            try:
                written = record_protocol_reference(session, protocol_id=protocol_id, requests=requests)
            except Exception as exc:
                logger.warning(
                    "disposition: protocol reference pass failed; every token stays not_determined",
                    extra={"protocol_id": protocol_id, "exc_type": type(exc).__name__, "error": str(exc)},
                )
                cost.count("reference_pass_failed")
            else:
                cost.count("reference_tokens_recorded", written)
        try:
            scan_delivery_shape(session, requests, rpc_url_for=rpc_url_for, cost=cost, protocol_id=protocol_id)
        except Exception as exc:
            logger.warning(
                "disposition scan failed; balances are unaffected and the pairs stay not_determined",
                extra={
                    "exc_type": type(exc).__name__,
                    "error": str(exc),
                    "get_logs": cost.get_logs,
                    "receipts": cost.receipts,
                    "head_reads": cost.head_reads,
                    "creation_lookups": cost.creation_lookups,
                },
            )
            cost.count("scan_failed")
        phase.update(
            {
                "get_logs": cost.get_logs,
                "receipts": cost.receipts,
                "head_reads": cost.head_reads,
                "creation_lookups": cost.creation_lookups,
                "degraded": dict(cost.degraded),
                **cost.counts,
            }
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
    protocol_id: int | None = None,
) -> None:
    """Decide what this cycle scans, scan a bounded slice of it, and record.

    THE QUEUE IS DELTA-GATED, and the gate is a balance rather than a clock.
    Head advances every cycle, so "resume below head" made every stored pair a
    forward scan forever and a converged corpus kept paying getLogs for verdicts
    that could not move. What can move a verdict is a NEW DELIVERY, and a new
    delivery necessarily moves the holder's balance — which the monitor already
    reads by multicall, at no extra request. So an unchanged balance over an
    extent that reached the head is the witness that there is nothing to scan.

    The gate is only ever allowed to skip, never to conclude: a skipped pair
    keeps the verdict and the extent it already earned, and nothing about it is
    published as newer than it is. The four arms, in order:

    * no row — a FRESH pair, scanned from the holder's creation block.
    * ``has_direct_delivery`` — settled and never scanned again. The verdict is
      an earned negative and ``min_fan_out`` only falls, so no later delivery can
      lift it back to the positive.
    * ``caught_up`` false — the extent stops at a slice boundary, so the balance
      argument does not apply to the blocks above it. Scanned forward regardless
      of the balance.
    * otherwise — scanned forward iff the balance moved, where a NULL stamp
      counts as moved so a row from before the stamp existed is scanned once
      more.

    A pair the gate holds back is still PRESENTED to the writer at its own stored
    extent: the basis is re-derived from the row's extent columns on every pass,
    so a row authored under an older rule is repaired by an ordinary cycle, and
    presenting it cannot advance the cursor because the extent it presents is the
    one it already claimed.
    """
    fresh: list[_Pair] = []
    forward: list[_Pair] = []
    carried: list[_Pair] = []
    balance_of: dict[tuple[str, str], str | None] = {}
    for request in requests:
        typed_set = {t.lower() for t in request.typed_tokens}
        balances = {token.lower(): raw for token, raw in request.balances}
        for token in {t.lower() for t in request.tokens}:
            balance_of.setdefault((request.holder_address, token), raw_balance_text(balances.get(token)))
            cost.count("pairs_considered")
            fact = stored.get((chain_id, request.holder_address, token))
            if fact is None:
                cost.count("pairs_fresh")
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
            # The two hold-backs are counted apart because they mean opposite
            # things about convergence: settled is a pair that will never be
            # scanned again, gate-skipped is one this cycle had no reason to.
            if _is_settled(fact):
                cost.count("pairs_settled_skipped")
                carried.append(pair)
                continue
            if not _worth_scanning(fact, balances.get(token)):
                cost.count("pairs_gate_skipped")
                carried.append(pair)
                continue
            cost.count("pairs_forward")
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
    priority = _token_priority(session, chain_id=chain_id, requests=requests, protocol_id=protocol_id)

    measured: dict[tuple[str, str], _Measured] = {}
    starved = False
    for group in (fresh, forward):
        if not group or starved:
            continue
        # The window start is the EARLIEST start any pair in the group needs.
        # Starting a pair earlier than it asked for is safe in one direction
        # only, and it is this one: it can only add deliveries, and an added
        # delivery can only withdraw a positive verdict.
        group_from = min(pair.from_block for pair in group)
        scan_to = min(head, group_from + _slice_windows(group, cost=cost) * max_block_range)
        in_slice = [pair for pair in group if pair.from_block <= scan_to]
        for pair in group:
            if pair.from_block > scan_to:
                # Above this cycle's slice. A pair with a row keeps its extent
                # and is carried for basis repair; one WITHOUT a row is deferred
                # whole — writing nothing, because the absence of a row already
                # reads not_determined everywhere and a partial delivery set is a
                # different claim rather than a smaller one.
                cost.count("pairs_above_slice")
                if stored.get((chain_id, pair.holder, pair.token)) is not None:
                    carried.append(pair)
        if not in_slice:
            continue
        cost.count("pairs_scanned", len(in_slice))
        for pair in in_slice:
            measured[(pair.holder, pair.token)] = _Measured(
                scanned_from_block=group_from,
                measured_through=scan_to,
                caught_up=scan_to >= head,
                observed_balance_raw=balance_of.get((pair.holder, pair.token)),
            )
        starved = _discover(
            fetcher,
            in_slice,
            chain_id=chain_id,
            from_block=group_from,
            to_block=scan_to,
            measured=measured,
            priority=priority,
            cost=cost,
        )
    for pair in carried:
        fact = stored.get((chain_id, pair.holder, pair.token))
        if fact is None:
            continue
        cost.count("pairs_carried")
        measured.setdefault(
            (pair.holder, pair.token),
            _Measured(
                scanned_from_block=int(fact.scanned_from_block),
                # Its own stored extent, so the writer's cursor rule is a no-op.
                # A carried pair was not scanned; claiming the head for it would
                # widen a published all-quantifier over unread blocks.
                measured_through=int(fact.measured_through_block),
            ),
        )

    # Runs even when discovery starved, and that ordering is the fix: every pair
    # whose windows were proven whole reaches the writer before the budget error
    # leaves this function, so a cycle that ran out of requests still made
    # forward progress instead of repeating itself next hour.
    _resolve_fan_out(
        session,
        chain_id=chain_id,
        rpc_url=rpc_url,
        measured=measured,
        stored=stored,
        max_block_range=max_block_range,
        cost=cost,
        priority=priority,
    )
    if starved:
        raise DispositionBudgetExceeded(f"disposition request budget of {DISPOSITION_REQUEST_BUDGET} reached")


def _slice_windows(pairs: Sequence[_Pair], *, cost: DispositionCost) -> int:
    """Windows this group may page, narrowed to what the budget can still pay.

    The slice alone bounds pages per BATCH, not per cycle, and a group is as many
    batches as it has holder chunks times token chunks — so a wide holder can
    still spend the whole ceiling inside discovery, and a chain scanned late pays
    for the chains ahead of it (the measured failure was optimism, chain 10,
    after ethereum). Dividing what is LEFT among the passes still to come keeps
    the group's discovery inside the budget.

    A narrowing, not a guarantee: the fetcher bisects, so one window can cost
    more than one request. :func:`_discover` is what makes the invariant true —
    this only makes reaching it rare.

    Never below one window. A cycle with nothing left should refuse at the
    fetcher, where the refusal is counted and logged, rather than quietly scan a
    range of nothing.
    """
    holders = _chunk_count(len({p.holder for p in pairs}), DISPOSITION_HOLDER_BATCH)
    tokens = _chunk_count(len({p.token for p in pairs}), DISPOSITION_TOKEN_BATCH)
    typed = _chunk_count(len({p.token for p in pairs if p.typed}), DISPOSITION_TOKEN_BATCH)
    passes = max(1, holders * (tokens + typed))
    remaining = max(0, DISPOSITION_REQUEST_BUDGET - cost.total)
    return max(1, min(DISPOSITION_SLICE_WINDOWS, remaining // passes))


def _chunk_count(items: int, size: int) -> int:
    return -(-items // size)


def _is_settled(fact: Any) -> bool:
    """``has_direct_delivery`` is an earned negative and it never moves again.

    ``min_fan_out`` only falls, so a delivery found later can only confirm the
    negative. Scanning the pair again could not change what it publishes.

    One consequence, deliberate: a row settled at a PARTIAL extent keeps
    ``caught_up`` false forever, because catch-up short-circuits here. Harmless
    for what it publishes — the negative was earned inside the extent the row
    names — but it is why only the POSITIVE is gated on ``caught_up``
    (``delivery_evidence.DeliveryFact.is_airdrop_only``) and why a consumer must
    not read that flag as "this pair is behind".
    """
    return str(getattr(fact, "shape", "")) == DELIVERY_SHAPE_HAS_DIRECT_DELIVERY


def _worth_scanning(fact: Any, balance: str | None) -> bool:
    """Whether anything says a forward scan of this pair could find a delivery.

    ``True`` on every doubt: a row whose extent stops below the head has blocks
    the balance argument says nothing about, and a NULL stamp is a pair nobody
    ever compared — neither is a witness that there is nothing to find, so both
    are scanned. Only an unchanged balance over an extent that reached the head
    earns the skip.
    """
    if not bool(getattr(fact, "caught_up", True)):
        return True
    stamped = getattr(fact, "observed_balance_raw", None)
    if stamped is None:
        return True
    return raw_balance_text(balance) != str(stamped)


def _token_priority(
    session: Session,
    *,
    chain_id: int,
    requests: Sequence[DispositionRequest],
    protocol_id: int | None,
) -> dict[str, int]:
    """Catch-up ORDER, and nothing else: no token is dropped, no verdict moves.

    A budget or a slice boundary cuts the queue somewhere, and where it cuts
    decides which pairs get a verdict this cycle. Order by how likely the token
    is to be one the protocol means to hold: first the tokens this protocol's own
    discovery names (``token_protocol_reference``, refreshed by
    :func:`record_protocol_reference` earlier in this same session), then the
    crumbs a price source did quote, then everything else.
    """
    tokens = sorted({token.lower() for request in requests for token in request.tokens})
    if not tokens:
        return {}
    dust = {token.lower() for request in requests for token in request.priced_dust_tokens}
    referenced: set[str] = set()
    if protocol_id is not None:
        from db.models import TokenProtocolReference

        for start in range(0, len(tokens), 500):
            rows = (
                session.query(TokenProtocolReference.token_address)
                .filter(
                    TokenProtocolReference.protocol_id == int(protocol_id),
                    TokenProtocolReference.chain_id == chain_id,
                    TokenProtocolReference.reference_shape == TOKEN_REFERENCE_IN_UNIVERSE,
                    TokenProtocolReference.token_address.in_(tokens[start : start + 500]),
                )
                .all()
            )
            referenced.update(str(row[0]).lower() for row in rows)
    return {token: (0 if token in referenced else 1 if token in dust else 2) for token in tokens}


def _discover(
    fetcher: RpcEventLogFetcher,
    pairs: Sequence[_Pair],
    *,
    chain_id: int,
    from_block: int,
    to_block: int,
    measured: dict[tuple[str, str], _Measured],
    priority: Mapping[str, int],
    cost: DispositionCost,
) -> bool:
    """Fill *measured* with every delivery the requested pairs received.

    The window is the caller's — it owns both the earliest start the group needs
    and the slice boundary this cycle stops at. Tokens are batched in
    ``priority`` order, so when a budget cuts the queue the tokens most likely to
    be real are the ones already on the far side of the cut.

    Returns whether the budget died here. IT IS NOT RAISED, and that is the
    point: a budget death used to propagate out of the whole chain scan before
    any evidence was written, so a chain that could not finish discovery in one
    cycle wrote NOTHING and the next cycle repeated it identically — measured on
    optimism, 4,974 requests an hour, forever. A pair is a claim on its own, and
    the pairs whose windows WERE proven whole are recorded. What the death costs
    is exactly the pairs it touched: the in-flight window's, and every window
    that never ran, all marked aborted so they publish nothing.
    """
    wanted = {(p.holder, p.token) for p in pairs}

    holders = sorted({p.holder for p in pairs})
    tokens = _ordered(sorted({p.token for p in pairs}), priority)
    typed_tokens = _ordered(sorted({p.token for p in pairs if p.typed}), priority)

    passes: list[tuple[list[str], list[str], list[Any], int]] = []
    for holder_batch in _chunks(holders, DISPOSITION_HOLDER_BATCH):
        padded = [_pad32(h) for h in holder_batch]
        for token_batch in _chunks(tokens, DISPOSITION_TOKEN_BATCH):
            passes.append((holder_batch, token_batch, [[TRANSFER_TOPIC0], None, padded], _RECIPIENT_TOPIC_ERC20))
        # ERC-1155's recipient sits in topic 3, so it needs its own pass or the
        # scan sees 1155 sends and misses 1155 RECEIPTS. Inert on today's
        # population (no typed receipt in it), and implemented anyway so a
        # future one is measured rather than silently unmeasured.
        for token_batch in _chunks(typed_tokens, DISPOSITION_TOKEN_BATCH):
            passes.append(
                (
                    holder_batch,
                    token_batch,
                    [list(_ERC1155_TOPIC0S), None, None, padded],
                    _RECIPIENT_TOPIC_ERC1155,
                )
            )

    for index, (holder_batch, token_batch, topics, recipient_topic) in enumerate(passes):
        try:
            _run_pass(
                fetcher,
                event_address=token_batch,
                topics=topics,
                recipient_topic=recipient_topic,
                from_block=from_block,
                to_block=to_block,
                wanted=wanted,
                holder_batch=holder_batch,
                token_batch=token_batch,
                measured=measured,
                chain_id=chain_id,
                cost=cost,
            )
        except DispositionBudgetExceeded as exc:
            logger.warning(
                "disposition: request budget died mid-discovery; the passes that had completed are recorded, "
                "the rest are aborted",
                extra={
                    "chain_id": chain_id,
                    "from_block": from_block,
                    "to_block": to_block,
                    "passes_completed": index,
                    "passes": len(passes),
                    "error": str(exc),
                },
            )
            # A pair covered by a pass that never ran has a delivery set nobody
            # enumerated, which is a different claim rather than a smaller one.
            for pending_holders, pending_tokens, _, _ in passes[index:]:
                _abort(pending_holders, pending_tokens, measured, cost=cost)
            return True
    return False


def _abort(
    holder_batch: Sequence[str],
    token_batch: Sequence[str],
    measured: Mapping[tuple[str, str], _Measured],
    *,
    cost: DispositionCost,
) -> None:
    """Mark every pair a window covered unproven, so it publishes nothing."""
    for holder in holder_batch:
        for token in token_batch:
            entry = measured.get((holder, token))
            if entry is not None and not entry.aborted:
                entry.aborted = True
                cost.count("pairs_aborted")


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
    cost: DispositionCost,
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
        logger.warning(
            "disposition: window could not be proven whole; its pairs publish nothing this cycle",
            extra={
                "chain_id": chain_id,
                "from_block": from_block,
                "to_block": to_block,
                "holders": len(holder_batch),
                "tokens": len(token_batch),
                "exc_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        _abort(holder_batch, token_batch, measured, cost=cost)
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


def _ordered(tokens: Sequence[str], priority: Mapping[str, int]) -> list[str]:
    """Tokens in catch-up order. A total order, so a cut point is reproducible."""
    return sorted(tokens, key=lambda token: (priority.get(token, 2), token))


def _resolve_fan_out(
    session: Session,
    *,
    chain_id: int,
    rpc_url: str,
    measured: Mapping[tuple[str, str], _Measured],
    stored: Mapping[tuple[int, str, str], Any],
    max_block_range: int,
    cost: DispositionCost,
    priority: Mapping[str, int],
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

    Pairs are metered in the queue's own ``priority`` order, so the receipts a
    budget does buy are spent on the tokens most likely to be real. Each pair is
    recorded at ITS OWN extent (``_Measured.measured_through``), which is the
    slice a scan proved or, for a carried pair, exactly the extent it already
    had — never a chain head nobody read up to.
    """
    receipts: dict[str, dict | None] = {}
    exhausted = False
    for (holder, token), entry in sorted(
        measured.items(), key=lambda item: (priority.get(item[0][1], 2), item[0][0], item[0][1])
    ):
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
            # One line per pair, and it is not noise: the row this writes can
            # never be disposed, so this is the only announcement that a pair
            # left the convergent population for good.
            logger.info(
                "disposition: pair abandoned as too heavy to meter; it stays not_determined permanently",
                extra={
                    "chain_id": chain_id,
                    "holder_address": holder,
                    "token_address": token,
                    "deliveries": len(ordered),
                    "max_deliveries_per_pair": DISPOSITION_MAX_DELIVERIES_PER_PAIR,
                },
            )
            cost.count("pairs_too_heavy")
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
                if receipts[tx] is None:
                    # ``get_transaction_receipt`` logs the per-call failure at
                    # DEBUG (hot path). The cycle counts it, because an unread
                    # receipt is an unmetered delivery and a flood of them is a
                    # flood of not_determined verdicts with no other trace.
                    cost.count("receipts_unreadable")
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
        shape = record_delivery_evidence(
            session,
            chain_id=chain_id,
            holder_address=holder,
            token_address=token,
            scanned_from_block=entry.scanned_from_block,
            measured_through_block=entry.measured_through,
            deliveries=deliveries,
            unmetered_elided=elided,
            scan_basis=_scan_basis(chain_id=chain_id, max_block_range=max_block_range),
            observed_balance_raw=entry.observed_balance_raw,
            caught_up=entry.caught_up,
            counts=cost.counts,
        )
        cost.count("pairs_recorded")
        cost.count(f"verdict_{shape}")
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
    "DISPOSITION_SLICE_WINDOWS",
    "DISPOSITION_TOKEN_BATCH",
    "DispositionBudgetExceeded",
    "DispositionCost",
    "DispositionRequest",
    "clear_creation_block_cache",
    "clear_protocol_universe_memo",
    "creation_block",
    "discovered_request",
    "disposition_cost_note",
    "disposition_requests",
    "is_unpriced",
    "raw_balance_text",
    "record_protocol_reference",
    "run_disposition",
    "scan_delivery_shape",
]
