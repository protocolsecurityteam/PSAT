"""The value plane: what each entity's balance sheet proves, in dollars."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import tuple_
from sqlalchemy.orm import Session

from services.scoring.planes._shared import (
    NATIVE_ASSET,
    _chain_name,
    _float,
    _lower,
    _round_presented,
    typed_receipt_is_resolved,
)
from services.scoring.schema import coalesce_chain, entity_key
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    STATUS_UNATTEMPTED,
    SWEEP_STATUS_COMPLETED,
)

# ``usd_value`` is a scaled decimal, so 0.00 may be its storage floor rather than zero. Only a proven-zero quantity
# makes a 0.00 reading a real zero; otherwise it is below resolution.
ASSET_PRICED = "priced"
ASSET_BELOW_RESOLUTION = "priced_below_resolution"
ASSET_PROVEN_ZERO = "proven_zero"
ASSET_UNPRICED = "unpriced"
# Every incoming delivery of this asset arrived in a transaction with at least K same-token transfer logs (an upper
# bound on recipients). A claim about delivery shape only, never worth: real tokens (HEX, WETH, USDC, uniETH, USDtb)
# share it.
ASSET_AIRDROP_DELIVERED = "airdrop_delivered"

SHEET_PRICED = "priced"
SHEET_BELOW_RESOLUTION = "priced_below_resolution"
SHEET_UNPRICED = "unpriced"
SHEET_PROVEN_EMPTY = "proven_empty"
SHEET_NO_ROWS = "no_rows"
# Distinct from ``proven_empty``: that says nothing arrived; this says what arrived came as a mass distribution.
SHEET_AIRDROP_DETERMINED = "airdrop_determined"

# Sheet states whose total isn't a number, kept apart: all lookups below resolution, no lookup answered, nothing
# observed.
SHEET_NOT_DETERMINED = (SHEET_BELOW_RESOLUTION, SHEET_UNPRICED, SHEET_NO_ROWS)

# Why an all-zero sheet still may not be published empty. "Holds nothing" is the strongest negative, so each way it can
# be wrong has its own token (they are closed by different work: chain scan, typed-receipt read, restaking pricing). A
# refused sheet publishes ``unpriced``, never $0.
EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE = "asset_set_not_proven_complete"
EMPTY_REFUSED_UNSCANNED_ACCOUNT = "folded_account_never_scanned"
EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED = "typed_receipt_unresolved"
EMPTY_REFUSED_UNPRICED_POSITIONS = "unpriced_positions_at_this_entity"
EMPTY_REFUSALS = (
    EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE,
    EMPTY_REFUSED_UNSCANNED_ACCOUNT,
    EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED,
    EMPTY_REFUSED_UNPRICED_POSITIONS,
)

# Why a fully disposed sheet may still not be determined. Its completeness conjunct is weaker than proven-empty's:
# disposition only needs the list not observably cut off (a whole-list witness isn't available), and says so in its
# basis.
DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED = "typed_receipt_unresolved"
DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED = "asset_list_truncated"
DISPOSITION_REFUSED_UNSCANNED_ACCOUNT = "folded_account_never_scanned"
DISPOSITION_REFUSED_UNPRICED_POSITIONS = "unpriced_positions_at_this_entity"
DISPOSITION_REFUSALS = (
    DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED,
    DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED,
    DISPOSITION_REFUSED_UNSCANNED_ACCOUNT,
    DISPOSITION_REFUSED_UNPRICED_POSITIONS,
)


@dataclass
class ValuePlane:
    """Per-entity value from the latest observation per (entity, asset).

    ``contract_entities`` is every entity the protocol's contracts name, priced or not: the confidence perimeter's base
    population, fixed by discovery. ``per_asset`` holds only determined dollar readings; undetermined assets are in
    ``per_asset_state`` instead (a key only in ``per_asset`` reads as determined).
    """

    contract_entities: set[str] = field(default_factory=set)
    per_asset: dict[str, dict[str, float]] = field(default_factory=dict)
    per_asset_state: dict[str, dict[str, str]] = field(default_factory=dict)
    native_fact: dict[str, str] = field(default_factory=dict)
    # Entities whose latest asset list hit the endpoint's page cap (a prefix, so a floor). One-directional: a short page
    # never proves the index complete.
    asset_set_truncated: set[str] = field(default_factory=set)
    # Entities whose ERC-20 list the chain's own transfer history proves whole through a named block (not the negation
    # of the truncated set). The only witness under which an empty sheet may publish $0; a third-party index's empty
    # answer only triggers the scan. Values are the carrier's own record (source, block range, basis).
    asset_set_proven_complete: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Accounts of a sheet that a scan reached elsewhere but never at their own address; a separate token so a
    # half-scanned sheet can't pass as scanned.
    asset_set_accounts_unscanned: dict[str, list[str]] = field(default_factory=dict)
    # ERC-721/1155 receipts whose current holding isn't resolved: the entity may still hold them, so ``proven_empty`` is
    # refused. Never summed into USD (``balanceOf`` counts items).
    typed_receipts_unresolved: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    alias: dict[str, str] = field(default_factory=dict)
    # Implementation keys shared by two proxies: aliased nowhere, since picking one would charge the other's sheet.
    alias_ambiguous: set[str] = field(default_factory=set)
    unpriced_positions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Per (entity, asset), the carrier record of the delivery evidence that disposed the reading, so narration quotes
    # evidence. Always empty since delivery classification was retired.
    asset_disposition: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    annotations: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def canonical(self, key: str) -> str:
        """An implementation folds onto its proxy, resolved to a fixed point (``J -> I -> P`` answers ``P``).

        Keys in ``alias_ambiguous`` fold nowhere.
        """
        return self.alias.get(key, key)

    def asset_set_is_truncated(self, key: str) -> bool:
        """Whether the canonical sheet's asset list is known cut off at the page cap (a truncated read of either
        account truncates the sheet). ``False`` is only the absence of that witness.
        """
        return self.canonical(key) in self.asset_set_truncated

    def asset_set_is_proven_complete(self, key: str) -> bool:
        """Whether chain logs prove the canonical sheet's list whole: every contributing account must have been
        scanned.

        ``False`` means no scan, not incomplete.
        """
        return self.canonical(key) in self.asset_set_proven_complete

    def unresolved_typed_receipts(self, key: str) -> list[dict[str, Any]]:
        return self.typed_receipts_unresolved.get(self.canonical(key)) or []

    def proven_empty_refusal(self, key: str) -> str | None:
        """Why this sheet may not be published as a proven $0, or ``None``.

        Asked in the order that names the actionable cause: an unresolved typed receipt (why the scan's completeness was
        withheld), then an account no scan reached, then no scan at all, then restaking quantities with no USD column (a
        $0 sheet would contradict them). A third-party index's empty answer is never a conjunct.
        """
        canonical = self.canonical(key)
        if self.typed_receipts_unresolved.get(canonical):
            return EMPTY_REFUSED_TYPED_RECEIPT_UNRESOLVED
        if canonical not in self.asset_set_proven_complete:
            if self.asset_set_accounts_unscanned.get(canonical):
                return EMPTY_REFUSED_UNSCANNED_ACCOUNT
            return EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE
        if self.unpriced_positions.get(canonical):
            return EMPTY_REFUSED_UNPRICED_POSITIONS
        return None

    def disposition_refusal(self, key: str) -> str | None:
        """Why this sheet's dispositions may not determine it, or ``None``: an unresolved typed receipt, an asset
        list at the page cap (the only completeness conjunct), an unscanned account, or restaking quantities.
        """
        canonical = self.canonical(key)
        if self.typed_receipts_unresolved.get(canonical):
            return DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED
        if canonical in self.asset_set_truncated:
            return DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED
        if self.asset_set_accounts_unscanned.get(canonical):
            return DISPOSITION_REFUSED_UNSCANNED_ACCOUNT
        if self.unpriced_positions.get(canonical):
            return DISPOSITION_REFUSED_UNPRICED_POSITIONS
        return None

    def sheet_state(self, key: str) -> str:
        """What the sheet proves, one of six states: ``priced`` (a determined non-zero reading; the total is a
        floor), ``priced_below_resolution`` (every answered lookup hit the storage floor), ``unpriced`` (rows but
        no answer), ``proven_empty`` (every quantity proven zero over a list proven whole),
        ``airdrop_determined``, ``no_rows``.

        The priced branch checks reading state before magnitude, so a tiny determined reading that rounds to 0.0 can't
        fall through to ``proven_empty``. ``proven_empty`` and ``airdrop_determined`` never collapse; disposition is
        asked after the unpriced states. A refused empty claim publishes ``unpriced``, never $0.
        """
        canonical = self.canonical(key)
        values = self.per_asset.get(canonical) or {}
        states = self.per_asset_state.get(canonical) or {}
        if any(state == ASSET_PRICED for state in states.values()) or any(value != 0.0 for value in values.values()):
            return SHEET_PRICED
        if any(state == ASSET_BELOW_RESOLUTION for state in states.values()):
            return SHEET_BELOW_RESOLUTION
        if any(state == ASSET_UNPRICED for state in states.values()):
            return SHEET_UNPRICED
        if any(state == ASSET_AIRDROP_DELIVERED for state in states.values()) and all(
            state in (ASSET_AIRDROP_DELIVERED, ASSET_PROVEN_ZERO) for state in states.values()
        ):
            # Refused: something was observed and no number covers it.
            return SHEET_AIRDROP_DETERMINED if self.disposition_refusal(canonical) is None else SHEET_UNPRICED
        if values or any(state == ASSET_PROVEN_ZERO for state in states.values()):
            return SHEET_PROVEN_EMPTY if self.proven_empty_refusal(canonical) is None else SHEET_UNPRICED
        if self.typed_receipts_unresolved.get(canonical):
            # A typed receipt is on record, so this isn't ``no_rows``.
            return SHEET_UNPRICED
        return SHEET_NO_ROWS

    def total(self, key: str) -> float | None:
        """The priced total, or ``None`` when not a number (the three reasons stay apart in ``sheet_state``; only
        proven-empty reaches consumers as ``0.0``). A fully disposed sheet also answers ``0.0``; see
        :meth:`trimming_total` for what that may bound.
        """
        state = self.sheet_state(key)
        if state in (SHEET_PROVEN_EMPTY, SHEET_AIRDROP_DETERMINED):
            return 0.0
        if state in SHEET_NOT_DETERMINED:
            return None
        assets = self.per_asset.get(self.canonical(key)) or {}
        return _round_presented(sum(sorted(assets.values())))

    def trimming_total(self, key: str) -> float | None:
        """:meth:`total`, except a disposed sheet trims nothing.

        ``total`` answers what the entity holds (a determined $0 when disposed); trim sites ask how much there is to
        move, and disposed assets are still held (some are real tokens), so trimming to $0 would claim the call moves
        nothing.
        """
        if self.sheet_state(key) == SHEET_AIRDROP_DETERMINED:
            return None
        return self.total(key)

    @property
    def tracked_total(self) -> float:
        # Only determined totals enter the denominator.
        totals = [self.total(k) for k in set(self.per_asset) | set(self.per_asset_state)]
        return round(sum(sorted(t for t in totals if t is not None)), 2)


# The sheet ceiling's eight reasons: three admit (``admitted``, the earned negatives ``proven_empty`` and
# ``airdrop_determined``), five refuse for different unmeasured reasons. Tokens rather than a bool because the refusals
# are the work list.
CEILING_ADMITTED = "admitted"
CEILING_PROVEN_EMPTY = "proven_empty"
# The third admit: its claim is delivery shape, never worth.
CEILING_AIRDROP_DETERMINED = "airdrop_determined"
CEILING_NO_ROWS = "no_rows"
CEILING_BELOW_RESOLUTION = "below_resolution"
CEILING_UNPRICED = "unpriced"
CEILING_ASSET_LIST_TRUNCATED = "asset_list_truncated"
CEILING_ALIAS_AMBIGUOUS = "alias_ambiguous"

CEILING_REASONS = (
    CEILING_ADMITTED,
    CEILING_PROVEN_EMPTY,
    CEILING_AIRDROP_DETERMINED,
    CEILING_NO_ROWS,
    CEILING_BELOW_RESOLUTION,
    CEILING_UNPRICED,
    CEILING_ASSET_LIST_TRUNCATED,
    CEILING_ALIAS_AMBIGUOUS,
)

# Named, so a census testing ``reason == "admitted"`` doesn't count proven-zero ceilings as refusals.
CEILING_ADMITTING_REASONS = (CEILING_ADMITTED, CEILING_PROVEN_EMPTY, CEILING_AIRDROP_DETERMINED)

# Unregistered sheet states raise rather than refuse under another fact's reason.
_CEILING_REFUSALS: dict[str, str] = {
    SHEET_NO_ROWS: CEILING_NO_ROWS,
    SHEET_BELOW_RESOLUTION: CEILING_BELOW_RESOLUTION,
    SHEET_UNPRICED: CEILING_UNPRICED,
}


def ceiling_for(plane: ValuePlane, key: str) -> tuple[float | None, str]:
    """The most an entity's own priced sheet can bound a code seizure at: ``(usd, reason)``, with a number exactly on
    the admitting reasons.

    Only the value-side conjuncts (the sheet is determined; the key isn't a shared implementation). Capability-side
    conjuncts are the caller's. ``proven_empty`` stays distinct from ``admitted`` so a witnessed $0 isn't hidden or
    refused.

    The alias test uses the key as passed (safe: ambiguous keys canonicalize to themselves). A truncated asset list
    refuses first, even admits: its total is a floor, and a floor published as an upper bound is false. Callers:
    ``fold._entity_contribution`` and ``fold._unresolved_stake``; every reason is pinned by
    ``tests/test_value_plane_ceiling.py``.
    """
    if key in plane.alias_ambiguous:
        return None, CEILING_ALIAS_AMBIGUOUS
    if plane.asset_set_is_truncated(key):
        return None, CEILING_ASSET_LIST_TRUNCATED
    state = plane.sheet_state(key)
    if state == SHEET_PRICED:
        return plane.total(key), CEILING_ADMITTED
    if state == SHEET_PROVEN_EMPTY:
        # A literal: the state is the witness.
        return 0.0, CEILING_PROVEN_EMPTY
    if state == SHEET_AIRDROP_DETERMINED:
        return 0.0, CEILING_AIRDROP_DETERMINED
    refusal = _CEILING_REFUSALS.get(state)
    if refusal is None:
        raise ValueError(f"sheet state {state!r} has no registered ceiling reason")
    return None, refusal


_EPOCH = datetime.min

# Every published counter, so a rule that never fired reports zero.
_REDUCTION_COUNTERS = (
    "buckets",
    "single_reading_accounts",
    "multi_observation_accounts",
    "height_witnessed_accounts",
    "write_order_accounts",
    "write_order_decided_accounts",
    "write_order_disagreeing_accounts",
    "multi_account_buckets",
    "unwitnessed_account_buckets",
    "unpriced_supersession_accounts",
    "stale_high_water_marks_dropped",
)


def _write_order(row: Any) -> tuple[bool, Any, int]:
    """Insert order, for observations with no recorded read height."""
    return (row.fetched_at is not None, row.fetched_at or _EPOCH, int(row.id or 0))


def _latest_observation(rows: list[Any]) -> tuple[Any, bool]:
    """One account's current reading, and whether a block height decided it.

    Only block order proves currency, and ERC-20 rows usually have no height, so the fallback is write order (a database
    fact), flagged and counted.
    """
    if len(rows) == 1:
        return rows[0], rows[0].block_number is not None
    if all(row.block_number is not None for row in rows):
        return max(rows, key=lambda row: (row.block_number, _write_order(row))), True
    return max(rows, key=_write_order), False


def _is_proven_zero_quantity(row: Any) -> bool:
    """Whether the quantity is proven zero (worth 0 at any price). Unparseable balances prove nothing."""
    try:
        return float(str(row.raw_balance)) == 0.0
    except (TypeError, ValueError):
        return False


def _asset_reading(row: Any) -> tuple[float | None, str]:
    usd = _float(row.usd_value)
    if usd is None:
        # NULL is not determined, never 0.
        return None, ASSET_UNPRICED
    if usd != 0.0:
        return usd, ASSET_PRICED
    if _is_proven_zero_quantity(row):
        return 0.0, ASSET_PROVEN_ZERO
    return None, ASSET_BELOW_RESOLUTION


def _reduce_observations(
    observations: dict[tuple[str, str], dict[str, list[Any]]],
) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, str]], dict[str, Any]]:
    """Latest observation per account, summed across distinct accounts.

    Two readings of one account are one holding read twice (MAX would publish a stale high-water mark); two accounts are
    two holdings. Where an account identity is missing, fall back to MAX (counted), since summing could double count.
    Every counter is published even at zero.
    """
    per_asset: dict[str, dict[str, float]] = defaultdict(dict)
    per_asset_state: dict[str, dict[str, str]] = defaultdict(dict)
    counters: dict[str, int] = dict.fromkeys(_REDUCTION_COUNTERS, 0)
    for state in (ASSET_PRICED, ASSET_BELOW_RESOLUTION, ASSET_PROVEN_ZERO, ASSET_UNPRICED):
        counters[f"assets_{state}"] = 0
    stale_usd = 0.0
    write_order_selected_usd = 0.0
    write_order_spread_usd = 0.0

    for (key, asset), accounts in sorted(observations.items()):
        counters["buckets"] += 1
        readings: list[tuple[float | None, str]] = []
        for account in sorted(accounts):
            rows = accounts[account]
            competing = len(rows) > 1
            counters["multi_observation_accounts" if competing else "single_reading_accounts"] += 1
            row, height_witnessed = _latest_observation(rows)
            counters["height_witnessed_accounts" if height_witnessed else "write_order_accounts"] += 1
            readings.append(_asset_reading(row))
            priced = [value for value in (_float(candidate.usd_value) for candidate in rows) if value is not None]
            current = _float(row.usd_value)
            if competing and not height_witnessed:
                # How many readings write order actually decided, between differing figures, and the dollars it chose.
                counters["write_order_decided_accounts"] += 1
                if len(set(priced)) > 1:
                    counters["write_order_disagreeing_accounts"] += 1
                    write_order_spread_usd += max(priced) - min(priced)
                    if current is not None:
                        write_order_selected_usd += current
            if priced and current is None:
                # A determined value disappears when the current reading has no price.
                counters["unpriced_supersession_accounts"] += 1
            highest = max(priced, default=None)
            if highest is not None and current is not None and highest > current:
                counters["stale_high_water_marks_dropped"] += 1
                stale_usd += highest - current

        if len(accounts) > 1:
            counters["multi_account_buckets"] += 1
            if "" in accounts:
                counters["unwitnessed_account_buckets"] += 1

        determined = [value for value, state in readings if value is not None]
        if any(state == ASSET_PRICED for _, state in readings):
            state = ASSET_PRICED
            value = max(determined) if "" in accounts and len(accounts) > 1 else sum(determined)
        elif any(pair[1] == ASSET_BELOW_RESOLUTION for pair in readings):
            state, value = ASSET_BELOW_RESOLUTION, None
        elif any(pair[1] == ASSET_UNPRICED for pair in readings):
            state, value = ASSET_UNPRICED, None
        else:
            state, value = ASSET_PROVEN_ZERO, 0.0
        counters[f"assets_{state}"] += 1
        per_asset_state[key][asset] = state
        if value is not None:
            per_asset[key][asset] = _round_presented(value)

    reduction: dict[str, Any] = dict(sorted(counters.items()))
    reduction["stale_high_water_usd_dropped"] = round(stale_usd, 2)
    reduction["write_order_selected_usd"] = round(write_order_selected_usd, 2)
    reduction["write_order_spread_usd"] = round(write_order_spread_usd, 2)
    return (
        {k: dict(sorted(v.items())) for k, v in sorted(per_asset.items())},
        {k: dict(sorted(v.items())) for k, v in sorted(per_asset_state.items())},
        reduction,
    )


class AliasCycleError(ValueError): ...


def _alias_fixed_point(alias: dict[str, str]) -> dict[str, str]:
    """Resolve ``J -> I -> P`` to ``J -> P`` (a single level orphans J and double counts P).

    Cycles raise rather than pick a member.
    """
    out: dict[str, str] = {}
    for key in sorted(alias):
        seen = [key]
        current = alias[key]
        while current in alias and alias[current] != current:
            if current in seen:
                raise AliasCycleError("implementation alias cycle: " + " -> ".join([*seen, current]))
            seen.append(current)
            current = alias[current]
        out[key] = current
    return out


def _balance_account(row: Any) -> Any:
    """The account a balance row is keyed on: ``contracts.id`` or ``(entity_chain, entity_address)`` (the schema
    populates exactly one).
    """
    if row.contract_id is not None:
        return row.contract_id
    return (row.entity_chain or "", row.entity_address or "")


def _account_sort_key(item: tuple[Any, Any]) -> tuple[int, str]:
    """Total order over both account kinds: contracts by id, then entity accounts."""
    account = item[0]
    if isinstance(account, tuple):
        return (1, "::".join(str(part) for part in account))
    return (0, f"{int(account):012d}")


def _implementation_alias(
    rows: Iterable[tuple[str | None, str | None, str | None]],
) -> tuple[dict[str, str], set[str], dict[str, set[str]]]:
    """Proxy -> implementation fold from ``(chain, address, implementation)`` rows.

    Two proxies sharing an implementation fold it onto neither (pinning one would charge the other's sheet) and publish
    the collision.
    """
    impl_to_proxy: dict[str, str] = {}
    impl_proxies: dict[str, set[str]] = defaultdict(set)
    for chain, address, implementation in rows:
        if not implementation:
            continue
        chain_tok = coalesce_chain(chain)
        impl_key = entity_key(chain_tok, implementation)
        proxy_key = entity_key(chain_tok, address)
        impl_proxies[impl_key].add(proxy_key)
        impl_to_proxy[impl_key] = proxy_key
    ambiguous = {impl for impl, proxies in impl_proxies.items() if len(proxies) > 1}
    for impl in ambiguous:
        impl_to_proxy.pop(impl, None)
    return _alias_fixed_point(impl_to_proxy), ambiguous, impl_proxies


def load_entity_alias(session: Session, protocol_id: int) -> tuple[dict[str, str], set[str]]:
    """Only the proxy/impl fold, same rules as :func:`load_value_plane`."""
    from db.models import Contract

    rows = (
        session.query(Contract.chain, Contract.address, Contract.implementation)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(Contract.id)
        .all()
    )
    alias, ambiguous, _ = _implementation_alias(
        (chain, address, implementation) for chain, address, implementation in rows
    )
    return alias, ambiguous


def load_value_plane(session: Session, protocol_id: int) -> ValuePlane:
    from db.models import Contract, ContractBalanceFetch, ContractBalanceLatest, RestakingPositionLatest
    from services.monitoring.balance_reads import (
        ObservationSubject,
        latest_partial_asset_fetches,
        latest_partial_entity_asset_fetches,
        native_balance_fact,
        winning_asset_fetches,
        winning_entity_asset_fetches,
    )

    plane = ValuePlane()
    contracts = session.query(Contract).filter(Contract.protocol_id == protocol_id).order_by(Contract.id).all()
    # An account is a ``contracts.id`` or an entity's ``(chain, address)``; disjoint types, so they can't collide.
    chain_of: dict[Any, str] = {}
    address_of: dict[Any, str] = {}
    for contract in contracts:
        chain = coalesce_chain(contract.chain)
        chain_of[contract.id] = chain
        address_of[contract.id] = _lower(contract.address)
        plane.contract_entities.add(entity_key(chain, contract.address))
    alias, ambiguous, impl_proxies = _implementation_alias(
        (contract.chain, contract.address, contract.implementation) for contract in contracts
    )
    shared_impl = [{"implementation": impl, "proxies": sorted(impl_proxies[impl])} for impl in sorted(ambiguous)]
    plane.alias = alias
    plane.alias_ambiguous = ambiguous

    # Proven-codeless principals the control graph reached with no ``contracts`` row, loaded by identity (membership is
    # the ``eth_getCode`` witness).
    entity_identities = sorted(
        (chain, address)
        for chain, _, address in (key.partition("::") for key in load_proven_eoa_entities(session, protocol_id))
        if chain and address
    )
    entity_subjects = [ObservationSubject.of_entity(chain, address) for chain, address in entity_identities]
    for chain, address in entity_identities:
        chain_of[(chain, address)] = chain
        address_of[(chain, address)] = address

    native_seen: set[str] = set()
    fetched: list[Any] = []
    rows = (
        session.query(ContractBalanceLatest)
        .join(Contract, Contract.id == ContractBalanceLatest.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ContractBalanceLatest.contract_id, ContractBalanceLatest.token_address, ContractBalanceLatest.id)
        .all()
    )
    if entity_identities:
        rows = list(rows) + (
            session.query(ContractBalanceLatest)
            .filter(
                ContractBalanceLatest.contract_id.is_(None),
                tuple_(ContractBalanceLatest.entity_chain, ContractBalanceLatest.entity_address).in_(entity_identities),
            )
            .order_by(
                ContractBalanceLatest.entity_chain,
                ContractBalanceLatest.entity_address,
                ContractBalanceLatest.token_address,
                ContractBalanceLatest.id,
            )
            .all()
        )
    # One bucket per (entity, asset, account): a proxy and its implementation are the same account read twice, not two
    # holdings.
    observations: dict[tuple[str, str], dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        account = _balance_account(row)
        key = plane.canonical(entity_key(chain_of.get(account), address_of.get(account)))
        # NULL ``token_address`` is the native asset by definition.
        asset = _lower(row.token_address) if row.token_address else NATIVE_ASSET
        if asset == NATIVE_ASSET:
            native_seen.add(key)
        if row.fetched_at is not None:
            fetched.append(row.fetched_at)
        observations[(key, asset)][_lower(row.observed_address)].append(row)

    per_asset, per_asset_state, reduction = _reduce_observations(observations)
    plane.per_asset = per_asset
    plane.per_asset_state = per_asset_state

    latest_fetch: dict[Any, Any] = {}
    fetch_rows = list(
        session.query(ContractBalanceFetch)
        .join(Contract, Contract.id == ContractBalanceFetch.contract_id)
        .filter(Contract.protocol_id == protocol_id)
        .order_by(ContractBalanceFetch.contract_id, ContractBalanceFetch.fetched_at, ContractBalanceFetch.id)
        .all()
    )
    if entity_identities:
        fetch_rows += (
            session.query(ContractBalanceFetch)
            .filter(
                ContractBalanceFetch.contract_id.is_(None),
                tuple_(ContractBalanceFetch.entity_chain, ContractBalanceFetch.entity_address).in_(entity_identities),
            )
            .order_by(
                ContractBalanceFetch.entity_chain,
                ContractBalanceFetch.entity_address,
                ContractBalanceFetch.fetched_at,
                ContractBalanceFetch.id,
            )
            .all()
        )
    for fetch in fetch_rows:
        if fetch.native_status != STATUS_UNATTEMPTED:
            latest_fetch[_balance_account(fetch)] = fetch
    # Completeness is read from the fetch whose rows were loaded, not the latest (a later failure would hide the
    # truncation).
    winning_asset_fetch: dict[Any, Any] = dict(winning_asset_fetches(session, protocol_id))
    entity_winners = winning_entity_asset_fetches(session, entity_subjects)
    partial_accounts: set[Any] = set(latest_partial_asset_fetches(session, protocol_id, winners=winning_asset_fetch))
    partial_accounts.update(
        (subject.chain, subject.address)
        for subject in latest_partial_entity_asset_fetches(session, entity_subjects, winners=entity_winners)
    )
    # A newer capped observation still invalidates completeness and empty-sheet claims.
    for account in partial_accounts:
        plane.asset_set_truncated.add(plane.canonical(entity_key(chain_of.get(account), address_of.get(account))))
    for subject, fetch in entity_winners.items():
        winning_asset_fetch[(subject.chain, subject.address)] = fetch
    # Every account folding onto a key: the list is whole only if each was scanned at its own address. An unscanned
    # implementation folded into a proxy's sheet would otherwise be declared empty.
    accounts_of: dict[str, set[Any]] = defaultdict(set)
    for contract in contracts:
        accounts_of[plane.canonical(entity_key(chain_of[contract.id], address_of[contract.id]))].add(contract.id)
    # An entity subject is its own single account and gets the same scan requirement.
    for account in entity_identities:
        accounts_of[plane.canonical(entity_key(chain_of[account], address_of[account]))].add(account)
    scanned: dict[str, list[dict[str, Any]]] = defaultdict(list)
    typed_unresolved: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for account, fetch in sorted(winning_asset_fetch.items(), key=_account_sort_key):
        key = plane.canonical(entity_key(chain_of.get(account), address_of.get(account)))
        # A truncated list holds whether or not a native row exists; unioned over folded accounts.
        if fetch.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP:
            plane.asset_set_truncated.add(key)
        # A malformed typed record is unreadable evidence, not an empty one.
        entries = fetch.typed_assets if isinstance(fetch.typed_assets, list) else None
        for entry in entries or ():
            if typed_receipt_is_resolved(entry):
                continue
            typed_unresolved[key].append(
                {
                    "asset": _lower(entry.get("address")) if isinstance(entry, dict) else None,
                    "quantity_readable": bool(isinstance(entry, dict) and entry.get("quantity_readable") is True),
                    "quantity": (str(entry.get("quantity")) if isinstance(entry, dict) else None),
                }
            )
        if (
            fetch.asset_set_source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP
            and fetch.sweep_status == SWEEP_STATUS_COMPLETED
            and fetch.swept_through_block is not None
            and entries is not None
            # The scan must be issued at this account's own address; a proxy scan filed against its implementation's row
            # proves nothing about the implementation.
            and _lower(fetch.observed_address) == address_of.get(account)
        ):
            scanned[key].append(
                {
                    "account": account,
                    "source": str(fetch.asset_set_source),
                    "swept_from_block": int(fetch.swept_from_block or 0),
                    "swept_through_block": int(fetch.swept_through_block),
                    "basis": fetch.asset_set_basis,
                }
            )
    plane.typed_receipts_unresolved = {key: records for key, records in sorted(typed_unresolved.items())}
    for key, records in sorted(scanned.items()):
        unscanned = accounts_of.get(key, set()) - {record["account"] for record in records}
        if unscanned:
            # Named: the one refusal a producer cycle can close.
            plane.asset_set_accounts_unscanned[key] = sorted(address_of.get(account) or "" for account in unscanned)
            continue
        if key in plane.asset_set_truncated:
            # Contradictory witnesses (one scanned, one capped) refuse.
            continue
        plane.asset_set_proven_complete[key] = {
            "source": ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            # Both figures, so a two-account sheet can't read as fully scanned.
            "accounts_scanned": len(records),
            "accounts_folded": len(accounts_of.get(key, ())),
            "accounts": sorted(address_of.get(record["account"]) or "" for record in records),
            # The weakest end of the accounts' scans.
            "swept_from_block": max(record["swept_from_block"] for record in records),
            "swept_through_block": min(record["swept_through_block"] for record in records),
            # The carriers' basis strings, verbatim.
            "basis": [record["basis"] for record in records if record["basis"]],
        }
    # The native discriminator for an absent native row, per entity: taken from the canonical account's own fetch (a
    # folded implementation's fetch once published a stale ``proven_zero`` over a proxy holding ETH), and nothing when
    # accounts disagree on polarity.
    native_by_account: dict[str, dict[str, str]] = defaultdict(dict)
    for account, fetch in sorted(latest_fetch.items(), key=_account_sort_key):
        own = entity_key(chain_of.get(account), address_of.get(account))
        native_by_account[plane.canonical(own)][own] = native_balance_fact(fetch.native_status, fetch.block_number)
    native_facts_refused_on_disagreement = 0
    for key, by_account in sorted(native_by_account.items()):
        if key in native_seen:
            continue
        polarities = {fact.split("_at_block")[0] for fact in by_account.values()}
        if len(polarities) > 1:
            native_facts_refused_on_disagreement += 1
            plane.native_fact[key] = "not_determined"
            continue
        plane.native_fact[key] = by_account.get(key, "not_determined")

    # The restaking plane has no USD column: MAX per node, published as unpriced quantities.
    positions = (
        session.query(RestakingPositionLatest)
        .filter(RestakingPositionLatest.protocol_id == protocol_id)
        .order_by(RestakingPositionLatest.chain_id, RestakingPositionLatest.node_address)
        .all()
    )
    unpriced: dict[str, dict[str, float]] = defaultdict(dict)
    residual_seen = False
    # Every drop is counted, or it would read as a node holding nothing.
    dropped: dict[str, int] = {
        "unknown_chain_id": 0,
        "shares_basis_not_admissible": 0,
        "shares_unreadable": 0,
        "cross_read_inconsistent": 0,
    }
    for position in positions:
        chain = _chain_name(position.chain_id)
        if chain is None:
            dropped["unknown_chain_id"] += 1
            continue
        key = plane.canonical(entity_key(chain, position.node_address))
        shares = _float(position.eigenlayer_beacon_shares_wei)
        if position.shares_basis not in ("eigenlayer_beacon_shares", "no_eigenpod_proven"):
            dropped["shares_basis_not_admissible"] += 1
            continue
        if shares is None:
            dropped["shares_unreadable"] += 1
            continue
        if position.cross_read_agreement == "inconsistent":
            dropped["cross_read_inconsistent"] += 1
            continue
        previous = unpriced[key].get("eigenlayer_beacon_shares_wei")
        if previous is None or shares > previous:
            unpriced[key]["eigenlayer_beacon_shares_wei"] = shares
        residual_seen = residual_seen or position.consensus_layer_residual is not None
    plane.unpriced_positions = {
        key: [{"asset": asset, "quantity_wei": qty} for asset, qty in sorted(assets.items())]
        for key, assets in sorted(unpriced.items())
    }
    if positions:
        plane.annotations.append(
            {
                "fact": "restaking positions folded as UNPRICED entity contributions",
                "entities": len(plane.unpriced_positions),
                "positions_read": len(positions),
                "positions_dropped": dict(sorted(dropped.items())),
                "note": (
                    "the plane carries no USD column and pricing it would need a "
                    "banned price source, so these quantities raise a confidence gap "
                    "and never a band; node_set_completeness is not_determined, so "
                    "any cross-node aggregate is a floor"
                ),
                "consensus_layer_residual": (
                    "not_determined and BANNED as a number; never read as 0" if residual_seen else "no rows"
                ),
            }
        )

    # ``native_status = proven_zero`` becomes an asset reading only on sheets whose list a chain scan proved whole:
    # together they mean the entity holds nothing. A stored native row always wins; the fact is the entity's own and
    # refused where accounts disagree.
    native_proven_zero_readings = 0
    for key in sorted(plane.asset_set_proven_complete):
        if key in native_seen:
            continue
        if not (plane.native_fact.get(key) or "").startswith("proven_zero"):
            continue
        plane.per_asset.setdefault(key, {})[NATIVE_ASSET] = 0.0
        plane.per_asset_state.setdefault(key, {})[NATIVE_ASSET] = ASSET_PROVEN_ZERO
        native_proven_zero_readings += 1

    # Every state, including empty ones.
    sheet_states: dict[str, int] = dict.fromkeys(
        (
            SHEET_PRICED,
            SHEET_BELOW_RESOLUTION,
            SHEET_UNPRICED,
            SHEET_PROVEN_EMPTY,
            SHEET_AIRDROP_DETERMINED,
            SHEET_NO_ROWS,
        ),
        0,
    )
    # Over the typed-receipt-only entities and the base population too, folded canonically: otherwise the census
    # undercounts ``unpriced`` and can never report ``no_rows``.
    for key in sorted(
        {plane.canonical(key) for key in plane.contract_entities}
        | set(plane.per_asset)
        | set(plane.per_asset_state)
        | set(plane.typed_receipts_unresolved)
    ):
        sheet_states[plane.sheet_state(key)] += 1

    # The empty claim's refusal census over all-zero sheets, published even at zero.
    empty_refused: dict[str, int] = dict.fromkeys(EMPTY_REFUSALS, 0)
    empty_admitted = 0
    # The complement: a held typed receipt adds a non-zero row and drops its sheet out of the all-zero population, so
    # both are published and sum to every refused sheet.
    empty_refused_outside: dict[str, int] = dict.fromkeys(EMPTY_REFUSALS, 0)
    # Includes sheets refused for an unscanned account with no reading at all (the reading is missing because the
    # refusal fired).
    for key in sorted(
        set(plane.per_asset)
        | set(plane.per_asset_state)
        | set(plane.typed_receipts_unresolved)
        | set(plane.asset_set_accounts_unscanned)
    ):
        states_at_key = plane.per_asset_state.get(key) or {}
        in_population = not any(state != ASSET_PROVEN_ZERO for state in states_at_key.values()) and bool(
            states_at_key or plane.typed_receipts_unresolved.get(key)
        )
        refusal = plane.proven_empty_refusal(key)
        if not in_population:
            if refusal is not None:
                empty_refused_outside[refusal] += 1
            continue
        if refusal is None:
            empty_admitted += 1
        else:
            empty_refused[refusal] += 1

    if reduction.get(f"assets_{ASSET_BELOW_RESOLUTION}"):
        plane.annotations.append(
            {
                "fact": "priced readings at the storage column's resolution floor are NOT proven zeros",
                "assets": reduction[f"assets_{ASSET_BELOW_RESOLUTION}"],
                "entities": sheet_states[SHEET_BELOW_RESOLUTION],
                "note": (
                    "usd_value is a scaled decimal column, so a holding below its last digit "
                    "stores as 0.00. Such a reading answers 'below the column's resolution', "
                    "never 'holds nothing', and an entity whose every priced reading is one has "
                    "NO determined total. Only a proven-zero QUANTITY witnesses an empty sheet"
                ),
                "proven_zero_quantity_assets": reduction.get(f"assets_{ASSET_PROVEN_ZERO}", 0),
                "proven_zero_arm_exercised": bool(reduction.get(f"assets_{ASSET_PROVEN_ZERO}")),
            }
        )

    plane.contract_entities = {plane.canonical(key) for key in plane.contract_entities}
    plane.provenance = {
        "entity_key": "effective_functions.deployment_address -> contracts.address, chain-scoped",
        "contract_entities": len(plane.contract_entities),
        "reduction": (
            "latest observation per (entity, asset, observed account); SUM across DISTINCT observed accounts"
        ),
        "observation_reduction": reduction,
        "observation_reduction_reading": (
            "two readings of ONE account are one holding read twice, so the later one is the "
            "answer and MAX would publish a stale high-water mark; two readings of TWO accounts "
            "are two holdings and the entity holds their sum. height_witnessed_accounts were "
            "ordered by block_number; write_order_accounts had no recorded read height (ERC-20 "
            "rows are never height-pinned by construction) and fell back to insert order, which "
            "is a fact about this database and not about the chain. write_order_accounts counts "
            "the ordering BASIS and includes single_reading_accounts, where nothing was ordered; "
            "write_order_decided_accounts is the subset the fallback actually decided, of which "
            "write_order_disagreeing_accounts decided between figures that DIFFER. "
            "write_order_selected_usd is the dollars those decisions selected and "
            "write_order_spread_usd the max-minus-min they were selected from — together the "
            "size of the fiat, not a claim that the selected figure is wrong"
        ),
        "sheet_states": dict(sorted(sheet_states.items())),
        "sheet_states_reading": (
            "priced = a determined non-zero reading, so the total is a floor; "
            "priced_below_resolution = every price that answered landed on the storage column's "
            "resolution floor and the total is NOT a number; unpriced = no price answered; proven_empty = "
            "every quantity proven zero, the only state in which 0.00 is a number; "
            "no_rows = nothing observed. "
            "The census is taken over this plane's BASE POPULATION (contract_entities, folded "
            "onto canonical keys) unioned with every entity the observation maps carry, so "
            "no_rows counts the entities the protocol names and nobody has read — a count "
            "taken over the observations alone could only ever report 0 there, which is not "
            "the same fact"
        ),
        "asset_set_completeness": {
            "entities_proven_complete": len(plane.asset_set_proven_complete),
            "entities_proven_truncated": len(plane.asset_set_truncated),
            "completeness_source": ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
            "native_proven_zero_sheet_readings": native_proven_zero_readings,
            "native_facts_refused_on_cross_account_disagreement": native_facts_refused_on_disagreement,
            "entities_with_unresolved_typed_receipts": len(plane.typed_receipts_unresolved),
            "unresolved_typed_receipts": sum(len(v) for v in plane.typed_receipts_unresolved.values()),
            "entities_with_an_unscanned_folded_account": len(plane.asset_set_accounts_unscanned),
            "unscanned_folded_accounts": sum(len(v) for v in plane.asset_set_accounts_unscanned.values()),
            "accounts_scanned_over_accounts_folded": {
                "scanned": sum(int(r["accounts_scanned"]) for r in plane.asset_set_proven_complete.values()),
                "folded": sum(int(r["accounts_folded"]) for r in plane.asset_set_proven_complete.values()),
            },
            "sheets_published_empty": empty_admitted,
            "sheets_refused_empty_by_reason": dict(sorted(empty_refused.items())),
            "sheets_refused_empty_by_reason_outside_the_all_zero_population": dict(
                sorted(empty_refused_outside.items())
            ),
            "reading": (
                "the two completeness figures are NOT complements: proven_complete is an earned "
                "positive and proven_truncated an earned negative, and an entity in neither is the "
                "third state. The positive is earned PER ACCOUNT: a sheet sums over every contract "
                "row that folds onto its key, so it is whole only where the chain's transfer "
                "history was scanned at EVERY one of those addresses, at that address itself — a "
                "scan of a proxy filed against its implementation's row proves nothing about the "
                "implementation's address, which is why accounts_scanned is published beside "
                "accounts_folded and why folded_account_never_scanned is its own refusal rather "
                "than a shade of 'nobody scanned this'. Only a proven-complete sheet admits an "
                "empty one as a proven $0; every refusal publishes unpriced, never a zero. "
                "sheets_refused_empty_by_reason counts ONLY the sheets whose every reading is a "
                "proven zero — the population the empty claim was ever available to — so it is NOT "
                "the count of entities a reason refuses, and reading it against "
                "entities_with_unresolved_typed_receipts as though it were will mislead: a receipt "
                "read back as a HELD item writes a non-zero count row, which drops its sheet out of "
                "that population while still refusing it. Those sheets are counted in "
                "sheets_refused_empty_by_reason_outside_the_all_zero_population, and the two dicts "
                "sum per reason to every refused sheet in the plane. Most of the "
                "asset_set_not_proven_complete entries in the second are sheets holding real money, "
                "which were never candidates for an empty claim at all"
            ),
        },
        # The fold's exposure denominator, published directly; an empty priced sheet is not determined.
        "tracked_total_usd": plane.tracked_total if plane.per_asset else None,
        "tracked_total_usd_reading": (
            "latest observation per (entity, asset, observed account), implementation folded "
            "onto its proxy; entities with no determined total contribute nothing and are not "
            "read as 0, so this is a floor. null = no priced entity in the perimeter"
        ),
        "balance_rows": len(rows),
        "restaking_rows": len(positions),
        "shared_implementations": shared_impl,
        "shared_implementation_aliases_refused": len(shared_impl),
        "shared_implementation_reading": (
            "an implementation two proxies share folds onto NEITHER: it keeps its own entity "
            "key, so a reach that lands on it is charged that key's own sheet and never the "
            "sheet of whichever proxy an arbitrary pin happened to select. A zero here is the "
            "proven 'no implementation is shared', not an unasked question"
        ),
        "implementation_alias_fixed_point": (
            "resolved transitively, so J->I beside I->P answers P for J; a cycle raises rather than selecting a member"
        ),
        "fetched_at_span_seconds": (
            round((max(fetched) - min(fetched)).total_seconds(), 3) if len(fetched) > 1 else None
        ),
        "fetched_at_is_a_write_timestamp": (
            "not an observation height; a cross-contract sum is not a single-block quantity"
        ),
        "absent_native_row": "not_determined unless contract_balance_fetches.native_status proves zero",
    }
    return plane


def load_proven_eoa_entities(session: Session, protocol_id: int) -> set[str]:
    """Entity keys proven codeless: ``resolved_type == 'eoa'`` is only written after an empty ``eth_getCode`` (RPC
    failures classify as ``contract``).
    """
    from db.models import Contract, ControlGraphNode

    rows = (
        session.query(ControlGraphNode.address, Contract.chain)
        .join(Contract, Contract.id == ControlGraphNode.contract_id)
        .filter(Contract.protocol_id == protocol_id, ControlGraphNode.resolved_type == "eoa")
        .order_by(ControlGraphNode.id)
        .all()
    )
    return {entity_key(chain, address) for address, chain in rows}
