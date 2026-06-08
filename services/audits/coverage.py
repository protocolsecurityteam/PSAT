"""Match audit reports to the contracts they actually reviewed.

Populates the ``audit_contract_coverage`` join table so "has this impl been
audited?" is a cheap join, not a query-time scan of ``scope_contracts[]``.
Proxy-aware: a coverage row links the *implementation* contract the audit
reviewed, not the proxy — using ``UpgradeEvent`` history to pin the audit
to the right era.

Two symmetric entry points call the same core matcher:

    match_contracts_for_audit(session, audit_id)     # scope_contracts → Contracts
    match_audits_for_contract(session, contract_id)  # Contract name → AuditReports

Both produce ``CoverageMatch`` records. ``upsert_coverage_for_audit`` (and
the ``upsert_coverage_for_protocol`` wrapper) writes them to the DB with
idempotent delete-then-insert semantics so re-running is safe and scope
re-extractions pick up cleanly.

Matching signals are layered, cheapest first:

  - ``'direct'`` — scope name matches a Contract.contract_name. No proxy
    history; confidence=high if audit has a date, medium if not.
  - ``'impl_era'`` — scope name matches AND the impl was active at the
    audit's date per ``UpgradeEvent`` history. Confidence=high inside
    window, medium in a 14-day grace zone on either boundary, low when
    clearly outside.
  - ``'reviewed_commit'`` — source-equivalence proof (see
    ``services/audits/source_equivalence.py``). The audit PDF references
    a commit whose source file is byte-identical to Etherscan's verified
    source for the matched impl. Overrides temporal confidence with
    high — this is definitive evidence the audit reviewed the deployed
    code. Opt-in via ``verify_source_equivalence=True`` because it
    costs ~2 HTTP requests per (scope-contract × reviewed-commit) pair.

The ``AuditReport.source_commit`` field is a *discovery-time* SHA (where
the PDF was found in an org's repo), not a review-commit anchor. The
real reviewed commits live in ``AuditReport.reviewed_commits``, extracted
from PDF text by scope extraction and then consumed by the source-
equivalence pass.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final

from sqlalchemy import case, func, or_, select
from sqlalchemy import delete as sql_delete
from sqlalchemy.orm import Session

from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    UpgradeEvent,
)

logger = logging.getLogger(__name__)


# Grace zone around an impl's active range — audits published shortly
# after an upgrade usually reviewed the older impl (engagement predates
# publication). 14d catches the common case without overreaching.
GRACE_DAYS: Final[int] = 14


# --- Result types -------------------------------------------------------


@dataclass(frozen=True)
class ImplWindow:
    """A contiguous span during which an address was an active impl."""

    proxy_contract_id: int  # Contract.id of the proxy this window is on
    proxy_address: str
    from_block: int
    to_block: int | None  # None = still current on this proxy
    from_ts: datetime | None
    to_ts: datetime | None


@dataclass(frozen=True)
class CoverageMatch:
    """One contract ↔ audit link that ``upsert_coverage_for_audit`` will persist."""

    audit_report_id: int
    contract_id: int
    protocol_id: int
    matched_name: str
    match_type: str  # 'direct' | 'impl_era' | 'reviewed_address' | 'reviewed_commit'
    match_confidence: str  # 'high' | 'medium' | 'low'
    covered_from_block: int | None = None
    covered_to_block: int | None = None
    # Runtime bytecode keccak256 of the impl at the moment this match was
    # resolved. Populated by ``_apply_bytecode_anchor`` during HTTP phase.
    # NULL propagates when the RPC call failed — the UI treats NULL as
    # "drift unknown" rather than "drift detected".
    bytecode_keccak_at_match: str | None = None
    verified_at: datetime | None = None
    # Source-equivalence verdict for this specific (audit × matched_name)
    # pair. See services.audits.source_equivalence.EQUIVALENCE_STATUSES.
    # None means verification never ran — should only happen on legacy
    # rows predating the rollout.
    equivalence_status: str | None = None
    equivalence_reason: str | None = None
    equivalence_checked_at: datetime | None = None
    # Phase F: the specific commit the auditor tied to THIS contract in
    # the scope table, when available. Sourced from
    # ``AuditReport.scope_entries[*].commit``. When non-null, source-
    # equivalence uses only this commit instead of treating every SHA in
    # the audit text as a candidate. Not persisted to the DB — it's a
    # runtime hint from matcher to verifier inside one upsert cycle.
    pinned_commit: str | None = None
    # Phase C: strength kind for ``equivalence_status='proven'`` rows.
    # See db.models.AuditContractCoverage.proof_kind for the vocabulary.
    proof_kind: str | None = None
    # The specific commit SHA from ``classified_commits`` that this row's
    # bytecode matched, when verification resolved to one. Preference is
    # for commits labeled ``reviewed`` so the UI can link to the commit the
    # auditor actually reviewed. None on heuristic-only matches.
    matched_commit_sha: str | None = None


# --- Date parsing -------------------------------------------------------


def _audit_effective_ts(audit_date: str | None) -> datetime | None:
    """Parse ``AuditReport.date`` into a tz-aware datetime (end-of-period).

    Accepts ``YYYY-MM-DD`` / ``YYYY-MM`` / ``YYYY-MM-00`` / ``YYYY``. Returns
    ``None`` on malformed input so coverage downgrades to ``low`` instead
    of crashing. End-of-period semantics are deliberate — audits finalize
    late in the stated period.
    """
    if not audit_date:
        return None
    s = audit_date.strip()
    if not s:
        return None

    # YYYY-MM-DD
    if len(s) >= 10 and s[4] == "-" and s[7] == "-":
        y, m, d = s[0:4], s[5:7], s[8:10]
        try:
            year, month, day = int(y), int(m), int(d)
            if day == 0:
                # YYYY-MM-00 placeholder → end of month
                return _end_of_month(year, month)
            return datetime(year, month, day, 23, 59, 59, tzinfo=timezone.utc)
        except ValueError:
            return None

    # YYYY-MM
    if len(s) == 7 and s[4] == "-":
        try:
            return _end_of_month(int(s[0:4]), int(s[5:7]))
        except ValueError:
            return None

    # YYYY
    if len(s) == 4 and s.isdigit():
        try:
            return datetime(int(s), 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        except ValueError:
            return None

    return None


def _end_of_month(year: int, month: int) -> datetime:
    """Return the last second of the given month as tz-aware UTC."""
    if month == 12:
        first_of_next = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        first_of_next = datetime(year, month + 1, 1, tzinfo=timezone.utc)
    return first_of_next - timedelta(seconds=1)


# --- Impl window computation --------------------------------------------


def _compute_impl_windows_batch(session: Session, contracts: list[Contract]) -> dict[int, list[ImplWindow]]:
    """Return impl windows for each input contract, keyed by Contract.id.

    Batched replacement for per-contract ``_compute_impl_windows_for_contract``:
    fires ONE proxy-lookup and ONE event-history query regardless of how
    many candidate contracts are passed. Callers iterating over large
    candidate lists (e.g. ``match_contracts_for_audit`` on a protocol
    with many scope-name matches) see O(1) queries instead of O(N*K).
    """
    addr_to_ids: dict[str, list[int]] = {}
    for c in contracts:
        if c.address:
            addr_to_ids.setdefault(c.address.lower(), []).append(c.id)
    result: dict[int, list[ImplWindow]] = {c.id: [] for c in contracts}
    if not addr_to_ids:
        return result

    # One query: every (proxy_contract_id, new_impl) where new_impl is in
    # the candidate address set. ``new_impl`` may be mixed-case, so we
    # lowercase on both sides and project it back for the addr→impl map.
    proxy_rows = session.execute(
        select(
            UpgradeEvent.contract_id,
            func.lower(UpgradeEvent.new_impl).label("new_impl_lc"),
        )
        .where(func.lower(UpgradeEvent.new_impl).in_(list(addr_to_ids.keys())))
        .distinct()
    ).all()
    if not proxy_rows:
        return result

    proxy_ids = {row[0] for row in proxy_rows}
    # addr → set of proxy contract_ids that ever pointed at this address.
    addr_to_proxies: dict[str, set[int]] = {}
    for pid, impl_addr in proxy_rows:
        addr_to_proxies.setdefault(impl_addr, set()).add(pid)

    # One query: full event history for all relevant proxies, ordered
    # canonically. Events with NULL block_number sink so a hand-crafted
    # (test) event without blocks doesn't corrupt ordering.
    events_by_proxy: dict[int, list[UpgradeEvent]] = {pid: [] for pid in proxy_ids}
    events = (
        session.execute(
            select(UpgradeEvent)
            .where(UpgradeEvent.contract_id.in_(proxy_ids))
            .order_by(
                UpgradeEvent.contract_id.asc(),
                UpgradeEvent.block_number.asc().nullslast(),
                UpgradeEvent.id.asc(),
            )
        )
        .scalars()
        .all()
    )
    for ev in events:
        events_by_proxy.setdefault(ev.contract_id, []).append(ev)

    # One query: Contract rows for every relevant proxy, for the
    # ``proxy_address`` display field on ImplWindow.
    proxy_addr_by_id: dict[int, str] = {}
    if proxy_ids:
        rows = session.execute(select(Contract.id, Contract.address).where(Contract.id.in_(proxy_ids))).all()
        for pid, addr in rows:
            proxy_addr_by_id[pid] = addr or ""

    # Build a window list per (lowercase address) once; then distribute to
    # every Contract.id whose address matches (identical impl addresses on
    # different rows is rare, but the invariant costs nothing).
    windows_by_addr: dict[str, list[ImplWindow]] = {}
    for addr_lower, proxy_id_set in addr_to_proxies.items():
        windows: list[ImplWindow] = []
        for pid in proxy_id_set:
            proxy_events = events_by_proxy.get(pid) or []
            for i, ev in enumerate(proxy_events):
                if not ev.new_impl or ev.new_impl.lower() != addr_lower:
                    continue
                from_block = ev.block_number or 0
                from_ts = ev.timestamp
                to_block: int | None = None
                to_ts: datetime | None = None
                if i + 1 < len(proxy_events):
                    nxt = proxy_events[i + 1]
                    to_block = nxt.block_number
                    to_ts = nxt.timestamp
                windows.append(
                    ImplWindow(
                        proxy_contract_id=pid,
                        proxy_address=proxy_addr_by_id.get(pid, ""),
                        from_block=from_block,
                        to_block=to_block,
                        from_ts=from_ts,
                        to_ts=to_ts,
                    )
                )
        # Deterministic order so callers (and tests) can rely on it.
        windows.sort(key=lambda w: (w.from_block, w.proxy_contract_id))
        windows_by_addr[addr_lower] = windows

    for addr_lower, contract_ids in addr_to_ids.items():
        ws = windows_by_addr.get(addr_lower, [])
        for cid in contract_ids:
            # Copy so distinct list identity per contract_id, cheap for small lists.
            result[cid] = list(ws)
    return result


def _compute_impl_windows_for_contract(session: Session, contract: Contract) -> list[ImplWindow]:
    """Return windows during which ``contract.address`` was an active impl.

    Thin wrapper around :func:`_compute_impl_windows_batch` for the
    single-contract ``match_audits_for_contract`` entry point. Kept for
    callers that only need one contract's windows.
    """
    return _compute_impl_windows_batch(session, [contract]).get(contract.id, [])


# --- Confidence scoring -------------------------------------------------


def _confidence_for_impl_era(audit_ts: datetime | None, windows: list[ImplWindow]) -> tuple[str, ImplWindow | None]:
    """Pick the best-matching window for the audit timestamp.

    Returns ``(confidence, window)``:
        high   — audit lands inside an active window
        medium — audit within ``GRACE_DAYS`` of a window boundary
        low    — no timestamp, or clearly outside every window

    Low-confidence rows still emit so the UI can flag name-matches with
    bad timing. Window is ``None`` when nothing is a plausible anchor.
    """
    if not windows:
        # No impl history at all — shouldn't be called in impl_era mode.
        return "low", None

    if audit_ts is None:
        # No audit date. Best effort: attach to the most recent (open-ended)
        # window if any — the naive assumption that absent-date audits are
        # modern. Low confidence; UI can filter these out.
        open_windows = [w for w in windows if w.to_block is None]
        if open_windows:
            return "low", open_windows[0]
        return "low", windows[-1]

    # In a strictly-inside window → high.
    for w in windows:
        if w.from_ts is None:
            # Block-only windows can't be temporally placed — fall through
            # to the grace check, which will skip them too.
            continue
        if audit_ts >= w.from_ts and (w.to_ts is None or audit_ts < w.to_ts):
            return "high", w

    # Within grace of some boundary → medium. Pick the closest window.
    grace = timedelta(days=GRACE_DAYS)
    best_distance: timedelta | None = None
    best_window: ImplWindow | None = None
    for w in windows:
        if w.from_ts is None:
            continue
        # Distance to this window (0 if inside, otherwise to the nearest edge).
        if audit_ts < w.from_ts:
            dist = w.from_ts - audit_ts
        elif w.to_ts is not None and audit_ts >= w.to_ts:
            dist = audit_ts - w.to_ts
        else:
            # Inside, but we would have matched above — timestamp weirdness.
            dist = timedelta(0)
        if dist <= grace:
            if best_distance is None or dist < best_distance:
                best_distance = dist
                best_window = w
    if best_window is not None:
        return "medium", best_window

    # Neither inside nor within grace. Pick the nearest window anyway so
    # covered_from_block isn't NULL when we have some plausible anchor.
    # This is a 'low' — the UI / caller decides what to do with it.
    for w in windows:
        if w.from_ts is None:
            continue
        if audit_ts < w.from_ts:
            dist = w.from_ts - audit_ts
        elif w.to_ts is not None and audit_ts >= w.to_ts:
            dist = audit_ts - w.to_ts
        else:
            dist = timedelta(0)
        if best_distance is None or dist < best_distance:
            best_distance = dist
            best_window = w
    return "low", best_window


def _confidence_for_direct(audit_ts: datetime | None, contract: Contract) -> str:
    """High when audit has a date, medium when name-only (no date).

    Direct matches never go low: a clean name match without history to
    falsify against beats a distant impl_era match.
    """
    return "high" if audit_ts is not None else "medium"


# --- Core matchers ------------------------------------------------------


def _normalize_name(name: str | None) -> str:
    return (name or "").strip().lower()


def _normalize_chain(chain: str | None) -> str:
    normalized = (chain or "").strip().lower()
    return normalized or "ethereum"


_AddressRowCache = dict[tuple[int, str, str, bool], Contract | None]


def _lookup_contract_by_address_chain(
    session: Session,
    protocol_id: int,
    address: str,
    chain_key: str,
    row_cache: _AddressRowCache,
    *,
    allow_global_fallback: bool = False,
) -> Contract | None:
    """Return the best Contract row for ``(protocol, address, chain)``.

    Historical data may contain legacy ``chain=NULL`` rows for Ethereum.
    Treat those as Ethereum-compatible, but prefer an explicit
    ``chain='ethereum'`` row when both exist. Explicit audit scope
    addresses may fall back to the global row because ``contracts`` is
    unique by deployed ``(address, chain)``, not by protocol.
    """
    cache_key = (protocol_id, address, chain_key, allow_global_fallback)
    if cache_key not in row_cache:
        exact_chain = func.lower(Contract.chain) == chain_key
        if chain_key == "ethereum":
            chain_filter = or_(exact_chain, Contract.chain.is_(None))
        else:
            chain_filter = exact_chain
        row = (
            session.execute(
                select(Contract)
                .where(
                    Contract.protocol_id == protocol_id,
                    func.lower(Contract.address) == address,
                    chain_filter,
                )
                .order_by(
                    case((exact_chain, 0), else_=1).asc(),
                    Contract.id.asc(),
                )
            )
            .scalars()
            .first()
        )
        if row is None and allow_global_fallback:
            row = (
                session.execute(
                    select(Contract)
                    .where(
                        func.lower(Contract.address) == address,
                        chain_filter,
                    )
                    .order_by(
                        case((exact_chain, 0), else_=1).asc(),
                        Contract.id.asc(),
                    )
                )
                .scalars()
                .first()
            )
        row_cache[cache_key] = row
    return row_cache[cache_key]


def _resolve_impl_for_address(
    session: Session,
    protocol_id: int,
    row: Contract,
    *,
    audit_ts: datetime | None,
    row_cache: _AddressRowCache,
    proxy_events_cache: dict[int, list[UpgradeEvent]],
    allow_global_fallback: bool = False,
) -> Contract | None:
    """Return the impl Contract row that should carry a coverage insert.

    When ``row`` is a proxy, resolve to the impl active at the audit's
    timestamp. If the proxy has no recorded upgrade history we fall back
    to its current ``implementation`` pointer; if it does have history
    but the audit can't be placed inside a specific impl window, return
    ``None`` rather than rebinding the audit to today's impl.
    """
    chain_key = _normalize_chain(row.chain)
    if not row.is_proxy:
        return row
    proxy_events = proxy_events_cache.get(row.id)
    if proxy_events is None:
        proxy_events = list(
            session.execute(
                select(UpgradeEvent)
                .where(UpgradeEvent.contract_id == row.id)
                .order_by(
                    UpgradeEvent.block_number.asc().nullslast(),
                    UpgradeEvent.id.asc(),
                )
            )
            .scalars()
            .all()
        )
        proxy_events_cache[row.id] = proxy_events

    impl_addr = ""
    if not proxy_events:
        impl_addr = (row.implementation or "").lower() if row.implementation else ""
    else:
        if audit_ts is None or any(ev.timestamp is None for ev in proxy_events):
            return None
        for i, ev in enumerate(proxy_events):
            if not ev.new_impl or ev.timestamp is None:
                continue
            next_ts = proxy_events[i + 1].timestamp if i + 1 < len(proxy_events) else None
            if audit_ts >= ev.timestamp and (next_ts is None or audit_ts < next_ts):
                impl_addr = ev.new_impl.lower()
                break
    if not impl_addr:
        return None
    target = _lookup_contract_by_address_chain(
        session,
        protocol_id,
        impl_addr,
        chain_key,
        row_cache,
        allow_global_fallback=allow_global_fallback,
    )
    if target is None or target.is_proxy:
        return None
    return target


def _resolve_scope_entry_target(
    session: Session,
    protocol_id: int,
    entry: dict,
    *,
    audit_ts: datetime | None,
    row_cache: _AddressRowCache,
    proxy_events_cache: dict[int, list[UpgradeEvent]],
) -> Contract | None:
    """Resolve one scope entry to the impl Contract row it actually pins."""
    addr = (entry.get("address") or "").lower()
    if not addr:
        return None
    chain_key = _normalize_chain(entry.get("chain"))
    row = _lookup_contract_by_address_chain(
        session,
        protocol_id,
        addr,
        chain_key,
        row_cache,
        allow_global_fallback=True,
    )
    if row is None:
        return None
    return _resolve_impl_for_address(
        session,
        protocol_id,
        row,
        audit_ts=audit_ts,
        row_cache=row_cache,
        proxy_events_cache=proxy_events_cache,
        allow_global_fallback=True,
    )


def _address_anchored_matches(
    session: Session, audit: AuditReport, scope_entries: list
) -> tuple[dict[int, CoverageMatch], set[str]]:
    """Build address-anchored CoverageMatch rows from ``audit.scope_entries``.

    Returns ``(by_contract, matched_names)`` where ``by_contract`` maps
    ``contract_id → CoverageMatch`` keyed by the impl row (proxies resolved
    to their implementation before keying). ``matched_names`` is the set
    of name spellings already covered — the caller uses it to suppress
    a duplicate weaker name-match on the same contract.
    """
    by_contract: dict[int, CoverageMatch] = {}
    matched_names: set[str] = set()
    if not any(isinstance(e, dict) and e.get("address") for e in scope_entries):
        return by_contract, matched_names

    audit_ts = _audit_effective_ts(audit.date)
    row_cache: _AddressRowCache = {}
    proxy_events_cache: dict[int, list[UpgradeEvent]] = {}

    for entry in scope_entries:
        if not isinstance(entry, dict):
            continue
        target = _resolve_scope_entry_target(
            session,
            audit.protocol_id,
            entry,
            audit_ts=audit_ts,
            row_cache=row_cache,
            proxy_events_cache=proxy_events_cache,
        )
        if target is None:
            continue

        matched_name = str(entry.get("name") or target.contract_name or "")
        match = CoverageMatch(
            audit_report_id=audit.id,
            contract_id=target.id,
            protocol_id=audit.protocol_id,
            matched_name=matched_name,
            match_type="reviewed_address",
            match_confidence="high",
            pinned_commit=entry.get("commit") or None,
        )
        prev = by_contract.get(target.id)
        if prev is None or _row_score(match) > _row_score(prev):
            by_contract[target.id] = match
        matched_names.add(_normalize_name(matched_name))
        if target.contract_name:
            matched_names.add(_normalize_name(target.contract_name))

    return by_contract, matched_names


def match_contracts_for_audit(session: Session, audit_id: int) -> list[CoverageMatch]:
    """Find every Contract in the audit's protocol that matches a scope entry.

    Two paths:
      1. **Address-anchored** (Phase F): when the audit has
         ``scope_entries`` with explicit addresses, each entry maps to a
         single ``Contract`` row at that ``(address, chain)`` in the
         protocol — unambiguous. Emits ``match_type='reviewed_address'``.
         Handles proxies by resolving to the impl active at the audit's
         timestamp before the final insert (the
         ``_reject_proxy_coverage`` trigger enforces this at the DB
         layer too). Ambiguous proxy entries are skipped.
      2. **Name-anchored** (legacy): falls through for scope names NOT
         covered by an address-anchored entry. Uses case-insensitive
         name equality against ``Contract.contract_name``; emits
         ``'direct'`` or ``'impl_era'`` depending on proxy history.

    Returns at most one CoverageMatch per ``(contract_id, audit_id)`` pair
    — when multiple scope names/addresses collapse onto the same Contract,
    the highest-``_row_score`` match wins.
    """
    audit = session.get(AuditReport, audit_id)
    if audit is None:
        return []
    scope_names = audit.scope_contracts or []
    scope_entries = audit.scope_entries or []
    if not scope_names and not scope_entries:
        return []

    scope_lookup: dict[str, str] = {}
    for name in scope_names:
        key = _normalize_name(name)
        if not key:
            continue
        # Preserve the first raw spelling for the matched_name column.
        scope_lookup.setdefault(key, name)

    # Address-anchored pass: authoritative when the audit has scope_entries.
    by_contract, addr_matched_names = _address_anchored_matches(session, audit, scope_entries)

    # Trim the name-match candidate pool so a weaker ``direct`` / ``impl_era``
    # row doesn't get emitted for the same contract.
    for n in addr_matched_names:
        scope_lookup.pop(n, None)

    if not scope_lookup:
        return list(by_contract.values())

    # Protocol contracts whose contract_name matches a scope entry, case-
    # insensitively. Parameter binding makes LLM-sourced strings safe to
    # pass through IN_. Proxies are excluded at the query boundary: scope
    # names like ``UUPSProxy`` match generic proxy rows verbatim but the
    # audit reviewed the impl's code, not the proxy glue — real coverage
    # flows via the impl's own Contract row + audit_timeline's union.
    # Filtering here (instead of later in the loop) makes the invariant
    # architectural: proxies can't reach the impl_era or direct branches,
    # the source-equivalence pass, or the coverage-insert path. A DB
    # trigger on ``audit_contract_coverage`` enforces the same invariant
    # against raw SQL writes.
    candidates = (
        session.execute(
            select(Contract).where(
                Contract.protocol_id == audit.protocol_id,
                func.lower(Contract.contract_name).in_(list(scope_lookup.keys())),
                Contract.is_proxy.is_(False),
            )
        )
        .scalars()
        .all()
    )
    if not candidates:
        return list(by_contract.values())

    audit_ts = _audit_effective_ts(audit.date)

    # Batch impl-window computation: one query for the proxy lookup and
    # one for the event history across every candidate, instead of N+K per
    # candidate. For protocols with a wide scope, this is the difference
    # between a single rebuild lasting seconds vs. minutes.
    windows_by_id = _compute_impl_windows_batch(session, list(candidates))

    # Per-contract: pick the best match. When a contract has impl windows,
    # we emit impl_era; otherwise direct. ``by_contract`` may already
    # contain address-anchored wins from Phase F above — _row_score
    # decides which survives when a name-match collides.
    for c in candidates:
        matched_name = scope_lookup.get(_normalize_name(c.contract_name))
        if not matched_name:
            continue
        windows = windows_by_id.get(c.id, [])
        if windows:
            confidence, window = _confidence_for_impl_era(audit_ts, windows)
            match = CoverageMatch(
                audit_report_id=audit.id,
                contract_id=c.id,
                protocol_id=audit.protocol_id,
                matched_name=matched_name,
                match_type="impl_era",
                match_confidence=confidence,
                covered_from_block=window.from_block if window else None,
                covered_to_block=window.to_block if window else None,
            )
        else:
            confidence = _confidence_for_direct(audit_ts, c)
            match = CoverageMatch(
                audit_report_id=audit.id,
                contract_id=c.id,
                protocol_id=audit.protocol_id,
                matched_name=matched_name,
                match_type="direct",
                match_confidence=confidence,
            )
        prev = by_contract.get(c.id)
        if prev is None or _row_score(match) > _row_score(prev):
            by_contract[c.id] = match

    return list(by_contract.values())


_CONFIDENCE_ORDER: Final[dict[str, int]] = {"low": 0, "medium": 1, "high": 2}
# Match-type strength as a tiebreaker WITHIN equal confidence:
# reviewed_commit (cryptographic source-hash proof) beats impl_era
# (temporal-window heuristic) beats direct (pure name match). Confidence
# always dominates — a low-confidence reviewed_commit still loses to a
# high-confidence direct.
_MATCH_TYPE_ORDER: Final[dict[str, int]] = {
    "direct": 0,
    "impl_era": 1,
    # Phase F: audit's scope table named THIS address. Authoritative over
    # name-overlap heuristics (direct / impl_era) but weaker than a
    # reviewed_commit proof, which additionally verifies the source bytes.
    "reviewed_address": 2,
    "reviewed_commit": 3,
}


def _row_score(row) -> tuple[int, int]:
    """Composite rank: ``(confidence, match_type)`` — higher is better.

    Used by both the per-contract dedupe in ``match_contracts_for_audit``
    and the per-audit dedupe in ``api.contract_audit_timeline`` so the
    two paths agree on which row wins. Accepts anything with
    ``.match_confidence`` and ``.match_type`` attributes (CoverageMatch
    dataclass + the AuditContractCoverage ORM row both qualify).
    """
    return (
        _CONFIDENCE_ORDER.get(row.match_confidence, 0),
        _MATCH_TYPE_ORDER.get(row.match_type, 0),
    )


def match_audits_for_contract(session: Session, contract_id: int) -> list[CoverageMatch]:
    """Dual entry. For each audit in the contract's protocol whose scope
    matches this contract (by explicit address in ``scope_entries`` OR by
    name in ``scope_contracts``), emit one CoverageMatch per audit.

    Proxies are excluded unconditionally — the coverage matcher targets
    impl rows only. Short-circuiting here keeps ``audit_timeline`` from
    surfacing a redundant direct row on the proxy's generic name when the
    impl already has the legitimate match.
    """
    contract = session.get(Contract, contract_id)
    if contract is None or contract.protocol_id is None:
        return []
    if contract.is_proxy:
        return []
    name_key = _normalize_name(contract.contract_name)
    contract_chain = _normalize_chain(contract.chain)

    audits = (
        session.execute(
            select(AuditReport).where(
                AuditReport.protocol_id == contract.protocol_id,
                AuditReport.scope_extraction_status == "success",
                or_(
                    AuditReport.scope_contracts.isnot(None),
                    AuditReport.scope_entries.isnot(None),
                ),
            )
        )
        .scalars()
        .all()
    )
    windows = _compute_impl_windows_for_contract(session, contract)
    contract_addr_lower = (contract.address or "").lower()
    row_cache: _AddressRowCache = {}
    proxy_events_cache: dict[int, list[UpgradeEvent]] = {}

    # Track per-audit best match so one audit doesn't emit both an
    # address-anchored row AND a name-match row for the same contract.
    best_by_audit: dict[int, CoverageMatch] = {}

    for audit in audits:
        # --- Address-anchored pass (Phase F) ---
        audit_ts = _audit_effective_ts(audit.date)
        for entry in audit.scope_entries or []:
            if not isinstance(entry, dict):
                continue
            addr = (entry.get("address") or "").lower()
            if not addr:
                continue
            if _normalize_chain(entry.get("chain")) != contract_chain:
                continue
            if addr == contract_addr_lower:
                target = contract
            else:
                target = _resolve_scope_entry_target(
                    session,
                    audit.protocol_id,
                    entry,
                    audit_ts=audit_ts,
                    row_cache=row_cache,
                    proxy_events_cache=proxy_events_cache,
                )
            if target is None or target.id != contract.id:
                continue
            matched_name = str(entry.get("name") or contract.contract_name or "")
            commit_hint = entry.get("commit") or None
            match = CoverageMatch(
                audit_report_id=audit.id,
                contract_id=contract.id,
                protocol_id=contract.protocol_id,
                matched_name=matched_name,
                match_type="reviewed_address",
                match_confidence="high",
                pinned_commit=commit_hint,
            )
            prev = best_by_audit.get(audit.id)
            if prev is None or _row_score(match) > _row_score(prev):
                best_by_audit[audit.id] = match

        # --- Name-anchored pass (legacy) ---
        if audit.id in best_by_audit:
            # Already covered by address-anchor on this audit — don't
            # emit a weaker name-only row.
            continue
        scope_names = audit.scope_contracts or []
        matched_name = next((n for n in scope_names if _normalize_name(n) == name_key), None)
        if not matched_name:
            continue
        if windows:
            confidence, window = _confidence_for_impl_era(audit_ts, windows)
            best_by_audit[audit.id] = CoverageMatch(
                audit_report_id=audit.id,
                contract_id=contract.id,
                protocol_id=contract.protocol_id,
                matched_name=matched_name,
                match_type="impl_era",
                match_confidence=confidence,
                covered_from_block=window.from_block if window else None,
                covered_to_block=window.to_block if window else None,
            )
        else:
            confidence = _confidence_for_direct(audit_ts, contract)
            best_by_audit[audit.id] = CoverageMatch(
                audit_report_id=audit.id,
                contract_id=contract.id,
                protocol_id=contract.protocol_id,
                matched_name=matched_name,
                match_type="direct",
                match_confidence=confidence,
            )

    return list(best_by_audit.values())


# --- Upsert helpers -----------------------------------------------------


def _match_to_row_kwargs(match: CoverageMatch) -> dict:
    return {
        "contract_id": match.contract_id,
        "audit_report_id": match.audit_report_id,
        "protocol_id": match.protocol_id,
        "matched_name": match.matched_name,
        "match_type": match.match_type,
        "match_confidence": match.match_confidence,
        "covered_from_block": match.covered_from_block,
        "covered_to_block": match.covered_to_block,
        "bytecode_keccak_at_match": match.bytecode_keccak_at_match,
        "verified_at": match.verified_at,
        "equivalence_status": match.equivalence_status,
        "equivalence_reason": match.equivalence_reason,
        "equivalence_checked_at": match.equivalence_checked_at,
        "proof_kind": match.proof_kind,
        "matched_commit_sha": match.matched_commit_sha,
    }


# --- Bytecode anchor ----------------------------------------------------


def _rpc_url() -> str:
    """eRPC route for bytecode-anchor reads.

    Coverage anchors are ethereum-deployed, so this resolves the mainnet eRPC
    route — same as policy_worker / protocol_monitor, which also go through
    ``default_rpc_url``. Raises when eRPC is unconfigured; the caller catches
    that and records "drift unknown" rather than hitting a direct provider.
    """
    from utils.rpc import require_rpc_url

    return require_rpc_url(chain_id=1)


def _fetch_bytecode_keccak(address: str) -> str | None:
    """Runtime bytecode keccak256 at ``address`` via ``eth_getCode``.

    Returns ``"0x" + 64hex`` on success, ``None`` when the RPC call fails
    or the address has no code (EOA / selfdestructed). ``None`` propagates
    to ``AuditContractCoverage.bytecode_keccak_at_match`` meaning "drift
    unknown" — safer than fabricating a zero-bytecode hash.
    """
    from eth_utils.crypto import keccak

    from utils.rpc import get_code

    if not address:
        return None
    try:
        code_hex = get_code(_rpc_url(), address)
    except Exception as exc:
        logger.warning("bytecode anchor: eth_getCode failed for %s: %s", address, exc)
        return None
    if not code_hex or code_hex == "0x":
        return None
    try:
        raw = bytes.fromhex(code_hex[2:]) if code_hex.startswith("0x") else bytes.fromhex(code_hex)
    except ValueError:
        logger.warning("bytecode anchor: malformed hex from RPC for %s: %r", address, code_hex[:40])
        return None
    return "0x" + keccak(raw).hex()


def _apply_bytecode_anchor(
    session: Session,
    matches: list[CoverageMatch],
) -> list[CoverageMatch]:
    """Stamp each match with the current runtime-bytecode keccak of its impl.

    One RPC per distinct contract_id — results reused when multiple audits
    hit the same impl. Called during the HTTP phase of the upsert so the
    tx is released while RPC is in flight.
    """
    if not matches:
        return matches
    addr_by_cid: dict[int, str] = {
        cid: addr
        for cid, addr in session.execute(
            select(Contract.id, Contract.address).where(Contract.id.in_({m.contract_id for m in matches}))
        ).all()
    }

    keccak_by_cid: dict[int, str | None] = {}
    for cid in addr_by_cid:
        keccak_by_cid[cid] = _fetch_bytecode_keccak(addr_by_cid[cid])

    now = datetime.now(timezone.utc)
    stamped: list[CoverageMatch] = []
    for m in matches:
        kk = keccak_by_cid.get(m.contract_id)
        stamped.append(
            CoverageMatch(
                audit_report_id=m.audit_report_id,
                contract_id=m.contract_id,
                protocol_id=m.protocol_id,
                matched_name=m.matched_name,
                match_type=m.match_type,
                match_confidence=m.match_confidence,
                covered_from_block=m.covered_from_block,
                covered_to_block=m.covered_to_block,
                bytecode_keccak_at_match=kk,
                # Only stamp verified_at when we actually got a keccak —
                # a NULL keccak with a fresh timestamp is a misleading signal.
                verified_at=now if kk is not None else m.verified_at,
                # Preserve equivalence stamps from _apply_equivalence_http.
                equivalence_status=m.equivalence_status,
                equivalence_reason=m.equivalence_reason,
                equivalence_checked_at=m.equivalence_checked_at,
                pinned_commit=m.pinned_commit,
                proof_kind=m.proof_kind,
                matched_commit_sha=m.matched_commit_sha,
            )
        )
    return stamped


@dataclass(frozen=True)
class _EquivalenceInputs:
    """Inputs to run ``check_audit_covers_impl`` without holding a session.

    Materialized in the DB phase so the HTTP phase can run with no open
    transaction: the GitHub fetches inside ``check_audit_covers_impl`` are
    pure HTTP and need no session.
    """

    audit_report_id: int
    contract_id: int
    contract_address: str | None
    reviewed_commits: tuple[str, ...]
    scope_contracts: tuple[str, ...]
    source_repo: str | None
    # Phase D: every github.com/<owner>/<repo> the audit PDF mentions.
    # Fallback candidates tried after ``source_repo`` when it doesn't
    # contain the reviewed commit.
    referenced_repos: tuple[str, ...]
    # Phase C: LLM-labeled commits with {sha, label, context}. Used to
    # derive ``proof_kind`` on proven rows.
    classified_commits: tuple[dict, ...]
    # DB-resolved impl source, if Contract.job_id had SourceFile rows.
    # None means the HTTP phase should call Etherscan as a fallback.
    # Typed as Any so we don't force import of VerifiedSource at module
    # load (keeps the coverage module importable without the source_eq
    # dep chain resolved).
    db_impl_source: Any


def _preload_equivalence_inputs(
    session: Session, matches: list[CoverageMatch]
) -> dict[tuple[int, int], _EquivalenceInputs]:
    """Pull the data needed for source-equivalence into plain Python objects.

    Runs inside the caller's DB phase so the subsequent HTTP phase can
    execute with the transaction released. Each match gets one entry keyed
    by ``(audit_id, contract_id)``. Matches whose audit lacks
    ``reviewed_commits``/``source_repo`` are still recorded (with empty
    tuples) so the HTTP phase can cheaply skip them.
    """
    from services.audits.source_equivalence import fetch_db_source_files

    out: dict[tuple[int, int], _EquivalenceInputs] = {}
    audit_cache: dict[int, AuditReport | None] = {}
    contract_cache: dict[int, Contract | None] = {}
    for m in matches:
        audit = audit_cache.get(m.audit_report_id)
        if m.audit_report_id not in audit_cache:
            audit = session.get(AuditReport, m.audit_report_id)
            audit_cache[m.audit_report_id] = audit
        contract = contract_cache.get(m.contract_id)
        if m.contract_id not in contract_cache:
            contract = session.get(Contract, m.contract_id)
            contract_cache[m.contract_id] = contract
        if audit is None or contract is None:
            continue
        db_source = fetch_db_source_files(session, m.contract_id)
        out[(m.audit_report_id, m.contract_id)] = _EquivalenceInputs(
            audit_report_id=m.audit_report_id,
            contract_id=m.contract_id,
            contract_address=contract.address,
            reviewed_commits=tuple(audit.reviewed_commits or ()),
            scope_contracts=tuple(audit.scope_contracts or ()),
            source_repo=audit.source_repo,
            referenced_repos=tuple(audit.referenced_repos or ()),
            classified_commits=tuple(audit.classified_commits or ()),
            db_impl_source=db_source,
        )
    return out


def _compute_proof_kind(
    matched_commits: set[str],
    classified_commits: list[dict] | None,
) -> str:
    """Map a proven (matched, labeled) pair to a ``proof_kind``.

    Rules (see ``db.models.AuditContractCoverage.proof_kind`` for the
    vocabulary):

    - ``unclassified`` when the audit has no classification data
    - ``clean`` when we matched a ``reviewed`` commit AND (no ``fix``
      commits exist OR we also matched a ``fix`` commit)
    - ``pre_fix_unpatched`` when we matched a ``reviewed`` commit AND
      ``fix`` commits exist but we didn't match any — DANGER: audit's
      findings are present in the deployed code
    - ``post_fix`` when we matched a ``fix`` commit only (no reviewed match)
    - ``cited_only`` when our match hit only commits labeled ``cited``
      or ``unclear`` — coincidental, suspicious
    """
    if not classified_commits:
        return "unclassified"

    reviewed_shas: set[str] = set()
    fix_shas: set[str] = set()
    for entry in classified_commits:
        if not isinstance(entry, dict):
            continue
        sha = (entry.get("sha") or "").lower()
        label = (entry.get("label") or "").lower()
        if not sha:
            continue
        if label == "reviewed":
            reviewed_shas.add(sha)
        elif label == "fix":
            fix_shas.add(sha)

    # Match SHAs using prefix comparison: our matched commits come from
    # the audit's ``reviewed_commits`` list (may be full 40-char), the
    # classified_commits come from LLM (variable length). Compare on
    # shared prefix at 7 chars (git's default abbrev) to be safe.
    def _matches_any(prefix_set: set[str]) -> bool:
        if not prefix_set:
            return False
        for mc in matched_commits:
            mc_short = mc[:7]
            for cs in prefix_set:
                if mc.startswith(cs) or cs.startswith(mc_short):
                    return True
        return False

    matched_reviewed = _matches_any(reviewed_shas)
    matched_fix = _matches_any(fix_shas)

    if matched_reviewed and not matched_fix and fix_shas:
        # Deployed == reviewed; a fix was known but never shipped.
        return "pre_fix_unpatched"
    if matched_reviewed:
        # Either no fix exists, or we also matched a fix.
        return "clean"
    if matched_fix:
        return "post_fix"
    # Matched something, but not a labeled commit.
    return "cited_only"


def _apply_equivalence_http(
    matches: list[CoverageMatch],
    inputs: dict[tuple[int, int], _EquivalenceInputs],
) -> list[CoverageMatch]:
    """HTTP phase: stamp every match with a verification verdict.

    For each match, runs ``verify_audit_covers_impl`` against the row's
    own ``matched_name`` (not the full audit scope — otherwise failure
    reasons describe the wrong contract). Every row gets an
    ``equivalence_status`` + ``equivalence_reason`` + ``equivalence_checked_at``
    stamp regardless of outcome, so the DB reflects whether verification
    ran and why it did/didn't succeed.

    When ``status='proven'``, also upgrades ``match_type`` →
    ``'reviewed_commit'`` and ``match_confidence`` → ``'high'``. Other
    statuses leave the heuristic temporal match intact — a failed
    verification annotates but doesn't delete.

    Per-match work fans out via ``parallel_map(max_workers=4)`` — the
    GitHub authenticated rate limit is 5000/hr and the Etherscan cache
    collapses repeats behind a lock, so 4 concurrent workers stay well
    inside both budgets.
    """
    import os
    import threading

    from services.audits.source_equivalence import (
        EtherscanFetch,
        VerifiedSource,
        fetch_etherscan_source_files,
        verify_audit_covers_impl,
    )
    from utils.concurrency import parallel_map

    gh_token = os.environ.get("GITHUB_TOKEN") or None
    # Per-address cache so two audit rows pointing at the same impl only
    # pay one Etherscan round-trip. Stores EtherscanFetch (the new envelope
    # that carries status + detail, not just source). Lock guards the
    # check-then-set pattern across worker threads.
    etherscan_cache: dict[str, Any] = {}
    cache_lock = threading.Lock()
    now = datetime.now(timezone.utc)

    def _stamp(
        base: CoverageMatch,
        *,
        status: str,
        reason: str,
        proven: bool = False,
        proof_kind: str | None = None,
        matched_commit_sha: str | None = None,
    ) -> CoverageMatch:
        return CoverageMatch(
            audit_report_id=base.audit_report_id,
            contract_id=base.contract_id,
            protocol_id=base.protocol_id,
            matched_name=base.matched_name,
            match_type="reviewed_commit" if proven else base.match_type,
            match_confidence="high" if proven else base.match_confidence,
            covered_from_block=base.covered_from_block,
            covered_to_block=base.covered_to_block,
            bytecode_keccak_at_match=base.bytecode_keccak_at_match,
            verified_at=base.verified_at,
            equivalence_status=status,
            equivalence_reason=reason[:1000] if reason else None,
            equivalence_checked_at=now,
            pinned_commit=base.pinned_commit,
            proof_kind=proof_kind if proven else None,
            matched_commit_sha=matched_commit_sha if proven else None,
        )

    def _fetch_etherscan(addr_key: str, contract_address: str, contract_id: int) -> EtherscanFetch:
        with cache_lock:
            cached = etherscan_cache.get(addr_key)
        if cached is not None:
            return cached
        try:
            raw_fetch = fetch_etherscan_source_files(contract_address)
            if isinstance(raw_fetch, EtherscanFetch):
                fetch = raw_fetch
            elif isinstance(raw_fetch, VerifiedSource):
                # Backward compatibility for older tests/callers
                # that still stub the pre-envelope return type.
                fetch = EtherscanFetch(source=raw_fetch, status="ok", detail="")
            else:
                raise TypeError(
                    f"fetch_etherscan_source_files returned {type(raw_fetch).__name__}, expected EtherscanFetch"
                )
        except Exception as exc:
            logger.exception(
                "source-equivalence Etherscan fetch crashed for contract %s",
                contract_id,
            )
            # Synthesize a fetch_failed envelope so the branches below
            # treat this uniformly with API-returned errors.
            fetch = EtherscanFetch(source=None, status="fetch_failed", detail=f"crash: {exc}")
        with cache_lock:
            # First writer wins — avoid clobbering another thread's
            # successful fetch with a later error.
            return etherscan_cache.setdefault(addr_key, fetch)

    def _process_match(m: CoverageMatch) -> CoverageMatch:
        key = (m.audit_report_id, m.contract_id)
        data = inputs.get(key)
        if data is None:
            return _stamp(m, status="not_attempted", reason="no preload inputs")
        if not data.reviewed_commits:
            return _stamp(m, status="no_reviewed_commit", reason="audit has no reviewed_commits")
        if not data.source_repo and not data.referenced_repos:
            return _stamp(m, status="no_source_repo", reason="audit has no source_repo or referenced_repos")

        # Resolve impl source: DB preload first, Etherscan (cached) next.
        impl_source = data.db_impl_source
        fetch_status = "ok"
        fetch_detail = ""
        if impl_source is None and data.contract_address:
            fetch = _fetch_etherscan(data.contract_address.lower(), data.contract_address, m.contract_id)
            impl_source = fetch.source
            fetch_status = fetch.status
            fetch_detail = fetch.detail

        if impl_source is None:
            # Map Etherscan envelope into the row's equivalence status.
            if fetch_status == "unverified":
                return _stamp(m, status="etherscan_unverified", reason=fetch_detail or "no verified source")
            return _stamp(m, status="etherscan_fetch_failed", reason=fetch_detail or "etherscan fetch failed")

        # Verify scoped to THIS row's matched_name — critical: the reason
        # must describe the right contract. When the match came from an
        # address-anchored scope_entry with a pinned commit, pass it as
        # ``specific_commit`` so verification targets exactly that SHA
        # instead of every SHA in the PDF text (Phase F tightening).
        # Phase D: pass the audit's full ``referenced_repos`` list as
        # fallback candidates — if the primary ``source_repo`` doesn't
        # contain the commit, verification retries against each
        # PDF-mentioned repo.
        try:
            outcome = verify_audit_covers_impl(
                reviewed_commits=list(data.reviewed_commits),
                scope_name=m.matched_name,
                impl_source=impl_source,
                source_repo=data.source_repo,
                github_token=gh_token,
                specific_commit=m.pinned_commit,
                fallback_repos=list(data.referenced_repos),
            )
        except Exception as exc:
            logger.exception(
                "source-equivalence check crashed for audit %s / contract %s",
                m.audit_report_id,
                m.contract_id,
            )
            return _stamp(m, status="github_fetch_failed", reason=f"crash: {exc}")

        proven = outcome.status == "proven"
        proof_kind: str | None = None
        matched_commit_sha: str | None = None
        if proven:
            matched_commits = {em.commit.lower() for em in outcome.matches}
            proof_kind = _compute_proof_kind(matched_commits, list(data.classified_commits))
            # Pick a representative SHA for this (audit, contract) pair.
            # Prefer a commit the auditor labelled ``reviewed`` so the UI
            # links to the SHA that was actually audited rather than a fix
            # or cited reference. Fall back to any matched commit.
            for entry in data.classified_commits or ():
                sha = str(entry.get("sha") or "").lower()
                if sha and sha in matched_commits and entry.get("label") == "reviewed":
                    matched_commit_sha = sha
                    break
            if matched_commit_sha is None and matched_commits:
                matched_commit_sha = next(iter(matched_commits))
            logger.info(
                "coverage: audit %s proven to cover contract %s (%s) kind=%s sha=%s — %s",
                m.audit_report_id,
                m.contract_id,
                m.matched_name,
                proof_kind,
                (matched_commit_sha or "")[:12],
                outcome.reason,
            )
        return _stamp(
            m,
            status=outcome.status,
            reason=outcome.reason,
            proven=proven,
            proof_kind=proof_kind,
            matched_commit_sha=matched_commit_sha,
        )

    results = parallel_map(_process_match, matches, max_workers=4)
    stamped: list[CoverageMatch] = []
    for m, outcome in results:
        if isinstance(outcome, BaseException):
            stamped.append(_stamp(m, status="github_fetch_failed", reason=f"crash: {outcome}"))
            continue
        stamped.append(outcome)
    return stamped


def _persist_coverage_for_audit(session: Session, audit_id: int, matches: list[CoverageMatch]) -> int:
    """Delete-then-insert coverage rows for one audit in a short tx."""
    session.execute(sql_delete(AuditContractCoverage).where(AuditContractCoverage.audit_report_id == audit_id))
    for match in matches:
        session.add(AuditContractCoverage(**_match_to_row_kwargs(match)))
    return len(matches)


def _persist_coverage_for_contract(session: Session, contract_id: int, matches: list[CoverageMatch]) -> int:
    """Delete-then-insert local-protocol coverage rows for one contract."""
    contract = session.get(Contract, contract_id)
    if contract is not None and contract.protocol_id is not None:
        session.execute(
            sql_delete(AuditContractCoverage).where(
                AuditContractCoverage.contract_id == contract_id,
                AuditContractCoverage.protocol_id == contract.protocol_id,
            )
        )
    for match in matches:
        session.add(AuditContractCoverage(**_match_to_row_kwargs(match)))
    return len(matches)


# --- Deferred verification (CoverageVerifyWorker) ----------------------


def _stamp_pending_when_verifiable(
    matches: list[CoverageMatch],
    audits_by_id: dict[int, AuditReport | None],
) -> list[CoverageMatch]:
    """Stamp ``equivalence_status`` for the deferred-verify path.

    Used when ``verify_source_equivalence=False``: rows that *could* later
    be proven by source-equivalence land with ``status='pending'`` so
    ``workers.coverage_verify`` can drain them. Rows whose audit lacks
    inputs (no commits or no candidate repo) get a terminal status
    immediately so the verify worker doesn't bother re-checking — a
    re-extraction that fills those fields will trigger a fresh upsert
    that re-stamps them as ``pending``.
    """
    out: list[CoverageMatch] = []
    for m in matches:
        # Don't override stamps that the inline verify path already set
        # (in case a caller mixes paths). Idempotent fallthrough.
        if m.equivalence_status:
            out.append(m)
            continue
        audit = audits_by_id.get(m.audit_report_id)
        if audit is None:
            out.append(m)
            continue
        has_commits = bool(audit.reviewed_commits)
        has_repo = bool(audit.source_repo) or bool(audit.referenced_repos)
        if not has_commits:
            status = "no_reviewed_commit"
            reason: str | None = "audit has no reviewed_commits"
        elif not has_repo:
            status = "no_source_repo"
            reason = "audit has no source_repo or referenced_repos"
        else:
            status = "pending"
            reason = None
        out.append(
            CoverageMatch(
                audit_report_id=m.audit_report_id,
                contract_id=m.contract_id,
                protocol_id=m.protocol_id,
                matched_name=m.matched_name,
                match_type=m.match_type,
                match_confidence=m.match_confidence,
                covered_from_block=m.covered_from_block,
                covered_to_block=m.covered_to_block,
                bytecode_keccak_at_match=m.bytecode_keccak_at_match,
                verified_at=m.verified_at,
                equivalence_status=status,
                equivalence_reason=reason,
                # Leave equivalence_checked_at NULL until the worker
                # actually runs — a NOW() stamp on a never-attempted row
                # is misleading.
                equivalence_checked_at=None,
                pinned_commit=m.pinned_commit,
                proof_kind=m.proof_kind,
                matched_commit_sha=m.matched_commit_sha,
            )
        )
    return out


def _resolve_pinned_commit(
    session: Session,
    audit: AuditReport,
    row: AuditContractCoverage,
) -> str | None:
    """Recover the auditor-pinned commit for a ``reviewed_address`` row.

    The inline verify path carries ``pinned_commit`` on the
    ``CoverageMatch`` dataclass; the DB schema doesn't persist it.
    Phase F (address-anchored matches) targets a specific commit per
    scope entry, so the deferred verify worker re-derives that commit
    from ``audit.scope_entries`` by matching against the row's contract.

    Returns the commit SHA when a scope entry resolves (through proxy
    history if needed) to the same impl Contract this row covers, else
    ``None``. ``None`` falls through to "try every reviewed commit" —
    the proven outcome is identical, only the failure-mode reason text
    is broader.
    """
    if row.match_type != "reviewed_address":
        return None
    if not audit.scope_entries:
        return None
    audit_ts = _audit_effective_ts(audit.date)
    row_cache: _AddressRowCache = {}
    proxy_events_cache: dict[int, list[UpgradeEvent]] = {}
    for entry in audit.scope_entries:
        if not isinstance(entry, dict):
            continue
        commit = entry.get("commit")
        if not commit:
            continue
        target = _resolve_scope_entry_target(
            session,
            audit.protocol_id,
            entry,
            audit_ts=audit_ts,
            row_cache=row_cache,
            proxy_events_cache=proxy_events_cache,
        )
        if target is not None and target.id == row.contract_id:
            return str(commit)
    return None


def _stamp_coverage_row(
    session: Session,
    row: AuditContractCoverage,
    *,
    status: str,
    reason: str | None,
    proven: bool = False,
    proof_kind: str | None = None,
    matched_commit_sha: str | None = None,
    now: datetime | None = None,
) -> None:
    """Write a verification verdict back to one coverage row.

    On ``proven=True`` we upgrade ``match_type`` → ``reviewed_commit``
    and ``match_confidence`` → ``high`` so the timeline view sees the
    cryptographic proof override the heuristic temporal match.
    Other statuses leave the heuristic match intact — a failed
    verification annotates but never deletes.
    """
    now = now or datetime.now(timezone.utc)
    row.equivalence_status = status
    row.equivalence_reason = reason[:1000] if reason else None
    row.equivalence_checked_at = now
    if proven:
        row.match_type = "reviewed_commit"
        row.match_confidence = "high"
        row.proof_kind = proof_kind
        row.matched_commit_sha = matched_commit_sha
    else:
        # Non-proven verdicts must not carry a stale proof_kind /
        # matched_commit_sha from a prior proven attempt that was later
        # invalidated. Conservative: NULL them so the UI never shows
        # "proven" badges next to a non-proven status.
        row.proof_kind = None
        row.matched_commit_sha = None


def verify_one_coverage_row(
    session: Session,
    coverage_row_id: int,
    *,
    github_token: str | None = None,
) -> str | None:
    """Run source-equivalence on one ``audit_contract_coverage`` row.

    Resolves audit + contract from the row, fetches the impl source
    (DB-first, Etherscan fallback), and runs ``verify_audit_covers_impl``
    against the row's ``matched_name``. The verdict is persisted onto
    the row in the caller's session — caller commits.

    Returns the resulting ``equivalence_status`` or ``None`` if the row
    vanished. Re-running on a row that's already been verified is safe
    (it just re-writes the same verdict, possibly with a fresher
    ``equivalence_checked_at``); the worker only claims rows where
    ``equivalence_status='pending'`` so this is rarely exercised.

    Network errors are caught and mapped to transient statuses
    (``etherscan_fetch_failed`` / ``github_fetch_failed``) so the
    caller's transaction commits cleanly. The verify worker re-claims
    transients on its next pass after operator intervention promotes
    them back to ``pending``.
    """
    from services.audits.source_equivalence import (
        EtherscanFetch,
        VerifiedSource,
        fetch_db_source_files,
        fetch_etherscan_source_files,
        verify_audit_covers_impl,
    )

    row = session.get(AuditContractCoverage, coverage_row_id)
    if row is None:
        return None

    audit = session.get(AuditReport, row.audit_report_id)
    contract = session.get(Contract, row.contract_id)
    if audit is None or contract is None:
        _stamp_coverage_row(session, row, status="not_attempted", reason="audit or contract row vanished")
        return row.equivalence_status

    reviewed_commits = list(audit.reviewed_commits or [])
    referenced_repos = list(audit.referenced_repos or [])
    classified_commits = list(audit.classified_commits or [])
    source_repo = audit.source_repo

    if not reviewed_commits:
        _stamp_coverage_row(session, row, status="no_reviewed_commit", reason="audit has no reviewed_commits")
        return row.equivalence_status
    if not source_repo and not referenced_repos:
        _stamp_coverage_row(
            session, row, status="no_source_repo", reason="audit has no source_repo or referenced_repos"
        )
        return row.equivalence_status

    # Resolve impl source: DB rows first (free), Etherscan single-call fallback.
    # The deferred path makes one Etherscan call per row max — vs. the
    # inline path's per-batch fan-out — so the global Etherscan rate
    # limit is the only throttle that matters here.
    impl_source: VerifiedSource | None = fetch_db_source_files(session, contract.id)
    fetch_status = "ok"
    fetch_detail = ""
    if impl_source is None and contract.address:
        try:
            fetch = fetch_etherscan_source_files(contract.address)
        except Exception as exc:
            logger.exception(
                "verify_one_coverage_row: etherscan fetch crashed for contract %s",
                contract.id,
            )
            _stamp_coverage_row(session, row, status="etherscan_fetch_failed", reason=f"crash: {exc}")
            return row.equivalence_status
        if isinstance(fetch, EtherscanFetch):
            impl_source = fetch.source
            fetch_status = fetch.status
            fetch_detail = fetch.detail
        elif isinstance(fetch, VerifiedSource):
            # Backwards-compat: legacy stubs may still return the unwrapped
            # type. Treat as a happy fetch with empty detail.
            impl_source = fetch

    if impl_source is None:
        if fetch_status == "unverified":
            _stamp_coverage_row(
                session,
                row,
                status="etherscan_unverified",
                reason=fetch_detail or "no verified source",
            )
        else:
            _stamp_coverage_row(
                session,
                row,
                status="etherscan_fetch_failed",
                reason=fetch_detail or "etherscan fetch failed",
            )
        return row.equivalence_status

    pinned_commit = _resolve_pinned_commit(session, audit, row)

    try:
        outcome = verify_audit_covers_impl(
            reviewed_commits=reviewed_commits,
            scope_name=row.matched_name,
            impl_source=impl_source,
            source_repo=source_repo,
            github_token=github_token,
            specific_commit=pinned_commit,
            fallback_repos=referenced_repos,
        )
    except Exception as exc:
        logger.exception(
            "verify_one_coverage_row: verify crashed for row %s (audit=%s contract=%s)",
            coverage_row_id,
            row.audit_report_id,
            row.contract_id,
        )
        _stamp_coverage_row(session, row, status="github_fetch_failed", reason=f"crash: {exc}")
        return row.equivalence_status

    proven = outcome.status == "proven"
    proof_kind: str | None = None
    matched_commit_sha: str | None = None
    if proven:
        matched_commits = {em.commit.lower() for em in outcome.matches}
        proof_kind = _compute_proof_kind(matched_commits, classified_commits)
        for entry in classified_commits:
            sha = str(entry.get("sha") or "").lower()
            if sha and sha in matched_commits and entry.get("label") == "reviewed":
                matched_commit_sha = sha
                break
        if matched_commit_sha is None and matched_commits:
            matched_commit_sha = next(iter(matched_commits))

    _stamp_coverage_row(
        session,
        row,
        status=outcome.status,
        reason=outcome.reason,
        proven=proven,
        proof_kind=proof_kind,
        matched_commit_sha=matched_commit_sha,
    )
    return row.equivalence_status


def upsert_coverage_for_audit(
    session: Session,
    audit_id: int,
    *,
    verify_source_equivalence: bool = False,
) -> int:
    """Replace all coverage rows for ``audit_id`` with a fresh match.

    Two paths:

    - ``verify_source_equivalence=True`` (legacy): inline two-phase —
      compute matches, pre-load inputs, commit, run GitHub + Etherscan
      HTTP with the tx released, then open a fresh tx for the
      delete-then-insert. Used by the admin ``refresh_coverage`` endpoint
      where the caller is willing to wait minutes for cryptographic
      proof to land synchronously.

    - ``verify_source_equivalence=False`` (default): defer the verify
      pass to ``workers.coverage_verify``. Rows that *could* be proven
      land with ``equivalence_status='pending'`` so the verify worker
      drains them at a controlled rate; rows whose audit lacks inputs
      (``no_reviewed_commit`` / ``no_source_repo``) get a terminal
      status immediately. This keeps the synchronous coverage write
      under a second instead of holding the worker thread through tens
      of Etherscan calls — the Etherscan rate-limit storm that used to
      cascade across every worker on the box (#82).

    Returns inserted row count; caller commits.
    """
    audit = session.get(AuditReport, audit_id)
    if audit is None:
        # Nothing to rebuild — ensure no stale coverage rows linger.
        _persist_coverage_for_audit(session, audit_id, [])
        return 0

    if audit.scope_extraction_status != "success":
        # Nothing to insert — either not yet extracted or explicitly skipped.
        _persist_coverage_for_audit(session, audit_id, [])
        return 0

    matches = match_contracts_for_audit(session, audit_id)
    if not matches:
        logger.info(
            "coverage: audit %s has scope but no Contract rows matched in protocol %s",
            audit_id,
            audit.protocol_id,
        )
        _persist_coverage_for_audit(session, audit_id, [])
        return 0

    # Phase A2: pre-load anything the HTTP phase needs, then commit to
    # release the tx so network I/O isn't holding row locks.
    equiv_inputs = _preload_equivalence_inputs(session, matches) if verify_source_equivalence else None
    session.commit()

    if verify_source_equivalence and equiv_inputs is not None:
        matches = _apply_equivalence_http(matches, equiv_inputs)
    else:
        # Deferred path: stamp ``pending`` for rows the verify worker
        # can later prove; stamp the appropriate terminal otherwise.
        matches = _stamp_pending_when_verifiable(matches, {audit_id: audit})

    # Bytecode anchor — one eth_getCode per distinct impl. Runs outside
    # the tx; keccak stays NULL on RPC failure (drift-unknown, not
    # drift-detected). Cheap enough (one RPC per impl, not Etherscan)
    # to keep inline on both paths.
    matches = _apply_bytecode_anchor(session, matches)

    # Phase B: fresh transaction for the delete-then-insert.
    return _persist_coverage_for_audit(session, audit_id, matches)


def upsert_coverage_for_contract(
    session: Session,
    contract_id: int,
    *,
    verify_source_equivalence: bool = False,
) -> int:
    """Refresh coverage rows for one contract (delete-then-insert by contract_id).

    Called after a live upgrade changes the contract's impl windows.
    ``verify_source_equivalence`` selects between the inline-verify and
    deferred paths described on :func:`upsert_coverage_for_audit`. The
    coverage worker calls in with ``verify=False`` so the tens of
    Etherscan calls that used to ride on every coverage job now land
    on the dedicated ``CoverageVerifyWorker`` instead.
    """
    matches = match_audits_for_contract(session, contract_id)
    if matches:
        equiv_inputs = _preload_equivalence_inputs(session, matches) if verify_source_equivalence else None
        session.commit()
        if verify_source_equivalence and equiv_inputs is not None:
            matches = _apply_equivalence_http(matches, equiv_inputs)
        else:
            audit_ids = {m.audit_report_id for m in matches}
            audits_by_id: dict[int, AuditReport | None] = {aid: session.get(AuditReport, aid) for aid in audit_ids}
            matches = _stamp_pending_when_verifiable(matches, audits_by_id)
        matches = _apply_bytecode_anchor(session, matches)
    return _persist_coverage_for_contract(session, contract_id, matches)


def upsert_coverage_for_protocol(
    session: Session,
    protocol_id: int,
    *,
    verify_source_equivalence: bool = False,
) -> int:
    """Rebuild coverage for every scoped audit in a protocol. Idempotent.

    Batch entry point used by CLI flows, admin refresh endpoints, and
    integration tests. ``verify_source_equivalence`` adds ~2 HTTP/pair.
    """
    audit_ids = (
        session.execute(
            select(AuditReport.id).where(
                AuditReport.protocol_id == protocol_id,
                AuditReport.scope_extraction_status == "success",
            )
        )
        .scalars()
        .all()
    )
    total = 0
    for aid in audit_ids:
        total += upsert_coverage_for_audit(session, aid, verify_source_equivalence=verify_source_equivalence)
    return total
