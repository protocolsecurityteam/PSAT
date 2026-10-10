"""Match audit reports to the implementation contracts they reviewed, persisted in ``audit_contract_coverage``.

Signals, cheapest first:

  - ``'direct'`` — scope name matches ``contract_name``; high with an audit date, medium without.
  - ``'impl_era'`` — name match and the impl was active at the audit date per ``UpgradeEvent``; medium within a 14-day
grace zone, low outside.
  - ``'reviewed_commit'`` — source-equivalence proof (``source_equivalence.py``); overrides to high. Opt-in: ~2 HTTP
requests per pair.

``AuditReport.source_commit`` is where the PDF was found, not what was reviewed; reviewed commits are in
``reviewed_commits``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final

from sqlalchemy import case, func, or_, select
from sqlalchemy import delete as sql_delete
from sqlalchemy.orm import Session

from db.jsonb import jsonb_has_payload
from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    UpgradeEvent,
)
from schemas.upgrade_history import UPGRADE_FETCH_ERROR
from utils.logging import record_degraded, record_stage_metric

logger = logging.getLogger(__name__)


# Audits published shortly after an upgrade usually reviewed the older impl.
GRACE_DAYS: Final[int] = 14


SUCCESSOR_NOT_DETERMINED = "not_determined"


@dataclass(frozen=True)
class ImplWindow:
    proxy_contract_id: int  # Contract.id of the proxy this window is on
    proxy_address: str
    # None = the writer couldn't determine the block (the poller reads a slot, not a log). ``to_block=None`` alone does
    # NOT mean current; ``successor`` says that.
    from_block: int | None
    to_block: int | None
    from_ts: datetime | None
    to_ts: datetime | None
    # 'none' — open. 'known' — replaced at a known block. 'block_unknown' — replaced, upper bound unknown.
    # 'not_determined' — the proxy's last history fetch errored, so an unread upgrade could fall inside or end it.
    successor: str = "none"


def _publishable_block_bounds(window: ImplWindow | None) -> tuple[int | None, int | None]:
    """Block bounds, or ``(None, None)`` if either is unknown: a NULL ``covered_to_block`` would read as open-ended
    and spread the audit across later impls.
    """
    if window is None:
        return None, None
    if window.from_block is None or window.successor in ("block_unknown", SUCCESSOR_NOT_DETERMINED):
        return None, None
    return window.from_block, window.to_block


@dataclass(frozen=True)
class CoverageMatch:
    audit_report_id: int
    contract_id: int
    protocol_id: int
    matched_name: str
    match_type: str  # 'direct' | 'impl_era' | 'reviewed_address' | 'reviewed_commit'
    match_confidence: str  # 'high' | 'medium' | 'low'
    covered_from_block: int | None = None
    covered_to_block: int | None = None
    # NULL on RPC failure means drift unknown, not detected.
    bytecode_keccak_at_match: str | None = None
    verified_at: datetime | None = None
    # None only on legacy rows predating verification.
    equivalence_status: str | None = None
    equivalence_reason: str | None = None
    equivalence_checked_at: datetime | None = None
    # Auditor-pinned commit from ``scope_entries``; narrows verification to it. Runtime hint only, not persisted.
    pinned_commit: str | None = None
    # Vocabulary: db.models.AuditContractCoverage.proof_kind.
    proof_kind: str | None = None
    # Prefers a ``reviewed``-labeled commit so the UI links what the auditor reviewed.
    matched_commit_sha: str | None = None


def _audit_effective_ts(audit_date: str | None) -> datetime | None:
    """Parse ``AuditReport.date`` (``YYYY-MM-DD`` / ``YYYY-MM`` / ``YYYY-MM-00`` / ``YYYY``) to end-of-period UTC,
    since audits finalize late in the period. ``None`` on malformed input.
    """
    if not audit_date:
        return None
    s = audit_date.strip()
    if not s:
        return None

    if len(s) >= 10 and s[4] == "-" and s[7] == "-":
        y, m, d = s[0:4], s[5:7], s[8:10]
        try:
            year, month, day = int(y), int(m), int(d)
            if day == 0:
                return _end_of_month(year, month)
            return datetime(year, month, day, 23, 59, 59, tzinfo=timezone.utc)
        except ValueError:
            return None

    if len(s) == 7 and s[4] == "-":
        try:
            return _end_of_month(int(s[0:4]), int(s[5:7]))
        except ValueError:
            return None

    if len(s) == 4 and s.isdigit():
        try:
            return datetime(int(s), 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        except ValueError:
            return None

    return None


def _end_of_month(year: int, month: int) -> datetime:
    if month == 12:
        first_of_next = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        first_of_next = datetime(year, month + 1, 1, tzinfo=timezone.utc)
    return first_of_next - timedelta(seconds=1)


def _compute_impl_windows_batch(session: Session, contracts: list[Contract]) -> dict[int, list[ImplWindow]]:
    """Impl windows per Contract.id in a fixed number of queries regardless of candidate count."""
    addr_to_ids: dict[str, list[int]] = {}
    for c in contracts:
        if c.address:
            addr_to_ids.setdefault(c.address.lower(), []).append(c.id)
    result: dict[int, list[ImplWindow]] = {c.id: [] for c in contracts}
    if not addr_to_ids:
        return result

    # ``new_impl`` may be mixed-case.
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
    addr_to_proxies: dict[str, set[int]] = {}
    for pid, impl_addr in proxy_rows:
        addr_to_proxies.setdefault(impl_addr, set()).add(pid)

    # NULL blocks sink so a block-less event doesn't corrupt ordering.
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

    proxy_addr_by_id: dict[int, str] = {}
    unread_history: set[int] = set()
    if proxy_ids:
        rows = session.execute(
            select(Contract.id, Contract.address, Contract.upgrade_history_status).where(Contract.id.in_(proxy_ids))
        ).all()
        for pid, addr, history_status in rows:
            proxy_addr_by_id[pid] = addr or ""
            if history_status == UPGRADE_FETCH_ERROR:
                unread_history.add(pid)

    windows_by_addr: dict[str, list[ImplWindow]] = {}
    for addr_lower, proxy_id_set in addr_to_proxies.items():
        windows: list[ImplWindow] = []
        for pid in proxy_id_set:
            proxy_events = events_by_proxy.get(pid) or []
            for i, ev in enumerate(proxy_events):
                if not ev.new_impl or ev.new_impl.lower() != addr_lower:
                    continue
                # ``or 0`` would sort a block-less event back to the front, undoing NULLS LAST.
                from_block = ev.block_number
                from_ts = ev.timestamp
                to_block: int | None = None
                to_ts: datetime | None = None
                successor = "none"
                if i + 1 < len(proxy_events):
                    nxt = proxy_events[i + 1]
                    to_block = nxt.block_number
                    to_ts = nxt.timestamp
                    successor = "known" if nxt.block_number is not None else "block_unknown"
                if pid in unread_history:
                    successor = SUCCESSOR_NOT_DETERMINED
                windows.append(
                    ImplWindow(
                        proxy_contract_id=pid,
                        proxy_address=proxy_addr_by_id.get(pid, ""),
                        from_block=from_block,
                        to_block=to_block,
                        from_ts=from_ts,
                        to_ts=to_ts,
                        successor=successor,
                    )
                )
        # Unknown starts sink, matching the SQL order.
        windows.sort(key=lambda w: (w.from_block is None, w.from_block or 0, w.proxy_contract_id))
        windows_by_addr[addr_lower] = windows

    for addr_lower, contract_ids in addr_to_ids.items():
        ws = windows_by_addr.get(addr_lower, [])
        for cid in contract_ids:
            result[cid] = list(ws)
    return result


def _compute_impl_windows_for_contract(session: Session, contract: Contract) -> list[ImplWindow]:
    return _compute_impl_windows_batch(session, [contract]).get(contract.id, [])


def _confidence_for_impl_era(audit_ts: datetime | None, windows: list[ImplWindow]) -> tuple[str, ImplWindow | None]:
    """``(confidence, window)``: high inside a window, medium within ``GRACE_DAYS`` of a boundary, low otherwise.

    Low rows still emit so the UI can flag badly-timed name matches. A window whose bounds weren't fully read is never
    better than low.
    """
    confidence, window = _confidence_for_read_era(audit_ts, windows)
    if window is not None and window.successor == SUCCESSOR_NOT_DETERMINED:
        return "low", window
    return confidence, window


def _confidence_for_read_era(audit_ts: datetime | None, windows: list[ImplWindow]) -> tuple[str, ImplWindow | None]:
    if not windows:
        return "low", None

    if audit_ts is None:
        # No audit date: attach to the open window (low). ``successor``, not ``to_block is None``: a window closed by a
        # block-less upgrade also has to_block=None.
        open_windows = [w for w in windows if w.successor == "none"]
        if open_windows:
            return "low", open_windows[0]
        return "low", windows[-1]

    for w in windows:
        if w.from_ts is None:
            continue
        if audit_ts >= w.from_ts and (w.to_ts is None or audit_ts < w.to_ts):
            return "high", w

    grace = timedelta(days=GRACE_DAYS)
    best_distance: timedelta | None = None
    best_window: ImplWindow | None = None
    for w in windows:
        if w.from_ts is None:
            continue
        if audit_ts < w.from_ts:
            dist = w.from_ts - audit_ts
        elif w.to_ts is not None and audit_ts >= w.to_ts:
            dist = audit_ts - w.to_ts
        else:
            dist = timedelta(0)
        if dist <= grace:
            if best_distance is None or dist < best_distance:
                best_distance = dist
                best_window = w
    if best_window is not None:
        return "medium", best_window

    # Nearest window anyway so a plausible anchor isn't NULL.
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
    """Never low: a clean name match with no history to falsify it beats a distant impl_era match."""
    return "high" if audit_ts is not None else "medium"


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
    """Best Contract for ``(protocol, address, chain)``.

    Legacy ``chain=NULL`` counts as Ethereum, but an explicit row wins. May fall back to the global row since
    ``contracts`` is unique by ``(address, chain)``.
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
    """Impl row for a coverage insert.

    Proxy with no history: current ``implementation``. With history but no placeable window, or a history whose last
    fetch errored: ``None`` rather than rebinding to today's impl.
    """
    chain_key = _normalize_chain(row.chain)
    if not row.is_proxy:
        return row
    if row.upgrade_history_status == UPGRADE_FETCH_ERROR:
        return None
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
    """``(by_contract, matched_names)`` from ``audit.scope_entries``, keyed by impl row; ``matched_names`` suppresses
    weaker name matches.
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
    """Find every protocol Contract matching a scope entry.

      1. Address-anchored: ``scope_entries`` with addresses map to one row each (``reviewed_address``); proxies resolve
    to the impl active at the audit date (``_reject_proxy_coverage`` enforces this in the DB); ambiguous proxies are
    skipped.
      2. Name-anchored (legacy): remaining names, case-insensitive; ``direct`` or ``impl_era``.

    At most one match per ``(contract_id, audit_id)``; highest ``_row_score`` wins.
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
        scope_lookup.setdefault(key, name)

    by_contract, addr_matched_names = _address_anchored_matches(session, audit, scope_entries)

    for n in addr_matched_names:
        scope_lookup.pop(n, None)

    if not scope_lookup:
        return list(by_contract.values())

    # Proxies are excluded here: generic names like ``UUPSProxy`` match proxy rows but the audit reviewed the impl. A DB
    # trigger enforces the same.
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

    windows_by_id = _compute_impl_windows_batch(session, list(candidates))

    # ``_row_score`` decides collisions with address-anchored wins.
    for c in candidates:
        matched_name = scope_lookup.get(_normalize_name(c.contract_name))
        if not matched_name:
            logger.debug(
                "coverage match skip",
                extra={"reason": "scope_name_trimmed", "contract_id": c.id, "audit_id": audit.id},
            )
            continue
        windows = windows_by_id.get(c.id, [])
        if windows:
            confidence, window = _confidence_for_impl_era(audit_ts, windows)
            cov_from, cov_to = _publishable_block_bounds(window)
            match = CoverageMatch(
                audit_report_id=audit.id,
                contract_id=c.id,
                protocol_id=audit.protocol_id,
                matched_name=matched_name,
                match_type="impl_era",
                match_confidence=confidence,
                covered_from_block=cov_from,
                covered_to_block=cov_to,
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
# Tiebreaker within equal confidence: reviewed_commit > impl_era > direct. Confidence always dominates.
_MATCH_TYPE_ORDER: Final[dict[str, int]] = {
    "direct": 0,
    "impl_era": 1,
    # Beats name heuristics; weaker than reviewed_commit, which also verifies bytes.
    "reviewed_address": 2,
    "reviewed_commit": 3,
}


def _row_score(row) -> tuple[int, int]:
    """``(confidence, match_type)`` rank shared with the timeline dedupe so both agree.

    Works on CoverageMatch and ORM rows.
    """
    return (
        _CONFIDENCE_ORDER.get(row.match_confidence, 0),
        _MATCH_TYPE_ORDER.get(row.match_type, 0),
    )


def match_audits_for_contract(session: Session, contract_id: int) -> list[CoverageMatch]:
    """One CoverageMatch per audit whose scope names this contract (by address or name).

    Proxies are excluded unconditionally.
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
                    # ``scope_entries`` is JSONB: a Python ``None`` is stored as jsonb null, which passes a SQL null
                    # test.
                    AuditReport.scope_contracts.isnot(None),
                    jsonb_has_payload(AuditReport.scope_entries),
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

    best_by_audit: dict[int, CoverageMatch] = {}

    for audit in audits:
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

        if audit.id in best_by_audit:
            continue
        scope_names = audit.scope_contracts or []
        matched_name = next((n for n in scope_names if _normalize_name(n) == name_key), None)
        if not matched_name:
            logger.debug(
                "coverage match skip",
                extra={"reason": "no_name_match", "contract_id": contract.id, "audit_id": audit.id},
            )
            continue
        if windows:
            confidence, window = _confidence_for_impl_era(audit_ts, windows)
            cov_from, cov_to = _publishable_block_bounds(window)
            best_by_audit[audit.id] = CoverageMatch(
                audit_report_id=audit.id,
                contract_id=contract.id,
                protocol_id=contract.protocol_id,
                matched_name=matched_name,
                match_type="impl_era",
                match_confidence=confidence,
                covered_from_block=cov_from,
                covered_to_block=cov_to,
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


def _rpc_url(chain: str) -> str:
    """eRPC route on the contract's own chain. Raises on unknown chain; the caller records drift unknown."""
    from services.clients.rpc import require_rpc_url

    return require_rpc_url(chain=chain, context="audit coverage bytecode anchor")


def _fetch_bytecode_keccak(address: str, chain: str) -> str | None:
    """``"0x" + 64hex``, or ``None`` on RPC failure or no code: drift unknown beats a fabricated hash."""
    from eth_utils.crypto import keccak

    from services.clients.rpc import get_code

    if not address:
        return None
    try:
        code_hex = get_code(_rpc_url(chain), address)
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
    """One RPC per distinct impl, run with the tx released."""
    if not matches:
        return matches
    row_by_cid: dict[int, tuple[str, str | None]] = {
        cid: (addr, chain)
        for cid, addr, chain in session.execute(
            select(Contract.id, Contract.address, Contract.chain).where(
                Contract.id.in_({m.contract_id for m in matches})
            )
        ).all()
    }

    keccak_by_cid: dict[int, str | None] = {}
    for cid, (addr, chain) in row_by_cid.items():
        keccak_by_cid[cid] = _fetch_bytecode_keccak(addr, chain or "ethereum")

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
                # A NULL keccak with a fresh timestamp is misleading.
                verified_at=now if kk is not None else m.verified_at,
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
    """Materialized in the DB phase so the HTTP phase runs with no transaction."""

    audit_report_id: int
    contract_id: int
    contract_address: str | None
    contract_chain: str | None
    reviewed_commits: tuple[str, ...]
    scope_contracts: tuple[str, ...]
    source_repo: str | None
    # Fallback repos when ``source_repo`` lacks the commit.
    referenced_repos: tuple[str, ...]
    classified_commits: tuple[dict, ...]
    # None: fall back to Etherscan. ``Any`` keeps this module importable without the source-equivalence deps.
    db_impl_source: Any


def _preload_equivalence_inputs(
    session: Session, matches: list[CoverageMatch]
) -> dict[tuple[int, int], _EquivalenceInputs]:
    """Matches lacking commits/repo are recorded with empty tuples so the HTTP phase can skip them cheaply."""
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
            contract_chain=contract.chain,
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
    """Map a proven pair to ``proof_kind``:

    - ``unclassified`` — no classification data
    - ``clean`` — matched ``reviewed``, and no ``fix`` commits or a ``fix`` also matched
    - ``pre_fix_unpatched`` — matched ``reviewed``, ``fix`` commits exist, none matched: known findings are deployed
    - ``post_fix`` — matched only a ``fix``
    - ``cited_only`` — matched only ``cited``/``unclear``: coincidental
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

    # LLM SHAs vary in length; compare 7-char prefixes (git's default abbrev).
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
        return "pre_fix_unpatched"
    if matched_reviewed:
        return "clean"
    if matched_fix:
        return "post_fix"
    return "cited_only"


def _apply_equivalence_http(
    matches: list[CoverageMatch],
    inputs: dict[tuple[int, int], _EquivalenceInputs],
) -> list[CoverageMatch]:
    """HTTP phase: stamp every match with a verdict, scoped to the row's own ``matched_name`` so reasons describe the
    right contract. ``proven`` upgrades to ``reviewed_commit``/high; other statuses annotate without deleting. 4
    workers stay inside GitHub's 5000/hr and the locked Etherscan cache.
    """
    import os
    import threading

    from services.audits.source_equivalence import (
        EtherscanFetch,
        VerifiedSource,
        fetch_etherscan_source_files,
        verify_audit_covers_impl,
    )
    from services.concurrency import parallel_map

    gh_token = os.environ.get("GITHUB_TOKEN") or None
    # Two rows on one impl pay one Etherscan call; the lock guards check-then-set across threads.
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

    def _fetch_etherscan(addr_key: str, contract_address: str, contract_id: int, chain: str | None) -> EtherscanFetch:
        with cache_lock:
            cached = etherscan_cache.get(addr_key)
        if cached is not None:
            return cached
        try:
            from utils.chains import require_chain

            raw_fetch = fetch_etherscan_source_files(
                contract_address,
                chain_id=require_chain(chain=chain or "ethereum", context="coverage etherscan fetch").chain_id,
            )
            if isinstance(raw_fetch, EtherscanFetch):
                fetch = raw_fetch
            elif isinstance(raw_fetch, VerifiedSource):
                # Legacy stubs return the pre-envelope type.
                fetch = EtherscanFetch(source=raw_fetch, status="ok", detail="")
            else:
                raise TypeError(
                    f"fetch_etherscan_source_files returned {type(raw_fetch).__name__}, expected EtherscanFetch"
                )
        except Exception as exc:
            # Degrades to a transient status; doesn't fail the job.
            logger.warning(
                "source-equivalence Etherscan fetch crashed for contract %s",
                contract_id,
                extra={"exc_type": type(exc).__name__, "contract_id": contract_id},
            )
            record_degraded(phase="coverage_etherscan_fetch", exc=exc, context={"contract_id": contract_id})
            fetch = EtherscanFetch(source=None, status="fetch_failed", detail=f"crash: {exc}")
        with cache_lock:
            # First writer wins so a later error can't clobber a success.
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

        impl_source = data.db_impl_source
        fetch_status = "ok"
        fetch_detail = ""
        if impl_source is None and data.contract_address:
            fetch = _fetch_etherscan(
                data.contract_address.lower(), data.contract_address, m.contract_id, data.contract_chain
            )
            impl_source = fetch.source
            fetch_status = fetch.status
            fetch_detail = fetch.detail

        if impl_source is None:
            if fetch_status == "unverified":
                return _stamp(m, status="etherscan_unverified", reason=fetch_detail or "no verified source")
            return _stamp(m, status="etherscan_fetch_failed", reason=fetch_detail or "etherscan fetch failed")

        # Scoped to this row's matched_name so the reason describes the right contract. A pinned commit narrows to that
        # SHA; ``referenced_repos`` are fallbacks.
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
            logger.warning(
                "source-equivalence check crashed for audit %s / contract %s",
                m.audit_report_id,
                m.contract_id,
                extra={
                    "exc_type": type(exc).__name__,
                    "audit_id": m.audit_report_id,
                    "contract_id": m.contract_id,
                },
            )
            record_degraded(
                phase="coverage_source_equivalence",
                exc=exc,
                context={"audit_id": m.audit_report_id, "contract_id": m.contract_id},
            )
            return _stamp(m, status="github_fetch_failed", reason=f"crash: {exc}")

        proven = outcome.status == "proven"
        proof_kind: str | None = None
        matched_commit_sha: str | None = None
        if proven:
            matched_commits = {em.commit.lower() for em in outcome.matches}
            proof_kind = _compute_proof_kind(matched_commits, list(data.classified_commits))
            # Prefer a ``reviewed`` commit for the UI link.
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
    session.execute(sql_delete(AuditContractCoverage).where(AuditContractCoverage.audit_report_id == audit_id))
    for match in matches:
        session.add(AuditContractCoverage(**_match_to_row_kwargs(match)))
    return len(matches)


def _persist_coverage_for_contract(session: Session, contract_id: int, matches: list[CoverageMatch]) -> int:
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


def _stamp_pending_when_verifiable(
    matches: list[CoverageMatch],
    audits_by_id: dict[int, AuditReport | None],
) -> list[CoverageMatch]:
    """Deferred path: verifiable rows land ``pending`` for ``workers.coverage_verify``; rows lacking inputs get a
    terminal status now (a re-extraction re-stamps them).
    """
    out: list[CoverageMatch] = []
    for m in matches:
        # Don't override stamps from the inline path.
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
                # NOW() on a never-attempted row is misleading.
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
    """Recover the auditor-pinned commit for a ``reviewed_address`` row from ``audit.scope_entries`` (it isn't
    persisted). ``None`` falls back to every reviewed commit: same proof, broader failure reason.
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
    """Write a verdict to one coverage row. ``proven`` upgrades to ``reviewed_commit``/high; others annotate only.

    A status change marks the protocol score dirty: proven equivalence settles here asynchronously, long after the
    effects stage.
    """
    now = now or datetime.now(timezone.utc)
    previous = row.equivalence_status
    row.equivalence_status = status
    row.equivalence_reason = reason[:1000] if reason else None
    row.equivalence_checked_at = now
    if status != previous and row.protocol_id is not None:
        from services.scoring.dirty import SCORE_DIRTY_COVERAGE_VERIFY, mark_protocol_score_dirty

        mark_protocol_score_dirty(session, row.protocol_id, SCORE_DIRTY_COVERAGE_VERIFY)
    if proven:
        row.match_type = "reviewed_commit"
        row.match_confidence = "high"
        row.proof_kind = proof_kind
        row.matched_commit_sha = matched_commit_sha
    else:
        # Clear stale proof fields so no "proven" badge sits beside a non-proven status.
        row.proof_kind = None
        row.matched_commit_sha = None


def verify_one_coverage_row(
    session: Session,
    coverage_row_id: int,
    *,
    github_token: str | None = None,
) -> str | None:
    """Run source-equivalence on one coverage row; the verdict is written in the caller's session.

    Returns the status, or ``None`` if the row vanished. Network errors map to transient statuses so the transaction
    commits cleanly.
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

    # At most one Etherscan call per row, so the global rate limit is the only throttle.
    impl_source: VerifiedSource | None = fetch_db_source_files(session, contract.id)
    fetch_status = "ok"
    fetch_detail = ""
    if impl_source is None and contract.address:
        try:
            from utils.chains import require_chain

            fetch = fetch_etherscan_source_files(
                contract.address,
                chain_id=require_chain(
                    chain=contract.chain or "ethereum", context="coverage row etherscan fetch"
                ).chain_id,
            )
        except Exception as exc:
            logger.warning(
                "verify_one_coverage_row: etherscan fetch crashed for contract %s",
                contract.id,
                extra={"exc_type": type(exc).__name__, "contract_id": contract.id},
            )
            record_degraded(phase="coverage_etherscan_fetch", exc=exc, context={"contract_id": contract.id})
            _stamp_coverage_row(session, row, status="etherscan_fetch_failed", reason=f"crash: {exc}")
            return row.equivalence_status
        if isinstance(fetch, EtherscanFetch):
            impl_source = fetch.source
            fetch_status = fetch.status
            fetch_detail = fetch.detail
        elif isinstance(fetch, VerifiedSource):
            # Legacy stubs return the unwrapped type.
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
        logger.warning(
            "verify_one_coverage_row: verify crashed for row %s (audit=%s contract=%s)",
            coverage_row_id,
            row.audit_report_id,
            row.contract_id,
            extra={
                "exc_type": type(exc).__name__,
                "row_id": coverage_row_id,
                "audit_id": row.audit_report_id,
                "contract_id": row.contract_id,
            },
        )
        record_degraded(
            phase="coverage_source_equivalence",
            exc=exc,
            context={"row_id": coverage_row_id, "audit_id": row.audit_report_id, "contract_id": row.contract_id},
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
    """Replace all coverage rows for ``audit_id``. Returns inserted count; caller commits.

    - ``verify_source_equivalence=True``: inline, with HTTP run between two transactions. For admin
    ``refresh_coverage``, which waits minutes for proof.
    - ``False`` (default): verifiable rows land ``pending`` for ``workers.coverage_verify``. Keeps the write under a
    second; inline Etherscan calls caused a rate-limit storm across every worker (#82).
    """
    audit = session.get(AuditReport, audit_id)
    if audit is None:
        _persist_coverage_for_audit(session, audit_id, [])
        return 0

    if audit.scope_extraction_status != "success":
        _persist_coverage_for_audit(session, audit_id, [])
        return 0

    matches = match_contracts_for_audit(session, audit_id)
    record_stage_metric("coverage_matches", len(matches))
    if not matches:
        logger.info(
            "coverage: audit %s has scope but no Contract rows matched in protocol %s",
            audit_id,
            audit.protocol_id,
            extra={"audit_id": audit_id, "protocol_id": audit.protocol_id, "matches": 0},
        )
        _persist_coverage_for_audit(session, audit_id, [])
        return 0

    # Commit before network I/O so row locks aren't held.
    equiv_inputs = _preload_equivalence_inputs(session, matches) if verify_source_equivalence else None
    session.commit()

    if verify_source_equivalence and equiv_inputs is not None:
        matches = _apply_equivalence_http(matches, equiv_inputs)
    else:
        matches = _stamp_pending_when_verifiable(matches, {audit_id: audit})

    # Cheap (eth_getCode, not Etherscan), so inline on both paths.
    matches = _apply_bytecode_anchor(session, matches)

    return _persist_coverage_for_audit(session, audit_id, matches)


def upsert_coverage_for_contract(
    session: Session,
    contract_id: int,
    *,
    verify_source_equivalence: bool = False,
) -> int:
    """Refresh one contract's coverage after an upgrade changes its impl windows.

    See :func:`upsert_coverage_for_audit` for the verify modes.
    """
    matches = match_audits_for_contract(session, contract_id)
    record_stage_metric("coverage_matches", len(matches))
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
    """Rebuild coverage for every scoped audit in a protocol. Idempotent."""
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
