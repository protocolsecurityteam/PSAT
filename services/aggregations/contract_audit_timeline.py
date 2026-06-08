"""Build the per-contract audit timeline (impl windows + coverage rows)."""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AuditContractCoverage, AuditReport, Contract, UpgradeEvent
from services.audits.serializers import _audit_brief
from utils.rpc import require_supported_chain_id

logger = logging.getLogger(__name__)

# Per-process TTL cache of eth_getCode keccak hashes keyed by (chain_id, address).
# The audit_timeline endpoint fetches these live to compare against the
# per-coverage-row ``bytecode_keccak_at_match`` — a rapid reload of the
# surface view shouldn't fire one RPC per audit row on every request.
# TTL is intentionally short (30s) so "just upgraded" reflects quickly
# in the UI when someone's actively debugging a drift.
_BYTECODE_KECCAK_CACHE: dict[tuple[int, str], tuple[float, str]] = {}
_BYTECODE_KECCAK_TTL_SECONDS: float = 30.0


def _bytecode_keccak_now_batch(targets: set[tuple[int, str]]) -> dict[tuple[int, str], str]:
    """Return ``{(chain_id, lower_address): keccak_hex}`` for targets.

    Uses a short TTL cache so the typical burst-of-requests pattern (UI
    loading and user flipping between contracts) only pays for one RPC
    per impl per 30s. eRPC failures and no-code results raise so outages or
    invalid contract rows are visible instead of being treated as missing
    bytecode.
    """
    from services.audits.coverage import _fetch_bytecode_keccak

    now = time.monotonic()
    out: dict[tuple[int, str], str] = {}
    for raw_chain_id, raw_address in targets:
        if not raw_address:
            logger.error("audit timeline bytecode anchor target missing address chain_id=%s", raw_chain_id)
            raise RuntimeError("audit timeline bytecode anchor target missing address")
        chain_id = require_supported_chain_id(
            chain_id=raw_chain_id,
            context=f"audit timeline bytecode anchor for {raw_address}",
        )
        addr = raw_address.lower()
        key = (chain_id, addr)
        cached = _BYTECODE_KECCAK_CACHE.get(key)
        if cached is not None and (now - cached[0]) < _BYTECODE_KECCAK_TTL_SECONDS:
            out[key] = cached[1]
            continue
        keccak = _fetch_bytecode_keccak(addr, chain_id=chain_id)
        _BYTECODE_KECCAK_CACHE[key] = (now, keccak)
        out[key] = keccak
    return out


def build_contract_audit_timeline(session: Session, contract_id: int) -> dict[str, Any] | None:
    """Per-impl audit timeline annotated with coverage. ``None`` for unknown contract."""
    contract = session.get(Contract, contract_id)
    if contract is None:
        return None
    contract_chain_id = require_supported_chain_id(
        chain_id=contract.chain_id,
        context=f"audit timeline for contract {contract_id}",
    )

    # Historical upgrade windows on this contract if it's a proxy.
    upgrade_rows = (
        session.execute(
            select(UpgradeEvent)
            .where(UpgradeEvent.contract_id == contract.id)
            .order_by(
                UpgradeEvent.block_number.asc().nullslast(),
                UpgradeEvent.id.asc(),
            )
        )
        .scalars()
        .all()
    )
    impl_windows: list[dict[str, Any]] = []
    for i, ev in enumerate(upgrade_rows):
        nxt = upgrade_rows[i + 1] if i + 1 < len(upgrade_rows) else None
        impl_windows.append(
            {
                "impl_address": ev.new_impl,
                "from_block": ev.block_number,
                "to_block": nxt.block_number if nxt is not None else None,
                "from_ts": ev.timestamp.isoformat() if ev.timestamp else None,
                "to_ts": nxt.timestamp.isoformat() if (nxt and nxt.timestamp) else None,
                "tx_hash": ev.tx_hash,
            }
        )

    # Coverage rows. For a proxy the timeline should show every audit
    # that covered ANY impl in its history — not just direct name matches
    # on the proxy row. We union:
    #   - rows keyed to the contract itself (direct or impl_era coverage)
    #   - for proxies, rows keyed to every historical-impl Contract.id
    #     resolved from UpgradeEvent.new_impl, plus the current pointer
    #     in Contract.implementation
    scope_contract_ids: set[int] = {contract.id}
    if contract.is_proxy:
        impl_addrs: set[str] = set()
        if upgrade_rows:
            impl_addrs.update(ev.new_impl.lower() for ev in upgrade_rows if ev.new_impl)
        if contract.implementation:
            impl_addrs.add(contract.implementation.lower())
        if impl_addrs:
            impl_contract_ids = (
                session.execute(
                    select(Contract.id).where(
                        Contract.protocol_id == contract.protocol_id,
                        Contract.address.in_(impl_addrs),
                        Contract.chain_id == contract_chain_id,
                    )
                )
                .scalars()
                .all()
            )
            scope_contract_ids.update(impl_contract_ids)

    cov_rows = (
        session.execute(
            select(AuditContractCoverage).where(
                AuditContractCoverage.contract_id.in_(scope_contract_ids),
            )
        )
        .scalars()
        .all()
    )
    audit_ids = [r.audit_report_id for r in cov_rows]
    audits_by_id: dict[int, Any] = {}
    if audit_ids:
        audits_by_id = {
            a.id: a for a in session.execute(select(AuditReport).where(AuditReport.id.in_(audit_ids))).scalars().all()
        }

    # Dedupe: multiple impl rows can produce rows against the same
    # audit_id (the audit's scope name matched several historical impls).
    # Rank by (confidence, match_type) so cryptographic source-equivalence
    # proofs always beat heuristic temporal matches at equal confidence.
    from services.audits.coverage import _row_score

    best_by_audit: dict[int, Any] = {}
    for r in cov_rows:
        prev = best_by_audit.get(r.audit_report_id)
        if prev is None or _row_score(r) > _row_score(prev):
            best_by_audit[r.audit_report_id] = r

    contract_by_cid: dict[int, tuple[str, int]] = {}
    for cid, addr, chain_id in session.execute(
        select(Contract.id, Contract.address, Contract.chain_id).where(Contract.id.in_(scope_contract_ids))
    ).all():
        try:
            scoped_chain_id = require_supported_chain_id(
                chain_id=chain_id,
                context=f"audit timeline coverage contract {cid}",
            )
        except RuntimeError:
            logger.error("Audit timeline coverage contract %s is missing chain_id", cid)
            raise
        contract_by_cid[cid] = (addr, scoped_chain_id)

    missing_contract_ids = {r.contract_id for r in best_by_audit.values()} - set(contract_by_cid)
    if missing_contract_ids:
        ordered = sorted(missing_contract_ids)
        logger.error("Audit timeline coverage rows reference missing Contract rows: contract_ids=%s", ordered)
        raise RuntimeError(f"audit timeline coverage rows reference missing Contract rows: contract_ids={ordered}")

    # Live bytecode keccak for every impl referenced by a coverage row —
    # one RPC per distinct address, cached briefly so repeated hits don't
    # spam the provider. Compared against the persisted
    # ``bytecode_keccak_at_match`` to produce ``bytecode_drift``.
    live_keccaks = _bytecode_keccak_now_batch(
        {
            (chain_id, addr)
            for r in best_by_audit.values()
            for addr, chain_id in [contract_by_cid[r.contract_id]]
        }
    )

    coverage_out: list[dict[str, Any]] = []
    for r in best_by_audit.values():
        audit = audits_by_id.get(r.audit_report_id)
        if not audit:
            continue
        brief = _audit_brief(audit, r)
        impl_addr, impl_chain_id = contract_by_cid[r.contract_id]
        brief["impl_address"] = impl_addr
        brief["bytecode_keccak_at_match"] = r.bytecode_keccak_at_match
        now_keccak = live_keccaks[(impl_chain_id, impl_addr.lower())]
        brief["bytecode_keccak_now"] = now_keccak
        # Drift is only asserted when the persisted match-time anchor exists
        # and differs from the live bytecode hash. A NULL persisted anchor
        # leaves drift=None so the UI can say "unverified" rather than
        # falsely flashing a drift warning.
        if r.bytecode_keccak_at_match and now_keccak:
            brief["bytecode_drift"] = r.bytecode_keccak_at_match.lower() != now_keccak.lower()
        else:
            brief["bytecode_drift"] = None
        brief["verified_at"] = r.verified_at.isoformat() if r.verified_at else None
        # live_findings: audit.findings filtered to non-'fixed' statuses.
        # Phase 3a seeds these manually; Phase 3b (deferred) fills them
        # from scope extraction. None/missing → empty list, not an error.
        findings = audit.findings or []
        brief["live_findings"] = [
            f for f in findings if isinstance(f, dict) and (f.get("status") or "").lower() != "fixed"
        ]
        coverage_out.append(brief)
    coverage_out.sort(key=lambda e: (e.get("date") or "", e["audit_id"]), reverse=True)

    return {
        "contract": {
            "contract_id": contract.id,
            "address": contract.address,
            "chain_id": contract.chain_id,
            "contract_name": contract.contract_name,
            "is_proxy": contract.is_proxy,
            "current_implementation": contract.implementation,
        },
        "impl_windows": impl_windows,
        "coverage": coverage_out,
        "current_status": _current_status(session, contract, cov_rows),
    }


def _current_status(session: Session, contract: Contract, cov_rows: Sequence[Any]) -> str:
    """Compute the badge state for a contract's current code.

    "audited" is a strong claim we only grant when the current impl has a
    HIGH-confidence open-ended coverage row (audit dated inside the impl's
    active window). A 'medium' match means the audit sits in the grace
    zone on either side of the window boundary — those audits still
    appear in the ``coverage`` array, but the contract isn't badged as
    audited on their strength alone.
    """
    if not contract.is_proxy:
        return "non_proxy_audited" if cov_rows else "non_proxy_unaudited"

    current_impl = contract.implementation
    if not current_impl:
        return "never_audited" if not cov_rows else "unaudited_since_upgrade"

    contract_chain_id = require_supported_chain_id(
        chain_id=contract.chain_id,
        context=f"audit timeline current implementation lookup for contract {contract.id}",
    )
    impl_contract = session.execute(
        select(Contract).where(
            Contract.address == current_impl.lower(),
            Contract.chain_id == contract_chain_id,
            Contract.protocol_id == contract.protocol_id,
        )
    ).scalar_one_or_none()
    if impl_contract is None:
        return "unaudited_since_upgrade" if cov_rows else "never_audited"

    current_cov = [r for r in cov_rows if r.contract_id == impl_contract.id]
    # 'audited' requires definitive coverage of the currently-open impl
    # window. Two paths:
    #   (a) any row on this impl has a cryptographic proof
    #       (equivalence_status='proven') with a non-coincidental
    #       proof kind — strongest evidence, overrides everything else;
    #   (b) a high-confidence open-ended temporal match AND no
    #       hash_mismatch anywhere on the impl. hash_mismatch is strong
    #       negative evidence — deployed code differs from what the
    #       auditor reviewed — so we don't let a heuristic temporal
    #       match paper over cryptographic disproof from a different
    #       audit. Weak ``proof_kind='cited_only'`` rows don't qualify
    #       here either just because their coverage row is
    #       ``reviewed_commit/high``.
    has_proven = any(r.equivalence_status == "proven" and r.proof_kind != "cited_only" for r in current_cov)
    has_temporal_high = any(
        r.match_confidence == "high"
        and r.covered_to_block is None
        and not (r.equivalence_status == "proven" and r.proof_kind == "cited_only")
        for r in current_cov
    )
    has_hash_mismatch = any(r.equivalence_status == "hash_mismatch" for r in current_cov)
    if has_proven:
        return "audited"
    if has_temporal_high and not has_hash_mismatch:
        return "audited"
    if current_cov or cov_rows:
        return "unaudited_since_upgrade"
    return "never_audited"
