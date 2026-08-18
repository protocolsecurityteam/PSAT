"""Build the per-contract audit timeline (impl windows + coverage rows)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AuditContractCoverage, AuditReport, Contract, UpgradeEvent
from schemas.api_responses import AuditBrief
from services.audits.serializers import _audit_brief
from utils.chains import UnknownChainError, chain_by_name


def _bytecode_keccak_now_batch(addresses: set[str], *, chain_id: int = 1) -> dict[str, str | None]:
    """Return ``{lower_address: keccak_hex_or_None}`` for a set of addresses.

    Reads ``code_keccak`` from the durable ``bytecode_cache`` (utils.rpc PG
    layer) on ``chain_id`` — derived from the timeline's contract row so an L2
    contract reads its own chain's cache, not mainnet's; only addresses absent
    there are fetched live. There is no timeline-local cache — dedup and
    size-bounding live in those shared layers, so a rapid reload of the surface
    view doesn't fire one RPC per audit row. The live fetch fallback
    (``services.audits.coverage._fetch_bytecode_keccak``) reads on the same
    chain, derived from ``chain_id`` via the registry."""
    from services.audits.coverage import _fetch_bytecode_keccak
    from utils.chains import chain_by_id
    from utils.rpc import _pg_bytecode_get

    chain_name = chain_by_id(chain_id).name
    out: dict[str, str | None] = {}
    for raw in addresses:
        if not raw:
            continue
        addr = raw.lower()
        pg_hit = _pg_bytecode_get(chain_id, addr)
        if pg_hit is not None:
            out[addr] = pg_hit[1]
            continue
        out[addr] = _fetch_bytecode_keccak(addr, chain_name)
    return out


def build_contract_audit_timeline(session: Session, contract_id: int) -> dict[str, Any] | None:
    """Per-impl audit timeline annotated with coverage. ``None`` for unknown contract."""
    contract = session.get(Contract, contract_id)
    if contract is None:
        return None

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

    addr_by_cid: dict[int, str] = {
        cid: addr
        for cid, addr in session.execute(
            select(Contract.id, Contract.address).where(Contract.id.in_(scope_contract_ids))
        ).all()
    }

    # Live bytecode keccak for every impl referenced by a coverage row —
    # one RPC per distinct address, cached briefly so repeated hits don't
    # spam the provider. Compared against the persisted
    # ``bytecode_keccak_at_match`` to produce ``bytecode_drift``.
    try:
        anchor_chain_id = chain_by_name(contract.chain).chain_id if contract.chain else 1
    except UnknownChainError:
        anchor_chain_id = 1
    live_keccaks = _bytecode_keccak_now_batch(
        {addr_by_cid[r.contract_id] for r in best_by_audit.values() if r.contract_id in addr_by_cid},
        chain_id=anchor_chain_id,
    )

    coverage_out: list[AuditBrief] = []
    for r in best_by_audit.values():
        audit = audits_by_id.get(r.audit_report_id)
        if not audit:
            continue
        brief = _audit_brief(audit, r)
        impl_addr = addr_by_cid.get(r.contract_id)
        brief["impl_address"] = impl_addr
        brief["bytecode_keccak_at_match"] = r.bytecode_keccak_at_match
        now_keccak = live_keccaks.get(impl_addr.lower()) if impl_addr else None
        brief["bytecode_keccak_now"] = now_keccak
        # Drift is only asserted when BOTH are known and differ. A NULL
        # on either side leaves drift=None so the UI can say
        # "unverified" rather than falsely flashing a drift warning.
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
            "chain": contract.chain,
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

    impl_contract = session.execute(
        select(Contract).where(
            Contract.address == current_impl.lower(),
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
    # ``covered_to_block is None`` alone is NOT "this row covers the currently-open
    # impl window" — it is also what a row whose upper bound was never
    # determined looks like, and this module's own ImplWindow docstring declares
    # that inference invalid ("``to_block=None`` alone does NOT mean 'still
    # current' — ``successor`` is what says that"). ``AuditContractCoverage``
    # carries no ``successor``-equivalent column, so the only evidence available
    # here is the LOWER bound: a row with a determined ``covered_from_block`` and
    # no upper bound is open-ended, while a row with neither bound was never
    # windowed at all and cannot earn the badge on the strength of a missing
    # number.
    #
    # Armed population 15 (``match_confidence='high'`` with BOTH bounds NULL);
    # realised badge changes today 0, because such a row does not currently land in
    # ``current_cov`` — the 2 high-confidence rows that DO are
    # ``covered_from_block`` set / ``covered_to_block`` NULL, i.e. genuinely
    # open-ended, and they keep the badge.
    has_temporal_high = any(
        r.match_confidence == "high"
        and r.covered_from_block is not None
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
