from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AuditContractCoverage, AuditReport, Contract, UpgradeEvent
from schemas.api_responses import AuditBrief
from schemas.upgrade_history import UPGRADE_FETCH_ERROR
from services.audits.serializers import _audit_brief
from utils.chains import UnknownChainError, chain_by_name
from utils.scoring_status import NOT_DETERMINED


def _bytecode_keccak_now_batch(addresses: set[str], *, chain_id: int = 1) -> dict[str, str | None]:
    """``{address: keccak or None}`` from ``bytecode_cache`` on the contract's own chain, fetching only misses live."""
    from services.audits.coverage import _fetch_bytecode_keccak
    from services.clients.rpc import _pg_bytecode_get
    from utils.chains import chain_by_id

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
    contract = session.get(Contract, contract_id)
    if contract is None:
        return None

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
    # A partial history can't place a window's end, nor rule out an upgrade inside one.
    history_unread = contract.upgrade_history_status == UPGRADE_FETCH_ERROR
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
                "bounds": NOT_DETERMINED if history_unread else "recorded",
            }
        )

    # For a proxy, union rows keyed to the contract and to every historical impl.
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

    # Rank by (confidence, match_type) so source-equivalence proofs beat temporal matches.
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
        # Drift only when both are known and differ; otherwise ``None`` (unverified).
        if r.bytecode_keccak_at_match and now_keccak:
            brief["bytecode_drift"] = r.bytecode_keccak_at_match.lower() != now_keccak.lower()
        else:
            brief["bytecode_drift"] = None
        brief["verified_at"] = r.verified_at.isoformat() if r.verified_at else None
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
            "upgrade_history_status": contract.upgrade_history_status or NOT_DETERMINED,
        },
        "impl_windows": impl_windows,
        "coverage": coverage_out,
        "current_status": _current_status(session, contract, cov_rows),
    }


def _current_status(session: Session, contract: Contract, cov_rows: Sequence[Any]) -> str:
    """ "audited" only for a high-confidence open-ended row on the current impl; 'medium' grace-zone matches appear in
    ``coverage`` but don't earn the badge.
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
    # Either (a) a proven, non-``cited_only`` equivalence row, or (b) a high open-ended temporal match with no
    # hash_mismatch anywhere on the impl (cryptographic disproof beats heuristics).
    has_proven = any(r.equivalence_status == "proven" and r.proof_kind != "cited_only" for r in current_cov)
    # ``covered_to_block is None`` alone isn't open-ended; it's also an undetermined bound. Require a determined
    # ``covered_from_block``.
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
