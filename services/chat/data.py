"""Read-side helpers for chat tools, returning JSON-serializable primitives.

They re-query rather than share code with the company/timeline routes to avoid regressing those routes.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import selectinload

from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    ContractSummary,
    Job,
    JobStatus,
    Protocol,
    UpgradeEvent,
)

# NULL/empty stays its own bucket: treating it as Ethereum turns missing data into false confidence.
_CHAIN_ALIASES = {"ethereum": "ethereum", "mainnet": "ethereum"}


def _canonical_chain(c: str | None) -> str | None:
    if not c:
        return None
    return _CHAIN_ALIASES.get(c.lower(), c.lower())


def _chain_match_values(canonical: str) -> list[str]:
    """The alias fold expanded for SQL, or a ``mainnet`` row is invisible to ``chain="ethereum"``."""
    values = {canonical}
    values.update(stored for stored, folded in _CHAIN_ALIASES.items() if folded == canonical)
    return sorted(values)


def classify_address(session, address: str, chain: str | None = None) -> dict[str, Any]:
    """Resolve an address to its control type and gating properties, with a plain-English ``note``, so the model
    never infers EOA vs contract (the main anti-hallucination lever).

    Sources: ``control_graph_nodes`` type/details, then a ``contracts`` row (generic contract), else "unknown" with a
    verify-first note.
    """
    from db.models import ControlGraphNode

    if not address:
        return {"address": address, "kind": "unknown", "is_eoa": False, "note": ""}
    addr_lc = address.lower()

    # CGN has no chain column; scope via the Contract join. Cross-chain twins exist (``0x5bdd4b0d…`` TopUp on ethereum
    # and scroll); aliasing is unrealised only because no second-chain analysis has run. No chain given keeps the
    # address-only lookup rather than inventing mainnet.
    stmt = select(ControlGraphNode).join(Contract, ControlGraphNode.contract_id == Contract.id)
    stmt = stmt.where(func.lower(ControlGraphNode.address) == addr_lc)
    canonical = _canonical_chain(chain)
    if canonical is not None:
        stmt = stmt.where(func.lower(Contract.chain).in_(_chain_match_values(canonical)))
    # An unordered LIMIT 1 is a coin flip: some addresses have rows disagreeing on type. Total order preferring the
    # classified row.
    stmt = stmt.order_by(
        case((ControlGraphNode.resolved_type.is_(None), 1), (ControlGraphNode.resolved_type == "unknown", 1), else_=0),
        ControlGraphNode.id.asc(),
    ).limit(1)
    cg_node = session.execute(stmt).scalars().first()
    contract = _resolve_contract(session, address, chain)

    details = (cg_node.details if cg_node else None) or {}
    kind = (cg_node.resolved_type if cg_node else None) or ("contract" if contract else "unknown")
    label = (cg_node.contract_name if cg_node else None) or (contract.contract_name if contract else None)

    # Many timelocks are typed plain "contract" with a delay in details; promote so the delay window isn't lost.
    raw_delay = details.get("delay") or details.get("delay_seconds")
    name_hint = (label or "").lower()
    if kind == "contract" and ((isinstance(raw_delay, (int, float)) and raw_delay > 0) or "timelock" in name_hint):
        kind = "timelock"

    out: dict[str, Any] = {
        "address": address,
        "kind": kind,
        "is_eoa": kind == "eoa",
        "has_bytecode": kind != "eoa" if kind != "unknown" else None,
        "label": label,
    }

    threshold = details.get("threshold")
    if threshold is not None:
        out["threshold"] = threshold
    owners = details.get("owners")
    if owners:
        out["owners"] = owners
        out["owner_count"] = len(owners)
    delay = details.get("delay") or details.get("delay_seconds")
    if delay is not None:
        out["delay_seconds"] = delay

    return out


def _resolve_contract(session, address: str, chain: str | None) -> Contract | None:
    """Find a Contract by address. The LLM's chain hint is sometimes wrong:

    1. With chain: address + canonical chain (ethereum ≡ mainnet); a miss falls to (3).
    2. Without chain: address-only.
    3. Fallback: address-only, preferring ethereum/mainnet, NULL last.
    """
    if not address:
        return None
    addr_lc = address.lower()
    rows = session.execute(select(Contract).where(func.lower(Contract.address) == addr_lc)).scalars().all()
    if not rows:
        return None
    if len(rows) == 1:
        return rows[0]

    if chain is not None:
        target = _canonical_chain(chain)
        canonical_matches = [r for r in rows if _canonical_chain(r.chain) == target]
        if canonical_matches:
            return canonical_matches[0]
        # The LLM's hint was probably wrong.

    eth = [r for r in rows if _canonical_chain(r.chain) == "ethereum"]
    if eth:
        return eth[0]
    nonempty = [r for r in rows if r.chain]
    if nonempty:
        return nonempty[0]
    return rows[0]


def contract_brief(session, address: str, chain: str | None = None) -> dict[str, Any]:
    """One-screen contract summary; every address is annotated via ``classify_address``."""
    from db.models import ControllerValue

    contract = _resolve_contract(session, address, chain)
    if contract is None:
        return {"error": f"contract not found: {address} on chain={chain}"}

    summary = session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == contract.id)
    ).scalar_one_or_none()

    # Timestamp first: poll-detected upgrades have NULL blocks, and NULLS LAST reported the newest upgrade as oldest.
    # Block NULLS FIRST, then id for a total order.
    last_event = (
        session.execute(
            select(UpgradeEvent)
            .where(UpgradeEvent.contract_id == contract.id)
            .order_by(
                UpgradeEvent.timestamp.desc().nullslast(),
                UpgradeEvent.block_number.desc().nullsfirst(),
                UpgradeEvent.id.desc(),
            )
            .limit(1)
        )
        .scalars()
        .first()
    )

    # Otherwise the model treats every controller as an EOA.
    cv_rows = session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract.id)).scalars().all()
    controllers: dict[str, dict[str, Any]] = {}
    for cv in cv_rows:
        if cv.value and cv.value.startswith("0x"):
            controllers[cv.controller_id] = classify_address(session, cv.value, chain)
        else:
            controllers[cv.controller_id] = {"value": cv.value}

    self_kind = classify_address(session, contract.address, contract.chain)

    return {
        "address": contract.address,
        "chain": contract.chain,
        "name": contract.contract_name,
        "kind": self_kind.get("kind"),
        "is_eoa": self_kind.get("is_eoa", False),
        "has_bytecode": True,  # by definition: it's in the contracts table
        "delay_seconds": self_kind.get("delay_seconds"),
        "threshold": self_kind.get("threshold"),
        "owner_count": self_kind.get("owner_count"),
        "is_proxy": bool(contract.is_proxy),
        "proxy_type": contract.proxy_type,
        "implementation": contract.implementation,
        "deployer": contract.deployer,
        "source_verified": summary.source_verified if summary else None,
        "is_pausable": summary.is_pausable if summary else None,
        "has_timelock": summary.has_timelock if summary else None,
        "control_model": summary.control_model if summary else None,
        "controllers": controllers,
        "last_upgrade": (
            {
                "block": last_event.block_number,
                "timestamp": last_event.timestamp.isoformat() if last_event.timestamp else None,
                "new_impl": last_event.new_impl,
                "tx_hash": last_event.tx_hash,
                # An LLM may read ``"block": null`` as block zero; name the route instead.
                "detection": ("log_indexed" if last_event.block_number is not None else "poll_detected"),
            }
            if last_event
            else None
        ),
    }


def upgrade_summary(session, address: str, chain: str | None = None) -> dict[str, Any]:
    contract = _resolve_contract(session, address, chain)
    if contract is None:
        return {"error": f"contract not found: {address}"}

    rows = (
        session.execute(
            select(UpgradeEvent)
            .where(UpgradeEvent.contract_id == contract.id)
            .order_by(UpgradeEvent.block_number.asc().nullslast(), UpgradeEvent.id.asc())
        )
        .scalars()
        .all()
    )
    impls = []
    for i, ev in enumerate(rows):
        nxt = rows[i + 1] if i + 1 < len(rows) else None
        impls.append(
            {
                "impl_address": ev.new_impl,
                "from_block": ev.block_number,
                "to_block": nxt.block_number if nxt else None,
                "from_ts": ev.timestamp.isoformat() if ev.timestamp else None,
                "tx_hash": ev.tx_hash,
            }
        )

    impl_addrs = {ev.new_impl.lower() for ev in rows if ev.new_impl}
    if contract.implementation:
        impl_addrs.add(contract.implementation.lower())
    scope_ids = {contract.id}
    if impl_addrs:
        scope_ids.update(
            r[0] for r in session.execute(select(Contract.id).where(func.lower(Contract.address).in_(impl_addrs))).all()
        )

    coverage_rows = session.execute(
        select(AuditContractCoverage, AuditReport)
        .join(AuditReport, AuditContractCoverage.audit_report_id == AuditReport.id)
        .where(AuditContractCoverage.contract_id.in_(scope_ids))
    ).all()
    coverage = [
        {
            "audit_id": cov.audit_report_id,
            "auditor": rep.auditor,
            "title": rep.title,
            "date": rep.date.isoformat() if rep.date else None,
            "covered_from_block": cov.covered_from_block,
            "covered_to_block": cov.covered_to_block,
            "match_type": cov.match_type,
        }
        for cov, rep in coverage_rows
    ]

    return {
        "address": contract.address,
        "is_proxy": bool(contract.is_proxy),
        "current_implementation": contract.implementation,
        "impl_count": len(impls),
        "impls": impls,
        "audit_count": len(coverage),
        "coverage": coverage,
    }


def live_findings(
    session,
    *,
    address: str | None = None,
    company: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Findings still affecting current code (status != 'fixed'), by address and/or company, capped at ``limit``."""
    stmt = select(AuditReport)
    if address:
        addr_lc = address.lower()
        stmt = (
            stmt.join(AuditContractCoverage, AuditContractCoverage.audit_report_id == AuditReport.id)
            .join(Contract, Contract.id == AuditContractCoverage.contract_id)
            .where(func.lower(Contract.address) == addr_lc)
        )
    if company:
        proto = session.execute(select(Protocol).where(Protocol.name == company)).scalar_one_or_none()
        if proto is None:
            return {"findings": [], "truncated": False}
        stmt = stmt.where(AuditReport.protocol_id == proto.id)
    audits = session.execute(stmt.distinct()).scalars().all()
    out = []
    for rep in audits:
        for f in rep.findings or []:
            if (f.get("status") or "").lower() == "fixed":
                continue
            out.append(
                {
                    "audit_id": rep.id,
                    "auditor": rep.auditor,
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "status": f.get("status"),
                    "contract_hint": f.get("contract_hint"),
                }
            )
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break
    return {"findings": out, "truncated": len(out) >= limit}


def protocol_brief(session, name: str) -> dict[str, Any]:
    proto = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if proto is None:
        return {"error": f"protocol not found: {name}"}

    job_ids = [
        j.id
        for j in session.execute(
            select(Job).where(
                Job.protocol_id == proto.id,
                Job.status == JobStatus.completed,
                Job.address.isnot(None),
            )
        ).scalars()
    ]
    contracts = session.execute(select(Contract).where(Contract.job_id.in_(job_ids))).scalars().all() if job_ids else []
    proxy_count = sum(1 for c in contracts if c.is_proxy)
    # Must match /audits and /audit_coverage ``audit_count``.
    audit_count = session.execute(
        select(func.count(AuditReport.id)).where(AuditReport.protocol_id == proto.id)
    ).scalar_one()

    return {
        "name": proto.name,
        "contract_count": len(contracts),
        "proxy_count": proxy_count,
        "audit_count": audit_count,
    }


def list_protocol_principals(session, name: str) -> dict[str, Any]:
    from db.models import ControlGraphNode  # local import to avoid cycle at module load

    proto = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if proto is None:
        return {"error": f"protocol not found: {name}"}
    job_ids = [
        j.id
        for j in session.execute(
            select(Job).where(Job.protocol_id == proto.id, Job.status == JobStatus.completed)
        ).scalars()
    ]
    if not job_ids:
        return {"principals": []}
    contract_ids = [c.id for c in session.execute(select(Contract).where(Contract.job_id.in_(job_ids))).scalars()]
    nodes = (
        session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id.in_(contract_ids))).scalars().all()
    )
    by_addr: dict[str, dict[str, Any]] = {}
    for n in nodes:
        if not n.address or n.address.startswith("role:"):
            continue
        slot = by_addr.setdefault(
            n.address.lower(),
            {
                "address": n.address,
                "controls_count": 0,
            },
        )
        slot["controls_count"] += 1

    # So the model can't call a Timelock or a 4-of-7 Safe "a single EOA".
    out = []
    for entry in by_addr.values():
        cls = classify_address(session, entry["address"])
        merged = {**cls, "controls_count": entry["controls_count"]}
        out.append(merged)

    principals = sorted(
        out,
        key=lambda p: (-p["controls_count"], p.get("address") or ""),
    )
    return {"principals": principals[:30]}


ROLE_SOURCE_NOT_A_ROLE = (
    "function_principals.origin is a resolver-source constant "
    "('semantic_capability:finite_set' on 1132/1132 rows), not a role name; roles are derived "
    "from each function's capability_expr role grants (effective_functions.authority_roles is "
    "the fallback when no capability is stored)"
)


def _role_key(value: Any) -> str:
    """``"2"``, ``"role 2"`` and ``"PROTOCOL_PAUSER"`` reach the same bucket."""
    text = str(value).strip()
    if text.lower().startswith("role "):
        text = text[5:].strip()
    return text.lower()


def _grant_principal_addresses(grant: Any) -> list[str] | None:
    """Members named by one grant, or ``None`` when the role gates the function but holders weren't determined (not
    an empty set).
    """
    if not isinstance(grant, dict):
        return None
    raw = grant.get("principals")
    if not isinstance(raw, list):
        return None
    addresses: list[str] = []
    for member in raw:
        address = member.get("address") if isinstance(member, dict) else member
        if isinstance(address, str) and address.startswith("0x"):
            lowered = address.lower()
            if lowered not in addresses:
                addresses.append(lowered)
    return addresses or None


def role_holders(session, *, company: str, role_name: str | None = None) -> dict[str, Any]:
    """Who holds which role, and where that's not determined.

    Roles come from ``authority_roles``, never ``function_principals.origin`` (a constant resolver tag; grouping by it
    produced one fake role with 136 holders and empty real roles).

    * grant with members — witnessed.
    * grant without members — ``holders_state: "not_determined"``, never "no holders".
    * NULL / ``[]`` — not read / proven no role-keyed authority; both counted in ``role_evidence`` so "no roles" and
    "didn't look" differ.

    The caller sets ``origin`` describes are published as ``authorized_callers``, labeled as not roles.
    """
    from db.models import EffectiveFunction
    from services.policy.capability_surface import capability_role_grants

    proto = session.execute(select(Protocol).where(Protocol.name == company)).scalar_one_or_none()
    if proto is None:
        return {"error": f"protocol not found: {company}"}

    contracts = list(session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars())
    if not contracts:
        return {"roles": [], "role_evidence": {"functions_examined": 0}, "note": ROLE_SOURCE_NOT_A_ROLE}
    chain_by_cid = {c.id: c.chain for c in contracts}

    ef_rows = list(
        session.execute(
            select(EffectiveFunction)
            .where(EffectiveFunction.contract_id.in_(list(chain_by_cid)))
            .options(selectinload(EffectiveFunction.principals))
            .order_by(EffectiveFunction.id.asc())
        ).scalars()
    )

    by_role: dict[str, dict[str, Any]] = {}
    caller_functions: dict[str, list[str]] = {}
    chain_for_address: dict[str, str | None] = {}
    counts = {
        "functions_examined": len(ef_rows),
        "functions_with_witnessed_roles": 0,
        "functions_with_a_role_whose_holders_are_not_determined": 0,
        "functions_role_structure_not_determined": 0,
        "functions_proven_no_role_gate": 0,
    }

    for ef in ef_rows:
        chain = chain_by_cid.get(ef.contract_id)
        fn_name = ef.function_name or ef.selector or "?"

        # Authorized callers without role attribution.
        for fp in ef.principals or []:
            address = (fp.address or "").lower()
            if not address:
                continue
            chain_for_address.setdefault(address, chain)
            slot = caller_functions.setdefault(address, [])
            if fn_name not in slot:
                slot.append(fn_name)

        # Same function that writes ``authority_roles``, so they agree where the column is current; every persisted row
        # still has the pre-derivation ``[]``, which would falsely read as proven.
        capability = ef.capability_expr
        grants = (
            capability_role_grants(capability) if isinstance(capability, dict) and capability else ef.authority_roles
        )
        if grants is None:
            counts["functions_role_structure_not_determined"] += 1
            continue
        if not grants:
            counts["functions_proven_no_role_gate"] += 1
            continue

        saw_witnessed = False
        saw_undetermined = False
        for grant in grants:
            if not isinstance(grant, dict) or "role" not in grant:
                saw_undetermined = True
                continue
            key = _role_key(grant["role"])
            entry = by_role.setdefault(
                key,
                {"role": grant["role"], "addresses": {}, "functions": [], "undetermined_functions": []},
            )
            if fn_name not in entry["functions"]:
                entry["functions"].append(fn_name)
            members = _grant_principal_addresses(grant)
            if members is None:
                saw_undetermined = True
                if fn_name not in entry["undetermined_functions"]:
                    entry["undetermined_functions"].append(fn_name)
                continue
            saw_witnessed = True
            for address in members:
                chain_for_address.setdefault(address, chain)
                fns = entry["addresses"].setdefault(address, [])
                if fn_name not in fns:
                    fns.append(fn_name)
        if saw_witnessed:
            counts["functions_with_witnessed_roles"] += 1
        if saw_undetermined:
            counts["functions_with_a_role_whose_holders_are_not_determined"] += 1

    def _holder(address: str, functions: list[str]) -> dict[str, Any]:
        # With the gating contract's chain, or cross-chain twin aliasing reopens.
        record = classify_address(session, address, chain_for_address.get(address))
        record["function_count"] = len(functions)
        record["functions"] = functions[:8]
        return record

    def _compact(h: dict[str, Any]) -> dict[str, Any]:
        kind = h.get("kind")
        out: dict[str, Any] = {"address": h.get("address"), "kind": kind}
        if h.get("label"):
            out["label"] = h["label"]
        if kind == "safe":
            out["threshold"] = h.get("threshold")
            out["owner_count"] = h.get("owner_count")
        elif kind == "timelock":
            out["delay_seconds"] = h.get("delay_seconds")
        out["function_count"] = h.get("function_count", 0)
        return out

    if role_name:
        entry = by_role.get(_role_key(role_name))
        if entry is None:
            # No grant names it, which may mean nobody read the gates.
            return {
                "role": role_name,
                "holders": [],
                "state": "not_witnessed",
                "role_evidence": counts,
                "note": ROLE_SOURCE_NOT_A_ROLE,
            }
        holders = [_holder(address, fns) for address, fns in sorted(entry["addresses"].items())]
        return {
            "role": entry["role"],
            "holders": holders,
            "state": "witnessed" if holders else "not_determined",
            "gated_functions": entry["functions"][:20],
            "functions_with_undetermined_holders": entry["undetermined_functions"][:20],
            "role_evidence": counts,
            "note": ROLE_SOURCE_NOT_A_ROLE,
        }

    roles_summary = []
    for key in sorted(by_role):
        entry = by_role[key]
        holders = [_holder(address, fns) for address, fns in sorted(entry["addresses"].items())]
        kinds: dict[str, int] = {}
        for h in holders:
            k = h.get("kind") or "unknown"
            kinds[k] = kinds.get(k, 0) + 1
        roles_summary.append(
            {
                "role": entry["role"],
                "holder_count": len(holders),
                "by_kind": kinds,
                "holders": [_compact(h) for h in holders],
                "gated_function_count": len(entry["functions"]),
                "holders_state": "witnessed" if holders else "not_determined",
            }
        )
    roles_summary.sort(key=lambda r: (-r["holder_count"], str(r["role"])))

    caller_records = [_holder(address, fns) for address, fns in sorted(caller_functions.items())]
    caller_kinds: dict[str, int] = {}
    for record in caller_records:
        k = record.get("kind") or "unknown"
        caller_kinds[k] = caller_kinds.get(k, 0) + 1
    caller_records.sort(key=lambda r: (-r.get("function_count", 0), str(r.get("address"))))

    return {
        "roles": roles_summary[:30],
        "role_evidence": counts,
        "authorized_callers": {
            "count": len(caller_records),
            "by_kind": caller_kinds,
            "callers": [_compact(r) for r in caller_records[:30]],
            "note": (
                "Addresses authorized to call gated functions. NOT role holders: the resolver "
                "records no role attribution for them."
            ),
        },
        "note": ROLE_SOURCE_NOT_A_ROLE,
    }


def list_protocol_addresses(session, name: str) -> set[str]:
    proto = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if proto is None:
        return set()
    job_ids = [
        j.id
        for j in session.execute(
            select(Job).where(Job.protocol_id == proto.id, Job.status == JobStatus.completed)
        ).scalars()
    ]
    if not job_ids:
        return set()
    rows = session.execute(
        select(Contract.address).where(Contract.job_id.in_(job_ids), Contract.address.isnot(None))
    ).all()
    return {r[0].lower() for r in rows}
