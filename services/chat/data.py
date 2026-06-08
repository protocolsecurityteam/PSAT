"""Read-side helpers used by chat agent tools.

These wrap small, targeted DB queries that are already executed inside
the larger `/api/company/{name}` and `/api/contracts/{id}/audit_timeline`
endpoints. We deliberately re-query here (rather than refactor those
routes) so adding tools doesn't risk regressing the routes during this
slice. If three+ callers ever need the same shape, lift it then.

Every function takes a SQLAlchemy ``Session`` and returns plain
JSON-serializable Python primitives — the agent passes results back to
the LLM as message content, so they must round-trip through ``json``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from db.models import (
    AuditContractCoverage,
    AuditReport,
    Contract,
    ContractSummary,
    Protocol,
    UpgradeEvent,
)
from utils.rpc import require_supported_chain_id


def classify_address(
    session,
    address: str,
    *,
    chain_id: int | None = None,
) -> dict[str, Any]:
    """Resolve an address to its control type and gating properties.

    Surfaced to the agent so it never has to *infer* "is this an EOA or
    a contract?" from indirect signals — the answer is in the tool
    result, with a plain-English ``note`` explaining the compromise
    semantics. This is the single highest-leverage anti-hallucination
    move: the model can't pattern-match "owner = EOA = single point of
    failure" when the tool literally returns ``kind: "timelock"`` plus
    a sentence saying private keys don't apply.

    Sources, in priority:
      1. ``control_graph_nodes.resolved_type`` and ``.details`` — the
         pipeline already classifies these, including thresholds,
         owners, and delays.
      2. ``contracts`` row — if the address has a Contract row it has
         bytecode and is at minimum a generic "contract".
      3. Unknown, only when the chain-scoped pipeline has no classification.
    """
    from db.models import ControlGraphNode

    if not address:
        return {"address": address, "kind": "unknown", "is_eoa": False, "note": ""}
    addr_lc = address.lower()
    try:
        effective_chain_id = require_supported_chain_id(chain_id=chain_id, context=f"chat classify address {addr_lc}")
    except RuntimeError as exc:
        return {"address": address, "error": str(exc)}

    cg_stmt = select(ControlGraphNode).where(func.lower(ControlGraphNode.address) == addr_lc)
    cg_stmt = cg_stmt.join(Contract, ControlGraphNode.contract_id == Contract.id).where(
        Contract.chain_id == effective_chain_id
    )
    cg_node = session.execute(cg_stmt.limit(1)).scalar_one_or_none()
    contract = _resolve_contract(session, address, chain_id=effective_chain_id)

    details = (cg_node.details if cg_node else None) or {}
    kind = (cg_node.resolved_type if cg_node else None) or ("contract" if contract else "unknown")
    label = (cg_node.contract_name if cg_node else None) or (contract.contract_name if contract else None)

    # The pipeline classifies many timelock contracts as plain "contract"
    # but writes the delay into details. If we have a delay or the name
    # looks like a timelock, promote — otherwise the agent loses the most
    # important fact about this address (it has a delay window).
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
    # control_graph_nodes uses `delay` for timelock seconds in this codebase.
    delay = details.get("delay") or details.get("delay_seconds")
    if delay is not None:
        out["delay_seconds"] = delay

    return out


def _resolve_contract(
    session,
    address: str,
    *,
    chain_id: int,
) -> Contract | None:
    """Find a Contract by ``(chain_id, address)``."""
    if not address:
        return None
    effective_chain_id = require_supported_chain_id(chain_id=chain_id, context=f"chat contract lookup for {address}")
    addr_lc = address.lower()
    stmt = select(Contract).where(
        func.lower(Contract.address) == addr_lc,
        Contract.chain_id == effective_chain_id,
    )
    return session.execute(stmt.order_by(Contract.id.asc()).limit(1)).scalar_one_or_none()


def contract_brief(
    session,
    address: str,
    *,
    chain_id: int | None = None,
) -> dict[str, Any]:
    """One-screen contract summary: identity, proxy status, controls, recent upgrade.

    Every address that appears (the contract itself + each controller)
    is annotated via ``classify_address`` so the agent sees the type
    (eoa / safe / timelock / contract) and gating semantics inline,
    without having to infer them.
    """
    from db.models import ControllerValue

    try:
        contract = _resolve_contract(session, address, chain_id=chain_id)
    except RuntimeError as exc:
        return {"error": str(exc), "address": address}
    if contract is None:
        return {"error": f"contract not found: {address} on chain_id={chain_id}"}

    summary = session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == contract.id)
    ).scalar_one_or_none()

    last_event = session.execute(
        select(UpgradeEvent)
        .where(UpgradeEvent.contract_id == contract.id)
        .order_by(UpgradeEvent.block_number.desc().nullslast())
        .limit(1)
    ).scalar_one_or_none()

    # Classify each controller value (often the address that holds a
    # role like ``owner`` or ``DEFAULT_ADMIN_ROLE``). Without this the
    # model treats every controller as an EOA by default.
    cv_rows = session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract.id)).scalars().all()
    controllers: dict[str, dict[str, Any]] = {}
    for cv in cv_rows:
        if cv.value and cv.value.startswith("0x"):
            controllers[cv.controller_id] = classify_address(session, cv.value, chain_id=contract.chain_id)
        else:
            controllers[cv.controller_id] = {"value": cv.value}

    self_kind = classify_address(session, contract.address, chain_id=contract.chain_id)

    return {
        "address": contract.address,
        "chain_id": contract.chain_id,
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
        "risk_level": summary.risk_level if summary else None,
        "controllers": controllers,
        "last_upgrade": (
            {
                "block": last_event.block_number,
                "timestamp": last_event.timestamp.isoformat() if last_event.timestamp else None,
                "new_impl": last_event.new_impl,
                "tx_hash": last_event.tx_hash,
            }
            if last_event
            else None
        ),
    }


def upgrade_summary(
    session,
    address: str,
    *,
    chain_id: int | None = None,
) -> dict[str, Any]:
    """Per-impl windows + audit-coverage status for a (proxy) contract."""
    try:
        contract = _resolve_contract(session, address, chain_id=chain_id)
    except RuntimeError as exc:
        return {"error": str(exc), "address": address}
    if contract is None:
        return {"error": f"contract not found: {address} on chain_id={chain_id}"}

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

    # Coverage: union over the proxy's id and any historical impl ids.
    impl_addrs = {ev.new_impl.lower() for ev in rows if ev.new_impl}
    if contract.implementation:
        impl_addrs.add(contract.implementation.lower())
    scope_ids = {contract.id}
    if impl_addrs:
        scope_ids.update(
            r[0]
            for r in session.execute(
                select(Contract.id).where(
                    func.lower(Contract.address).in_(impl_addrs),
                    Contract.chain_id == contract.chain_id,
                )
            ).all()
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
    chain_id: int | None = None,
    company: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Audit findings still affecting the current code (status != 'fixed').

    Filters: by address (joins through coverage), by company (all audits
    of the protocol), or both. Caps at ``limit`` for prompt budget.
    """
    stmt = select(AuditReport)
    if address:
        addr_lc = address.lower()
        try:
            effective_chain_id = require_supported_chain_id(
                chain_id=chain_id,
                context=f"chat audit findings for {addr_lc}",
            )
        except RuntimeError as exc:
            return {"error": str(exc), "findings": [], "truncated": False}
        stmt = (
            stmt.join(AuditContractCoverage, AuditContractCoverage.audit_report_id == AuditReport.id)
            .join(Contract, Contract.id == AuditContractCoverage.contract_id)
            .where(func.lower(Contract.address) == addr_lc)
            .where(Contract.chain_id == effective_chain_id)
        )
    if company:
        # AuditReport keys to Protocol via protocol_id; resolve the name.
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
    """Top-level snapshot for one protocol: counts + key principals."""
    proto = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if proto is None:
        return {"error": f"protocol not found: {name}"}

    contracts = session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars().all()
    proxy_count = sum(1 for c in contracts if c.is_proxy)
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
    """Roll up principals (Safes/EOAs/timelocks) that govern a protocol's contracts."""
    from db.models import ControlGraphNode  # local import to avoid cycle at module load

    proto = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if proto is None:
        return {"error": f"protocol not found: {name}"}
    contracts = list(session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars())
    contract_ids = [c.id for c in contracts]
    if not contract_ids:
        return {"principals": []}
    chain_id_by_contract_id = {c.id: c.chain_id for c in contracts}
    nodes = (
        session.execute(select(ControlGraphNode).where(ControlGraphNode.contract_id.in_(contract_ids))).scalars().all()
    )
    by_addr: dict[tuple[str, int | None], dict[str, Any]] = {}
    for n in nodes:
        if not n.address or n.address.startswith("role:"):
            continue
        chain_id = chain_id_by_contract_id.get(n.contract_id)
        slot = by_addr.setdefault(
            (n.address.lower(), chain_id),
            {
                "address": n.address,
                "chain_id": chain_id,
                "controls_count": 0,
            },
        )
        slot["controls_count"] += 1

    # Classify each principal address — kind, threshold, owners, delay,
    # and the plain-English compromise-semantics note. The model can no
    # longer say "a single EOA controls X" when this output literally
    # tags X as a Timelock contract or a 4-of-7 Safe.
    out = []
    for entry in by_addr.values():
        cls = classify_address(session, entry["address"], chain_id=entry.get("chain_id"))
        merged = {**cls, "controls_count": entry["controls_count"]}
        out.append(merged)

    principals = sorted(
        out,
        key=lambda p: (-p["controls_count"], p.get("address") or ""),
    )
    return {"principals": principals[:30]}


def role_holders(session, *, company: str, role_name: str | None = None) -> dict[str, Any]:
    """Who can call functions gated by which role, across a protocol.

    The pipeline writes one ``FunctionPrincipal`` per (function × actual
    address authorized to call it), with ``origin`` carrying the role
    name (e.g. ``PROTOCOL_PAUSER``). Group those by role and annotate
    each holder with its kind (eoa / safe / timelock / contract).

    Two modes:
      - ``role_name`` provided  → list distinct holders of that role
      - omitted                → summary of all roles in the protocol
        with a per-role holder breakdown by kind
    """
    from db.models import EffectiveFunction, FunctionPrincipal

    proto = session.execute(select(Protocol).where(Protocol.name == company)).scalar_one_or_none()
    if proto is None:
        return {"error": f"protocol not found: {company}"}

    contracts = list(session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars())
    contract_ids = [c.id for c in contracts]
    chain_id_by_contract_id = {c.id: c.chain_id for c in contracts}
    if not contract_ids:
        return {"roles": []}

    stmt = (
        select(FunctionPrincipal, EffectiveFunction)
        .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(EffectiveFunction.contract_id.in_(contract_ids))
        .where(FunctionPrincipal.origin.is_not(None))
    )
    if role_name:
        stmt = stmt.where(FunctionPrincipal.origin == role_name)

    rows = session.execute(stmt).all()

    # Group by (role, address). For each unique (role, address) build a
    # holder entry once, classify the address via classify_address so the
    # caller sees kind/threshold/owners/delay.
    by_role: dict[str, dict[tuple[str, int | None], dict[str, Any]]] = {}
    for fp, ef in rows:
        role = fp.origin or ""
        addr = (fp.address or "").lower()
        if not addr:
            continue
        chain_id = chain_id_by_contract_id.get(ef.contract_id)
        slot = by_role.setdefault(role, {})
        key = (addr, chain_id)
        if key not in slot:
            slot[key] = classify_address(session, fp.address, chain_id=chain_id)
            slot[key]["functions"] = []
        slot[key]["functions"].append(f"{ef.function_name}")

    # Cap functions list per holder so the prompt stays small even when
    # one principal holds the role on many contracts.
    for role, holders in by_role.items():
        for h in holders.values():
            fns = h.get("functions") or []
            h["function_count"] = len(fns)
            h["functions"] = fns[:8]

    if role_name:
        holders = list(by_role.get(role_name, {}).values())
        return {"role": role_name, "holders": holders}

    # Summary mode: include the actual holders inline so a single call
    # answers "who can do what unilaterally?" without the agent having
    # to drill into each role separately. Compact representation: full
    # detail for EOAs (the high-risk single-key holders) and short
    # metadata for Safe / Timelock / contract holders.
    def _compact(h: dict[str, Any]) -> dict[str, Any]:
        kind = h.get("kind")
        out: dict[str, Any] = {
            "address": h.get("address"),
            "kind": kind,
        }
        if h.get("label"):
            out["label"] = h["label"]
        if kind == "safe":
            out["threshold"] = h.get("threshold")
            out["owner_count"] = h.get("owner_count")
        elif kind == "timelock":
            out["delay_seconds"] = h.get("delay_seconds")
        out["function_count"] = h.get("function_count", 0)
        return out

    roles_summary = []
    for role, holders in by_role.items():
        kinds: dict[str, int] = {}
        for h in holders.values():
            k = h.get("kind") or "unknown"
            kinds[k] = kinds.get(k, 0) + 1
        roles_summary.append(
            {
                "role": role,
                "holder_count": len(holders),
                "by_kind": kinds,
                "holders": [_compact(h) for h in holders.values()],
            }
        )
    roles_summary.sort(key=lambda r: -r["holder_count"])
    return {"roles": roles_summary[:30]}


def list_protocol_addresses(session, name: str) -> set[str]:
    """All in-scope contract addresses (lowercase) for a protocol — used to
    intersect with addresses extracted from the agent's final answer when
    deciding what to highlight on the canvas."""
    proto = session.execute(select(Protocol).where(Protocol.name == name)).scalar_one_or_none()
    if proto is None:
        return set()
    rows = session.execute(
        select(Contract.address).where(Contract.protocol_id == proto.id, Contract.address.isnot(None))
    ).all()
    return {r[0].lower() for r in rows}
