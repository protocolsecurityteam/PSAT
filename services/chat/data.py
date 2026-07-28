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

from sqlalchemy import case, func, select

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

# Common aliases the same chain shows up under in our DB. Treat
# `ethereum`/`mainnet` as the same canonical chain when matching, so a
# tool call with `chain="ethereum"` resolves rows tagged `mainnet` and
# vice versa. NULL/empty chain stays a separate "legacy/unknown" bucket
# — we don't blanket-treat it as Ethereum because that turns missing
# data into false confidence (per codex's pitfall flag).
_CHAIN_ALIASES = {"ethereum": "ethereum", "mainnet": "ethereum"}


def _canonical_chain(c: str | None) -> str | None:
    if not c:
        return None
    return _CHAIN_ALIASES.get(c.lower(), c.lower())


def _chain_match_values(canonical: str) -> list[str]:
    """Every stored spelling that canonicalizes to *canonical*.

    ``_canonical_chain`` folds aliases in Python; a SQL predicate needs the fold
    expanded, or a row tagged ``mainnet`` is invisible to a ``chain="ethereum"``
    query and the caller silently sees "no such node" instead of the node.
    """
    values = {canonical}
    values.update(stored for stored, folded in _CHAIN_ALIASES.items() if folded == canonical)
    return sorted(values)


def classify_address(session, address: str, chain: str | None = None) -> dict[str, Any]:
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
      3. Fallback: "unknown" with a note instructing the agent to
         verify before reasoning about compromise semantics.
    """
    from db.models import ControlGraphNode

    if not address:
        return {"address": address, "kind": "unknown", "is_eoa": False, "note": ""}
    addr_lc = address.lower()

    # ``control_graph_nodes`` has no chain column at all — ``contract_id`` (which
    # is chain-scoped through ``contracts.chain``) is the only scoping key — so the
    # chain predicate goes through the join, not onto the node. Without it this
    # lookup keys on a BARE ADDRESS while ``chain`` is a parameter of this function
    # and is used on the very next line: three real cross-chain twins already exist
    # in ``contracts`` (``0x5bdd4b0d…`` ``TopUp`` on ethereum AND scroll, both
    # protocol_id=1 — the canonical deterministic-deploy aliasing case), and the
    # aliasing is unrealised today for exactly one reason: no analysis job has ever
    # run on a second chain, so every control-graph row is ethereum. That number
    # measures analysis coverage, not the hazard.
    #
    # A caller that supplies no chain keeps the address-only lookup (there is no
    # chain to scope to, and inventing mainnet would turn a missing hint into false
    # confidence — the same reason ``_canonical_chain`` keeps NULL its own bucket).
    stmt = select(ControlGraphNode).join(Contract, ControlGraphNode.contract_id == Contract.id)
    stmt = stmt.where(func.lower(ControlGraphNode.address) == addr_lc)
    canonical = _canonical_chain(chain)
    if canonical is not None:
        stmt = stmt.where(func.lower(Contract.chain).in_(_chain_match_values(canonical)))
    # An unordered LIMIT 1 over a multi-row set is a query-plan coin flip, and it is
    # not hypothetical here: 10 local addresses carry differing ``details`` across
    # their rows and 2 disagree on ``resolved_type`` between ``contract`` (a
    # non-terminal way-point) and ``timelock`` (a settled key with a delay). The
    # order is a total one AND prefers a classified row, so the answer is both
    # reproducible and never the less-resolved of two rows about the same address.
    stmt = stmt.order_by(
        case((ControlGraphNode.resolved_type.is_(None), 1), (ControlGraphNode.resolved_type == "unknown", 1), else_=0),
        ControlGraphNode.id.asc(),
    ).limit(1)
    cg_node = session.execute(stmt).scalars().first()
    contract = _resolve_contract(session, address, chain)

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


def _resolve_contract(session, address: str, chain: str | None) -> Contract | None:
    """Find a Contract by address. The LLM may pass ``chain`` as a hint
    (sometimes it's wrong — e.g. it says "ethereum" while the row is
    tagged ``mainnet`` or NULL). Resolution strategy (codex-recommended):

      1. If chain is provided: match address + canonical chain. ethereum
         and mainnet are aliases. Strict miss falls through to (3).
      2. If chain not provided: address-only.
      3. Fallback: address-only across all rows, with a tiebreak that
         prefers ethereum/mainnet over multi-chain hits, NULL last.
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
        # Strict canonical match (handles ethereum/mainnet alias).
        canonical_matches = [r for r in rows if _canonical_chain(r.chain) == target]
        if canonical_matches:
            return canonical_matches[0]
        # No canonical match — fall through to the address-only tiebreak
        # below rather than returning None, since the LLM's chain hint
        # was probably wrong.

    # Tiebreak: prefer ethereum/mainnet rows; then any non-NULL chain;
    # NULL last. Stable within each bucket via input order.
    eth = [r for r in rows if _canonical_chain(r.chain) == "ethereum"]
    if eth:
        return eth[0]
    nonempty = [r for r in rows if r.chain]
    if nonempty:
        return nonempty[0]
    return rows[0]


def contract_brief(session, address: str, chain: str | None = None) -> dict[str, Any]:
    """One-screen contract summary: identity, proxy status, controls, recent upgrade.

    Every address that appears (the contract itself + each controller)
    is annotated via ``classify_address`` so the agent sees the type
    (eoa / safe / timelock / contract) and gating semantics inline,
    without having to infer them.
    """
    from db.models import ControllerValue

    contract = _resolve_contract(session, address, chain)
    if contract is None:
        return {"error": f"contract not found: {address} on chain={chain}"}

    summary = session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == contract.id)
    ).scalar_one_or_none()

    # "The last upgrade", and the polarity has to match the words (L-20). Under
    # ``block_number DESC NULLS LAST`` a poll-detected upgrade — ``block_number``
    # is NULL by design for the event-scan/poll writers — sorted LAST, i.e. was
    # reported as the OLDEST event, so ``last_upgrade`` named the newest
    # BLOCK-CARRYING upgrade while a more recent one sat unreported. Timestamp
    # leads because every writer sets it (W0-9 gave the poll rows one) and it
    # answers the question actually being asked; the block tiebreak puts NULLS
    # FIRST under DESC for the same reason, and ``id`` makes the order total so two
    # rows with one timestamp cannot swap between calls.
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

    # Classify each controller value (often the address that holds a
    # role like ``owner`` or ``DEFAULT_ADMIN_ROLE``). Without this the
    # model treats every controller as an EOA by default.
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
        "risk_level": summary.risk_level if summary else None,
        "controllers": controllers,
        "last_upgrade": (
            {
                "block": last_event.block_number,
                "timestamp": last_event.timestamp.isoformat() if last_event.timestamp else None,
                "new_impl": last_event.new_impl,
                "tx_hash": last_event.tx_hash,
                # This result is read by an LLM, which cannot be relied on to
                # interpret ``"block": null`` as "the block is unknown" rather than
                # "block zero" or "no upgrade". Name the detection route instead:
                # a poll-detected upgrade has no block and no tx hash by design.
                "detection": ("log_indexed" if last_event.block_number is not None else "poll_detected"),
            }
            if last_event
            else None
        ),
    }


def upgrade_summary(session, address: str, chain: str | None = None) -> dict[str, Any]:
    """Per-impl windows + audit-coverage status for a (proxy) contract."""
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

    # Coverage: union over the proxy's id and any historical impl ids.
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
    """Audit findings still affecting the current code (status != 'fixed').

    Filters: by address (joins through coverage), by company (all audits
    of the protocol), or both. Caps at ``limit`` for prompt budget.
    """
    stmt = select(AuditReport)
    if address:
        addr_lc = address.lower()
        stmt = (
            stmt.join(AuditContractCoverage, AuditContractCoverage.audit_report_id == AuditReport.id)
            .join(Contract, Contract.id == AuditContractCoverage.contract_id)
            .where(func.lower(Contract.address) == addr_lc)
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

    # Classify each principal address — kind, threshold, owners, delay,
    # and the plain-English compromise-semantics note. The model can no
    # longer say "a single EOA controls X" when this output literally
    # tags X as a Timelock contract or a 4-of-7 Safe.
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

    contract_ids = [c.id for c in session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars()]
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
    by_role: dict[str, dict[str, dict[str, Any]]] = {}
    for fp, ef in rows:
        role = fp.origin or ""
        addr = (fp.address or "").lower()
        if not addr:
            continue
        slot = by_role.setdefault(role, {})
        if addr not in slot:
            slot[addr] = classify_address(session, fp.address)
            slot[addr]["functions"] = []
        slot[addr]["functions"].append(f"{ef.function_name}")

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
