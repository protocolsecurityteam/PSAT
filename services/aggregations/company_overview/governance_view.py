from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy.orm import Session

from db.models import (
    CONTROL_EDGE_RELATIONS,
    Contract,
    ControlGraphEdge,
    ControlGraphNode,
    ControllerValue,
    Job,
)
from services.clients.etherscan import TOKEN_BALANCE_PAGE_SIZE
from services.governance.primary_controller import (
    assign_co_controllers,
    assign_operand_render_groups,
    assign_primary_controllers,
)
from services.governance.primary_controller import (
    function_capabilities as _function_capabilities,
)
from services.scoring.planes import CONTROL_RELATIONS as SCORER_REACH_RELATIONS
from services.scoring.planes import MAPPING_ENUMERATION_STATUS, controllers_not_determined
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
)

from .entity_keys import _coalesce_chain, _entity_addr, _entity_chain, _entity_key, _entity_prefix
from .jobs import GovernanceView, _secondary_impl_contracts
from .prefetch import _prefetch_child_tables
from .principals import (
    _PASSTHROUGH_CONTROLLER_TYPES,
    _SETTLED_CONTROLLER_TYPES,
    _build_principal_lookup,
    _is_active_owner_controller,
    _principal_lookup_meta,
    _trim_control_graph,
)
from .runtime_scope import (
    RuntimeKey,
    code_id,
    entry_key,
    principal_classification,
    scoped_rows,
    scoped_walks,
    with_classification,
)


def build_governance_view(
    session: Session,
    jobs: list[Job],
    contracts_by_job_id: dict[Any, Contract],
    impl_job_by_entity: dict[str, Job],
) -> GovernanceView:
    relevant_contract_ids: set[int] = {c.id for c in contracts_by_job_id.values() if c is not None}
    children = _prefetch_child_tables(session, relevant_contract_ids)
    from services.monitoring.balance_reads import partial_asset_rows

    partial_by_cid: dict[int, list[Any]] = {}
    for protocol_id in {c.protocol_id for c in contracts_by_job_id.values() if c and c.protocol_id is not None}:
        partial_by_cid.update(partial_asset_rows(session, protocol_id))

    controller_values_by_cid: dict[RuntimeKey, list[ControllerValue]] = children["controller_values"]
    ef_effects_by_cid: dict[RuntimeKey, list[dict[str, list[str]]]] = children["ef_effects"]
    fp_governance_by_cid: dict[RuntimeKey, list[dict[str, Any]]] = children["fp_governance_rows"]
    upgrade_events_count_by_cid: dict[int, dict[str, Any]] = children["upgrade_events_count"]
    last_upgrade_by_cid: dict[int, dict[str, Any]] = children["upgrade_events_last"]
    balances_by_cid: dict[int, list[Any]] = children["balances"]
    balance_fetch_by_id: dict[int, Any] = children["balance_fetches"]
    cgn_by_cid: dict[RuntimeKey, list[ControlGraphNode]] = children["cgn"]
    cge_by_cid: dict[RuntimeKey, list[ControlGraphEdge]] = children["cge"]
    fp_in_contract_by_cid: dict[RuntimeKey, set[str]] = children["fp_in_contract_principals"]
    fp_all_addrs_by_cid: dict[RuntimeKey, set[str]] = children["fp_all_addrs"]
    fp_function_detail_by_cid: dict[RuntimeKey, list[dict[str, Any]]] = children["fp_function_detail"]
    terminal_walk_by_entity: dict[RuntimeKey, dict[str, dict[str, Any]]] = children["terminal_walk"]

    def _fetch_for(balance_row: Any) -> Any | None:
        fetch_id = getattr(balance_row, "fetch_id", None)
        return balance_fetch_by_id.get(int(fetch_id)) if fetch_id is not None else None

    # Fold secondary-impl rows into the primary impl's buckets so a Safe with authority only on the admin impl still
    # surfaces as a proxy controller.
    folded: set[RuntimeKey] = set()
    for job in jobs:
        cr = contracts_by_job_id.get(job.id)
        secondaries = _secondary_impl_contracts(cr, impl_job_by_entity, contracts_by_job_id)
        if not secondaries:
            continue
        impl_job = (
            impl_job_by_entity.get(_entity_key(cr.chain, cr.implementation)) if cr and cr.implementation else None
        )
        primary_impl = contracts_by_job_id.get(impl_job.id) if impl_job else None
        primary_cid = primary_impl.id if primary_impl else (cr.id if cr else None)
        if primary_cid is None or cr is None:
            continue
        primary_key = entry_key(primary_cid, cr)
        if primary_key in folded:
            continue
        folded.add(primary_key)
        for sc in secondaries:
            if sc.id == primary_cid:
                continue
            extra_nodes = cgn_by_cid.get(entry_key(sc.id, cr))
            if extra_nodes:
                cgn_by_cid[primary_key] = list(cgn_by_cid.get(primary_key) or []) + extra_nodes
            extra_edges = cge_by_cid.get(entry_key(sc.id, cr))
            if extra_edges:
                cge_by_cid[primary_key] = list(cge_by_cid.get(primary_key) or []) + extra_edges
            cv_extra = controller_values_by_cid.get(entry_key(sc.id, cr))
            if cv_extra:
                controller_values_by_cid[primary_key] = list(controller_values_by_cid.get(primary_key) or []) + cv_extra
            fpg_extra = fp_governance_by_cid.get(entry_key(sc.id, cr))
            if fpg_extra:
                fp_governance_by_cid[primary_key] = list(fp_governance_by_cid.get(primary_key) or []) + fpg_extra
            extra_addrs = fp_in_contract_by_cid.get(entry_key(sc.id, cr))
            if extra_addrs:
                fp_in_contract_by_cid[primary_key] = set(fp_in_contract_by_cid.get(primary_key) or set()) | set(
                    extra_addrs
                )
            # The CGN principal gate checks the primary cid, so fold secondary-impl governors up too.
            extra_all = fp_all_addrs_by_cid.get(entry_key(sc.id, cr))
            if extra_all:
                fp_all_addrs_by_cid[primary_key] = set(fp_all_addrs_by_cid.get(primary_key) or set()) | set(extra_all)

    # Only immutable code classification is global; runtime metadata is selected per rendered deployment.
    principal_lookup = principal_classification(contracts_by_job_id, controller_values_by_cid, cgn_by_cid)
    principal_lookups_by_entity: dict[str, dict[str, dict[str, Any]]] = {}

    contracts: list[dict[str, Any]] = []
    owner_groups: dict[str, list[dict]] = {}

    for job in jobs:
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("proxy_address"):
            continue

        contract_row = contracts_by_job_id.get(job.id)
        is_proxy = contract_row.is_proxy if contract_row else False
        proxy_type = contract_row.proxy_type if contract_row else None
        impl_addr = contract_row.implementation if contract_row else None

        impl_job = (
            impl_job_by_entity.get(_entity_key(contract_row.chain, impl_addr)) if contract_row and impl_addr else None
        )
        impl_job_id = str(impl_job.id) if impl_job else None
        impl_contract = contracts_by_job_id.get(impl_job.id) if impl_job else None

        secondary_impl_contracts = _secondary_impl_contracts(contract_row, impl_job_by_entity, contracts_by_job_id)
        runtime_keys = [
            entry_key(c.id, contract_row)
            for c in [contract_row, impl_contract, *secondary_impl_contracts]
            if c is not None and contract_row is not None
        ]
        local_lookup = _build_principal_lookup(
            contracts_by_job_id,
            scoped_rows(controller_values_by_cid, runtime_keys),
            scoped_rows(cgn_by_cid, runtime_keys),
            scoped_walks(terminal_walk_by_entity, runtime_keys),
        )
        local_lookup = with_classification(local_lookup, principal_lookup)
        principal_lookups_by_entity[_entity_key(contract_row.chain if contract_row else None, job.address)] = (
            local_lookup
        )

        summary_row = impl_contract.summary if impl_contract else None
        if not summary_row and contract_row:
            summary_row = contract_row.summary

        # Prefer the logic contract's controller snapshot (read against proxy storage).
        lookup_contract = contract_row
        if is_proxy:
            for candidate in [impl_contract, *secondary_impl_contracts]:
                if candidate and controller_values_by_cid.get(entry_key(candidate.id, contract_row)):
                    lookup_contract = candidate
                    break

        owner = None
        controllers: dict[str, Any] = {}
        if lookup_contract:
            for cv in controller_values_by_cid.get(entry_key(lookup_contract.id, contract_row), []):
                controllers[cv.controller_id] = cv.value
                if _is_active_owner_controller(cv.controller_id) and cv.value and cv.value.startswith("0x"):
                    owner = cv.value.lower()

        upgrade_entry = (upgrade_events_count_by_cid.get(contract_row.id) if contract_row else None) or {}
        # ``None`` when no proven upgrade exists, including post-exclusion zero, which would render as "0 upgrades".
        upgrade_count = upgrade_entry.get("count")
        upgrade_count_basis = upgrade_entry.get("basis")
        last_upgrade_entry = (last_upgrade_by_cid.get(contract_row.id) if contract_row else None) or {}
        last_upgrade_block = last_upgrade_entry.get("block")
        last_ts = last_upgrade_entry.get("timestamp")
        last_upgrade_timestamp = last_ts.isoformat() if last_ts is not None else None

        primary_ef_cid = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)
        ef_contract_ids = [primary_ef_cid] if primary_ef_cid else []
        ef_contract_ids += [sc.id for sc in secondary_impl_contracts]

        # ``value_effects`` stays on legacy labels (drives role + fund-flow lane); capability chips come from claims.
        value_effects: list[str] = []
        caps_set: set[str] = set()
        for cid in ef_contract_ids:
            for rec in ef_effects_by_cid.get(entry_key(cid, contract_row), []):
                for label in rec["labels"]:
                    if label in ("asset_pull", "asset_send", "mint", "burn") and label not in value_effects:
                        value_effects.append(label)
                caps_set |= _function_capabilities(rec["claims"])

        if is_proxy:
            caps_set.add("upgradeable")
        # Three-state column: only a proven ``True`` earns the chip; absence isn't published as proof of the opposite.
        if summary_row is not None and summary_row.is_pausable is True:
            caps_set.add("pause")
        capabilities: list[str] = sorted(caps_set)

        contract_name = None
        if is_proxy and impl_job:
            if impl_contract and impl_contract.contract_name:
                contract_name = impl_contract.contract_name
            elif impl_job.name:
                contract_name = impl_job.name
        if not contract_name:
            contract_name = (contract_row.contract_name if contract_row else None) or job.name or ""
        standards = list(summary_row.standards or []) if summary_row else []
        # Three states through the payload. ``False`` used to be published for contracts with no summary row, asserting
        # facts nobody checked. ``summary_evidence`` says which route produced a ``None``.
        is_factory = summary_row.is_factory if summary_row else None
        has_timelock = summary_row.has_timelock if summary_row else None
        is_pausable = summary_row.is_pausable if summary_row else None
        control_model = summary_row.control_model if summary_row else None

        name_lower = contract_name.lower()
        if "bridge" in name_lower or "gateway" in name_lower:
            role = "bridge"
        elif any(e in value_effects for e in ("asset_pull", "asset_send")):
            role = "value_handler"
        elif any(s in standards for s in ("ERC20", "ERC721", "ERC1155")):
            role = "token"
        elif has_timelock is True or control_model == "governance":
            role = "governance"
        elif is_factory is True:
            role = "factory"
        else:
            role = "utility"

        # Only the ``utility`` fall-through is reachable from all-not-determined inputs; published separately so the
        # role vocabulary keeps its meaning.
        role_evidence = (
            "witnessed"
            if role != "utility" or (summary_row is not None and has_timelock is not None and is_factory is not None)
            else "not_determined"
        )

        # Balances are filed against the row whose address was read (the proxy's own row); ``lookup_contract`` may be
        # the impl, where nothing is filed.
        balance_contract = contract_row or lookup_contract
        balances_list = []
        total_usd: float | None = None
        unvalued_rows = 0
        at_page_cap = False
        if balance_contract:
            for b in balances_by_cid.get(balance_contract.id, []):
                usd = float(b.usd_value) if b.usd_value is not None else None
                if usd is None:
                    unvalued_rows += 1
                if getattr(_fetch_for(b), "asset_set_status", None) == ASSET_SET_STATUS_AT_PAGE_CAP:
                    # Weakest wins: one truncated contributing fetch means entries may be missing.
                    at_page_cap = True
                balances_list.append(
                    {
                        "token_symbol": b.token_symbol,
                        "token_name": b.token_name,
                        "token_address": b.token_address,
                        "raw_balance": b.raw_balance,
                        "decimals": b.decimals,
                        "usd_value": usd,
                        # ``null`` vs ``0`` are one truthiness test apart in JS and mean opposite things.
                        # ``not_determined`` names no cause: no writer persists ``decimals_reported``, so no-price vs
                        # no-divisor can't be told apart.
                        "usd_value_state": "measured" if usd is not None else "not_determined",
                        # Not a money fact: 0 means no price known, or an old real quote truncated before the
                        # Numeric(38,18) widening. Read ``usd_value`` / ``usd_value_state``.
                        "price_usd": float(b.price_usd) if b.price_usd is not None else None,
                        "decimals_known": getattr(b, "decimals_known", None),
                        "observed_at": b.observed_at.isoformat() if getattr(b, "observed_at", None) else None,
                        "price_observed_at": b.price_observed_at.isoformat()
                        if getattr(b, "price_observed_at", None)
                        else None,
                        "source": b.source,
                    }
                )
                # Delivery shape doesn't gate the sum: a priced holding is real money however it arrived.
                if usd is not None:
                    total_usd = (total_usd or 0.0) + usd
        # No ``complete`` member on purpose. The witness is the fetch's ``asset_set_status``, never list length (the
        # fetch pages past ``TOKEN_BALANCE_PAGE_SIZE``).
        holdings_coverage = {
            "rows": len(balances_list),
            "page_cap": TOKEN_BALANCE_PAGE_SIZE,
            "state": ("may_be_incomplete" if at_page_cap else "not_determined"),
            # Non-zero means ``total_usd`` is a lower bound.
            "unvalued_rows": unvalued_rows,
            "scope": "observed provider holdings; completeness not established",
        }

        # A newer interrupted page is a separate observation; never add it to the accepted snapshot.
        partial_rows = partial_by_cid.get(balance_contract.id, []) if balance_contract else []
        displayed_fetches = (
            {b.fetch_id for b in balances_by_cid.get(balance_contract.id, [])} if balance_contract else set()
        )
        partial_rows = [b for b in partial_rows if b.fetch_id not in displayed_fetches]
        partial_observations = [
            {
                "token_symbol": b.token_symbol,
                "token_name": b.token_name,
                "token_address": b.token_address,
                "raw_balance": b.raw_balance,
                "decimals": b.decimals,
                "decimals_known": getattr(b, "decimals_known", None),
                "usd_value": float(b.usd_value) if b.usd_value is not None else None,
                "usd_value_state": "measured" if b.usd_value is not None else "not_determined",
                "observed_at": b.observed_at.isoformat() if getattr(b, "observed_at", None) else None,
            }
            for b in partial_rows
        ]
        if partial_rows:
            holdings_coverage["state"] = "may_be_incomplete"
            holdings_coverage["newer_partial_rows"] = len(partial_rows)

        entry: dict[str, Any] = {
            "partial_balance_observations": partial_observations,
            # Legacy job rows may hold checksummed addresses.
            "address": (job.address or "").lower(),
            "name": contract_name,
            "contract_id": contract_row.id if contract_row else None,
            "job_id": str(job.id),
            "impl_job_id": impl_job_id,
            "is_proxy": is_proxy,
            "proxy_type": proxy_type,
            "implementation": impl_addr,
            "secondary_implementations": (
                [s.lower() for s in (contract_row.secondary_implementations or [])] if contract_row else []
            ),
            "deployer": contract_row.deployer if contract_row else None,
            "owner": owner,
            "controllers": controllers,
            "control_model": control_model,
            "source_verified": summary_row.source_verified if summary_row else None,
            "chain": contract_row.chain if contract_row else None,
            "upgrade_count": upgrade_count,
            # An upper bound with stated coverage plus the three questions this plane can't answer.
            "upgrade_count_basis": upgrade_count_basis,
            "last_upgrade_block": last_upgrade_block,
            "last_upgrade_timestamp": last_upgrade_timestamp,
            "role": role,
            "role_evidence": role_evidence,
            "standards": standards,
            "value_effects": value_effects,
            "is_pausable": is_pausable,
            "has_timelock": has_timelock,
            "is_factory": is_factory,
            # ``absent``: no ContractSummary row; ``present``: row exists, column NULL. Never omitted.
            "summary_evidence": "present" if summary_row is not None else "absent",
            "capabilities": capabilities,
            "balances": balances_list,
            "total_usd": round(total_usd, 2) if total_usd is not None else None,
            "holdings_coverage": holdings_coverage,
        }

        graph_contract = impl_contract or lookup_contract or contract_row
        if graph_contract:
            cg_nodes = cgn_by_cid.get(entry_key(graph_contract.id, contract_row), [])
            cg_edges = cge_by_cid.get(entry_key(graph_contract.id, contract_row), [])
            node_meta = {
                n.address: _principal_lookup_meta(local_lookup, graph_contract.chain, n.address, n.details)
                for n in cg_nodes
            }
            nodes_payload = [
                {
                    "address": n.address,
                    "type": node_meta[n.address].get("resolved_type") or n.resolved_type,
                    "label": node_meta[n.address].get("label") or n.contract_name or n.label,
                    "details": node_meta[n.address]["details"],
                }
                for n in cg_nodes
            ]
            edges_payload = [
                {
                    "from": e.from_node_id.replace("address:", ""),
                    "to": e.to_node_id.replace("address:", ""),
                    "relation": e.relation,
                }
                for e in cg_edges
            ]
            entry["control_graph"] = _trim_control_graph(nodes_payload, edges_payload)
        contracts.append(entry)

        if owner:
            owner_groups.setdefault(_entity_key(entry["chain"], owner), []).append(entry)

    # Drop standalone impls already represented under a proxy; composite keys so another chain's twin isn't collapsed.
    impl_entities = {_entity_key(c.get("chain"), c["implementation"]) for c in contracts if c.get("implementation")}
    for c in contracts:
        for saddr in c.get("secondary_implementations") or []:
            impl_entities.add(_entity_key(c.get("chain"), saddr))
    contracts = [
        c
        for c in contracts
        if not c["address"] or _entity_key(c.get("chain"), c["address"]) not in impl_entities or c["is_proxy"]
    ]

    remaining = {_entity_key(c.get("chain"), c["address"]) for c in contracts if c["address"]}
    for owner_key in list(owner_groups):
        owner_groups[owner_key] = [
            e for e in owner_groups[owner_key] if _entity_key(e.get("chain"), e["address"]) in remaining
        ]
        if not owner_groups[owner_key]:
            del owner_groups[owner_key]

    controller_enumeration = _controller_enumeration(contracts_by_job_id, cgn_by_cid)
    for entry in contracts:
        state = controller_enumeration.get(_entity_key(entry.get("chain"), entry.get("address")))
        if state is not None:
            entry["controller_enumeration"] = state

    hierarchy = _build_ownership_hierarchy(contracts, owner_groups)
    protocol_ids = {c.protocol_id for c in contracts_by_job_id.values() if c is not None and c.protocol_id is not None}
    reach_edges = _protocol_reach_edges(session, protocol_ids)
    fund_flows, principals = _build_flows_and_principals(
        contracts,
        contracts_by_job_id,
        controller_values_by_cid,
        fp_governance_by_cid,
        cgn_by_cid,
        cge_by_cid,
        fp_in_contract_by_cid,
        fp_all_addrs_by_cid,
        principal_lookup,
        reach_edges,
        principal_lookups_by_entity,
    )

    # FP-by-cid reshaped to FP-by-entity for ``primary_for`` (Surface group containment):
    #
    #   1. Proxy->impl keying: FP rows live on impls but the canvas draws proxies; without it proxied contracts drop out
    # of every group.
    #   2. Governance pass-through: an in-protocol Timelock/ProxyAdmin is never a principal, so
    # ``assign_primary_controllers`` resolves one hop further. Only FP edges are followed, so fund-destination Safes
    # can't re-enter.
    #
    # The fold stays in composite-entity space so twins run separate per-chain contests; output fields are rendered back
    # to bare addresses (the frontend composes them with the active chain).
    contract_entity_by_cid: dict[int, str] = {
        c.id: _entity_key(c.chain, c.address) for c in contracts_by_job_id.values() if c is not None and c.address
    }

    def _rendered_entity(key: RuntimeKey) -> str | None:
        own_entity = contract_entity_by_cid.get(code_id(key))
        if not own_entity:
            return None
        if isinstance(key, tuple):
            entity = _entity_key(_entity_chain(own_entity), key[1])
            return entity if entity in remaining else None
        return own_entity if own_entity in remaining else None

    # Callers are composited with their target's chain (always same-chain) so a governance contract is one node as key
    # and as caller.
    fp_addrs_by_contract_entity: dict[str, set[str]] = {}
    for cid, addrs in fp_all_addrs_by_cid.items():
        rendered = _rendered_entity(cid)
        if not rendered:
            continue
        chain_tok = _entity_chain(rendered)
        bucket = fp_addrs_by_contract_entity.setdefault(rendered, set())
        bucket.update(_entity_key(chain_tok, a) for a in addrs)

    governance_passthrough = {
        entity
        for entity in fp_addrs_by_contract_entity
        if principal_lookup.get(entity, {}).get("resolved_type") in _PASSTHROUGH_CONTROLLER_TYPES
    }

    # Feeds the primary contest, the co-controller rule and capability detail.
    fp_function_detail_by_entity: dict[str, list[dict[str, Any]]] = {}
    for cid, functions in fp_function_detail_by_cid.items():
        rendered = _rendered_entity(cid)
        if not rendered:
            continue
        fp_function_detail_by_entity.setdefault(rendered, []).extend(functions)

    primary_for = assign_primary_controllers(
        principals,
        fp_addrs_by_contract_entity,
        governance_passthrough=governance_passthrough,
        fp_function_detail_by_contract=fp_function_detail_by_entity,
    )

    # Principals with real authority on a contract they lost the primary contest for, shown as guardian-rail nodes and
    # monitored. See ``assign_co_controllers``.
    co_controls = assign_co_controllers(principals, fp_function_detail_by_entity, primary_for)

    # Rendering home for machinery whose operand unit lives in another principal's group (passthrough timelocks, pauser
    # fan-outs); ``primary_for`` still names the true controller.
    render_groups = assign_operand_render_groups(
        fp_addrs_by_contract_entity,
        {_entity_key(c.get("chain"), c["address"]) for c in contracts if c.get("address")},
        governance_passthrough,
        primary_for,
    )
    if render_groups:
        for entry in contracts:
            gw = render_groups.get(_entity_key(entry.get("chain"), entry.get("address") or ""))
            if gw:
                # Same chain as the contract, so the bare address is unambiguous on the canvas.
                entry["grouped_with"] = _entity_addr(gw)

    # Principals are per (chain, address); callers below are bare addresses on their contract's chain.
    principal_meta = {_entity_key(p.get("chain"), p["address"]): p for p in principals if p.get("address")}

    # Per-(controller, contract) functions and capability tags from FunctionPrincipal, so the canvas shows "pause ·
    # recover". Keeps every FP caller, including governance contracts needed for passthrough; non-principals are
    # filtered at consumption.
    caller_detail: dict[str, dict[str, dict[str, set[str]]]] = {}
    for caddr, functions in fp_function_detail_by_entity.items():
        for fn in functions:
            fname = fn.get("function")
            fn_caps = _function_capabilities(fn.get("claims") or ())
            for a in fn.get("callers", ()):
                la = (a or "").lower()
                if not la:
                    continue
                detail = caller_detail.setdefault(caddr, {}).setdefault(la, {"functions": set(), "capabilities": set()})
                if fname:
                    detail["functions"].add(fname)
                detail["capabilities"].update(fn_caps)

    # Per-principal capabilities: direct FP authority plus one passthrough hop via a governance contract the principal
    # controls. Without the hop, a Safe acting only through its timelock shows no capabilities.
    detail_acc: dict[str, dict[str, dict[str, set[str]]]] = {}

    def _accumulate(principal_lc: str, contract_lc: str, src: dict[str, set[str]]) -> None:
        slot = detail_acc.setdefault(principal_lc, {}).setdefault(
            contract_lc, {"functions": set(), "capabilities": set()}
        )
        slot["functions"].update(src.get("functions", ()))
        slot["capabilities"].update(src.get("capabilities", ()))

    for caddr, callers_map in caller_detail.items():
        caddr_chain = _entity_chain(caddr)
        for la, detail in callers_map.items():
            principal_key = _entity_key(caddr_chain, la)
            if principal_key in principal_meta:  # direct rights belong to principals, not contract callers
                _accumulate(principal_key, caddr, detail)
    for principal_key, owned in primary_for.items():
        for caddr in owned:
            # Control is intra-chain.
            caddr_chain = _entity_chain(caddr)
            for gov_addr, gov_detail in caller_detail.get(caddr, {}).items():
                gov_entity = _entity_key(caddr_chain, gov_addr)
                if gov_entity in governance_passthrough and _entity_addr(principal_key) in caller_detail.get(
                    gov_entity, {}
                ):
                    _accumulate(principal_key, caddr, gov_detail)

    detail_by_principal: dict[str, list[dict[str, Any]]] = {}
    for la, by_contract in detail_acc.items():
        rows = [
            {
                "address": _entity_addr(caddr),
                "chain": _entity_chain(caddr),
                "functions": sorted(d["functions"]),
                "capabilities": sorted(d["capabilities"]),
            }
            for caddr, d in by_contract.items()
        ]
        rows.sort(key=lambda e: (e["address"], e["chain"]))
        detail_by_principal[la] = rows

    for p in principals:
        p_addr_lc = (p.get("address") or "").lower()
        p_key = _entity_key(p.get("chain"), p_addr_lc)
        # Serialized as bare addresses; the frontend re-composes with the active chain.
        p["primary_for"] = sorted({_entity_addr(e) for e in primary_for.get(p_key, [])})
        p["co_controls"] = sorted({_entity_addr(e) for e in co_controls.get(p_key, [])})
        # Enrollment needs the chains a principal controls on, rather than a caller default.
        p["controls_chains"] = sorted(
            {_entity_chain(e) for e in primary_for.get(p_key, [])}
            | {_entity_chain(e) for e in co_controls.get(p_key, [])}
        )
        p["controls_detail"] = detail_by_principal.get(p_key, [])
        states = [controller_enumeration.get(_entity_key(chain, p_addr_lc)) for chain in p.get("chains") or []]
        unread = [state for state in states if state and state["state"] == "not_determined"]
        if unread:
            p["controller_enumeration"] = {
                "state": "not_determined",
                "status": ",".join(sorted({state["status"] for state in unread})),
            }
        elif any(states):
            p["controller_enumeration"] = {"state": "complete"}

    # What the source can do to the target, from the same machinery as ``controls_detail`` so edge and panel can't
    # disagree. ``[]`` isn't proof of inability.
    for flow in fund_flows:
        src_lc = (flow.get("from") or "").lower()
        target_entity = _entity_key(flow.get("to_chain"), flow.get("to"))
        detail = detail_acc.get(_entity_key(flow.get("from_chain"), src_lc), {}).get(target_entity)
        if detail is None:
            detail = caller_detail.get(target_entity, {}).get(src_lc)
        flow["capabilities"] = sorted(detail["capabilities"]) if detail else []

    # FP principals that are neither primary nor co-controller (e.g. whitelisted bidders), rendered as "+N callers".
    # FP-typed only, so state-var noise can't leak in.
    primary_by_contract: dict[str, str] = {c: paddr for paddr, owned in primary_for.items() for c in owned}
    co_by_contract: dict[str, set[str]] = {}
    for paddr, owned in co_controls.items():
        for c in owned:
            co_by_contract.setdefault(c, set()).add(paddr)
    for entry in contracts:
        addr = (entry.get("address") or "").lower()
        chain = entry.get("chain")
        entity = _entity_key(chain, addr)
        cd = caller_detail.get(entity, {})
        # Contract callers aren't "other callers".
        callers = {a for a in cd if _entity_key(chain, a) in principal_meta}
        callers.discard(addr)
        callers.discard(_entity_addr(primary_by_contract.get(entity, "")))
        callers -= {_entity_addr(key) for key in co_by_contract.get(entity, set())}
        entry["other_callers"] = [
            {
                "address": a,
                "type": (principal_meta.get(_entity_key(chain, a)) or {}).get("type"),
                "label": (principal_meta.get(_entity_key(chain, a)) or {}).get("label"),
                "functions": sorted(cd[a]["functions"]),
                "capabilities": sorted(cd[a]["capabilities"]),
            }
            for a in sorted(callers)
        ]

    return GovernanceView(
        contracts=contracts,
        principals=principals,
        hierarchy=hierarchy,
        fund_flows=fund_flows,
    )


def _build_ownership_hierarchy(
    contracts: list[dict[str, Any]], owner_groups: dict[str, list[dict]]
) -> list[dict[str, Any]]:
    """Contracts grouped by owner per chain; *owner_groups* is keyed by the owner's entity."""
    contracts_by_entity = {_entity_key(c.get("chain"), c["address"]): c for c in contracts if c["address"]}
    hierarchy: list[dict[str, Any]] = []
    assigned: set[str] = set()
    for owner_key, owned in sorted(owner_groups.items(), key=lambda x: (-len(x[1]), x[0])):
        owner_contract = contracts_by_entity.get(owner_key)
        hierarchy.append(
            {
                "owner": _entity_addr(owner_key),
                "chain": _entity_chain(owner_key),
                "owner_name": owner_contract["name"] if owner_contract else None,
                "owner_is_contract": owner_contract is not None,
                "contracts": [{"address": c["address"], "name": c["name"]} for c in owned],
            }
        )
        assigned.update(_entity_key(c.get("chain"), c["address"]) for c in owned)

    unowned = [c for c in contracts if _entity_key(c.get("chain"), c["address"]) not in assigned]
    if unowned:
        hierarchy.append(
            {
                "owner": None,
                "owner_name": "No owner detected",
                "owner_is_contract": False,
                "contracts": [{"address": c["address"], "name": c["name"]} for c in unowned],
            }
        )
    return hierarchy


_ZERO_ADDR = "0x0000000000000000000000000000000000000000"


def _protocol_reach_edges(
    session: Session, protocol_ids: set[int]
) -> list[tuple[str, str, str, str | None, str | None]]:
    """Protocol-wide control edges the scorer's closure walks.

    Display edges only; reach claims live in the top-level ``reach`` block.

    Mirrors ``services.scoring.planes.load_control_closure`` exactly (``SCORER_REACH_RELATIONS`` reversed, plus
    ``Contract.admin`` / ``Contract.beacon`` pairs) and isn't limited to this payload's contracts, so the surface graph
    can route every hop the score document holds. Admin pairs have ``relation=None`` (the column is the witness).
    ``safe_owner``/``capability_principal`` are excluded as the scorer excludes them; zero-address ends are skipped.
    """
    rows: list[tuple[str, str, str, str | None, str | None]] = []
    if not protocol_ids:
        return rows
    id_list = sorted(protocol_ids)
    edge_rows = (
        session.query(ControlGraphEdge, Contract.chain)
        .join(Contract, Contract.id == ControlGraphEdge.contract_id)
        .filter(Contract.protocol_id.in_(id_list), ControlGraphEdge.relation.in_(SCORER_REACH_RELATIONS))
        .order_by(ControlGraphEdge.id)
        .all()
    )
    for edge, chain in edge_rows:
        subject = (edge.from_node_id or "").replace("address:", "").lower()
        holder = (edge.to_node_id or "").replace("address:", "").lower()
        if not subject or not holder or subject == holder or _ZERO_ADDR in (subject, holder):
            continue
        rows.append((_coalesce_chain(chain), holder, subject, edge.relation, edge.label or None))
    for contract in session.query(Contract).filter(Contract.protocol_id.in_(id_list)).order_by(Contract.id).all():
        address = (contract.address or "").lower()
        for column in ((contract.admin or "").lower(), (contract.beacon or "").lower()):
            if address and column and column != address and _ZERO_ADDR not in (address, column):
                rows.append((_coalesce_chain(contract.chain), column, address, None, None))
    return rows


def _control_edge_witness(
    contracts: list[dict[str, Any]],
    lookup_contract_by_entity: dict[str, Contract | None],
    cge_by_cid: dict[RuntimeKey, list[ControlGraphEdge]],
    reach_edges: Iterable[tuple[str, str, str, str | None, str | None]] = (),
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """``(chain, flow_from, flow_to)`` -> witnessed claims on that control edge.

    Rows are written subject-first, so they're indexed reversed, and only ``CONTROL_EDGE_RELATIONS`` (reversing an
    ``external_call_target`` would assert unproven authority). Single claims get scalar ``relation``/``label``; multiple
    get ``relations`` rather than an arbitrary pick.
    """
    claims: dict[tuple[str, str, str], set[tuple[str, str | None]]] = {}
    for entry in contracts:
        if not entry.get("address"):
            continue
        lookup_c = lookup_contract_by_entity.get(_entity_key(entry.get("chain"), entry["address"]))
        if not lookup_c:
            continue
        chain_tok = _coalesce_chain(entry.get("chain"))
        for edge in cge_by_cid.get(entry_key(lookup_c.id, entry), []):
            if edge.relation not in CONTROL_EDGE_RELATIONS:
                continue
            subject = (edge.from_node_id or "").replace("address:", "").lower()
            holder = (edge.to_node_id or "").replace("address:", "").lower()
            if not subject or not holder or subject == holder:
                continue
            claims.setdefault((chain_tok, holder, subject), set()).add((edge.relation, edge.label or None))
    for chain_tok, holder, subject, relation, label in reach_edges:
        if relation is not None:
            claims.setdefault((chain_tok, holder, subject), set()).add((relation, label))

    witness: dict[tuple[str, str, str], dict[str, Any]] = {}
    for key, pairs in claims.items():
        ordered = sorted(pairs, key=lambda p: (p[0], p[1] or ""))
        if len(ordered) == 1:
            relation, label = ordered[0]
            witness[key] = {"relation": relation, **({"label": label} if label else {})}
        else:
            witness[key] = {
                "relations": [{"relation": r, **({"label": lb} if lb else {})} for r, lb in ordered],
            }
    return witness


def _build_flows_and_principals(
    contracts: list[dict[str, Any]],
    contracts_by_job_id: dict[Any, Contract],
    controller_values_by_cid: dict[RuntimeKey, list[ControllerValue]],
    fp_governance_by_cid: dict[RuntimeKey, list[dict[str, Any]]],
    cgn_by_cid: dict[RuntimeKey, list[ControlGraphNode]],
    cge_by_cid: dict[RuntimeKey, list[ControlGraphEdge]],
    fp_in_contract_by_cid: dict[RuntimeKey, set[str]],
    fp_all_addrs_by_cid: dict[RuntimeKey, set[str]],
    principal_lookup: dict[str, dict[str, Any]],
    reach_edges: list[tuple[str, str, str, str | None, str | None]],
    principal_lookups_by_entity: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    # Composite keys throughout: an address that is a contract on one chain can be a Safe or an EOA on another.
    contract_entities = {_entity_key(c.get("chain"), c["address"]) for c in contracts if c["address"]}
    # Dedup per chain so a twin keeps its own edge.
    flow_seen: set[tuple[str, str, str]] = set()
    fund_flows: list[dict[str, Any]] = []
    # Absent keys are normal: most edges have no witnessed relation.
    edge_witness: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_flow(from_addr: str, to_addr: str, flow_type: str, chain: str | None, lane: str = "control") -> None:
        chain_tok = _coalesce_chain(chain)
        key = (chain_tok, (from_addr or "").lower(), (to_addr or "").lower())
        if key in flow_seen:
            return
        flow_seen.add(key)
        fund_flows.append(
            {
                "from": from_addr,
                "to": to_addr,
                "type": flow_type,
                "lane": lane,
                # Only where a control-graph row witnesses this exact pair.
                **edge_witness.get(key, {}),
                # Filled later: the source's rights on the target, not the target's capability union.
                "capabilities": [],
                "from_chain": chain_tok,
                "to_chain": chain_tok,
            }
        )

    def _lookup_contract_for(entry: dict[str, Any]) -> Contract | None:
        import uuid as _uuid

        lookup_job_id = entry.get("impl_job_id") or entry["job_id"]
        try:
            key_id = _uuid.UUID(lookup_job_id) if isinstance(lookup_job_id, str) else lookup_job_id
        except (TypeError, ValueError):
            key_id = lookup_job_id
        return contracts_by_job_id.get(key_id)

    lookup_contract_by_entity: dict[str, Contract | None] = {}
    for entry in contracts:
        if entry.get("address"):
            lookup_contract_by_entity[_entity_key(entry.get("chain"), entry["address"])] = _lookup_contract_for(entry)

    edge_witness.update(_control_edge_witness(contracts, lookup_contract_by_entity, cge_by_cid, reach_edges))

    for c in contracts:
        if not c["address"]:
            continue
        target = c["address"].lower()
        chain = c.get("chain")
        prefix = _entity_prefix(chain)
        lookup_c = lookup_contract_by_entity.get(prefix + target)
        fp_principals: set[str] = fp_in_contract_by_cid.get(entry_key(lookup_c.id, c), set()) if lookup_c else set()

        if c.get("owner") and prefix + c["owner"].lower() in contract_entities:
            flow_type = (
                "controls_value"
                if any(e in c.get("value_effects", []) for e in ("asset_pull", "asset_send"))
                else "controls"
            )
            add_flow(c["owner"], target, flow_type, chain)

        # ``controllers`` includes composability references (weth, oracle, swapRouter); gate on FunctionPrincipal so
        # only real call-authority emits a controller flow.
        for cid, val in c.get("controllers", {}).items():
            if isinstance(val, str) and val.startswith("0x"):
                val_lower = val.lower()
                if (
                    prefix + val_lower in contract_entities
                    and val_lower != (c.get("owner") or "")
                    and val_lower in fp_principals
                ):
                    add_flow(val_lower, target, "controller", chain)

        # FunctionPrincipal, not bare CGN matches: CGN over-reported transitive lineage (tokens mid-chain flagged as
        # principals).
        if lookup_c:
            for node_addr in sorted(fp_principals):
                if not node_addr or node_addr == target:
                    continue
                if prefix + node_addr not in contract_entities:
                    continue
                add_flow(node_addr, target, "principal", chain)

    # First pass: safe_owner edges, so Safe owners nest. A Safe's owners are read on its own chain.
    principal_map: dict[str, dict[str, Any]] = {}
    safe_owners_map: dict[str, list[str]] = {}
    owner_of_safe: set[str] = set()

    for c in sorted(contracts, key=_contract_order):
        if not c["address"]:
            continue
        chain = c.get("chain")
        prefix = _entity_prefix(chain)
        lookup_c = lookup_contract_by_entity.get(prefix + c["address"].lower())
        if not lookup_c:
            continue
        safe_owner_edges = [e for e in cge_by_cid.get(entry_key(lookup_c.id, c), []) if e.relation == "safe_owner"]
        for edge in sorted(safe_owner_edges, key=_edge_order):
            safe_key = prefix + edge.from_node_id.replace("address:", "").lower()
            owner_addr = edge.to_node_id.replace("address:", "").lower()
            owners = safe_owners_map.setdefault(safe_key, [])
            if owner_addr not in owners:
                owners.append(owner_addr)
            owner_of_safe.add(prefix + owner_addr)

    def _principal_entry(principal_key: str, resolved_type: str, label: str, details: dict[str, Any]) -> dict:
        if resolved_type == "safe":
            if not details.get("owners"):
                details["owners"] = safe_owners_map.get(principal_key, [])
            if "threshold" not in details and details.get("owners"):
                details["threshold"] = len(details["owners"])
        return {
            "address": _entity_addr(principal_key),
            "chain": _entity_chain(principal_key),
            "type": resolved_type,
            "label": label,
            "details": details,
            "controls": [],
            "chains": {_entity_chain(principal_key)},
        }

    for c in sorted(contracts, key=_contract_order):
        if not c["address"]:
            continue
        target = c["address"].lower()
        chain = c.get("chain")
        prefix = _entity_prefix(chain)
        lookup_c = lookup_contract_by_entity.get(prefix + target)
        if not lookup_c:
            continue
        fp_addrs = fp_all_addrs_by_cid.get(entry_key(lookup_c.id, c), set())

        accepted: list[tuple[Any, str, str, dict[str, Any], str]] = []
        for cgn in cgn_by_cid.get(entry_key(lookup_c.id, c), []):
            node_addr = (cgn.address or "").lower()
            principal_key = prefix + node_addr
            if not node_addr or principal_key in contract_entities:
                continue
            if principal_key in owner_of_safe:
                continue
            # Only CGN nodes with FP authority become principals; otherwise beneficiary state vars (treasury,
            # feeRecipient) claim control they don't hold.
            if node_addr not in fp_addrs or node_addr == "0x0000000000000000000000000000000000000000":
                continue
            lookup_meta = (
                (principal_lookups_by_entity or {}).get(prefix + target, principal_lookup).get(principal_key, {})
            )
            resolved_type = lookup_meta.get("resolved_type") or cgn.resolved_type
            if resolved_type not in _SETTLED_CONTROLLER_TYPES:
                continue
            accepted.append((cgn, node_addr, principal_key, lookup_meta, resolved_type))

        # The first row for a principal supplies its label and details, so take rows in a fixed order.
        for cgn, node_addr, principal_key, lookup_meta, resolved_type in sorted(
            accepted, key=lambda row: _node_order(row[0])
        ):
            if principal_key not in principal_map:
                # The CGN's own introspection (getOwners/getThreshold, getMinDelay) is authoritative for the principal's
                # config; CV rows describe the consumer side.
                details: dict[str, Any] = dict(lookup_meta.get("details") or {})
                if isinstance(cgn.details, dict):
                    details.update(cgn.details)
                for cv in controller_values_by_cid.get(entry_key(lookup_c.id, c), []):
                    if (cv.value or "").lower() != node_addr:
                        continue
                    if cv.details and isinstance(cv.details, dict):
                        for k, v in cv.details.items():
                            details.setdefault(k, v)
                principal_map[principal_key] = _principal_entry(
                    principal_key,
                    resolved_type,
                    lookup_meta.get("label") or cgn.contract_name or cgn.label or resolved_type,
                    details,
                )

            principal_map[principal_key]["controls"].append(target)
            add_flow(node_addr, target, "principal", chain)

    # Third pass: some Safes appear only on per-function FP rows (e.g. EtherFiTimelock.cancel) with no CGN entry.
    for c in sorted(contracts, key=_contract_order):
        if not c["address"]:
            continue
        target = c["address"].lower()
        chain = c.get("chain")
        prefix = _entity_prefix(chain)
        lookup_c = lookup_contract_by_entity.get(prefix + target)
        if not lookup_c:
            continue
        accepted_fp: list[tuple[dict[str, Any], str, str, dict[str, Any], str]] = []
        for fp in fp_governance_by_cid.get(entry_key(lookup_c.id, c), []):
            pa = (fp.get("address") or "").lower()
            if not pa or pa == target:
                continue
            if pa == "0x0000000000000000000000000000000000000000":
                continue
            principal_key = prefix + pa
            if principal_key in owner_of_safe or principal_key in contract_entities:
                continue
            lookup_meta = (
                (principal_lookups_by_entity or {}).get(prefix + target, principal_lookup).get(principal_key, {})
            )
            resolved_type = fp.get("resolved_type")
            if lookup_meta.get("resolved_type") and resolved_type in (None, "", "unknown", "contract"):
                resolved_type = lookup_meta["resolved_type"]
            if resolved_type not in _SETTLED_CONTROLLER_TYPES:
                continue
            accepted_fp.append((fp, pa, principal_key, lookup_meta, resolved_type))
        # Rows arrive ordered from the prefetch, so the first one for a principal is fixed.
        for fp, pa, principal_key, lookup_meta, resolved_type in accepted_fp:
            if principal_key not in principal_map:
                fp_details = dict(lookup_meta.get("details") or {})
                fp_raw_details = fp.get("details")
                if isinstance(fp_raw_details, dict):
                    fp_details.update(fp_raw_details)
                principal_map[principal_key] = _principal_entry(
                    principal_key, resolved_type, lookup_meta.get("label") or resolved_type, fp_details
                )
            if target not in principal_map[principal_key]["controls"]:
                principal_map[principal_key]["controls"].append(target)
            add_flow(pa, target, "principal", chain)

    # Scorer reach edges carried verbatim so every route the score document publishes is drawable. No holder gate (the
    # admitted relations all carry authority provenance). Emits edges only, and runs last so first-writer-wins keeps
    # richer types from earlier passes.
    for chain_tok, holder, subject, _relation, _label in reach_edges:
        add_flow(holder, subject, "controller", chain_tok)

    principals_out = [principal_map[key] for key in sorted(principal_map)]
    for pr in principals_out:
        pr["chains"] = sorted(pr["chains"])
    return fund_flows, principals_out


def _contract_order(entry: dict[str, Any]) -> tuple[str, str]:
    return (_coalesce_chain(entry.get("chain")), (entry.get("address") or "").lower())


def _node_order(node: Any) -> tuple[str, int]:
    return ((node.address or "").lower(), getattr(node, "id", None) or 0)


def _edge_order(edge: Any) -> tuple[str, str, int]:
    return (edge.from_node_id or "", edge.to_node_id or "", getattr(edge, "id", None) or 0)


def _controller_enumeration(
    contracts_by_job_id: dict[Any, Contract], cgn_by_cid: dict[RuntimeKey, list[ControlGraphNode]]
) -> dict[str, dict[str, str]]:
    """Per entity with a member replay: ``complete``, or ``not_determined`` with the statuses it reached.

    Without it an unread member set draws as a contract nobody controls. Entities with no replay get no entry.
    """
    chain_by_cid = {c.id: c.chain for c in contracts_by_job_id.values() if c is not None}
    statuses: dict[str, set[str]] = {}
    for cid, nodes in cgn_by_cid.items():
        for node in nodes:
            details = node.details if isinstance(node.details, dict) else {}
            status = details.get(MAPPING_ENUMERATION_STATUS)
            if status is not None:
                statuses.setdefault(_entity_key(chain_by_cid.get(code_id(cid)), node.address), set()).add(str(status))
    unread = controllers_not_determined(statuses)
    return {
        key: ({"state": "not_determined", "status": unread[key]} if key in unread else {"state": "complete"})
        for key in statuses
    }
