"""``build_governance_view`` — contracts list, ownership hierarchy, fund
flows and principals."""

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
from services.effects.selection import disposed_from_holdings, load_protocol_reference_shapes
from services.governance.primary_controller import (
    assign_co_controllers,
    assign_operand_render_groups,
    assign_primary_controllers,
)
from services.governance.primary_controller import (
    function_capabilities as _function_capabilities,
)
from services.monitoring.delivery_evidence import load_delivery_evidence
from services.scoring.planes import CONTROL_RELATIONS as SCORER_REACH_RELATIONS
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_NOT_DETERMINED,
    TOKEN_REFERENCE_NOT_DETERMINED,
)
from utils.chains import UnknownChainError, chain_by_name

from .entity_keys import _coalesce_chain, _entity_addr, _entity_chain, _entity_key
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


def build_governance_view(
    session: Session,
    jobs: list[Job],
    contracts_by_job_id: dict[Any, Contract],
    impl_job_by_entity: dict[str, Job],
) -> GovernanceView:
    """Build the contracts list + ownership hierarchy + fund flows + principals."""
    relevant_contract_ids: set[int] = {c.id for c in contracts_by_job_id.values() if c is not None}
    children = _prefetch_child_tables(session, relevant_contract_ids)
    controller_values_by_cid: dict[int, list[ControllerValue]] = children["controller_values"]
    ef_effects_by_cid: dict[int, list[dict[str, list[str]]]] = children["ef_effects"]
    fp_governance_by_cid: dict[int, list[dict[str, Any]]] = children["fp_governance_rows"]
    upgrade_events_count_by_cid: dict[int, dict[str, Any]] = children["upgrade_events_count"]
    last_upgrade_by_cid: dict[int, dict[str, Any]] = children["upgrade_events_last"]
    balances_by_cid: dict[int, list[Any]] = children["balances"]
    balance_fetch_by_id: dict[int, Any] = children["balance_fetches"]
    cgn_by_cid: dict[int, list[ControlGraphNode]] = children["cgn"]
    cge_by_cid: dict[int, list[ControlGraphEdge]] = children["cge"]
    fp_in_contract_by_cid: dict[int, set[str]] = children["fp_in_contract_principals"]
    fp_all_addrs_by_cid: dict[int, set[str]] = children["fp_all_addrs"]
    fp_function_detail_by_cid: dict[int, list[dict[str, Any]]] = children["fp_function_detail"]
    # Keyed by ADDRESS, unlike every sibling stage's contract_id map — the walk is a
    # fact about the address, not about the subject contract that recorded it.
    terminal_walk_by_address: dict[str, dict[str, Any]] = children["terminal_walk"]  # pyright: ignore[reportAssignmentType]

    # Delivery shape for every balance row in this view, read ONCE for the whole
    # request. The evidence plane is keyed by the account the read was issued
    # against, so the key is built from each row's own ``observed_address`` — it
    # differs from ``contracts.address`` on 162 of this protocol's token rows, and
    # keying on the contract would answer ``not_determined`` for all of them.
    chain_name_by_cid: dict[int, str | None] = {c.id: c.chain for c in contracts_by_job_id.values() if c is not None}

    def _fetch_for(balance_row: Any) -> Any | None:
        """The fetch a latest-view row came from, or ``None`` for a legacy row.

        A legacy row (``fetch_id IS NULL``) predates the fetch-provenance plane; it
        has no status and no chain of its own, and both callers below read that
        absence as not-determined rather than filling it in.
        """
        fetch_id = getattr(balance_row, "fetch_id", None)
        return balance_fetch_by_id.get(int(fetch_id)) if fetch_id is not None else None

    def _delivery_account(balance_row: Any) -> tuple[int, str] | None:
        observed = (getattr(balance_row, "observed_address", None) or "").lower()
        if not observed:
            return None
        chain_id = getattr(_fetch_for(balance_row), "chain_id", None)
        if chain_id is None:
            chain_name = chain_name_by_cid.get(balance_row.contract_id)
            if not chain_name:
                return None
            try:
                chain_id = chain_by_name(chain_name).chain_id
            except UnknownChainError:
                return None
        return int(chain_id), observed

    delivery_facts = load_delivery_evidence(
        session,
        {
            account
            for rows_for_cid in balances_by_cid.values()
            for row in rows_for_cid
            if (account := _delivery_account(row)) is not None
        },
    )
    # The second disposition conjunct, read as the producer last MEASURED it. This
    # plane cannot assemble the protocol's universe itself — that is a 26.5 s
    # object-storage read and this is an API path — so it reads the stored verdict and
    # inherits its staleness; :func:`services.effects.selection.disposed_from_holdings`
    # states what that costs.
    reference_shapes = load_protocol_reference_shapes(
        session,
        {c.protocol_id for c in contracts_by_job_id.values() if c is not None and c.protocol_id is not None},
    )

    # Fold each proxy's secondary-impl child rows into its PRIMARY impl's
    # contract_id buckets. The flow/principal passes key on the primary impl
    # (the proxy's lookup contract), so a governor/admin Safe that holds
    # authority only on the secondary (admin) impl's functions still surfaces as
    # a controller of the proxy node.
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
        if primary_cid is None:
            continue
        for sc in secondaries:
            if sc.id == primary_cid:
                continue
            cv_extra = controller_values_by_cid.get(sc.id)
            if cv_extra:
                controller_values_by_cid[primary_cid] = list(controller_values_by_cid.get(primary_cid) or []) + cv_extra
            fpg_extra = fp_governance_by_cid.get(sc.id)
            if fpg_extra:
                fp_governance_by_cid[primary_cid] = list(fp_governance_by_cid.get(primary_cid) or []) + fpg_extra
            extra_addrs = fp_in_contract_by_cid.get(sc.id)
            if extra_addrs:
                fp_in_contract_by_cid[primary_cid] = set(fp_in_contract_by_cid.get(primary_cid) or set()) | set(
                    extra_addrs
                )
            # The second-pass CGN principal gate (:_build_flows_and_principals)
            # admits a Safe/EOA/timelock only if it holds FP authority on the
            # PRIMARY impl's cid. A governor that gates only the secondary impl's
            # functions lives in fp_all_addrs under the secondary cid, so fold it
            # up too — the sibling projections above already do.
            extra_all = fp_all_addrs_by_cid.get(sc.id)
            if extra_all:
                fp_all_addrs_by_cid[primary_cid] = set(fp_all_addrs_by_cid.get(primary_cid) or set()) | set(extra_all)

    principal_lookup = _build_principal_lookup(
        contracts_by_job_id, controller_values_by_cid, cgn_by_cid, terminal_walk_by_address
    )

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

        # Split-proxy secondary logic contracts (admin-impl set). Their
        # functions + principals attribute to this proxy node too.
        secondary_impl_contracts = _secondary_impl_contracts(contract_row, impl_job_by_entity, contracts_by_job_id)

        summary_row = impl_contract.summary if impl_contract else None
        if not summary_row and contract_row:
            summary_row = contract_row.summary

        # Prefer a logic contract's controller snapshot for proxies — the impl
        # (or a secondary impl) read against proxy storage, whichever has rows.
        lookup_contract = contract_row
        if is_proxy:
            for candidate in [impl_contract, *secondary_impl_contracts]:
                if candidate and controller_values_by_cid.get(candidate.id):
                    lookup_contract = candidate
                    break

        owner = None
        controllers: dict[str, Any] = {}
        if lookup_contract:
            for cv in controller_values_by_cid.get(lookup_contract.id, []):
                controllers[cv.controller_id] = cv.value
                if _is_active_owner_controller(cv.controller_id) and cv.value and cv.value.startswith("0x"):
                    owner = cv.value.lower()

        upgrade_entry = (upgrade_events_count_by_cid.get(contract_row.id) if contract_row else None) or {}
        # ``count`` is None whenever the rows support no PROVEN upgrade action —
        # including the post-exclusion zero, which the UI would otherwise render
        # as the earned negative "0 upgrades".
        upgrade_count = upgrade_entry.get("count")
        upgrade_count_basis = upgrade_entry.get("basis")
        last_upgrade_entry = (last_upgrade_by_cid.get(contract_row.id) if contract_row else None) or {}
        last_upgrade_block = last_upgrade_entry.get("block")
        last_ts = last_upgrade_entry.get("timestamp")
        last_upgrade_timestamp = last_ts.isoformat() if last_ts is not None else None

        # Effects from every logic contract of this node: the impl (or the row
        # itself for non-proxies) plus any secondary impls.
        primary_ef_cid = (impl_contract.id if impl_contract else None) or (contract_row.id if contract_row else None)
        ef_contract_ids = [primary_ef_cid] if primary_ef_cid else []
        ef_contract_ids += [sc.id for sc in secondary_impl_contracts]

        # ``value_effects`` stays a Plane-0 fact off legacy labels (it drives the
        # role classification + fund-flow lane); the capability chips key off
        # Plane-1 claims per function, legacy labels the claim-less fallback.
        value_effects: list[str] = []
        caps_set: set[str] = set()
        for cid in ef_contract_ids:
            for rec in ef_effects_by_cid.get(cid, []):
                for label in rec["labels"]:
                    if label in ("asset_pull", "asset_send", "mint", "burn") and label not in value_effects:
                        value_effects.append(label)
                caps_set |= _function_capabilities(rec["labels"], rec["claims"])

        # Two non-label extras layered on: ``upgradeable`` (it's a proxy shell)
        # and ``pause`` from the summary flag (a contract can be pausable without
        # a pause_toggle EffectiveFunction surfacing).
        if is_proxy:
            caps_set.add("upgradeable")
        # ``is True``, not truthiness: the column is three-state and a ``None``
        # means the pause detector did not answer (or there is no summary row at
        # all). A capability chip is a positive claim — "this contract can be
        # paused" — so only a proven ``True`` earns one. Absence of the chip is
        # NOT published as proof of the opposite; the three-state flag below is
        # where a consumer reads that.
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
        # Three states through the payload. ``False`` used to be published for a
        # contract that HAS NO SUMMARY ROW — 3 of the 56 entries the endpoint
        # serves on the local corpus (lower bound; every dependency-only contract
        # without a summary takes this path) — so "this contract cannot be paused
        # / has no timelock / is not
        # a factory" was asserted on the strength of never having looked. The
        # producer's own columns are three-state (``bool | None``), and a row
        # whose column is NULL means the detector ran and could not tell; both
        # routes to "nobody answered" publish ``None`` here, and
        # ``summary_evidence`` below names WHICH route it was — the two are
        # different questions for whoever wants to fix it (re-run the stage vs
        # improve the detector), and the same answer for anyone reading the flag.
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

        # ``role`` has no not-determined member and every consumer needs one:
        # each branch above except the last fires on a POSITIVE fact (a name, an
        # observed value effect, a declared standard, a proven timelock/factory),
        # so only the ``utility`` fall-through can be reached by a chain of
        # not-determined inputs. Published as its own key rather than folded into
        # ``role`` so the existing role vocabulary — read by the canvas, the
        # layout bands and ``protocolScore`` — keeps its meaning, and a consumer
        # that cares can refuse to treat this row's ``utility`` as evidence.
        role_evidence = (
            "witnessed"
            if role != "utility" or (summary_row is not None and has_timelock is not None and is_factory is not None)
            else "not_determined"
        )

        # Balances are FILED against the row whose ADDRESS was read — a proxy's
        # holdings belong to the proxy's own row (resolution_worker._fetch_balances),
        # which is this entry's row. ``lookup_contract`` answers governance lookups
        # and may be the implementation's row, where no balance is ever filed.
        balance_contract = contract_row or lookup_contract
        balances_list = []
        total_usd = 0.0
        unvalued_rows = 0
        airdrop_delivered_rows = 0
        disposed_rows = 0
        at_page_cap = False
        if balance_contract:
            for b in balances_by_cid.get(balance_contract.id, []):
                usd = float(b.usd_value) if b.usd_value is not None else None
                if usd is None:
                    unvalued_rows += 1
                if getattr(_fetch_for(b), "asset_set_status", None) == ASSET_SET_STATUS_AT_PAGE_CAP:
                    # WEAKEST WINS across the rows: one contributing fetch that was
                    # cut off means this list may be missing entries, whatever the
                    # others recorded.
                    at_page_cap = True
                account = _delivery_account(b)
                token = (b.token_address or "").lower()
                fact = delivery_facts.get((*account, token)) if account and token else None
                delivery_shape = fact.shape if fact is not None else DELIVERY_SHAPE_NOT_DETERMINED
                reference_shape = (
                    reference_shapes.get(
                        (balance_contract.protocol_id, account[0], token), TOKEN_REFERENCE_NOT_DETERMINED
                    )
                    if account and token and balance_contract.protocol_id is not None
                    else TOKEN_REFERENCE_NOT_DETERMINED
                )
                if delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL:
                    airdrop_delivered_rows += 1
                # The DISPOSITION, which is the delivery shape AND the universe verdict
                # AND the reading being unpriced — never the delivery shape alone. The
                # two counts are published side by side because they answer different
                # questions: how many rows arrived in a batch, and how many rows that
                # is enough to stop presenting as a position.
                #
                # THIS PAGE AND THE SCORE DIVERGE BY DESIGN, and the gap is not a
                # defect: ``disposed_from_holdings`` disposes only an UNPRICED reading,
                # while the scorer's arm
                # (``services.scoring.planes._resolve_asset_disposition``) also disposes
                # a ``priced_below_resolution`` one — so presentation is WEAKER and
                # spares every such row here that the score has already stopped
                # counting, never the reverse. Showing a holding the score dropped is
                # the safe direction; hiding one it still counts is not. Both rules
                # are stated in full on ``disposed_from_holdings``.
                disposed = disposed_from_holdings(
                    delivery_shape=delivery_shape, reference_shape=reference_shape, usd_value=usd
                )
                if disposed:
                    disposed_rows += 1
                balances_list.append(
                    {
                        "token_symbol": b.token_symbol,
                        "token_name": b.token_name,
                        "token_address": b.token_address,
                        "raw_balance": b.raw_balance,
                        "decimals": b.decimals,
                        "usd_value": usd,
                        # ``usd_value: null`` and ``usd_value: 0`` are one
                        # truthiness test apart in JS and mean opposite things —
                        # "we do not know what this holding is worth" versus
                        # "priced, and the figure is zero to eighteen decimals".
                        # The state is published rather than left to be inferred
                        # from the value's shape.
                        #
                        # ``not_determined`` deliberately does not name a CAUSE:
                        # ``services/clients/etherscan`` distinguishes "no price returned"
                        # from "no token divisor returned" (which would make any
                        # USD figure wrong by 10^n), but neither writer persists
                        # ``decimals_reported``, so the DB cannot tell them apart
                        # and this payload must not pretend otherwise.
                        "usd_value_state": "measured" if usd is not None else "not_determined",
                        # Kept for continuity, and NOT a money fact: the producer
                        # writes 0 for "no price known", and a row written before
                        # the column widened to Numeric(38,18) may carry the same
                        # 0 for a real quote its eighth decimal could not hold —
                        # so 0 is ambiguous between the two and a consumer reading
                        # this column directly reads both as worthless. Read
                        # ``usd_value`` / ``usd_value_state``.
                        "price_usd": float(b.price_usd) if b.price_usd is not None else None,
                        # How this balance ARRIVED, one of
                        # ``utils.balance_status.DELIVERY_SHAPES``. A claim about
                        # DELIVERY and never about worth: two demonstrably real
                        # tokens on this corpus are airdrop-delivered (uniETH at
                        # fan-out 101, HEX at 199/399/399), so ``fan_out_all`` says
                        # every delivery on record was a mass distribution and says
                        # nothing at all about what the holding is worth.
                        #
                        # The row is PUBLISHED under every shape, and this shape ALONE
                        # withholds nothing: HEX, WETH and base USDC are all
                        # airdrop-delivered on this corpus and all real holdings. The
                        # withholding predicate is ``disposition_state`` below.
                        "delivery_shape": delivery_shape,
                        # The evidence row's own basis string, carried verbatim so a
                        # consumer quoting the scope quotes the carrier. ``None``
                        # where no evidence row exists, which is what
                        # ``not_determined`` means here.
                        "delivery_shape_basis": (fact.basis if fact is not None else None),
                        # Whether this token was found in the protocol's own discovered
                        # universe, one of ``utils.balance_status.TOKEN_REFERENCE_SHAPES``,
                        # read off the last verdict the producer measured. A pair with
                        # no stored row is ``not_determined`` and therefore stays a
                        # presented holding.
                        "reference_shape": reference_shape,
                        # The published verdict, so no consumer has to re-derive the
                        # conjunction (and get it wrong): ``disposed`` only where all
                        # three conjuncts hold, ``presented`` otherwise. The row is
                        # here either way — a disposed row is withheld from the
                        # holdings CLAIM, never from the record.
                        "disposition_state": ("disposed" if disposed else "presented"),
                    }
                )
                # Delivery shape does NOT gate this sum. A priced holding is a real
                # dollar figure whatever the shape of its arrival, and dropping one
                # here would publish a total lower than the money that was measured.
                # It costs nothing on today's data — every ``fan_out_all`` reading in
                # the census is unpriced and already contributes $0 — but the reason
                # it is not gated is the invariant, not the coincidence.
                if usd:
                    total_usd += usd
        # Whether this contract's holdings list is the whole set. There is no
        # ``complete`` member ON PURPOSE, and the witness is the FETCH's recorded
        # ``asset_set_status``, never a length. The fetch pages the endpoint to
        # exhaustion and the stored list routinely exceeds
        # ``TOKEN_BALANCE_PAGE_SIZE`` without having been cut off at all, so
        # comparing its length to the cap read a complete list as a truncated one.
        # ``at_page_cap`` is the producer's own statement that what it stored is a
        # prefix, and it is the only positive statement available — the other arm is
        # not-determined, never "whole".
        holdings_coverage = {
            "rows": len(balances_list),
            "page_cap": TOKEN_BALANCE_PAGE_SIZE,
            "state": ("may_be_incomplete" if at_page_cap else "not_determined"),
            # Rows inside the stored set whose USD value was never determined.
            # ``total_usd`` skips them, so any non-zero total is a lower bound
            # whenever this is non-zero — independently of truncation.
            "unvalued_rows": unvalued_rows,
            # Rows every recorded delivery of which was a mass distribution. A NAMED
            # count, published as a zero when there are none. It is a DELIVERY count
            # and not an exclusion count — the two differ by every real token the
            # protocol was airdropped, which on this corpus is 39 rows of HEX, WETH
            # and base USDC.
            "airdrop_delivered_rows": airdrop_delivered_rows,
            # Rows actually withheld from the holdings claim: airdrop-delivered AND
            # absent from the protocol's own universe AND unpriced. Always
            # ``<= airdrop_delivered_rows``. Published so a consumer reads the
            # exclusion off the payload instead of inferring it from rows that are
            # present but not presented.
            "disposed_rows": disposed_rows,
            "delivery_shape_reading": (
                "delivery_shape states how a balance ARRIVED and never what it is worth, and it "
                "withholds nothing on its own — real tokens are airdropped too (HEX, WETH, USDC "
                "on this corpus). A row is withheld from the holdings claim only when it is "
                "fan_out_all AND absent from the protocol's discovered universe AND unpriced; "
                "read disposition_state per row. Withheld rows are kept and labelled, never removed"
            ),
        }

        entry: dict[str, Any] = {
            # Canonical lowercase: node ids and selection keys downstream
            # assume one form, but a legacy job row can hold a checksummed
            # address (ingress normalizes only since the AnalyzeRequest
            # validator landed).
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
            # Never a proven-complete count: it is an upper bound whose coverage
            # (how many of the events carry a receipt fact, how many proven
            # deployments were removed) is stated rather than implied, together
            # with the three refusals — signer set, decoy verdict, and whether
            # the recording surface saw everything — that this plane cannot
            # answer at all.
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
            # Which route a ``None`` on the three flags above took: ``absent``
            # means no ContractSummary row exists for this entry (nor for its
            # implementation), ``present`` means the row exists and the column
            # itself is NULL. Never omitted, so key-absence marks a pre-fix
            # payload rather than either state.
            "summary_evidence": "present" if summary_row is not None else "absent",
            "capabilities": capabilities,
            "balances": balances_list,
            "total_usd": round(total_usd, 2) if total_usd > 0 else None,
            "holdings_coverage": holdings_coverage,
        }

        graph_contract = lookup_contract or contract_row
        if graph_contract:
            cg_nodes = cgn_by_cid.get(graph_contract.id, [])
            cg_edges = cge_by_cid.get(graph_contract.id, [])
            node_meta = {n.address: _principal_lookup_meta(principal_lookup, n.address, n.details) for n in cg_nodes}
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
            owner_groups.setdefault(owner, []).append(entry)

    # Deduplicate: remove standalone impl contracts already represented via a
    # proxy — both the EIP-1967 impl and any split-proxy secondary impls (the
    # latter were analysed standalone in older runs). Keyed by the composite
    # entity token (a proxy's impl is on the proxy's own chain) so a same-address
    # standalone on ANOTHER chain isn't collapsed away.
    impl_entities = {_entity_key(c.get("chain"), c["implementation"]) for c in contracts if c.get("implementation")}
    for c in contracts:
        for saddr in c.get("secondary_implementations") or []:
            impl_entities.add(_entity_key(c.get("chain"), saddr))
    contracts = [
        c
        for c in contracts
        if not c["address"] or _entity_key(c.get("chain"), c["address"]) not in impl_entities or c["is_proxy"]
    ]

    remaining_addrs = {c["address"] for c in contracts if c["address"]}
    for owner_addr in list(owner_groups):
        owner_groups[owner_addr] = [e for e in owner_groups[owner_addr] if e["address"] in remaining_addrs]
        if not owner_groups[owner_addr]:
            del owner_groups[owner_addr]

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
    )

    # Reshape FP-by-contract-id into FP-by-contract-address so each principal
    # gets a ``primary_for`` list — the contracts it canonically governs,
    # consumed by Surface group containment (see
    # ``services.governance.primary_controller``). Two transforms make this
    # correct across protocols, not just for directly-Safe-owned contracts:
    #
    #   1. Proxy→impl keying. EffectiveFunction / FunctionPrincipal rows live
    #      on the *implementation* contract, but the canvas renders and groups
    #      by the *proxy* address. Map impl→proxy so a principal's primary_for
    #      lands on the address the frontend actually draws; without this every
    #      proxied contract silently drops out of all groups.
    #
    #   2. Governance pass-through. When a protocol is governed via an
    #      in-protocol Timelock / ProxyAdmin, the governed contracts' direct FP
    #      caller resolves to that governance contract — which is itself
    #      in-protocol and therefore never a principal. We hand the set of such
    #      contracts to ``assign_primary_controllers`` so it resolves authority
    #      one hop further, to the terminal Safe/EOA. Only FP (call-authority)
    #      edges are followed, so fund-destination Safes (which hold no FP row)
    #      cannot be re-introduced.
    # cid → the composite entity token of the contract's OWN (chain, address).
    # The whole attribution fold below stays in composite-entity space so a
    # same-address twin on another chain never merges into this chain's
    # authority sets: two standalone CREATE2 twins render to distinct
    # ``<chain>::<address>`` keys, so ``assign_primary_controllers`` runs a
    # separate contest per chain. The per-principal OUTPUT fields (primary_for /
    # co_controls / controls_detail / other_callers) are rendered back to BARE
    # addresses at the landing points — the frontend composes those with the
    # active chain (site/src/surface/layout/elkLayout.js), so the serialized
    # values must stay bare.
    contract_entity_by_cid: dict[int, str] = {
        c.id: _entity_key(c.chain, c.address) for c in contracts_by_job_id.values() if c is not None and c.address
    }
    impl_entity_to_proxy_entity: dict[str, str] = {}
    for c in contracts:
        if not (c.get("is_proxy") and c.get("address")):
            continue
        # An impl renders under its proxy only on the proxy's own chain.
        proxy_entity = _entity_key(c.get("chain"), c["address"])
        if c.get("implementation"):
            impl_entity_to_proxy_entity[_entity_key(c.get("chain"), c["implementation"])] = proxy_entity
        # Secondary impls render under the proxy too, so their FunctionPrincipal
        # authority (e.g. a governor over admin functions) attributes here.
        for saddr in c.get("secondary_implementations") or []:
            impl_entity_to_proxy_entity[_entity_key(c.get("chain"), saddr)] = proxy_entity

    def _rendered_entity(cid: int) -> str | None:
        own_entity = contract_entity_by_cid.get(cid)
        if not own_entity:
            return None
        # Fold onto the proxy (its own chain) if this cid is a proxy's impl; else
        # render under the contract's own entity.
        return impl_entity_to_proxy_entity.get(own_entity) or own_entity

    # ``{contract_entity: {caller_entity}}`` — the FP authority graph the
    # primary-controller contest walks. Callers are composited with the chain of
    # the contract they call (a caller and its target are always same-chain), so
    # an in-protocol governance contract is one node whether it appears as a
    # contract key or as a passthrough caller — the graph stays connected.
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
        if principal_lookup.get(_entity_addr(entity), {}).get("resolved_type") in _PASSTHROUGH_CONTROLLER_TYPES
    }
    # Bare-address mirror for the caller_detail capability walk below, whose inner
    # caller keys stay bare addresses.
    governance_passthrough_addrs = {_entity_addr(e) for e in governance_passthrough}

    # Per-function caller/labels/claims rows keyed to the rendered (proxy)
    # address — same keying as the FP graph above. Feeds the primary contest
    # (authority-tier ranking + veto gating), the co-controller rule, and the
    # per-(controller, contract) capability detail below.
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

    # Co-controllers: principals holding real (privileged or tightly-gated)
    # authority on a contract they lost the primary contest for. Surfaced as
    # their own guardian-rail nodes (not group containers) and enrolled in
    # monitoring, so a pause / fund-recovery guardian Safe isn't invisible just
    # because a bigger governance Safe won the same contracts. See
    # ``services.governance.primary_controller.assign_co_controllers``.
    co_controls = assign_co_controllers(principals, fp_function_detail_by_entity, primary_for)

    # Rendering home for machinery contracts whose operand unit lives in
    # another principal's group — passthrough timelocks (etherfi's 2d operating
    # timelock: driven by the ops Safe, acting entirely on the core-governance
    # box), Pauser fan-outs, single-target bridge receivers. Published as
    # ``grouped_with`` on the machinery's contract entry; the frontend group
    # assignment honors it as a placement override while ``primary_for`` —
    # enrollment, accordion, every authority claim — still names the true
    # controller. See ``assign_operand_render_groups``.
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
                entry["grouped_with"] = gw

    principal_meta = {(p.get("address") or "").lower(): p for p in principals if p.get("address")}

    # Per-(controller, contract) capability detail: the concrete functions — and
    # effect-category tags — each FP caller can actually invoke. Lets the canvas
    # show "pause · recover" instead of a generic "controlled", from verified
    # call rights (FunctionPrincipal), not the CGN-derived ``controls`` list.
    # ``caller_detail[contract_entity][caller_lc] = {functions, labels}`` — the
    # contract key is the composite ``<chain>::<address>`` entity (so twins stay
    # separate), the caller key a bare address. EVERY FP caller is kept here,
    # including in-protocol governance *contracts* (timelocks / proxy-admins) —
    # they're the passthrough hop a governance Safe reaches its contracts
    # through, so the capability resolution below needs them. Non-principal
    # callers are filtered out at the consumption points.
    caller_detail: dict[str, dict[str, dict[str, set[str]]]] = {}
    for caddr, functions in fp_function_detail_by_entity.items():
        for fn in functions:
            fname = fn.get("function")
            # Capability chips are computed per function (claims-first) then
            # unioned, so the claims-vs-legacy choice stays per-function.
            fn_caps = _function_capabilities(fn.get("labels") or (), fn.get("claims") or ())
            for a in fn.get("callers", ()):
                la = (a or "").lower()
                if not la:
                    continue
                detail = caller_detail.setdefault(caddr, {}).setdefault(la, {"functions": set(), "capabilities": set()})
                if fname:
                    detail["functions"].add(fname)
                detail["capabilities"].update(fn_caps)

    # Invert to per-principal: the contracts it can call, with functions +
    # capability tags. Drives the sidebar "Can Call" and the on-select chips for
    # BOTH co-controllers and primaries. Two sources merged:
    #   1. Direct FP authority (caller_detail).
    #   2. Passthrough — capabilities held via an in-protocol governance
    #      contract (timelock / proxy-admin) the principal controls, the same
    #      hop assign_primary_controllers used to award primary_for. Without
    #      this the governance Safe that acts only through its timelock would
    #      show no capabilities on the 20 contracts it governs (just
    #      "controlled"). One hop — covers Safe → Timelock → contracts.
    detail_acc: dict[str, dict[str, dict[str, set[str]]]] = {}

    def _accumulate(principal_lc: str, contract_lc: str, src: dict[str, set[str]]) -> None:
        slot = detail_acc.setdefault(principal_lc, {}).setdefault(
            contract_lc, {"functions": set(), "capabilities": set()}
        )
        slot["functions"].update(src.get("functions", ()))
        slot["capabilities"].update(src.get("capabilities", ()))

    # detail_acc keys: principal (bare address) → contract (composite entity).
    for caddr, callers_map in caller_detail.items():
        for la, detail in callers_map.items():
            if la in principal_meta:  # direct rights belong to principals, not contract callers
                _accumulate(la, caddr, detail)
    for la, owned in primary_for.items():
        for caddr in owned:
            # The governance contract's own entity shares the governed contract's
            # chain (control is intra-chain), so rebuild it from the bare caller.
            caddr_chain = _entity_chain(caddr)
            for gov_addr, gov_detail in caller_detail.get(caddr, {}).items():
                gov_entity = _entity_key(caddr_chain, gov_addr)
                if gov_addr in governance_passthrough_addrs and la in caller_detail.get(gov_entity, {}):
                    _accumulate(la, caddr, gov_detail)

    detail_by_principal: dict[str, list[dict[str, Any]]] = {}
    for la, by_contract in detail_acc.items():
        # Render the contract entity back to a bare address for the payload.
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
        # primary_for / co_controls carry composite contract entities internally;
        # the serialized fields are bare addresses (the frontend re-composes them
        # with the active chain).
        p["primary_for"] = sorted({_entity_addr(e) for e in primary_for.get(p_addr_lc, [])})
        p["co_controls"] = sorted({_entity_addr(e) for e in co_controls.get(p_addr_lc, [])})
        # The chains the flattening above discards, kept as their own field:
        # the per-chain contests already ran, so the set of chains this
        # principal won or co-controls ON is a computed fact — enrollment needs
        # it to put a controller's MonitoredContract row on the chain of the
        # contracts it governs instead of a caller-supplied default.
        p["controls_chains"] = sorted(
            {_entity_chain(e) for e in primary_for.get(p_addr_lc, [])}
            | {_entity_chain(e) for e in co_controls.get(p_addr_lc, [])}
        )
        p["controls_detail"] = detail_by_principal.get(p_addr_lc, [])

    # Per-edge ``capabilities``: what THE SOURCE can do to THE TARGET, from
    # the same FunctionPrincipal-derived machinery that feeds
    # ``controls_detail`` — so an edge chip and the principal's own detail
    # panel can never disagree about the same (source, target) pair.
    # ``detail_acc`` (principal sources; includes the one-hop governance
    # passthrough) is consulted first, then ``caller_detail`` (contract
    # sources with direct FP rights). A source with no witnessed rights on
    # the target publishes ``[]`` — same convention as the contract-level
    # list: a capability chip is a positive claim, and its absence is not
    # published as proof of inability (the edge itself still states the
    # ownership/controller relationship via ``type``).
    for flow in fund_flows:
        src_lc = (flow.get("from") or "").lower()
        target_entity = _entity_key(flow.get("to_chain"), flow.get("to"))
        detail = detail_acc.get(src_lc, {}).get(target_entity)
        if detail is None:
            detail = caller_detail.get(target_entity, {}).get(src_lc)
        flow["capabilities"] = sorted(detail["capabilities"]) if detail else []

    # Per-contract "other callers": principal-callers holding FP authority that
    # are neither the contract's primary owner nor a co-controller of it — the
    # permissionless / lower-privilege long tail (e.g. AuctionManager's
    # whitelisted ``createBid`` bidders). The canvas renders these in aggregate
    # as a "+N callers" affordance per contract, so an authorized caller is
    # never silently invisible, without drawing 30+ cross-group edges or minting
    # a node per bidder. Each carries its own functions / capabilities so the
    # sidebar list says what each caller can do. Restricted to FP-typed
    # principals, so state-variable destinations / CGN noise don't leak in.
    # Keyed by composite contract entity (primary_for / co_controls carry those);
    # the principal values stay bare addresses.
    primary_by_contract: dict[str, str] = {c: paddr for paddr, owned in primary_for.items() for c in owned}
    co_by_contract: dict[str, set[str]] = {}
    for paddr, owned in co_controls.items():
        for c in owned:
            co_by_contract.setdefault(c, set()).add(paddr)
    for entry in contracts:
        addr = (entry.get("address") or "").lower()
        entity = _entity_key(entry.get("chain"), addr)
        cd = caller_detail.get(entity, {})
        callers = {a for a in cd if a in principal_meta}  # contract callers aren't "other callers"
        callers.discard(addr)
        callers.discard(primary_by_contract.get(entity, ""))
        callers -= co_by_contract.get(entity, set())
        entry["other_callers"] = [
            {
                "address": a,
                "type": (principal_meta.get(a) or {}).get("type"),
                "label": (principal_meta.get(a) or {}).get("label"),
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
    hierarchy: list[dict[str, Any]] = []
    assigned: set[str | None] = set()
    for owner_addr, owned in sorted(owner_groups.items(), key=lambda x: -len(x[1])):
        owner_contract = next((c for c in contracts if c["address"] and c["address"].lower() == owner_addr), None)
        hierarchy.append(
            {
                "owner": owner_addr,
                "owner_name": owner_contract["name"] if owner_contract else None,
                "owner_is_contract": owner_contract is not None,
                "contracts": [{"address": c["address"], "name": c["name"]} for c in owned],
            }
        )
        assigned.update(c["address"] for c in owned)

    unowned = [c for c in contracts if c["address"] not in assigned]
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
    """The control edges the scorer's closure walks, protocol-wide.

    DISPLAY EDGES ONLY: each row is a witnessed relation the frontend draws
    and names, never a transitive claim. The reach *claims* — walked /
    not_determined / absent, per entity — travel in the top-level ``reach``
    block (:mod:`services.scoring.reach`), which is the scorer's own verdict
    per hop; nothing here says any path along these edges is established.

    Mirrors ``services.scoring.planes.load_control_closure`` exactly: every
    ``ControlGraphEdge`` row of the protocol whose relation is in
    ``SCORER_REACH_RELATIONS`` (reversed to authority direction), plus the
    ``Contract.admin`` AND ``Contract.beacon`` column pairs — the two column
    witnesses the loader admits, kept in step here so the surface graph cannot
    route a path the score document does not hold, or miss one it does.
    Deliberately NOT restricted to the
    contracts that make this payload's list — the scorer isn't either, so a
    score-document reach can route through an implementation or an orphaned
    contract row this page never renders, and the surface graph must carry
    those hops to route the path. Rows are ``(chain_tok, holder, subject,
    relation, label)``; admin pairs carry ``relation=None`` (the column is the
    witness — inventing a relation name for it would overclaim).

    ``safe_owner`` and ``capability_principal`` witnesses never appear here:
    the scorer excludes both from reach, and admitting them would draw routes
    the score document does not vouch for. Zero-address ends are skipped —
    a renounced owner holds nothing, and no host-seeded path routes through
    the zero address.
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
    cge_by_cid: dict[int, list[ControlGraphEdge]],
    reach_edges: Iterable[tuple[str, str, str, str | None, str | None]] = (),
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """``(chain, flow_from, flow_to)`` → the witnessed claims on that control edge.

    A ``control_graph_edges`` row is written subject-first: ``from_node_id`` is
    the contract the row was recorded against and ``to_node_id`` the related
    address, and for the relations in ``CONTROL_EDGE_RELATIONS`` that reads
    "the to-node has authority over the from-node" (see ``db.models``). A
    fund-flow control edge runs the other way — authority holder → contract —
    so rows are indexed reversed. Only those relations are indexed: reversing
    an ``external_call_target`` would assert an authority nobody proved.

    ``reach_edges`` (from :func:`_protocol_reach_edges`) contributes the same
    claims for pairs whose carrying row lives on a contract outside this
    payload — an edge admitted from that plane must be nameable too.

    One pair can carry several distinct claims at once (a Teller both holds
    ``roles 2,3`` on a vault and is its ``hook`` controller-value). Collapsing
    them to one would publish an arbitrary pick, so the single-claim case gets
    the scalar ``relation`` / ``label`` and the multi-claim case gets the whole
    witnessed set as ``relations``. A pair with no control-graph row at all gets
    neither, and the edge is published with its flow type alone.
    """
    claims: dict[tuple[str, str, str], set[tuple[str, str | None]]] = {}
    for entry in contracts:
        if not entry.get("address"):
            continue
        lookup_c = lookup_contract_by_entity.get(_entity_key(entry.get("chain"), entry["address"]))
        if not lookup_c:
            continue
        chain_tok = _coalesce_chain(entry.get("chain"))
        for edge in cge_by_cid.get(lookup_c.id, []):
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
    controller_values_by_cid: dict[int, list[ControllerValue]],
    fp_governance_by_cid: dict[int, list[dict[str, Any]]],
    cgn_by_cid: dict[int, list[ControlGraphNode]],
    cge_by_cid: dict[int, list[ControlGraphEdge]],
    fp_in_contract_by_cid: dict[int, set[str]],
    fp_all_addrs_by_cid: dict[int, set[str]],
    principal_lookup: dict[str, dict[str, Any]],
    reach_edges: list[tuple[str, str, str, str | None, str | None]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    contract_addrs = {c["address"].lower() for c in contracts if c["address"]}
    # Control relations are intra-chain, so every flow carries a single chain
    # (from_chain == to_chain). Dedup is per-chain so a same-address twin on
    # another chain keeps its own edge instead of colliding on the bare pair.
    flow_seen: set[tuple[str, str, str]] = set()
    fund_flows: list[dict[str, Any]] = []
    # Filled once the contract→Contract lookup exists (below), before the first
    # add_flow call. Absent keys are the normal case: an edge the control graph
    # never witnessed a relation for carries no relation/label at all.
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
                # Additive, and present only where a control-graph row witnesses
                # this exact pair (see _control_edge_witness) — the frontend's
                # reach-path inspector names the hop's relation/role from it and
                # shows the type alone when it is absent.
                **edge_witness.get(key, {}),
                # Filled by build_governance_view once caller_detail exists:
                # the SOURCE's witnessed rights on the target, never the
                # target's own capability union — an edge is a claim about the
                # relationship, and the frontend renders it as a per-edge chip.
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

    # Keyed by composite ``<chain>::<address>`` entity, not bare address: two
    # standalone twins share an address, so a bare key would resolve both to one
    # chain's Contract row and collapse the other chain's principals.
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
        lookup_c = lookup_contract_by_entity.get(_entity_key(chain, target))
        # In-protocol contract addresses that hold actual call authority
        # on this target's EffectiveFunctions. Same authoritative signal
        # (FunctionPrincipal) drives both the controller-flow gate and
        # the principal-flow emit below.
        fp_principals: set[str] = fp_in_contract_by_cid.get(lookup_c.id, set()) if lookup_c else set()

        if c.get("owner") and c["owner"] in contract_addrs:
            flow_type = (
                "controls_value"
                if any(e in c.get("value_effects", []) for e in ("asset_pull", "asset_send"))
                else "controls"
            )
            add_flow(c["owner"], target, flow_type, chain)

        # The ``controllers`` dict at the contract entry is populated
        # unfiltered from every tracked address-typed ControllerValue
        # row, which includes integration/composability references
        # (``weth``, ``oracle``, ``treasury``, ``swapRouter``, ``stEth``)
        # alongside real authorizers. Emitting type=controller for the
        # former asserts a control relationship that doesn't exist.
        # Gate on FunctionPrincipal membership so only CV values that
        # the capability resolver also identified as call-authority
        # principals produce a controller flow.
        for cid, val in c.get("controllers", {}).items():
            if isinstance(val, str) and val.startswith("0x"):
                val_lower = val.lower()
                if val_lower in contract_addrs and val_lower != (c.get("owner") or "") and val_lower in fp_principals:
                    add_flow(val_lower, target, "controller", chain)

        # In-protocol contract principals come from FunctionPrincipal —
        # the per-function access-control record produced by the
        # capability resolver. A bare ControlGraphNode match used to
        # drive this and over-reported transitive lineage (e.g. a token
        # mid-chain like ``WithdrawalQueueERC721 -> WstETH -> Lido stETH``
        # was flagged as a principal of every EtherFi contract whose
        # graph traversed it). FP is the authoritative signal: an
        # address only appears here if it can actually call a function.
        if lookup_c:
            for node_addr in fp_principals:
                if not node_addr or node_addr == target:
                    continue
                if node_addr not in contract_addrs:
                    continue
                add_flow(node_addr, target, "principal", chain)

    # Collect non-contract principals from control graph + function principals.
    # First pass: find safe_owner edges so we can nest Safe owners later.
    principal_map: dict[str, dict[str, Any]] = {}
    safe_owners_map: dict[str, list[str]] = {}
    owner_of_safe: set[str] = set()

    for c in contracts:
        if not c["address"]:
            continue
        lookup_c = lookup_contract_by_entity.get(_entity_key(c.get("chain"), c["address"]))
        if not lookup_c:
            continue
        for edge in cge_by_cid.get(lookup_c.id, []):
            if edge.relation != "safe_owner":
                continue
            safe_addr = edge.from_node_id.replace("address:", "").lower()
            owner_addr = edge.to_node_id.replace("address:", "").lower()
            safe_owners_map.setdefault(safe_addr, [])
            if owner_addr not in safe_owners_map[safe_addr]:
                safe_owners_map[safe_addr].append(owner_addr)
            owner_of_safe.add(owner_addr)

    # Second pass: collect direct controllers (skip Safe owners — they're nested)
    for c in contracts:
        if not c["address"]:
            continue
        target = c["address"].lower()
        chain = c.get("chain")
        lookup_c = lookup_contract_by_entity.get(_entity_key(chain, target))
        if not lookup_c:
            continue

        for cgn in cgn_by_cid.get(lookup_c.id, []):
            node_addr = (cgn.address or "").lower()
            if not node_addr or node_addr in contract_addrs:
                continue
            if node_addr in owner_of_safe:
                continue
            lookup_meta = principal_lookup.get(node_addr, {})
            resolved_type = lookup_meta.get("resolved_type") or cgn.resolved_type
            if resolved_type not in _SETTLED_CONTROLLER_TYPES:
                continue
            if node_addr == "0x0000000000000000000000000000000000000000":
                continue
            # Gate on FunctionPrincipal authority: a safe/eoa/timelock/
            # proxy_admin CGN node earns a principal + controls edge only if it
            # can actually call a function on this contract. Without it, a
            # zero-authority beneficiary stored in a state var (treasury /
            # feeRecipient / _owner / payoutAddress) becomes a spurious
            # principal claiming control it doesn't hold. Mirrors the
            # controller-flow gate above and the FP third pass below;
            # cgn_by_cid and fp_all_addrs_by_cid are both keyed by lookup_c.id.
            if node_addr not in fp_all_addrs_by_cid.get(lookup_c.id, set()):
                continue

            if node_addr not in principal_map:
                # Seed details with the CGN's own introspection result
                # (getOwners/getThreshold for safes, getMinDelay for
                # timelocks). This is the authoritative source for the
                # principal's intrinsic config — ControllerValue rows
                # describe the relationship FROM a consumer, not the
                # Safe's own threshold, so prior code that only merged
                # CV details missed the threshold and fell back to
                # len(owners).
                details: dict[str, Any] = dict(lookup_meta.get("details") or {})
                if isinstance(cgn.details, dict):
                    details.update(cgn.details)
                for cv in controller_values_by_cid.get(lookup_c.id, []):
                    if (cv.value or "").lower() != node_addr:
                        continue
                    if cv.details and isinstance(cv.details, dict):
                        for k, v in cv.details.items():
                            details.setdefault(k, v)

                if resolved_type == "safe":
                    if not details.get("owners"):
                        details["owners"] = safe_owners_map.get(node_addr, [])
                    if "threshold" not in details and details.get("owners"):
                        details["threshold"] = len(details["owners"])

                principal_map[node_addr] = {
                    "address": node_addr,
                    "type": resolved_type,
                    "label": lookup_meta.get("label") or cgn.contract_name or cgn.label or resolved_type,
                    "details": details,
                    "controls": [],
                    "chains": set(),
                }

            principal_map[node_addr]["controls"].append(target)
            principal_map[node_addr]["chains"].add(_coalesce_chain(chain))
            add_flow(node_addr, target, "principal", chain)

    # Third pass: pull principals out of FunctionPrincipal rows. Some
    # role-gated functions (e.g. EtherFiTimelock.cancel / .execute) have
    # their controlling Safe/EOA stored *only* on the per-function
    # principal row — the Safe never gets a top-level ControlGraphNode
    # entry for that contract, so the prior CGN-only pass misses the
    # Safe→Contract edge entirely. This pass backfills, reading from the
    # narrow ``fp_governance_rows`` projection (already filtered to
    # safe/timelock/eoa/proxy_admin) instead of walking full EF rows.
    for c in contracts:
        if not c["address"]:
            continue
        target = c["address"].lower()
        chain = c.get("chain")
        lookup_c = lookup_contract_by_entity.get(_entity_key(chain, target))
        if not lookup_c:
            continue
        for fp in fp_governance_by_cid.get(lookup_c.id, []):
            pa = (fp.get("address") or "").lower()
            if not pa or pa == target:
                continue
            if pa == "0x0000000000000000000000000000000000000000":
                continue
            if pa in owner_of_safe:
                continue
            lookup_meta = principal_lookup.get(pa, {})
            resolved_type = fp.get("resolved_type")
            if lookup_meta.get("resolved_type") and resolved_type in (None, "", "unknown", "contract"):
                resolved_type = lookup_meta["resolved_type"]
            if resolved_type not in _SETTLED_CONTROLLER_TYPES:
                continue
            if pa in contract_addrs:
                continue
            if pa not in principal_map:
                fp_details = dict(lookup_meta.get("details") or {})
                fp_raw_details = fp.get("details")
                if isinstance(fp_raw_details, dict):
                    fp_details.update(fp_raw_details)
                if resolved_type == "safe":
                    if not fp_details.get("owners"):
                        fp_details["owners"] = safe_owners_map.get(pa, [])
                    if "threshold" not in fp_details and fp_details.get("owners"):
                        fp_details["threshold"] = len(fp_details["owners"])
                principal_map[pa] = {
                    "address": pa,
                    "type": resolved_type,
                    "label": lookup_meta.get("label") or resolved_type,
                    "details": fp_details,
                    "controls": [],
                    "chains": set(),
                }
            if target not in principal_map[pa]["controls"]:
                principal_map[pa]["controls"].append(target)
            principal_map[pa]["chains"].add(_coalesce_chain(chain))
            add_flow(pa, target, "principal", chain)

    # The authority edges the scorer's control closure walks (see
    # _protocol_reach_edges), carried verbatim: the score document publishes
    # reach over exactly these pairs, and one this graph drops is a route the
    # frontend can only report as "not carried". No holder gate — the closure
    # routes through whatever the witnessed rows name, including a
    # RolesAuthority that gates functions without ever being a
    # FunctionPrincipal, an implementation row the page does not render, and
    # contracts never enrolled in the inventory at all. The relations admitted
    # here all carry established authority provenance (an unattributed value
    # lands on controller_value_unattributed, which neither the scorer nor
    # this pass walks), so a beneficiary state-var cannot ride in — and the
    # FP-gated passes stay authoritative for which addresses become principal
    # CARDS; this pass emits edges only. It runs LAST so add_flow's
    # first-writer-wins dedup lets every pass above keep its richer type
    # (``principal``, gate-derived ``controller``) — reach edges only fill
    # pairs no other witness emitted.
    for chain_tok, holder, subject, _relation, _label in reach_edges:
        add_flow(holder, subject, "controller", chain_tok)

    # ``chains`` accumulates as a set during collection (a principal may govern
    # on several chains); the payload carries a sorted list. It stays additive —
    # a single-chain protocol reports ``["ethereum"]`` and nothing else moves.
    principals_out = list(principal_map.values())
    for pr in principals_out:
        pr["chains"] = sorted(pr["chains"])
    return fund_flows, principals_out
