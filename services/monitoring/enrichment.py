"""Enrichment: add decoded fields to published monitored events.

Rules: enrichment only adds ``data`` keys (never ``event_type``, ``witness_tier``, or whether a row exists); derived
fields are either witnessed facts or labeled heuristics under ``data.heuristics``; an incomplete decode publishes a
``status``, and an absent block means enrichment didn't run; failures are never fatal; historical rows are never
enriched.

Per chain: registered enrichers (Safe ``execTransaction`` decode, MultiSend expansion, selector -> signature), a
salience recompute, then the zero-RPC same-transaction correlation join and another recompute. Recomputing inside the
window transaction, before commit, means the notifier and frontend only see post-enrichment levels.

``_SAFE_MULTISEND_ADDRESSES`` is vendored from ``safe-global/safe-deployments`` (v1.3.0 and v1.4.1 multi_send and
multi_send_call_only). An address not on it is not proven to be MultiSend, which raises the level rather than lowering
it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from db.models import Contract, EffectiveFunction, MonitoredContract, MonitoredEvent
from services.clients.rpc import rpc_batch_request_classified
from services.monitoring.salience import (
    DATA_KEY_CORRELATED_EVENTS,
    SAFE_EXEC_BATCH_UNDECODABLE,
    SAFE_EXEC_KEY_MULTISEND_RECOGNIZED,
    SAFE_EXEC_STATUS_AMBIGUOUS_ATTRIBUTION,
    SAFE_EXEC_STATUS_ARGS_UNDECODABLE,
    SAFE_EXEC_STATUS_DECODED,
    SAFE_EXEC_STATUS_NOT_TOP_LEVEL,
    SAFE_EXEC_STATUS_OVER_BUDGET,
    stamp_salience,
)
from services.static.claims.context import abi_selector
from services.static.claims.matchers._gates import SAFE_EXEC_TRANSACTION
from utils.chains import chain_by_name

logger = logging.getLogger(__name__)

# Read via ``unified_watcher._scan_int_env``; declared here with the code that spends it.
ENRICH_TX_BUDGET_ENV = "PSAT_SCAN_MAX_ENRICH_TX_PER_PASS"
DEFAULT_MAX_ENRICH_TX_PER_PASS = 50

# Lower-cased at declaration. zkSync-variant addresses are excluded: on chains we scan they'd be unknown contracts.
_SAFE_MULTISEND_ADDRESSES: frozenset[str] = frozenset(
    address.lower()
    for address in (
        # v1.3.0 multi_send.json
        "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761",  # canonical
        "0x998739BFdAAdde7C933B942a68053933098f9EDa",  # eip155
        # v1.3.0 multi_send_call_only.json
        "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D",  # canonical
        "0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B",  # eip155
        # v1.4.1 multi_send.json / multi_send_call_only.json
        "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526",
        "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
    )
)

# Hashed from the signature, not transcribed.
MULTISEND_SELECTOR = abi_selector("multiSend(bytes)")  # 0x8d80ff0a

# Nested MultiSends are real calls worth showing; the cap stops adversarial depth from eating the window transaction.
# Exceeding it is a stated gap.
MAX_MULTISEND_DEPTH = 3

# Safe ``execTransaction`` args; ``Enum.Operation`` is ``uint8``.
_EXEC_TRANSACTION_ARG_TYPES = [
    "address",
    "uint256",
    "bytes",
    "uint8",
    "uint256",
    "uint256",
    "uint256",
    "address",
    "address",
    "bytes",
]

_OPERATION_CALL = 0
_OPERATION_DELEGATECALL = 1
_OPERATION_LABELS = {_OPERATION_CALL: "call", _OPERATION_DELEGATECALL: "delegatecall"}

# Why a batch wasn't expanded; changes no level, and no partial list is ever published.
BATCH_REASON_MALFORMED = "malformed_payload"
BATCH_REASON_NESTED_UNDECODABLE = "nested_payload_undecodable"
BATCH_REASON_DEPTH_EXCEEDED = "nested_depth_exceeded"

# Empty ``correlated_events`` means no monitored contract emitted in the tx, not that the execution had no effect.
CORRELATED_SCOPE_MONITORED_ONLY = "monitored_only"

# Cause-side families in a same-transaction join. The registry decides direction, not log order (``ExecutionSuccess`` is
# emitted after its calls).
_CAUSE_EVENT_TYPES = frozenset(
    {
        "safe_tx_executed",
        "safe_tx_failed",
        "safe_module_executed",
        "safe_module_failed",
        "timelock_scheduled",
        "timelock_executed",
    }
)

_SIGNATURE_SOURCE_EFFECTIVE_FUNCTIONS = "effective_functions"


@dataclass(frozen=True)
class EnrichmentContext:
    """What an enricher may read besides its own event.

    A hash missing from ``txs`` was not fetched (failed or over budget), never proof the transaction doesn't exist.
    ``contested`` holds ``(monitored_contract_id, tx_hash)`` pairs with more than one execution row, which may not be
    attributed a single top-level call.
    """

    chain: str
    chain_id: int
    session: Session
    txs: Mapping[str, dict] = field(default_factory=dict)
    over_budget: frozenset[str] = frozenset()
    contested: frozenset[tuple[Any, str]] = frozenset()


# Returns keys to merge into ``event.data`` or ``None``; must not mutate the event (the driver merges and re-rates).
Enricher = Callable[[MonitoredEvent, MonitoredContract, EnrichmentContext], "dict[str, Any] | None"]

# event_type -> enricher; populated at the bottom of the module.
ENRICHERS: dict[str, Enricher] = {}

# Only these contribute hashes to the fetch; windows without them cost no RPC.
NEEDS_TX: frozenset[str] = frozenset()

# The closed set of keys an enricher may write (enforced, and rejections logged). ``witness_tier`` and ``historical``
# drive notification, so no decoder may write them. ``target_function`` is the timelock families' namespaced E2 block.
ENRICHABLE_KEYS: frozenset[str] = frozenset(
    {
        "safe_exec",
        "target_function",
        "correlated_events",
        "correlated_scope",
        "caused_by",
        "heuristics",
        "salience",
        "salience_basis",
    }
)


def _pass_tx_budget() -> int:
    """Transactions one pass may fetch across all chains: the budget bounds how long the open window transaction is
    held, which is per pass.
    """
    # Local import: ``unified_watcher`` imports this module.
    from services.monitoring.unified_watcher import _scan_int_env

    return max(0, _scan_int_env(ENRICH_TX_BUDGET_ENV, DEFAULT_MAX_ENRICH_TX_PER_PASS))


def _fetch_txs(
    rpc_url: str | None,
    chain_id: int,
    tx_hashes: list[str],
) -> dict[str, dict]:
    """Transaction objects for *tx_hashes*, one classified batch per chain with the URL/chain guard.

    Failed slots are simply absent ("not fetched").
    """
    if not tx_hashes:
        return {}

    if not rpc_url:
        # No endpoint: nothing fetched or declined, so these events get no block ("didn't run").
        logger.warning("Enrichment tx fetch skipped on chain %d: no RPC endpoint for the chain", chain_id)
        return {}

    results = rpc_batch_request_classified(
        rpc_url,
        [("eth_getTransactionByHash", [tx_hash]) for tx_hash in tx_hashes],
        chain_id=chain_id,
    )

    txs: dict[str, dict] = {}
    for tx_hash, (result, status) in zip(tx_hashes, results):
        # A null ``ok`` result or a failed slot leaves the hash out.
        if status == "ok" and isinstance(result, Mapping):
            txs[tx_hash] = dict(result)
    return txs


def _contested_attributions(
    session: Session,
    tx_hashes: list[str],
) -> frozenset[tuple[Any, str]]:
    """``(monitored_contract_id, tx_hash)`` pairs with more than one execution row for that contract.

    One transaction has one set of ``execTransaction`` arguments, which fits at most one of the rows, and nothing
    witnesses which; both are refused. Queried rather than read from the window so earlier windows' rows still contest.
    """
    if not tx_hashes:
        return frozenset()
    rows = session.execute(
        select(MonitoredEvent.monitored_contract_id, MonitoredEvent.tx_hash)
        .where(
            MonitoredEvent.tx_hash.in_(tx_hashes),
            MonitoredEvent.tx_hash != "",
            MonitoredEvent.event_type.in_(sorted(NEEDS_TX)),
        )
        .group_by(MonitoredEvent.monitored_contract_id, MonitoredEvent.tx_hash)
        .having(func.count() > 1)
    ).all()
    return frozenset((mc_id, tx_hash) for mc_id, tx_hash in rows)


def _normalize_address(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text.startswith("0x") or len(text) != 42:
        return None
    try:
        int(text, 16)
    except ValueError:
        return None
    return text


def _normalize_selector(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text.startswith("0x") or len(text) != 10:
        return None
    try:
        int(text, 16)
    except ValueError:
        return None
    return text


def _resolve_signatures(
    session: Session,
    chain: str,
    wanted: set[tuple[str, str]],
) -> dict[tuple[str, str], str]:
    """``(address, selector) -> abi_signature`` from targets this system analyzed itself (so witnessed, not
    third-party ABI). Ambiguous selectors stay unresolved.
    """
    if not wanted:
        return {}

    addresses = {address for address, _selector in wanted}
    selectors = {selector for _address, selector in wanted}

    rows = session.execute(
        select(Contract.address, EffectiveFunction.selector, EffectiveFunction.abi_signature)
        .join(EffectiveFunction, EffectiveFunction.contract_id == Contract.id)
        .where(
            func.lower(Contract.address).in_(addresses),
            Contract.chain == chain,
            func.lower(EffectiveFunction.selector).in_(selectors),
            EffectiveFunction.abi_signature.isnot(None),
        )
    ).all()

    candidates: dict[tuple[str, str], set[str]] = {}
    for address, selector, signature in rows:
        key = (_normalize_address(address), _normalize_selector(selector))
        if key[0] is None or key[1] is None or not signature:
            continue
        candidates.setdefault((key[0], key[1]), set()).add(signature)

    return {key: next(iter(names)) for key, names in candidates.items() if len(names) == 1}


def _function_block(selector: str | None, signature: str | None) -> dict[str, Any]:
    """The function block: raw selector always, ``signature: null`` when unresolved, and the resolving source when
    resolved.
    """
    block: dict[str, Any] = {"selector": selector, "signature": signature}
    if signature:
        block["source"] = _SIGNATURE_SOURCE_EFFECTIVE_FUNCTIONS
    return block


# (operation: 1B, to: 20B, value: 32B, dataLength: 32B, data: dataLength B)
_MULTISEND_ENTRY_HEADER = 1 + 20 + 32 + 32


def _decode_multisend(payload: bytes, depth: int = 1) -> tuple[list[dict[str, Any]] | None, str | None]:
    """``(entries, None)`` if the batch decoded whole, else ``(None, reason)``.

    Never partial, at any depth: an unexpandable inner MultiSend fails the whole batch.
    """
    if len(payload) < 4 or "0x" + payload[:4].hex() != MULTISEND_SELECTOR:
        return None, BATCH_REASON_MALFORMED

    from eth_abi.abi import decode as eth_abi_decode

    try:
        (transactions,) = eth_abi_decode(["bytes"], payload[4:])
    except Exception:
        return None, BATCH_REASON_MALFORMED
    if not isinstance(transactions, bytes):
        return None, BATCH_REASON_MALFORMED

    calls: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(transactions):
        if cursor + _MULTISEND_ENTRY_HEADER > len(transactions):
            return None, BATCH_REASON_MALFORMED
        operation = transactions[cursor]
        to = "0x" + transactions[cursor + 1 : cursor + 21].hex()
        value = int.from_bytes(transactions[cursor + 21 : cursor + 53], "big")
        data_length = int.from_bytes(transactions[cursor + 53 : cursor + 85], "big")
        start = cursor + _MULTISEND_ENTRY_HEADER
        end = start + data_length
        if end > len(transactions):
            return None, BATCH_REASON_MALFORMED
        data = transactions[start:end]
        recognized = to in _SAFE_MULTISEND_ADDRESSES
        entry: dict[str, Any] = {
            "operation": operation,
            "operation_label": _OPERATION_LABELS.get(operation),
            "to": to,
            "value": str(value),
            "selector": "0x" + data[:4].hex() if len(data) >= 4 else None,
            "data_length": len(data),
            # Set on inner calls too: an unvouched inner delegatecall raises the whole batch.
            SAFE_EXEC_KEY_MULTISEND_RECOGNIZED: recognized,
        }

        if operation == _OPERATION_DELEGATECALL and recognized:
            # Nested batch, judged by the same rules so wrapping can't hide a delegatecall.
            if depth >= MAX_MULTISEND_DEPTH:
                return None, BATCH_REASON_DEPTH_EXCEEDED
            nested, reason = _decode_multisend(data, depth + 1)
            if nested is None:
                # Name which layer failed.
                return None, BATCH_REASON_NESTED_UNDECODABLE if reason == BATCH_REASON_MALFORMED else reason
            entry["batch"] = nested

        calls.append(entry)
        cursor = end

    return calls, None


def _enrich_safe_exec(
    event: MonitoredEvent,
    mc: MonitoredContract,
    ctx: EnrichmentContext,
) -> dict[str, Any] | None:
    """Decode the ``execTransaction`` behind a ``safe_tx_executed``/``safe_tx_failed``.

    Only a transaction sent to this Safe with that selector qualifies; relayers, nested Safes and batched calls fail the
    top-level check rather than being guessed at.
    """
    tx_hash = event.tx_hash if isinstance(event.tx_hash, str) else ""
    if not tx_hash:
        return None

    if tx_hash in ctx.over_budget:
        # A recorded decline, not a finding.
        return {"safe_exec": {"status": SAFE_EXEC_STATUS_OVER_BUDGET}}

    tx = ctx.txs.get(tx_hash)
    if not isinstance(tx, Mapping):
        # Not fetched: no block, so the row stays visible as "enrichment absent".
        return None

    if "to" not in tx or not isinstance(tx.get("input"), str):
        # ``not_top_level_call`` demotes the row, so it needs both fields actually present.
        logger.warning(
            "Transaction %s carries no to/input; %s publishes no decode rather than a finding",
            tx_hash,
            mc.address,
        )
        return None

    to = _normalize_address(tx.get("to"))
    tx_input = tx["input"].lower()
    if to is None or to != mc.address.lower() or tx_input[:10] != SAFE_EXEC_TRANSACTION:
        # Includes ``to: null`` (a creation). A statement about the whole transaction, so it survives the ambiguity
        # check.
        return {"safe_exec": {"status": SAFE_EXEC_STATUS_NOT_TOP_LEVEL}}

    if (mc.id, tx_hash) in ctx.contested:
        # Several executions of this Safe in one tx share one argument set; attributing needs the nonce/EIP-712
        # recompute, over budget.
        logger.info(
            "Refusing execTransaction attribution for %s on %s: the transaction carries more than one "
            "execution of this Safe",
            mc.address,
            tx_hash,
        )
        return {"safe_exec": {"status": SAFE_EXEC_STATUS_AMBIGUOUS_ATTRIBUTION}}

    from eth_abi.abi import decode as eth_abi_decode

    try:
        args = eth_abi_decode(_EXEC_TRANSACTION_ARG_TYPES, bytes.fromhex(tx_input[10:]))
    except Exception as exc:
        logger.info(
            "execTransaction arguments did not decode for %s on %s: %s",
            mc.address,
            tx_hash,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return {"safe_exec": {"status": SAFE_EXEC_STATUS_ARGS_UNDECODABLE}}

    target = _normalize_address(args[0])
    if target is None:
        return {"safe_exec": {"status": SAFE_EXEC_STATUS_ARGS_UNDECODABLE}}
    value = int(args[1])
    data = args[2] if isinstance(args[2], bytes) else b""
    operation = int(args[3])
    gas_token = _normalize_address(args[7])
    refund_receiver = _normalize_address(args[8])

    safe_exec: dict[str, Any] = {
        "status": SAFE_EXEC_STATUS_DECODED,
        "to": target,
        "value": str(value),
        "selector": "0x" + data[:4].hex() if len(data) >= 4 else None,
        "data_length": len(data),
        "operation": operation,
        "operation_label": _OPERATION_LABELS.get(operation),
        "gas_token": gas_token,
        "refund_receiver": refund_receiver,
        SAFE_EXEC_KEY_MULTISEND_RECOGNIZED: target in _SAFE_MULTISEND_ADDRESSES,
    }

    batch: list[dict[str, Any]] | None = None
    if operation == _OPERATION_DELEGATECALL and safe_exec[SAFE_EXEC_KEY_MULTISEND_RECOGNIZED]:
        batch, reason = _decode_multisend(data)
        if batch is None:
            # Decoded whole or failure recorded, never unexamined silently.
            safe_exec["batch_status"] = SAFE_EXEC_BATCH_UNDECODABLE
            safe_exec["batch_status_reason"] = reason
        else:
            safe_exec["batch"] = batch

    _attach_signatures(ctx, safe_exec, batch)
    return {"safe_exec": safe_exec}


def _walk_batch(batch: list[dict[str, Any]] | None) -> Iterator[dict[str, Any]]:
    """Every decoded call in a batch tree, nested ones included."""
    for call in batch or ():
        yield call
        nested = call.get("batch")
        if isinstance(nested, list):
            yield from _walk_batch(nested)


def _attach_signatures(
    ctx: EnrichmentContext,
    safe_exec: dict[str, Any],
    batch: list[dict[str, Any]] | None,
) -> None:
    """Resolve signatures for the outer and every inner call in one query. Display only; no level depends on it."""
    calls = list(_walk_batch(batch))
    wanted: set[tuple[str, str]] = set()
    outer_to = _normalize_address(safe_exec.get("to"))
    outer_selector = _normalize_selector(safe_exec.get("selector"))
    if outer_to and outer_selector:
        wanted.add((outer_to, outer_selector))
    for call in calls:
        call_to = _normalize_address(call.get("to"))
        call_selector = _normalize_selector(call.get("selector"))
        if call_to and call_selector:
            wanted.add((call_to, call_selector))

    try:
        resolved = _resolve_signatures(ctx.session, ctx.chain, wanted)
    except Exception as exc:
        logger.warning(
            "Selector resolution failed on %s; selectors publish unresolved: %s",
            ctx.chain,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        resolved = {}

    if outer_selector:
        safe_exec["target_function"] = _function_block(outer_selector, resolved.get((outer_to or "", outer_selector)))
    for call in calls:
        call_selector = _normalize_selector(call.get("selector"))
        call_to = _normalize_address(call.get("to"))
        # The source rides with the signature.
        call["signature"] = resolved.get((call_to or "", call_selector or "")) if call_selector else None
        if call["signature"]:
            call["signature_source"] = _SIGNATURE_SOURCE_EFFECTIVE_FUNCTIONS


def _enrich_timelock(
    event: MonitoredEvent,
    mc: MonitoredContract,
    ctx: EnrichmentContext,
) -> dict[str, Any] | None:
    """Resolve the timelock families' already-decoded ``target``/``selector`` into ``data.target_function``."""
    data = event.data if isinstance(event.data, Mapping) else {}
    selector = _normalize_selector(data.get("selector"))
    if not selector:
        # A plain-value call has no selector.
        return None

    target = _normalize_address(data.get("target"))
    try:
        resolved = _resolve_signatures(ctx.session, ctx.chain, {(target, selector)} if target else set())
    except Exception as exc:
        logger.warning(
            "Selector resolution failed on %s; the timelock selector publishes unresolved: %s",
            ctx.chain,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        resolved = {}

    return {"target_function": _function_block(selector, resolved.get((target or "", selector)))}


def _admit_keys(
    produced: Mapping[str, Any],
    event: MonitoredEvent,
    mc: MonitoredContract,
) -> dict[str, Any]:
    """The subset of *produced* an enricher may write; rejected keys are logged as the bug they are."""
    admitted = {key: value for key, value in produced.items() if key in ENRICHABLE_KEYS}
    rejected = sorted(set(produced) - ENRICHABLE_KEYS)
    if rejected:
        logger.warning(
            "Enricher for %s on %s returned non-additive key(s) %s; refused",
            event.event_type,
            mc.address,
            ", ".join(rejected),
        )
    return admitted


def _correlate(
    session: Session,
    chain: str,
    pairs: list[tuple[MonitoredEvent, MonitoredContract]],
) -> list[tuple[MonitoredEvent, MonitoredContract, dict[str, Any]]]:
    """Both directions of the same-transaction join, as additive key sets.

    ``caused_by`` is written only when the transaction has exactly one execution. Scoped per chain (hashes can collide
    across chains) and per protocol (the API spreads ``data`` verbatim, so an unscoped join would leak rows across
    tenants). Not scoped per window: an earlier effect still links when its cause arrives, with no extra lookup.
    """
    causes = [
        (event, mc)
        for event, mc in pairs
        if event.event_type in _CAUSE_EVENT_TYPES and isinstance(event.tx_hash, str) and event.tx_hash
    ]
    if not causes:
        return []

    # Read-witnessed rows store ``tx_hash = ''``, which must never join.
    hashes = sorted({event.tx_hash for event, _mc in causes})
    rows = session.execute(
        select(MonitoredEvent, MonitoredContract)
        .join(MonitoredContract, MonitoredEvent.monitored_contract_id == MonitoredContract.id)
        .where(
            MonitoredEvent.tx_hash.in_(hashes),
            MonitoredEvent.tx_hash != "",
            MonitoredContract.chain == chain,
        )
    ).all()

    # ``by_tx`` is keyed by (protocol, tx), the scope of every write; NULL protocols are dropped. ``members_by_tx``
    # spans tenants and is only for counting possible causes.
    by_tx: dict[tuple[Any, str], list[tuple[MonitoredEvent, MonitoredContract]]] = {}
    members_by_tx: dict[str, list[tuple[MonitoredEvent, MonitoredContract]]] = {}
    for event, mc in rows:
        data = event.data if isinstance(event.data, Mapping) else {}
        # Historical rows witness nothing this window did.
        if data.get("historical"):
            continue
        members_by_tx.setdefault(event.tx_hash, []).append((event, mc))
        if mc.protocol_id is None:
            continue
        by_tx.setdefault((mc.protocol_id, event.tx_hash), []).append((event, mc))

    produced: list[tuple[MonitoredEvent, MonitoredContract, dict[str, Any]]] = []

    for cause, cause_mc in causes:
        if cause_mc.protocol_id is None:
            continue
        siblings = [
            (event, mc) for event, mc in by_tx.get((cause_mc.protocol_id, cause.tx_hash), []) if event.id != cause.id
        ]
        entries = []
        for event, mc in siblings:
            entry: dict[str, Any] = {
                "event_id": str(event.id),
                "event_type": event.event_type,
                "contract_address": _normalize_address(mc.address) or mc.address,
            }
            data = event.data if isinstance(event.data, Mapping) else {}
            level = data.get("salience")
            if isinstance(level, str) and level:
                # The rule raising a cause to its effects' max reads this; without it an alert effect would under-rate
                # the cause.
                entry["salience"] = level
            entries.append(entry)
        produced.append(
            (
                cause,
                cause_mc,
                {"correlated_events": entries, "correlated_scope": CORRELATED_SCOPE_MONITORED_ONLY},
            )
        )

    for (protocol_id, tx_hash), members in by_tx.items():
        # Counted across tenants: another protocol's execution is an equally plausible cause.
        in_tx_causes = [
            (event, mc) for event, mc in members_by_tx.get(tx_hash, []) if event.event_type in _CAUSE_EVENT_TYPES
        ]
        if len(in_tx_causes) != 1:
            if len(in_tx_causes) > 1:
                logger.debug(
                    "Transaction %s carries %d executions; ambiguous direction, no caused_by written",
                    tx_hash,
                    len(in_tx_causes),
                )
            continue
        cause, cause_mc = in_tx_causes[0]
        if cause_mc.protocol_id != protocol_id:
            # The only cause belongs to another tenant: publish no link rather than redirect it.
            continue
        for event, mc in members:
            if event.id == cause.id or event.event_type in _CAUSE_EVENT_TYPES:
                continue
            produced.append(
                (
                    event,
                    mc,
                    {"caused_by": {"event_id": str(cause.id), "event_type": cause.event_type}},
                )
            )

    return produced


def _contracts_for(session: Session, events: list[MonitoredEvent]) -> dict[Any, MonitoredContract]:
    """Each event's ``MonitoredContract`` in one query (freshly minted rows have no loaded relationship)."""
    ids = {event.monitored_contract_id for event in events if event.monitored_contract_id is not None}
    if not ids:
        return {}
    rows = session.execute(select(MonitoredContract).where(MonitoredContract.id.in_(ids))).scalars().all()
    return {mc.id: mc for mc in rows}


def enrich_events(
    session: Session,
    events: list[MonitoredEvent],
    rpc_by_chain: Mapping[str, str],
) -> None:
    """Run the enrichers over *events* and re-assign salience.

    Called inside the window transaction after the ON-CONFLICT insert, before the commit that precedes notification.
    Never raises: a failing enricher leaves its row untouched, and a driver failure must not roll back a correct window.
    """
    if not events:
        return

    try:
        mc_by_id = _contracts_for(session, events)
    except Exception as exc:
        logger.warning(
            "Enrichment could not load monitored contracts; skipping the pass: %s",
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return

    # The tx fetch is per chain (one endpoint, one chain_id guard).
    by_chain: dict[str, list[tuple[MonitoredEvent, MonitoredContract]]] = {}
    for event in events:
        mc = mc_by_id.get(event.monitored_contract_id)
        if mc is None:
            continue
        if not mc.chain:
            # Defaulting a chain would publish another chain's decode as this contract's.
            logger.warning(
                "Enrichment skipped for %s: the monitored contract names no chain",
                mc.address,
            )
            continue
        by_chain.setdefault(mc.chain, []).append((event, mc))

    # One budget per pass, spent in chain order.
    budget_remaining = _pass_tx_budget()

    for chain, pairs in by_chain.items():
        # Deduplicated: two executions in one tx cost one fetch.
        hashes = sorted(
            {
                event.tx_hash
                for event, _mc in pairs
                if event.event_type in NEEDS_TX and isinstance(event.tx_hash, str) and event.tx_hash
            }
        )
        # An unresolvable chain skips enrichment for that chain (no URL/chain guard); guarded because this function must
        # never raise.
        try:
            chain_id = chain_by_name(chain).chain_id
        except Exception as exc:
            logger.warning(
                "Enrichment skipped for %s: chain id not resolved: %s",
                chain,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            continue

        # Budget is only spent on chains that will actually be read.
        wanted, over_budget = hashes[:budget_remaining], frozenset(hashes[budget_remaining:])
        budget_remaining -= len(wanted)
        if over_budget:
            logger.info(
                "Enrichment tx budget exhausted on %s: %d fetched, %d recorded over budget",
                chain,
                len(wanted),
                len(over_budget),
            )

        # A failed fetch isn't fatal: hashes are just absent, and the zero-RPC enrichers still run.
        try:
            txs = _fetch_txs(rpc_by_chain.get(chain), chain_id, wanted)
        except Exception as exc:
            logger.warning(
                "Enrichment transaction fetch failed for %s; enrichers that need a tx will publish a status: %s",
                chain,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            txs = {}

        # Must fail closed: if the query fails, every asked hash is contested.
        try:
            contested = _contested_attributions(session, hashes)
        except Exception as exc:
            logger.warning(
                "Contested-attribution query failed on %s; refusing attribution for the whole pass: %s",
                chain,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            contested = frozenset(
                (mc.id, event.tx_hash)
                for event, mc in pairs
                if event.event_type in NEEDS_TX and isinstance(event.tx_hash, str) and event.tx_hash
            )

        ctx = EnrichmentContext(
            chain=chain,
            chain_id=chain_id,
            session=session,
            txs=txs,
            over_budget=over_budget,
            contested=contested,
        )

        changed: list[tuple[MonitoredEvent, MonitoredContract]] = []
        for event, mc in pairs:
            enricher = ENRICHERS.get(event.event_type)
            if enricher is None:
                continue
            try:
                produced = enricher(event, mc, ctx)
            except Exception as exc:
                logger.warning(
                    "Enricher for %s on %s failed: %s",
                    event.event_type,
                    mc.address,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                continue
            if _merge(produced, event, mc):
                changed.append((event, mc))

        # Before the join, which copies each effect's level onto its cause.
        _recompute(session, changed)

        # The join writes ``caused_by`` on rows the registry never visits, so the driver owns it.
        try:
            correlated = _correlate(session, chain, pairs)
        except Exception as exc:
            logger.warning(
                "Correlation join failed on %s; the window's rows keep their own levels: %s",
                chain,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            correlated = []

        linked: list[tuple[MonitoredEvent, MonitoredContract]] = []
        for event, mc, produced in correlated:
            if not _merge(produced, event, mc):
                continue
            # Only causes are re-rated: no rule reads ``caused_by``, and re-rating an ``initialized`` effect would now
            # see itself as a prior row.
            if DATA_KEY_CORRELATED_EVENTS in produced:
                linked.append((event, mc))
        _recompute(session, linked)


def _merge(
    produced: Mapping[str, Any] | None,
    event: MonitoredEvent,
    mc: MonitoredContract,
) -> bool:
    """Merge an enricher's admitted keys into *event*'s data; True if the row changed."""
    if not produced:
        return False
    additive = _admit_keys(produced, event, mc)
    if not additive:
        return False
    merged = dict(event.data or {})
    merged.update(additive)
    event.data = merged
    flag_modified(event, "data")
    return True


def _recompute(session: Session, changed: list[tuple[MonitoredEvent, MonitoredContract]]) -> None:
    """Re-rate every row an enricher touched before commit, so notifier and frontend only see final levels."""
    for event, mc in changed:
        try:
            stamp_salience(session, event, mc)
        except Exception as exc:
            logger.warning(
                "Salience recompute failed for %s on %s: %s",
                event.event_type,
                mc.address,
                exc,
                extra={"exc_type": type(exc).__name__},
            )


ENRICHERS.update(
    {
        "safe_tx_executed": _enrich_safe_exec,
        "safe_tx_failed": _enrich_safe_exec,
        "timelock_scheduled": _enrich_timelock,
        "timelock_executed": _enrich_timelock,
    }
)

# Timelock args are decoded at mint and the join reads nothing from the wire.
NEEDS_TX = frozenset({"safe_tx_executed", "safe_tx_failed"})
