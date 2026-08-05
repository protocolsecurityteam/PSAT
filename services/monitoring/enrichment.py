"""Enrichment driver — adds decoded fields to what the taxonomy published.

Ground rules (§3.0, normative):

1. Enrichment adds fields to ``monitored_events.data``. It never changes
   ``event_type``, never changes ``witness_tier``, and never causes or
   suppresses a row insert. The taxonomy decides what may be published;
   enrichment describes what was published.
2. Every derived field is either a **witnessed fact** — decoded from on-chain
   bytes — published bare, or a **labeled heuristic**, published under
   ``data.heuristics.<name>`` with its basis and never promoted to a bare key.
3. A decode that does not complete publishes a reason, not a guess: every
   enrichment block carries a ``status``. An absent block means enrichment did
   not run; it never means "nothing to find".
4. Enrichment failure is never fatal. It runs inside try/except, logs, and
   leaves the row exactly as the taxonomy wrote it.
5. Historical rows are never enriched — ``_process_window`` already excludes
   ``data.historical`` events from the list this driver receives, so
   pre-enrollment backfill costs zero RPC.

The salience recompute in step 6 is not an optimization: enrichment changes the
inputs ``assign_salience`` reads (``safe_exec.*``, ``correlated_events``), so
the mint-time assignment is provisional for enrichable types. Recomputing here,
inside the window transaction and BEFORE the commit that precedes
``_notify_committed_events``, is what guarantees the notifier and the frontend
only ever see the post-enrichment level.

What runs, in order, per chain:

* the per-event registry (``ENRICHERS``) — E1 ``execTransaction`` decode, E4
  MultiSend batch expansion, E2 selector→signature — over the transactions
  ``_fetch_txs`` brought back;
* the salience recompute for the rows those touched, so the correlation join
  reads post-decode levels rather than mint-time provisional ones;
* the window-level correlation join (E3), which is zero-RPC and writes BOTH
  directions, followed by its own recompute.

``_SAFE_MULTISEND_ADDRESSES`` provenance
----------------------------------------
The pinned MultiSend deployment list is vendored verbatim from
``safe-global/safe-deployments`` @ ``main`` (read 2026-08-04):
``src/assets/v1.3.0/multi_send.json``, ``v1.3.0/multi_send_call_only.json``,
``v1.4.1/multi_send.json``, ``v1.4.1/multi_send_call_only.json``. Address
equality against a pinned deployment is a *witnessed* comparison, and it is the
only MultiSend witness this run takes: the stronger ``eth_getCode`` code-hash
check (OQ3) needs live RPC and is deferred out of the run entirely. An address
NOT on the list is not proven malicious — it is **not proven to be MultiSend**,
which is exactly why it raises the level instead of lowering it.
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
from services.monitoring.chain_rpc import chain_id_for
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
from utils.rpc import rpc_batch_request_classified

logger = logging.getLogger(__name__)

# Default budget for the per-pass transaction fetch. Read through
# ``unified_watcher._scan_int_env``; declared here so the knob's name and
# default live with the code that spends it.
ENRICH_TX_BUDGET_ENV = "PSAT_SCAN_MAX_ENRICH_TX_PER_PASS"
DEFAULT_MAX_ENRICH_TX_PER_PASS = 50

# Pinned MultiSend deployments — see the module docstring for provenance.
# Lower-cased at declaration so every comparison is against one normal form.
# The zkSync-variant deployments are deliberately EXCLUDED: they are the same
# code at a different address on chains this system does not scan, and an
# address that is MultiSend on zkSync is an unknown contract on ethereum —
# admitting it would quiet a delegatecall this list cannot vouch for.
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

# ``multiSend(bytes)`` — the entry point whose single argument holds the packed
# batch. Hashed from the published signature rather than transcribed, for the
# same reason ``_gates`` does it.
MULTISEND_SELECTOR = abi_selector("multiSend(bytes)")  # 0x8d80ff0a

# How many levels of packed payload this decoder will expand. A MultiSend entry
# may itself delegatecall MultiSend, and each layer is a real call the operator
# is entitled to see; what a cap prevents is an adversarially deep payload
# spending the window transaction's time. Exceeding it is a STATED gap, never a
# quiet floor.
MAX_MULTISEND_DEPTH = 3

# The published Safe ABI's ``execTransaction`` argument list. ``Enum.Operation``
# lowers to ``uint8``.
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

# Why a batch was not expanded. Rides beside ``batch_status`` so the gap says
# what kind of gap it is; neither key changes a level (``batch_status`` alone
# does that), and no partial list is ever published with either.
BATCH_REASON_MALFORMED = "malformed_payload"
BATCH_REASON_NESTED_UNDECODABLE = "nested_payload_undecodable"
BATCH_REASON_DEPTH_EXCEEDED = "nested_depth_exceeded"

# ``correlated_events`` is scoped to what is MONITORED. An empty list means "no
# monitored contract emitted in this transaction", never "this execution had no
# effect", and this key is what keeps a consumer from reading the second.
CORRELATED_SCOPE_MONITORED_ONLY = "monitored_only"

# The execution families §3.4 treats as the cause when they share a transaction
# with anything else monitored. Same transaction hash is a witnessed fact; which
# side is the cause comes from this registry, not from log ordering (a Safe's
# ``ExecutionSuccess`` is emitted AFTER the calls it made).
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

    ``txs`` maps ``tx_hash`` → the RPC transaction object. A hash MISSING from
    the map is a fetch that failed or was skipped over budget — never an
    assertion that the transaction does not exist — so an enricher that needs
    one and cannot find it publishes a status, not a guess.

    ``contested`` holds every ``(monitored_contract_id, tx_hash)`` a decoder
    may NOT attribute a single top-level call to, because that contract has
    more than one execution row in that transaction.
    """

    chain: str
    chain_id: int
    session: Session
    txs: Mapping[str, dict] = field(default_factory=dict)
    over_budget: frozenset[str] = frozenset()
    contested: frozenset[tuple[Any, str]] = frozenset()


# An enricher returns the keys to MERGE into ``event.data``, or ``None`` when
# it has nothing to add. It must not mutate the event itself: the driver owns
# the merge, the change bookkeeping, and the salience recompute.
Enricher = Callable[[MonitoredEvent, MonitoredContract, EnrichmentContext], "dict[str, Any] | None"]

# event_type → enricher. Mirrors how ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` already
# keys behaviour off the canonical type. Populated at the bottom of the module,
# once the enrichers it names are defined.
ENRICHERS: dict[str, Enricher] = {}

# Event types whose enricher wants the top-level transaction. Only these
# contribute hashes to the per-chain fetch, so a window with no Safe execution
# in it issues no RPC at all.
NEEDS_TX: frozenset[str] = frozenset()

# Invariant 8, enforced rather than documented: enrichment is ADDITIVE. These
# are the only ``data`` keys an enricher may write. The list is closed on
# purpose — ``witness_tier`` is read by ``notifier._may_notify`` and
# ``historical`` by the scanner's notify gate, so an enricher that returned
# either would move a side-effect decision from the taxonomy to a decoder. The
# driver is the natural chokepoint: every enricher's output passes through it,
# and a rejected key is logged rather than dropped in silence.
#
# ``target_function`` is the one widening this lane took, under an explicit
# orchestrator ruling: the timelock families already publish ``target`` and
# ``selector`` as bare top-level keys (``event_topics`` decodes them at mint),
# so their E2 resolution has no ``safe_exec``-shaped block to live inside and
# gets its own namespaced one. Nothing else is admitted — a key outside this
# set stays loudly refused.
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
    """How many transactions one enrichment pass may fetch, across ALL chains.

    The budget bounds how long the round-trip can hold the open window
    transaction (the same seam holds the cursor update), and that seam is
    per-pass, not per-chain — so a fleet on N chains may not spend N×.
    """
    # Local import: ``unified_watcher`` imports this module at module scope, so
    # a top-level import back would close the cycle.
    from services.monitoring.unified_watcher import _scan_int_env

    return max(0, _scan_int_env(ENRICH_TX_BUDGET_ENV, DEFAULT_MAX_ENRICH_TX_PER_PASS))


def _fetch_txs(
    rpc_url: str | None,
    chain_id: int,
    tx_hashes: list[str],
) -> dict[str, dict]:
    """Transaction objects for *tx_hashes* (already inside the pass budget).

    One ``rpc_batch_request_classified`` per chain, passing ``chain_id`` so the
    URL↔chain guard the rest of monitoring uses applies here too. Per-slot
    failures are already classified there; a failed slot simply leaves its hash
    out of the returned map, which the context's contract reads as "not
    fetched", never as "no such transaction". A whole-batch transport failure
    degrades identically: the caller catches it and proceeds with an empty map
    rather than denying the chain its zero-RPC enrichers.
    """
    if not tx_hashes:
        return {}

    if not rpc_url:
        # No endpoint for this chain. Nothing was fetched and nothing was
        # DECLINED either, so these hashes are not over-budget: their events
        # publish no block at all, which reads as "enrichment did not run".
        logger.warning("Enrichment tx fetch skipped on chain %d: no RPC endpoint for the chain", chain_id)
        return {}

    results = rpc_batch_request_classified(
        rpc_url,
        [("eth_getTransactionByHash", [tx_hash]) for tx_hash in tx_hashes],
        chain_id=chain_id,
    )

    txs: dict[str, dict] = {}
    for tx_hash, (result, status) in zip(tx_hashes, results):
        # ``ok`` with a null result is a node saying it does not have the
        # transaction; both that and a non-``ok`` slot leave the hash out, which
        # the enricher reads as "not fetched" rather than as a fact about it.
        if status == "ok" and isinstance(result, Mapping):
            txs[tx_hash] = dict(result)
    return txs


def _contested_attributions(
    session: Session,
    tx_hashes: list[str],
) -> frozenset[tuple[Any, str]]:
    """``(monitored_contract_id, tx_hash)`` pairs carrying MORE THAN ONE
    execution row for the same contract.

    One transaction holds one set of top-level ``execTransaction`` arguments.
    When a Safe executed twice inside it — an outer execution plus a nested one
    reached through MultiSend or a callback — those arguments describe at most
    one of the rows, and nothing in the transaction object witnesses which. The
    decoder refuses both rather than attributing a call to a row that may not
    have made it.

    Queried rather than read off the window, so a sibling execution inserted by
    an earlier window still contests.
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


# ---------------------------------------------------------------------------
# E2 — selector → signature, fleet-internal only
# ---------------------------------------------------------------------------


def _normalize_address(value: Any) -> str | None:
    """The one normal form every published address and every comparison uses."""
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
    """``(address, selector) → abi_signature`` for the targets this system has
    itself analysed.

    Fleet-internal and therefore *witnessed*: the signature comes from the
    target's own verified source as this pipeline read it, not from a
    third-party ABI claim (§3.3's Etherscan fallback is deferred and produces a
    heuristic, which is why it would have to live under ``heuristics``).

    A selector that resolves to more than one DISTINCT signature is left
    unresolved: two contracts at one address across re-analyses disagreeing
    about a selector is an ambiguity, and picking one would publish a name no
    witness picked.
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
    """The §3.3 shape. A raw selector is a real fact and renders fine; an
    unresolved one publishes ``signature: null`` rather than a guess, and a
    resolved one names the source that resolved it — a name without a stated
    source is exactly the thing this system does not let stand for a witness."""
    block: dict[str, Any] = {"selector": selector, "signature": signature}
    if signature:
        block["source"] = _SIGNATURE_SOURCE_EFFECTIVE_FUNCTIONS
    return block


# ---------------------------------------------------------------------------
# E4 — MultiSend batch expansion
# ---------------------------------------------------------------------------

# (operation: 1B, to: 20B, value: 32B, dataLength: 32B, data: dataLength B)
_MULTISEND_ENTRY_HEADER = 1 + 20 + 32 + 32


def _decode_multisend(payload: bytes, depth: int = 1) -> tuple[list[dict[str, Any]] | None, str | None]:
    """``(entries, None)`` for a batch that decoded whole, or ``(None, reason)``.

    Never a partial list, at any depth. A truncated batch would understate what
    the Safe did, which is the one direction this decode may not fail in — and
    an inner MultiSend that will not expand takes the WHOLE batch down with it
    rather than standing as an entry whose contents nobody read. One extra
    wrapping layer is not a reason to trust a payload.
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
            # Set on every inner call for the same reason it is set on the
            # outer one: it is the witnessed comparison the salience rules
            # read, and an inner delegatecall whose target this list cannot
            # vouch for is what raises the whole batch.
            SAFE_EXEC_KEY_MULTISEND_RECOGNIZED: recognized,
        }

        if operation == _OPERATION_DELEGATECALL and recognized:
            # A nested batch. Its inner calls are evaluated by the same rules,
            # so a hostile delegatecall cannot be hidden by wrapping it.
            if depth >= MAX_MULTISEND_DEPTH:
                return None, BATCH_REASON_DEPTH_EXCEEDED
            nested, reason = _decode_multisend(data, depth + 1)
            if nested is None:
                # Which LAYER failed is part of the gap: an outer payload this
                # decoder could not read is a different fact from an outer one
                # that read fine and a payload under it that did not.
                # ``nested_depth_exceeded`` already names its own layer.
                return None, BATCH_REASON_NESTED_UNDECODABLE if reason == BATCH_REASON_MALFORMED else reason
            entry["batch"] = nested

        calls.append(entry)
        cursor = end

    return calls, None


# ---------------------------------------------------------------------------
# E1 — Safe ``execTransaction`` decode
# ---------------------------------------------------------------------------


def _enrich_safe_exec(
    event: MonitoredEvent,
    mc: MonitoredContract,
    ctx: EnrichmentContext,
) -> dict[str, Any] | None:
    """Decode the transaction that carried a ``safe_tx_executed`` /
    ``safe_tx_failed`` into what the Safe was actually asked to do.

    Step 1 is a top-level-call check, and it is the whole reason this decoder
    is honest: the observed transaction is only this Safe's ``execTransaction``
    when it was sent TO this Safe with that selector. A relayer, a nested Safe
    (A is an owner of B), or a batch of two ``execTransaction`` calls inside one
    outer call all fail it — and guessing at the inner call from the outer
    input would be exactly the unwitnessed inference the overhaul removed.
    """
    tx_hash = event.tx_hash if isinstance(event.tx_hash, str) else ""
    if not tx_hash:
        return None

    if tx_hash in ctx.over_budget:
        # A recorded decline to look, not a finding about the transaction.
        return {"safe_exec": {"status": SAFE_EXEC_STATUS_OVER_BUDGET}}

    tx = ctx.txs.get(tx_hash)
    if not isinstance(tx, Mapping):
        # Not fetched (transport failure, missing endpoint, node without the
        # transaction). No block at all: the salience rules read that as
        # "enrichment absent" and keep the row visible.
        return None

    if "to" not in tx or not isinstance(tx.get("input"), str):
        # ``not_top_level_call`` is a POSITIVE finding and it demotes the row,
        # so it may only be minted from fields the response actually carried.
        # A transaction object missing either one is an unread transaction, not
        # a proven indirect one.
        logger.warning(
            "Transaction %s carries no to/input; %s publishes no decode rather than a finding",
            tx_hash,
            mc.address,
        )
        return None

    to = _normalize_address(tx.get("to"))
    tx_input = tx["input"].lower()
    if to is None or to != mc.address.lower() or tx_input[:10] != SAFE_EXEC_TRANSACTION:
        # Includes ``to: null`` — a contract creation is witnessed NOT to be a
        # call to this Safe. This arm survives the ambiguity check below on
        # purpose: it is a statement about the OBSERVED TRANSACTION, true of
        # every row in it, not an attribution of arguments to one row.
        return {"safe_exec": {"status": SAFE_EXEC_STATUS_NOT_TOP_LEVEL}}

    if (mc.id, tx_hash) in ctx.contested:
        # More than one execution of THIS Safe landed in this transaction (the
        # live feed already carries the shape: two ExecutionSuccess logs, one
        # tx, one Safe). There is exactly one set of top-level arguments and it
        # describes at most one of those executions — publishing it on both
        # would state another execution's target, value and operation as a
        # witnessed fact about this row. Which row it belongs to needs the Safe
        # nonce / EIP-712 recompute, which is outside this run's RPC budget.
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
            # Either the batch decodes whole or its failure is on the record. A
            # recognized-MultiSend delegatecall carrying neither would be a
            # shape whose contents nobody examined and nobody said so.
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
    """E2 over the outer call and every inner one, in a single query.

    Name resolution is DISPLAY only: nothing here may change a level, and the
    salience rules read none of these keys.
    """
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
        # The §3.5 entry shape names the signature inline; the source rides
        # with it so a name is never read as sourceless.
        call["signature"] = resolved.get((call_to or "", call_selector or "")) if call_selector else None
        if call["signature"]:
            call["signature_source"] = _SIGNATURE_SOURCE_EFFECTIVE_FUNCTIONS


# ---------------------------------------------------------------------------
# E2 — the timelock families (no decoder work; the args are already published)
# ---------------------------------------------------------------------------


def _enrich_timelock(
    event: MonitoredEvent,
    mc: MonitoredContract,
    ctx: EnrichmentContext,
) -> dict[str, Any] | None:
    """Resolve the already-decoded ``target`` + ``selector`` to a signature.

    ``event_topics`` decodes ``CallScheduled``/``CallExecuted`` at mint, so
    these families need no decoder — only the name. The resolved block is
    namespaced at ``data.target_function`` rather than folded in beside the
    bare ``target``/``selector`` keys the taxonomy owns.
    """
    data = event.data if isinstance(event.data, Mapping) else {}
    selector = _normalize_selector(data.get("selector"))
    if not selector:
        # No selector was decoded (a plain-value timelock call has no
        # calldata). There is nothing to resolve and nothing to say.
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
    """The subset of *produced* an enricher is allowed to write (invariant 8).

    A rejected key is logged, never dropped in silence: an enricher trying to
    write ``witness_tier`` or ``event_type`` is a bug about who decides what a
    row claims, and it must be visible as one rather than mysteriously
    ineffective.
    """
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


# ---------------------------------------------------------------------------
# E3 — cause/effect correlation join (zero RPC, one query per chain)
# ---------------------------------------------------------------------------


def _correlate(
    session: Session,
    chain: str,
    pairs: list[tuple[MonitoredEvent, MonitoredContract]],
) -> list[tuple[MonitoredEvent, MonitoredContract, dict[str, Any]]]:
    """Both directions of the same-transaction join, as additive key sets.

    Sharing a transaction hash is a witnessed fact, not an inference — which is
    why both directions may be published. What is NOT witnessed is which of two
    executions in one transaction caused a given effect, so ``caused_by`` is
    written only where exactly one execution is in the transaction; the
    ambiguous case still links from the execution's side, so nothing is lost.

    Scoped to one chain: two chains can carry the same transaction hash, and a
    cross-chain "correlation" would be a coincidence published as a cause.

    Scoped to one PROTOCOL: the published entry names another row's id, address
    and level, and the API spreads ``data`` verbatim, so an unscoped join would
    hand one tenant a row belonging to another. A contract with no protocol is
    not proven to be any tenant's and never joins.

    Not scoped to one window — deliberately, and this is a deviation from the
    lane's earlier report: §3.4's query has no window restriction, so an effect
    inserted by an earlier window still links when its cause arrives. That is
    additive (the effect is not re-notified and the scope key still rides), and
    it is not the bounded look-back OQ4 declined to build: no extra lookup is
    performed, the cause's own transaction hash is simply matched against
    whatever is already stored.
    """
    causes = [
        (event, mc)
        for event, mc in pairs
        if event.event_type in _CAUSE_EVENT_TYPES and isinstance(event.tx_hash, str) and event.tx_hash
    ]
    if not causes:
        return []

    # Read-witnessed rows persist ``tx_hash = ''``; the empty string is not a
    # transaction and must never join.
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

    # Two indexes, because tenancy scopes what may be PUBLISHED and not what is
    # KNOWN. ``by_tx`` is keyed by (protocol, tx) — the scope of every write, so
    # no code path can reach a row across it, and a NULL protocol_id is not a
    # tenant and is dropped outright. ``members_by_tx`` holds every row in the
    # transaction regardless of tenant, and exists for exactly one purpose:
    # counting how many executions could have caused a given effect.
    by_tx: dict[tuple[Any, str], list[tuple[MonitoredEvent, MonitoredContract]]] = {}
    members_by_tx: dict[str, list[tuple[MonitoredEvent, MonitoredContract]]] = {}
    for event, mc in rows:
        data = event.data if isinstance(event.data, Mapping) else {}
        # §3.0 rule 5: historical rows are never enriched. One that predates
        # enrollment is not a witness to anything this window did.
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
                # The effect's OWN level rides on the entry: the rule that
                # raises a cause to the max of its effects reads this list and
                # does not query, so an entry without it would silently
                # under-rate a cause whose effect is an alert.
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
        # Counted over EVERY row in the transaction, not just this tenant's.
        # Another protocol's execution in the same transaction is exactly as
        # plausible a cause, and the shared hash witnesses direction no better
        # across a tenancy boundary than within one — so a per-protocol count
        # would name a cause the transaction does not single out.
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
            # The transaction's only execution belongs to another tenant. It is
            # the only plausible cause and it is not this tenant's to name, so
            # the link is simply not published — never redirected to a row that
            # merely happens to be in scope.
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
    """The ``MonitoredContract`` behind each event, in one query.

    Rows minted by ``_process_window`` are detached-then-added instances with
    no relationship loaded, so touching ``event.monitored_contract`` per event
    would emit one SELECT each.
    """
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
    """Run the registered enrichers over *events* and re-assign salience.

    Called inside the window transaction, after the ON-CONFLICT insert has
    decided which rows are real (no RPC spend on rows a concurrent scanner
    won) and before the commit that precedes ``_notify_committed_events``.

    Never raises: a failing enricher leaves its row exactly as the taxonomy
    wrote it (§3.0 rule 4), and a failure in the driver itself must not roll
    back a window whose rows are already correct.
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

    # Partition by chain: the transaction fetch is per-chain (one RPC endpoint,
    # one chain_id guard) even though the enrichers are not.
    by_chain: dict[str, list[tuple[MonitoredEvent, MonitoredContract]]] = {}
    for event in events:
        mc = mc_by_id.get(event.monitored_contract_id)
        if mc is None:
            continue
        if not mc.chain:
            # No chain means no endpoint and no chain_id for the URL↔chain
            # guard. Defaulting one here would enrich a row against whatever
            # ethereum answered and publish it as this contract's decode.
            logger.warning(
                "Enrichment skipped for %s: the monitored contract names no chain",
                mc.address,
            )
            continue
        by_chain.setdefault(mc.chain, []).append((event, mc))

    # One budget for the pass, spent in chain order — the seam it protects (the
    # open window transaction) is per-pass, so N chains may not cost N×.
    budget_remaining = _pass_tx_budget()

    for chain, pairs in by_chain.items():
        # Deduplicated: two Safe executions in one transaction cost one fetch.
        hashes = sorted(
            {
                event.tx_hash
                for event, _mc in pairs
                if event.event_type in NEEDS_TX and isinstance(event.tx_hash, str) and event.tx_hash
            }
        )
        # Two guards, because the two failures are not the same failure.
        #
        # An unresolvable chain is fatal to this chain: without a chain_id
        # there is no URL↔chain guard, and an enricher that reads ctx.chain_id
        # would be reading a value nobody resolved. Skip it. (Guarded at all
        # because this function's contract is that it never raises, and
        # chain_rpc is free to become fail-loud on an unknown chain — that must
        # cost the chain its enrichment, never the window commit.)
        try:
            chain_id = chain_id_for(chain)
        except Exception as exc:
            logger.warning(
                "Enrichment skipped for %s: chain id not resolved: %s",
                chain,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            continue

        # Spent only once the chain is known to be enrichable: a chain skipped
        # above fetches nothing, so it may not consume budget the next chain
        # would have spent on transactions it actually reads.
        wanted, over_budget = hashes[:budget_remaining], frozenset(hashes[budget_remaining:])
        budget_remaining -= len(wanted)
        if over_budget:
            logger.info(
                "Enrichment tx budget exhausted on %s: %d fetched, %d recorded over budget",
                chain,
                len(wanted),
                len(over_budget),
            )

        # A failed transaction fetch is NOT fatal. It degrades exactly as a
        # per-slot failure does — the hashes are simply absent from ctx.txs,
        # which the context's contract already reads as "not fetched", never as
        # "no such transaction". The zero-RPC enrichers (§3.9: correlation and
        # the poll-field classification) need nothing from this map and must
        # still run, so a transport blip on the Safe decode may not take them
        # down with it.
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

        # Which (contract, tx) pairs a decoder may not attribute a single
        # top-level call to. Zero RPC, one query, and a failure here may not
        # cost the chain its enrichment — but it MUST fail closed: an empty set
        # read as "nothing contested" would re-open exactly the attribution the
        # query exists to refuse, so a failed query contests every hash it was
        # asked about.
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

        # Step 6, first pass. Run BEFORE the correlation join, not after it:
        # the join copies each effect's own level onto the cause's entry, and a
        # level read before the decode landed would be the provisional one.
        _recompute(session, changed)

        # E3 is zero-RPC and does not go through ENRICHERS: it writes the
        # reciprocal ``caused_by`` onto rows the per-event registry never
        # visits (an effect has no enricher of its own), so the driver owns it
        # the same way it owns the merge.
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
            # Only the CAUSE side is re-rated. No salience rule reads
            # ``caused_by``, so an effect row that gained only that keeps the
            # level it was minted with — and re-rating it would not be the
            # no-op it looks like: the reinitialization rule asks whether a
            # prior ``initialized`` row exists, and by now the row being rated
            # is itself one of the rows that query can see.
            if DATA_KEY_CORRELATED_EVENTS in produced:
                linked.append((event, mc))
        _recompute(session, linked)


def _merge(
    produced: Mapping[str, Any] | None,
    event: MonitoredEvent,
    mc: MonitoredContract,
) -> bool:
    """Merge an enricher's admitted keys into *event*'s data. True when the row
    changed and therefore needs re-rating."""
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
    """Step 6 — the seam that is part of phase 2's contract, not an
    optimization. Every row whose data an enricher touched (which includes
    every row that gained ``correlated_events`` / ``caused_by``) is re-rated
    before the commit, and therefore before the notifier and the frontend ever
    see it."""
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

# Only the Safe executions need the top-level transaction. The timelock
# families' arguments are already decoded at mint (``event_topics``), and E3
# reads nothing off the wire — so a window with no Safe execution in it costs
# zero RPC.
NEEDS_TX = frozenset({"safe_tx_executed", "safe_tx_failed"})
