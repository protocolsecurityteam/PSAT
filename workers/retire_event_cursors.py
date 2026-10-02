"""Retire tracked-topic cursors no reader consumes: an operator tool, never run automatically.

    python -m workers.retire_event_cursors [--chain-id N]    # dry run (default): prints, writes nothing
    python -m workers.retire_event_cursors --apply --addresses 0xA,0xB [--chain-id N]

A cursor is retirable only when every gate holds, each with its evidence printed:

1. ``tracked_basis``: its ``enrollment_basis`` is ``tracked_topics_asserted`` (or ``retiring``, left by an interrupted
   apply);
2. ``no_indexed_spec``: no active monitored contract on its chain names its (address, topic0) with a tier that is
   indexed (anything but ``activity`` / ``hint``, so an unstamped spec blocks);
3. ``no_predicate_hint``: no completed job's predicate trees resolve to its (chain, address, topic0), replayed through
   the enrolment resolver; a delegated role gate counts every role-store topic, since detection isn't replayed;
4. ``not_restaking_emitter``: its (chain, address) has no ``PubkeyLinked`` cursor or row;
5. ``no_materializable_check``: no external bool check targets its (chain, address) unless the callee's ABI proves it
   returns nothing (an empty return decodes as false, so such a check never reads the rows); a callee whose outputs
   can't be read blocks;
6. ``floor_witness_kept``: when it is its address's last cursor, an ``address_floor_witnesses`` row exists.

An external check whose target no controller value names can't be placed by gate 5; the dry run lists every such check
and ``--apply`` refuses to run while any exist unless given ``--acknowledge-unresolved-checks``.

``--apply`` deletes only retirable cursors at the listed addresses, re-evaluating every gate at apply time. Rows go in
transactions of at most 5,000; the cursor is deleted in the same transaction as its final batch. The log-delete
trigger marks ``reorg`` for the address and the cursor delete marks ``reconcile`` for the chain.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Sequence

from eth_utils.crypto import keccak
from sqlalchemy import delete, func, select, tuple_, update
from sqlalchemy.orm import Session

from db.models import (
    ENROLLMENT_BASIS_RETIRING,
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    AddressFloorWitness,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    MonitoredContract,
    SessionLocal,
)
from db.queue import get_artifact
from services.clients.etherscan import get as etherscan_get
from services.monitoring.restaking_enrollment import PUBKEY_LINKED_TOPIC0
from services.resolution.role_store_standards import all_topic0s
from utils.chains import UnknownChainError, chain_by_name
from utils.logging import configure_logging
from workers.event_log_indexer import (
    _event_address_for_descriptor,
    _state_var_values_for_job,
    completed_jobs_query,
    hint_targets_for_job,
    job_chain,
    tracked_spec_enrols,
)

logger = logging.getLogger("workers.retire_event_cursors")

DELETE_BATCH_ROWS = 5_000
# A ``retiring`` cursor is one an interrupted apply left behind; retiring it again finishes the job.
_RETIRABLE_BASES = (ENROLLMENT_BASIS_TRACKED_TOPICS, ENROLLMENT_BASIS_RETIRING)

GATES = (
    "tracked_basis",
    "no_indexed_spec",
    "no_predicate_hint",
    "not_restaking_emitter",
    "no_materializable_check",
    "floor_witness_kept",
)


@dataclass
class CursorVerdict:
    chain_id: int
    address: str
    topic0: str
    enrollment_basis: str | None
    rows: int
    gates: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def retirable(self) -> bool:
        return all(self.gates.get(name, {}).get("pass") is True for name in GATES)

    def to_json(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "address": self.address,
            "topic0": self.topic0,
            "enrollment_basis": self.enrollment_basis,
            "rows": self.rows,
            "retirable": self.retirable,
            "gates": self.gates,
        }


AbiLookup = Callable[[int, str], "list[dict[str, Any]] | None"]


def etherscan_abi(chain_id: int, address: str) -> list[dict[str, Any]] | None:
    """The verified ABI at ``address``, followed once to an implementation Etherscan reports; ``None`` when unread."""
    try:
        result = etherscan_get("contract", "getsourcecode", address=address, chain_id=chain_id)["result"][0]
        abi = json.loads(result.get("ABI") or "")
    except Exception as exc:
        logger.warning("callee ABI unreadable", extra={"address": address, "exc_type": type(exc).__name__})
        return None
    if not isinstance(abi, list):
        return None
    implementation = str(result.get("Implementation") or "").lower()
    if implementation.startswith("0x") and len(implementation) == 42 and implementation != address.lower():
        try:
            impl_result = etherscan_get("contract", "getsourcecode", address=implementation, chain_id=chain_id)
            impl_abi = json.loads(impl_result["result"][0].get("ABI") or "")
            if isinstance(impl_abi, list):
                abi = abi + impl_abi
        except Exception as exc:
            logger.warning(
                "implementation ABI unreadable", extra={"address": implementation, "exc_type": type(exc).__name__}
            )
            return None
    return abi


def _abi_type(entry: dict[str, Any]) -> str:
    kind = str(entry.get("type") or "")
    if kind.startswith("tuple"):
        inner = ",".join(_abi_type(c) for c in entry.get("components") or [])
        return f"({inner}){kind[5:]}"
    return kind


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature.replace(" ", "")).hex()[:8]


def _callee_outputs(abi: list[dict[str, Any]] | None, selector: str) -> tuple[list[str] | None, str | None]:
    """``(output types, signature)`` of the ABI function with ``selector``; ``(None, None)`` when not determined."""
    if abi is None:
        return None, None
    for entry in abi:
        if not isinstance(entry, dict) or entry.get("type") != "function":
            continue
        signature = f"{entry.get('name', '')}({','.join(_abi_type(i) for i in entry.get('inputs') or [])})"
        if _selector(signature) == selector.lower():
            return [_abi_type(o) for o in entry.get("outputs") or []], signature
    return None, None


def _external_bool_descriptors(node: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(node, dict):
        return
    if node.get("op") == "LEAF":
        leaf = node.get("leaf")
        if isinstance(leaf, dict) and leaf.get("kind") == "external_bool":
            descriptor = leaf.get("set_descriptor")
            if isinstance(descriptor, dict):
                yield descriptor
        return
    for child in node.get("children") or []:
        yield from _external_bool_descriptors(child)


@dataclass
class _Evidence:
    hint_keys: dict[tuple[int, str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    role_store_addresses: dict[tuple[int, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    checks: dict[tuple[int, str], list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    unresolved_checks: list[dict[str, Any]] = field(default_factory=list)


def _replay_jobs(session: Session) -> _Evidence:
    """Predicate-hint keys over every completed job, and external check targets over every job with predicate trees,
    read-only."""
    from services.resolution.capability_resolver import _load_state_var_values

    evidence = _Evidence()
    for job in session.execute(completed_jobs_query()).scalars():
        job_ref = str(job.id)
        for target in hint_targets_for_job(session, job):
            if target.topics is None:
                evidence.role_store_addresses[(target.chain_id, target.address)].append(job_ref)
                continue
            for topic0 in target.topics:
                evidence.hint_keys[(target.chain_id, target.address, topic0.lower())].append(job_ref)
    # A job still in the pipeline resolves its checks too, so every job with trees counts here.
    for job in session.execute(select(Job).where(Job.address.isnot(None)).order_by(Job.id)).scalars():
        artifact = get_artifact(session, job.id, "predicate_trees")
        if not isinstance(artifact, dict):
            continue
        chain_id = job_chain(job)
        if chain_id is None:
            continue
        # Both sources a resolution may read the target from: the job's own controller values and the
        # deployment-scoped ones; a check counts against every address either names.
        value_sets = [
            _state_var_values_for_job(session, job),
            _load_state_var_values(session, str(job.address), job_id=job.id),
        ]
        for tree_key in ("trees", "check_trees"):
            trees = artifact.get(tree_key)
            if not isinstance(trees, dict):
                continue
            for function, tree in trees.items():
                for descriptor in _external_bool_descriptors(tree):
                    signature = descriptor.get("callee_signature")
                    selector = descriptor.get("callee_selector")
                    if not isinstance(selector, str) and isinstance(signature, str):
                        selector = _selector(signature)
                    if not isinstance(selector, str):
                        continue
                    check = {
                        "job_id": str(job.id),
                        "function": function,
                        "callee_signature": signature,
                        "callee_selector": selector.lower(),
                    }
                    targets = {
                        target.lower()
                        for values in value_sets
                        if isinstance(
                            target := _event_address_for_descriptor(
                                descriptor, {}, job, values, allow_job_fallback=False
                            ),
                            str,
                        )
                    }
                    if not targets:
                        evidence.unresolved_checks.append(
                            {**check, "chain_id": chain_id, "authority_contract": descriptor.get("authority_contract")}
                        )
                    for target in sorted(targets):
                        evidence.checks[(chain_id, target)].append(check)
    return evidence


def _monitored_specs(session: Session) -> dict[tuple[int, str, str], list[dict[str, Any]]]:
    out: dict[tuple[int, str, str], list[dict[str, Any]]] = defaultdict(list)
    rows = session.execute(
        select(
            MonitoredContract.id,
            MonitoredContract.address,
            MonitoredContract.chain,
            MonitoredContract.monitoring_config,
        ).where(MonitoredContract.is_active.is_(True))
    ).all()
    for monitored_id, address, chain, config in rows:
        try:
            chain_id = chain_by_name(chain).chain_id
        except (UnknownChainError, TypeError):
            continue
        specs = (config or {}).get("tracked_topics") if isinstance(config, dict) else None
        if not isinstance(address, str) or not isinstance(specs, list):
            continue
        for spec in specs:
            topic0 = spec.get("topic0") if isinstance(spec, dict) else None
            if isinstance(topic0, str):
                out[(chain_id, address.lower(), topic0.lower())].append(
                    {
                        "monitored_id": str(monitored_id),
                        "witness_tier": spec.get("witness_tier"),
                        "indexed": tracked_spec_enrols(spec),
                    }
                )
    return out


def plan_retirement(
    session: Session,
    *,
    chain_id: int | None = None,
    addresses: Sequence[str] | None = None,
    abi_lookup: AbiLookup | None = None,
    unresolved_checks: list[dict[str, Any]] | None = None,
) -> list[CursorVerdict]:
    """Every cursor in scope with its gate evidence. Read-only.

    ``unresolved_checks`` receives the external checks whose target address no controller value names: gate 5′ can't
    place them, so they are shown rather than assumed harmless.
    """
    query = select(
        IndexedEventCursor.chain_id,
        func.lower(IndexedEventCursor.event_address),
        func.lower(IndexedEventCursor.topic0),
        IndexedEventCursor.enrollment_basis,
    ).order_by(IndexedEventCursor.chain_id, func.lower(IndexedEventCursor.event_address), IndexedEventCursor.topic0)
    if chain_id is not None:
        query = query.where(IndexedEventCursor.chain_id == chain_id)
    if addresses is not None:
        query = query.where(func.lower(IndexedEventCursor.event_address).in_(sorted({a.lower() for a in addresses})))
    cursors = session.execute(query).all()
    if not cursors:
        return []
    groups = sorted({(int(c), str(a)) for c, a, _t, _b in cursors})
    row_counts = {
        (int(c), str(a), str(t)): int(n)
        for c, a, t, n in session.execute(
            select(
                IndexedEventLog.chain_id,
                func.lower(IndexedEventLog.event_address),
                IndexedEventLog.topic0,
                func.count(),
            )
            .where(tuple_(IndexedEventLog.chain_id, func.lower(IndexedEventLog.event_address)).in_(groups))
            .group_by(IndexedEventLog.chain_id, func.lower(IndexedEventLog.event_address), IndexedEventLog.topic0)
        )
    }
    restaking_cursors = {
        (int(c), str(a))
        for c, a in session.execute(
            select(IndexedEventCursor.chain_id, func.lower(IndexedEventCursor.event_address))
            .where(func.lower(IndexedEventCursor.topic0) == PUBKEY_LINKED_TOPIC0)
            .distinct()
        )
    }
    restaking_rows = {
        (int(c), str(a))
        for c, a in session.execute(
            select(IndexedEventLog.chain_id, func.lower(IndexedEventLog.event_address))
            .where(IndexedEventLog.topic0 == PUBKEY_LINKED_TOPIC0)
            .where(tuple_(IndexedEventLog.chain_id, func.lower(IndexedEventLog.event_address)).in_(groups))
            .distinct()
        )
    }
    witnesses = {
        (int(c), str(a)): {"outcome": outcome, "first_indexed_block": block}
        for c, a, outcome, block in session.execute(
            select(
                AddressFloorWitness.chain_id,
                AddressFloorWitness.address,
                AddressFloorWitness.outcome,
                AddressFloorWitness.first_indexed_block,
            ).where(tuple_(AddressFloorWitness.chain_id, AddressFloorWitness.address).in_(groups))
        )
    }
    cursors_per_group = defaultdict(int)
    for c, a, _t, _b in session.execute(
        select(
            IndexedEventCursor.chain_id,
            func.lower(IndexedEventCursor.event_address),
            IndexedEventCursor.topic0,
            IndexedEventCursor.enrollment_basis,
        ).where(tuple_(IndexedEventCursor.chain_id, func.lower(IndexedEventCursor.event_address)).in_(groups))
    ):
        cursors_per_group[(int(c), str(a))] += 1
    specs = _monitored_specs(session)
    replay = _replay_jobs(session)
    if unresolved_checks is not None:
        unresolved_checks[:] = replay.unresolved_checks
    role_store_topics = {t.lower() for t in all_topic0s()}
    abi_cache: dict[tuple[int, str], list[dict[str, Any]] | None] = {}
    lookup = abi_lookup if abi_lookup is not None else etherscan_abi

    def check_gate(group: tuple[int, str]) -> dict[str, Any]:
        checks = replay.checks.get(group, [])
        if not checks:
            return {"pass": True, "evidence": {"checks": []}}
        if group not in abi_cache:
            abi_cache[group] = lookup(*group)
        recorded = []
        blocking = False
        for check in checks:
            outputs, abi_signature = _callee_outputs(abi_cache[group], check["callee_selector"])
            void = outputs == []
            blocking |= not void
            recorded.append(
                {
                    **check,
                    "abi_signature": abi_signature,
                    "abi_outputs": outputs if outputs is not None else "not_determined",
                    "blocks": not void,
                }
            )
        return {"pass": not blocking, "evidence": {"checks": recorded}}

    verdicts: list[CursorVerdict] = []
    check_results: dict[tuple[int, str], dict[str, Any]] = {}
    for c, a, t, basis in cursors:
        group = (int(c), str(a))
        key = (int(c), str(a), str(t))
        verdict = CursorVerdict(chain_id=key[0], address=key[1], topic0=key[2], enrollment_basis=basis, rows=0)
        verdict.rows = row_counts.get(key, 0)
        verdict.gates["tracked_basis"] = {
            "pass": basis in _RETIRABLE_BASES,
            "evidence": {"enrollment_basis": basis},
        }
        key_specs = specs.get(key, [])
        verdict.gates["no_indexed_spec"] = {
            "pass": not any(spec["indexed"] for spec in key_specs),
            "evidence": {"specs": key_specs},
        }
        hint_jobs = list(replay.hint_keys.get(key, []))
        role_jobs = replay.role_store_addresses.get(group, []) if key[2] in role_store_topics else []
        verdict.gates["no_predicate_hint"] = {
            "pass": not hint_jobs and not role_jobs,
            "evidence": {"hint_jobs": sorted(set(hint_jobs)), "role_store_gate_jobs": sorted(set(role_jobs))},
        }
        verdict.gates["not_restaking_emitter"] = {
            "pass": group not in restaking_cursors and group not in restaking_rows,
            "evidence": {
                "pubkey_linked_cursor": group in restaking_cursors,
                "pubkey_linked_rows": group in restaking_rows,
            },
        }
        if group not in check_results:
            check_results[group] = check_gate(group)
        verdict.gates["no_materializable_check"] = check_results[group]
        verdicts.append(verdict)

    retiring: dict[tuple[int, str], int] = defaultdict(int)
    for verdict in verdicts:
        if all(verdict.gates[name]["pass"] for name in GATES[:-1]):
            retiring[(verdict.chain_id, verdict.address)] += 1
    for verdict in verdicts:
        group = (verdict.chain_id, verdict.address)
        remaining = cursors_per_group[group] - retiring[group]
        witness = witnesses.get(group)
        verdict.gates["floor_witness_kept"] = {
            "pass": remaining > 0 or witness is not None,
            "evidence": {"cursors_left_after_retirement": remaining, "floor_witness": witness},
        }
    return verdicts


def _retire_cursor(session: Session, verdict: CursorVerdict, *, batch_rows: int) -> int | None:
    """Delete one cursor's rows in bounded transactions, the cursor with the final batch; returns rows deleted, or
    ``None`` when the cursor is no longer a tracked one at its first lock (nothing is deleted then).

    The first transaction marks the cursor ``retiring`` under its row lock, so no enrolment upgrade can make the partly
    deleted cursor eligible between batches.
    """
    cursor_filter = (
        (IndexedEventCursor.chain_id == verdict.chain_id)
        & (func.lower(IndexedEventCursor.event_address) == verdict.address)
        & (func.lower(IndexedEventCursor.topic0) == verdict.topic0)
    )
    log_filter = (
        (IndexedEventLog.chain_id == verdict.chain_id)
        & (func.lower(IndexedEventLog.event_address) == verdict.address)
        & (IndexedEventLog.topic0 == verdict.topic0)
    )
    deleted = 0
    while True:
        # The cursor lock first, as every indexer write takes it, so no page lands rows behind the final batch.
        held = session.execute(
            select(IndexedEventCursor.enrollment_basis).where(cursor_filter).with_for_update()
        ).first()
        if held is None:
            session.rollback()
            return deleted
        if held[0] not in _RETIRABLE_BASES:
            session.rollback()
            logger.warning(
                "cursor basis changed since its gates were evaluated; not retired",
                extra={
                    "chain_id": verdict.chain_id,
                    "event_address": verdict.address,
                    "topic0": verdict.topic0,
                    "enrollment_basis": held[0],
                },
            )
            return None
        if held[0] != ENROLLMENT_BASIS_RETIRING:
            session.execute(
                update(IndexedEventCursor).where(cursor_filter).values(enrollment_basis=ENROLLMENT_BASIS_RETIRING)
            )
        keys = session.execute(
            select(
                IndexedEventLog.chain_id,
                IndexedEventLog.event_address,
                IndexedEventLog.topic0,
                IndexedEventLog.tx_hash,
                IndexedEventLog.log_index,
            )
            .where(log_filter)
            .order_by(IndexedEventLog.block_number, IndexedEventLog.log_index)
            .limit(batch_rows)
        ).all()
        if keys:
            session.execute(
                delete(IndexedEventLog).where(
                    tuple_(
                        IndexedEventLog.chain_id,
                        IndexedEventLog.event_address,
                        IndexedEventLog.topic0,
                        IndexedEventLog.tx_hash,
                        IndexedEventLog.log_index,
                    ).in_([tuple(k) for k in keys])
                )
            )
            deleted += len(keys)
        if len(keys) < batch_rows:
            session.execute(delete(IndexedEventCursor).where(cursor_filter))
            session.commit()
            return deleted
        session.commit()


def apply_retirement(
    session: Session,
    *,
    addresses: Sequence[str],
    chain_id: int | None = None,
    abi_lookup: AbiLookup | None = None,
    batch_rows: int = DELETE_BATCH_ROWS,
    acknowledge_unresolved_checks: bool = False,
) -> list[CursorVerdict]:
    """Retire the retirable cursors at ``addresses``, re-evaluating every gate first; returns the retired set.

    Refuses to delete anything while an external check has no resolvable target, unless the operator acknowledges
    having reviewed them.
    """
    if not addresses:
        raise ValueError("--apply needs an explicit address list")
    unresolved: list[dict[str, Any]] = []
    verdicts = plan_retirement(
        session, chain_id=chain_id, addresses=addresses, abi_lookup=abi_lookup, unresolved_checks=unresolved
    )
    session.rollback()
    if unresolved and not acknowledge_unresolved_checks:
        raise UnresolvedChecks(unresolved)
    retired = []
    for verdict in (v for v in verdicts if v.retirable):
        rows = _retire_cursor(session, verdict, batch_rows=batch_rows)
        if rows is None:
            continue
        verdict.rows = rows
        retired.append(verdict)
        logger.info(
            "retired event cursor",
            extra={
                "chain_id": verdict.chain_id,
                "event_address": verdict.address,
                "topic0": verdict.topic0,
                "rows_deleted": verdict.rows,
            },
        )
    return retired


class UnresolvedChecks(RuntimeError):
    def __init__(self, checks: list[dict[str, Any]]) -> None:
        super().__init__(
            f"{len(checks)} external check(s) have no resolvable target; review them in the dry run and pass "
            "--acknowledge-unresolved-checks"
        )
        self.checks = checks


def _summary(verdicts: Sequence[CursorVerdict], *, applied: bool) -> dict[str, Any]:
    retirable = [v for v in verdicts if v.retirable]
    blocked: dict[str, int] = defaultdict(int)
    for verdict in verdicts:
        for name in GATES:
            if not verdict.gates[name]["pass"]:
                blocked[name] += 1
    return {
        "mode": "apply" if applied else "dry_run",
        "cursors_in_scope": len(verdicts),
        "retirable_cursors": len(retirable),
        "retirable_rows": sum(v.rows for v in retirable),
        "retirable_addresses": sorted({f"{v.chain_id}:{v.address}" for v in retirable}),
        "blocked_by_gate": dict(blocked),
    }


def main(argv: Sequence[str] | None = None, *, session_factory: Callable[[], Session] = SessionLocal) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m workers.retire_event_cursors", description=(__doc__ or "").split("\n")[0]
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="print every cursor's gate evidence (default)")
    mode.add_argument("--apply", action="store_true", help="retire the retirable cursors at --addresses")
    parser.add_argument("--addresses", default="", help="comma-separated addresses; required with --apply")
    parser.add_argument("--chain-id", type=int, default=None)
    parser.add_argument(
        "--acknowledge-unresolved-checks",
        action="store_true",
        help="apply even though some external checks have no resolvable target (listed by the dry run)",
    )
    args = parser.parse_args(argv)
    addresses = [a.strip().lower() for a in args.addresses.split(",") if a.strip()]
    if args.apply and not addresses:
        parser.error("--apply needs --addresses")
    unresolved: list[dict[str, Any]] = []
    with session_factory() as session:
        if args.apply:
            try:
                verdicts = apply_retirement(
                    session,
                    addresses=addresses,
                    chain_id=args.chain_id,
                    acknowledge_unresolved_checks=args.acknowledge_unresolved_checks,
                )
            except UnresolvedChecks as exc:
                print(json.dumps({"unresolved_external_checks": exc.checks}, sort_keys=True, default=str))
                print(json.dumps({"error": str(exc)}))
                return 2
        else:
            verdicts = plan_retirement(
                session, chain_id=args.chain_id, addresses=addresses or None, unresolved_checks=unresolved
            )
            session.rollback()
    for verdict in verdicts:
        print(json.dumps(verdict.to_json(), sort_keys=True, default=str))
    if not args.apply:
        print(json.dumps({"unresolved_external_checks": unresolved}, sort_keys=True, default=str))
    summary = _summary(verdicts, applied=args.apply)
    if not args.apply:
        summary["unresolved_external_checks"] = len(unresolved)
    print(json.dumps({"summary": summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    configure_logging()
    sys.exit(main())
