"""Historical principal intervals derived from semantic authority events."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

import requests
from eth_utils.crypto import keccak

from services.resolution.capability_resolver import _selector_for_signature
from utils.etherscan import ETHERSCAN_API
from utils.logging import record_degraded, record_stage_metric

logger = logging.getLogger(__name__)

MAX_LOGS_PER_TOPIC = int(os.getenv("PSAT_PRINCIPAL_HISTORY_MAX_LOGS_PER_TOPIC", "10000"))

# Process-wide cache of an authority's full role-event log history, keyed
# (chain_id, authority, topic0) so the contracts sharing one authority fetch it
# once. Size-capped with oldest-fraction eviction; entries carry a monotonic
# insert time and a medium TTL so a later grant/revoke is eventually re-read.
_LOG_CACHE: dict[tuple[int, str, str], tuple[list[dict[str, Any]], float]] = {}
_LOG_CACHE_LOCK = threading.Lock()
_LOG_CACHE_MAX = 256
_LOG_CACHE_TTL_S = float(os.getenv("PSAT_PRINCIPAL_LOG_CACHE_TTL_S", "1800"))


def clear_log_cache() -> None:
    """Clear the process-wide authority-log cache. For tests + manual reset."""
    from utils.memory import reset_cache_pressure_state

    with _LOG_CACHE_LOCK:
        _LOG_CACHE.clear()
    reset_cache_pressure_state("principal_log")


def _evict_log_cache_if_needed() -> None:
    """Drop the oldest 25% of _LOG_CACHE entries when the bound is reached (caller holds _LOG_CACHE_LOCK)."""
    if len(_LOG_CACHE) < _LOG_CACHE_MAX:
        return
    cutoff = sorted(_LOG_CACHE.values(), key=lambda v: v[1])[len(_LOG_CACHE) // 4][1]
    for k in [k for k, v in _LOG_CACHE.items() if v[1] <= cutoff]:
        _LOG_CACHE.pop(k, None)


def _log_principal_log_pressure() -> None:
    """Log when _LOG_CACHE crosses 50/75/95% of its bound (caller holds the lock)."""
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("principal_log", len(_LOG_CACHE), _LOG_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def build_principal_history(
    *,
    contract_address: str,
    chain_id: int,
    predicate_trees: dict[str, Any] | None,
    state_var_values: dict[str, str],
) -> dict[str, Any]:
    """Build a historical permission artifact for external semantic checks.

    The artifact is deliberately separate from ``FunctionPrincipal`` rows:
    rows remain current-state caller principals, while this payload records
    role/capability intervals when the external authority exposes enough
    event structure to replay them.
    """
    contract_address = contract_address.lower()
    checks = _external_authority_checks(
        contract_address=contract_address,
        predicate_trees=predicate_trees or {},
        state_var_values=state_var_values,
    )
    if not checks:
        return _empty_payload(contract_address=contract_address, chain_id=chain_id, status="no_external_authority")

    functions_by_authority: dict[str, dict[tuple[str, str], str]] = defaultdict(dict)
    for check in checks:
        functions_by_authority[check["authority_address"]][(contract_address, check["selector"])] = check["function"]

    sources: list[dict[str, Any]] = []
    role_membership: list[dict[str, Any]] = []
    capability_roles: list[dict[str, Any]] = []
    function_permissions: list[dict[str, Any]] = []
    public_capabilities: list[dict[str, Any]] = []

    for authority_address, functions in sorted(functions_by_authority.items()):
        try:
            authority_history = build_role_authority_history(
                authority_address=authority_address,
                chain_id=chain_id,
                functions=functions,
            )
        except Exception as exc:
            record_degraded(
                phase="principal_history_authority",
                exc=exc,
                context={"authority_address": authority_address},
            )
            logger.warning(
                "principal history failed for authority %s: %s",
                authority_address,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            sources.append(
                {
                    "authority_address": authority_address,
                    "status": "error",
                    "reason": str(exc),
                }
            )
            continue
        sources.append(authority_history["source"])
        role_membership.extend(authority_history["role_membership"])
        capability_roles.extend(authority_history["capability_roles"])
        function_permissions.extend(authority_history["function_permissions"])
        public_capabilities.extend(authority_history["public_capabilities"])

    status = "ok" if any(source.get("status") == "ok" for source in sources) else "unsupported"
    n_ok = sum(1 for source in sources if source.get("status") == "ok")
    n_unsupported = sum(1 for source in sources if source.get("status") == "unsupported")
    n_error = sum(1 for source in sources if source.get("status") == "error")
    total_role_events = sum(
        sum(v for v in (source.get("events") or {}).values() if isinstance(v, int))
        for source in sources
        if isinstance(source.get("events"), dict)
    )
    logger.info(
        "principal history: %d authorities (ok=%d unsupported=%d error=%d, %d role events)",
        len(sources),
        n_ok,
        n_unsupported,
        n_error,
        total_role_events,
        extra={
            "authority_count": len(sources),
            "ok": n_ok,
            "unsupported": n_unsupported,
            "error": n_error,
            "total_role_events": total_role_events,
        },
    )
    record_stage_metric("principal_history_authorities", len(sources))
    record_stage_metric("principal_history_role_events", total_role_events)
    return {
        "schema_version": "principal_history.v1",
        "contract_address": contract_address,
        "chain_id": chain_id,
        "status": status,
        "sources": sources,
        "role_membership": role_membership,
        "capability_roles": capability_roles,
        "function_permissions": function_permissions,
        "public_capabilities": public_capabilities,
    }


def build_role_authority_history(
    *,
    authority_address: str,
    chain_id: int,
    functions: dict[tuple[str, str], str],
    abi: list[dict[str, Any]] | None = None,
    logs_by_topic: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    authority_address = authority_address.lower()
    abi = abi if abi is not None else _fetch_abi(authority_address, chain_id)
    event_topics = _classify_role_event_topics(abi)
    if event_topics is None:
        return {
            "source": {
                "authority_address": authority_address,
                "status": "unsupported",
                "reason": "authority_event_shapes_not_supported",
            },
            "role_membership": [],
            "capability_roles": [],
            "function_permissions": [],
            "public_capabilities": [],
        }

    if logs_by_topic is None:
        logs_by_topic = {
            topic0: _fetch_logs(authority_address=authority_address, chain_id=chain_id, topic0=topic0)
            for topic0 in event_topics.values()
        }

    events = _decode_authority_events(event_topics=event_topics, logs_by_topic=logs_by_topic)
    history = _replay_role_authority_events(
        authority_address=authority_address,
        functions=functions,
        events=events,
    )
    history["source"] = {
        "authority_address": authority_address,
        "status": "ok",
        "mode": "role_capability_event_replay",
        "event_topics": event_topics,
        "events": {name: len(logs_by_topic.get(topic0, [])) for name, topic0 in event_topics.items()},
    }
    return history


def _external_authority_checks(
    *,
    contract_address: str,
    predicate_trees: dict[str, Any],
    state_var_values: dict[str, str],
) -> list[dict[str, str]]:
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return []
    out: list[dict[str, str]] = []
    for function, tree in trees.items():
        if not isinstance(function, str):
            continue
        selector = _selector_for_signature(function, predicate_trees.get("canonical_signatures"))
        if selector is None:
            continue
        for leaf in _walk_leaves(tree):
            if leaf.get("kind") != "external_bool":
                continue
            descriptor = leaf.get("set_descriptor")
            if not isinstance(descriptor, dict) or descriptor.get("kind") != "external_set":
                continue
            authority = descriptor.get("authority_contract") or {}
            address_source = authority.get("address_source") or {}
            state_var_name = address_source.get("state_variable_name")
            authority_address = state_var_values.get(state_var_name) if isinstance(state_var_name, str) else None
            if not _is_address(authority_address):
                continue
            authority_address_str = str(authority_address).lower()
            operands = leaf.get("operands") or []
            if not _has_target_selector_call_shape(operands):
                continue
            out.append(
                {
                    "function": function,
                    "selector": selector,
                    "contract_address": contract_address,
                    "authority_address": authority_address_str,
                }
            )
    return out


def _walk_leaves(node: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(node, dict):
        return
    if node.get("op") == "LEAF":
        leaf = node.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in node.get("children") or []:
        yield from _walk_leaves(child)


def _has_target_selector_call_shape(operands: list[Any]) -> bool:
    sources = [operand.get("source") for operand in operands if isinstance(operand, dict)]
    return (
        any(source in {"msg_sender", "tx_origin", "signature_recovery", "root_caller"} for source in sources)
        and "self_address" in sources
        and any(
            operand.get("source") == "computed" and operand.get("computed_kind") == "msg.sig"
            for operand in operands
            if isinstance(operand, dict)
        )
    )


def _classify_role_event_topics(abi: list[dict[str, Any]]) -> dict[str, str] | None:
    topics: dict[str, str] = {}
    for entry in abi:
        if entry.get("type") != "event":
            continue
        inputs = list(entry.get("inputs") or [])
        indexed = [inp for inp in inputs if inp.get("indexed")]
        unindexed = [inp for inp in inputs if not inp.get("indexed")]
        indexed_types = [str(inp.get("type")) for inp in indexed]
        unindexed_types = [str(inp.get("type")) for inp in unindexed]
        topic0 = _event_topic(entry)
        if topic0 is None:
            continue
        if indexed_types == ["address", "uint8"] and unindexed_types == ["bool"]:
            topics["user_role"] = topic0
        elif indexed_types == ["uint8", "address", "bytes4"] and unindexed_types == ["bool"]:
            topics["role_capability"] = topic0
        elif indexed_types == ["address", "bytes4"] and unindexed_types == ["bool"]:
            topics["public_capability"] = topic0
    required = {"user_role", "role_capability", "public_capability"}
    return topics if required <= topics.keys() else None


def _event_topic(entry: dict[str, Any]) -> str | None:
    name = entry.get("name")
    inputs = entry.get("inputs")
    if not isinstance(name, str) or not isinstance(inputs, list):
        return None
    signature = f"{name}({','.join(str(inp.get('type', '')) for inp in inputs)})"
    return "0x" + keccak(text=signature).hex()


def _decode_authority_events(
    *,
    event_topics: dict[str, str],
    logs_by_topic: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    decoded: list[dict[str, Any]] = []
    for log in logs_by_topic.get(event_topics["user_role"], []):
        topics = log.get("topics") or []
        if len(topics) < 3:
            continue
        decoded.append(
            _event_base(log)
            | {
                "kind": "user_role",
                "principal": _topic_address(topics[1]),
                "role": _topic_uint(topics[2]),
                "enabled": _data_bool(log.get("data")),
            }
        )
    for log in logs_by_topic.get(event_topics["role_capability"], []):
        topics = log.get("topics") or []
        if len(topics) < 4:
            continue
        decoded.append(
            _event_base(log)
            | {
                "kind": "role_capability",
                "role": _topic_uint(topics[1]),
                "target": _topic_address(topics[2]),
                "selector": _topic_bytes4(topics[3]),
                "enabled": _data_bool(log.get("data")),
            }
        )
    for log in logs_by_topic.get(event_topics["public_capability"], []):
        topics = log.get("topics") or []
        if len(topics) < 3:
            continue
        decoded.append(
            _event_base(log)
            | {
                "kind": "public_capability",
                "target": _topic_address(topics[1]),
                "selector": _topic_bytes4(topics[2]),
                "enabled": _data_bool(log.get("data")),
            }
        )
    return sorted(decoded, key=lambda item: (item["block_number"], item["transaction_index"], item["log_index"]))


def _replay_role_authority_events(
    *,
    authority_address: str,
    functions: dict[tuple[str, str], str],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    user_roles: dict[str, int] = defaultdict(int)
    role_caps: dict[tuple[str, str], int] = defaultdict(int)
    public_caps: dict[tuple[str, str], bool] = defaultdict(bool)
    role_intervals: dict[tuple[str, int], dict[str, Any]] = {}
    cap_intervals: dict[tuple[str, str, int], dict[str, Any]] = {}
    public_intervals: dict[tuple[str, str], dict[str, Any]] = {}
    permission_intervals: dict[tuple[str, str], dict[str, Any]] = {}

    closed_roles: list[dict[str, Any]] = []
    closed_caps: list[dict[str, Any]] = []
    closed_public: list[dict[str, Any]] = []
    closed_permissions: list[dict[str, Any]] = []

    def recompute_permissions(event: dict[str, Any]) -> None:
        principals = sorted(user_roles)
        for target_selector, function in functions.items():
            required_mask = role_caps.get(target_selector, 0)
            for principal in principals:
                roles = _roles_from_mask(user_roles[principal] & required_mask)
                key = (function, principal)
                current = permission_intervals.get(key)
                if roles and current is None:
                    permission_intervals[key] = _interval_start(
                        event,
                        authority_address=authority_address,
                        function=function,
                        selector=target_selector[1],
                        principal=principal,
                        roles=roles,
                    )
                elif roles and current is not None and current.get("roles") != roles:
                    closed_permissions.append(_interval_end(current, event))
                    permission_intervals[key] = _interval_start(
                        event,
                        authority_address=authority_address,
                        function=function,
                        selector=target_selector[1],
                        principal=principal,
                        roles=roles,
                    )
                elif not roles and current is not None:
                    closed_permissions.append(_interval_end(current, event))
                    del permission_intervals[key]

    for event in events:
        kind = event["kind"]
        if kind == "user_role":
            principal = event["principal"]
            role = int(event["role"])
            bit = 1 << role
            key = (principal, role)
            if event["enabled"]:
                user_roles[principal] |= bit
                role_intervals.setdefault(
                    key,
                    _interval_start(event, authority_address=authority_address, principal=principal, role=role),
                )
            else:
                user_roles[principal] &= ~bit
                if key in role_intervals:
                    closed_roles.append(_interval_end(role_intervals.pop(key), event))
        elif kind == "role_capability":
            target_selector = (event["target"], event["selector"])
            role = int(event["role"])
            bit = 1 << role
            key = (target_selector[0], target_selector[1], role)
            if event["enabled"]:
                role_caps[target_selector] |= bit
                cap_intervals.setdefault(
                    key,
                    _interval_start(
                        event,
                        authority_address=authority_address,
                        target_address=target_selector[0],
                        selector=target_selector[1],
                        function=functions.get(target_selector),
                        role=role,
                    ),
                )
            else:
                role_caps[target_selector] &= ~bit
                if key in cap_intervals:
                    closed_caps.append(_interval_end(cap_intervals.pop(key), event))
        elif kind == "public_capability":
            target_selector = (event["target"], event["selector"])
            if target_selector not in functions:
                continue
            if event["enabled"]:
                public_caps[target_selector] = True
                public_intervals.setdefault(
                    target_selector,
                    _interval_start(
                        event,
                        authority_address=authority_address,
                        target_address=target_selector[0],
                        selector=target_selector[1],
                        function=functions.get(target_selector),
                    )
                    | {"public": True},
                )
            else:
                public_caps[target_selector] = False
                if target_selector in public_intervals:
                    closed_public.append(_interval_end(public_intervals.pop(target_selector), event))
        recompute_permissions(event)

    active_roles = [_active_interval(value) for value in role_intervals.values()]
    active_caps = [_active_interval(value) for value in cap_intervals.values()]
    active_public = [_active_interval(value) for value in public_intervals.values()]
    active_permissions = [_active_interval(value) for value in permission_intervals.values()]

    return {
        "role_membership": sorted(closed_roles + active_roles, key=_interval_sort_key),
        "capability_roles": sorted(closed_caps + active_caps, key=_interval_sort_key),
        "function_permissions": sorted(closed_permissions + active_permissions, key=_interval_sort_key),
        "public_capabilities": sorted(closed_public + active_public, key=_interval_sort_key),
    }


def _interval_start(event: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        **{key: value for key, value in fields.items() if value is not None},
        "granted_at_block": event["block_number"],
        "granted_at_tx": event["tx_hash"],
        "granted_at_log_index": event["log_index"],
        "revoked_at_block": None,
        "revoked_at_tx": None,
        "revoked_at_log_index": None,
        "status": "active",
    }


def _interval_end(interval: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    out = dict(interval)
    out["revoked_at_block"] = event["block_number"]
    out["revoked_at_tx"] = event["tx_hash"]
    out["revoked_at_log_index"] = event["log_index"]
    out["status"] = "revoked"
    return out


def _active_interval(interval: dict[str, Any]) -> dict[str, Any]:
    out = dict(interval)
    out["status"] = "active"
    return out


def _interval_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(item.get("function") or ""),
        str(item.get("principal") or ""),
        int(item.get("role") or -1),
        int(item.get("granted_at_block") or 0),
        int(item.get("granted_at_log_index") or 0),
    )


def _roles_from_mask(mask: int) -> list[int]:
    return [idx for idx in range(mask.bit_length()) if mask & (1 << idx)]


def _event_base(log: dict[str, Any]) -> dict[str, Any]:
    return {
        "block_number": _hex_int(log.get("blockNumber")),
        "transaction_index": _hex_int(log.get("transactionIndex")),
        "log_index": _hex_int(log.get("logIndex")),
        "tx_hash": str(log.get("transactionHash") or "").lower(),
    }


def _fetch_abi(address: str, chain_id: int) -> list[dict[str, Any]]:
    # ABI is served by utils.etherscan.get, which carries the durable PG layer
    # and a bounded in-memory LRU — no third copy here.
    from utils.etherscan import get

    data = get("contract", "getabi", chain_id=chain_id, address=address)
    raw = data.get("result")
    decoded = json.loads(raw) if isinstance(raw, str) else raw
    return decoded if isinstance(decoded, list) else []


def _fetch_logs(*, authority_address: str, chain_id: int, topic0: str) -> list[dict[str, Any]]:
    cache_key = (chain_id, authority_address.lower(), topic0.lower())
    now = time.monotonic()
    with _LOG_CACHE_LOCK:
        cached = _LOG_CACHE.get(cache_key)
        if cached is not None:
            logs, inserted_at = cached
            if now - inserted_at < _LOG_CACHE_TTL_S:
                return logs
            del _LOG_CACHE[cache_key]
    api_key = os.getenv("ETHERSCAN_API_KEY")
    if not api_key:
        raise RuntimeError("ETHERSCAN_API_KEY not set")
    out: list[dict[str, Any]] = []
    page = 1
    while True:
        response = requests.get(
            ETHERSCAN_API,
            params={
                "chainid": str(chain_id),
                "module": "logs",
                "action": "getLogs",
                "address": authority_address,
                "fromBlock": "0",
                "toBlock": "latest",
                "topic0": topic0,
                "page": str(page),
                "offset": "1000",
                "apikey": api_key,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "1":
            batch = data.get("result") or []
        elif str(data.get("result", "")).lower() in {"no records found", ""}:
            batch = []
        else:
            raise RuntimeError(f"Etherscan logs error: {data.get('message')} - {data.get('result')}")
        out.extend(batch)
        if len(out) > MAX_LOGS_PER_TOPIC:
            raise RuntimeError(f"principal history log cap exceeded for {authority_address} topic {topic0}")
        if len(batch) < 1000:
            with _LOG_CACHE_LOCK:
                _evict_log_cache_if_needed()
                _LOG_CACHE[cache_key] = (list(out), time.monotonic())
                _log_principal_log_pressure()
            return out
        page += 1
        time.sleep(0.25)


def _topic_address(topic: str) -> str:
    return "0x" + str(topic)[-40:].lower()


def _topic_uint(topic: str) -> int:
    return int(str(topic), 16)


def _topic_bytes4(topic: str) -> str:
    return "0x" + str(topic)[2:10].lower()


def _data_bool(data: Any) -> bool:
    return int(str(data or "0x0"), 16) != 0


def _hex_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    raw = str(value or "0")
    return int(raw, 16) if raw.startswith("0x") else int(raw)


def _is_address(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("0x") and len(value) == 42


def _empty_payload(*, contract_address: str, chain_id: int, status: str) -> dict[str, Any]:
    return {
        "schema_version": "principal_history.v1",
        "contract_address": contract_address.lower(),
        "chain_id": chain_id,
        "status": status,
        "sources": [],
        "role_membership": [],
        "capability_roles": [],
        "function_permissions": [],
        "public_capabilities": [],
    }
