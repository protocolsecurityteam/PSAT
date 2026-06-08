"""Historical principal intervals derived from semantic authority events."""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from eth_utils.crypto import keccak

from services.resolution.capability_resolver import _selector_for_signature
from utils.logging import record_stage_metric
from utils.rpc import default_rpc_url, rpc_request

logger = logging.getLogger(__name__)

MAX_LOGS_PER_TOPIC = int(os.getenv("PSAT_PRINCIPAL_HISTORY_MAX_LOGS_PER_TOPIC", "10000"))
_LOG_BLOCK_RANGE = int(os.getenv("PSAT_PRINCIPAL_HISTORY_BLOCK_RANGE", "10000"))
_MAX_LOG_WINDOWS = int(os.getenv("PSAT_PRINCIPAL_HISTORY_MAX_LOG_WINDOWS", "5000"))
_LOG_CACHE: dict[tuple[int, str, str], list[dict[str, Any]]] = {}

_ROLE_AUTHORITY_EVENT_TOPICS = {
    "role_capability": "0x" + keccak(text="RoleCapabilityUpdated(uint8,address,bytes4,bool)").hex(),
    "public_capability": "0x" + keccak(text="PublicCapabilityUpdated(address,bytes4,bool)").hex(),
    "user_role": "0x" + keccak(text="UserRoleUpdated(address,uint8,bool)").hex(),
}


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
        authority_history = build_role_authority_history(
            authority_address=authority_address,
            chain_id=chain_id,
            functions=functions,
        )
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
    event_topics = _classify_role_event_topics(abi) if abi is not None else dict(_ROLE_AUTHORITY_EVENT_TOPICS)
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
            raise RuntimeError("principal history user role log missing indexed topics")
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
            raise RuntimeError("principal history role capability log missing indexed topics")
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
            raise RuntimeError("principal history public capability log missing indexed topics")
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


def _fetch_logs(*, authority_address: str, chain_id: int, topic0: str) -> list[dict[str, Any]]:
    cache_key = (chain_id, authority_address.lower(), topic0.lower())
    cached = _LOG_CACHE.get(cache_key)
    if cached is not None:
        return cached
    rpc_url = default_rpc_url(chain_id=chain_id)
    head_raw = rpc_request(rpc_url, "eth_blockNumber", [], chain_id=chain_id)
    if not isinstance(head_raw, str) or not head_raw.startswith("0x"):
        logger.error(
            "principal history eth_blockNumber returned invalid payload chain_id=%s authority=%s: %r",
            chain_id,
            authority_address,
            head_raw,
        )
        raise RuntimeError(f"principal history eth_blockNumber returned invalid payload for chain_id={chain_id}")
    head_block = int(head_raw, 16)

    out: list[dict[str, Any]] = []
    current_from = 0
    windows = 0
    while current_from <= head_block:
        if windows >= _MAX_LOG_WINDOWS:
            logger.error(
                "principal history eRPC getLogs hit max windows chain_id=%s authority=%s topic0=%s last_block=%s",
                chain_id,
                authority_address,
                topic0,
                current_from,
            )
            raise RuntimeError(f"principal history eRPC getLogs hit max windows for chain_id={chain_id}")
        current_to = min(head_block, current_from + _LOG_BLOCK_RANGE - 1)
        filter_params = {
            "address": authority_address.lower(),
            "topics": [topic0.lower()],
            "fromBlock": hex(current_from),
            "toBlock": hex(current_to),
        }
        try:
            batch = rpc_request(rpc_url, "eth_getLogs", [filter_params], chain_id=chain_id)
        except Exception as exc:
            logger.error(
                "principal history eRPC getLogs failed chain_id=%s authority=%s topic0=%s blocks=%d-%d: %s",
                chain_id,
                authority_address,
                topic0,
                current_from,
                current_to,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            raise RuntimeError(f"principal history eRPC getLogs failed for chain_id={chain_id}") from exc
        if not isinstance(batch, list):
            logger.error(
                "principal history eRPC getLogs returned invalid payload chain_id=%s authority=%s topic0=%s: %r",
                chain_id,
                authority_address,
                topic0,
                batch,
            )
            raise RuntimeError(f"principal history eRPC getLogs returned invalid payload for chain_id={chain_id}")
        for log in batch:
            if not isinstance(log, dict):
                logger.error(
                    "principal history eRPC getLogs returned malformed log chain_id=%s authority=%s "
                    "topic0=%s blocks=%d-%d: %r",
                    chain_id,
                    authority_address,
                    topic0,
                    current_from,
                    current_to,
                    log,
                )
                raise RuntimeError(f"principal history eRPC getLogs returned malformed log for chain_id={chain_id}")
            topics = log.get("topics")
            if (
                not isinstance(topics, list)
                or not topics
                or not all(_is_topic(topic) for topic in topics)
                or str(topics[0]).lower() != topic0.lower()
            ):
                logger.error(
                    "principal history eRPC getLogs returned invalid topics chain_id=%s authority=%s "
                    "topic0=%s blocks=%d-%d: %r",
                    chain_id,
                    authority_address,
                    topic0,
                    current_from,
                    current_to,
                    topics,
                )
                raise RuntimeError(f"principal history eRPC getLogs returned invalid topics for chain_id={chain_id}")
            data = log.get("data")
            if not isinstance(data, str) or not data.startswith("0x"):
                logger.error(
                    "principal history eRPC getLogs returned invalid data chain_id=%s authority=%s "
                    "topic0=%s blocks=%d-%d: %r",
                    chain_id,
                    authority_address,
                    topic0,
                    current_from,
                    current_to,
                    data,
                )
                raise RuntimeError(f"principal history eRPC getLogs returned invalid data for chain_id={chain_id}")
            try:
                bytes.fromhex(data[2:])
            except ValueError as exc:
                logger.error(
                    "principal history eRPC getLogs returned malformed data chain_id=%s authority=%s "
                    "topic0=%s blocks=%d-%d",
                    chain_id,
                    authority_address,
                    topic0,
                    current_from,
                    current_to,
                )
                raise RuntimeError(
                    f"principal history eRPC getLogs returned malformed data for chain_id={chain_id}"
                ) from exc
            out.append(log)
        if len(out) > MAX_LOGS_PER_TOPIC:
            raise RuntimeError(f"principal history log cap exceeded for {authority_address} topic {topic0}")
        windows += 1
        current_from = current_to + 1
    _LOG_CACHE[cache_key] = list(out)
    return out


def _topic_address(topic: str) -> str:
    if not _is_topic(topic):
        raise ValueError(f"malformed topic address: {topic!r}")
    return "0x" + str(topic)[-40:].lower()


def _topic_uint(topic: str) -> int:
    if not _is_topic(topic):
        raise ValueError(f"malformed topic uint: {topic!r}")
    return int(str(topic), 16)


def _topic_bytes4(topic: str) -> str:
    if not _is_topic(topic):
        raise ValueError(f"malformed topic bytes4: {topic!r}")
    return "0x" + str(topic)[2:10].lower()


def _data_bool(data: Any) -> bool:
    if not isinstance(data, str) or not data.startswith("0x") or len(data) != 66:
        raise ValueError(f"malformed bool event data: {data!r}")
    try:
        return int(data, 16) != 0
    except ValueError as exc:
        raise ValueError(f"malformed bool event data: {data!r}") from exc


def _is_topic(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        return False
    try:
        bytes.fromhex(value[2:])
    except ValueError:
        return False
    return True


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
