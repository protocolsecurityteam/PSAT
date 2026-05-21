"""Runtime bridge context resolvers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from eth_abi.abi import decode, encode
from eth_utils.crypto import keccak

from services.bridges.chains import (
    chain_id_for_chain,
    display_name_for_chain,
    layerzero_eid_entries,
)
from utils.rpc import rpc_batch_request, rpc_request

ZERO_ADDRESS = "0x" + "0" * 40
ZERO_BYTES32 = "0x" + "0" * 64
_ULN_CONFIG_TYPE = 2
_EXECUTOR_CONFIG_TYPE = 1

# Controller `source` substrings the semantic pipeline reads off chain that
# correspond to local-app admin authority. Order matters in
# ``_policy_rank``: stronger access-control signals come first.
_CONTROL_SOURCE_KEYWORDS = ("owner", "authority", "admin", "governor", "governance", "delegate")


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _calldata(signature: str, arg_types: list[str] | None = None, args: list[Any] | None = None) -> str:
    arg_types = arg_types or []
    args = args or []
    return _selector(signature) + (encode(arg_types, args).hex() if arg_types else "")


def _decode_output(output_types: list[str], raw: str | None) -> tuple[Any, ...] | None:
    if not isinstance(raw, str) or raw in {"0x", "0x0"}:
        return None
    try:
        return decode(output_types, bytes.fromhex(raw.removeprefix("0x")))
    except Exception:
        return None


def _call(
    rpc_url: str,
    address: str,
    signature: str,
    arg_types: list[str] | None = None,
    args: list[Any] | None = None,
    output_types: list[str] | None = None,
) -> tuple[Any, ...] | None:
    try:
        raw = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": address, "data": _calldata(signature, arg_types, args)}, "latest"],
            retries=0,
        )
    except Exception:
        return None
    return _decode_output(output_types or [], raw)


def _batch_call(
    rpc_url: str,
    specs: list[tuple[str, str, list[str], list[Any], list[str]]],
) -> list[tuple[Any, ...] | None]:
    if not specs:
        return []
    calls = [
        ("eth_call", [{"to": address, "data": _calldata(signature, arg_types, args)}, "latest"])
        for address, signature, arg_types, args, _output_types in specs
    ]
    try:
        raw_results = rpc_batch_request(rpc_url, calls)
    except Exception:
        return [
            _call(rpc_url, address, signature, arg_types, args, output_types)
            for address, signature, arg_types, args, output_types in specs
        ]
    return [
        _decode_output(output_types, raw)
        for raw, (_address, _signature, _arg_types, _args, output_types) in zip(raw_results, specs)
    ]


def _contract_address(contract: dict[str, Any]) -> str | None:
    address = contract.get("address")
    if not isinstance(address, str):
        subject = contract.get("subject")
        address = subject.get("address") if isinstance(subject, dict) else None
    if isinstance(address, str) and address.startswith("0x") and len(address) == 42:
        return address.lower()
    return None


def _bridge_static_context(contract: dict[str, Any]) -> dict[str, Any]:
    context = contract.get("bridge_static_context")
    return context if isinstance(context, dict) else {}


def _protocol_result(status: str, protocol: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"status": status, "protocol": protocol, "protocols": [protocol], "routes": []}
    if reason:
        out["reason"] = reason
    out.update(extra)
    return out


def _first_address(rpc_url: str, address: str, signatures: list[str]) -> str | None:
    for signature in signatures:
        out = _call(rpc_url, address, signature, output_types=["address"])
        if out and out[0] != ZERO_ADDRESS:
            return str(out[0]).lower()
    return None


def _bytes32_hex(raw: bytes | str | None) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return "0x" + raw.hex()
    return raw.lower()


def _bytes32_to_address(raw: bytes | str | None) -> str | None:
    hex_value = _bytes32_hex(raw)
    if not isinstance(hex_value, str) or hex_value == ZERO_BYTES32 or len(hex_value) != 66:
        return None
    if hex_value[2:26] != "0" * 24:
        return None
    address = "0x" + hex_value[-40:]
    return None if address == ZERO_ADDRESS else address


def _peer_from_decoded(raw: bytes | str | None, signature: str) -> dict[str, Any] | None:
    peer_bytes32 = _bytes32_hex(raw)
    if not peer_bytes32 or peer_bytes32 == ZERO_BYTES32:
        return None
    peer_address = _bytes32_to_address(raw)
    return {
        "peer": peer_address or peer_bytes32,
        "peer_address": peer_address,
        "peer_bytes32": peer_bytes32,
        "peer_source": signature,
    }


def _peer_map_for_eids(rpc_url: str, address: str) -> dict[int, dict[str, Any]]:
    entries = layerzero_eid_entries()
    specs: list[tuple[str, str, list[str], list[Any], list[str]]] = []
    for entry in entries:
        eid = int(entry["eid"])
        specs.append((address, "getReceiver(uint32)", ["uint32"], [eid], ["bytes32"]))
        specs.append((address, "peers(uint32)", ["uint32"], [eid], ["bytes32"]))

    peers: dict[int, dict[str, Any]] = {}
    for index, raw in enumerate(_batch_call(rpc_url, specs)):
        if not raw:
            continue
        eid = int(entries[index // 2]["eid"])
        if eid in peers:
            continue
        peer = _peer_from_decoded(raw[0], specs[index][1])
        if peer:
            peers[eid] = peer
    return peers


def _decode_uln_config(raw: bytes | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        config = decode(["(uint64,uint8,uint8,uint8,address[],address[])"], raw)[0]
    except Exception:
        return None
    confirmations, required_count, optional_count, optional_threshold, required_dvns, optional_dvns = config
    return {
        "confirmations": int(confirmations),
        "required_dvn_count": int(required_count),
        "optional_dvn_count": int(optional_count),
        "optional_dvn_threshold": int(optional_threshold),
        "required_dvns": [str(addr).lower() for addr in required_dvns],
        "optional_dvns": [str(addr).lower() for addr in optional_dvns],
    }


def _decode_executor_config(raw: bytes | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        max_message_size, executor = decode(["uint32", "address"], raw)
    except Exception:
        return None
    return {"max_message_size": int(max_message_size), "executor": str(executor).lower()}


def _endpoint_config(
    rpc_url: str,
    endpoint: str,
    oapp: str,
    library: str | None,
    eid: int,
    config_type: int,
) -> bytes | None:
    if not library:
        return None
    out = _call(
        rpc_url,
        endpoint,
        "getConfig(address,address,uint32,uint32)",
        ["address", "address", "uint32", "uint32"],
        [oapp, library, eid, config_type],
        ["bytes"],
    )
    return out[0] if out and isinstance(out[0], bytes) else None


def _layerzero_route_security(rpc_url: str, endpoint: str, oapp: str, eid: int) -> dict[str, Any]:
    send_library_out = _call(
        rpc_url,
        endpoint,
        "getSendLibrary(address,uint32)",
        ["address", "uint32"],
        [oapp, eid],
        ["address"],
    )
    receive_library_out = _call(
        rpc_url,
        endpoint,
        "getReceiveLibrary(address,uint32)",
        ["address", "uint32"],
        [oapp, eid],
        ["address", "bool"],
    )
    send_library = str(send_library_out[0]).lower() if send_library_out else None
    receive_library = str(receive_library_out[0]).lower() if receive_library_out else None
    send_uln = _decode_uln_config(_endpoint_config(rpc_url, endpoint, oapp, send_library, eid, _ULN_CONFIG_TYPE))
    receive_uln = _decode_uln_config(_endpoint_config(rpc_url, endpoint, oapp, receive_library, eid, _ULN_CONFIG_TYPE))
    executor = _decode_executor_config(
        _endpoint_config(rpc_url, endpoint, oapp, send_library, eid, _EXECUTOR_CONFIG_TYPE)
    )
    return {
        "send_library": send_library,
        "receive_library": receive_library,
        "receive_library_default": bool(receive_library_out[1]) if receive_library_out else None,
        "send_uln": send_uln,
        "receive_uln": receive_uln,
        "executor": executor,
    }


def _policy_rank(policy: dict[str, Any]) -> int:
    """Order policies so the strongest access-control signal sorts first.

    ``_config_control_label`` in services/aggregations/company_overview.py
    only inspects ``policies[0]``, so the head of the list drives the
    user-facing label.
    """
    resolved = str(policy.get("resolved_type") or "").lower()
    source = str(policy.get("source") or "").lower()
    if resolved == "safe":
        return 0
    if resolved == "timelock":
        return 1
    if resolved == "proxy_admin":
        return 2
    if "authority" in source:
        return 3
    if "owner" in source:
        return 4
    if "delegate" in source:
        return 5
    return 6


def _policies_from_control_snapshot(snapshot: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Project the semantic ``control_snapshot`` into bridge ``policies``.

    The semantic resolution layer already probes every controller surfaced
    by static analysis (Solady ``Auth.authority()``, Safe owners, Ownable
    ``owner()``, AccessControl admin roles, etc.) and stores the resolved
    values + types in ``control_snapshot.controller_values``. Surfacing
    them as bridge ``policies`` lets the bridge card inherit every
    controller pattern the semantic layer learns, instead of duplicating a
    narrow ``owner()`` / ``delegate()`` probe that misses ``authority()``.
    """
    if not isinstance(snapshot, Mapping):
        return []
    controller_values = snapshot.get("controller_values")
    if not isinstance(controller_values, Mapping):
        return []
    policies: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in controller_values.values():
        if not isinstance(entry, Mapping):
            continue
        source = str(entry.get("source") or "").lower()
        if not any(keyword in source for keyword in _CONTROL_SOURCE_KEYWORDS):
            continue
        raw_value = entry.get("value")
        if not isinstance(raw_value, str) or not raw_value.startswith("0x"):
            continue
        normalized = raw_value.lower()
        try:
            if int(normalized, 16) == 0:
                continue
        except ValueError:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        resolved_type = str(entry.get("resolved_type") or "").lower()
        details_raw = entry.get("details")
        details: dict[str, Any] = dict(details_raw) if isinstance(details_raw, Mapping) else {}
        # The label is keyword-matched downstream by
        # ``_config_control_label``: pick wording it already recognises
        # ("safe", "timelock", "owner", "delegate") and add "authority"
        # for the Solady ``Auth`` pattern.
        if resolved_type == "safe":
            label = f"{source} controls via Safe multisig"
        elif resolved_type == "timelock":
            label = f"{source} controls via timelock"
        elif resolved_type == "proxy_admin":
            label = f"{source} controls via proxy admin"
        elif "authority" in source:
            label = "roles authority controls local app admin functions"
        else:
            label = f"{source} controls local app admin functions"
        policies.append(
            {
                "label": label,
                "address": normalized,
                "source": source,
                "resolved_type": resolved_type or None,
                "details": details,
            }
        )
    policies.sort(key=_policy_rank)
    return policies


def resolve_layerzero_runtime(
    rpc_url: str,
    contract: dict[str, Any],
    *,
    control_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    address = _contract_address(contract)
    if not address:
        return _protocol_result("unresolved", "LayerZero", "Missing contract address.")

    endpoint = _first_address(rpc_url, address, ["endpoint()", "getEndpoint()", "lzEndpoint()"])
    if not endpoint:
        return _protocol_result("unresolved", "LayerZero", "No endpoint address was found.")

    local_eid_out = _call(rpc_url, endpoint, "eid()", output_types=["uint32"])
    delegate_out = _call(rpc_url, endpoint, "delegates(address)", ["address"], [address], ["address"])
    peers_by_eid = _peer_map_for_eids(rpc_url, address)

    routes: list[dict[str, Any]] = []
    for entry in layerzero_eid_entries():
        eid = int(entry["eid"])
        peer = peers_by_eid.get(eid)
        if not peer:
            continue
        route = {
            "protocol": "LayerZero",
            "eid": eid,
            "network": entry["network"],
            "chain": entry["chain"],
            "chain_type": entry["chain_type"],
            "chain_id": chain_id_for_chain(entry["chain"]),
            "chain_display_name": display_name_for_chain(entry["chain"]),
            **peer,
            **_layerzero_route_security(rpc_url, endpoint, address, eid),
        }
        routes.append(route)

    # Prefer the semantic ``control_snapshot`` because it covers
    # ``authority()`` / Safe / timelock / proxy-admin patterns that the
    # narrow ``owner()`` + ``delegate()`` probe below misses (etherfi-liquid
    # LayerZero teller uses Solady ``Auth.authority()``, so ``owner()``
    # returns the zero address and the snapshot is the only source of
    # truth). The probe stays as the fallback for callers that don't have
    # a resolution-stage snapshot yet — primarily the existing unit tests.
    policies = _policies_from_control_snapshot(control_snapshot)
    if not policies:
        owner_out = _call(rpc_url, address, "owner()", output_types=["address"])
        if owner_out and owner_out[0] != ZERO_ADDRESS:
            policies.append({"label": "owner controls local app admin functions", "address": str(owner_out[0]).lower()})
        if delegate_out and delegate_out[0] != ZERO_ADDRESS:
            policies.append({"label": "LayerZero delegate", "address": str(delegate_out[0]).lower()})

    return {
        "status": "resolved" if routes else "partial",
        "protocol": "LayerZero",
        "protocols": ["LayerZero"],
        "endpoint": {"address": endpoint, "local_eid": int(local_eid_out[0]) if local_eid_out else None},
        "routes": routes,
        "policies": policies,
    }


def resolve_bridge_runtime(
    rpc_url: str,
    contract: dict[str, Any],
    *,
    control_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    static_context = _bridge_static_context(contract)
    protocols = {str(protocol) for protocol in static_context.get("protocols") or []}
    if not static_context.get("is_bridge") and not protocols:
        return _protocol_result("not_bridge", "Bridge", "No static bridge context was detected.")
    if "LayerZero" in protocols:
        return resolve_layerzero_runtime(rpc_url, contract, control_snapshot=control_snapshot)
    protocol = sorted(protocols)[0] if protocols else "Bridge"
    return _protocol_result(
        "unsupported",
        protocol,
        "Static bridge shape was detected, but no runtime resolver is available for this protocol yet.",
    )
