from __future__ import annotations

from typing import Any

from eth_abi.abi import encode

from services.bridges import runtime
from services.bridges.chains import rpc_url_for_chain


def _encoded_bytes32(value: str) -> str:
    return "0x" + encode(["bytes32"], [bytes.fromhex(value.removeprefix("0x"))]).hex()


def _encoded_address(value: str) -> str:
    return "0x" + encode(["address"], [value]).hex()


def _encoded_address_bool(value: str, flag: bool) -> str:
    return "0x" + encode(["address", "bool"], [value, flag]).hex()


def test_runtime_rpc_url_uses_erpc_for_known_chain_without_unknown_fallback(monkeypatch) -> None:
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")

    assert rpc_url_for_chain("base", "https://ethereum.example") == "https://erpc-proxy.example/main/evm/8453"
    assert rpc_url_for_chain("fantom", "https://ethereum.example") is None


def test_layerzero_runtime_resolves_endpoint_peer_and_libraries(monkeypatch) -> None:
    oapp = "0x" + "11" * 20
    endpoint = "0x" + "22" * 20
    peer = "0x" + "33" * 20
    send_library = "0x" + "44" * 20
    receive_library = "0x" + "55" * 20
    owner = "0x" + "66" * 20
    eid = 39999

    monkeypatch.setattr(
        runtime,
        "layerzero_eid_entries",
        lambda: ({"eid": eid, "network": "custom-mainnet", "chain": "base", "chain_type": "evm"},),
    )

    def fake_batch(_rpc_url: str, calls: list[tuple[str, list[Any]]]) -> list[str | None]:
        assert calls[0][1][0]["to"] == oapp
        return [_encoded_bytes32("0x" + ("00" * 12) + peer[2:]), None]

    monkeypatch.setattr(runtime, "rpc_batch_request", fake_batch)

    def fake_request(_rpc_url: str, method: str, params: list[Any], **_kwargs: Any) -> str | None:
        assert method == "eth_call"
        call = params[0]
        target = call["to"]
        selector = call["data"][:10]
        if target == oapp and selector == runtime._selector("endpoint()"):
            return _encoded_address(endpoint)
        if target == oapp and selector == runtime._selector("owner()"):
            return _encoded_address(owner)
        if target == endpoint and selector == runtime._selector("eid()"):
            return "0x" + encode(["uint32"], [30101]).hex()
        if target == endpoint and selector == runtime._selector("delegates(address)"):
            return _encoded_address(runtime.ZERO_ADDRESS)
        if target == endpoint and selector == runtime._selector("getSendLibrary(address,uint32)"):
            return _encoded_address(send_library)
        if target == endpoint and selector == runtime._selector("getReceiveLibrary(address,uint32)"):
            return _encoded_address_bool(receive_library, True)
        return None

    monkeypatch.setattr(runtime, "rpc_request", fake_request)

    resolved = runtime.resolve_bridge_runtime(
        "https://rpc.invalid",
        {
            "subject": {"address": oapp},
            "bridge_static_context": {"is_bridge": True, "protocols": ["LayerZero"]},
        },
    )

    assert resolved["status"] == "resolved"
    assert resolved["endpoint"] == {"address": endpoint, "local_eid": 30101}
    assert resolved["policies"] == [{"label": "owner controls local app admin functions", "address": owner}]

    route = resolved["routes"][0]
    assert route["eid"] == eid
    assert route["chain"] == "base"
    assert route["chain_id"] == 8453
    assert route["peer_address"] == peer
    assert route["send_library"] == send_library
    assert route["receive_library"] == receive_library
    assert route["receive_library_default"] is True


def test_bridge_runtime_reports_unsupported_protocol() -> None:
    resolved = runtime.resolve_bridge_runtime(
        "https://rpc.invalid",
        {"address": "0x" + "11" * 20, "bridge_static_context": {"is_bridge": True, "protocols": ["Bridge"]}},
    )

    assert resolved["status"] == "unsupported"
    assert resolved["protocol"] == "Bridge"


def test_layerzero_runtime_prefers_control_snapshot_over_owner_probe(monkeypatch) -> None:
    """When a ``control_snapshot`` is supplied (production path), the resolver
    sources policies from the semantic layer instead of doing its own narrow
    ``owner()`` probe — which is the only way to pick up Solady ``Auth.authority()``
    contracts (etherfi-liquid LayerZero teller), where ``owner()`` is zero."""
    oapp = "0x" + "11" * 20
    endpoint = "0x" + "22" * 20
    authority_addr = "0x" + "aa" * 20
    safe_addr = "0x" + "bb" * 20

    monkeypatch.setattr(runtime, "layerzero_eid_entries", lambda: ())
    monkeypatch.setattr(runtime, "rpc_batch_request", lambda *_args, **_kwargs: [])

    def fake_request(_rpc_url: str, method: str, params: list[Any], **_kwargs: Any) -> str | None:
        assert method == "eth_call"
        target = params[0]["to"]
        selector = params[0]["data"][:10]
        if target == oapp and selector == runtime._selector("endpoint()"):
            return _encoded_address(endpoint)
        if target == endpoint and selector == runtime._selector("eid()"):
            return "0x" + encode(["uint32"], [30101]).hex()
        if target == endpoint and selector == runtime._selector("delegates(address)"):
            return _encoded_address(runtime.ZERO_ADDRESS)
        # Crucially, owner() returns zero. Without the snapshot path the
        # resolver would emit no policies and the UI would show "Unknown".
        if target == oapp and selector == runtime._selector("owner()"):
            return _encoded_address(runtime.ZERO_ADDRESS)
        return None

    monkeypatch.setattr(runtime, "rpc_request", fake_request)

    snapshot = {
        "controller_values": {
            "external_contract:authority": {
                "source": "authority",
                "value": authority_addr,
                "resolved_type": "contract",
                "details": {"address": authority_addr},
            },
            # Owner here is the RolesAuthority's owner — a Safe. The resolver
            # should rank "safe" ahead of plain "authority" so the card label
            # surfaces the multisig.
            "state_variable:_owner": {
                "source": "_owner",
                "value": safe_addr,
                "resolved_type": "safe",
                "details": {
                    "address": safe_addr,
                    "owners": ["0x" + "cc" * 20, "0x" + "dd" * 20, "0x" + "ee" * 20],
                    "threshold": 2,
                },
            },
        }
    }

    resolved = runtime.resolve_bridge_runtime(
        "https://rpc.invalid",
        {
            "subject": {"address": oapp},
            "bridge_static_context": {"is_bridge": True, "protocols": ["LayerZero"]},
        },
        control_snapshot=snapshot,
    )

    assert resolved["status"] == "partial"
    # Safe sorts first (strongest signal) so the card-level config_control
    # label becomes "2-of-3 Safe" via the existing _config_control_label logic.
    assert [p["address"] for p in resolved["policies"]] == [safe_addr, authority_addr]
    assert resolved["policies"][0]["resolved_type"] == "safe"
    assert "safe" in resolved["policies"][0]["label"].lower()
    assert "authority" in resolved["policies"][1]["label"].lower()
