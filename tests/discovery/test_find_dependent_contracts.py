import pytest

from services.discovery import static_dependencies as fdc

# The BFS batch-prefetches bytecode; stubbed empty it falls back to the per-address mocks.
pytestmark = pytest.mark.usefixtures("_stub_rpc_bytecode")


def test_normalize_address_and_extract_push20():
    assert fdc.normalize_address("0xAbCd" + "0" * 36) == "0xabcd" + "0" * 36
    assert fdc.normalize_address("AbCd" + "0" * 36) == "0xabcd" + "0" * 36

    assert fdc.has_deployed_code("0x60016000") is True
    assert fdc.has_deployed_code("0x") is False
    assert fdc.has_deployed_code("0x0") is False

    assert fdc.extract_push20_addresses("0x") == set()
    assert fdc.extract_push20_addresses("0x6001") == set()

    addr = "aabbccddee11223344556677889900aabbccddee"
    bytecode = "0x73" + addr + "60"  # PUSH20 <addr> PUSH1
    result = fdc.extract_push20_addresses(bytecode)
    assert "0x" + addr in result

    zero_addr = "0" * 40
    bytecode = "0x73" + zero_addr + "73" + addr + "00"
    result = fdc.extract_push20_addresses(bytecode)
    assert "0x" + zero_addr not in result
    assert "0x" + addr in result

    # A PUSH20 opcode inside PUSH32 data must be ignored.
    push32_data = "73" + addr + "00" * 11  # 0x73 inside PUSH32 data (32 bytes total)
    bytecode = "0x7f" + push32_data
    result = fdc.extract_push20_addresses(bytecode)
    assert result == set()

    addr2 = "1122334455667788990011223344556677889900"
    bytecode = "0x73" + addr + "73" + addr2 + "00"
    result = fdc.extract_push20_addresses(bytecode)
    assert result == {"0x" + addr, "0x" + addr2}

    assert fdc.extract_push20_addresses("0x600") == set()


def test_find_dependencies_uses_erpc_when_no_explicit(monkeypatch):
    monkeypatch.setenv("ERPC_BASE_URL", "https://erpc-proxy.example")
    monkeypatch.delenv("ETH_RPC", raising=False)
    monkeypatch.setattr(fdc, "load_dotenv", lambda _path: None)
    captured: dict[str, str] = {}

    def _fake_discover(rpc_url, _root, code_cache=None, chain_id=None):
        captured["rpc"] = rpc_url
        return []

    monkeypatch.setattr(fdc, "discover_dependencies", _fake_discover)

    out = fdc.find_dependencies("0x1111111111111111111111111111111111111111")
    assert captured["rpc"] == "https://erpc-proxy.example/main/evm/1"
    assert "rpc" not in out


def test_discover_dependencies_bfs_mocked(monkeypatch):
    root = "0x1111111111111111111111111111111111111111"
    dep_a = "0x2222222222222222222222222222222222222222"
    dep_b = "0x3333333333333333333333333333333333333333"
    dep_c = "0x4444444444444444444444444444444444444444"

    def _bc(*addrs: str) -> str:
        return "0x" + "".join("73" + a[2:] for a in addrs) + "00"

    code_map = {
        root: _bc(dep_a, dep_b),
        dep_a: _bc(dep_c),
        dep_b: _bc(dep_a),  # back-reference — must not loop
        dep_c: "0x6000",  # no PUSH20
    }

    def fake_get_code(_rpc, address, chain_id=None):
        return code_map.get(fdc.normalize_address(address), "0x")

    monkeypatch.setattr(fdc, "get_code", fake_get_code)

    deps = fdc.discover_dependencies("https://rpc.example", root)
    assert sorted(deps) == sorted([dep_a, dep_b, dep_c])
