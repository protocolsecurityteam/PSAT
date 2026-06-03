import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery import static_dependencies as fdc

# offline: BFS pre-fills bytecode via a batched eth_getCode (utils.rpc.get_code_batch,
# imported at call time); stub it empty so it falls back to the per-address get_code mocks
pytestmark = pytest.mark.usefixtures("_stub_rpc_bytecode")


# ---------------------------------------------------------------------------
# Core helpers: normalize_address, extract_push20_addresses
# ---------------------------------------------------------------------------


def test_normalize_address_and_extract_push20():
    # normalize_address: strips prefix, lowercases
    assert fdc.normalize_address("0xAbCd" + "0" * 36) == "0xabcd" + "0" * 36
    assert fdc.normalize_address("AbCd" + "0" * 36) == "0xabcd" + "0" * 36

    # has_deployed_code
    assert fdc.has_deployed_code("0x60016000") is True
    assert fdc.has_deployed_code("0x") is False
    assert fdc.has_deployed_code("0x0") is False

    # extract_push20_addresses: empty / no PUSH20
    assert fdc.extract_push20_addresses("0x") == set()
    assert fdc.extract_push20_addresses("0x6001") == set()

    # extract_push20_addresses: single embedded address
    addr = "aabbccddee11223344556677889900aabbccddee"
    bytecode = "0x73" + addr + "60"  # PUSH20 <addr> PUSH1
    result = fdc.extract_push20_addresses(bytecode)
    assert "0x" + addr in result

    # extract_push20_addresses: filters zero address
    zero_addr = "0" * 40
    bytecode = "0x73" + zero_addr + "73" + addr + "00"
    result = fdc.extract_push20_addresses(bytecode)
    assert "0x" + zero_addr not in result
    assert "0x" + addr in result

    # extract_push20_addresses: skips PUSH data correctly
    # PUSH32 (0x7f) has 32 bytes of data — a PUSH20 opcode inside that data should be ignored
    push32_data = "73" + addr + "00" * 11  # 0x73 inside PUSH32 data (32 bytes total)
    bytecode = "0x7f" + push32_data
    result = fdc.extract_push20_addresses(bytecode)
    assert result == set()

    # extract_push20_addresses: multiple addresses
    addr2 = "1122334455667788990011223344556677889900"
    bytecode = "0x73" + addr + "73" + addr2 + "00"
    result = fdc.extract_push20_addresses(bytecode)
    assert result == {"0x" + addr, "0x" + addr2}

    # extract_push20_addresses: odd-length hex returns empty
    assert fdc.extract_push20_addresses("0x600") == set()


# ---------------------------------------------------------------------------
# RPC resolution
# ---------------------------------------------------------------------------


# Verifies find_dependencies raises when no RPC is available.
def test_find_dependencies_raises_without_rpc(monkeypatch):
    monkeypatch.delenv("ETH_RPC", raising=False)
    monkeypatch.setattr(fdc, "load_dotenv", lambda _path: None)

    with pytest.raises(RuntimeError, match="No RPC URL provided"):
        fdc.find_dependencies("0x1111111111111111111111111111111111111111")


# Verifies find_dependencies uses the explicitly provided RPC URL and
# does not echo it into the returned artifact body.
def test_find_dependencies_uses_explicit_rpc(monkeypatch):
    monkeypatch.setattr(fdc, "load_dotenv", lambda _path: None)
    captured: dict[str, str] = {}

    def _fake_discover(rpc_url, _root, code_cache=None):
        captured["rpc"] = rpc_url
        return ["0x2222222222222222222222222222222222222222"]

    monkeypatch.setattr(fdc, "discover_dependencies", _fake_discover)

    out = fdc.find_dependencies(
        "0x1111111111111111111111111111111111111111",
        "https://explicit-rpc.example",
    )
    assert captured["rpc"] == "https://explicit-rpc.example"
    assert out["dependencies"] == ["0x2222222222222222222222222222222222222222"]
    assert "rpc" not in out, "rpc URL must not be echoed back in the artifact body"


# Verifies find_dependencies falls back to ETH_RPC env var when no explicit RPC is given.
def test_find_dependencies_uses_env_rpc(monkeypatch):
    monkeypatch.setenv("ETH_RPC", "https://env-rpc.example")
    monkeypatch.setattr(fdc, "load_dotenv", lambda _path: None)
    captured: dict[str, str] = {}

    def _fake_discover(rpc_url, _root, code_cache=None):
        captured["rpc"] = rpc_url
        return []

    monkeypatch.setattr(fdc, "discover_dependencies", _fake_discover)

    out = fdc.find_dependencies("0x1111111111111111111111111111111111111111")
    assert captured["rpc"] == "https://env-rpc.example"
    assert "rpc" not in out


# ---------------------------------------------------------------------------
# Mocked BFS traversal
# ---------------------------------------------------------------------------


def test_discover_dependencies_bfs_mocked(monkeypatch):
    """BFS discovers transitive deps, handles back-references, and excludes EOAs."""
    root = "0x1111111111111111111111111111111111111111"
    dep_a = "0x2222222222222222222222222222222222222222"
    dep_b = "0x3333333333333333333333333333333333333333"
    dep_c = "0x4444444444444444444444444444444444444444"

    def _bc(*addrs: str) -> str:
        """Build minimal bytecode with PUSH20 for each address."""
        return "0x" + "".join("73" + a[2:] for a in addrs) + "00"

    code_map = {
        root: _bc(dep_a, dep_b),
        dep_a: _bc(dep_c),
        dep_b: _bc(dep_a),  # back-reference — must not loop
        dep_c: "0x6000",  # no PUSH20
    }

    def fake_get_code(_rpc, address):
        return code_map.get(fdc.normalize_address(address), "0x")

    monkeypatch.setattr(fdc, "get_code", fake_get_code)

    deps = fdc.discover_dependencies("https://rpc.example", root)
    assert sorted(deps) == sorted([dep_a, dep_b, dep_c])


def test_discover_dependencies_raises_on_empty_root(monkeypatch):
    """discover_dependencies raises if root has no deployed bytecode."""
    monkeypatch.setattr(fdc, "get_code", lambda _rpc, _addr: "0x")
    with pytest.raises(RuntimeError, match="no deployed bytecode"):
        fdc.discover_dependencies("https://rpc.example", "0x" + "11" * 20)
