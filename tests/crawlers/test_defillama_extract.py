"""Tests for contract address extraction from adapter source files."""

import tempfile
from pathlib import Path

from services.crawlers.defillama.extract import extract_addresses_from_file, extract_protocol, infer_chain_from_context


def test_extract_basic_addresses():
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write('const vault = "0xaabbccddee00112233445566778899aabbccddee";\n')
        f.flush()
        addrs = extract_addresses_from_file(Path(f.name))
    assert addrs == ["0xaabbccddee00112233445566778899aabbccddee"]


def test_extract_deduplicates():
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(
            'const a = "0xaabbccddee00112233445566778899aabbccddee";\n'
            'const b = "0xAABBCCDDEE00112233445566778899AABBCCDDEE";\n'
        )
        f.flush()
        addrs = extract_addresses_from_file(Path(f.name))
    assert len(addrs) == 1


def test_extract_filters_zero_address():
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write('const zero = "0x0000000000000000000000000000000000000000";\n')
        f.flush()
        addrs = extract_addresses_from_file(Path(f.name))
    assert addrs == []


def test_extract_filters_dead_address():
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write('const dead = "0x000000000000000000000000000000000000dead";\n')
        f.flush()
        addrs = extract_addresses_from_file(Path(f.name))
    assert addrs == []


def test_extract_multiple_addresses():
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(
            'const a = "0x1111111111111111111111111111111111111111";\n'
            'const b = "0x2222222222222222222222222222222222222222";\n'
        )
        f.flush()
        addrs = extract_addresses_from_file(Path(f.name))
    assert len(addrs) == 2


def test_extract_protocol_directory():
    with tempfile.TemporaryDirectory() as tmp:
        proto_dir = Path(tmp) / "test-protocol"
        proto_dir.mkdir()
        (proto_dir / "index.js").write_text(
            "module.exports = {\n"
            "  ethereum: {\n"
            '    staking: staking("0xaabbccddee00112233445566778899aabbccddee"),\n'
            "  }\n"
            "};\n"
        )
        result = extract_protocol(proto_dir)

    assert result["protocol"] == "test-protocol"
    assert result["files_scanned"] >= 1
    assert len(result["addresses"]) == 1
    assert result["addresses"][0]["address"] == "0xaabbccddee00112233445566778899aabbccddee"


def test_extract_protocol_with_chain_inference():
    with tempfile.TemporaryDirectory() as tmp:
        proto_dir = Path(tmp) / "my-protocol"
        proto_dir.mkdir()
        (proto_dir / "index.js").write_text(
            'const arbitrum = {\n  vault: "0x1111111111111111111111111111111111111111",\n};\n'
        )
        result = extract_protocol(proto_dir)

    assert len(result["addresses"]) == 1
    assert result["addresses"][0]["chain"] == "arbitrum"


def test_extract_protocol_empty_dir():
    with tempfile.TemporaryDirectory() as tmp:
        proto_dir = Path(tmp) / "empty-protocol"
        proto_dir.mkdir()
        result = extract_protocol(proto_dir)

    assert result["protocol"] == "empty-protocol"
    assert result["addresses"] == []


def test_infer_chain_ethereum():
    text = 'const ethereum = { token: "0x1111111111111111111111111111111111111111" };'
    chain = infer_chain_from_context(Path("test.js"), text, "0x1111111111111111111111111111111111111111")
    assert chain == "ethereum"


def test_infer_chain_none():
    text = 'const x = "0x1111111111111111111111111111111111111111";'
    chain = infer_chain_from_context(Path("test.js"), text, "0x1111111111111111111111111111111111111111")
    assert chain is None


def test_extract_nonexistent_file():
    addrs = extract_addresses_from_file(Path("/nonexistent/file.js"))
    assert addrs == []
