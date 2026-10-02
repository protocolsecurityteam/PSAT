import tempfile
from pathlib import Path

from services.crawlers.defillama.extract import extract_addresses_from_file, extract_protocol


def test_extract_deduplicates():
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(
            'const a = "0xaabbccddee00112233445566778899aabbccddee";\n'
            'const b = "0xAABBCCDDEE00112233445566778899AABBCCDDEE";\n'
        )
        f.flush()
        addrs = extract_addresses_from_file(Path(f.name))
    assert len(addrs) == 1


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


def test_extract_nonexistent_file():
    addrs = extract_addresses_from_file(Path("/nonexistent/file.js"))
    assert addrs == []
