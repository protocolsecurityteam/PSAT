import importlib
import json

fetcher = importlib.import_module("services.discovery.fetch")


STANDARD_JSON_RESULT = {
    "ContractName": "BoringVault",
    "CompilerVersion": "v0.8.21+commit.d9974bed",
    "OptimizationUsed": "1",
    "Runs": "200",
    "EVMVersion": "shanghai",
    "LicenseType": "MIT",
    "SourceCode": (
        "{{\n"
        '  "language": "Solidity",\n'
        '  "sources": {\n'
        '    "src/base/BoringVault.sol": {\n'
        '      "content": "pragma solidity 0.8.21;\\nimport {\\"Auth\\"} from '
        '\\"@solmate/auth/Auth.sol\\";\\ncontract BoringVault is Auth {}\\n"\n'
        "    },\n"
        '    "lib/solmate/src/auth/Auth.sol": {\n'
        '      "content": "pragma solidity >=0.8.0;\\nabstract contract Auth {}\\n"\n'
        "    }\n"
        "  },\n"
        '  "settings": {\n'
        '    "remappings": [\n'
        '      "@solmate/=lib/solmate/src/",\n'
        '      "@openzeppelin/=lib/openzeppelin-contracts/"\n'
        "    ]\n"
        "  }\n"
        "}}"
    ),
}


def test_scaffold_writes_standard_json_layout_and_metadata(tmp_path):
    project_dir = tmp_path / "BoringVault"
    returned = fetcher.scaffold(
        "0x08c6F91e2B681FaF5e17227F2a44C307b3C1364C",
        STANDARD_JSON_RESULT,
        project_dir,
    )

    assert returned == project_dir
    assert (project_dir / "src/base/BoringVault.sol").exists()
    assert (project_dir / "lib/solmate/src/auth/Auth.sol").exists()
    assert (project_dir / "remappings.txt").read_text() == (
        "@solmate/=lib/solmate/src/\n@openzeppelin/=lib/openzeppelin-contracts/\n"
    )

    bundle = json.loads((project_dir / "etherscan_standard_input.json").read_text())
    assert sorted(bundle["sources"]) == [
        "lib/solmate/src/auth/Auth.sol",
        "src/base/BoringVault.sol",
    ]

    meta = json.loads((project_dir / "contract_meta.json").read_text())
    assert meta["source_format"] == "standard_json"
    assert meta["source_file_count"] == 2
    assert meta["remappings"] == [
        "@solmate/=lib/solmate/src/",
        "@openzeppelin/=lib/openzeppelin-contracts/",
    ]

    foundry_toml = (project_dir / "foundry.toml").read_text()
    assert 'src = "src"' in foundry_toml
    assert 'solc_version = "0.8.21"' in foundry_toml
