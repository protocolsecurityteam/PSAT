import importlib
import json

import pytest

fetch = importlib.import_module("services.discovery.fetch")


def _standard_json_result(sources: dict, *, remappings=None, evm_version="shanghai") -> dict:
    settings = {}
    if remappings is not None:
        settings["remappings"] = remappings
    bundle = {"language": "Solidity", "sources": sources, "settings": settings}
    return {
        "ContractName": "C",
        "CompilerVersion": "v0.8.24+commit.abcdef01",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": evm_version,
        "SourceCode": "{" + json.dumps(bundle) + "}",
    }


@pytest.mark.parametrize(
    ("key", "expected_file"),
    [
        pytest.param(
            "/Users/dev/repo/contracts/v2/Token.sol", "Users/dev/repo/contracts/v2/Token.sol", id="relativized_absolute"
        ),
        pytest.param("src/C.sol", "src/C.sol", id="legit_relative"),
    ],
)
def test_scaffold_writes_source(tmp_path, key, expected_file):
    result = _standard_json_result({key: {"content": "pragma solidity 0.8.24;"}})
    project = tmp_path / "proj"
    fetch.scaffold("0xabc", result, project)
    assert (project / expected_file).exists()


def test_evm_version_injection_falls_back():
    injected = 'shanghai"\nffi = true\nx = "'
    assert fetch.sanitize_evm_version(injected) == "shanghai"


def test_evm_version_allowlist_passes_legit():
    assert fetch.sanitize_evm_version("cancun") == "cancun"
    assert fetch.sanitize_evm_version("CANCUN") == "cancun"
    assert fetch.sanitize_evm_version("") == "shanghai"


def test_scaffold_evm_injection_not_in_toml(tmp_path):
    injected = 'shanghai"\nffi = true\nx = "'
    result = _standard_json_result({"src/C.sol": {"content": "pragma solidity 0.8.24;"}}, evm_version=injected)
    project = tmp_path / "proj"
    fetch.scaffold("0xabc", result, project)
    toml = (project / "foundry.toml").read_text()
    assert 'evm_version = "shanghai"' in toml
    assert "ffi = true" not in toml


def test_parse_remappings_drops_escaping_target():
    result = _standard_json_result(
        {"src/C.sol": {"content": "x"}},
        remappings=["@x/=/etc/", "@oz/=lib/openzeppelin/", "@y/=../../secrets/"],
    )
    assert fetch.parse_remappings(result) == ["@oz/=lib/openzeppelin/"]


def test_remapping_target_rejects_embedded_newline():
    # An embedded LF would split into a second, absolute remapping line (F2).
    assert not fetch._remapping_target_is_safe("@a/=lib/\n@x/=/etc/")
    assert not fetch._remapping_target_is_safe("@a/=lib/\r@x/=/etc/")
    assert not fetch._remapping_target_is_safe("@a/=lib/\r\n@x/=/etc/")
    assert fetch._remapping_target_is_safe("@openzeppelin/=lib/openzeppelin-contracts/")
    assert fetch._remapping_target_is_safe("@a/=")


def test_static_prune_remappings_applies_escape_filter():
    from workers.static_worker import _prune_remappings

    remappings = ["@x/=/etc/", "@y/=lib/../../../etc/", "@oz/=lib/openzeppelin/"]
    kept = _prune_remappings(remappings, {"lib/openzeppelin/Ownable.sol"})
    assert kept == ["@oz/=lib/openzeppelin/"]
