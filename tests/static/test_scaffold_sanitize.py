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
    "key",
    [
        pytest.param("contracts/../../../../tmp/evil.sol", id="parent_traversal"),
        pytest.param("/tmp/../../etc/evil.sol", id="absolute_with_traversal"),
        # Path-traversal confinement is a security boundary.
        pytest.param("//tmp/../../etc/evil.sol", id="double_slash_absolute_with_traversal"),
    ],
)
def test_parse_sources_rejects_traversal(key):
    result = _standard_json_result({key: {"content": "x"}})
    with pytest.raises(ValueError):
        fetch.parse_sources(result)


def test_parse_sources_relativizes_absolute():
    # Verified bundles carry absolute keys from the developer's machine (e.g. Circle's EURC FiatTokenV2_2).
    eurc_key = (
        "/Users/aloysius.chan/Repositories/circlefin/"
        "stablecoin-evm-private-eurc-mainnet-eth/contracts/v2/FiatTokenV2_2.sol"
    )
    result = _standard_json_result({eurc_key: {"content": "x"}})
    parsed = fetch.parse_sources(result)
    assert parsed == {eurc_key.lstrip("/"): "x"}


def test_parse_sources_windows_style_keys_stay_confined():
    # The POSIX normalizer keeps Windows-style keys inside the project dir.
    result = _standard_json_result(
        {
            "C:\\Users\\dev\\A.sol": {"content": "a"},
            "C:/Users/dev/B.sol": {"content": "b"},
        }
    )
    parsed = fetch.parse_sources(result)
    assert parsed == {"C:\\Users\\dev\\A.sol": "a", "C:/Users/dev/B.sol": "b"}


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


def test_parse_sources_accepts_legit_relative():
    result = _standard_json_result(
        {
            "contracts/A.sol": {"content": "a"},
            "src/B.sol": {"content": "b"},
            "./src/C.sol": {"content": "c"},
        }
    )
    parsed = fetch.parse_sources(result)
    assert parsed == {"contracts/A.sol": "a", "src/B.sol": "b", "src/C.sol": "c"}


def test_confine_refuses_escape(tmp_path):
    with pytest.raises(ValueError):
        fetch._confine(tmp_path, "../../etc/passwd")


def test_scaffold_refuses_escaping_source(tmp_path):
    result = _standard_json_result({"contracts/../../../../tmp/evil.sol": {"content": "x"}})
    project = tmp_path / "proj"
    escape = (project / "contracts/../../../../tmp/evil.sol").resolve()
    with pytest.raises(ValueError):
        fetch.scaffold("0xabc", result, project)
    assert not escape.exists()


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


def test_remapping_target_is_safe():
    assert fetch._remapping_target_is_safe("@oz/=lib/openzeppelin/")
    assert not fetch._remapping_target_is_safe("@x/=/etc/")
    assert not fetch._remapping_target_is_safe("@y/=../../secrets/")
    assert not fetch._remapping_target_is_safe("@z/=~/private/")
    assert not fetch._remapping_target_is_safe("@x/=lib/../../../etc/")


def test_remapping_target_rejects_embedded_newline():
    # An embedded LF would split into a second, absolute remapping line (F2).
    assert not fetch._remapping_target_is_safe("@a/=lib/\n@x/=/etc/")
    assert not fetch._remapping_target_is_safe("@a/=lib/\r@x/=/etc/")
    assert not fetch._remapping_target_is_safe("@a/=lib/\r\n@x/=/etc/")
    assert fetch._remapping_target_is_safe("@openzeppelin/=lib/openzeppelin-contracts/")
    assert fetch._remapping_target_is_safe("@a/=")


def test_scaffold_remappings_never_writes_absolute_line(tmp_path):
    result = _standard_json_result(
        {"src/C.sol": {"content": "pragma solidity 0.8.24;"}},
        remappings=["@a/=lib/\n@x/=/etc/", "@oz/=lib/openzeppelin/"],
    )
    project = tmp_path / "proj"
    fetch.scaffold("0xabc", result, project)
    lines = (project / "remappings.txt").read_text().splitlines()
    assert lines == ["@oz/=lib/openzeppelin/"]
    assert not any(line.split("=", 1)[-1].startswith("/") for line in lines if line)


def test_static_prune_remappings_applies_escape_filter():
    from workers.static_worker import _prune_remappings

    remappings = ["@x/=/etc/", "@y/=lib/../../../etc/", "@oz/=lib/openzeppelin/"]
    kept = _prune_remappings(remappings, {"lib/openzeppelin/Ownable.sol"})
    assert kept == ["@oz/=lib/openzeppelin/"]
