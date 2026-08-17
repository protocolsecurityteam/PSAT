"""Sanitization of attacker-controlled Etherscan verified-source metadata.

Covers path-traversal confinement of scaffolded source files, the EVMVersion
TOML-injection allowlist, and the remapping arbitrary-read filter.
"""

import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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


# ---- FINDING 1: path traversal ----


def test_parse_sources_rejects_parent_traversal():
    result = _standard_json_result({"contracts/../../../../tmp/evil.sol": {"content": "x"}})
    with pytest.raises(ValueError):
        fetch.parse_sources(result)


def test_parse_sources_rejects_absolute():
    result = _standard_json_result({"/tmp/evil.sol": {"content": "x"}})
    with pytest.raises(ValueError):
        fetch.parse_sources(result)


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


def test_confine_accepts_legit(tmp_path):
    full = fetch._confine(tmp_path, "contracts/A.sol")
    assert full == (tmp_path / "contracts/A.sol").resolve()


def test_scaffold_refuses_escaping_source(tmp_path):
    result = _standard_json_result({"contracts/../../../../tmp/evil.sol": {"content": "x"}})
    project = tmp_path / "proj"
    escape = (project / "contracts/../../../../tmp/evil.sol").resolve()
    with pytest.raises(ValueError):
        fetch.scaffold("0xabc", result, project)
    assert not escape.exists()


def test_scaffold_writes_legit_sources(tmp_path):
    result = _standard_json_result({"src/C.sol": {"content": "pragma solidity 0.8.24;"}})
    project = tmp_path / "proj"
    fetch.scaffold("0xabc", result, project)
    assert (project / "src/C.sol").exists()


# ---- FINDING 3: EVMVersion TOML injection ----


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


# ---- FINDING 4: remapping arbitrary read ----


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
    # mid-path traversal that escapes must be rejected, not just leading "../"
    assert not fetch._remapping_target_is_safe("@x/=lib/../../../etc/")


def test_static_prune_remappings_applies_escape_filter():
    from workers.static_worker import _prune_remappings

    remappings = ["@x/=/etc/", "@y/=lib/../../../etc/", "@oz/=lib/openzeppelin/"]
    # lib/openzeppelin/ has a matching source file so it survives the existence prune;
    # both escaping targets are dropped by the safety filter.
    kept = _prune_remappings(remappings, {"lib/openzeppelin/Ownable.sol"})
    assert kept == ["@oz/=lib/openzeppelin/"]
