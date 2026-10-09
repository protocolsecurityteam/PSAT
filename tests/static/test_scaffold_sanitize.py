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


_OZ = "../../node_modules/@openzeppelin/contracts"
# Key layout of a verified ERC1967Proxy whose verifier compiled from a nested package (keys climb to a hoisted
# node_modules); the files import each other relatively.
_DOTDOT_BUNDLE = {
    f"{_OZ}/proxy/ERC1967/ERC1967Proxy.sol": (
        'pragma solidity ^0.8.20;\nimport {Proxy} from "../Proxy.sol";\n'
        'import {ERC1967Utils} from "./ERC1967Utils.sol";\n'
        "contract ERC1967Proxy is Proxy { function _implementation() internal view override returns (address) "
        "{ return ERC1967Utils.getImplementation(); } }\n"
    ),
    f"{_OZ}/proxy/Proxy.sol": (
        "pragma solidity ^0.8.20;\nabstract contract Proxy { function _implementation() internal view virtual "
        "returns (address); }\n"
    ),
    f"{_OZ}/proxy/ERC1967/ERC1967Utils.sol": (
        'pragma solidity ^0.8.21;\nimport {StorageSlot} from "../../utils/StorageSlot.sol";\n'
        "library ERC1967Utils { function getImplementation() internal view returns (address) "
        "{ return StorageSlot.read(); } }\n"
    ),
    f"{_OZ}/utils/StorageSlot.sol": (
        "pragma solidity ^0.8.20;\nlibrary StorageSlot { function read() internal view returns (address a) "
        "{ a = address(uint160(block.number)); } }\n"
    ),
}


def _dotdot_result() -> dict:
    result = _standard_json_result({k: {"content": v} for k, v in _DOTDOT_BUNDLE.items()})
    result["ContractName"] = "ERC1967Proxy"
    return result


def test_parse_sources_drops_leading_parent_segments():
    sources = fetch.parse_sources(_dotdot_result())
    assert sorted(sources) == sorted(k.removeprefix("../../") for k in _DOTDOT_BUNDLE)


def test_scaffold_keeps_dotdot_bundle_inside_project(tmp_path):
    project = tmp_path / "proj"
    fetch.scaffold("0xabc", _dotdot_result(), project)
    written = {p.relative_to(project).as_posix() for p in project.rglob("*.sol")}
    assert written == {k.removeprefix("../../") for k in _DOTDOT_BUNDLE}
    assert not list(tmp_path.glob("node_modules"))


@pytest.mark.compile
def test_scaffolded_dotdot_bundle_resolves_its_relative_imports(tmp_path):
    import subprocess

    try:
        from solc_select import solc_select as ss
    except Exception:
        pytest.skip("solc-select unavailable")
    if "0.8.27" not in ss.installed_versions():
        pytest.skip("solc 0.8.27 not installed (run `solc-select install 0.8.27`)")
    project = tmp_path / "proj"
    fetch.scaffold("0xabc", _dotdot_result(), project)
    entry = "node_modules/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol"
    proc = subprocess.run(
        [str(ss.artifact_path("0.8.27")), "--base-path", str(project), "--bin", str(project / entry)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize(
    "key",
    [
        pytest.param("src/../../etc/passwd", id="interior_climb_past_root"),
        pytest.param("../../lib/../../../etc/passwd", id="climb_after_leading_run"),
        pytest.param("a/b/../../../x.sol", id="collapse_past_root"),
        pytest.param("..", id="only_parent"),
        pytest.param("/", id="only_root"),
        pytest.param("./", id="only_dot"),
    ],
)
def test_parse_sources_rejects_paths_that_escape(key):
    with pytest.raises(ValueError):
        fetch.parse_sources(_standard_json_result({key: {"content": "x"}}))


def test_scaffold_rejects_escaping_key_without_writing(tmp_path):
    project = tmp_path / "proj"
    with pytest.raises(ValueError):
        fetch.scaffold("0xabc", _standard_json_result({"src/../../escape.sol": {"content": "x"}}), project)
    assert not (tmp_path / "escape.sol").exists()
    assert not list(tmp_path.rglob("escape.sol"))


def test_absolute_key_is_written_under_the_project(tmp_path):
    project = tmp_path / "proj"
    target = tmp_path / "outside.sol"
    fetch.scaffold("0xabc", _standard_json_result({str(target): {"content": "x"}}), project)
    assert not target.exists()
    assert (project / str(target).lstrip("/")).exists()


def test_parse_sources_rejects_keys_that_collide_after_normalization():
    result = _standard_json_result({"../a/X.sol": {"content": "one"}, "a/X.sol": {"content": "two"}})
    with pytest.raises(ValueError, match="collide"):
        fetch.parse_sources(result)


def test_parse_sources_accepts_identical_duplicates_after_normalization():
    result = _standard_json_result({"../a/X.sol": {"content": "same"}, "a/X.sol": {"content": "same"}})
    assert fetch.parse_sources(result) == {"a/X.sol": "same"}


def test_interior_parent_segment_collapses_inside_the_path():
    result = _standard_json_result({"src/../lib/X.sol": {"content": "x"}})
    assert fetch.parse_sources(result) == {"lib/X.sol": "x"}
