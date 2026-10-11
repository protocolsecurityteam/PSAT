from __future__ import annotations

import json

import pytest

from services.discovery.fetch import _detect_solc_version as detect_fetch_solc
from services.discovery.fetch import scaffold, verified_solc_version
from workers.static_worker import StaticWorker

TELLER_PRAGMA = "pragma solidity <0.9.0 =0.8.21 >=0.8.0 ^0.8.0 ^0.8.20;"


@pytest.mark.parametrize(
    ("sources", "expected"),
    [
        pytest.param(
            {"src/Legacy.sol": "pragma solidity ^0.4.24;\ncontract Legacy {}"},
            "0.4.24",
            id="preserves_legacy_majors",
        ),
        pytest.param(
            {"src/Modern.sol": "pragma solidity ^0.8.21;\ncontract Modern {}"},
            "0.8.24",
            id="bumps_buggy_0_8_versions",
        ),
        # solc 0.9.0 has no release artifact, so foundry fails on it.
        pytest.param(
            {
                "src/Vault.sol": "pragma solidity ^0.8.26;\ncontract Vault {}",
                "src/IThing.sol": "pragma solidity <0.9.0;\ninterface IThing {}",
            },
            "0.8.26",
            id="ignores_standalone_upper_bound_pragma",
        ),
        pytest.param(
            {"src/M.sol": "pragma solidity >=0.8.0 <0.9.0;\ncontract M {}"},
            "0.8.24",
            id="two_sided_range_uses_lower_bound_not_ceiling",
        ),
        pytest.param(
            {"C.sol": "pragma solidity >=0.8.20 <=0.8.30;"},
            "0.8.24",
            id="compatible_preference_before_upper_bound",
        ),
        pytest.param(
            {"C.sol": "pragma solidity <0.9.0 =0.8.21 >=0.8.0 ^0.8.0 ^0.8.20; contract C {}"},
            "0.8.21",
            id="embedded_exact_version",
        ),
        pytest.param({"C.sol": "pragma solidity 0.8.21; contract C {}"}, "0.8.21", id="exact_is_not_floored"),
        pytest.param({"C.sol": "pragma solidity <0.8.24 >=0.8.20;"}, "0.8.23", id="ceiling_below_preference"),
        pytest.param({"C.sol": "pragma solidity >0.8.24 <0.8.26;"}, "0.8.25", id="strict_lower_bound"),
        pytest.param(
            {"A.sol": "pragma solidity ^0.8.0;", "B.sol": "pragma solidity <=0.8.21 = 0.8.21;"},
            "0.8.21",
            id="intersects_files",
        ),
        pytest.param({"C.sol": "pragma solidity 0.8.21 || 0.8.27;"}, "0.8.27", id="disjunction"),
        pytest.param(
            {
                "C.sol": "// pragma solidity 0.8.99;\n/* pragma solidity 0.8.98; */\n"
                'pragma solidity 0.8.21; contract C { string s = "pragma solidity 0.8.97;"; }'
            },
            "0.8.21",
            id="ignores_comments_and_strings",
        ),
        pytest.param(
            {"src/C.sol": "pragma solidity >=0.8.0 <0.8.20;\ncontract C {}"},
            "0.8.19",
            id="ceiling_below_floor_is_honored",
        ),
        pytest.param(
            {"src/C.sol": "pragma solidity >= 0.8.0 < 0.8.20;\ncontract C {}"},
            "0.8.19",
            id="spaced_operators",
        ),
        pytest.param({"src/C.sol": "pragma solidity 0.8.0 - 0.8.20;\ncontract C {}"}, "0.8.20", id="hyphen_range"),
        pytest.param({"src/C.sol": "pragma solidity ^0.6.0 || ^0.7.0;\ncontract C {}"}, "0.7.0", id="alternatives"),
        pytest.param(
            {"src/C.sol": "pragma solidity ^0.8.0 || ^0.7.0;\ncontract C {}"}, "0.8.24", id="alternatives_newest_first"
        ),
        pytest.param(
            {
                "src/A.sol": "pragma solidity ^0.6.0 || ^0.7.0;\ncontract A {}",
                "src/B.sol": "pragma solidity ^0.6.12;\ncontract B {}",
            },
            "0.6.12",
            id="alternative_narrowed_by_another_file",
        ),
        pytest.param({"src/C.sol": "pragma solidity ~0.7.6;\ncontract C {}"}, "0.7.6", id="tilde"),
        pytest.param(
            {"src/C.sol": "pragma solidity >=0.6.0\n    <0.8.0;\ncontract C {}"}, "0.6.0", id="pragma_spans_lines"
        ),
        pytest.param(
            {"src/C.sol": "// pragma solidity version below\ncontract C {}"},
            "0.8.24",
            id="no_pragma_uses_default",
        ),
        pytest.param({"C.sol": "pragma solidity >=0.8.24 <0.8.21;"}, None, id="contradictory_bounds"),
        pytest.param(
            {"A.sol": "pragma solidity 0.8.21;", "B.sol": "pragma solidity 0.8.27;"},
            None,
            id="conflicting_exact_versions",
        ),
    ],
)
def test_detect_solc_version(sources, expected):
    for detect in (detect_fetch_solc, lambda s: verified_solc_version(None, s)):
        if expected is None:
            with pytest.raises(ValueError, match="compiler metadata"):
                detect(sources)
        else:
            assert detect(sources) == expected


def _foundry_solc(project) -> str:
    for line in (project / "foundry.toml").read_text().splitlines():
        if line.startswith("solc_version"):
            return line.split('"')[1]
    raise AssertionError("foundry.toml has no solc_version")


def test_discovery_scaffold_uses_verified_compiler_and_keeps_pragma(tmp_path):
    bundle = {"language": "Solidity", "sources": {"src/T.sol": {"content": f"{TELLER_PRAGMA}\ncontract T {{}}\n"}}}
    result = {
        "ContractName": "T",
        "CompilerVersion": "v0.8.21+commit.d9974bed",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "shanghai",
        "SourceCode": "{" + json.dumps(bundle) + "}",
    }
    project = scaffold("0xabc", result, tmp_path / "proj")
    assert _foundry_solc(project) == "0.8.21"
    assert (project / "src/T.sol").read_text().splitlines()[0] == TELLER_PRAGMA


def test_static_scaffold_uses_verified_compiler_and_keeps_pragma(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    StaticWorker()._scaffold_project(
        project,
        {"src/T.sol": f"{TELLER_PRAGMA}\ncontract T {{}}\n"},
        {"contract_name": "T", "compiler_version": "v0.8.21+commit.d9974bed"},
        {"evm_version": "shanghai", "optimization_used": True, "runs": 200},
        [],
    )
    assert _foundry_solc(project) == "0.8.21"
    assert (project / "src/T.sol").read_text().splitlines()[0] == TELLER_PRAGMA
