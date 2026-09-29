from __future__ import annotations

import pytest

from services.discovery.fetch import _detect_solc_version as detect_fetch_solc
from workers.static_worker import _detect_solc_version as detect_static_solc


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
        # A ``<0.9.0`` ceiling must not be picked as the compiler version: solc 0.9.0 has no release
        # artifact, so foundry fails with "version not found in artifacts for this platform: 0.9.0".
        pytest.param(
            {
                "src/Vault.sol": "pragma solidity ^0.8.26;\ncontract Vault {}",
                "src/IThing.sol": "pragma solidity <0.9.0;\ninterface IThing {}",
            },
            "0.8.26",
            id="ignores_standalone_upper_bound_pragma",
        ),
        # ``>=0.8.0 <0.9.0`` resolves to the lower bound (min-bumped to 0.8.24), never the 0.9.0 ceiling.
        pytest.param(
            {"src/M.sol": "pragma solidity >=0.8.0 <0.9.0;\ncontract M {}"},
            "0.8.24",
            id="two_sided_range_uses_lower_bound_not_ceiling",
        ),
    ],
)
def test_detect_solc_version(sources, expected):
    assert detect_fetch_solc(sources) == expected
    assert detect_static_solc(sources) == expected
