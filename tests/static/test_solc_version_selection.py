from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.discovery.fetch import _detect_solc_version as detect_fetch_solc
from workers.static_worker import _detect_solc_version as detect_static_solc


def test_detect_solc_preserves_legacy_majors():
    sources = {"src/Legacy.sol": "pragma solidity ^0.4.24;\ncontract Legacy {}"}
    assert detect_fetch_solc(sources) == "0.4.24"
    assert detect_static_solc(sources) == "0.4.24"


def test_detect_solc_still_bumps_buggy_0_8_versions():
    sources = {"src/Modern.sol": "pragma solidity ^0.8.21;\ncontract Modern {}"}
    assert detect_fetch_solc(sources) == "0.8.24"
    assert detect_static_solc(sources) == "0.8.24"


def test_detect_solc_ignores_standalone_upper_bound_pragma():
    """A ``<0.9.0`` ceiling (common in interface/lib files) must not be picked
    as the compiler version — solc 0.9.0 has no release artifact, so foundry
    fails with "version not found in artifacts for this platform: 0.9.0".
    The real target pragma wins instead."""
    sources = {
        "src/Vault.sol": "pragma solidity ^0.8.26;\ncontract Vault {}",
        "src/IThing.sol": "pragma solidity <0.9.0;\ninterface IThing {}",
    }
    assert detect_fetch_solc(sources) == "0.8.26"
    assert detect_static_solc(sources) == "0.8.26"


def test_detect_solc_two_sided_range_uses_lower_bound_not_ceiling():
    """``>=0.8.0 <0.9.0`` resolves to the lower bound (min-bumped to 0.8.24),
    never the 0.9.0 ceiling."""
    sources = {"src/M.sol": "pragma solidity >=0.8.0 <0.9.0;\ncontract M {}"}
    assert detect_fetch_solc(sources) == "0.8.24"
    assert detect_static_solc(sources) == "0.8.24"
