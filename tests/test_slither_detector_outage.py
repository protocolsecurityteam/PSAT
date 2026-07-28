"""The Slither DETECTOR pass has never run, and the artifact said otherwise.

``slither_results.json`` is read with a ``{}`` default and ``{}`` flowed into
``detector_counts = {High: 0, Medium: 0, Low: 0, Informational: 0}`` and
``static_risk_level = "unknown"``, published next to
``static_analysis_completed: true`` and ``errors: []``. Measured: on 75/75
production artifacts ``slither_completed`` is false, every detector total is 0,
``errors`` is empty and ``risk_level`` is ``"unknown"`` on 92/92
``contract_summaries`` rows -- the same value a clean run gives.

The writer was removed deliberately (``StaticWorker._run_slither_phase``, see
``db/queue.py``'s ``_STATIC_ARTIFACT_NAMES`` comment), so this is a permanent
total outage rather than a transient one. That makes silent reporting worse,
not better: nothing will ever come along and correct the record.

Three states now: ``None``/``absent`` not determined, ``"clean"`` ran and found
nothing, ``low``/``medium``/``high`` ran and found something.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _derive_static_risk_level,
    _summarize_slither,
)

_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract C {
    address public owner;
    uint256 public value;
    function poke(uint256 v) external { require(msg.sender == owner, "no"); value = v; }
}
"""

_CLEAN_RUN = {"results": {"detectors": []}}
_HIGH_RUN = {
    "results": {
        "detectors": [
            {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium", "description": "bad\nmore"},
        ]
    }
}


@pytest.mark.parametrize("absent", [{}, None, {"error": "boom"}, {"results": None}, "not-a-dict"])
def test_absent_detector_output_is_not_a_zero_count(absent):
    summary = _summarize_slither(absent)  # type: ignore[arg-type]
    assert summary["detector_output"] == "absent"
    assert summary["detector_counts"] is None, "a zero-filled count map is a clean bill of health"
    assert summary["key_findings"] is None
    assert _derive_static_risk_level(summary["detector_counts"]) is None


def test_clean_run_is_distinguishable_from_no_run():
    """R1/R4 positive case. The whole point: these two must not be the same
    answer, and before the change both were ``unknown`` with all-zero counts."""
    clean = _summarize_slither(_CLEAN_RUN)
    assert clean["detector_output"] == "present"
    assert clean["detector_counts"] is not None and set(clean["detector_counts"].values()) == {0}
    assert _derive_static_risk_level(clean["detector_counts"]) == "clean"

    absent = _summarize_slither({})
    assert _derive_static_risk_level(absent["detector_counts"]) is None
    assert _derive_static_risk_level(clean["detector_counts"]) != _derive_static_risk_level(absent["detector_counts"])


def test_findings_still_drive_the_level():
    summary = _summarize_slither(_HIGH_RUN)
    assert summary["detector_output"] == "present"
    assert summary["detector_counts"] is not None and summary["detector_counts"]["High"] == 1
    assert _derive_static_risk_level(summary["detector_counts"]) == "high"
    assert summary["key_findings"] == [
        {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium", "description": "bad"}
    ]


def test_outage_is_loud_in_analysis_status(tmp_path):
    """R2 FIRING PROOF. The sentinel is not hypothetical: it fires on every
    contract this pipeline analyses today, because the detector writer no
    longer exists. 88/88 locally replayed contracts take this branch."""
    from services.static.contract_analysis_pipeline import core
    from tests.support.foundry_project import write_foundry_project  # noqa: PLC0415

    project = write_foundry_project(tmp_path, "C", _SOURCE)
    (project / "slither_results.json").unlink()

    analysis, _trees, _effects = core.collect_contract_analysis_with_artifacts(project)
    status = analysis["analysis_status"]
    assert status["detector_output"] == "absent"
    assert status["slither_completed"] is False
    assert status["errors"], "a total detector outage with errors: [] is its own defect"
    assert "NOT DETERMINED" in status["errors"][0]
    assert analysis["summary"]["static_risk_level"] is None
    assert analysis["slither"]["detector_counts"] is None
    # The IR-derived half is NOT withheld: the outage is scoped to the pass
    # that actually failed.
    assert status["static_analysis_completed"] is True
    assert analysis["contract_classification"]["standards"] is not None


def test_present_detector_output_reports_no_error(tmp_path):
    """NEGATIVE CONTROL for the loud path: a run that produced output must not
    manufacture an error, or the signal is worthless."""
    from services.static.contract_analysis_pipeline import core
    from tests.support.foundry_project import write_foundry_project  # noqa: PLC0415

    project = write_foundry_project(tmp_path, "C", _SOURCE)
    analysis, _trees, _effects = core.collect_contract_analysis_with_artifacts(project)
    assert analysis["analysis_status"]["detector_output"] == "present"
    assert analysis["analysis_status"]["errors"] == []
    assert analysis["summary"]["static_risk_level"] == "clean"


# ---------------------------------------------------------------------------
# The classification columns: which of them can actually be not-determined.
# ---------------------------------------------------------------------------


def test_is_factory_is_not_determined_without_the_effects_artifact(tmp_path):
    """``is_factory`` is the ONLY classification field that is not IR-derived:
    it reads the effects artifact's ``contract_creation`` sinks. ``core``
    substitutes ``{"schema_version", "error"}`` when ``build_effects`` raises,
    and ``false`` would then assert that a contract deploys nothing on the
    strength of never having looked."""
    from slither import Slither  # noqa: PLC0415

    from services.static.contract_analysis_pipeline.summaries import _detect_contract_classification
    from tests.support.foundry_project import write_foundry_project  # noqa: PLC0415

    project = write_foundry_project(tmp_path, "C", _SOURCE)
    contract = next(c for c in Slither(str(project)).contracts if c.name == "C")

    degraded = _detect_contract_classification(contract, tmp_path, {"schema_version": "semantic", "error": "boom"})
    assert degraded["is_factory"] is None
    assert degraded["factory_functions"] is None
    # The IR-derived half is unaffected -- the sentinel narrows one field.
    assert degraded["standards"] == []
    assert degraded["is_nft"] is False

    ran = _detect_contract_classification(contract, tmp_path, {"functions": {}})
    assert ran["is_factory"] is False, "an effects artifact that ran and found no creation sink is a PROVEN absence"
    assert ran["factory_functions"] == []


def test_standards_absence_is_measured_not_missing(tmp_path):
    """A proposal to null ``standards`` on the reasoning that ``{}`` on
    61/92 rows meant "no detector ran" was rejected by measurement: ``standards``
    comes from ``contract.ercs()`` plus a signature+event match off the IR, not
    from the detector pass, and it is non-empty on 31 of the 88 local contracts
    -- every real token among them. Nulling it would suppress a true negative,
    so this pins that it stays a list."""
    from slither import Slither  # noqa: PLC0415

    from services.static.contract_analysis_pipeline.summaries import _detect_contract_classification
    from tests.support.foundry_project import write_foundry_project  # noqa: PLC0415

    erc20 = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.19;
    contract C {
        mapping(address => uint256) public balanceOf;
        mapping(address => mapping(address => uint256)) public allowance;
        uint256 public totalSupply;
        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
        function transfer(address to, uint256 v) external returns (bool) { balanceOf[to] += v; return true; }
        function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; return true; }
        function transferFrom(address f, address t, uint256 v) external returns (bool) {
            balanceOf[f] -= v; balanceOf[t] += v; return true;
        }
    }
    """
    project = write_foundry_project(tmp_path, "C", erc20)
    contract = next(c for c in Slither(str(project)).contracts if c.name == "C")
    # No effects artifact at all: standards must still resolve, because the
    # detector pass is not what produces them.
    classification = _detect_contract_classification(contract, tmp_path, None)
    assert "ERC20" in classification["standards"]
    assert classification["is_factory"] is None
