"""``build_controller_tracking`` once typed callees (``eETH``, ``lido``) as controllers. Each target now carries its
provenance: ``caller_gate``, ``call_target``, absent when neither, and absent for every slot when there are no
predicate trees (builder raised, ``core.py`` continued).
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.resolution.tracking_plan import build_control_tracking_plan  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)
from services.static.contract_analysis_pipeline.tracking import build_controller_tracking  # noqa: E402

SOURCE = """
    pragma solidity ^0.8.20;

    interface IAuthority {
        function canCall(address who, address target, bytes4 sig) external view returns (bool);
    }

    interface IToken {
        function mint(address to, uint256 amount) external;
    }

    contract Vault {
        // Gate: every admin call is checked against this registry.
        IAuthority public roleRegistry;
        // Callee: only ever invoked, never consulted about the caller.
        IToken public eETH;
        // Neither: consulted by business logic, never gated on, never called.
        address public feeRecipient;

        constructor(IAuthority r, IToken t, address fr) {
            roleRegistry = r;
            eETH = t;
            feeRecipient = fr;
        }

        function issue(address to, uint256 amount) external {
            require(roleRegistry.canCall(msg.sender, address(this), msg.sig), "denied");
            require(to != feeRecipient, "fee recipient cannot mint");
            eETH.mint(to, amount);
        }

        function setFeeRecipient(address fr) external {
            require(roleRegistry.canCall(msg.sender, address(this), msg.sig), "denied");
            feeRecipient = fr;
        }
    }
"""


def _build(tmp_path: Path):
    src = textwrap.dedent(SOURCE).strip() + "\n"
    f = tmp_path / "Vault.sol"
    f.write_text(src)
    contract = next(c for c in Slither(str(f)).contracts if c.name == "Vault")
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    return contract, predicate_trees, effects, semantic_control


_UNSET: Any = object()


def _targets(tmp_path: Path, predicate_trees_override: Any = _UNSET):
    contract, predicate_trees, effects, semantic_control = _build(tmp_path)
    if predicate_trees_override is not _UNSET:
        predicate_trees = predicate_trees_override
    targets = build_controller_tracking(contract, tmp_path, predicate_trees, effects, semantic_control)
    return {t["source"]: t for t in targets}


def test_gate_and_callee_are_distinguishable(tmp_path):
    by_source = _targets(tmp_path)

    assert by_source["roleRegistry"]["kind"] == "external_contract"
    assert by_source["eETH"]["kind"] == "external_contract"

    assert by_source["roleRegistry"].get("authority_provenance") == "caller_gate"
    assert by_source["eETH"].get("authority_provenance") == "call_target"


def test_neither_gate_nor_callee_stays_not_determined(tmp_path):
    by_source = _targets(tmp_path)
    # Neither gated on nor called, so either answer would be invented.
    assert "feeRecipient" in by_source
    assert "authority_provenance" not in by_source["feeRecipient"]


# ``core.py`` passes this exact object when the predicate builder raises.
_TREELESS_ARTIFACTS = {
    "degraded_from_exception": {"schema_version": "semantic", "error": "boom"},
    "trees_key_empty": {"schema_version": "semantic", "trees": {}},
    "absent": None,
}


@pytest.mark.parametrize("shape", sorted(_TREELESS_ARTIFACTS))
def test_treeless_artifact_claims_no_provenance_for_anything(tmp_path, shape):
    """Answering ``call_target`` would demote the control edge and strip the registry's controller labels because the
    analysis crashed.
    """
    by_source = _targets(tmp_path, _TREELESS_ARTIFACTS[shape])

    assert by_source["roleRegistry"]["kind"] == "external_contract"
    assert by_source["eETH"]["kind"] == "external_contract"

    for name in ("roleRegistry", "eETH"):
        assert "authority_provenance" not in by_source[name], (
            f"{name} claimed provenance from a treeless artifact ({shape})"
        )


@pytest.mark.parametrize("shape", sorted(_TREELESS_ARTIFACTS))
def test_treeless_artifact_keeps_the_control_edge_through_the_plan(tmp_path, shape):
    by_source = _targets(tmp_path, _TREELESS_ARTIFACTS[shape])
    analysis = {
        "subject": {"address": "0x" + "11" * 20, "name": "Vault"},
        "controller_tracking": list(by_source.values()),
    }
    plan = build_control_tracking_plan(analysis)  # pyright: ignore[reportArgumentType]
    assert plan["tracked_controllers"], "plan lost every controller"
    assert not any(c.get("authority_provenance") for c in plan["tracked_controllers"])


def test_provenance_survives_the_tracking_plan(tmp_path):
    by_source = _targets(tmp_path)
    analysis = {
        "subject": {"address": "0x" + "11" * 20, "name": "Vault"},
        "controller_tracking": list(by_source.values()),
    }
    plan = build_control_tracking_plan(analysis)  # pyright: ignore[reportArgumentType]
    by_id = {c["controller_id"]: c for c in plan["tracked_controllers"]}
    assert by_id["external_contract:roleRegistry"].get("authority_provenance") == "caller_gate"
    assert by_id["external_contract:eETH"].get("authority_provenance") == "call_target"
    assert "authority_provenance" not in by_id["state_variable:feeRecipient"]


def test_marked_uncertain_guard_unanswers_the_names_that_function_reads(tmp_path):
    """The marker says the tree doesn't carry the whole gate."""
    contract, predicate_trees, effects, semantic_control = _build(tmp_path)
    marked = dict(predicate_trees)
    marked["guard_extraction_uncertain"] = ["issue(address,uint256)"]
    targets = build_controller_tracking(contract, tmp_path, marked, effects, semantic_control)
    by_source = {t["source"]: t for t in targets}

    assert "authority_provenance" not in by_source["eETH"]
    assert by_source["roleRegistry"].get("authority_provenance") == "caller_gate"


# EtherFi PriorityWithdrawalQueue gates ``receive()`` on ``liquidityPool``; the builder used to skip ``receive()``.
UNLOWERED_GATE_SOURCE = """
    pragma solidity ^0.8.20;

    interface ILiquidityPool {
        function escrowMigrationCompleted() external view returns (bool);
    }

    interface IRegistry {
        function canCall(address who) external view returns (bool);
    }

    interface IToken {
        function mint(address to, uint256 amount) external;
    }

    contract Queue {
        ILiquidityPool public liquidityPool;
        IRegistry public roleRegistry;
        IToken public eETH;
        uint256 public locked;

        constructor(ILiquidityPool lp, IRegistry rr, IToken t) {
            liquidityPool = lp;
            roleRegistry = rr;
            eETH = t;
        }

        // The ONLY caller gate on liquidityPool lives here. Post G3 class R
        // the builder lowers receive(), so the lowered path is pinned on this
        // fixture directly and the withholding path is exercised by removing
        // the tree (a constructed lowering failure) in the test below.
        receive() external payable {
            if (msg.sender != address(liquidityPool)) revert("IncorrectCaller");
            if (liquidityPool.escrowMigrationCompleted()) {
                locked += msg.value;
            }
        }

        function sweep() external {
            require(roleRegistry.canCall(msg.sender), "denied");
            locked = 0;
        }

        function drip(address to) external {
            eETH.mint(to, 1);
        }

        // Treeless AND caller-blind: no revert path, never reads
        // msg.sender/tx.origin. It reads ``eETH``, so dropping the
        // caller-observation narrowing would unanswer ``eETH`` too.
        function eethAddress() external view returns (address) {
            return address(eETH);
        }
    }
"""


def _unlowered_targets(tmp_path: Path):
    src = textwrap.dedent(UNLOWERED_GATE_SOURCE).strip() + "\n"
    f = tmp_path / "Queue.sol"
    f.write_text(src)
    contract = next(c for c in Slither(str(f)).contracts if c.name == "Queue")
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    targets = build_controller_tracking(contract, tmp_path, predicate_trees, effects, semantic_control)
    return predicate_trees, {t["source"]: t for t in targets}


def test_a_lowered_receive_gate_publishes_caller_gate(tmp_path):
    """G3 class-R: replaces a test that asserted the pre-class-R absence."""
    predicate_trees, by_source = _unlowered_targets(tmp_path)

    trees = predicate_trees["trees"]
    assert any(k.startswith("receive") for k in trees), (
        "class R stopped lowering receive(); the withholding test below is"
        " no longer a construction and must be re-derived"
    )
    assert by_source["liquidityPool"].get("authority_provenance") == "caller_gate"


def test_gate_in_an_unlowered_function_is_not_published_as_a_callee(tmp_path):
    """The builder now lowers every plain gate we could write, so a lowering failure is constructed by removing the
    tree. Realised rows are a lower bound.
    """
    predicate_trees, _ = _unlowered_targets(tmp_path)
    degraded = dict(predicate_trees)
    degraded["trees"] = {k: v for k, v in predicate_trees["trees"].items() if not k.startswith("receive")}
    src = textwrap.dedent(UNLOWERED_GATE_SOURCE).strip() + "\n"
    f = tmp_path / "QueueDegraded.sol"
    f.write_text(src)
    contract = next(c for c in Slither(str(f)).contracts if c.name == "Queue")
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, degraded, effects)
    targets = build_controller_tracking(contract, tmp_path, degraded, effects, semantic_control)
    by_source = {t["source"]: t for t in targets}

    assert "authority_provenance" not in by_source["liquidityPool"], (
        "a gate the builder never lowered was published as a proven callee"
    )


def test_the_correction_does_not_swallow_the_other_two_answers(tmp_path):
    """Without these the fix is indistinguishable from deleting the split."""
    _predicate_trees, by_source = _unlowered_targets(tmp_path)

    assert by_source["roleRegistry"].get("authority_provenance") == "caller_gate"
    # It never reads msg.sender/tx.origin, so it can't hold a caller gate.
    assert by_source["eETH"].get("authority_provenance") == "call_target"


def test_unenumerable_entry_points_answer_not_determined(tmp_path):
    contract, predicate_trees, effects, semantic_control = _build(tmp_path)

    class _Opaque:
        functions_entry_points = None

        def __getattr__(self, item):
            return getattr(contract, item)

    targets = build_controller_tracking(_Opaque(), tmp_path, predicate_trees, effects, semantic_control)
    by_source = {t["source"]: t for t in targets}
    assert "authority_provenance" not in by_source["eETH"]


def test_plan_built_from_a_pre_provenance_artifact_claims_nothing(tmp_path):
    by_source = _targets(tmp_path)
    legacy = []
    for target in by_source.values():
        stripped = dict(target)
        stripped.pop("authority_provenance", None)
        legacy.append(stripped)
    analysis = {
        "subject": {"address": "0x" + "11" * 20, "name": "Vault"},
        "controller_tracking": legacy,
    }
    plan = build_control_tracking_plan(analysis)  # pyright: ignore[reportArgumentType]
    assert all("authority_provenance" not in c for c in plan["tracked_controllers"])


@pytest.mark.parametrize("failing_accessor", ["all_state_variables_read", "all_solidity_variables_read"])
def test_accessor_failure_answers_not_determined_instead_of_narrowing(tmp_path, failing_accessor):
    """The non-recursive attribute is narrower, so falling back turns "couldn't read callees" into a proven absence.

    Runs on the degraded ``receive()`` shape because the Vault fixture never reaches the accessor. Reachable by
    construction only.
    """
    predicate_trees, _ = _unlowered_targets(tmp_path)
    degraded = dict(predicate_trees)
    degraded["trees"] = {k: v for k, v in predicate_trees["trees"].items() if not k.startswith("receive")}
    src = textwrap.dedent(UNLOWERED_GATE_SOURCE).strip() + "\n"
    f = tmp_path / "QueueAccessorFailure.sol"
    f.write_text(src)
    contract = next(c for c in Slither(str(f)).contracts if c.name == "Queue")
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, degraded, effects)

    clean = {t["source"]: t for t in build_controller_tracking(contract, tmp_path, degraded, effects, semantic_control)}
    assert clean["eETH"].get("authority_provenance") == "call_target"
    assert clean["roleRegistry"].get("authority_provenance") == "caller_gate"
    assert "authority_provenance" not in clean["liquidityPool"]

    class _FailingFn:
        def __init__(self, fn: Any) -> None:
            self._fn = fn

        def __getattr__(self, item: str) -> Any:
            if item == failing_accessor:

                def _raise() -> Any:
                    raise RuntimeError("slither internal failure")

                return _raise
            return getattr(self._fn, item)

    class _Degraded:
        functions_entry_points = [_FailingFn(fn) for fn in contract.functions_entry_points]

        def __getattr__(self, item: str) -> Any:
            return getattr(contract, item)

    by_source = {
        t["source"]: t for t in build_controller_tracking(_Degraded(), tmp_path, degraded, effects, semantic_control)
    }

    assert "authority_provenance" not in by_source["eETH"], (
        "a failed accessor read narrowed the gate set and minted call_target anyway"
    )
    assert by_source["roleRegistry"].get("authority_provenance") == "caller_gate"
    assert "authority_provenance" not in by_source["liquidityPool"]
