""" "Gates the caller" and "gets called" must stay distinguishable.

``build_controller_tracking`` used to union the two into one set and type both
``external_contract``, so a callee (``eETH``, ``lido``, ``liquidityPool``) was
published as a controller. The union is still what decides ``kind`` (both do
hold another contract's address); what is new is that each target carries the
provenance that put it there, and the resolution stage reads it.

Positive control: an authority registry the caller is checked against —
``authority_provenance == "caller_gate"``.
Negative control: a token the contract only calls — ``"call_target"``.
Third state: a slot that is neither — the key is absent, never guessed.
Fourth state: no predicate trees at all (the builder raised and ``core.py``
continued) — NEITHER answer is evidence, so the key is absent for every slot
including the proven gate, and no control edge is demoted.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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

    # Both are still ``external_contract`` kind — that question ("does this slot
    # hold another contract's address") was never the defective one.
    assert by_source["roleRegistry"]["kind"] == "external_contract"
    assert by_source["eETH"]["kind"] == "external_contract"

    # POSITIVE control: the registry the caller is checked against.
    assert by_source["roleRegistry"].get("authority_provenance") == "caller_gate"
    # NEGATIVE control: the token that is only ever called.
    assert by_source["eETH"].get("authority_provenance") == "call_target"


def test_neither_gate_nor_callee_stays_not_determined(tmp_path):
    by_source = _targets(tmp_path)
    # ``feeRecipient`` is a leaf operand under a business-logic role: neither
    # gated on nor called. The key must be ABSENT — inventing "call_target"
    # here would claim a call the effects stage never witnessed, and
    # "caller_gate" would claim an access check that does not exist.
    assert "feeRecipient" in by_source
    assert "authority_provenance" not in by_source["feeRecipient"]


# ``core.py`` catches any exception out of the predicate builder and continues
# with this exact object, then passes it straight to ``build_controller_tracking``.
# The other two are the degenerate shapes of the same state.
_TREELESS_ARTIFACTS = {
    "degraded_from_exception": {"schema_version": "semantic", "error": "boom"},
    "trees_key_empty": {"schema_version": "semantic", "trees": {}},
    "absent": None,
}


@pytest.mark.parametrize("shape", sorted(_TREELESS_ARTIFACTS))
def test_treeless_artifact_claims_no_provenance_for_anything(tmp_path, shape):
    """Without trees, ``caller_gate`` is unanswerable — so ``call_target`` must
    not be emitted either.

    ``caller_gate`` is read out of ``predicate_trees`` alone. If a treeless
    artifact still let the effects arm answer, every name would fall through to
    ``call_target``, and the POSITIVE control — a registry the caller is
    provably checked against — would be published as a proven callee. That is a
    proven-absent gate synthesized from a failure to determine, and downstream
    it demotes the control edge to ``external_call_target``, drops the address
    out of the authority closure and strips its ``controller_*`` labels: the
    contract is published as having no external authority controller because
    the analysis crashed.
    """
    by_source = _targets(tmp_path, _TREELESS_ARTIFACTS[shape])

    # The registry is still a target and still ``external_contract`` kind — the
    # effects artifact is intact, and "does this slot hold another contract's
    # address" is answerable without trees.
    assert by_source["roleRegistry"]["kind"] == "external_contract"
    assert by_source["eETH"]["kind"] == "external_contract"

    for name in ("roleRegistry", "eETH"):
        assert "authority_provenance" not in by_source[name], (
            f"{name} claimed provenance from a treeless artifact ({shape})"
        )


@pytest.mark.parametrize("shape", sorted(_TREELESS_ARTIFACTS))
def test_treeless_artifact_keeps_the_control_edge_through_the_plan(tmp_path, shape):
    """End of the chain: no ``call_target`` reaches the resolution stage, so
    ``resolve_control_graph`` keeps ``relation="controller_value"``."""
    by_source = _targets(tmp_path, _TREELESS_ARTIFACTS[shape])
    analysis = {
        "subject": {"address": "0x" + "11" * 20, "name": "Vault"},
        "controller_tracking": list(by_source.values()),
    }
    plan = build_control_tracking_plan(analysis)  # type: ignore[arg-type]
    assert plan["tracked_controllers"], "plan lost every controller"
    assert not any(c.get("authority_provenance") for c in plan["tracked_controllers"])


def test_provenance_survives_the_tracking_plan(tmp_path):
    by_source = _targets(tmp_path)
    analysis = {
        "subject": {"address": "0x" + "11" * 20, "name": "Vault"},
        "controller_tracking": list(by_source.values()),
    }
    plan = build_control_tracking_plan(analysis)  # type: ignore[arg-type]
    by_id = {c["controller_id"]: c for c in plan["tracked_controllers"]}
    assert by_id["external_contract:roleRegistry"].get("authority_provenance") == "caller_gate"
    assert by_id["external_contract:eETH"].get("authority_provenance") == "call_target"
    assert "authority_provenance" not in by_id["state_variable:feeRecipient"]


def test_marked_uncertain_guard_unanswers_the_names_that_function_reads(tmp_path):
    """``guard_extraction_uncertain`` names a function whose caller-authority
    comparison the builder saw and could not lower. Every name that function
    reads is then unanswered — including one that already has a tree, because
    the marker says the tree does not carry the whole gate."""
    contract, predicate_trees, effects, semantic_control = _build(tmp_path)
    marked = dict(predicate_trees)
    marked["guard_extraction_uncertain"] = ["issue(address,uint256)"]
    targets = build_controller_tracking(contract, tmp_path, marked, effects, semantic_control)
    by_source = {t["source"]: t for t in targets}

    # ``eETH`` is read by ``issue`` — no longer a proven callee.
    assert "authority_provenance" not in by_source["eETH"]
    # ``roleRegistry`` is still PROVEN to gate the caller by a lowered leaf in
    # ``setFeeRecipient``. Evidence in hand is not erased by a blind spot.
    assert by_source["roleRegistry"].get("authority_provenance") == "caller_gate"


# The reviewer-confirmed corpus shape: EtherFi PriorityWithdrawalQueue gates
# ``receive()`` on ``msg.sender == address(liquidityPool)``. The predicate
# builder never lowered ``receive()``, so that gate is invisible to
# ``caller_gate_vars`` and ``liquidityPool`` fell through to ``call_target``.
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
    """The G3 class-R merge pin: ``receive()`` now IS lowered, so its
    ``msg.sender != liquidityPool`` gate reaches ``caller_gate_vars`` and the
    address earns the stronger, correct answer instead of the withholding
    path. This test replaces one that asserted the pre-class-R absence."""
    predicate_trees, by_source = _unlowered_targets(tmp_path)

    trees = predicate_trees["trees"]
    assert any(k.startswith("receive") for k in trees), (
        "class R stopped lowering receive(); the withholding test below is"
        " no longer a construction and must be re-derived"
    )
    assert by_source["liquidityPool"].get("authority_provenance") == "caller_gate"


def test_gate_in_an_unlowered_function_is_not_published_as_a_callee(tmp_path):
    """A gate the builder FAILED to lower must not mint ``call_target``.

    Post class R the builder lowers every plain caller gate we could write —
    including receive() and assembly if-reverts — so the blind-spot branch's
    realised population is *lowering failures*, which have no nameable source
    shape. The failure is therefore constructed directly: the tree the builder
    produced for ``receive()`` is removed from the artifact, which is exactly
    the shape a raised or degraded tree stage persists. Reachable by
    construction, fixture-covered; realised rows are a lower bound, per the
    R2 convention this suite already uses for the entry-point arm.
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
    """NEGATIVE controls, both directions.

    Without these the fix is indistinguishable from deleting the split: a proven
    gate must stay ``caller_gate``, and a callee reached only from a function
    that never observes the caller must stay ``call_target``.
    """
    _predicate_trees, by_source = _unlowered_targets(tmp_path)

    assert by_source["roleRegistry"].get("authority_provenance") == "caller_gate"
    # ``eethAddress`` has no tree either, but it cannot contain a caller gate:
    # it never reads msg.sender/tx.origin. Its callee's question WAS answered.
    assert by_source["eETH"].get("authority_provenance") == "call_target"


def test_unenumerable_entry_points_answer_not_determined(tmp_path):
    """If the entry-point surface itself cannot be read, no name can claim
    ``call_target`` — the failure to enumerate is not evidence of no gate."""
    contract, predicate_trees, effects, semantic_control = _build(tmp_path)

    class _Opaque:
        """Slither contract whose entry points cannot be listed."""

        functions_entry_points = None

        def __getattr__(self, item):
            return getattr(contract, item)

    targets = build_controller_tracking(_Opaque(), tmp_path, predicate_trees, effects, semantic_control)
    by_source = {t["source"]: t for t in targets}
    assert "authority_provenance" not in by_source["eETH"]


def test_plan_built_from_a_pre_provenance_artifact_claims_nothing(tmp_path):
    """A stored analysis written before the field exists must stay
    not-determined all the way through — no default, no guess."""
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
    plan = build_control_tracking_plan(analysis)  # type: ignore[arg-type]
    assert all("authority_provenance" not in c for c in plan["tracked_controllers"])
