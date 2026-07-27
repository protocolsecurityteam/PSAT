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
