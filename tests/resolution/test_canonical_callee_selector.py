"""The resolver finds a callee's tree, and keys a child frame's ``msg.sig``, by the selector the call dispatches on.

A caller and its callee often spell the same parameter differently (``IToken`` in the caller's interface, ``Token`` in
the callee's source), so their Slither spellings never match and only the canonical selector joins them. Trees stored
before canonical lowering carry the hash of the caller's spelling and must still resolve.
"""

from __future__ import annotations

import tempfile
import textwrap
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.resolution.adapters.enumerable_role_store import _resolve_callee_selector  # noqa: E402
from services.resolution.predicate_evaluator.binding import _tree_for_signature_or_selector  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


CALLEE_KEY = "onlyOperator(address,Token)"
CALLEE_CANONICAL = "onlyOperator(address,address)"
CALLER_SPELLING = "onlyOperator(address,IToken)"
_TREE = {"op": "LEAF", "leaf": {"kind": "equality", "operator": "truthy", "operands": []}}


@pytest.mark.parametrize(
    ("selector", "canonical", "found"),
    [
        pytest.param(_sel(CALLEE_CANONICAL), {CALLEE_KEY: CALLEE_CANONICAL}, True, id="canonical_via_map"),
        # A tree stored before lowering carries the hash of the spelling it was keyed under.
        pytest.param(_sel(CALLEE_KEY), {CALLEE_KEY: CALLEE_CANONICAL}, True, id="legacy_spelling_hash"),
        # Without the map an unlowered key has no dispatch selector, so the canonical one can't be matched.
        pytest.param(_sel(CALLEE_CANONICAL), None, False, id="no_map_no_invention"),
        pytest.param(_sel(CALLER_SPELLING), {CALLEE_KEY: CALLEE_CANONICAL}, False, id="foreign_spelling"),
    ],
)
def test_callee_tree_lookup_by_selector(selector, canonical, found):
    got = _tree_for_signature_or_selector(
        {CALLEE_KEY: _TREE},
        callee_signature=CALLER_SPELLING,
        callee_selector=selector,
        canonical_signatures=canonical,
    )
    assert (got is _TREE) is found


def test_an_already_canonical_key_matches_without_a_map():
    trees = {"isOperator(address)": _TREE}
    got = _tree_for_signature_or_selector(
        trees, callee_signature=None, callee_selector=_sel("isOperator(address)"), canonical_signatures=None
    )
    assert got is _TREE


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        ("hasRole(bytes32,address)", _sel("hasRole(bytes32,address)")),
        ("exit(address,ERC20,uint256,address,uint256)", None),
        ("fallback()", None),
        (None, None),
    ],
)
def test_a_missing_selector_is_recovered_only_from_a_canonical_signature(signature, expected):
    from services.resolution.predicate_evaluator.binding import _selector_for_canonical_signature

    assert _selector_for_canonical_signature(signature) == expected
    assert _resolve_callee_selector({"callee_signature": signature}) == expected


def test_a_stored_selector_is_used_as_is():
    assert _resolve_callee_selector({"callee_selector": "0xABCDEF01", "callee_signature": "x(Foo)"}) == "0xabcdef01"


_CALLER = """
pragma solidity ^0.8.19;
interface IToken {}
interface IReg {
    function onlyOperator(address account, IToken token) external view;
}
contract CallerLike {
    IReg public registry;
    IToken public token;
    uint256 public v;
    function guarded(uint256 x) external {
        registry.onlyOperator(msg.sender, token);
        v = x;
    }
}
"""


def _caller_trees() -> dict[str, Any]:
    path = Path(tempfile.mkdtemp()) / "CallerLike.sol"
    path.write_text(textwrap.dedent(_CALLER).strip() + "\n")
    contract = next(c for c in Slither(str(path)).contracts if c.name == "CallerLike")
    return {fn.full_name: build_predicate_tree(fn) for fn in contract.functions if not fn.is_constructor}


def _opaque_callee_tree() -> dict[str, Any]:
    """The registry's ``onlyOperator`` gate as an opaque leaf: inlining it projects public, so the refine-only guard
    closes it and tags the basis. The tag proves the callee tree was found."""
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "operator": "truthy",
            "authority_role": "business",
            "operands": [{"source": "view_call", "callee": "hasRole"}],
            "references_msg_sender": False,
            "parameter_indices": [],
            "expression": "! hasRole(account, OPERATOR_ROLE)",
            "basis": [],
        },
    }


def _resolve_two_hop(session, caller_trees: dict[str, Any], callee_artifact: dict[str, Any]) -> dict[str, Any]:
    from db.models import Contract, ControllerValue, Job, JobStage, JobStatus, Protocol
    from db.queue import store_artifact
    from services.resolution.capability_resolver import resolve_contract_capabilities

    proto = Protocol(name=f"canonical-callee-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    caller_addr = "0x" + uuid.uuid4().hex[:8] + "a1" * 16
    registry_addr = "0x" + uuid.uuid4().hex[:8] + "b2" * 16

    def _seed(addr: str, artifact: dict[str, Any]):
        now = datetime.now(timezone.utc)
        job = Job(
            address=addr,
            request={"address": addr, "name": "T"},
            status=JobStatus.completed,
            stage=JobStage.done,
            created_at=now,
            updated_at=now,
        )
        session.add(job)
        session.flush()
        store_artifact(session, job.id, "predicate_trees", data={"schema_version": "semantic", **artifact})
        contract = Contract(address=addr, chain="ethereum", protocol_id=proto.id, job_id=job.id)
        session.add(contract)
        session.flush()
        return job, contract

    caller_job, caller_contract = _seed(caller_addr, {"trees": caller_trees})
    _seed(registry_addr, callee_artifact)
    session.add(
        ControllerValue(
            contract_id=caller_contract.id,
            controller_id="external_contract:registry",
            value=registry_addr,
            resolved_type="contract",
            source="state_variable",
        )
    )
    session.commit()
    caps = resolve_contract_capabilities(
        session, address=caller_addr, chain_id=1, chain="ethereum", job_id=caller_job.id
    )
    return (caps or {})["guarded(uint256)"]


def _basis(cap: dict[str, Any]) -> list[str]:
    return list(((cap.get("check") or {}).get("extra") or {}).get("basis") or [])


@requires_postgres
def test_inlining_reaches_a_callee_spelled_differently_through_the_canonical_selector(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", "1")
    caller = _caller_trees()
    cap = _resolve_two_hop(
        db_session,
        caller,
        {"trees": {CALLEE_KEY: _opaque_callee_tree()}, "canonical_signatures": {CALLEE_KEY: CALLEE_CANONICAL}},
    )
    assert cap["kind"] == "external_check_only"
    assert "inline_refine_only_guard" in _basis(cap)
    assert cap["check"]["target_call_selector"] == _sel(CALLEE_CANONICAL)
