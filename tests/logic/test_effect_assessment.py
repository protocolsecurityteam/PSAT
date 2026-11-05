"""Effect-specific model estimates cannot erase or spread authorization across branches."""

import copy
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from eth_abi.abi import decode
from eth_abi.abi import encode as abi_encode
from eth_utils.crypto import keccak

from services.clients.jev import DEFAULT_MODEL, JevClient
from services.logic.expansion import Selection, expand_formula, formula_hash
from services.logic.formula import compile_function
from services.logic.model import decode_value, encode
from services.logic.source_context import build_bundle, build_context, digest
from services.resolution.logic_assessment import assess_formulas
from services.resolution.logic_impact import RUBRIC_VERSION, JudgmentCache, rate_effects
from services.resolution.logic_selection import selections_from_report
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.logic.test_impact import inputs, response
from tests.support.anvil import rpc

SOURCE = """pragma solidity ^0.8.10;
contract C {
 address public x;address public y;address public authority;uint public preference;uint public sharedCounter;
 constructor(address a,address b){x=a;y=b;authority=a;}
 function act(address next,uint color) external returns(address,uint) {
  if(msg.sender==x)authority=next;
  if(msg.sender==y)preference=color;
  return(authority,preference);
 }
 function restricted() external {require(msg.sender==authority);sharedCounter++;}
}"""


class EffectSession:
    def __init__(self, ratings, mutate=None):
        self.ratings, self.mutate, self.calls = ratings, mutate, []

    def post(self, url, **kwargs):
        payload = json.loads(kwargs["data"])
        self.calls.append(payload)
        answers = {}
        for key in payload["questions"]:
            effect, dimension = key.split("__")
            index = int(effect.removeprefix("effect_"))
            answers[key] = copy.deepcopy(self.ratings[index]["answers"][dimension])
        result = {"model": DEFAULT_MODEL, "answers": answers}
        if self.mutate:
            self.mutate(result)
        return SimpleNamespace(status_code=200, json=lambda: result)


@pytest.fixture
def effect_case(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C", ("address", "address"), (O.OWNER, O.ACCOUNTS[1]))
    fn = O.function(d, "C", "act")
    reads = d.chain()
    f = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C"))
    bundle = build_bundle(d.contracts("C"))
    artifact = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": O.hex20(d.at["C"]),
        "block": reads.block,
        "functions": {f.signature: encode(f)},
        "contexts": {f.signature: build_context(f, fn, bundle)},
        "source_bundle": bundle,
    }
    indices = {e.target[1]: i for i, e in enumerate(f.effects)}
    assert set(indices) == {"authority", "preference"}
    return d, reads, f, artifact, indices


def test_open_function_separate_effect_ratings_and_exact_principals(effect_case, tmp_path):
    d, reads, f, artifact, indices = effect_case
    authority, preference = indices["authority"], indices["preference"]
    # Deliberately distinct provider judgments test routing, not model accuracy.
    wire = EffectSession({authority: response(3, "shared_control"), preference: response(0, "own_entitlement")})
    before = copy.deepcopy(artifact)
    result = assess_formulas(
        artifact,
        reads=reads,
        contracts=d.contracts("C"),
        cache=JudgmentCache(tmp_path),
        client=JevClient("fake", max_requests=1, session=wire),
    )
    assert artifact == before and len(wire.calls) == 1
    assert result["assessment"]["schema"] == 3 and result["assessment"]["rubric_version"] == RUBRIC_VERSION
    ratings = result["assessment"]["functions"][f.signature]
    assert "level" not in ratings
    assert ratings["effects"][str(authority)]["level"] == "high"
    assert ratings["effects"][str(preference)]["level"] == "none"
    rows = {r["effect_index"]: r for r in result["rows"]}
    assert rows[authority]["decision"] == "expand" and rows[preference]["decision"] == "review"
    assert all(r["access"]["status"] == "restricted" for r in rows.values())
    assert selections_from_report(artifact, result) == {f.signature: Selection(False, (authority,))}
    program = decode_value(wire.calls[0]["state"]["program"])
    assert program["transitions"] == decode_value(encode(f.transitions))
    assert set(program["effects"]) == {str(authority), str(preference)}
    assert all(k.startswith(("effect_0__", "effect_1__")) for k in wire.calls[0]["questions"])
    assert "restricted()" in "\n".join(u["source"] for u in wire.calls[0]["state"]["sources"])
    both = expand_formula(f, reads, d.contracts("C"), selection=Selection(True, (authority, preference)))
    assert both.callers is not None and both.callers.complete and both.callers.representation == "cofinite"
    assert both.effects[0].complete and both.effects[0].members == (O.OWNER,)
    assert both.effects[1].complete and both.effects[1].members == (O.ACCOUNTS[1],)
    # Independent EVM observation: all callers succeed, but their changes differ.
    next_address = O.ACCOUNTS[3]
    data = "0x" + (keccak(text=f.signature)[:4] + abi_encode(["address", "uint256"], [O.hex20(next_address), 9])).hex()
    for caller, want in [(O.OWNER, (next_address, 0)), (O.ACCOUNTS[1], (O.OWNER, 9)), (O.ACCOUNTS[2], (O.OWNER, 0))]:
        raw = rpc(d.url, "eth_call", [{"to": O.hex20(d.at["C"]), "from": O.hex20(caller), "data": data}, "latest"])
        owner, color = decode(["address", "uint256"], bytes.fromhex(raw[2:]))
        assert (int(owner, 16), color) == want


@pytest.mark.parametrize("defect", ["missing", "extra", "legacy"])
def test_incomplete_or_unscoped_batch_is_not_reused_for_other_effects(effect_case, tmp_path, defect):
    d, reads, f, artifact, indices = effect_case

    def mutate(result):
        if defect == "missing":
            result["answers"].pop("effect_1__scope")
        elif defect == "extra":
            result["answers"]["effect_99__scope"] = response()["answers"]["scope"]
        else:
            result["answers"] = response()["answers"]

    wire = EffectSession({i: response() for i in indices.values()}, mutate)
    result = assess_formulas(
        artifact,
        reads=reads,
        contracts=d.contracts("C"),
        cache=JudgmentCache(tmp_path),
        client=JevClient("fake", session=wire),
    )
    assert not result["suggested_expansions"] and not result["assessment"]["judgments_complete"]
    assert all(r["model_status"] == "error" for r in result["assessment"]["functions"][f.signature]["effects"].values())
    assert not list(tmp_path.glob("*.json"))


def test_effect_order_and_transition_changes_invalidate_cached_judgment(effect_case, tmp_path):
    _, _, f, artifact, indices = effect_case
    wire = EffectSession({i: response() for i in indices.values()})
    cache = JudgmentCache(tmp_path)
    rate_effects(artifact, cache=cache, client=JevClient("fake", session=wire))
    for changed in [replace(f, effects=tuple(reversed(f.effects))), replace(f, transitions=())]:
        edited = copy.deepcopy(artifact)
        edited["functions"][f.signature] = encode(changed)
        context = edited["contexts"][f.signature]
        context["formula_hash"] = formula_hash(changed)
        context["context_hash"] = digest({k: v for k, v in context.items() if k != "context_hash"})
        result = rate_effects(edited, cache=cache)
        assert result["wire_requests"] == 0 and result["functions"][f.signature]["model_status"] == "cache_miss"


def test_legacy_assessment_cannot_authorize_effect_enumeration(effect_case, tmp_path):
    d, reads, f, artifact, indices = effect_case
    result = assess_formulas(
        artifact,
        reads=reads,
        contracts=d.contracts("C"),
        cache=JudgmentCache(tmp_path),
        client=JevClient("fake", session=EffectSession({i: response() for i in indices.values()})),
    )
    result["assessment"]["schema"] = 2
    with pytest.raises(ValueError, match="assessment"):
        selections_from_report(artifact, result)


def test_no_effects_and_pending_operations_remain_visible_without_model_guesses(tmp_path):
    f, artifact, _ = inputs()
    f = replace(f, effects=())
    artifact["functions"][f.signature] = encode(f)
    artifact.pop("contexts")
    artifact["pending_functions"] = {"unfinished()": {"reason": "call", "blocker": "unresolved:call_target"}}
    wire = EffectSession({})
    result = assess_formulas(artifact, cache=JudgmentCache(tmp_path), client=JevClient("fake", session=wire))
    assert not wire.calls and not result["assessment"]["judgments_complete"]
    assert result["rows"][0]["effect_index"] is None and result["rows"][0]["decision"] == "review"
    assert result["pending_functions"]["unfinished()"]["blocker"] == "unresolved:call_target"


POWER_SOURCE = """pragma solidity ^0.8.10;
contract C {
 address public owner=msg.sender;uint8 public value;
 function branch(uint8 v) external returns(uint8) {if(msg.sender==owner)value=v;else value=1;return value;}
 function guarded(uint8 v) external returns(uint8) {require(msg.sender==owner || v==1);value=v;return value;}
 function bounded(uint8 v) external returns(uint8) {require(v<=(msg.sender==owner?100:1));value=v;return value;}
 function sameDomain(uint8 v) external returns(uint8) {value=msg.sender==owner?v:255-v;return value;}
}
"""


@pytest.mark.parametrize("name", ["branch", "guarded", "bounded", "sameDomain"])
def test_same_slot_outcome_control_selects_owner_without_splitting_paths(anvil, tmp_path, name):
    from services.resolution.logic_selection import ReportLimits

    d = O.deployment(anvil[0], tmp_path, POWER_SOURCE)
    d.deploy("C")
    fn, reads = O.function(d, "C", name), d.chain()
    f = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C"))
    bundle = build_bundle(d.contracts("C"))
    artifact = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": O.hex20(d.at["C"]),
        "block": reads.block,
        "functions": {f.signature: encode(f)},
        "source_bundle": bundle,
        "contexts": {f.signature: build_context(f, fn, bundle)},
    }
    assert len(f.effects) == 1
    result = assess_formulas(
        artifact,
        reads=reads,
        contracts=d.contracts("C"),
        cache=JudgmentCache(tmp_path / "cache"),
        client=JevClient("fake", session=EffectSession({0: response(3, "shared_control")})),
        limits=ReportLimits(solver_ms=3000),
    )
    access = result["rows"][0]["access"]
    if name == "sameDomain":
        assert access["status"] == "unrestricted" and access["outcome_access"] == "uniform", access
        assert not result["suggested_expansions"]
    else:
        assert access["status"] == "restricted" and access["occurrence_status"] == "unrestricted", access
        selection = selections_from_report(artifact, result)[f.signature]
        assert selection.power_indices == (0,)
        expanded = expand_formula(f, reads, d.contracts("C"), selection=selection)
        assert expanded.power_indices == (0,)
        assert expanded.effects[0].complete and expanded.effects[0].members == (O.OWNER,), expanded
        # A report cannot change from outcome-control to occurrence enumeration unnoticed.
        edited = copy.deepcopy(result)
        edited["suggested_expansions"][0].pop("power_indices")
        with pytest.raises(ValueError, match="scope"):
            selections_from_report(artifact, edited)
        edited = copy.deepcopy(result)
        edited["policy"] = "access-evidence-v2"
        with pytest.raises(ValueError, match="policy"):
            selections_from_report(artifact, edited)
    # Independent execution observes both callers' actual attainable outputs, including
    # argument changes needed by the reparameterized same-domain implementation.
    for who in (O.OWNER, O.ACCOUNTS[1]):
        values = (1, 50, 100) if who == O.OWNER or name == "sameDomain" else (1,)
        for wanted in values:
            arg = 255 - wanted if name == "sameDomain" and who != O.OWNER else wanted
            data = "0x" + (keccak(text=f.signature)[:4] + abi_encode(["uint8"], [arg])).hex()
            raw = rpc(d.url, "eth_call", [{"to": O.hex20(d.at["C"]), "from": O.hex20(who), "data": data}, "latest"])
            assert decode(["uint8"], bytes.fromhex(raw[2:])) == (wanted,)
        if who != O.OWNER and name in ("guarded", "bounded"):
            assert not O.passes(d, "C", fn, (50,), sender=who)
