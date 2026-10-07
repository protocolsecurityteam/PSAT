"""The stored effect-scope form expands to exactly the trees it was encoded from; v1 artifacts read unchanged."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from services.policy.capability_surface import capability_surface_openness, project_capability_surface
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import evaluate_tree
from services.static.contract_analysis_pipeline.effect_scope_codec import (
    encode_effect_scopes,
    expand_effect_scopes,
    expand_site_predicate,
)

ROOT = Path(__file__).resolve().parents[2]


def _leaf(name: str, **extra) -> dict:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "operator": "eq",
            "authority_role": "caller_authority",
            "operands": [{"source": "msg_sender"}, {"source": "state_variable", "state_variable_name": name}],
            "basis": [f"guard on {name}"],
            **extra,
        },
    }


def _unsupported(reason: str) -> dict:
    return {"op": "LEAF", "leaf": {"kind": "unsupported", "unsupported_reason": reason, "basis": [reason]}}


def _site(signature: str, n: int, predicate) -> dict:
    return {
        "id": f"{signature}/C.f()/{n}/state_write/x",
        "kind": "state_write",
        "target": "x",
        "origin": "body",
        "sink_ids": [f"s{n}"],
        "declaration": "C.f()",
        "node": n,
        "predicate": predicate,
    }


def _artifacts():
    owner, guardian = _leaf("owner"), _leaf("guardian")
    both = {"op": "AND", "children": [owner, guardian]}
    alternatives = {"op": "OR", "children": [both, _leaf("operator")]}
    first = [
        _site("a()", 1, both),
        _site("a()", 2, both),
        _site("a()", 3, {"op": "AND", "children": [alternatives, _unsupported("effect_call_graph_incomplete")]}),
        _site("a()", 4, None),
        {**_site("a()", 5, owner), "forwarded_parameters": {"destination": 0, "payload": 1}},
    ]
    # Content-equal but distinct objects in another function collapse to the same entries.
    second = [_site("b()", 6, deepcopy(both)), _site("b()", 7, _leaf("unique_to_b"))]
    del second[1]["predicate"]
    trees = {"trees": {"a()": owner}, "check_trees": {}, "effect_scopes": {"a()": first, "b()": second}}
    effects = {
        "functions": {"a()": {"effect_scopes": first}, "b()": {"effect_scopes": second}, "c()": {"effect_scopes": []}},
        "effect_scopes_version": 2,
    }
    return trees, effects


def _stored(value):
    return json.loads(json.dumps(value))


def test_round_trip_restores_every_site_exactly():
    trees, effects = _artifacts()
    expected = json.dumps(trees["effect_scopes"])
    encode_effect_scopes(trees, effects)
    stored = _stored(trees)

    assert stored["effect_guards"]
    assert json.dumps(expand_effect_scopes(stored)) == expected
    assert json.dumps(stored["trees"]) == json.dumps({"a()": _leaf("owner")})
    refs = json.dumps(stored["effect_scopes"]).count('"ref"')
    assert refs >= 4


def test_equal_guards_in_different_functions_share_one_entry():
    trees, effects = _artifacts()
    encode_effect_scopes(trees, effects)
    stored = _stored(trees)
    first = stored["effect_scopes"]["a()"][0]["predicate"]
    other = stored["effect_scopes"]["b()"][0]["predicate"]
    assert first == other == {"ref": first["ref"]}
    assert len(stored["effect_guards"]) == len(
        {json.dumps(v, sort_keys=True) for v in stored["effect_guards"].values()}
    )


def test_expanded_guards_are_shared_between_the_sites_they_govern():
    trees, effects = _artifacts()
    encode_effect_scopes(trees, effects)
    scopes = expand_effect_scopes(_stored(trees))
    assert scopes["a()"][0]["predicate"] is scopes["a()"][1]["predicate"]
    assert scopes["a()"][0]["predicate"] is scopes["b()"][0]["predicate"]


def test_stored_effects_drop_site_predicates_without_touching_the_trees_copy():
    trees, effects = _artifacts()
    assert effects["functions"]["a()"]["effect_scopes"] is trees["effect_scopes"]["a()"]
    expected_meta = [
        [{k: v for k, v in site.items() if k != "predicate"} for site in sites]
        for sites in (trees["effect_scopes"]["a()"], trees["effect_scopes"]["b()"])
    ]
    encode_effect_scopes(trees, effects)

    stored = _stored(effects)
    assert [stored["functions"][sig]["effect_scopes"] for sig in ("a()", "b()")] == expected_meta
    assert stored["functions"]["c()"]["effect_scopes"] == []
    assert all("predicate" in site for site in trees["effect_scopes"]["a()"])


def test_ids_do_not_depend_on_the_process():
    script = (
        "import json, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from tests.static.test_effect_scope_codec import _artifacts\n"
        "from services.static.contract_analysis_pipeline.effect_scope_codec import encode_effect_scopes\n"
        "trees, effects = _artifacts()\n"
        "encode_effect_scopes(trees, effects)\n"
        "print(json.dumps(sorted(trees['effect_guards'])))\n"
    )
    runs = [
        subprocess.run(
            [sys.executable, "-c", script, str(ROOT)],
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            check=True,
            cwd=ROOT,
        ).stdout
        for seed in ("1", "2")
    ]
    trees, effects = _artifacts()
    encode_effect_scopes(trees, effects)
    assert runs[0] == runs[1] == json.dumps(sorted(trees["effect_guards"])) + "\n"


def test_v1_sites_are_read_unchanged():
    trees, _ = _artifacts()
    v1 = _stored(trees)
    scopes = expand_effect_scopes(v1)
    assert scopes == v1["effect_scopes"]
    for signature, sites in v1["effect_scopes"].items():
        for site, expanded in zip(sites, scopes[signature], strict=True):
            assert expanded.get("predicate") is site.get("predicate")


def test_an_unavailable_guard_is_not_determined_never_public():
    site = _site("a()", 1, {"op": "AND", "children": [{"ref": "0" * 24}, _leaf("owner")]})
    predicate = expand_site_predicate({"effect_guards": {}, "effect_scopes": {"a()": [site]}}, site)
    assert predicate["children"][0]["leaf"]["unsupported_reason"] == "effect_guard_unavailable"
    cap = capability_to_dict(evaluate_tree(predicate))
    assert cap["kind"] != "conditional_universal"
    alone = capability_to_dict(
        evaluate_tree(expand_site_predicate({"effect_guards": {}}, _site("a()", 2, {"ref": "x"})))
    )
    assert capability_surface_openness(alone, project_capability_surface(alone)) == "not_determined"


def test_a_cyclic_table_is_not_followed():
    site = _site("a()", 1, {"ref": "loop"})
    table = {"loop": {"op": "AND", "children": [{"ref": "loop"}, _leaf("owner")]}}
    predicate = expand_site_predicate({"effect_guards": table}, site)
    assert predicate["children"][0]["leaf"]["unsupported_reason"] == "effect_guard_unavailable"


def _business(name: str) -> dict:
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "comparison",
            "operator": "gt",
            "authority_role": "business",
            "operands": [{"source": "parameter", "parameter_index": 0}, {"source": "constant", "constant_value": "0"}],
            "expression": f"{name} > 0",
            "basis": [],
        },
    }


@pytest.mark.parametrize(
    "table",
    [{}, {"loop": {"op": "AND", "children": [{"ref": "loop"}, _business("inner")]}}],
    ids=["missing", "cyclic"],
)
def test_an_unavailable_guard_beside_a_business_condition_is_not_determined(table):
    ref = "loop" if table else "gone"
    site = _site("a()", 1, {"op": "AND", "children": [{"ref": ref}, _business("amount")]})
    cap = capability_to_dict(evaluate_tree(expand_site_predicate({"effect_guards": table}, site)))
    assert capability_surface_openness(cap, project_capability_surface(cap)) == "not_determined"


def test_equal_content_in_another_key_order_expands_as_built():
    first = _leaf("owner")
    reordered = {"leaf": dict(reversed(list(first["leaf"].items()))), "op": "LEAF"}
    sites = [_site("a()", n, tree) for n, tree in enumerate([first, first, reordered, reordered])]
    trees = {"trees": {}, "check_trees": {}, "effect_scopes": {"a()": sites}}
    expected = json.dumps(trees["effect_scopes"])
    encode_effect_scopes(trees, {"functions": {}})
    stored = _stored(trees)
    assert len(stored["effect_guards"]) == 2
    assert json.dumps(expand_effect_scopes(stored)) == expected
