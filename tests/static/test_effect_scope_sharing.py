"""Sites share guard objects. The stored form must still expand to the in-memory trees, every leaf-rewriting pass must
give shared trees exactly what it gives per-site copies, and the incremental storage-dependency fixpoint must agree
with the full-copy fixpoint it replaced.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.effect_scopes import resolve_effect_scopes, site_predicates
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts, core, effect_scopes
from services.static.contract_analysis_pipeline.authorization import attach_membership_inventories
from services.static.contract_analysis_pipeline.effect_scope_codec import expand_effect_scopes
from services.static.contract_analysis_pipeline.reentrancy_pause import apply_reentrancy_pause_pass
from services.static.contract_analysis_pipeline.structural_evidence import (
    _has_state_dependency,
    _requires_authority,
    declaration,
    evidence_for,
    structural_scope,
)
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass
from tests.static.test_effect_scope_caching import SHARED_HELPERS
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/contracts/authorization"
CIRCULAR = """pragma solidity ^0.8.19;
contract Circular {
 mapping(bytes32 => uint256) a; mapping(bytes32 => uint256) b;
 function grantA(bytes32 key) external { require(b[key] != 0); a[key] = 1; }
 function grantB(bytes32 key) external { require(a[key] != 0); b[key] = 1; }
 function execute(address target, bytes calldata payload) external {
  require(a[keccak256(payload)] != 0); (bool ok,) = target.call(payload); require(ok);
 }
}"""


def _chain(length: int) -> str:
    """Authority reaches execute only through length state requirements, one fixpoint round each."""
    maps = " ".join(f"mapping(bytes32 => uint256) m{i};" for i in range(length))
    grants = "\n".join(
        f" function g{i}(bytes32 k) external {{ require(m{i - 1}[k] != 0); m{i}[k] = 1; }}" for i in range(1, length)
    )
    return f"""pragma solidity ^0.8.19;
contract Chain{length} {{
 address owner; {maps}
 function g0(bytes32 k) external {{ require(msg.sender == owner); m0[k] = 1; }}
{grants}
 function execute(address t, bytes calldata p) external {{
  require(m{length - 1}[keccak256(p)] != 0); (bool ok,) = t.call(p); require(ok);
 }}
}}"""


SOURCES = {
    "StructuralControls": (FIXTURES / "structural_controls.sol").read_text(),
    "SharedHelpers": SHARED_HELPERS,
    "CountedPermissions": (FIXTURES / "counted_permissions.sol").read_text(),
    "Circular": CIRCULAR,
    "Chain8": _chain(8),
    "Chain9": _chain(9),
}


def _reference_once(contract, scoped_trees, sites_by_function, writer_trees):
    """Relate non-caller-keyed state requirements to the actual sites that can enable them.

    Caller-keyed balances/allowances remain resource constraints. State transitions and writer gates are independent
    facts; a writer guarded only on the same unresolved dependency cannot bootstrap a proof.
    """

    evidence = evidence_for(contract)
    sites = [s for values in sites_by_function.values() for s in values]
    writer_sites = {}
    for site in sites:
        if site["kind"] == "state_write":
            writer_sites.setdefault((site["declaration"], site["node"], site["target"]), []).append(site)
    original = writer_trees
    variables = {v.name: v for v in contract.state_variables}
    relation_names = {
        "eq": "EQUAL",
        "ne": "NOT_EQUAL",
        "gt": "GREATER",
        "gte": "GREATER_EQUAL",
        "lt": "LESS",
        "lte": "LESS_EQUAL",
    }

    def visit(tree):
        if not isinstance(tree, dict):
            return
        leaf = tree.get("leaf") or {}
        descriptor = leaf.get("set_descriptor") or {}
        keys = descriptor.get("key_sources") or []
        value_predicate = descriptor.get("value_predicate") or {}
        variable = variables.get(descriptor.get("storage_var"))
        if (
            leaf.get("kind") == "membership"
            and variable is not None
            and keys
            and not any(k.get("source") in ("msg_sender", "tx_origin", "signature_recovery") for k in keys)
        ):
            op = relation_names.get(value_predicate.get("op") or "")
            rhs_values = value_predicate.get("rhs_values") or []
            try:
                rhs = int(rhs_values[0], 0) if len(rhs_values) == 1 else None
            except (TypeError, ValueError):
                rhs = None
            if op is not None and rhs is not None:
                grants = [w for w in evidence.writes_to(variable) if w.transition(op, rhs) != "revokes"]
                guards = []
                guard_ids = []
                unresolved_dependency = False
                complete = bool(grants)
                for write in grants:
                    located = writer_sites.get((declaration(write.function), write.node.node_id, variable.name), [])
                    if not located:
                        complete = False
                    for site in located:
                        predicate = original.get(site["id"])
                        if not _requires_authority(predicate):
                            complete = False
                            unresolved_dependency |= _has_state_dependency(predicate)
                        else:
                            guards.append(predicate)
                            guard_ids.append(site["id"])
                if not complete and unresolved_dependency:
                    leaf["authority_role"] = "caller_authority"
                    leaf["authority_proof"] = {"state": "not_determined", "requirements": ["state_writer_authority"]}
                if complete and guards:
                    leaf["kind"] = "authorization"
                    leaf["authority_role"] = "caller_authority"
                    leaf["authority_proof"] = {"state": "proven", "basis": "authority_enabling_writes"}
                    leaf["set_descriptor"] = {
                        "kind": "state_authority",
                        "writer_scope_ids": sorted(set(guard_ids)),
                        "storage_var": variable.name,
                        "key_sources": keys,
                    }
        for child in tree.get("children") or []:
            visit(child)

    for tree in scoped_trees.values():
        visit(tree)


def _reference_attach(contract, scoped_trees, sites_by_function):
    raw = deepcopy(scoped_trees)
    previous = scoped_trees
    updated = previous
    for _ in range(8):
        updated = deepcopy(raw)
        _reference_once(contract, updated, sites_by_function, previous)
        if updated == previous:
            break
        previous = updated
    scoped_trees.clear()
    scoped_trees.update(updated)


def _unshared(value):
    """A copy in which no object is reachable twice, i.e. the per-site copies the pipeline used to make."""
    if isinstance(value, dict):
        return {k: _unshared(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unshared(v) for v in value]
    return value


def _containers(value, found=None) -> set[int]:
    found = set() if found is None else found
    if isinstance(value, (dict, list)) and id(value) not in found:
        found.add(id(value))
        for child in value.values() if isinstance(value, dict) else value:
            _containers(child, found)
    return found


def _dump(value) -> str:
    return json.dumps(value, default=str)


def _shared_leaves(trees) -> int:
    owners: dict[int, set[str]] = {}

    def walk(key, node):
        if not isinstance(node, dict):
            return
        if isinstance(node.get("leaf"), dict):
            owners.setdefault(id(node["leaf"]), set()).add(key)
        for child in node.get("children") or []:
            walk(key, child)

    for key, tree in trees.items():
        walk(key, tree)
    return sum(1 for keys in owners.values() if len(keys) > 1)


class _Run:
    """One analysis with spies on the effect-scope passes and the encoder; every spy calls through."""

    def __init__(self, monkeypatch, project):
        self.shared_leaves = 0
        self.passes = []
        self.storage = []
        self.in_memory = None
        self.aliased = None
        writer_gate, storage, encode = (
            effect_scopes.apply_writer_gate_pass,
            effect_scopes.attach_storage_dependencies,
            core.encode_effect_scopes,
        )

        def spy_writer_gate(contract, classified):
            self.shared_leaves = max(self.shared_leaves, _shared_leaves(classified))
            self.passes.append([contract, classified, _unshared(classified)])
            return writer_gate(contract, classified)

        def spy_storage(contract, scoped_trees, sites_by_function):
            before = _unshared(scoped_trees)
            original = _dump(before)
            storage(contract, scoped_trees, sites_by_function)
            _reference_attach(contract, before, sites_by_function)
            self.storage.append((_dump(scoped_trees), _dump(before), _dump(scoped_trees) != original))
            self.passes[-1].append(sites_by_function)

        def spy_encode(predicate_trees, effects):
            self.in_memory = _dump(_unshared(predicate_trees.get("effect_scopes")))
            entry = [predicate_trees.get("trees"), predicate_trees.get("check_trees")]
            sites = [s.get("predicate") for v in (predicate_trees.get("effect_scopes") or {}).values() for s in v]
            self.aliased = len((_containers(entry) - {id(entry)}) & (_containers(sites) - {id(sites)}))
            return encode(predicate_trees, effects)

        monkeypatch.setattr(effect_scopes, "apply_writer_gate_pass", spy_writer_gate)
        monkeypatch.setattr(effect_scopes, "attach_storage_dependencies", spy_storage)
        monkeypatch.setattr(core, "encode_effect_scopes", spy_encode)
        _, trees, _ = collect_contract_analysis_with_artifacts(project)
        self.stored = json.loads(_dump(trees))


@pytest.fixture(scope="module", params=sorted(SOURCES))
def project(request, tmp_path_factory):
    return write_foundry_project(tmp_path_factory.mktemp(request.param), request.param, SOURCES[request.param])


def test_stored_scopes_expand_to_the_in_memory_trees(project, monkeypatch):
    run = _Run(monkeypatch, project)
    assert run.in_memory is not None
    # Site guards are shared with each other, never with the separately published entry trees.
    assert run.aliased == 0
    assert _dump(expand_effect_scopes(run.stored)) == run.in_memory


def test_leaf_passes_give_shared_trees_what_they_give_per_site_copies(project, monkeypatch):
    run = _Run(monkeypatch, project)
    assert run.passes
    for contract, shared, copies, sites_by_function in run.passes:
        with structural_scope(contract):
            apply_writer_gate_pass(contract, copies)
            apply_reentrancy_pause_pass(contract, copies)
            attach_membership_inventories(contract, copies)
            effect_scopes.attach_storage_dependencies(contract, copies, sites_by_function)
        assert _dump(shared) == _dump(copies)


def test_shared_trees_actually_share_leaves(monkeypatch, tmp_path):
    run = _Run(monkeypatch, write_foundry_project(tmp_path, "SharedHelpers", SHARED_HELPERS))
    assert run.shared_leaves > 0


def test_storage_dependencies_match_the_full_copy_fixpoint(project, monkeypatch):
    run = _Run(monkeypatch, project)
    assert run.storage
    for incremental, reference, _ in run.storage:
        assert incremental == reference


@pytest.mark.parametrize("length, proven", [(8, True), (9, False)])
def test_the_round_bound_still_stops_long_chains(tmp_path, monkeypatch, length, proven):
    run = _Run(monkeypatch, write_foundry_project(tmp_path, f"Chain{length}", _chain(length)))
    assert any(rewritten for _, _, rewritten in run.storage)
    sites = expand_effect_scopes(run.stored)["execute(address,bytes)"]
    kinds = {
        (leaf.get("set_descriptor") or {}).get("storage_var"): leaf.get("kind")
        for site in sites
        for leaf in _leaves(site["predicate"])
    }
    assert (kinds[f"m{length - 1}"] == "authorization") is proven


def _leaves(node):
    if not isinstance(node, dict):
        return []
    if isinstance(node.get("leaf"), dict):
        return [node["leaf"]]
    return [leaf for child in node.get("children") or [] for leaf in _leaves(child)]


def test_resolution_never_mutates_expanded_guards(project):
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    scopes = expand_effect_scopes(json.loads(_dump(trees)))
    before = _dump(scopes)
    predicates = site_predicates(scopes)
    for sites in scopes.values():
        resolve_effect_scopes(sites, AdapterRegistry(), EvaluationContext(chain_id=1), effect_predicates=predicates)
    assert _dump(scopes) == before
