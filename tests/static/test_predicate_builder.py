from __future__ import annotations

from typing import Any, cast

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicate_types import Operand  # noqa: E402
from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    _operand_sort_key,
    build_predicate_tree,
    build_return_predicate_tree,
)
from tests.support.slither_compile import _compile, _function  # noqa: E402


def _all_leaves(tree):
    if tree is None:
        return []
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        return [leaf] if leaf else []
    out = []
    for child in tree.get("children") or []:
        out.extend(_all_leaves(child))
    return out


def test_try_catch_external_bool_call_builds_delegated_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAuthority {
            function canCall(address who) external view returns (bool);
        }
        contract C {
            IAuthority public authority;
            function f() external {
                try authority.canCall(msg.sender) returns (bool ok) {
                    require(ok);
                } catch {
                    revert("denied");
                }
            }
        }
    """,
    )
    fn = _function(sl, "f")
    tree = build_predicate_tree(fn)
    assert tree is not None
    leaves = _all_leaves(tree)
    leaf = next(
        leaf
        for leaf in leaves
        if leaf.get("kind") == "external_bool" and leaf.get("authority_role") == "delegated_authority"
    )
    assert leaf["kind"] == "external_bool"
    assert leaf["authority_role"] == "delegated_authority"
    descriptor = leaf.get("set_descriptor")
    assert isinstance(descriptor, dict)
    assert descriptor.get("callee_signature") == "canCall(address)"


def test_confidence_low_for_unsupported(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            function externalCheck() external pure returns (bool) { return true; }
            function f() external {
                bool a = (block.timestamp + block.number) % 2 == 0;
                require(a);
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["confidence"] == "low"  # pyright: ignore[reportTypedDictNotRequiredAccess]


def test_caller_equals_constant_address_classifies_caller_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function f() external {
                require(msg.sender == 0x1111111111111111111111111111111111111111);
                x = 1;
            }
        }
    """,
    )
    fn = _function(sl, "f")
    leaves = _all_leaves(build_predicate_tree(fn))
    assert leaves[0]["authority_role"] == "caller_authority"


# #120: a tail ``return true`` must carry the negation of every dominating deny-IF, or fail closed.


def _membership_var(leaf):
    return (leaf.get("set_descriptor") or {}).get("storage_var")


def test_issue120_maker_dsauth_allow_chain_unchanged(tmp_path):
    """Verbatim Maker ds-auth: its ``return true`` paths are genuine allows."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface DSAuthority {
            function canCall(address src, address dst, bytes4 sig) external view returns (bool);
        }
        contract C {
            address owner;
            DSAuthority authority;
            function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
                if (src == address(this)) {
                    return true;
                } else if (src == owner) {
                    return true;
                } else if (authority == DSAuthority(address(0))) {
                    return false;
                } else {
                    return authority.canCall(src, address(this), sig);
                }
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "OR", tree
    leaves = _all_leaves(tree)
    kinds = sorted(le["kind"] for le in leaves)
    assert kinds == ["equality", "equality", "external_bool"], leaves
    assert sorted(le["operator"] for le in leaves) == ["eq", "eq", "truthy"], leaves
    assert not any(le["operator"] == "falsy" for le in leaves), leaves
    assert not any(le["kind"] == "unsupported" for le in leaves), leaves


def test_issue120_standalone_require_not_projected_public(tmp_path):
    """The builder only inspected IF nodes, so ``require(wl)`` was dropped."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) wl;
            mapping(address => bool) bl;
            function isAuthorized(address src) internal view returns (bool) {
                require(wl[src]);
                if (bl[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "AND", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("wl", "truthy"),
        ("bl", "falsy"),
    }, leaves
    assert any(le["operator"] == "truthy" and _membership_var(le) == "wl" for le in leaves), leaves


def _assert_no_lone_falsy(tree):
    """A dropped positive guard would re-admit every principal outside the set."""
    leaves = _all_leaves(tree)
    has_falsy = any(le["kind"] == "membership" and le["operator"] == "falsy" for le in leaves)
    has_truthy = any(le["kind"] == "membership" and le["operator"] == "truthy" for le in leaves)
    is_unsupported = any(le["kind"] == "unsupported" for le in leaves)
    assert (not has_falsy) or has_truthy or is_unsupported, leaves


def test_issue120_internal_call_revert_deny_ands_positive_guard(tmp_path):
    """The helper call's EXPRESSION node keeps a fall-through edge unless a provably always-reverting callee is sunk."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(address => bool) auth;
            mapping(address => bool) b;
            function _deny() internal pure { revert("denied"); }
            function isAuthorized(address src) internal view returns (bool) {
                if (!auth[src]) _deny();
                if (b[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    assert tree is not None
    assert tree.get("op") == "AND", tree
    leaves = _all_leaves(tree)
    assert {(_membership_var(le), le["operator"]) for le in leaves} == {
        ("auth", "truthy"),
        ("b", "falsy"),
    }, leaves
    assert any(le["operator"] == "truthy" and _membership_var(le) == "auth" for le in leaves), leaves
    _assert_no_lone_falsy(tree)


def test_issue120_unclassified_call_deny_fails_closed(tmp_path):
    """``_callee_always_reverts`` can't see an external call's body."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IGuard { function enforce(address s) external; }
        contract C {
            mapping(address => bool) auth;
            mapping(address => bool) b;
            IGuard g;
            function isAuthorized(address src) internal returns (bool) {
                if (!auth[src]) g.enforce(src);
                if (b[src]) return false;
                return true;
            }
        }
    """,
    )
    tree = build_return_predicate_tree(_function(sl, "isAuthorized"))
    leaves = _all_leaves(tree)
    assert any(le["kind"] == "unsupported" for le in leaves), leaves
    _assert_no_lone_falsy(tree)


def test_hash_commitment_leaf_keeps_its_computed_operand_and_names_what_it_commits(tmp_path):
    """Teller ``refundDeposit``: the gate names the parameters the hash commits, and the ``computed`` operand
    survives, since promoting a committed parameter would read as self-service.
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            mapping(uint256 => bytes32) history;
            function refund(uint256 nonce, address receiver, uint256 amount) external {
                require(history[nonce] == keccak256(abi.encode(receiver, amount)), "bad");
                delete history[nonce];
            }
        }
    """,
    )
    leaves = _all_leaves(build_predicate_tree(_function(sl, "refund")))
    leaf = next(le for le in leaves if "keccak256" in str(le.get("operands")))
    computed = next(o for o in leaf["operands"] if o["source"] == "computed")
    computed_kind = computed.get("computed_kind")
    assert computed_kind is not None and computed_kind.startswith("keccak256")
    assert leaf["kind"] == "equality"
    derived_from = computed.get("derived_from")
    assert derived_from is not None
    bound = {(o.get("parameter_index"), o.get("parameter_name")) for o in derived_from if o["source"] == "parameter"}
    assert bound == {(1, "receiver"), (2, "amount")}
    assert [o["source"] for o in leaf["operands"]] == ["parameter", "computed"]
    assert leaf["parameter_indices"] == [0]


def test_computed_operand_without_argument_provenance_says_not_determined(tmp_path):
    """``or []`` would claim no parameter reaches it."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public price;
            function buy(uint256 qty) external payable {
                require(msg.value == price * qty, "bad");
            }
        }
    """,
    )
    leaves = _all_leaves(build_predicate_tree(_function(sl, "buy")))
    computed = [o for le in leaves for o in le["operands"] if o["source"] == "computed"]
    assert computed, leaves
    assert all("derived_from" in o for o in computed)
    assert all(o.get("derived_from") is None for o in computed)


# Over the 88-contract replay the marker has zero realised rows, so these prove it's reachable by construction and
# precise both ways.


_VALUE_GATED = """
    pragma solidity ^0.8.19;
    contract C {
        function sweep(uint256 amount) external {
            require(amount > 0);
            payable(msg.sender).transfer(amount);
        }
    }
"""


def test_uncertain_marker_not_fired_for_value_gate_under_same_failure(tmp_path, monkeypatch):
    """Adverse direction: the SAME failure on a value-check gate (``require(amount >
    0)``) must NOT flag the function; marking real public functions unsupported is an
    over-hedge: a value constraint does not establish caller authority."""
    import services.static.contract_analysis_pipeline.predicates.tree as predicates_mod

    sl = _compile(tmp_path, _VALUE_GATED)
    fn = _function(sl, "sweep")

    monkeypatch.setattr(predicates_mod, "_build_subtree_from_gate", lambda gate, prov, function: None)
    uncertain: set[str] = set()
    tree = predicates_mod.build_predicate_tree(fn, uncertain_out=uncertain)
    assert tree is None
    assert uncertain == set()


def test_uncertain_marker_reaches_artifact_and_policy_routes_unsupported(tmp_path, monkeypatch):
    import services.static.contract_analysis_pipeline.predicates.tree as predicates_mod
    from services.policy.effective_permissions import build_effective_permissions
    from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts

    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public ownerVar;
            uint256 public counter;
            function sweep(address to) external {
                if (msg.sender != ownerVar) revert();
                payable(to).transfer(address(this).balance);
            }
            function ping() external {
                counter += 1;
            }
        }
    """,
    )
    contract = next(c for c in sl.contracts if c.name == "C")

    monkeypatch.setattr(predicates_mod, "_build_subtree_from_gate", lambda gate, prov, function: None)
    artifact = build_predicate_artifacts(contract)
    assert artifact.get("guard_extraction_uncertain") == ["sweep(address)"]
    assert "sweep(address)" not in (artifact.get("trees") or {})

    target = {"subject": {"address": "0x" + "ab" * 20, "name": "C"}}
    effects = {
        "functions": {
            "sweep(address)": {
                "function": "sweep(address)",
                "state_changing": True,
                "state_writes": [],
                "sinks": [],
                "writer_selectors": [],
            },
            "ping()": {
                "function": "ping()",
                "state_changing": True,
                "state_writes": ["counter"],
                "sinks": [{"kind": "external_call", "target": "hook"}],
                "writer_selectors": [],
            },
        }
    }
    payload = build_effective_permissions(
        target,
        capability_resolver_output={},
        effects=effects,
        predicate_trees=artifact,
    )
    sweep = next(f for f in payload["functions"] if f["function"] == "sweep(address)")
    assert sweep.get("status") == "unsupported"
    assert sweep.get("capability_expr", {}).get("unsupported_reason") == "guard_extraction_uncertain"
    assert sweep.get("authority_public") is not True
    ping = next(f for f in payload["functions"] if f["function"] == "ping()")
    assert ping.get("status") == "public"
    assert ping["authority_public"] is True


def test_operand_sort_key_totally_orders_element_fields():
    """``absorbed_operands`` is evidence, so order comes from content."""

    def key(op: dict[str, Any]) -> tuple[str, ...]:
        # ``bare`` is the shape of an operand that resolved no element read.
        return _operand_sort_key(cast(Operand, op))

    bare = {"source": "state_variable", "state_variable_name": "bids"}
    keyed = {
        **bare,
        "element_base_variable": "C.bids",
        "element_member_path": ["amount"],
        "element_key_param_index": 0,
    }
    other_key = {**keyed, "element_key_param_index": 2}

    assert key(bare) != key(keyed)
    assert key(keyed) != key(other_key)
    assert sorted([keyed, bare, other_key], key=key)[0] is bare
    assert all(isinstance(slot, str) for slot in key(keyed))


_ELEMENT_FIELDS = ("element_base_variable", "element_member_path", "element_key_param_index")

_ELEMENT_SRC = """
pragma solidity ^0.8.19;
contract C {
    struct Bid { address bidderAddress; uint256 amount; }
    mapping(uint256 => Bid) public bids;
    mapping(address => uint256) public balances;
    mapping(uint256 => mapping(uint256 => address)) public nested;
    address[] public admins;

    function guardedRecord(uint256 _bidId) external view {
        require(bids[_bidId].bidderAddress == msg.sender);
    }
    function scalarCollection(uint256 _idx) external view {
        require(admins[_idx] == msg.sender);
    }
    function bareParameter(address who) external view {
        require(msg.sender == who);
    }
    function callerKeyed() external view {
        require(balances[msg.sender] > 0);
    }
    function constantKey() external view {
        require(admins[3] == msg.sender);
    }
    function computedKey(uint256 _bidId) external view {
        require(bids[_bidId + 1].bidderAddress == msg.sender);
    }
    function storagePointer(uint256 _bidId) external view {
        Bid storage b = bids[_bidId];
        require(b.bidderAddress == msg.sender);
    }
    function twoKeyLevels(uint256 a, uint256 b) external view {
        require(nested[a][b] == msg.sender);
    }
    function mergedChain(uint256 _id, bool flag) external view {
        address who = flag ? bids[_id].bidderAddress : admins[_id];
        require(who == msg.sender);
    }
    function mergedKeyTernary(uint256 a, uint256 b, bool flag) external view {
        uint256 k = flag ? a : b;
        require(bids[k].bidderAddress == msg.sender);
    }
    function mergedKeyIfElse(uint256 a, uint256 b, bool flag) external view {
        uint256 k;
        if (flag) { k = a; } else { k = b; }
        require(bids[k].bidderAddress == msg.sender);
    }
    function mergedCallerOrParameterKey(address who, bool flag) external view {
        address k = flag ? msg.sender : who;
        require(balances[k] > 0);
    }
}
"""


@pytest.fixture(scope="module")
def element_slither(tmp_path_factory):
    return _compile(tmp_path_factory.mktemp("element"), _ELEMENT_SRC)


def _operands(sl: Slither, name: str) -> list[dict[str, Any]]:
    tree = build_predicate_tree(_function(sl, name))
    out: list[dict[str, Any]] = []
    for leaf in _all_leaves(tree):
        out.extend(cast("list[dict[str, Any]]", leaf.get("operands") or []))
    assert out, f"{name} produced no operands"
    # A base without its key is not a cell.
    for op in out:
        present = [field for field in _ELEMENT_FIELDS if field in op]
        assert present in ([], list(_ELEMENT_FIELDS)), op
    return out


def test_element_read_stamps_record_on_the_parameter_polarity(element_slither):
    """The pick publishes the bare parameter, so without the stamp the guarded record is lost."""
    element, caller = _operands(element_slither, "guardedRecord")
    assert element["element_base_variable"] == "C.bids"
    assert element["element_member_path"] == ["bidderAddress"]
    assert element["element_key_param_index"] == 0
    assert element["source"] == "parameter"
    assert element["parameter_index"] == 0
    assert element["parameter_name"] == "_bidId"
    assert caller["source"] == "msg_sender"
    assert not any(field in caller for field in _ELEMENT_FIELDS)


def test_collection_polarity_refuses_a_key_it_cannot_pin(element_slither):
    collection = next(op for op in _operands(element_slither, "constantKey") if op["source"] == "state_variable")
    assert collection["state_variable_name"] == "admins"
    assert not any(field in collection for field in _ELEMENT_FIELDS)


@pytest.mark.parametrize(
    "function_name",
    [
        pytest.param("bareParameter", id="bare_parameter_comparison"),
        # Reading the slot would claim agreement with ``bids[_bidId]`` over two different cells.
        pytest.param("computedKey", id="computed_key"),
        pytest.param("storagePointer", id="storage_pointer_local"),
        pytest.param("twoKeyLevels", id="two_key_levels"),
        pytest.param("mergedChain", id="merged_chain"),
    ],
)
def test_unpinnable_element_read_stamps_nothing(element_slither, function_name):
    for op in _operands(element_slither, function_name):
        assert not any(field in op for field in _ELEMENT_FIELDS)


def test_caller_or_parameter_merged_key_stamps_nothing(element_slither):
    """The surviving source is the parameter, so a slot-only reading would publish a possibly-caller cell as
    parameter-named.
    """
    for op in _operands(element_slither, "mergedCallerOrParameterKey"):
        assert not any(field in op for field in _ELEMENT_FIELDS)
    sibling = next(op for op in _operands(element_slither, "callerKeyed") if "element_base_variable" in op)
    assert sibling["element_base_variable"] == "C.balances"
    assert sibling["element_key_param_index"] is None
