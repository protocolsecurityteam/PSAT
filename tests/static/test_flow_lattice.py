"""Regression tests for the ``flow.out`` destination/amount lattice.

Guards the -12 theft-vs-routing false positives: fixed destinations must differ from caller-chosen ones, and ambiguity
degrades to ``indeterminate``.
"""

from __future__ import annotations

from typing import Any

import pytest

slither = pytest.importorskip("slither")

from services.static.claims import build_claims  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from tests.support.slither_compile import _compile_named  # noqa: E402


def _out_flow(info, kind: str | None = None) -> Any:
    flows: list[Any] = [vf for vf in info["value_flows"] if vf["direction"] == "out"]
    if kind is not None:
        flows = [vf for vf in flows if vf["kind"] == kind]
    assert flows, f"no matching out-flow in {info['value_flows']}"
    return flows[0]


LATTICE_SRC = """
pragma solidity ^0.8.20;

interface ILP { function totalValueOutOfLp() external view returns (uint256); }
interface IERC20 { function transfer(address,uint256) external returns (bool); }

library Math { function min(uint256 a, uint256 b) internal pure returns (uint256){ return a < b ? a : b; } }

contract Lattice {
    ILP public immutable liquidityPool;
    address public immutable feeSink;
    address public treasury;               // has a setter -> storage_setter
    address public collector;              // no setter    -> storage_no_setter
    address public constant BURN = address(0xdead);
    uint256 public cap;

    constructor(ILP lp, address fs) { liquidityPool = lp; feeSink = fs; }

    function setTreasury(address t) external { treasury = t; }

    // Cast-through-immutable (the withdrawEther shape): dest is a TMP from
    // address(liquidityPool) -> immutable, static_trace. Amount is a Math.min of
    // the self-balance and a view call -> capped_by_balance (<= own balance).
    function withdrawEther() external {
        uint256 amt = Math.min(address(this).balance, liquidityPool.totalValueOutOfLp());
        (bool ok,) = payable(address(liquidityPool)).call{value: amt}("");
        require(ok);
    }

    // Caller-supplied destination + caller-supplied amount = extraction.
    function payTo(address dest, uint256 amount) external {
        (bool ok,) = payable(dest).call{value: amount}("");
        require(ok);
    }

    // Direct immutable destination (no cast): ERC20 send with a state var arg0
    // -> immutable, dispositive_ast. msg.sender is a direct caller read.
    function feeToSink(address tok, uint256 amt) external {
        IERC20(tok).transfer(feeSink, amt);
    }

    function claim(address tok, uint256 amt) external {
        IERC20(tok).transfer(msg.sender, amt);
    }

    // storage_setter destination + storage amount.
    function payTreasury() external {
        (bool ok,) = payable(treasury).call{value: cap}("");
        require(ok);
    }

    // storage_no_setter destination (collector is never written outside ctor).
    function payCollector() external {
        (bool ok,) = payable(collector).call{value: 1 ether}("");
        require(ok);
    }

    // constant destination + msg.value amount.
    function toBurn() external payable {
        (bool ok,) = payable(BURN).call{value: msg.value}("");
        require(ok);
    }

    // Cross-branch MIX: caller param on one path, immutable on the other.
    // The union absorbs to TOP -> indeterminate. Never guess a member.
    function payMix(bool cond, address who, uint256 amt) external {
        if (cond) { (bool a,) = payable(who).call{value: amt}(""); require(a); }
        else { (bool b,) = payable(address(liquidityPool)).call{value: amt}(""); require(b); }
    }

    // Native transfer to an immutable destination + whole-balance amount.
    function sweep() external {
        payable(address(liquidityPool)).transfer(address(this).balance);
    }

    // SINGLE call site through a branch-reassigned LOCAL (a Phi merge). This is
    // the merged-local guard's own shape (payMix covers the two-site fold
    // instead): the engine keys locals by base name, so the two branch origins
    // collapse to one entry and the surviving kind is an order-of-processing
    // accident — the guard must force indeterminate.
    function payMerged(bool cond, address who, uint256 amt) external {
        address d = address(liquidityPool);
        if (cond) { d = who; }
        (bool ok,) = payable(d).call{value: amt}("");
        require(ok);
    }
}
"""


def test_cast_through_immutable_destination(tmp_path):
    contract = _compile_named(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["withdrawEther()"])
    assert flow["target_kind"] == {"kind": "immutable", "tier": "static_trace"}
    assert flow["amount_kind"] == {"kind": "capped_by_balance", "tier": "static_trace"}


def test_caller_param_destination_is_extraction(tmp_path):
    contract = _compile_named(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payTo(address,uint256)"])
    assert flow["target_kind"]["kind"] == "param"
    assert flow["amount_kind"] == {"kind": "param", "tier": "dispositive_ast"}


def test_storage_setter_vs_no_setter(tmp_path):
    contract = _compile_named(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    setter = _out_flow(effects["functions"]["payTreasury()"])
    assert setter["target_kind"]["kind"] == "storage_setter"
    assert setter["amount_kind"] == {"kind": "bounded_by_storage", "tier": "dispositive_ast"}
    no_setter = _out_flow(effects["functions"]["payCollector()"])
    assert no_setter["target_kind"]["kind"] == "storage_no_setter"
    assert no_setter["amount_kind"] == {"kind": "fixed_constant", "tier": "dispositive_ast"}


def test_constant_destination_and_msg_value(tmp_path):
    contract = _compile_named(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["toBurn()"])
    assert flow["target_kind"]["kind"] == "constant"
    assert flow["amount_kind"] == {"kind": "msg_value", "tier": "dispositive_ast"}


def test_native_transfer_immutable_whole_balance(tmp_path):
    contract = _compile_named(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["sweep()"], kind="native_transfer_send")
    assert flow["target_kind"]["kind"] == "immutable"
    assert flow["amount_kind"] == {"kind": "whole_balance", "tier": "static_trace"}


def test_lattice_reaches_the_claim_witness(tmp_path):
    contract = _compile_named(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    claims = build_claims(contract, effects, {})["functions"]

    def flow_out_witness(sig):
        rows = [c for c in claims[sig] if c["claim_id"] == "flow.out"]
        assert rows, f"no flow.out claim on {sig}"
        return rows[0]["witness"]["flows"]

    theft = flow_out_witness("payTo(address,uint256)")
    assert any(e.get("target_kind", {}).get("kind") == "param" for e in theft)

    routing = flow_out_witness("withdrawEther()")
    assert any(e.get("target_kind") == {"kind": "immutable", "tier": "static_trace"} for e in routing)


# ``storage_no_setter`` is a proven negative only when write attribution is exhaustive; raw-slot ``sstore`` and
# ``delegatecall`` aren't visible to the scan.

_RAW_SLOT_SRC = """
pragma solidity ^0.8.20;
contract RawSlot {
    address public collector;                       // no Solidity setter
    function setRaw(address t) external { assembly { sstore(0, t) } }  // unattributed
    function pay() external { (bool ok,) = payable(collector).call{value: 1}(""); require(ok); }
}
"""

_DELEGATECALL_SRC = """
pragma solidity ^0.8.20;
contract Dele {
    address public collector;                       // no setter
    function forward(address a, bytes calldata d) external { (bool ok,) = a.delegatecall(d); require(ok); }
    function pay() external { (bool ok,) = payable(collector).call{value: 1}(""); require(ok); }
}
"""


def test_raw_slot_sstore_defeats_no_setter_proof(tmp_path):
    contract = _compile_named(tmp_path, _RAW_SLOT_SRC, "RawSlot")
    effects = build_effects(contract)
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "indeterminate"


def test_delegatecall_defeats_no_setter_proof(tmp_path):
    contract = _compile_named(tmp_path, _DELEGATECALL_SRC, "Dele")
    effects = build_effects(contract)
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "indeterminate"


# Writes through a callee's ``storage`` reference aren't attributed by Slither, so resolve the alias.

_STORAGE_LIB = """
struct Box { address owner; }
library L {
    function put(Box storage s, address v) internal { s.owner = v; }
    function peek(Box storage s) internal view returns (address) { return s.owner; }
    function _inner(Box storage s, address v) internal { s.owner = v; }
    function putNested(Box storage s, address v) internal { _inner(s, v); }
}
"""

_LIB_WRITE_SRC = (
    """
pragma solidity ^0.8.20;
"""
    + _STORAGE_LIB
    + """
contract LibWrite {
    Box box;
    function setV(address v) external { L.put(box, v); }
    function pay() external { (bool ok,) = payable(box.owner).call{value: 1}(""); require(ok); }
}
"""
)

_LIB_READ_SRC = (
    """
pragma solidity ^0.8.20;
"""
    + _STORAGE_LIB
    + """
contract LibRead {
    Box box;
    function pk() external view returns (address) { return L.peek(box); }
    function pay() external { (bool ok,) = payable(box.owner).call{value: 1}(""); require(ok); }
}
"""
)

_LIB_NESTED_SRC = (
    """
pragma solidity ^0.8.20;
"""
    + _STORAGE_LIB
    + """
contract LibNested {
    Box box;
    function setV(address v) external { L.putNested(box, v); }
    function pay() external { (bool ok,) = payable(box.owner).call{value: 1}(""); require(ok); }
}
"""
)

_LIB_LOCAL_SRC = (
    """
pragma solidity ^0.8.20;
"""
    + _STORAGE_LIB
    + """
contract LibLocal {
    Box box;
    function setV(address v) external { Box storage b = box; L.put(b, v); }
    function pay() external { (bool ok,) = payable(box.owner).call{value: 1}(""); require(ok); }
}
"""
)

_LIB_UNRESOLVABLE_SRC = (
    """
pragma solidity ^0.8.20;
"""
    + _STORAGE_LIB
    + """
contract LibReturn {
    mapping(uint => Box) boxes;
    address fixedDest;               // clean no-setter var, but scan is now incomplete
    // storage pointer sourced from an internal call return -> origin unresolvable
    function _sel(uint k) internal view returns (Box storage) { return boxes[k]; }
    function setV(uint k, address v) external { Box storage b = _sel(k); L.put(b, v); }
    function pay() external { (bool ok,) = payable(fixedDest).call{value: 1}(""); require(ok); }
}
"""
)


@pytest.mark.parametrize(
    ("src", "name", "expected_kind"),
    [
        pytest.param(_LIB_WRITE_SRC, "LibWrite", "storage_setter", id="library_write"),
        pytest.param(_LIB_READ_SRC, "LibRead", "storage_no_setter", id="library_read_only"),
        pytest.param(_LIB_NESTED_SRC, "LibNested", "storage_setter", id="library_transitive_write"),
        pytest.param(_LIB_LOCAL_SRC, "LibLocal", "storage_setter", id="library_local_pointer_write"),
        # Some unknown var was written through the alias, so no no-setter proof is sound.
        pytest.param(_LIB_UNRESOLVABLE_SRC, "LibReturn", "indeterminate", id="library_unresolvable_alias"),
    ],
)
def test_library_storage_alias_target_kind(tmp_path, src, name, expected_kind):
    contract = _compile_named(tmp_path, src, name)
    effects = build_effects(contract)
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == expected_kind


# tx.origin is ``caller_controlled`` and not folded into msg_sender.


# The merged-local guard must reach the base through Member/Index ops.

_STRUCT_MERGE_SRC = """
pragma solidity ^0.8.20;
contract StructMerge {
    struct Box { address owner; }
    Box boxA;                       // has a setter
    Box boxB;                       // no setter
    function setA(address v) external { boxA.owner = v; }
    // s is a storage pointer merged across branches; the destination is a FIELD
    // of it. The engine collapses s to one branch (boxA -> storage_setter) — a
    // guessed member of the {boxA, boxB} union that the guard must reject.
    function payMerged(bool c, uint256 amt) external {
        Box storage s = c ? boxA : boxB;
        (bool ok,) = payable(s.owner).call{value: amt}(""); require(ok);
    }
}
"""


def test_struct_field_of_merged_local_is_indeterminate(tmp_path):
    contract = _compile_named(tmp_path, _STRUCT_MERGE_SRC, "StructMerge")
    effects = build_effects(contract)
    assert _out_flow(effects["functions"]["payMerged(bool,uint256)"])["target_kind"]["kind"] == "indeterminate"


# The fold hides resolved sites on a mix, so ``target_kinds`` / ``amount_kinds`` publish them.

_SITES_SRC = """
pragma solidity ^0.8.20;

contract Sites {
    address public immutable sink;
    address public treasury;

    constructor(address s) { sink = s; }

    function setTreasury(address t) external { treasury = t; }

    // Two sends sharing one flow key, each with its OWN resolved destination:
    // a fixed address and a caller-supplied one. The fold must not collapse to
    // either member; the breakdown must name both.
    function twoResolved(address dest, uint256 a) external payable {
        (bool ok1,) = payable(sink).call{value: a}("");
        (bool ok2,) = payable(dest).call{value: msg.value}("");
        require(ok1 && ok2);
    }

    // A withdrawal queue's real shape: the user is paid, and then, in the SAME
    // invocation, the remainder is swept to a fixed pool. Both sites execute —
    // neither is an alternative to the other — which is what the fold's name
    // must not contradict.
    function payThenSweep(address to, uint256 a) external {
        (bool ok1,) = payable(to).call{value: a}("");
        require(ok1);
        if (address(this).balance > 0) {
            (bool ok2,) = payable(sink).call{value: address(this).balance}("");
            require(ok2);
        }
    }

    // One resolved site + one genuinely-unknown site (a cross-branch merged
    // local). The unknown site must appear AS unknown, never be dropped to make
    // the list read resolved.
    function oneIndeterminate(bool flag, address dest, uint256 a) external {
        address m = flag ? dest : treasury;
        (bool ok1,) = payable(sink).call{value: a}("");
        (bool ok2,) = payable(m).call{value: a}("");
        require(ok1 && ok2);
    }

    // A single site: the fold already IS the whole answer.
    function single(uint256 a) external {
        (bool ok,) = payable(sink).call{value: a}("");
        require(ok);
    }

    // Two sites that agree: the breakdown would be a redundant copy of the fold.
    function twoAgreeing(uint256 a, uint256 b) external {
        (bool ok1,) = payable(sink).call{value: a}("");
        (bool ok2,) = payable(sink).call{value: b}("");
        require(ok1 && ok2);
    }

    // Many sites drawing from a small set of kinds: dedup by meaning bounds the
    // list by the LATTICE, never by the site count.
    function manySites(address dest, uint256 a) external {
        (bool o1,) = payable(sink).call{value: a}("");
        (bool o2,) = payable(dest).call{value: a}("");
        (bool o3,) = payable(sink).call{value: a}("");
        (bool o4,) = payable(dest).call{value: a}("");
        (bool o5,) = payable(msg.sender).call{value: a}("");
        (bool o6,) = payable(sink).call{value: a}("");
        (bool o7,) = payable(dest).call{value: a}("");
        require(o1 && o2 && o3 && o4 && o5 && o6 && o7);
    }
}
"""


def test_indeterminate_site_stays_visible_in_the_breakdown(tmp_path):
    contract = _compile_named(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["oneIndeterminate(bool,address,uint256)"])
    assert flow["target_kind"] == {"kind": "indeterminate", "tier": "static_trace"}
    kinds = [e["kind"] for e in flow["target_kinds"]]
    assert "immutable" in kinds
    assert "indeterminate" in kinds


def test_breakdown_is_bounded_by_the_lattice_not_the_site_count(tmp_path):
    contract = _compile_named(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["manySites(address,uint256)"])
    assert flow["target_kind"]["kind"] == "several"
    entries = flow["target_kinds"]
    assert {e["kind"] for e in entries} == {"immutable", "param", "msg_sender"}
    assert len(entries) == len({(e["kind"], e["tier"]) for e in entries})
    assert flow["amount_kind"]["kind"] == "param"
    assert "amount_kinds" not in flow


def test_breakdown_reaches_the_claim_witness(tmp_path):
    contract = _compile_named(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    claims = build_claims(contract, effects, {})["functions"]
    rows = [c for c in claims["twoResolved(address,uint256)"] if c["claim_id"] == "flow.out"]
    assert rows, "no flow.out claim"
    entry = rows[0]["witness"]["flows"][0]
    assert entry["target_kind"]["kind"] == "several"
    assert {e["kind"] for e in entry["target_kinds"]} == {"immutable", "param"}
    assert {e["kind"] for e in entry["amount_kinds"]} == {"param", "msg_value"}

    single = [c for c in claims["single(uint256)"] if c["claim_id"] == "flow.out"][0]
    assert "target_kinds" not in single["witness"]["flows"][0]
