"""Regression tests for the ``flow.out`` destination/amount lattice (SDG §3).

Each test compiles a real Solidity fixture with Slither and drives the
production ``build_effects`` (and, for the passthrough test, ``build_claims``)
sequence — no fakes, only the solc compile is real. Precedent:
``tests/test_effects_facts.py``.

These fixtures are the guard for the two −12 theft-vs-routing false positives:
an immutable/fixed destination (operational routing) must classify distinctly
from a caller-chosen one (extraction), and any ambiguity must degrade to
``indeterminate`` rather than silently guessing a member of the union.
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

from services.static.claims import build_claims  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402


def _compile(tmp_path: Path, source: str, name: str):
    f = tmp_path / f"{name}.sol"
    f.write_text(textwrap.dedent(source).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == name)


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
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["withdrawEther()"])
    assert flow["target_kind"] == {"kind": "immutable", "tier": "static_trace"}
    # Math.min(address(this).balance, view_call) is provably <= the contract's own
    # balance — the minimum of the self-balance and some other value.
    assert flow["amount_kind"] == {"kind": "capped_by_balance", "tier": "static_trace"}


def test_caller_param_destination_is_extraction(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payTo(address,uint256)"])
    assert flow["target_kind"]["kind"] == "param"
    assert flow["amount_kind"] == {"kind": "param", "tier": "dispositive_ast"}


def test_direct_immutable_is_dispositive(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["feeToSink(address,uint256)"])
    assert flow["target_kind"] == {"kind": "immutable", "tier": "dispositive_ast"}
    assert flow["amount_kind"] == {"kind": "param", "tier": "dispositive_ast"}


def test_msg_sender_destination(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["claim(address,uint256)"])
    assert flow["target_kind"] == {"kind": "msg_sender", "tier": "dispositive_ast"}


def test_storage_setter_vs_no_setter(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    setter = _out_flow(effects["functions"]["payTreasury()"])
    assert setter["target_kind"]["kind"] == "storage_setter"
    assert setter["amount_kind"] == {"kind": "bounded_by_storage", "tier": "dispositive_ast"}
    no_setter = _out_flow(effects["functions"]["payCollector()"])
    assert no_setter["target_kind"]["kind"] == "storage_no_setter"
    assert no_setter["amount_kind"] == {"kind": "fixed_constant", "tier": "dispositive_ast"}


def test_constant_destination_and_msg_value(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["toBurn()"])
    assert flow["target_kind"]["kind"] == "constant"
    assert flow["amount_kind"] == {"kind": "msg_value", "tier": "dispositive_ast"}


def test_cross_branch_mix_names_both_destinations(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payMix(bool,address,uint256)"])
    # param on one branch, immutable on the other. The scalar must never collapse
    # to a MEMBER of the union — but both members are themselves resolved, so it
    # is a known disjunction rather than an absence of knowledge, and saying
    # "indeterminate" claimed we had traced nothing on a flow we had traced fully.
    assert flow["target_kind"]["kind"] == "one_of"
    assert {e["kind"] for e in flow["target_kinds"]} == {"param", "immutable"}
    # Tier stays the weaker of the contributing sites, as for any other fold.
    assert flow["target_kind"]["tier"] == "static_trace"


def test_branch_reassigned_local_is_indeterminate(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payMerged(bool,address,uint256)"])
    # One call site, destination = Phi-merged local (param|immutable). The
    # engine's base-name keying can silently keep either branch; the guard must
    # never let a collapsed single kind through.
    assert flow["target_kind"] == {"kind": "indeterminate", "tier": "static_trace"}


def test_native_transfer_immutable_whole_balance(tmp_path):
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["sweep()"], kind="native_transfer_send")
    assert flow["target_kind"]["kind"] == "immutable"
    assert flow["amount_kind"] == {"kind": "whole_balance", "tier": "static_trace"}


INDIRECTION_SRC = """
pragma solidity ^0.8.20;

interface ILP { function x() external view returns (uint256); }

contract Indirection {
    ILP public immutable liquidityPool;
    constructor(ILP lp) { liquidityPool = lp; }

    // Entry -> internal helper that reads the STATE var directly. A state var is
    // contract-global, so the classification survives the internal-call boundary.
    function withdrawEther() external { _withdrawEther(); }
    function _withdrawEther() internal {
        (bool ok,) = payable(address(liquidityPool)).call{value: address(this).balance}("");
        require(ok);
    }

    // Entry forwards a caller parameter into a helper. The value-flow walk is
    // rooted at the single entry ``payForward``, so the argument forwarded into
    // ``_pay`` is unambiguous: ``dest``/``amt`` are the entry's own caller-chosen
    // params, recovered interprocedurally to ``param`` (a trace across the call).
    function payForward(address dest, uint256 amt) external { _pay(dest, amt); }
    function _pay(address d, uint256 a) internal {
        (bool ok,) = payable(d).call{value: a}("");
        require(ok);
    }
}
"""


def test_state_var_survives_internal_call(tmp_path):
    contract = _compile(tmp_path, INDIRECTION_SRC, "Indirection")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["withdrawEther()"])
    assert flow["target_kind"]["kind"] == "immutable"


def test_forwarded_param_recovers_in_callee(tmp_path):
    contract = _compile(tmp_path, INDIRECTION_SRC, "Indirection")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["payForward(address,uint256)"])
    # The entry's caller-chosen ``dest``/``amt`` forwarded one hop into ``_pay``:
    # recovered to ``param`` (a trace, since it crossed the internal-call boundary).
    assert flow["target_kind"] == {"kind": "param", "tier": "static_trace"}
    assert flow["amount_kind"] == {"kind": "param", "tier": "static_trace"}


def test_lattice_reaches_the_claim_witness(tmp_path):
    """The classified fields survive projection into the ``flow.out`` claim
    witness the scorer/frontend read (matchers/flows.py)."""
    contract = _compile(tmp_path, LATTICE_SRC, "Lattice")
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


# ---------------------------------------------------------------------------
# Setter-scan completeness: ``storage_no_setter`` is a proven negative only when
# Slither's write attribution is exhaustive. A raw/computed-slot ``sstore`` or a
# ``delegatecall`` is a write channel the scan cannot see, so "no attributed
# setter" must NOT be read as "fixed destination" — it degrades to indeterminate
# (never storage_setter, which would assert an unproven positive).
# ---------------------------------------------------------------------------

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

_SLOT_SYMBOL_SRC = """
pragma solidity ^0.8.20;
contract SlotSym {
    address public collector;
    function setAttr(address t) external { assembly { sstore(collector.slot, t) } }  // attributed to collector
    function pay() external { (bool ok,) = payable(collector).call{value: 1}(""); require(ok); }
}
"""

_CLEAN_NO_SETTER_SRC = """
pragma solidity ^0.8.20;
contract Clean {
    address public collector;                       // set once in ctor, never again
    constructor(address c) { collector = c; }
    function pay() external { (bool ok,) = payable(collector).call{value: 1}(""); require(ok); }
}
"""


def test_raw_slot_sstore_defeats_no_setter_proof(tmp_path):
    contract = _compile(tmp_path, _RAW_SLOT_SRC, "RawSlot")
    effects = build_effects(contract)
    # An unattributed sstore to a raw slot could redirect collector; the absence
    # of an attributed setter is no longer dispositive.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "indeterminate"


def test_delegatecall_defeats_no_setter_proof(tmp_path):
    contract = _compile(tmp_path, _DELEGATECALL_SRC, "Dele")
    effects = build_effects(contract)
    # Foreign code via delegatecall can write any slot as this contract.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "indeterminate"


def test_slot_symbol_sstore_counts_as_setter(tmp_path):
    contract = _compile(tmp_path, _SLOT_SYMBOL_SRC, "SlotSym")
    effects = build_effects(contract)
    # ``sstore(collector.slot, …)`` IS attributed to collector -> a real setter.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "storage_setter"


def test_clean_no_setter_stays_proven_negative(tmp_path):
    contract = _compile(tmp_path, _CLEAN_NO_SETTER_SRC, "Clean")
    effects = build_effects(contract)
    # No delegatecall, no assembly sstore, no setter -> the sound case survives.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "storage_no_setter"


# ---------------------------------------------------------------------------
# Storage-pointer aliasing (register #1): a state var written only through a
# callee taking a ``storage`` reference (``using X for`` / library idiom) is not
# attributed by Slither. We resolve the alias back to its origin var (a real
# setter -> storage_setter), and degrade to indeterminate only when the alias
# genuinely cannot be resolved — never a false storage_no_setter.
# ---------------------------------------------------------------------------

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


def test_library_storage_write_is_real_setter(tmp_path):
    contract = _compile(tmp_path, _LIB_WRITE_SRC, "LibWrite")
    effects = build_effects(contract)
    # box.owner is redirectable via L.put -> the alias is resolved to a setter.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "storage_setter"


def test_library_read_only_stays_no_setter(tmp_path):
    contract = _compile(tmp_path, _LIB_READ_SRC, "LibRead")
    effects = build_effects(contract)
    # A storage ref passed only for reading is not a setter; the clean proof holds.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "storage_no_setter"


def test_library_transitive_write_is_real_setter(tmp_path):
    contract = _compile(tmp_path, _LIB_NESTED_SRC, "LibNested")
    effects = build_effects(contract)
    # putNested forwards the storage ref into _inner, which writes it.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "storage_setter"


def test_library_local_pointer_write_is_real_setter(tmp_path):
    contract = _compile(tmp_path, _LIB_LOCAL_SRC, "LibLocal")
    effects = build_effects(contract)
    # ``Box storage b = box;`` traces back to box -> a resolved setter.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "storage_setter"


def test_library_unresolvable_alias_is_indeterminate(tmp_path):
    contract = _compile(tmp_path, _LIB_UNRESOLVABLE_SRC, "LibReturn")
    effects = build_effects(contract)
    # The storage pointer comes from a call return: some unknown var was written
    # through the alias, so no no-setter proof in the contract is sound.
    assert _out_flow(effects["functions"]["pay()"])["target_kind"]["kind"] == "indeterminate"


# ---------------------------------------------------------------------------
# tx.origin destination (register #7): a distinct caller-directed destination
# fact -> ``caller_controlled`` (theft-shaped, deduction-admissible like
# param/msg_sender), NOT folded into msg_sender (the address differs).
# ---------------------------------------------------------------------------

_TX_ORIGIN_SRC = """
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address,uint256) external returns (bool); }
contract Origin {
    // ERC-20 send with a direct tx.origin recipient (dispositive).
    function claim(address tok, uint256 amt) external { IERC20(tok).transfer(tx.origin, amt); }
    // Low-level value call to tx.origin (traced through the payable cast).
    function payOrigin(uint256 amt) external { (bool ok,) = payable(tx.origin).call{value: amt}(""); require(ok); }
}
"""


def test_tx_origin_destination_is_caller_controlled(tmp_path):
    contract = _compile(tmp_path, _TX_ORIGIN_SRC, "Origin")
    effects = build_effects(contract)
    direct = _out_flow(effects["functions"]["claim(address,uint256)"])
    assert direct["target_kind"] == {"kind": "caller_controlled", "tier": "dispositive_ast"}
    traced = _out_flow(effects["functions"]["payOrigin(uint256)"])
    assert traced["target_kind"] == {"kind": "caller_controlled", "tier": "static_trace"}


# ---------------------------------------------------------------------------
# Struct-field destination of a branch-reassigned local (register #8): the
# merged-local guard must reach the base through a Member/Index op, or the
# engine's collapsed (single-branch) value escapes as a guessed concrete kind.
# ---------------------------------------------------------------------------

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
    contract = _compile(tmp_path, _STRUCT_MERGE_SRC, "StructMerge")
    effects = build_effects(contract)
    # Without Member traversal in the def-use walk this escapes as storage_setter
    # (the collapsed boxA branch); the guard now reaches the merged base ``s``.
    assert _out_flow(effects["functions"]["payMerged(bool,uint256)"])["target_kind"]["kind"] == "indeterminate"


# ---------------------------------------------------------------------------
# Engine-bundle memoization (register #9): a helper reached from multiple entry
# points is analyzed once. Behavior-preserving — the bundle is a pure function of
# the helper's IR; only the per-context ``nested`` flag stays on _UnitCtx.
# ---------------------------------------------------------------------------

_SHARED_HELPER_SRC = """
pragma solidity ^0.8.20;
contract Shared {
    address public immutable sink;
    constructor(address s) { sink = s; }
    function _pay(uint256 amt) internal {
        (bool ok,) = payable(sink).call{value: amt}(""); require(ok);
    }
    function entryA(uint256 amt) external { _pay(amt); }
    function entryB(uint256 amt) external { _pay(amt); }
}
"""


def test_shared_helper_engine_built_once(tmp_path, monkeypatch):
    contract = _compile(tmp_path, _SHARED_HELPER_SRC, "Shared")
    import services.static.contract_analysis_pipeline.effects as eff_mod

    real_engine = eff_mod.ProvenanceEngine
    counts: dict[str, int] = {}

    class CountingEngine(real_engine):
        def __init__(self, function, *args, **kwargs):
            name = str(getattr(function, "name", None))
            counts[name] = counts.get(name, 0) + 1
            super().__init__(function, *args, **kwargs)

    monkeypatch.setattr(eff_mod, "ProvenanceEngine", CountingEngine)
    effects = build_effects(contract)

    # _pay moves value and is reached from BOTH entries, yet its engine is built
    # exactly once (cross-entry memoization); without it the count would be 2.
    assert counts.get("_pay") == 1

    a = _out_flow(effects["functions"]["entryA(uint256)"])
    b = _out_flow(effects["functions"]["entryB(uint256)"])
    assert a["target_kind"] == b["target_kind"] == {"kind": "immutable", "tier": "static_trace"}
    assert a["amount_kind"] == b["amount_kind"]


# ---------------------------------------------------------------------------
# Per-site breakdown: the fold collapses every contributing IR site to one
# scalar and returns ``indeterminate`` on any MIX — right for a single answer,
# but it hides destinations we actually resolved. ``target_kinds`` /
# ``amount_kinds`` publish the contributing sites beside the unchanged fold.
# ---------------------------------------------------------------------------

_SITES_SRC = """
pragma solidity ^0.8.20;

contract Sites {
    address public immutable sink;
    address public treasury;

    constructor(address s) { sink = s; }

    function setTreasury(address t) external { treasury = t; }

    // Two sends sharing one flow key, each with its OWN resolved destination:
    // a fixed address and a caller-supplied one. The fold must stay
    // indeterminate; the breakdown must name both.
    function twoResolved(address dest, uint256 a) external payable {
        (bool ok1,) = payable(sink).call{value: a}("");
        (bool ok2,) = payable(dest).call{value: msg.value}("");
        require(ok1 && ok2);
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


def test_two_resolved_sites_publish_both_destinations(tmp_path):
    contract = _compile(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["twoResolved(address,uint256)"])
    # Two sites, each resolved: the scalar names the disjunction and the members
    # ARE the alternatives (a consumer reads them and takes the worst).
    assert flow["target_kind"]["kind"] == "one_of"
    assert {e["kind"] for e in flow["target_kinds"]} == {"immutable", "param"}
    assert all(e["tier"] in ("dispositive_ast", "static_trace") for e in flow["target_kinds"])
    # The amount lattice gets the same treatment, independently.
    assert flow["amount_kind"]["kind"] == "one_of"
    assert {e["kind"] for e in flow["amount_kinds"]} == {"param", "msg_value"}


def test_indeterminate_site_stays_visible_in_the_breakdown(tmp_path):
    contract = _compile(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["oneIndeterminate(bool,address,uint256)"])
    assert flow["target_kind"] == {"kind": "indeterminate", "tier": "static_trace"}
    kinds = [e["kind"] for e in flow["target_kinds"]]
    # The resolved site is named AND the unknown one is still reported unknown.
    assert "immutable" in kinds
    assert "indeterminate" in kinds


def test_single_site_carries_no_breakdown(tmp_path):
    contract = _compile(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["single(uint256)"])
    assert flow["target_kind"]["kind"] == "immutable"
    assert "target_kinds" not in flow
    assert "amount_kinds" not in flow


def test_agreeing_sites_carry_no_breakdown(tmp_path):
    contract = _compile(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["twoAgreeing(uint256,uint256)"])
    assert flow["target_kind"]["kind"] == "immutable"
    # Two sites, one meaning: the breakdown would repeat the fold verbatim.
    assert "target_kinds" not in flow


def test_sites_agreeing_on_a_kind_carry_no_breakdown_even_at_mixed_tiers():
    from services.static.contract_analysis_pipeline.effects import _fold_sites, _site_breakdown

    sites = [("msg_sender", "dispositive_ast"), ("msg_sender", "static_trace")]
    # The fold keeps the kind and takes the weaker tier, so it already says
    # everything the sites do. A breakdown here would read "msg.sender,
    # msg.sender" on a flow whose destination was never in doubt.
    assert _fold_sites(sites) == {"kind": "msg_sender", "tier": "static_trace"}
    assert _site_breakdown(sites) is None


def test_breakdown_is_bounded_by_the_lattice_not_the_site_count(tmp_path):
    contract = _compile(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    flow = _out_flow(effects["functions"]["manySites(address,uint256)"])
    assert flow["target_kind"]["kind"] == "one_of"
    entries = flow["target_kinds"]
    # Seven sends, three meanings — deduplication by (kind, tier) is the cap.
    assert {e["kind"] for e in entries} == {"immutable", "param", "msg_sender"}
    assert len(entries) == len({(e["kind"], e["tier"]) for e in entries})
    # One amount origin across all seven sites still publishes nothing.
    assert flow["amount_kind"]["kind"] == "param"
    assert "amount_kinds" not in flow


def test_breakdown_reaches_the_claim_witness(tmp_path):
    contract = _compile(tmp_path, _SITES_SRC, "Sites")
    effects = build_effects(contract)
    claims = build_claims(contract, effects, {})["functions"]
    rows = [c for c in claims["twoResolved(address,uint256)"] if c["claim_id"] == "flow.out"]
    assert rows, "no flow.out claim"
    entry = rows[0]["witness"]["flows"][0]
    assert entry["target_kind"]["kind"] == "one_of"
    assert {e["kind"] for e in entry["target_kinds"]} == {"immutable", "param"}
    assert {e["kind"] for e in entry["amount_kinds"]} == {"param", "msg_value"}

    single = [c for c in claims["single(uint256)"] if c["claim_id"] == "flow.out"][0]
    assert "target_kinds" not in single["witness"]["flows"][0]
