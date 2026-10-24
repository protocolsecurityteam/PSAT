"""Every construct Slither can hand the lowering is classified: lowered with defined semantics, or rejected by name.

The enumeration is Slither's own, computed here, so a new Slither (a new operation class, builtin or special
variable) or a new Yul builtin fails this test until ``lower.py`` says what it does with it. A rejected construct,
exercised, never comes back as a formula: its label is the gap the verdict reports (not complete), checked on a
verdict where Solidity 0.8.27 can express it, and on the term the lowering builds where it can't (Vyper's builtins,
SSA-only operations, special variables no longer in the language)."""

from __future__ import annotations

import inspect

import pytest

import services.logic.lower as lower
from services.logic.decide import Chain
from services.logic.lower import Lowerer, State
from services.logic.terms import TRUE, contains, subterms
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401


def _labels(term) -> set:
    return {t[1] for kind in ("unknown", "opaque") for t in subterms(term, kind)} if isinstance(term, tuple) else set()


def test_every_operation_class_is_handled_or_rejected():
    import slither.slithir.operations as operations

    names = {name for name, _ in inspect.getmembers(operations, inspect.isclass)} | {"CodeSize"}
    classified = lower.HANDLED_OPERATIONS | set(lower.REJECTED_OPERATIONS) | lower.ABSTRACT_OPERATIONS
    assert names == classified, f"unclassified: {sorted(names - classified)}, stale: {sorted(classified - names)}"
    assert not lower.HANDLED_OPERATIONS & set(lower.REJECTED_OPERATIONS)


def test_every_binary_and_unary_operator_is_handled():
    from slither.slithir.operations import BinaryType, UnaryType

    handled = set(lower._BINARY) | set(lower._COMPARE) | {BinaryType.ANDAND, BinaryType.OROR}
    assert set(BinaryType) == handled
    assert set(UnaryType) == {UnaryType.BANG, UnaryType.TILD}


def test_every_builtin_is_handled_or_rejected():
    from slither.core.declarations.solidity_variables import SOLIDITY_FUNCTIONS

    names = set(SOLIDITY_FUNCTIONS)
    classified = lower.HANDLED_BUILTINS | set(lower.REJECTED_BUILTINS)
    assert names <= classified, f"unclassified: {sorted(names - classified)}"
    assert not lower.HANDLED_BUILTINS & set(lower.REJECTED_BUILTINS)


def test_every_special_variable_is_handled_or_rejected():
    from slither.core.declarations.solidity_variables import SOLIDITY_VARIABLES, SOLIDITY_VARIABLES_COMPOSED

    names = set(SOLIDITY_VARIABLES) | set(SOLIDITY_VARIABLES_COMPOSED)
    classified = lower.HANDLED_VARIABLES | set(lower.REJECTED_VARIABLES)
    assert names <= classified, f"unclassified: {sorted(names - classified)}"
    assert not lower.HANDLED_VARIABLES & set(lower.REJECTED_VARIABLES)


def test_every_yul_builtin_is_classified_for_the_legacy_reader():
    from slither.solc_parsing.yul.evm_functions import builtins

    sets = (lower.LEGACY_YUL_HANDLED, set(lower.LEGACY_YUL_OPAQUE), lower.LEGACY_YUL_UNSUPPORTED)
    names = set(builtins)
    assert names <= set().union(*sets), f"unclassified: {sorted(names - set().union(*sets))}"
    assert all(not (a & b) for i, a in enumerate(sets) for b in sets[i + 1 :])


def test_the_legacy_reader_does_with_each_yul_builtin_what_it_is_classified_as(contract):
    from slither.solc_parsing.yul.evm_functions import builtins

    from services.logic.yul import Unsupported, parse

    lowerer = Lowerer(contract)
    for name in sorted(builtins):
        arity = lower.LEGACY_YUL_ARITY.get(name, 2)
        text = f"let x := {name}({', '.join(['1'] * arity)})"
        statements = (
            parse(f"{name}({', '.join(['1'] * arity)})") if name in lower.LEGACY_YUL_STATEMENTS else parse(text)
        )
        if name in lower.LEGACY_YUL_UNSUPPORTED:
            with pytest.raises(Unsupported):
                lowerer._yul(statements, {}, {}, State(TRUE))
            continue
        lowerer._yul(statements, {}, {}, State(TRUE))  # handled or opaque: read, never refused


SOURCE = """
pragma solidity 0.8.27;

interface I {
    struct Info { string name; address who; }
    function info() external view returns (Info memory);
}

contract C {
    address owner;
    bytes20 stored;

    function _isOwner(address a) internal view returns (bool) { return a == owner; }

    function viaGasleft() external view { require(msg.sender == address(uint160(gasleft()))); }
    function viaBlockhash() external view {
        require(msg.sender == address(uint160(uint256(blockhash(block.number - 1)))));
    }
    function viaBlobhash() external view { require(msg.sender == address(uint160(uint256(blobhash(0))))); }
    function viaBlobbasefee() external view { require(uint160(msg.sender) == block.blobbasefee); }
    function viaGasprice() external view { require(uint160(msg.sender) == tx.gasprice); }
    function viaRipemd() external view { require(ripemd160(abi.encodePacked(msg.sender)) == stored); }
    function viaYulGas() external view { uint256 g; assembly { g := gas() } require(uint160(msg.sender) == g); }
    function viaYulMsize() external view { uint256 g; assembly { g := msize() } require(uint160(msg.sender) == g); }
    function viaYulGasprice() external view {
        uint256 g;
        assembly { g := gasprice() }
        require(uint160(msg.sender) == g);
    }
    function viaYulBlobbasefee() external view {
        uint256 g;
        assembly { g := blobbasefee() }
        require(uint160(msg.sender) == g);
    }
    function viaPointer() external view {
        function(address) internal view returns (bool) f = _isOwner;
        require(f(msg.sender));
    }
    function viaSend() external { require(payable(msg.sender).send(0)); }
    function viaSlice(bytes calldata d) external view { require(address(bytes20(d[4:])) == msg.sender); }
    function viaMember(address t) external view { require(I(t).info().who == msg.sender); }
}
"""

# Function -> the label its rejected construct reports.
VERDICTS = {
    "viaGasleft": "gasleft()",
    "viaBlockhash": "unsupported:blockhash(uint256)",
    "viaBlobhash": "unsupported:blobhash(uint256)",
    "viaBlobbasefee": "unsupported:block.blobbasefee",
    "viaGasprice": "unsupported:tx.gasprice",
    "viaRipemd": "unsupported:ripemd160(bytes)",
    "viaYulGas": "unsupported:gas()",
    "viaYulMsize": "unsupported:msize(uint256)",
    "viaYulGasprice": "unsupported:gasprice()",
    "viaYulBlobbasefee": "unsupported:blobbasefee()",
    "viaPointer": "unsupported:InternalDynamicCall",
    "viaSend": "Send",
    "viaSlice": "unsupported:slice",
    "viaMember": "unsupported:member:who",
}

AT = 0xA1 << 140


class _Zero(Chain):
    """Every slot zero, every call reverting."""

    def __init__(self):
        super().__init__(self._answer, 100, lambda calls: [self._safe(m, p) for m, p in calls])

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        if method == "eth_getLogs":
            return []
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == AT else b""

    def logs(self, address, topics):
        return []


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("coverage") / "C.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "C")


@pytest.mark.parametrize(("name", "label"), sorted(VERDICTS.items()))
def test_a_rejected_construct_reaches_the_verdict_by_name(contract, name, label):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    formula = Lowerer(contract).success(fn)
    assert label in _labels(formula), (name, formula)
    reset_terms()
    verdict, _ = function_verdict(contract, fn, AT, _Zero(), {AT: contract})
    assert not verdict.complete, (name, verdict)
    assert any(label in gap for gap in verdict.gaps), (name, verdict.gaps)


def _node(contract):
    return next(n for f in contract.functions for n in f.nodes if n.irs)


def test_each_rejected_builtin_lowers_to_its_label(contract):
    from slither.core.declarations import SolidityFunction
    from slither.slithir.operations import SolidityCall
    from slither.slithir.variables import Constant, TemporaryVariable

    node = _node(contract)
    for name, label in sorted(lower.REJECTED_BUILTINS.items()):
        result = TemporaryVariable(node, index=10_000)
        ir = SolidityCall(SolidityFunction(name), 1, result, "uint256")
        ir.set_node(node)
        ir.arguments = [Constant("1")]
        lowerer = Lowerer(contract)
        lowerer._node = node
        after = lowerer._solidity_call(ir, State(TRUE))
        produced = _labels(after.env.get(id(result))) | _labels(after.pc)
        assert label in produced, (name, after.env.get(id(result)), after.pc)


def test_an_unknown_builtin_is_rejected_by_its_name(contract):
    from slither.core.declarations import SolidityFunction
    from slither.slithir.operations import SolidityCall
    from slither.slithir.variables import TemporaryVariable

    node = _node(contract)
    name = "datasize(uint256)"  # Yul object builtins Slither renders without listing them
    SolidityFunction.__init__  # noqa: B018 - a name outside SOLIDITY_FUNCTIONS can't be built the normal way
    fn = SolidityFunction.__new__(SolidityFunction)
    fn._name = name
    fn._return_type = []
    result = TemporaryVariable(node, index=10_001)
    ir = SolidityCall(fn, 0, result, "uint256")
    lowerer = Lowerer(contract)
    lowerer._node = node
    after = lowerer._solidity_call(ir, State(TRUE))
    assert f"unsupported:{name}" in _labels(after.pc) and lowerer.lost


def test_each_rejected_variable_lowers_to_its_label(contract):
    from slither.core.declarations import SolidityVariable, SolidityVariableComposed

    lowerer = Lowerer(contract)
    for name, label in sorted(lower.REJECTED_VARIABLES.items()):
        var = SolidityVariableComposed(name) if "." in name else SolidityVariable(name)
        assert label in _labels(lowerer.val(var, State(TRUE))), name


def test_each_rejected_operation_lowers_to_its_label(contract):
    from slither.slithir.operations import Phi, PhiCallback
    from slither.slithir.variables import LocalIRVariable

    local = next(v for f in contract.functions for v in f.variables if v.name)
    for cls in (Phi, PhiCallback):
        ir = cls.__new__(cls)
        ir._lvalue = LocalIRVariable(local)
        lowerer = Lowerer(contract)
        lowerer._node = _node(contract)
        after = lowerer._exec_ir(ir, State(TRUE), 0)
        assert lower.REJECTED_OPERATIONS[cls.__name__] in _labels(after.pc), cls.__name__
        assert lowerer.lost


ENVIRONMENT = """
pragma solidity 0.8.27;

contract E {
    function yulAddress(uint256 want) external view { uint256 v; assembly { v := address() } require(v == want); }
    function yulSelfbalance(uint256 want) external view {
        uint256 v;
        assembly { v := selfbalance() }
        require(v == want);
    }
    function thisBalance(uint256 want) external view { require(address(this).balance == want); }
    function yulCodesize(uint256 want) external view { uint256 v; assembly { v := codesize() } require(v == want); }
    function yulCaller(uint256 want) external view { uint256 v; assembly { v := caller() } require(v == want); }
    function yulOrigin(uint256 want) external view { uint256 v; assembly { v := origin() } require(v == want); }
    function yulCallvalue(uint256 want) external view { uint256 v; assembly { v := callvalue() } require(v == want); }
    function yulChainid(uint256 want) external view { uint256 v; assembly { v := chainid() } require(v == want); }
    function yulTimestamp(uint256 want) external view { uint256 v; assembly { v := timestamp() } require(v >= want); }
    function yulNumber(uint256 want) external view { uint256 v; assembly { v := number() } require(v >= want); }
}
"""


@pytest.fixture(scope="module")
def environment(anvil):  # noqa: F811
    d = O.deployment(*anvil, ENVIRONMENT)
    d.deploy("E")
    O.rpc(d.url, "anvil_setBalance", [O.hex20(d.at["E"]), hex(7)])
    return d


def test_handled_environment_builtins_are_their_values(environment):
    d = environment
    block = O.rpc(d.url, "eth_getBlockByNumber", ["latest", False])
    code = O.rpc(d.url, "eth_getCode", [O.hex20(d.at["E"]), "latest"])
    actual = {
        "yulAddress": d.at["E"], "yulSelfbalance": 7, "thisBalance": 7, "yulCodesize": len(code) // 2 - 1,
        "yulCaller": O.OWNER, "yulOrigin": O.OWNER, "yulCallvalue": 0,
        "yulChainid": int(O.rpc(d.url, "eth_chainId", []), 16),
        "yulTimestamp": int(block["timestamp"], 16), "yulNumber": int(block["number"], 16),
    }  # fmt: skip
    for name, value in actual.items():
        fn = O.function(d, "E", name)
        for want in (value, value + 1, max(value - 1, 0)):
            chain = O.chain_says(d, fn, [want], "E")
            formula, engine = O.engine_says(d, fn, [want], "E")
            assert engine == chain, (name, want, chain, engine, formula)
            assert not contains(formula, frozenset({"unknown"})), name
        assert O.chain_says(d, fn, [value], "E"), name
