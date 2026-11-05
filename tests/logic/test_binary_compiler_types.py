"""Operation widths come from compiler common types, not destination or one operand."""

import pytest

from services.logic.formula import compile_function
from services.logic.lower import parameter
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

CASES = [
    ("uint8 x", "1000+x", (255,)),
    ("uint8 x", "x+1000", (255,)),
    ("uint8 x,uint16 y", "x+y", (200, 1000)),
    ("uint8 x,uint16 y", "x+y", (255, 65535)),
    ("int8 x,int16 y", "x+y", (-120, -1000)),
    ("int8 x,int16 y", "x+y", (120, 32700)),
    ("uint8 x,uint16 y", "x<<y", (255, 4)),
    ("uint8 x,uint16 y", "x<<y", (1, 8)),
    ("int8 x,int16 y", "x<y ? int16(7):int16(9)", (0, 1000)),
    ("uint8 x", "x+1", (255,)),
    ("bytes4 x,bytes8 y", "uint64(x|y)", (b"\x01\x02\x03\x04", bytes(8))),
    ("bytes4 x,bytes8 y", "uint64(x&y)", (b"\xff" * 4, bytes(range(1, 9)))),
    ("bytes4 x,bytes8 y", "x==y ? 1:2", (b"\x01\x02\x03\x04", b"\x01\x02\x03\x04" + bytes(4))),
    ("int256 x,uint256 y", "x>>y", (-(2**255), 255)),
    ("int256 x,uint256 y", "x>>y", (-127, 256)),
    ("int256 x,uint256 y", "x>>y", (-127, 300)),
    ("int256 x,int256 y", "x/y", (-(2**255), -1)),
    ("int8 x,int8 y", "x/y", (-128, -1)),
    ("int8 x,int8 y", "x/y", (-128, 1)),
]


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14", "0.8.10", "0.8.27"])
@pytest.mark.parametrize("parameters,expression,args", CASES)
def test_operation_common_type_matches_mined_result(anvil, tmp_path, version, parameters, expression, args):
    signed = parameters.startswith("int")
    target = "int256" if signed else "uint256"
    source = (
        f"pragma solidity {version};contract C {{{target} saved;"
        f"function act({parameters}) external {{saved={expression};}}}}"
    )
    d = O.deployment(anvil[0], tmp_path, source, version=version)
    at = d.deploy("C")
    fn = O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, at, d.chain(), d.contracts("C"))
    bindings = {
        CALLER: O.OWNER,
        mk("callvalue"): 0,
        **{parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, args))},
    }
    tr = Translation(d.chain(), d.contracts("C"), at, f.selector, bindings=bindings)
    predicted = tr.truth(f.success)
    values = [int(str(tr.translate(e.value))) % (2**256) for e in f.effects if tr.truth(e.guard) is True]
    actual = O.transact_data(d, at, O.calldata(fn, args))
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    assert predicted is actual, (version, expression, tr.issues)
    assert stored == (values[-1] if values else 0), (version, expression, stored, values)
    assert not tr.issues


@pytest.mark.parametrize("left", ["int8", "int256", "uint8", "uint256"])
@pytest.mark.parametrize("right", ["int8", "int256"])
@pytest.mark.parametrize("operator", ["<<", ">>"])
@pytest.mark.parametrize("count", [-1, 0, 1])
def test_legacy_signed_shift_count_must_be_nonnegative(anvil, tmp_path, left, right, operator, count):
    value = -127 if left.startswith("int") else 127
    test_operation_common_type_matches_mined_result(
        anvil, tmp_path, "0.4.19", f"{left} x,{right} y", f"x{operator}y", (value, count)
    )
