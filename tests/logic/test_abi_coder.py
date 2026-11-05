"""Each side of a call decodes by its own ABI coder; local encodings and caller-chosen decodes exclude no caller."""

import time

import pytest

from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

DIRTY = {
    "bool": """
interface I {function allowed() external view returns(bool);}
contract M {function allowed() public pure returns(uint256){return 2;}}
contract C {I m; uint public value; constructor(address a){m=I(a);}
    function act() external {require(m.allowed()); value=1;}}
""",
    "address": """
interface I {function owner() external view returns(address);}
contract M {address o; constructor(){o=msg.sender;}
    function owner() public view returns(uint256){return uint256(uint160(o)) | (1<<200);}}
contract C {I m; uint public value; constructor(address a){m=I(a);}
    function act() external {require(m.owner()==msg.sender); value=1;}}
""",
}


def _callers(d, name, fn_name="act"):
    contracts = d.contracts(*d.at)
    fn = O.function(d, name, fn_name)
    formula = compile_function(d.slither[name], fn, d.at[name], d.chain(), contracts)
    return fn, expand_formula(formula, d.chain(), contracts).callers


def _admitted(d, fn):
    return {s for s in O.ACCOUNTS if O.chain_says(d, fn, [], sender=s)}


@pytest.mark.parametrize("returned", list(DIRTY))
@pytest.mark.parametrize("version", ["0.7.0", "0.8.10"])
def test_dirty_return_word_is_cleaned_by_coder_v1_and_rejected_by_v2(anvil, tmp_path, returned, version):
    d = O.deployment(anvil[0], tmp_path, f"pragma solidity ^{version};\n" + DIRTY[returned], version)
    d.deploy("C", ("address",), (d.deploy("M"),))
    fn, callers = _callers(d, "C")
    assert callers.complete
    admitted = set(O.ACCOUNTS) - set(callers.excluded) if callers.representation == "cofinite" else set(callers.members)
    assert admitted & set(O.ACCOUNTS) == _admitted(d, fn)
    assert bool(_admitted(d, fn)) == (version == "0.7.0")


def test_decoding_caller_chosen_bytes_excludes_no_caller(anvil, tmp_path):
    d = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity ^0.8.10;
contract C {address owner; uint public value; constructor(){owner=msg.sender;}
    function act(bytes calldata data) external {require(msg.sender==owner); value=abi.decode(data,(uint));}}
""",
    )
    d.deploy("C")
    _, callers = _callers(d, "C")
    assert callers.complete and set(callers.members) == {O.OWNER}


def test_a_local_encoding_adds_no_condition(anvil, tmp_path):
    d = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity ^0.8.10;
contract C {address owner; mapping(address=>string) names; uint public value; constructor(){owner=msg.sender;}
    function act() external {
        require(msg.sender==owner, string(abi.encodePacked("denied ", names[msg.sender])));
        value=1;
    }}
""",
    )
    d.deploy("C")
    fn, callers = _callers(d, "C")
    assert callers.complete and set(callers.members) == {O.OWNER} == _admitted(d, fn)


def test_a_solver_timeout_ends_projection_unanswered(anvil, tmp_path):
    d = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity ^0.8.10;
contract M {address o; constructor(){o=msg.sender;}
    function allowed(address who) public view returns(bool){return who==o;}}
contract C {address m; uint public value; constructor(address a){m=a;} function act() external {
    uint dirty = uint256(uint160(msg.sender)) | (1<<200);
    (bool ok, bytes memory r) = m.staticcall(abi.encodeWithSignature("allowed(address)", dirty));
    require(ok); require(abi.decode(r,(bool))); value=1;}}
""",
    )
    d.deploy("C", ("address",), (d.deploy("M"),))
    start = time.monotonic()
    fn, callers = _callers(d, "C")
    assert time.monotonic() - start < 30
    assert callers.complete or not _admitted(d, fn)
    if callers.complete:
        assert not callers.members


@pytest.mark.parametrize("helper_coder", ["v1", "v2"])
@pytest.mark.parametrize("helper", ["library", "free"])
def test_decoder_uses_imported_call_site_scope(anvil, tmp_path, helper_coder, helper):
    from tests.logic import _anvil as A

    outer = "v2" if helper_coder == "v1" else "v1"
    body = "function check(address m) internal view returns(bool){return I(m).allowed();}"
    if helper == "library":
        body = "library L {" + body + "}"
        call = "L.check(m)"
    else:
        body = body.replace(" internal", "")
        call = "check(m)"
    (tmp_path / "Helper.sol").write_text(
        f"pragma solidity ^0.8.10; pragma abicoder {helper_coder};\n"
        "interface I {function allowed() external view returns(bool);}\n" + body
    )
    source = f"""pragma solidity ^0.8.10; pragma abicoder {outer}; import "./Helper.sol";
contract M {{function allowed() external pure returns(uint256){{return 2;}}}}
contract C {{address m; uint value; constructor(address a){{m=a;}}
function act() external {{require({call});value=1;}}}}
"""
    d = A.Deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("M"),))
    fn, callers = _callers(d, "C")
    assert callers.complete
    for sender in O.ACCOUNTS:
        actual = O.chain_says(d, fn, [], sender=sender)
        _, predicted = O.engine_says(d, fn, [], sender=sender, contracts=d.contracts(*d.at))
        assert predicted is actual is (helper_coder == "v1")


@pytest.mark.parametrize("name,args", [("encoded", []), ("chosen", [b""])])
def test_unused_decode_still_constrains_success(anvil, tmp_path, name, args):
    d = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity ^0.8.10;
contract C {uint value;
function encoded() external {abi.decode(abi.encode(uint256(2)),(bool)); value=1;}
function chosen(bytes calldata data) external {require(data.length==0);abi.decode(data,(bool));value=1;}
}""",
    )
    d.deploy("C")
    fn, callers = _callers(d, "C", name)
    for sender in O.ACCOUNTS:
        assert not O.chain_says(d, fn, args, sender=sender)
        _, predicted = O.engine_says(d, fn, args, sender=sender, contracts=d.contracts(*d.at))
        assert predicted is None or predicted is False
    if callers.complete:
        assert callers.representation == "finite" and not callers.members


@pytest.mark.parametrize("coder", ["v1", "v2"])
@pytest.mark.parametrize("position", ["before", "after", "body"])
@pytest.mark.parametrize("kind", ["call", "decode"])
def test_modifier_and_body_keep_their_own_decoder(anvil, tmp_path, coder, position, kind):
    from tests.logic import _anvil as A

    outer = "v2" if coder == "v1" else "v1"
    guard = "I(m).allowed()" if kind == "call" else "abi.decode(abi.encode(uint256(2)),(bool))"
    check = f"require({guard});"
    modifier = check + "_;" if position == "before" else "_;" + check if position == "after" else "_;"
    body = check + "value=1;" if position == "body" else "value=1;"
    (tmp_path / "Base.sol").write_text(f"""pragma solidity ^0.8.10; pragma abicoder {coder};
interface I {{function allowed() external view returns(bool);}}
contract Base {{address m; constructor(address a){{m=a;}} modifier authorized(){{{modifier}}}}}""")
    d = A.Deployment(
        anvil[0],
        tmp_path,
        f"""pragma solidity ^0.8.10; pragma abicoder {outer}; import "./Base.sol";
contract M {{function allowed() external pure returns(uint256){{return 2;}}}}
contract C is Base {{uint value; constructor(address a) Base(a) {{}} function act() external authorized {{{body}}}}}""",
    )
    d.deploy("C", ("address",), (d.deploy("M"),))
    fn, callers = _callers(d, "C")
    expected = (outer if position == "body" else coder) == "v1"
    assert callers.complete
    for sender in O.ACCOUNTS:
        actual = O.chain_says(d, fn, [], sender=sender)
        _, predicted = O.engine_says(d, fn, [], sender=sender, contracts=d.contracts(*d.at))
        assert predicted is actual is expected
