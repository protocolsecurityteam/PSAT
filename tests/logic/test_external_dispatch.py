"""External dispatch respects compiler shadowing/visibility, including returned-target chains."""

import subprocess
from dataclasses import replace

import pytest
from eth_utils import keccak
from slither import Slither

from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from services.logic.solver import Translation
from services.logic.terms import CALLER, FALSE, ORIGIN, TRUE, mk, replace_terms, subterms
from tests.logic import _anvil as A
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0, rpc

SOURCE = """pragma solidity ^0.8.10;
interface IM {function allowed(address who) external view returns(bool);}
interface IP {function getManager() external view returns(address);}
contract MB is IM {function allowed(address) public view virtual override returns(bool){return true;}}
contract M is MB {address public owner;
constructor(){owner=msg.sender;}
function allowed(address who) public view override returns(bool){return who==owner;}}
contract PB is IP {function getManager() public view virtual override returns(address){return address(0);}}
contract P is PB {address manager;
constructor(address m){manager=m;}
function getManager() public view override returns(address){return manager;}}
contract PG is IP {address public override getManager;
constructor(address m){getManager=m;}}
contract PrivateM {function allowed(address) private pure returns(bool){return true;}}
contract C {IP public provider;
uint public value;
constructor(IP p){provider=p;}
function act() external {IM m=IM(provider.getManager());require(m.allowed(msg.sender));value=1;}}
contract CI {IP public immutable provider;
uint public value;
constructor(IP p){provider=p;}
function act() external {IM m=IM(provider.getManager());require(m.allowed(msg.sender));value=1;}}
"""
SOURCE += """
contract UBase {function allowed(address) public pure virtual returns(uint){return 0;}}
contract WrongM is UBase {function allowed(address) public pure override returns(uint){return 2;}}
contract RawM {function allowed(address) public pure returns(bool){assembly{return(0,0)}}}
contract RevertM {function allowed(address) public pure returns(bool){assembly{mstore(0,1) revert(0,32)}}}
contract Discard {IM m; uint public value; constructor(address a){m=IM(a);}
    function act() external {m.allowed(msg.sender);value=1;}}
contract RawCaller {address m; uint public value; constructor(address a){m=a;}
    function act() external {
        (bool ok,bytes memory data)=m.staticcall(abi.encodeWithSignature("allowed(address)",msg.sender));
        require(ok);require(abi.decode(data,(bool)));value=1;
    }
    function fromFailure() external {
        (,bytes memory data)=m.staticcall(abi.encodeWithSignature("allowed(address)",msg.sender));
        require(abi.decode(data,(bool)));value=1;
    }
}
"""


@pytest.fixture(params=["0.8.10", "0.8.27"])
def dispatch(request, anvil, monkeypatch, tmp_path):
    monkeypatch.setattr(A, "SOLC", request.param)
    d = A.Deployment(anvil[0], tmp_path, SOURCE)
    m = d.deploy("M")
    p = d.deploy("P", ("address",), (m,))
    d.deploy("C", ("address",), (p,))
    d.deploy("CI", ("address",), (p,))
    # Production consumes compiler immutableReferences. Generate those artifacts independently
    # rather than replacing immutables with hand-chosen values in the test.
    compiler = str(A.solc_path(request.param))
    evm = "london" if request.param == "0.8.10" else "cancun"
    (tmp_path / "foundry.toml").write_text(
        f'[profile.default]\nsrc="."\nout="out"\nlibs=[]\noptimizer=false\nsolc="{compiler}"\nevm_version="{evm}"\n'
    )
    subprocess.run(["forge", "build", "--build-info"], cwd=tmp_path, check=True, capture_output=True)
    d.slither = {c.name: c for c in Slither(str(tmp_path)).contracts}
    return d


def compile_and_check(d, name, *, raw=False):
    fn = next(f for f in d.slither[name].functions_entry_points if f.name == "act")
    f = compile_function(d.slither[name], fn, d.at[name], d.chain(), d.contracts(*d.at))
    gaps = subterms(f.success, "unknown")
    result = expand_formula(f, d.chain(), d.contracts(*d.at))
    if raw:
        assert gaps and all(t[1] == "unsupported:raw_call_resources" for t in gaps)
        assert not result.callers.complete and result.callers.issues
        successful = replace(f, success=replace_terms(f.success, {t: TRUE for t in gaps}))
        projected = expand_formula(successful, d.chain(), d.contracts(*d.at)).callers
        assert projected.complete and projected.members == (O.OWNER,)
        # The successful-call branch still proves the owner gate. Resource failure is a
        # separately tested EVM outcome, not a reason to drop or invent that identity check.
        for caller in (O.OWNER, O.ACCOUNTS[1]):
            tr = Translation(
                d.chain(),
                d.contracts(*d.at),
                d.at[name],
                f.selector,
                bindings={
                    CALLER: caller,
                    ORIGIN: caller,
                    mk("callvalue"): 0,
                    **{t: True for t in gaps},
                },
            )
            assert tr.truth(f.success) is (caller == O.OWNER)
    else:
        assert not gaps
        assert result.callers.complete and result.callers.members == (int(ACCOUNT0, 16),)
    data = "0x" + keccak(text="act()")[:4].hex()
    assert rpc(d.url, "eth_call", [{"to": f"0x{d.at[name]:040x}", "from": ACCOUNT0, "data": data}, "latest"]) == "0x"
    with pytest.raises(RuntimeError, match="revert"):
        rpc(d.url, "eth_call", [{"to": f"0x{d.at[name]:040x}", "from": "0x" + "11" * 20, "data": data}, "latest"])


@pytest.mark.parametrize("name", ["C", "CI"])
def test_active_override_and_returned_target(dispatch, name):
    compile_and_check(dispatch, name)


def test_interface_getter_remains_supported(dispatch):
    d = dispatch
    p = d.deploy("PG", ("address",), (d.at["M"],))
    d.deploy("C", ("address",), (p,))
    compile_and_check(d, "C")


def test_external_calls_cannot_execute_private_functions(dispatch):
    d = dispatch
    m = d.deploy("PrivateM")
    p = d.deploy("P", ("address",), (m,))
    d.deploy("C", ("address",), (p,))
    fn = next(f for f in d.slither["C"].functions_entry_points if f.name == "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts(*d.at))
    assert f.success == FALSE  # The verified dispatcher has no public entry or fallback.
    data = "0x" + keccak(text="act()")[:4].hex()
    with pytest.raises(RuntimeError, match="revert"):
        rpc(d.url, "eth_call", [{"to": f"0x{d.at['C']:040x}", "from": ACCOUNT0, "data": data}, "latest"])


@pytest.mark.parametrize("target", ["WrongM", "RawM"])
@pytest.mark.parametrize("caller", ["C", "Discard", "RawCaller"])
def test_return_abi_mismatch_and_raw_return_never_promote(dispatch, target, caller):
    d = dispatch
    m = d.deploy(target)
    arg = d.deploy("P", ("address",), (m,)) if caller == "C" else m
    d.deploy(caller, ("address",), (arg,))
    fn = next(f for f in d.slither[caller].functions_entry_points if f.name == "act")
    f = compile_function(d.slither[caller], fn, d.at[caller], d.chain(), d.contracts(*d.at))
    for sender in (O.OWNER, O.ACCOUNTS[1]):
        actual = O.chain_says(d, fn, [], sender=sender)
        _, predicted = O.engine_says(d, fn, [], sender=sender, contracts=d.contracts(*d.at))
        assert predicted is None or predicted is actual
    result = expand_formula(f, d.chain(), d.contracts(*d.at)).callers
    if result.complete:
        assert result.representation == "finite" and not result.members
        assert not actual
    else:
        assert result.issues


def test_matching_low_level_decode_keeps_owner_proof(dispatch):
    d = dispatch
    d.deploy("RawCaller", ("address",), (d.at["M"],))
    compile_and_check(d, "RawCaller", raw=True)


def test_decodable_revert_data_is_not_refuted_as_call_failure(dispatch):
    d = dispatch
    m = d.deploy("RevertM")
    d.deploy("RawCaller", ("address",), (m,))
    fn = next(f for f in d.slither["RawCaller"].functions_entry_points if f.name == "fromFailure")
    f = compile_function(d.slither["RawCaller"], fn, d.at["RawCaller"], d.chain(), d.contracts(*d.at))
    assert any("revert_data_decode" in t[1] for t in subterms(f.success, "unknown"))
    assert not expand_formula(f, d.chain(), d.contracts(*d.at)).callers.complete
    assert (
        rpc(
            d.url,
            "eth_call",
            [
                {
                    "to": f"0x{d.at['RawCaller']:040x}",
                    "from": ACCOUNT0,
                    "data": "0x" + keccak(text="fromFailure()")[:4].hex(),
                },
                "latest",
            ],
        )
        == "0x"
    )
