"""Nested forwarding preserves storage, code, selector precedence, and dispatch guards."""

import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest
from slither import Slither

from services.logic import deployment
from services.logic.expansion import Selection
from services.logic.model import decode_formula
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity ^0.8.10;
contract Admin {
 uint pad; address owner; uint stored; address immutable embedded;
 constructor(address who){embedded=who;}
 function adminAct() external {require(msg.sender==owner);stored=2;}
 function immutableAct() external {require(msg.sender==embedded);stored=5;}
 function shared() external {require(msg.sender==owner);stored=4;}
 function value() external {stored=8;}
}
contract Core {
 address owner; uint pad; uint public value;
 constructor(address wrong){assembly{sstore(1234568,wrong)}}
 function coreAct() external {require(msg.sender==owner);value=1;}
 function shared() external {require(msg.sender==owner);value=3;}
 fallback() external payable {require(msg.sender==owner);assembly{
  let target:=sload(1234568) calldatacopy(0,0,calldatasize())
  let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
  returndatacopy(0,0,returndatasize())
  if iszero(ok){revert(0,returndatasize())} return(0,returndatasize())
 }}
}
contract Proxy {
 constructor(address core,address admin,address gateOwner,address bodyOwner){assembly{
  sstore(1234567,core) sstore(1234568,admin) sstore(0,gateOwner) sstore(1,bodyOwner)
 }}
 fallback() external payable {assembly{
  let target:=sload(1234567) calldatacopy(0,0,calldatasize())
  let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
  returndatacopy(0,0,returndatasize())
  if iszero(ok){revert(0,returndatasize())} return(0,returndatasize())
 }}
}"""


@pytest.fixture
def nested(anvil, tmp_path, monkeypatch):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    admin = d.deploy("Admin", ("address",), (O.OWNER,))
    core = d.deploy("Core", ("address",), (O.ACCOUNTS[2],))
    proxy = d.deploy("Proxy", ("address", "address", "address", "address"), (core, admin, O.OWNER, O.OWNER))
    # Retain real compiler immutableReferences; the deployed code is the independent oracle.
    root = Path(d.slither["Admin"].source_mapping.filename.absolute).parent
    (root / "foundry.toml").write_text(
        f'[profile.default]\nsrc="."\nout="out"\nlibs=[]\noptimizer=false\nsolc="{solc_path("0.8.27")}"\nevm_version="cancun"\n'
    )
    subprocess.run(["forge", "build", "--build-info"], cwd=root, capture_output=True, check=True)
    d.slither = {c.name: c for c in Slither(str(root)).contracts}

    @contextmanager
    def inputs(*args):
        reads = d.chain()
        builds = deployment.Builds(lambda at: None, lambda at: None, tmp_path, reads)
        builds._built.update({O.hex20(at): d.slither[name] for name, at in d.at.items()})
        yield reads, builds

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    return d, proxy, core, admin


def generate(nested):
    d, proxy, _, _ = nested
    return deployment.deployment_formulas(None, O.hex20(proxy), 1, "unused", block=d.chain().block)


def test_nested_entries_have_their_own_code_and_one_storage_address(nested):
    d, proxy, core, admin = nested
    artifact = generate(nested)
    codes = artifact["entry_code_addresses"]
    assert codes["coreAct()"] == codes["shared()"] == O.hex20(core)
    assert codes["adminAct()"] == codes["immutableAct()"] == O.hex20(admin)
    assert "value()" not in artifact["functions"]  # Core's getter shadows the admin mutator.
    assert artifact["code_locations"][O.hex20(proxy)] == O.hex20(core)
    contexts = {(x["address"], x["code_address"]) for x in artifact["source_bundle"]["deployments"]}
    assert {(O.hex20(proxy), O.hex20(c)) for c in (proxy, core, admin)} <= contexts
    selections = {name: Selection() for name in ["coreAct()", "shared()", "adminAct()", "immutableAct()"]}
    result = deployment.deployment_expansions(None, artifact, "unused", selections)
    for name in selections:
        row = result["functions"][name]["expansion"]["value"]["callers"]
        O.assumes_gas(row, {O.OWNER})
        fn = O.function(d, "Core" if name in ("coreAct()", "shared()") else "Admin", name[:-2])
        assert O.passes(d, proxy, fn, (), sender=O.OWNER)
        assert not O.passes(d, proxy, fn, (), sender=O.ACCOUNTS[1])
        assert decode_formula(artifact["functions"][name]).address == proxy


def test_same_variable_name_in_different_layers_uses_each_layout(nested):
    d, proxy, _, _ = nested
    rpc(d.url, "anvil_setStorageAt", [O.hex20(proxy), "0x1", "0x" + f"{O.ACCOUNTS[1]:064x}"])
    artifact = generate(nested)
    result = deployment.deployment_expansions(
        None, artifact, "unused", {"adminAct()": Selection(), "coreAct()": Selection()}
    )
    admin = result["functions"]["adminAct()"]["expansion"]["value"]["callers"]
    core = result["functions"]["coreAct()"]["expansion"]["value"]["callers"]
    O.assumes_gas(admin, set())
    O.assumes_gas(core, {O.OWNER})
    for sender in O.ACCOUNTS:
        assert not O.passes(d, proxy, O.function(d, "Admin", "adminAct"), (), sender=sender)


def test_forwarding_cycle_stops_with_a_qualification(nested):
    d, proxy, core, _ = nested
    # Metadata deliberately claims Admin while the actual second hop cycles through Core.
    from services.logic.expansion import expand_formula
    from services.logic.formula import compile_function

    rpc(d.url, "anvil_setStorageAt", [O.hex20(proxy), hex(1234568), "0x" + f"{core:064x}"])
    contracts = {proxy: d.slither["Admin"], **d.contracts("Core", "Admin")}
    own = {at: d.slither[name] for name, at in d.at.items()}

    def code_of(at):
        return d.at["Admin"] if at == proxy else at

    f = compile_function(
        d.slither["Admin"],
        O.function(d, "Admin", "adminAct"),
        proxy,
        d.chain(),
        contracts,
        code_of=code_of,
        own_code=own.get,
    )
    result = expand_formula(f, d.chain(), contracts).callers
    assert not result.complete and result.issues


def test_composition_does_not_confuse_names_in_delegated_and_native_layouts(anvil, tmp_path):
    from services.logic.expansion import expand_formula
    from services.logic.formula import compile_function
    from services.logic.solver import Translation, project
    from services.resolution.logic_composition import sequence

    source = """pragma solidity ^0.8.10;
contract Admin {uint renamed; function setup() external {renamed=7;}}
contract Core {uint value;
constructor(address impl){assembly{sstore(1234567,impl)}}
function finish() external view {require(value==7);}
fallback() external {assembly{
let impl:=sload(1234567) calldatacopy(0,0,calldatasize())
let ok:=delegatecall(gas(),impl,0,calldatasize(),0,0)
returndatacopy(0,0,returndatasize())
if iszero(ok){revert(0,returndatasize())} return(0,returndatasize())
}}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    admin = d.deploy("Admin")
    root = d.deploy("Core", ("address",), (admin,))
    reads = d.chain()
    own = {at: d.slither[name] for name, at in d.at.items()}
    layout = {root: d.slither["Admin"], admin: d.slither["Admin"]}

    def code_of(at):
        return admin if at == root else at

    first = compile_function(
        d.slither["Admin"], O.function(d, "Admin", "setup"), root, reads, layout, code_of=code_of, own_code=own.get
    )
    last = compile_function(
        d.slither["Core"], O.function(d, "Core", "finish"), root, reads, d.contracts("Core", "Admin")
    )
    assert first.state_specialized and last.state_specialized is False
    assert expand_formula(last, reads, d.contracts("Core", "Admin")).callers.members == ()
    result = project(sequence((first, last)), Translation(reads, d.contracts("Core", "Admin"), root))
    assert not result.complete and any("sequence_context_revalidation" in i.detail for i in result.issues)
    assert O.transact(d, root, "setup()", (), ())
    assert O.passes(d, root, O.function(d, "Core", "finish"), (), sender=O.OWNER)


def test_depth_cut_keeps_nested_functions_pending_and_resumable(nested):
    d, proxy, _, _ = nested
    first = deployment.deployment_formulas(None, O.hex20(proxy), 1, "unused", block=d.chain().block, callee_depth=1)
    assert first["status"] == "incomplete"
    assert "adminAct()" in first["pending_functions"] and "immutableAct()" in first["pending_functions"]
    assert "coreAct()" in first["functions"]
    resumed = deployment.deployment_formulas(None, O.hex20(proxy), 1, "unused", callee_depth=3, resume=first)
    assert resumed["status"] == "available"
    assert not resumed["pending_functions"]
    assert "fallback()" in resumed["functions"]
    assert "adminAct()" in resumed["functions"] and "immutableAct()" in resumed["functions"]


@pytest.mark.parametrize("mapping", [False, True])
def test_same_named_imported_namespace_types_are_not_guessed(anvil, tmp_path, mapping):
    from services.logic.expansion import expand_formula
    from services.logic.formula import compile_function
    from tests.logic._anvil import Deployment

    kind = "mapping(uint=>S)" if mapping else "S"
    for filename, fields in [("A.sol", "address owner;uint pad;"), ("B.sol", "uint pad;address owner;")]:
        (tmp_path / filename).write_text(
            "pragma solidity ^0.8.10; library Slot {struct S {" + fields + "} "
            "function state() internal pure returns(" + kind + " storage s){assembly{s.slot:=500}}}"
        )
    access = "state()[0]" if mapping else "state()"
    cell = "keccak256(abi.encode(uint(0),uint(500)))" if mapping else "bytes32(uint(500))"
    source = """pragma solidity ^0.8.10;
import {Slot as AS} from "./A.sol"; import {Slot as BS} from "./B.sol";
contract Core {fallback() external {require(msg.sender==AS.ACCESS.owner);assembly{
let target:=sload(100) calldatacopy(0,0,calldatasize())
let ok:=delegatecall(gas(),target,0,calldatasize(),0,0) returndatacopy(0,0,returndatasize())
if iszero(ok){revert(0,returndatasize())} return(0,returndatasize())}}}
contract Admin {function act() external {require(msg.sender==BS.ACCESS.owner);assembly{sstore(999,1)}}}
contract Root {constructor(address core,address admin,address a,address b){bytes32 cell=CELL;
assembly{sstore(100,admin) sstore(101,core) sstore(cell,a) sstore(add(cell,1),b)}}
fallback() external {assembly{let target:=sload(101) calldatacopy(0,0,calldatasize())
let ok:=delegatecall(gas(),target,0,calldatasize(),0,0) returndatacopy(0,0,returndatasize())
if iszero(ok){revert(0,returndatasize())} return(0,returndatasize())}}}
""".replace("ACCESS", access).replace("CELL", cell)
    d = Deployment(anvil[0], tmp_path, source)
    core = d.deploy("Core")
    admin = d.deploy("Admin")
    root = d.deploy("Root", ("address",) * 4, (core, admin, O.OWNER, O.ACCOUNTS[1]))
    own = {at: d.slither[name] for name, at in d.at.items()}
    contracts = {**own, root: d.slither["Admin"]}

    def code_of(at):
        return admin if at == root else at

    f = compile_function(
        d.slither["Admin"], O.function(d, "Admin", "act"), root, d.chain(), contracts, code_of=code_of, own_code=own.get
    )
    result = expand_formula(f, d.chain(), contracts).callers
    assert not result.complete and result.issues
    for who in O.ACCOUNTS[:2]:
        assert not O.passes(d, root, O.function(d, "Admin", "act"), (), sender=who)


@pytest.mark.parametrize("resume", [False, True])
def test_visited_branch_sources_survive_generation_and_resume(anvil, tmp_path, monkeypatch, resume):
    DELEGATE = """assembly {
let target:=sload(100) calldatacopy(0,0,calldatasize())
 let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
 returndatacopy(0,0,returndatasize())
 if iszero(ok){
revert(0,returndatasize())}
 return(0,returndatasize())}
"""
    from services.logic.source_context import materialize_context

    admin_src = """pragma solidity ^0.8.10;
 contract Admin {
uint pad;
uint pad2;
uint value;
function act() external {
value=7;
}
 function later(uint n) external {
for(uint i=0;
i<n;
i++){
value+=i;
}
}
}
"""
    left_src = """pragma solidity ^0.8.10;
 contract Left {
address owner;
fallback() external {
require(msg.sender==owner);
DELEGATE}
}
""".replace("DELEGATE", DELEGATE)
    right_src = """pragma solidity ^0.8.10;
 contract Right {
uint pad;
address owner;
fallback() external {
require(msg.sender==owner);
DELEGATE}
}
""".replace("DELEGATE", DELEGATE)
    root_src = """pragma solidity ^0.8.10;

contract Root {
address owner;

constructor(address a,address b,address admin,address whoA,address whoB){
assembly{

 sstore(0,whoA) sstore(1,whoB) sstore(10,a) sstore(11,b) sstore(100,admin)}
}

fallback() external {
if(msg.sender==owner){
go(10);
}
else{
go(11);
}
}

function go(uint slot) internal {
assembly{
let target:=sload(slot) calldatacopy(0,0,calldatasize())
 let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
 returndatacopy(0,0,returndatasize())
 if iszero(ok){
revert(0,returndatasize())}
 return(0,returndatasize())}
}

}
"""
    da = O.deployment(anvil[0], tmp_path, admin_src)
    admin = da.deploy("Admin")
    dl = O.deployment(anvil[0], tmp_path, left_src)
    left = dl.deploy("Left")
    db = O.deployment(anvil[0], tmp_path, right_src)
    right = db.deploy("Right")
    dr = O.deployment(anvil[0], tmp_path, root_src)
    root = dr.deploy("Root", ("address",) * 5, (left, right, admin, O.OWNER, O.ACCOUNTS[1]))
    own = {root: dr.slither["Root"], left: dl.slither["Left"], right: db.slither["Right"], admin: da.slither["Admin"]}

    @contextmanager
    def inputs(*args):
        b = deployment.Builds(
            lambda at: None, lambda at: O.hex20(admin) if at == O.hex20(root) else None, tmp_path, dr.chain()
        )
        b._built.update({O.hex20(a): c for a, c in own.items()})
        yield dr.chain(), b

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    artifact = deployment.deployment_formulas(
        None,
        O.hex20(root),
        1,
        "unused",
        block=dr.chain().block,
        signatures={"act()", "later(uint256)"},
        loop_iterations=1,
    )
    assert "act()" in artifact["functions"] and "later(uint256)" in artifact["pending_functions"]
    if resume:
        artifact = deployment.deployment_formulas(None, O.hex20(root), 1, "unused", loop_iterations=2, resume=artifact)
    expanded = deployment.deployment_expansions(None, artifact, "unused", {"act()": Selection()})
    result = expanded["functions"]["act()"]["expansion"]["value"]["callers"]
    O.assumes_gas(result, set(O.ACCOUNTS[:2]))
    for who in O.ACCOUNTS:
        assert O.passes(dr, root, O.function(da, "Admin", "act"), (), sender=who) is (who in O.ACCOUNTS[:2])
    f = decode_formula(artifact["functions"]["act()"])
    context = materialize_context(artifact["contexts"]["act()"], f, artifact["source_bundle"])
    sources = {u["source"] for u in context["units"]}
    assert {admin_src, left_src, right_src, root_src} <= sources, "Visited forwarding code omitted from source bundle"
