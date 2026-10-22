"""Solidity shapes the lowering reads as the language means them, compiled and lowered."""

from __future__ import annotations

import pytest

from services.logic.lower import Lowerer
from services.logic.terms import CALLER, THIS, contains, mk, subterms
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

interface IAuthority {
    function canCall(address caller, address target, bytes4 selector) external view returns (bool, uint32);
}

interface IRegistry {
    function fee() external returns (uint256);
}

library Percent {
    uint256 internal constant FACTOR = 1e4;
}

contract Manager {
    mapping(address => bool) allowed;

    function canCall(address caller_, bytes calldata data_) external view returns (bool) {
        uint256[3] memory params_ = _decode(data_);
        return caller_ != address(0) && allowed[address(uint160(params_[1]))];
    }

    function _decode(bytes calldata data_) internal pure returns (uint256[3] memory words) {
        if (data_.length > 64) {
            (words[0], words[1], words[2]) = abi.decode(data_, (uint256, uint256, uint256));
        } else {
            (words[0], words[1]) = abi.decode(data_, (uint256, uint256));
        }
    }
}

contract C is IRegistry {
    struct Config { uint16 bonus; address receiver; }

    address authority;
    uint256 public fee;
    mapping(uint256 => uint256[]) params;

    function canCallWithDelay(address caller) internal view returns (bool immediate) {
        bytes memory data = abi.encodeCall(IAuthority.canCall, (caller, address(this), bytes4(msg.data[0:4])));
        address target = authority;
        assembly ("memory-safe") {
            mstore(0x00, 0x00)
            mstore(0x20, 0x00)
            if staticcall(gas(), target, add(data, 0x20), mload(data), 0x00, 0x40) {
                immediate := mload(0x00)
            }
        }
    }

    function managed() external view {
        require(canCallWithDelay(msg.sender));
    }

    uint256 internal constant FOREVER = type(uint256).max;

    function configure(Config calldata config) external pure {
        require(config.bonus <= Percent.FACTOR && FOREVER > 0);
        require(config.receiver != address(0));
    }

    function arr(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        r[0] = a;
        r[1] = b;
    }

    function check(uint256 a) external pure returns (uint256) {
        uint256[] memory r = arr(a, 7);
        require(r[1] == 7);
        return r[0];
    }

    function pair(uint256 a) internal pure returns (uint256, uint256) {
        return (a, 3);
    }

    function forward(uint256 a) internal pure returns (uint256, uint256) {
        return pair(a);
    }

    Manager manager;

    function deposit(uint256 assets, address receiver) external view {
        require(manager.canCall(msg.sender, msg.data[4:]));
    }

    function made(uint256 a) external pure {
        (, uint256 three) = forward(a);
        Config memory c = Config(uint16(three), address(0));
        bytes memory b = new bytes(20);
        require(c.bonus == 3 && b.length == 20);
    }
}
"""


@pytest.fixture(scope="module")
def contracts(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("shapes") / "C.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


@pytest.fixture(scope="module")
def contract(contracts):
    return contracts["C"]


def _function(contract, name):
    return next(f for f in contract.functions_entry_points if f.name == name)


def test_an_assembly_staticcall_of_encoded_data_is_the_view_call_it_makes(contract):
    formula = Lowerer(contract).success(_function(contract, "managed"))
    calls = subterms(formula, "call")
    assert [c[2] for c in calls] == ["canCall(address,address,bytes4)"]
    assert calls[0][3] == (CALLER, THIS, mk("sig"))  # the selector this call came in with
    assert subterms(formula, "ok") and subterms(formula, "item")  # succeeded, and its first word is the answer
    assert not contains(formula, frozenset({"opaque", "unknown"}))


def test_a_struct_arguments_fields_are_arguments_and_library_constants_fold(contract):
    formula = Lowerer(contract).success(_function(contract, "configure"))
    names = {a[1] for a in subterms(formula, "arg")}
    assert names == {"config.bonus", "config.receiver"}
    assert any(c[1] == 10_000 for c in subterms(formula, "const"))
    assert not contains(formula, frozenset({"opaque", "unknown"}))


def test_a_memory_array_holds_what_was_written_to_it(contract):
    assert Lowerer(contract).success(_function(contract, "check")) == mk("const", True, "bool")


def test_a_declaration_a_public_variable_implements_is_its_getter(contract):
    getter = next(f for f in contract.functions_entry_points if f.name == "fee" and f.entry_point is None)
    pc, values = Lowerer(contract).returns(getter, [])
    assert pc == mk("const", True, "bool")
    assert values == (mk("load", THIS, "fee", ()),)


def test_what_a_function_builds_reads_back_as_built(contract):
    # ``return pair(a)`` hands on both values; a struct literal's field and ``new bytes(20)``'s length read back.
    assert Lowerer(contract).success(_function(contract, "made")) == mk("const", True, "bool")


def test_the_arguments_without_the_selector_decode_back_to_the_arguments(contracts):
    # Maple's pool hands its manager ``msg.data[4:]``; the manager decodes the lender from it into a static array.
    formula = Lowerer(contracts["C"]).success(_function(contracts["C"], "deposit"))
    (call,) = subterms(formula, "call")
    assets, receiver = mk("arg", "assets", "uint256"), mk("arg", "receiver", "address")
    assert call[3] == (CALLER, mk("enc", "abi.encode", (assets, receiver)))
    manager = contracts["Manager"]
    can_call = next(f for f in manager.functions_entry_points if f.name == "canCall")
    pc, (allowed,) = Lowerer(manager, sender=THIS, this=mk("const", 1, "address")).returns(can_call, list(call[3]))
    (lookup,) = subterms(allowed, "load")
    key = lookup[3][0][1]
    while key[0] == "conv":
        key = key[2]
    assert key == receiver  # the lender is the deposit's receiver
    assert not contains(allowed, frozenset({"opaque", "unknown"}))


SIGNED = """
pragma solidity 0.8.27;

contract Signed {
    // OpenZeppelin ``SignatureChecker`` behind USDC's ``permit``: the signature packed, then read back word by word.
    function check(address owner, bytes32 digest, uint8 v, bytes32 r, bytes32 s) external view {
        require(_valid(owner, digest, abi.encodePacked(r, s, v)));
    }

    function _valid(address signer, bytes32 digest, bytes memory signature) internal view returns (bool) {
        if (signer.code.length > 0) return false;
        require(signature.length == 65);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(digest, v, r, s) == signer;
    }
}
"""


def test_a_packed_signature_reads_back_as_the_signer_check(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("signed") / "S.sol"
    path.write_text(SIGNED)
    signed = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Signed")
    formula = Lowerer(signed).success(_function(signed, "check"))
    (signer,) = subterms(formula, "signer")
    assert signer[2:] == (mk("arg", "v", "uint8"), mk("arg", "r", "bytes32"), mk("arg", "s", "bytes32"))
    assert subterms(formula, "codesize") and not contains(formula, frozenset({"opaque"}))


LINKED = """
pragma solidity 0.4.19;

contract ERC20Basic {
    function transfer(address to, uint256 value) public returns (bool);
}

contract BasicToken is ERC20Basic {
    mapping(address => uint256) balances;

    function transfer(address to, uint256 value) public returns (bool) {
        require(value <= balances[msg.sender]);
        balances[msg.sender] -= value;
        balances[to] += value;
        return true;
    }
}

contract ERC677 is ERC20Basic {
    function transferAndCall(address to, uint256 value) public returns (bool);
}

contract ERC677Token is ERC677 {
    // ``super`` here is ``ERC20Basic``'s bodiless declaration to Slither; deployed, it is ``BasicToken``'s.
    function transferAndCall(address to, uint256 value) public returns (bool) {
        return super.transfer(to, value);
    }
}

contract LinkToken is BasicToken, ERC677Token {
    function transfer(address to, uint256 value) public returns (bool) {
        require(to != address(this));
        return super.transfer(to, value);
    }
}
"""


def test_super_runs_the_next_body_in_the_deployed_contracts_order(tmp_path_factory):
    solc = solc_path("0.4.19")
    if solc is None:
        pytest.skip("solc 0.4.19 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("linked") / "L.sol"
    path.write_text(LINKED)
    link = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "LinkToken")
    formula = Lowerer(link).success(_function(link, "transferAndCall"))
    assert not contains(formula, frozenset({"unknown"}))
    assert subterms(formula, "load")  # BasicToken's balance check, not an unanalysed declaration


SIZED = """
pragma solidity 0.4.19;

contract Sized {
    // Lido's ``SignatureUtils._hasCode``: assembly Slither leaves unlowered before Solidity 0.6.
    function _hasCode(address account) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }

    function onlyAccounts(address account) external view {
        require(!_hasCode(account));
    }
}
"""


def test_legacy_assemblys_code_size_reads_as_the_accounts_code_size(tmp_path_factory):
    solc = solc_path("0.4.19")
    if solc is None:
        pytest.skip("solc 0.4.19 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("sized") / "S.sol"
    path.write_text(SIZED)
    sized = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Sized")
    formula = Lowerer(sized).success(_function(sized, "onlyAccounts"))
    assert set(subterms(formula, "codesize")) == {mk("codesize", mk("arg", "account", "address"))}
    assert not contains(formula, frozenset({"unknown"}))
