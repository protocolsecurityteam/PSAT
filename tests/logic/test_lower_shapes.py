"""Solidity shapes the lowering reads as the language means them: each probe compiled, deployed on anvil, and its
lowered success condition (or a getter's return value) evaluated by the decision's own evaluator at concrete inputs
and senders, compared with ``eth_call`` of the same call."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_account import Account
from eth_utils import keccak

from services.logic.decide import FRESH, Evaluator, World
from services.logic.lower import Lowerer
from services.logic.terms import mk, reset_terms, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

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

contract Authority {
    address owner;
    constructor(address o) { owner = o; }
    function canCall(address caller, address, bytes4) external view returns (bool, uint32) {
        return (caller == owner, 0);
    }
}

contract Manager {
    mapping(address => bool) allowed;

    function allow(address a) external { allowed[a] = true; }

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

    constructor(address a, Manager m) { authority = a; manager = m; fee = 5; }

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
    function LinkToken() public { balances[msg.sender] = 100; }

    function transfer(address to, uint256 value) public returns (bool) {
        require(to != address(this));
        return super.transfer(to, value);
    }
}
"""

SIZED_SRC = """
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

KEY = Account.create("psat.logic.lower_shapes")
SIGNER = int(KEY.address, 16)
SENDERS = [O.OWNER, FRESH]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE + SIGNED.split("\n", 2)[2])
    d.deploy("Authority", ("address",), (O.OWNER,))
    d.deploy("Manager")
    d.deploy("C", ("address", "address"), (d.at["Authority"], d.at["Manager"]))
    d.deploy("Signed")
    assert O.transact(d, "Manager", "allow(address)", ("address",), (O.ACCOUNTS[1],))
    return d


@pytest.fixture(scope="module")
def legacy(anvil):  # noqa: F811
    source = LINKED + SIZED_SRC.split("\n", 2)[2]
    d = O.deployment(*anvil, source, "0.4.19")
    d.deploy("LinkToken")
    d.deploy("Sized")
    return d


def _agrees(d, contract, name, values, senders=SENDERS, followed=()):
    """For each sender: the evaluated formula is definite and is what ``eth_call`` says; the outcomes, per sender."""
    fn = O.function(d, contract, name)
    out = []
    for who in senders:
        chain = O.chain_says(d, fn, values, contract, sender=who)
        formula, engine = O.engine_says(d, fn, values, contract, sender=who, contracts=d.contracts(contract, *followed))
        assert engine == chain, (name, values, hex(who), chain, engine, formula)
        out.append(chain)
    return out


@pytest.mark.parametrize("followed", [("Authority",), ()], ids=["followed", "unfollowed"])
def test_an_assembly_staticcall_of_encoded_data_is_the_view_call_it_makes(d, followed):
    # ``canCall(caller, this, msg.sig)`` asked of the authority, its first word the answer: the owner passes only.
    assert _agrees(d, "C", "managed", [], followed=followed) == [True, False]


def test_a_struct_arguments_fields_are_arguments_and_library_constants_fold(d):
    fn = O.function(d, "C", "configure")
    reset_terms()
    formula = Lowerer(d.slither["C"]).success(fn)
    bonus, receiver = sorted(subterms(formula, "arg"), key=lambda a: a[1])
    assert (bonus[1], receiver[1]) == ("config.bonus", "config.receiver")
    world = World(d.chain(), d.at["C"], O.selector(fn.solidity_signature), {})
    seen = set()
    for b, r in [(10_000, 1), (10_001, 1), (0, 0), (5, O.OWNER)]:
        data = keccak(text="configure((uint16,address))")[:4] + encode(["(uint16,address)"], [(b, O.hex20(r))])
        chain = O.eth_call(d.url, d.at["C"], data, O.OWNER)
        engine = Evaluator(world, {"caller": O.OWNER, "signer": O.OWNER}, {bonus: b, receiver: r}).truth(formula)
        assert engine == chain, (b, r, chain, engine)
        seen.add(chain)
    assert seen == {True, False}


def test_a_memory_array_holds_what_was_written_to_it(d):
    assert _agrees(d, "C", "check", [4]) == [True, True]


def test_a_declaration_a_public_variable_implements_is_its_getter(d):
    getter = next(f for f in d.slither["C"].functions_entry_points if f.name == "fee" and f.entry_point is None)
    reset_terms()
    pc, values = Lowerer(d.slither["C"]).returns(getter, [])
    world = World(d.chain(), d.at["C"], O.selector("fee()"), d.contracts("C"))
    ev = Evaluator(world, {"caller": O.OWNER, "signer": O.OWNER})
    word = O.rpc(
        d.url, "eth_call", [{"to": O.hex20(d.at["C"]), "data": "0x" + keccak(text="fee()")[:4].hex()}, "latest"]
    )
    assert ev.eval(values[0]) == int(word, 16) == 5
    assert pc == mk("const", True, "bool")


def test_what_a_function_builds_reads_back_as_built(d):
    # ``return pair(a)`` hands on both values; a struct literal's field and ``new bytes(20)``'s length read back.
    assert _agrees(d, "C", "made", [9]) == [True, True]


@pytest.mark.parametrize("followed", [("Manager",), ()], ids=["followed", "unfollowed"])
def test_the_arguments_without_the_selector_decode_back_to_the_arguments(d, followed):
    # Maple's pool hands its manager ``msg.data[4:]``; the manager decodes the lender from it into a static array:
    # only an allowlisted receiver passes.
    assert _agrees(d, "C", "deposit", [7, O.ACCOUNTS[1]], followed=followed) == [True, True]
    assert _agrees(d, "C", "deposit", [7, O.ACCOUNTS[2]], followed=followed) == [False, False]


def _signed(digest: bytes):
    sig = Account._sign_hash(digest, KEY.key) if hasattr(Account, "_sign_hash") else KEY.unsafe_sign_hash(digest)
    return sig.v, sig.r.to_bytes(32, "big"), sig.s.to_bytes(32, "big")


def test_a_packed_signature_reads_back_as_the_signer_check(d):
    # The lowering reads the signature as ``signer(digest, v, r, s)``, the identity that signed: here, what
    # ``ecrecover`` of those arguments gives, and the formula must then say what the chain does.
    fn = O.function(d, "Signed", "check")
    digest = keccak(b"psat")
    v, r, s = _signed(digest)
    outcomes = set()
    for owner, (vv, rr, ss) in [(SIGNER, (v, r, s)), (O.OWNER, (v, r, s)), (d.at["C"], (v, r, s)),
                                (SIGNER, (v, s, r))]:  # fmt: skip
        values = [owner, digest, vv, rr, ss]
        try:
            signer = int(Account._recover_hash(digest, vrs=(vv, rr, ss)), 16)
        except Exception:
            signer = 0
        chain = O.chain_says(d, fn, values, "Signed")
        reset_terms()
        formula = Lowerer(d.slither["Signed"]).success(fn)
        world = World(d.chain(), d.at["Signed"], O.selector(fn.solidity_signature), {})
        names = [p.name for p in fn.parameters]
        words = [owner, int.from_bytes(digest, "big"), vv, int.from_bytes(rr, "big"), int.from_bytes(ss, "big")]
        args = {a: words[names.index(a[1])] for a in subterms(formula, "arg")}
        engine = Evaluator(world, {"caller": O.OWNER, "signer": signer}, args).truth(formula)
        assert engine == chain, (hex(owner), chain, engine)
        outcomes.add(chain)
    assert outcomes == {True, False}


@pytest.mark.xfail(
    strict=True,
    reason="A-row (new): super into the next body in the deployed order (0.4.19 LinkToken.transferAndCall) lowers "
    "BasicToken.transfer with value read as 0: `require(0 <= balances[caller])` passes where the chain reverts",
)
def test_super_runs_the_next_body_in_the_deployed_contracts_order(legacy):
    # ``super.transfer`` in ``ERC677Token`` is ``BasicToken``'s body in ``LinkToken``: the balance check holds.
    assert _agrees(legacy, "LinkToken", "transferAndCall", [O.ACCOUNTS[1], 50]) == [True, False]
    assert _agrees(legacy, "LinkToken", "transferAndCall", [O.ACCOUNTS[1], 150]) == [False, False]


def test_legacy_assemblys_code_size_reads_as_the_accounts_code_size(legacy):
    assert _agrees(legacy, "Sized", "onlyAccounts", [O.ACCOUNTS[1]]) == [True, True]
    assert _agrees(legacy, "Sized", "onlyAccounts", [legacy.at["LinkToken"]]) == [False, False]
