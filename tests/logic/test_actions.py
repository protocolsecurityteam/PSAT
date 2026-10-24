"""A state-changing call handed the caller is an action the caller arranges only when what its callee checks is the
caller's own to bring about there. Deployed on anvil and checked against ``eth_call`` (``_oracle.check``): for an
"open" verdict each stranger first brings about what the action needs for itself (tokens from a holder, an approval),
then its own call goes through; for "never open", no stranger's does."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_account import Account
from eth_utils import keccak

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

# anvil's second funded account, whose key is public: a signer for ``depositSigned``.
SIGNER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
SIGNER = O.ACCOUNTS[1]
DEADLINE = 2**64

SOURCE = """
pragma solidity 0.8.27;

contract Token {
    mapping(address => uint256) balanceOf;
    mapping(address => mapping(address => uint256)) allowance;

    constructor() { balanceOf[msg.sender] = 1e24; }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount && allowance[from][msg.sender] >= amount);
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract Vault {
    Token token;

    constructor(Token t) { token = t; }

    function deposit(uint256 amount) external {
        require(amount > 0);
        token.transferFrom(msg.sender, address(this), amount);
    }

    // A fixed fee: a stranger without tokens fails until it gets some (from any holder) and approves the vault.
    function payFee() external {
        token.transferFrom(msg.sender, address(this), 100);
    }

    mapping(address => uint256) nonces;

    // Aave's ``depositWithSig``: anyone relays a holder's signed deposit, the holder's tokens pulled in.
    function depositSigned(
        address owner, uint256 amount, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s
    )
        external
    {
        require(block.timestamp <= deadline && amount > 0);
        require(ecrecover(keccak256(abi.encode(owner, amount, nonce, deadline)), v, r, s) == owner);
        require(nonce == nonces[owner]);
        nonces[owner] = nonce + 1;
        token.transferFrom(owner, address(this), amount);
    }

    // Paying ether out is an action too.
    function refund() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    // A checked action: the call is both a condition and a revert point.
    function payOut(uint256 amount) external {
        require(token.transfer(msg.sender, amount));
    }
}

// Paxos' SupplyControl shape: a state-changing check of who may mint, handed the minter.
contract Supply {
    address admin;
    mapping(address => bool) controllers;
    mapping(address => uint256) minted;

    constructor() { admin = msg.sender; }

    function addController(address who) external {
        require(msg.sender == admin);
        controllers[who] = true;
    }

    function canMint(address sender, uint256 amount) external {
        require(controllers[sender]);
        minted[sender] += amount;
    }
}

contract Minter {
    Supply supply;
    uint256 total;

    constructor(Supply s) { supply = s; }

    function mint(uint256 amount) external {
        supply.canMint(msg.sender, amount);
        total += amount;
    }
}
"""


def _setup(d):
    d.deploy("Token")
    d.deploy("Vault", ("address",), (d.at["Token"],))
    d.deploy("Supply")
    d.deploy("Minter", ("address",), (d.at["Supply"],))


VAULT = ("deposit", "payFee", "depositSigned", "refund", "payOut")
PROBES = [O.Probe(SOURCE, _setup, (*(("Vault", f, ("Token",)) for f in VAULT), ("Minter", "mint", ("Supply",))))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _funded(amount):
    """A stranger handed ``amount`` tokens by the holder, approving the vault for them."""

    def arrange(d, who):
        assert O.transact(d, "Token", "transfer(address,uint256)", ("address", "uint256"), (who, amount))
        assert O.transact(d, "Token", "approve(address,uint256)", ("address", "uint256"), (d.at["Vault"], amount), who)

    return arrange


def _vault(d, name):
    return O.verdict(d, "Vault", name, "Token")


def test_a_deposit_pulling_the_callers_own_tokens_stays_open(d):
    v = O.check(d, "Vault", "deposit", _vault(d, "deposit"), arrange=_funded(5), open_at={"amount": 5})
    assert O.strangers_passing(d, "Vault", O.function(d, "Vault", "deposit"), {"amount": 5}) == {False}  # unfunded
    assert v.openness == "open"


def test_a_mint_its_supply_contract_allows_only_controllers_is_never_open(d):
    v = O.verdict(d, "Minter", "mint", "Supply")
    O.check(d, "Minter", "mint", v, samples=({"amount": 0}, {"amount": 1}), open_at=False)
    assert v.openness != "open"
    with O.snapshot(d):  # no stranger can make itself a controller
        assert not O.transact(d, "Supply", "addController(address)", ("address",), (O.STRANGERS[0],), O.STRANGERS[0])


def test_a_fixed_fee_in_tokens_anyone_can_obtain_stays_open(d):
    v = O.check(d, "Vault", "payFee", _vault(d, "payFee"), arrange=_funded(100), open_at={})
    assert v.openness == "open"


def test_a_checked_action_is_still_a_revert_point_of_its_own(d):
    # ``require(token.transfer(...))``: the call holding is a fact, and whether it returns is still asked of the call.
    O.check(d, "Vault", "payOut", _vault(d, "payOut"), open_at={"amount": 0})


def test_paying_ether_out_lowers_as_an_action(d):
    O.check(d, "Vault", "refund", _vault(d, "refund"), open_at={})


def test_a_check_handed_the_caller_by_a_contract_whose_address_went_unread_is_never_open(d):
    # Lido CSM's gate handing ``msg.sender`` to a module whose address the node failed to read: not "assumed".
    minter = d.at["Minter"]
    clean = O.verdict(d, "Minter", "mint", "Supply")
    faulted = O.verdict(
        d, "Minter", "mint", "Supply",
        chain=O.Faulty(d, storage=lambda m, p: int(p[0], 16) == minter and int(p[1], 16) == 0),
    )  # fmt: skip
    assert faulted.openness != "open"
    O.never_bolder(clean, faulted)


def _signed(amount, nonce=0):
    digest = keccak(encode(["address", "uint256", "uint256", "uint256"], [O.hex20(SIGNER), amount, nonce, DEADLINE]))
    sig = Account.unsafe_sign_hash(digest, SIGNER_KEY)
    return {
        "owner": SIGNER, "amount": amount, "nonce": nonce, "deadline": DEADLINE,
        "v": sig.v, "r": sig.r.to_bytes(32, "big"), "s": sig.s.to_bytes(32, "big"),
    }  # fmt: skip


def test_a_signed_deposit_pulling_chosen_amounts_is_open_to_any_signer(d):
    # The token pull is an action the signer arranges (an approval): a search that pins what it can't model must
    # still let it return. Any relayer submits the signer's deposit.
    def signer_ready(d, who):
        assert O.transact(d, "Token", "transfer(address,uint256)", ("address", "uint256"), (SIGNER, 5))
        assert O.transact(d, "Token", "approve(address,uint256)", ("address", "uint256"), (d.at["Vault"], 5), SIGNER)

    v = O.check(d, "Vault", "depositSigned", _vault(d, "depositSigned"), arrange=signer_ready, open_at=_signed(5))
    assert v.openness == "open"
