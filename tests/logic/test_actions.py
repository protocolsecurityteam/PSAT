"""A state-changing call handed the caller is an action the caller arranges only when what its callee checks is the
caller's own to bring about there."""

from __future__ import annotations

import pytest

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

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

    function mint(uint256 amount) external {
        supply.canMint(msg.sender, amount);
        total += amount;
    }
}
"""

VAULT, TOKEN, MINTER, SUPPLY = 0xA1 << 140, 0xB2 << 140, 0xC3 << 140, 0xD4 << 140


class _Deployed(Chain):
    """Each outer contract's first slot points at its callee; everything else as deployed and empty."""

    def __init__(self):
        super().__init__(self._answer, 1, lambda calls: [self._answer(m, p) for m, p in calls])

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            at, slot = int(params[0], 16), int(params[1], 16)
            return hex({(VAULT, 0): TOKEN, (MINTER, 0): SUPPLY}.get((at, slot), 0))
        if method == "eth_getLogs":
            return []
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(1)}
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address in (VAULT, TOKEN, MINTER, SUPPLY) else b""

    def logs(self, address, topics):
        return []


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("actions") / "A.sol"
    path.write_text(SOURCE)
    return {c.name: c for c in Slither(str(path), solc=str(solc)).contracts}


def _verdict(built, name, fn_name, at, contracts):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = built[name]
    fn = next(f for f in contract.functions_entry_points if f.name == fn_name)
    verdict, _ = function_verdict(contract, fn, at, _Deployed(), contracts)
    return verdict


def test_a_deposit_pulling_the_callers_own_tokens_stays_open(built):
    contracts = {VAULT: built["Vault"], TOKEN: built["Token"]}
    assert _verdict(built, "Vault", "deposit", VAULT, contracts).openness == "open"


def test_a_mint_its_supply_contract_allows_only_controllers_is_never_open(built):
    contracts = {MINTER: built["Minter"], SUPPLY: built["Supply"]}
    assert _verdict(built, "Minter", "mint", MINTER, contracts).openness != "open"


def test_a_fixed_fee_in_tokens_anyone_can_obtain_stays_open(built):
    contracts = {VAULT: built["Vault"], TOKEN: built["Token"]}
    assert _verdict(built, "Vault", "payFee", VAULT, contracts).openness == "open"


def test_a_checked_action_is_still_a_revert_point_of_its_own(built):
    # ``require(token.transfer(...))``: the call holding is a fact, and whether it returns is still asked of the call.
    contracts = {VAULT: built["Vault"], TOKEN: built["Token"]}
    assert _verdict(built, "Vault", "payOut", VAULT, contracts).openness == "open"


def test_paying_ether_out_lowers_as_an_action(built):
    contracts = {VAULT: built["Vault"], TOKEN: built["Token"]}
    assert _verdict(built, "Vault", "refund", VAULT, contracts).openness == "open"


class _SupplyUnread(_Deployed):
    """The node times out on the slot holding the minter's supply contract."""

    def _answer(self, method, params):
        if method == "eth_getStorageAt" and (int(params[0], 16), int(params[1], 16)) == (MINTER, 0):
            raise RuntimeError("timeout")
        return super()._answer(method, params)


def test_a_check_handed_the_caller_by_a_contract_whose_address_went_unread_is_never_open(built):
    # Lido CSM's gate handing ``msg.sender`` to a module whose address the node failed to read: not "assumed".
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in built["Minter"].functions_entry_points if f.name == "mint")
    contracts = {MINTER: built["Minter"], SUPPLY: built["Supply"]}
    verdict, _ = function_verdict(built["Minter"], fn, MINTER, _SupplyUnread(), contracts)
    assert verdict.openness != "open"


def test_a_signed_deposit_pulling_chosen_amounts_is_open_to_any_signer(built):
    # The token pull is an action the signer arranges (an approval): a search that pins what it can't model must
    # still let it return.
    contracts = {VAULT: built["Vault"], TOKEN: built["Token"]}
    assert _verdict(built, "Vault", "depositSigned", VAULT, contracts).openness == "open"
