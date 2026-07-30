// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// A4: destinations that ARE a parameter and are NOT freely chosen by the caller.
//
// Before this fixture every ``param`` destination in the corpus was genuinely
// unconstrained, so a change that narrows constrained ones produced a zero-diff
// for the WRONG reason — not "the narrowing is correct" but "the corpus has
// nothing to narrow". Three constraint shapes are present, each of which a real
// protocol uses, plus the unconstrained negative control that must NOT narrow.
//
// The constraint lives in the predicate tree, not in the flow fact, which is why
// the golden pins both: today all four functions publish an identical
// ``target_kind: {"kind": "param"}`` and are told apart only by their guards.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ConstrainedDestinations {
    address public owner;
    address public treasury;
    bytes32 public payoutCommitment;
    mapping(address => bool) public allowedPayee;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // SHAPE 1 — hash commitment. The destination is a parameter, but only the
    // address whose (address, salt) preimage was committed in storage can be
    // paid, so the caller chooses from a set of size one that it did not pick.
    function payCommitted(IERC20 token, address to, uint256 amount, bytes32 salt) external onlyOwner {
        require(keccak256(abi.encode(to, salt)) == payoutCommitment, "not committed");
        token.transfer(to, amount);
    }

    // SHAPE 2 — mapping allowlist. The caller chooses, but only from the set an
    // authority previously wrote into storage.
    function payAllowlisted(IERC20 token, address to, uint256 amount) external onlyOwner {
        require(allowedPayee[to], "not allowed");
        token.transfer(to, amount);
    }

    // SHAPE 3 — storage equality. Formally a parameter, factually the single
    // stored address; the parameter is decoration.
    function payTreasuryOnly(IERC20 token, address to, uint256 amount) external onlyOwner {
        require(to == treasury, "not treasury");
        token.transfer(to, amount);
    }

    // NEGATIVE CONTROL — genuinely unconstrained. Same body, same claim, same
    // flow fact, NO constraint on ``to``. A narrowing that also moves this one
    // is wrong, and this is the row that says so.
    function payAnyone(IERC20 token, address to, uint256 amount) external onlyOwner {
        token.transfer(to, amount);
    }

    function setTreasury(address newTreasury) external onlyOwner {
        treasury = newTreasury;
    }

    function setCommitment(bytes32 commitment) external onlyOwner {
        payoutCommitment = commitment;
    }

    function setAllowed(address payee, bool allowed) external onlyOwner {
        allowedPayee[payee] = allowed;
    }
}
