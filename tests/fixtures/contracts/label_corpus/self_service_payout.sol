// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// The self-service payout discrimination pair: a cancelBid-shaped refund that
// PROVES `self_service_payout` (the amount is read out of the caller's own
// record — `bids[_bidId].bidder == msg.sender` is mandatory — and the record
// is cleared before the external call), next to a rescueTokens-shaped admin
// sweep that must never carry the fact at all.
//
// Until this fixture the corpus's only `bounded_by_storage` amount was a
// scalar cap read (HelperReturns.drainToCap), which refuses at
// `amount_root_not_classifiable` — so every self-service assertion held
// vacuously: no element-read amount, no caller-authority element guard, no
// proven verdict, and no `amount_record_*` / `record_ordering` flow fields
// existed anywhere for the golden to pin. A producer that stopped resolving
// the record entirely would have produced a zero-diff.
//
// The pair discriminates on the evidence, not the name: the sweep is
// owner-gated and takes both destination and amount from the caller, so its
// flow carries `amount_constraint` (the SS-R3 substrate) and NOT the
// self-service keys — absence is the fail-closed reading downstream.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SelfServicePayout {
    struct Bid {
        address bidder;
        uint256 amount;
    }

    mapping(uint256 => Bid) public bids;
    IERC20 public immutable token;
    address public owner;

    constructor(IERC20 _token) {
        token = _token;
        owner = msg.sender;
    }

    // W1: the guard and the amount name the SAME cell (`bids[_bidId]`), the
    // guard compares its `.bidder` member to msg.sender, and the key is one
    // whole entry argument. W2: the zero-assign clearing write dominates the
    // external call. Both conjunctions proven => `proven_self_service`.
    function cancelBid(uint256 _bidId) external {
        require(bids[_bidId].bidder == msg.sender, "not bidder");
        uint256 amt = bids[_bidId].amount;
        bids[_bidId].amount = 0;
        token.transfer(msg.sender, amt);
    }

    // The sibling that must NOT move: caller-chosen destination AND amount,
    // no storage record read — the self-service question does not exist here,
    // and an owner gate must not stand in for a witness.
    function rescueTokens(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        token.transfer(to, amount);
    }
}
