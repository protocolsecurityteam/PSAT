// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// The ``policy_derived`` tier had ZERO producers anywhere in the data — 679
// claims, none of them policy tier — so nothing could catch a consumer that
// mishandles the weakest tier in the vocabulary. It is not unproducible: it is
// minted only by the cross-contract pass, which the corpus never ran.
//
// TWO body calls, deliberately.
//
// ``depositTo`` resolves onto the corpus CastWrappedPull at 0x…00a0, whose
// ``deposit(uint256)`` carries a standard_exact ``flow.in``; the derivation
// carries that claim here at ``policy_derived``. That row is the live one — the
// tier minted by the production code path, not written into a golden by hand.
//
// ``recoverVia`` resolves onto AssetRecovery at 0x…0070, whose ``sweepTo``
// carries a standard_exact ``flow.out``, and derives NOTHING today. The join
// keys the callee's claims by the selector on its own effects record, which is
// keccak of the DECLARED name — ``sweepTo(IERC20,address,uint256)`` →
// 0x38541c00 — while the caller records the ABI selector of the same function,
// ``sweepTo(address,address,uint256)`` → 0x0aeef8c8. Any callee taking an
// interface- or contract-typed parameter is therefore unreachable across the
// join. This row is pinned EMPTY on purpose: it is the shape that must gain a
// claim when that canonicalisation is fixed, and until then it is the corpus's
// record that the gap is real rather than hypothetical.
//
// The callee selectors are deliberately NOT standard ones. A call to
// ``mint(address,uint256)`` or ``transfer(address,uint256)`` is recognised by
// the caller's OWN static pass, which mints the claim at standard_exact, and
// precedence then discards the policy-tier claim — leaving no policy row and a
// fixture that proves nothing. The tier is only observable where the sibling's
// evidence is the ONLY evidence.

interface IVault {
    function deposit(uint256 amount) external;
}

interface IRecovery {
    function sweepTo(address token, address to, uint256 amount) external;
}

contract PolicyCaller {
    address public owner;
    address public vault;
    address public recovery;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setVault(address newVault) external onlyOwner {
        vault = newVault;
    }

    function setRecovery(address newRecovery) external onlyOwner {
        recovery = newRecovery;
    }

    // Body call, resolvable, derives flow.in at policy_derived. Guard-origin
    // calls are excluded from the derivation, so this must be a body call.
    function depositTo(uint256 amount) external onlyOwner {
        IVault(vault).deposit(amount);
    }

    // Body call, resolvable, derives nothing — see the header.
    function recoverVia(address token, address to, uint256 amount) external onlyOwner {
        IRecovery(recovery).sweepTo(token, to, amount);
    }
}
