// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Synthetic asset-recovery contract in the shape the corpus was blind to: it
// moves tokens through a TOKEN-FIRST safe-transfer library (`SafeTransferLib`
// / OZ `SafeERC20`) called in its OWN body, never across a contract boundary.
// The value move is invisible to the ERC-20 selector scan — the library's own
// canonical signature hashes to a selector that is not `transfer`'s, and its
// body issues the real selector from assembly — so a producer that only
// recognizes the idiom on a crossed frame publishes NO flow fact at all for
// every function here. That silence was the gap, and this fixture is what makes
// a change to it visible in the golden.
//
// Shapes pinned, one per function:
//
//  * sweep / sweepTo — token-first `safeTransfer` in the contract's own body,
//    with an immutable and a caller-supplied destination respectively (the
//    caller-redirect discriminator, on the same library call).
//  * pull — token-first `safeTransferFrom` INTO this contract.
//  * recoverERC721 — ERC-721 `safeTransferFrom(address,address,uint256)`, whose
//    trailing uint256 is a token IDENTITY, not a quantity. A consumer that
//    plants a probe amount in that slot is filling in a token id.
//  * splitPay — two sends with separately-resolved destinations, so the
//    cross-site fold has to say something about a disagreement in which every
//    member is itself resolved.
//  * payGateway / payGatewayDirect — a pull in which NEITHER party is this
//    contract (the caller pays a bridge endpoint directly), through the library
//    and through the plain ERC-20 selector. The two code paths classify
//    independently and both used to read the `from` argument alone, so both
//    published "value entered this contract" about a contract the funds never
//    touched.
//  * approveGateway — an APPROVAL, routed through the OZ `Address` helper chain
//    the real `SafeERC20` uses. It bottoms out in `target.call{value: value}`
//    with `value` bound to a literal `0` one frame up, so a scan that reads the
//    call shape without resolving the binding sees "sends ETH" on a function
//    that moves nothing. Only the interprocedural walk can tell.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// OZ's `Address`, reduced to the two frames that matter: the value a call sends
// is a parameter, and the literal that makes it zero is at the CALLER.
library Address {
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }

    function functionCallWithValue(address target, bytes memory data, uint256 value)
        internal
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "CALL_FAILED");
        return ret;
    }
}

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

// Token-first wrappers, deliberately built the way the real libraries are: the
// ERC-20 selector is materialized inside the helper (never at the call site),
// so nothing at the call site names the value move.
library SafeTransferLib {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "TRANSFER_FAILED");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "TRANSFER_FROM_FAILED");
    }
}

contract AssetRecovery {
    using SafeTransferLib for IERC20;

    address public owner;
    address public immutable treasury;
    address public immutable gateway;
    address public feeRecipient;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address treasury_, address gateway_) {
        owner = msg.sender;
        treasury = treasury_;
        gateway = gateway_;
    }

    function setFeeRecipient(address recipient) external onlyOwner {
        feeRecipient = recipient;
    }

    // Destination is an immutable; amount is the contract's whole balance.
    function sweep(IERC20 token) external onlyOwner {
        SafeTransferLib.safeTransfer(token, treasury, token.balanceOf(address(this)));
    }

    // Same library call, caller-chosen destination and caller-chosen amount.
    function sweepTo(IERC20 token, address to, uint256 amount) external onlyOwner {
        token.safeTransfer(to, amount);
    }

    // Token-first pull INTO this contract.
    function pull(IERC20 token, address from, uint256 amount) external onlyOwner {
        token.safeTransferFrom(from, address(this), amount);
    }

    // An approval, not a payment: the only ETH-bearing call it reaches carries a
    // provably-zero value.
    function approveGateway(IERC20 token, uint256 amount) external {
        Address.functionCall(address(token), abi.encodeWithSelector(IERC20.approve.selector, gateway, amount));
    }

    // The caller pays the gateway. This contract is neither the source nor the
    // sink; it only causes the move.
    function payGateway(IERC20 token, uint256 fee) external {
        token.safeTransferFrom(msg.sender, gateway, fee);
    }

    // The same shape reaching the other classifier: a plain ERC-20 pull selector
    // at the call site instead of the token-first library.
    function payGatewayDirect(IERC20 token, address payer, uint256 fee) external {
        token.transferFrom(payer, gateway, fee);
    }

    // The trailing uint256 is a token id, not a quantity.
    function recoverERC721(IERC721 collection, address to, uint256 tokenId) external onlyOwner {
        collection.safeTransferFrom(address(this), to, tokenId);
    }

    // Two sends on one function: one to a caller parameter, one to a mutable
    // storage destination. Both are resolved; they simply disagree.
    function splitPay(IERC20 token, address to, uint256 amount, uint256 fee) external onlyOwner {
        token.safeTransfer(to, amount);
        token.safeTransfer(feeRecipient, fee);
    }
}
