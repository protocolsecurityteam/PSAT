// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// A5: a bucket rate limiter in front of a value move, and the sibling that is
// byte-identical WITHOUT it.
//
// The corpus had no limiter at all, so nothing could pin the decision the audit
// actually made: a refilling bucket bounds throughput per window, not total
// loss, so it is recorded as a FACT at zero severity weight and the
// ``amount_kind`` lattice does not move. The two functions below differ in
// exactly one statement, which is what lets a test assert that the flow witness
// is identical across the difference — the assertion that pins the decision.
//
// Detection keys on the limiter's PUBLISHED selectors (consume(bytes32,uint64)
// / consumeToken(bytes32,uint64)), so ``decoyLimiter`` — a variable named like a
// limiter, whose callee takes a different signature — earns nothing. That is the
// negative control for name-based detection.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IRateLimiter {
    function consume(bytes32 id, uint64 amount) external;
    function consumeToken(bytes32 id, uint64 amount) external;
}

interface INotALimiter {
    // Same identifier, different published signature — a different selector.
    function consume(uint256 amount) external;
}

contract RateLimitedFlow {
    bytes32 public constant WITHDRAW_LIMIT_ID = keccak256("WITHDRAW");

    IRateLimiter public immutable limiter;
    INotALimiter public immutable decoyLimiter;
    IERC20 public immutable token;
    address public owner;

    constructor(IRateLimiter limiter_, INotALimiter decoy_, IERC20 token_) {
        limiter = limiter_;
        decoyLimiter = decoy_;
        token = token_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // Rate-limited. The limiter reverts on exhaustion, so the consume call is on
    // every path to the transfer.
    function withdrawLimited(address to, uint256 amount) external onlyOwner {
        limiter.consume(WITHDRAW_LIMIT_ID, uint64(amount));
        token.transfer(to, amount);
    }

    // The token-side entry, same shape.
    function withdrawTokenLimited(address to, uint256 amount) external onlyOwner {
        limiter.consumeToken(WITHDRAW_LIMIT_ID, uint64(amount));
        token.transfer(to, amount);
    }

    // THE CONTROL: identical body minus the limiter call. Its flow witness must
    // be byte-identical to withdrawLimited's — that equality is the published
    // form of "a rate limit does not change how much can leave".
    function withdrawUnlimited(address to, uint256 amount) external onlyOwner {
        token.transfer(to, amount);
    }

    // NEGATIVE CONTROL for name-based detection: a "limiter" whose consume takes
    // a different signature, so a different selector.
    function withdrawDecoy(address to, uint256 amount) external onlyOwner {
        decoyLimiter.consume(amount);
        token.transfer(to, amount);
    }
}
