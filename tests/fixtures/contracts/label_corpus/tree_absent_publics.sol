// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// G3 classes F and R: externally-callable functions that carry a real caller
// gate and end up with NO predicate tree, which every consumer reads as a
// positive assertion of "unguarded".
//
// The corpus had neither class. It could not have had them: nothing in the
// golden recorded whether a function has a tree, so a fixture of this shape
// would have been byte-identical to a genuinely permissionless function. The
// ``predicate_tree`` pin is what makes these four rows discriminate.

contract TreeAbsentPublics {
    address public owner;
    address public operator;
    uint256 public lastAmount;
    uint256 public pokes;

    modifier onlyOperator() {
        require(msg.sender == operator, "not operator");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // CLASS F. The forwarder's own body has no gate; the gate is on the overload
    // it calls, and the internal call's result is CONSUMED by the ``return``.
    // The gate recursion is skipped when the result is read, on the premise that
    // "the result feeds a condition" — here it feeds a return value, and the
    // caller restriction is lost. Callable in fact only by the operator.
    function withdrawAll() external returns (uint256) {
        return withdrawTo(address(this).balance);
    }

    function withdrawTo(uint256 amount) public onlyOperator returns (uint256) {
        lastAmount = amount;
        return amount;
    }

    // THE DISCRIMINATING SIBLING for class F: same forwarding, same gated
    // callee, result NOT consumed. This one does acquire the gate, so a fix that
    // simply stops skipping recursion must leave this row unchanged while
    // ``withdrawAll`` moves. Without it, "class F is fixed" and "recursion was
    // disabled everywhere" look the same.
    function pokeAll() external {
        pokeTo(1);
    }

    function pokeTo(uint256 amount) public onlyOperator {
        pokes += amount;
    }

    // CLASS R. ``receive`` and ``fallback`` can never carry a tree — they are
    // excluded from the externally-callable set twice over — yet both are
    // caller-gated here, and a caller-gated function published as unguarded is
    // the same error as class F reached by a different route.
    receive() external payable {
        require(msg.sender == owner, "not owner");
    }

    fallback() external payable {
        require(msg.sender == owner, "not owner");
        pokes += 1;
    }
}
