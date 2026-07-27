// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Discriminating corpus for the exec.arbitrary parameter BINDING.
//
// Every function here puts more than one candidate of at least one type in the
// call op's read set, or puts the destination somewhere no parameter can reach.
// A matcher that picks an arbitrary member of the read set and one that reads
// the operand positions give DIFFERENT answers on all five — which is exactly
// what the previous corpus could not express: every exec.arbitrary fixture in it
// had a single address parameter, so the pick was forced and any implementation
// passed.

library AddressLib {
    // The OpenZeppelin shape: the forwarding op is a low-level call on the
    // library's own first parameter, so one level of indirection resolves it.
    function functionCallWithValue(address target, bytes memory data, uint256 value)
        internal
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    // OpenZeppelin's own two-step: this body forwards to a sibling instead of
    // calling, so one level of resolution never reaches a call op.
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }
}

library ReversedLib {
    // Same shape with the parameters swapped: the destination is argument ONE,
    // not argument zero. A resolver that assumes position 0 gets this wrong.
    function send(bytes memory data, address target) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call failed");
        return ret;
    }
}

library AsmLib {
    // The Solady shape: the forwarding op is inline assembly, which is the only
    // place the destination and the payload are legible at all.
    function callContract(address target, uint256 value, bytes memory data)
        internal
        returns (bytes memory result)
    {
        assembly {
            result := mload(0x40)
            if iszero(call(gas(), target, value, add(data, 0x20), mload(data), codesize(), 0x00)) {
                returndatacopy(result, 0x00, returndatasize())
                revert(result, returndatasize())
            }
            mstore(result, returndatasize())
            returndatacopy(add(result, 0x20), 0x00, returndatasize())
            mstore(0x40, add(add(result, 0x20), returndatasize()))
        }
    }
}

interface IComposer {
    function compose(address from, bytes calldata message, bytes calldata extra) external;
}

interface ISwapper {
    function swap(address fromAsset, address toAsset, bytes calldata data) external;
}

interface IExec {
    function exec(address who, bytes calldata payload) external;
}

contract ExecBinding {
    using AddressLib for address;

    address public swapper;
    address public fallbackRoute;

    // TWO address parameters and TWO bytes parameters, and the destination is
    // the SECOND address. The EndpointV2.lzCompose shape.
    function compose(address from, address to, bytes calldata message, bytes calldata extra) external {
        IComposer(to).compose(from, message, extra);
    }

    // No parameter is the destination at all — it is a state variable — while
    // two address parameters and a bytes parameter sit in the read set. The
    // LRTSquaredAdmin.rebalance shape.
    function rebalance(address fromAsset, address toAsset, bytes calldata data) external {
        ISwapper(swapper).swap(fromAsset, toAsset, data);
    }

    // Library-mediated and resolvable: the destination operand is the library,
    // the real target is an argument, and the library body says which one.
    function manageViaLibrary(address target, bytes calldata data, uint256 value) external {
        target.functionCallWithValue(data, value);
    }

    // Same, with the library's parameters reversed.
    function manageReversed(address target, bytes calldata data) external {
        ReversedLib.send(data, target);
    }

    // Assembly-mediated, resolvable through the call opcode's operand layout.
    function manageViaAssembly(address target, bytes calldata data) external {
        AsmLib.callContract(target, 0, data);
    }

    // Two levels of library indirection. One level of resolution does not reach
    // the call op, and the honest answer is that the binding is not determined —
    // NOT the only address parameter, which is what a read-set pick would say.
    function manageViaTwoStepLibrary(address target, bytes calldata data) external {
        target.functionCall(data);
    }

    // ---- destinations that reach the call through a name defined twice ------
    //
    // The IR is not in SSA form, so both assignments below share ONE variable
    // object. Which value the call sees is a control-flow question, and neither
    // published proof state may be used to answer it. The sibling
    // `singlyAssignedLocal` is what keeps the guard from being "always hedge".

    // The caller CAN choose the destination — on one path. Answering `state_var`
    // here asserts the caller cannot, which is the governing rule inverted.
    function branchedStateOrParam(address a, bytes calldata d, bool flag) external {
        address t = fallbackRoute;
        if (flag) t = a;
        IExec(t).exec(a, d);
    }

    // Two address parameters, one per branch: naming either is a coin flip
    // dressed as a proof.
    function branchedParams(address a, address b, bytes calldata d, bool flag) external {
        address t = a;
        if (flag) t = b;
        IExec(t).exec(a, d);
    }

    // Straight-line reassignment. The destination is `b`; a map holding the
    // FIRST defining IR per name answers `a`.
    function reassignedLocal(address a, address b, bytes calldata d) external {
        address t = a;
        t = b;
        IExec(t).exec(a, d);
    }

    // The write FOLLOWS the call, so the destination is the parameter's incoming
    // value — but the resolver has no flow sensitivity to know that, and reading
    // through the one assignment it can see names the wrong parameter.
    function paramWrittenAfterCall(address a, address b, bytes calldata d) external {
        IExec(a).exec(a, d);
        a = b;
    }

    // The storage write also FOLLOWS the call: this destination is whatever
    // storage already held, which no caller supplied. Solmate's
    // `Auth.setAuthority` — deployed inside BoringVault — is this shape, and the
    // pre-guard resolver named its parameter.
    function stateWrittenAfterCall(address a, bytes calldata d) external {
        IExec(fallbackRoute).exec(a, d);
        fallbackRoute = a;
    }

    // THE DISCRIMINATING SIBLING: one definition, so the local IS the parameter
    // and the name is published. Without this the change above is
    // indistinguishable from a resolver that always hedges.
    function singlyAssignedLocal(address a, bytes calldata d) external {
        address t = a;
        IExec(t).exec(a, d);
    }
}
