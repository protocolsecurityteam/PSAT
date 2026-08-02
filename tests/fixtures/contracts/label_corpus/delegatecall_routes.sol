// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// The three ways a delegatecall destination reaches the sink, which the corpus
// could not previously tell apart because it contained ZERO
// ``delegatecall_execution`` functions of any kind.
//
//   * DIRECT, storage-setter destination — the destination is a state variable
//     with a setter, so whoever passes that setter's gate owns this contract's
//     entire storage.
//   * DIRECT, caller-keyed mapping element — the destination is
//     ``mapping[msg.sender]``. Nothing static can name the address, and the
//     honest answer is not-determined, NOT the mapping's name.
//   * LIBRARY-ROUTED — the same storage variable reaches the same opcode
//     through a library parameter, so the recorded sink target is the LIBRARY's
//     parameter name, a symbol that does not exist in this contract. Both
//     pre-existing A8 rows in production are direct/assembly routes, so this
//     distinction had no corpus representation at all.
//   * SELF — a literal ``address(this)``, the OZ v5 ``Multicall`` shape and the
//     whole of the production population of unresolved destinations. The
//     destination is a compile-time value no writer and no caller can point
//     elsewhere, so the honest answer is the PROVEN ``self`` with a
//     proven-constrained verdict, not the ``indeterminate`` a catch-all gives
//     it. Carried on both routes: through the library formal (where only the
//     binding substitution can see it) and directly.
//   * ASSEMBLY SPLIT-PROXY — the LRTSquaredCore.fallback shape, added with the
//     A8 matcher. The destination is not a variable at all: the fallback reads
//     a constant slot with ``sload`` and delegatecalls whatever it holds, and
//     the recorded sink target is a temporary. Whoever passes the setter's gate
//     owns this contract's entire storage, so the honest classification is
//     ``storage_setter`` and it is reachable only by folding the slot expression
//     back to the constant and finding the ``sstore`` on the same slot. The
//     unwritable sibling (``fixedSlotFallbackTarget``, never sstored) is the
//     control that keeps that join from being "any assembly slot is settable".

library AddressLib {
    // The OpenZeppelin ``Address.functionDelegateCall`` shape.
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}

contract DelegatecallRoutes {
    // Constant slots, the split-proxy idiom. Not EIP-1967's, on purpose: this
    // is the NON-standard shape, which is why it earns delegatecall.execute
    // rather than upgrade.implementation.
    bytes32 internal constant ADMIN_IMPL_SLOT = keccak256("corpus.admin.impl");
    bytes32 internal constant FIXED_IMPL_SLOT = keccak256("corpus.fixed.impl");

    address public owner;
    address public module;
    address public sideModule;
    mapping(address => address) public userModule;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setModule(address newModule) external onlyOwner {
        module = newModule;
    }

    // UNGATED on purpose: the two-site fold below is honest only if this
    // writer is visible in the union.
    function setSideModule(address newModule) external {
        sideModule = newModule;
    }

    function setUserModule(address newModule) external {
        userModule[msg.sender] = newModule;
    }

    // DIRECT, storage-setter destination.
    function execModule(bytes calldata data) external onlyOwner {
        (bool ok, ) = module.delegatecall(data);
        require(ok, "module call failed");
    }

    // TWO sites, ONE kind. Both destinations are storage-held with a setter,
    // but the setters are gated differently — the owner-gated ``setModule`` and
    // the UNGATED ``setSideModule``. The folded destination must publish BOTH
    // variables and the UNION of the writers: one site's answer presents a
    // complete, gated writer set while the ungated writer stays invisible,
    // which is the severity question answered wrongly.
    function execBothModules(bytes calldata data) external onlyOwner {
        (bool a, ) = module.delegatecall(data);
        require(a, "module call failed");
        (bool b, ) = sideModule.delegatecall(data);
        require(b, "side module call failed");
    }

    // DIRECT, caller-keyed mapping element. Must resolve not-determined.
    function execUserModule(bytes calldata data) external {
        (bool ok, ) = userModule[msg.sender].delegatecall(data);
        require(ok, "user module call failed");
    }

    // LIBRARY-ROUTED. Same real destination as ``execModule``, different
    // recorded sink target.
    function execModuleViaLibrary(bytes calldata data) external onlyOwner {
        AddressLib.functionDelegateCall(module, data);
    }

    // ASSEMBLY SPLIT-PROXY. Unauthenticated entry, destination held in a
    // constant slot, settable by the owner.
    fallback() external {
        bytes32 slot = ADMIN_IMPL_SLOT;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(slot), 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function setAdminImpl(address newImpl) external onlyOwner {
        bytes32 slot = ADMIN_IMPL_SLOT;
        assembly {
            sstore(slot, newImpl)
        }
    }

    // CONTROL for the slot join: read the same way, written by nobody.
    function execFixedSlot(bytes calldata data) external onlyOwner {
        bytes32 slot = FIXED_IMPL_SLOT;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), sload(slot), 0, calldatasize(), 0, 0)
            if iszero(result) { revert(0, 0) }
        }
    }

    // SELF, LIBRARY-ROUTED. The OZ v5 ``Multicall`` shape: the destination is a
    // compile-time ``address(this)`` that reaches the opcode as the LIBRARY's
    // formal, so only the binding substitution can see what it is. Declared
    // last, with its direct sibling, so the assembly rows above keep the IR
    // temporary numbering their recorded sink targets carry.
    function execSelfViaLibrary(bytes calldata data) external {
        AddressLib.functionDelegateCall(address(this), data);
    }

    // SELF, DIRECT. The same destination without the library, so the answer is
    // pinned independently of the binding walk.
    function execSelf(bytes calldata data) external {
        (bool ok, ) = address(this).delegatecall(data);
        require(ok, "self call failed");
    }
}
