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

library AddressLib {
    // The OpenZeppelin ``Address.functionDelegateCall`` shape.
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}

contract DelegatecallRoutes {
    address public owner;
    address public module;
    mapping(address => address) public userModule;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setModule(address newModule) external onlyOwner {
        module = newModule;
    }

    function setUserModule(address newModule) external {
        userModule[msg.sender] = newModule;
    }

    // DIRECT, storage-setter destination.
    function execModule(bytes calldata data) external onlyOwner {
        (bool ok, ) = module.delegatecall(data);
        require(ok, "module call failed");
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
}
