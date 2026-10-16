// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// A transient state variable and raw ``tstore``/``tload`` address the same transient storage.

library TransientLib {
    function set(bytes32 slot) internal {
        assembly {
            tstore(slot, 1)
        }
    }
}

contract TransientAliasing {
    bool transient lock;
    address public owner;
    bool public open;
    uint256 public hook;

    function _rawFlag() internal view returns (bool r) {
        assembly {
            r := tload(0)
        }
    }

    function _setLock() internal {
        lock = true;
    }

    function namedWriteRawRead(uint256 v) external {
        lock = true;
        if (_rawFlag()) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function helperNamedWriteRawRead(uint256 v) external {
        _setLock();
        if (_rawFlag()) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function rawWriteNamedRead(uint256 v) external {
        assembly {
            tstore(0, 1)
        }
        if (lock) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function slotWriteNamedRead(uint256 v) external {
        assembly {
            tstore(lock.slot, 1)
        }
        if (lock) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function libWriteNamedRead(uint256 v) external {
        TransientLib.set(0);
        if (lock) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function rawWritePersistentRead(uint256 v) external {
        assembly {
            tstore(0, 1)
        }
        if (open) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }

    function namedWritePersistentRead(uint256 v) external {
        lock = true;
        if (open) return;
        require(msg.sender == owner, "UNAUTHORIZED");
        hook = v;
    }
}
