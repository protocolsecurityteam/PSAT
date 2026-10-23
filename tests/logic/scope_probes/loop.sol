pragma solidity 0.8.27;
contract Probe {
    mapping(address => uint256) balances;      // 0
    mapping(address => bool) allowed;          // 1
    uint256 moved; uint256 supply;
    mapping(bytes32 => mapping(address => bool)) roles; // 4
    uint256 locked = 1;                        // 5
    address owner;
    mapping(uint256 => address) tokenOwner;
    mapping(uint256 => address[]) delegatesOf;
    mapping(uint256 => address) approved;
    function addDelegate(uint256 id, address d) external { require(tokenOwner[id] == msg.sender); delegatesOf[id].push(d); }
    function setApproved(uint256 id, address d) external { require(tokenOwner[id] == msg.sender); approved[id] = d; }
    function moveLoop(uint256 id, address to) external {
        bool ok = tokenOwner[id] == msg.sender;
        address[] storage ds = delegatesOf[id];
        for (uint256 i; i < ds.length; i++) { if (ds[i] == msg.sender) ok = true; }
        require(ok);
        tokenOwner[id] = to;
    }
    function moveApproved(uint256 id, address to) external {
        bool ok = tokenOwner[id] == msg.sender;
        for (uint256 i; i < 3; i++) { if (approved[id] == msg.sender) ok = true; }
        require(ok);
        tokenOwner[id] = to;
    }
}
