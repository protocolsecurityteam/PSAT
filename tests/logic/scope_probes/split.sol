pragma solidity 0.8.27;
contract Probe {
    mapping(address => uint256) balances;      // 0
    mapping(address => bool) allowed;          // 1
    uint256 moved; uint256 supply;
    mapping(bytes32 => mapping(address => bool)) roles; // 4
    uint256 locked = 1;                        // 5
    address owner;
    event Allowed(address indexed who, bool ok);
    function allow(address who, bool ok) external { require(msg.sender == owner); allowed[who] = ok; emit Allowed(who, ok); }
    struct Op { address manager; address reward; bool active; }
    mapping(uint256 => Op) ops;
    mapping(uint256 => address) tokenOwner;
    mapping(uint256 => bool) frozenToken;
    event Minted(uint256 indexed id, address who);
    function deactivate(uint256 id) external { require(msg.sender == owner); ops[id].active = false; }
    function reactivate(uint256 id) external { require(ops[id].manager == msg.sender); ops[id].active = true; }
    function changeReward(uint256 id, address r) external { require(ops[id].active && ops[id].manager == msg.sender); ops[id].reward = r; }
    function freeze(uint256 id) external { require(msg.sender == owner); frozenToken[id] = true; }
    function unfreezeToken(uint256 id) external { require(tokenOwner[id] == msg.sender); frozenToken[id] = false; }
    function move(uint256 id, address to) external { require(!frozenToken[id]); require(tokenOwner[id] == msg.sender); tokenOwner[id] = to; }
}
