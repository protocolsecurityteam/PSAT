pragma solidity 0.8.27;
// N1 constant first key: a global config slot held by "owner[0]"
contract ConstKey {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(uint256 => address) owner;
    mapping(uint256 => uint256) fee;
    constructor() { owner[0] = msg.sender; }
    function setFee(uint256 v) external { require(msg.sender == owner[0]); fee[0] = v; }
    function clearFee() external { require(msg.sender == owner[0]); fee[0] = 0; }
    function pay(address to, uint256 a) external { balances[msg.sender] -= a; balances[to] += a - fee[0]; balances[owner[0]] += fee[0]; }
}
// N2 keeper appointed by an admin, not by the vault holder
contract Keeper {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    address admin;
    mapping(address => address) keeper;
    mapping(address => uint256) vault;
    function setKeeper(address v, address k) external { require(msg.sender == admin); keeper[v] = k; }
    function sweep(address v) external { require(keeper[v] == msg.sender); vault[v] = 0; }
    function retarget(address v, address r) external { require(keeper[v] == msg.sender); payoutTo[v] = r; }
    mapping(address => address) payoutTo;
}
// N3 a reporter's own entry that everyone's settlement consumes (value flow, not a check)
contract Oracle {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    address admin; address constant FEED = address(0xFEED);
    mapping(address => uint256) price;
    function addReporter(address r) external { require(msg.sender == admin); allowed[r] = true; }
    function retract() external { require(allowed[msg.sender]); price[msg.sender] = 0; }
    function settle(address u) external { balances[u] = balances[u] * price[FEED] / 1e18; }
}
// N4 debit moved into the protocol's own entry / a treasury
contract Treasury {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    address treasury;
    function toThis(uint256 a) external { require(allowed[msg.sender]); balances[msg.sender] -= a; balances[address(this)] += a; }
    function toTreasury(uint256 a) external { require(allowed[msg.sender]); balances[msg.sender] -= a; balances[treasury] += a; }
}
// N5 self-transfer that also stamps a time; credit keyed by the caller too
contract Stamp {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) last;
    function selfMove(uint256 a) external { require(allowed[msg.sender]); balances[msg.sender] -= a; balances[msg.sender] += a; last[msg.sender] = block.timestamp; }
    function selfMoveOnly(uint256 a) external { require(allowed[msg.sender]); balances[msg.sender] -= a; balances[msg.sender] += a; }
}
