pragma solidity 0.8.27;
// N25 a check hidden behind recursion / call depth: the lowering is 'lost', not failed
contract Deep {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => bool) banned; mapping(address => uint256) credits;
    function _ok(address a, uint256 n) internal view returns (bool) { if (n > 0) return _ok(a, n - 1); return !banned[a]; }
    function act() external { require(_ok(msg.sender, 1)); credits[msg.sender] += 0; }
    function unban() external { require(allowed[msg.sender]); banned[msg.sender] = false; }
}
contract Deep2 {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => bool) banned2; mapping(address => uint256) credits;
    function d0(address a) internal view returns (bool) { return d1(a); }
    function d1(address a) internal view returns (bool) { return d2(a); }
    function d2(address a) internal view returns (bool) { return d3(a); }
    function d3(address a) internal view returns (bool) { return d4(a); }
    function d4(address a) internal view returns (bool) { return d5(a); }
    function d5(address a) internal view returns (bool) { return d6(a); }
    function d6(address a) internal view returns (bool) { return d7(a); }
    function d7(address a) internal view returns (bool) { return d8(a); }
    function d8(address a) internal view returns (bool) { return d9(a); }
    function d9(address a) internal view returns (bool) { return d10(a); }
    function d10(address a) internal view returns (bool) { return d11(a); }
    function d11(address a) internal view returns (bool) { return d12(a); }
    function d12(address a) internal view returns (bool) { return d13(a); }
    function d13(address a) internal view returns (bool) { return d14(a); }
    function d14(address a) internal view returns (bool) { return !banned2[a]; }
    function act() external { require(d0(msg.sender)); credits[msg.sender] += 0; }
    function unban() external { require(allowed[msg.sender]); banned2[msg.sender] = false; }
}
