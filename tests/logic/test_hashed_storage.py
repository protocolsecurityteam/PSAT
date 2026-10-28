"""Two-address code-derived keys recovered from hash preimages, with no event/name matching."""

from eth_abi import encode
from eth_utils import keccak

from services.clients.logic_reads import ChainReads
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.logic._oracle import ACCOUNTS, OWNER, analyze_function, function, passes
from tests.support.anvil import rpc

SOURCE = """
pragma solidity 0.8.27;
contract C {
    mapping(bytes32 => bool) entries;
    address public target;
    uint public x;
    constructor(address who, address to) {
        entries[keccak256(abi.encode(who,to))] = true;
        target = to;
    }
    function act(address to) external {
        require(entries[keccak256(abi.encode(msg.sender,to))]);
        require(to == target);
        x = 1;
    }
}
"""


def test_hash_of_two_addresses_is_accounted_without_guessing_a_holder(anvil):
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    target = ACCOUNTS[1]
    d.deploy("C", ("address", "address"), (OWNER, target))
    inner = encode(["address", "address"], [f"0x{OWNER:040x}", f"0x{target:040x}"])
    key = int.from_bytes(keccak(inner), "big")
    outer = encode(["uint256", "uint256"], [key, 0])
    occupied = int.from_bytes(keccak(outer), "big")

    class Reads(ChainReads):
        def storage_dump(self, address):
            return {slot: self.storage(address, slot) for slot in (1, occupied)}

        def key_words(self, address):
            return set()  # there are no events in this fixture

        def preimages(self, address, slots):
            return {key: inner, occupied: outer}

    reads = Reads(lambda m, p: rpc(url, m, p), int(rpc(url, "eth_blockNumber", []), 16))
    fn = function(d, "C", "act")
    row = analyze_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C"))
    assert row.callers.complete and row.callers.members == (OWNER,), row.callers
    assert passes(d, "C", fn, [target], OWNER)
    assert not passes(d, "C", fn, [target], ACCOUNTS[2])
    assert not passes(d, "C", fn, [ACCOUNTS[2]], OWNER)
