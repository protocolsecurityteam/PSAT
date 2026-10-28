"""Independent chain counterexamples and complete-domain checks for the formula engine."""

from __future__ import annotations

import pytest
from eth_abi import encode
from eth_utils import keccak

from services.clients.logic_reads import ChainReads
from services.logic.formula import analyze_function, compile_function
from services.logic.model import Limits, ReadError
from services.logic.model import encode as encode_analysis
from services.logic.solver import Translation, project
from services.logic.terms import CALLER, const, mk, mk_cmp
from services.resolution.logic_composition import sequence
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0, rpc

OWNER = int(ACCOUNT0, 16)
OTHER = 0x70997970C51812DC3A010C7D01B50E0D17DC79C8
STRANGER = 0x3C44CDDDB6A900FA2B585DD299E03D12FA4293BC

SOURCE = """
pragma solidity 0.8.27;
contract Guard {
    address public admin;
    constructor(address a) { admin = a; }
    function allowed(address who) external view returns(bool) { return who == admin; }
    function originOnly() external view returns(bool) { return tx.origin == admin; }
}
contract C {
    address public owner;
    bool public paused = true;
    uint public x;
    mapping(uint => address) public managers;
    mapping(address => bool) public banned;
    mapping(address => bool) public registered;
    Guard public guard;
    constructor(address other, Guard g) {
        owner = msg.sender; managers[0] = msg.sender; managers[1] = other; banned[other] = true; guard = g;
    }
    function selected(uint id) external { require(managers[id] == msg.sender); require(id == 0); x = 1; }
    function notBanned() external { require(!banned[msg.sender]); x = 1; }
    function register() external { registered[msg.sender] = true; }
    function erase() external { registered[msg.sender] = false; }
    function gated() external { require(registered[msg.sender]); x = 1; }
    function unpause() external { paused = false; }
    function destroyOwnerAndUnpause() external { paused = false; owner = address(0); }
    function withdraw() external { require(msg.sender == owner && msg.sender != address(0)); require(!paused); x = 1; }
    function early() external { if(msg.sender != owner) return; x = 1; }
    function delegated() external { require(guard.allowed(msg.sender)); x = 1; }
    function byOrigin() external { require(guard.originOnly()); x = 1; }
    function parity() external { require(uint160(msg.sender) % 2 == 0); x = 1; }
    function correlate(uint a) external { require(msg.sender == owner && a == 0); require(a > 0); x = 1; }
    function funded() external payable { require(msg.value > 0); require(address(this).balance >= msg.value); x = 1; }
}
"""


def slot(key: int, base: int) -> int:
    return int.from_bytes(keccak(encode(["uint256", "uint256"], [key, base])), "big")


class FixtureReads(ChainReads):
    """The fixture's complete known write domain, read from Anvil (not an engine-derived domain)."""

    def __init__(self, deployment):
        self.d = deployment
        super().__init__(lambda m, p: rpc(deployment.url, m, p), int(rpc(deployment.url, "eth_blockNumber", []), 16))

    def storage_dump(self, address):
        slots = set(range(6)) if address == self.d.at["C"] else {0}
        if address == self.d.at["C"]:
            slots |= {slot(0, 2), slot(1, 2), slot(OTHER, 3)}
        return {s: v for s in slots if (v := self.storage(address, s))}

    def key_words(self, address):
        return {OWNER, OTHER, 0, 1}


@pytest.fixture(scope="module")
def deployed(anvil):
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    guard = d.deploy("Guard", ("address",), (OWNER,))
    d.deploy("C", ("address", "address"), (OTHER, guard))
    return d


def fn(d, name):
    return next(f for f in d.slither["C"].functions if f.name == name)


def formula(d, name):
    return compile_function(d.slither["C"], fn(d, name), d.at["C"], FixtureReads(d), d.contracts("C", "Guard"))


def analyze(d, name, limits=Limits()):
    return analyze_function(d.slither["C"], fn(d, name), d.at["C"], FixtureReads(d), d.contracts("C", "Guard"), limits)


def passes(d, name, sender, args=()):
    function = fn(d, name)
    data = keccak(text=function.solidity_signature)[:4] + encode([str(p.type) for p in function.parameters], args)
    try:
        rpc(
            d.url,
            "eth_call",
            [{"to": f"0x{d.at['C']:040x}", "from": f"0x{sender:040x}", "data": "0x" + data.hex()}, "latest"],
        )
        return True
    except RuntimeError as exc:
        assert "revert" in str(exc).lower(), exc
        return False


def test_shared_argument_constraints_filter_mapping_values(deployed):
    row = analyze(deployed, "selected")
    assert row.callers.representation == "finite", row
    assert row.callers.members == (OWNER,)
    assert passes(deployed, "selected", OWNER, (0,))
    assert not passes(deployed, "selected", OTHER, (0,))
    assert not passes(deployed, "selected", OTHER, (1,))


def test_blocklist_is_a_complement_not_occupied_keys(deployed):
    row = analyze(deployed, "notBanned", Limits(members=2))
    assert row.callers.representation == "cofinite", row
    assert row.callers.excluded == (OTHER,)
    assert passes(deployed, "notBanned", STRANGER)
    assert not passes(deployed, "notBanned", OTHER)


def test_success_and_effect_authority_are_separate(deployed):
    row = analyze(deployed, "early")
    assert row.callers.representation == "cofinite" and not row.callers.excluded
    assert row.effects and all(e.members == (OWNER,) and e.complete for e in row.effects)
    assert passes(deployed, "early", STRANGER)


def test_related_conditions_never_get_independent_witnesses(deployed):
    row = analyze(deployed, "correlate")
    assert row.callers.representation == "finite" and row.callers.members == ()
    assert not passes(deployed, "correlate", OWNER, (0,))
    assert not passes(deployed, "correlate", OWNER, (1,))


def test_delegated_gate_is_followed_without_stranger_calls(deployed):
    row = analyze(deployed, "delegated")
    assert row.callers.complete and row.callers.members == (OWNER,), row
    assert passes(deployed, "delegated", OWNER)
    assert not passes(deployed, "delegated", STRANGER)


def test_origin_is_a_distinct_dependency(deployed):
    row = analyze(deployed, "byOrigin")
    from services.logic.terms import subterms

    assert subterms(row.formula.success, "origin")
    assert passes(deployed, "byOrigin", OWNER)
    assert not passes(deployed, "byOrigin", STRANGER)
    # Projection is conditional on an origin, not a claim that every actor controls that origin.
    assert row.callers.representation == "cofinite"


def test_arithmetic_address_set_stays_symbolic_without_sampling(deployed):
    row = analyze(deployed, "parity", Limits(members=2))
    assert row.callers.representation == "symbolic"
    assert all(a % 2 == 0 for a in row.callers.members)
    assert not row.callers.complete


@pytest.mark.parametrize(
    ("first", "last", "expected"),
    [
        ("register", "gated", "all"),
        ("erase", "gated", "none"),
        ("unpause", "withdraw", "owner"),
        ("destroyOwnerAndUnpause", "withdraw", "none"),
    ],
)
def test_composition_uses_values_and_all_updates(deployed, first, last, expected):
    combined = sequence((formula(deployed, first), formula(deployed, last)))
    result = project(combined, Translation(FixtureReads(deployed), deployed.contracts("C", "Guard"), deployed.at["C"]))
    if expected == "all":
        assert result.representation == "cofinite" and not result.excluded, result
    else:
        assert result.representation == "finite" and result.members == ((OWNER,) if expected == "owner" else ()), result


def test_budget_and_unknown_are_not_complete_empty_lists(deployed):
    row = analyze(deployed, "notBanned", Limits(storage_steps=0, members=1))
    assert not row.callers.complete and row.callers.issues


def test_failed_reads_abort_instead_of_publishing_an_answer(deployed):
    class Broken(FixtureReads):
        def storage(self, address, slot):
            raise ReadError("node unavailable")

    with pytest.raises(ReadError):
        analyze_function(
            deployed.slither["C"], fn(deployed, "early"), deployed.at["C"], Broken(deployed), deployed.contracts("C")
        )


def test_relation_is_serializable_without_losing_formula(deployed):
    import json

    row = analyze(deployed, "selected")
    out = encode_analysis(row)
    assert out["terms"] and out["schema"] == 2
    json.dumps(out)


def test_concrete_signature_recovery_keeps_zero_and_digest_semantics(deployed):
    from eth_keys import keys

    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    digest = keccak(b"original")
    sig = key.sign_msg_hash(digest)
    term = mk("signer", const(int.from_bytes(digest, "big")), const(sig.v + 27), const(sig.r), const(sig.s))
    translation = Translation(FixtureReads(deployed), {}, deployed.at["C"])
    from services.logic.solver import number

    assert number(translation.translate(term)) == int.from_bytes(key.public_key.to_canonical_address(), "big")
    zero = mk("signer", const(0), const(0), const(0), const(0))
    assert number(translation.translate(zero)) == 0
    wrong = mk("signer", const(int.from_bytes(keccak(b"wrong"), "big")), *term[2:])
    assert number(translation.translate(wrong)) != number(translation.translate(term))


def test_a_finite_list_requires_excluding_every_other_address(deployed):
    predicate = mk_cmp("eq", CALLER, const(OWNER, "address"))
    result = project(predicate, Translation(FixtureReads(deployed), {}, deployed.at["C"]), CALLER)
    assert result.complete and result.members == (OWNER,)


def test_a_call_reads_its_balance_after_receiving_value(deployed):
    from services.logic.terms import ORIGIN
    from tests.logic import _oracle as oracle

    f = formula(deployed, "funded")
    bindings = {CALLER: OWNER, ORIGIN: OWNER, mk("callvalue"): 1}
    answer = Translation(FixtureReads(deployed), deployed.contracts("C"), deployed.at["C"], bindings=bindings)
    assert oracle.passes(deployed, "C", fn(deployed, "funded"), {}, OWNER, value=1)
    assert answer.truth(f.success) is True
