"""Every "open now" with nothing to hold first is confirmed on the chain (``decide._confirmed_open``), with no
exemption: one resting on an action the caller is assumed to arrange (a call not handed the caller, a callee's
refusal only on entries the caller brings about), on the stranger's own entries arranged first, or on ether sent.
Every stranger's own call must go through as the chain stands, sending the witness's ether (its balance set to it
by a state override); an open on the stranger's own entries needs a call of its own that brings them about, run as
each stranger, then this call on the words that call leaves (state overrides), and is reported with that call
(``after``); an open on a callee's entries runs the calls that bring them about there as each stranger, then this
call with those entries set. Otherwise it is not determined: ``open_assumed_action_unconfirmed``,
``open_arranged_unconfirmed``, ``open_value_unconfirmed``, ``open_unconfirmed``. Each verdict is checked against
``eth_call`` on anvil (``_oracle.check``), the probes of review 7 (``q2_arranged``, ``q2c``, ``q5_declared``,
``q2d_value``) among them, beside controls that stay open."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

ARRANGED = """
pragma solidity 0.8.27;

contract Rev {}

// Lets through only the origins its admin allowed.
contract Registry {
    mapping(address => bool) public allowed;
    address admin;
    constructor(address a) { admin = a; }
    function allow(address w) external { require(msg.sender == admin); allowed[w] = true; }
    function enter() external { require(allowed[tx.origin]); }
}

contract Sink { uint256 n; function poke() external { n++; } }

// Lets through only the addresses its admin allowed: a view check handed the caller.
contract Allow {
    mapping(address => bool) public ok;
    address admin;
    constructor(address a) { admin = a; }
    function allow(address w) external { require(msg.sender == admin); ok[w] = true; }
    function check(address w) external view returns (bool) { return ok[w]; }
}

// Anyone registers itself; ``use`` refuses whoever hasn't.
contract Points {
    mapping(address => bool) public ok;
    uint256 n;
    function register() external { ok[msg.sender] = true; }
    function use(address who) external { require(ok[who]); n++; }
}

// Anyone stakes to level 1; only the admin promotes to 2, and ``use`` wants 2.
contract Levels {
    mapping(address => uint256) public level;
    address admin;
    uint256 n;
    constructor(address a) { admin = a; }
    function stake() external { level[msg.sender] = 1; }
    function promote(address w) external { require(msg.sender == admin); level[w] = 2; }
    function use(address who) external { require(level[who] >= 2); n++; }
}

contract C {
    Registry reg;
    Sink sink;
    Points points;
    Levels levels;
    Allow al;
    address rev;
    mapping(address => uint256) bal;
    mapping(address => uint256) bal2;
    mapping(address => uint256) b4;
    mapping(address => uint256) b2;
    mapping(address => uint256) b3;
    uint256 total;
    constructor(address r, address s, address p, address l, address v, address a) {
        reg = Registry(r);
        sink = Sink(s);
        points = Points(p);
        levels = Levels(l);
        rev = v;
        al = Allow(a);
    }
    function act(uint256 x) external { x; reg.enter(); total += 1; }
    function deposit(uint256 a) external { require(a > 0); reg.enter(); bal[msg.sender] += a; }
    function withdraw(uint256 a) external { require(a > 0 && bal[msg.sender] >= a); bal[msg.sender] -= a; }
    function selfCallPoke(uint256 x) external {
        x;
        address r = rev;
        assembly { let ok := call(gas(), r, 0, 0, 0, 0, 0) if iszero(ok) { revert(0, 0) } }
        sink.poke();
        total += 1;
    }
    function deposit2(uint256 a) external {
        require(a > 0);
        address r = rev;
        assembly { let ok := call(gas(), r, 0, 0, 0, 0, 0) if iszero(ok) { revert(0, 0) } }
        bal2[msg.sender] += a;
    }
    function withdraw2(uint256 a) external { require(a > 0 && bal2[msg.sender] >= a); bal2[msg.sender] -= a; }
    function selfCall(uint256 x) external {
        x;
        address r = rev;
        assembly { let ok := call(gas(), r, 0, 0, 0, 0, 0) if iszero(ok) { revert(0, 0) } }
        total += 1;
    }
    function out1() external { uint256 b = bal[msg.sender]; require(b > 0); bal[msg.sender] = 0; total += b; }
    // A deposit only the contract's own Yul call into always-reverting code lets through: nobody makes it.
    function dep2(uint256 a) external {
        require(a > 0);
        address r = rev;
        assembly { let ok := call(gas(), r, 0, 0, 0, 0, 0) if iszero(ok) { revert(0, 0) } }
        b2[msg.sender] += a;
    }
    function out2() external { uint256 b = b2[msg.sender]; require(b > 0); b2[msg.sender] = 0; total += b; }
    // A deposit only the allowed make, and checks the allowed alone pass: never open.
    function dep3(uint256 a) external { require(a > 0 && al.check(msg.sender)); b3[msg.sender] += a; }
    function out3(uint256 a) external { require(a > 0 && b3[msg.sender] >= a); b3[msg.sender] -= a; }
    function actView(uint256 x) external { x; require(al.check(msg.sender)); total += 1; }
    function actViewPoke(uint256 x) external { x; require(al.check(msg.sender)); sink.poke(); total += 1; }
    function actViewTotal(uint256 x) external { x; require(al.check(msg.sender) && total < 1000); total += 1; }
    // Controls: a deposit anyone makes, a plain action, a callee's entry anyone brings about.
    function dep4(uint256 a) external { require(a > 0); b4[msg.sender] += a; }
    function out4() external { uint256 b = b4[msg.sender]; require(b > 0); b4[msg.sender] = 0; total += b; }
    function bump() external { sink.poke(); total += 1; }
    function spend(uint256 x) external { x; points.use(msg.sender); total += 1; }
    // What a stranger brings about there (level 1) isn't what ``use`` wants: never open.
    function climb(uint256 x) external { x; levels.use(msg.sender); total += 1; }
}
"""

DECLARED = """
pragma solidity 0.8.27;

// Declares a bool and returns nothing: a caller decoding a bool reverts.
contract T {
    uint256 n;
    function pay(address to, uint256 a) external returns (bool) { to; n += a; assembly { return(0, 0) } }
    function ok(address to, uint256 a) external returns (bool) { to; n += a; return true; }
}
contract T2 {
    uint256 n;
    function pay(address to, uint256 a) external { to; n += a; }
}
interface IT { function pay(address to, uint256 a) external returns (bool); }
contract C {
    T t;
    IT t2;
    address owner;
    uint256 total;
    constructor(address a, address b) { t = T(a); t2 = IT(b); owner = msg.sender; }
    function f1(uint256 x) external { t.pay(msg.sender, x); total += 1; }
    function f2(uint256 x) external { t.pay(address(this), x); total += 1; }
    function f3(uint256 x) external {
        try t.pay(address(this), x) returns (bool) { total += 1; } catch { require(msg.sender == owner); total += 2; }
    }
    function f4(uint256 x) external {
        try t.pay(msg.sender, x) returns (bool) { total += 1; } catch { require(msg.sender == owner); total += 2; }
    }
    function g1(uint256 x) external { t2.pay(msg.sender, x); total += 1; }
    function g3(uint256 x) external {
        try t2.pay(address(this), x) returns (bool) { total += 1; } catch { require(msg.sender == owner); total += 2; }
    }
    function h3(uint256 x) external {
        try t.ok(address(this), x) returns (bool) { total += 1; } catch { require(msg.sender == owner); total += 2; }
    }
}
"""

VALUE = """
pragma solidity 0.8.27;

contract Rev {}
contract C {
    address rev;
    uint256 total;
    constructor(address v) { rev = v; }
    function payIn() external payable {
        require(msg.value > 0);
        address r = rev;
        assembly { let ok := call(gas(), r, 0, 0, 0, 0, 0) if iszero(ok) { revert(0, 0) } }
        total += msg.value;
    }
    function payInFree() external payable {
        address r = rev;
        assembly { let ok := call(gas(), r, 0, 0, 0, 0, 0) if iszero(ok) { revert(0, 0) } }
        total += 1;
    }
    function donate() external payable { require(msg.value > 0); total += msg.value; }
}
"""

ADMIN, MEMBER = O.ACCOUNTS[1], O.ACCOUNTS[2]


def _arranged(d):
    d.deploy("Rev")
    d.deploy("Registry", ("address",), (ADMIN,))
    d.deploy("Sink")
    d.deploy("Points")
    d.deploy("Levels", ("address",), (ADMIN,))
    d.deploy("Allow", ("address",), (ADMIN,))
    at = d.at
    d.deploy("C", ("address",) * 6, (at["Registry"], at["Sink"], at["Points"], at["Levels"], at["Rev"], at["Allow"]))
    assert O.transact(d, "Registry", "allow(address)", ("address",), (MEMBER,), sender=ADMIN)
    assert O.transact(d, "Allow", "allow(address)", ("address",), (MEMBER,), sender=ADMIN)


def _declared(d):
    d.deploy("T")
    d.deploy("T2")
    d.deploy("C", ("address", "address"), (d.at["T"], d.at["T2"]))


def _value(d):
    d.deploy("Rev")
    d.deploy("C", ("address",), (d.at["Rev"],))


# (function, followed contracts, the gap expected); ``None`` where it stays open, ``ANY`` where it is not open and
# the gaps it names are another module's to pin (an action handed the caller, its callee's code only proposing).
ANY = "any"
ARRANGED_CASES = [
    ("act", (), "open_assumed_action_unconfirmed"),
    ("act", ("Registry",), "open_assumed_action_unconfirmed"),
    ("withdraw", (), "open_arranged_unconfirmed"),
    ("withdraw", ("Registry",), "open_arranged_unconfirmed"),
    ("selfCall", (), "open_unconfirmed"),
    ("selfCallPoke", (), "open_assumed_action_unconfirmed"),
    ("selfCallPoke", ("Sink",), "open_assumed_action_unconfirmed"),
    ("withdraw2", (), "open_arranged_unconfirmed"),
    ("out1", (), "open_arranged_unconfirmed"),
    ("out1", ("Registry",), "open_arranged_unconfirmed"),
    ("out2", (), "open_arranged_unconfirmed"),
    ("out4", (), None),
    ("bump", ("Sink",), None),
    ("bump", (), None),
    ("spend", ("Points",), None),
    ("climb", ("Levels",), "open_assumed_action_unconfirmed"),
]
DECLARED_CASES = [
    ("f1", ("T",), ANY),
    ("f4", ("T",), ANY),
    ("g1", ("T2",), ANY),
    ("f2", ("T",), "open_assumed_action_unconfirmed"),
    ("f3", ("T",), "open_assumed_action_unconfirmed"),
    ("f3", (), "open_assumed_action_unconfirmed"),
    ("g3", ("T2",), "open_assumed_action_unconfirmed"),
    ("h3", ("T",), None),
]
# Review 7's ``q2_arranged`` gates on ``Allow``: restricted (never complete), followed or not, and with ``Allow``'s
# code misread as letting everyone through.
GATED = [("out3", ("Allow",)), ("out3", ()), ("actView", ("Allow",)), ("actViewPoke", ("Allow",))]
GATED += [("actViewTotal", ("Allow",))]
VALUE_CASES = [("payIn", (), "open_value_unconfirmed"), ("payInFree", (), "open_unconfirmed"), ("donate", (), None)]

PROBES = [
    O.Probe(
        ARRANGED, _arranged, tuple(("C", n, f) for n, f, _ in ARRANGED_CASES) + tuple(("C", n, f) for n, f in GATED)
    ),
    O.Probe(DECLARED, _declared, tuple(("C", n, f) for n, f, _ in DECLARED_CASES)),
    O.Probe(VALUE, _value, tuple(("C", n, f) for n, f, _ in VALUE_CASES)),
]


@pytest.fixture(scope="module")
def arranged(anvil):  # noqa: F811
    d = O.deployment(*anvil, ARRANGED)
    _arranged(d)
    return d


@pytest.fixture(scope="module")
def declared(anvil):  # noqa: F811
    d = O.deployment(*anvil, DECLARED)
    _declared(d)
    return d


@pytest.fixture(scope="module")
def value(anvil):  # noqa: F811
    d = O.deployment(*anvil, VALUE)
    _value(d)
    return d


def _register(d, who):
    assert O.transact(d, "Points", "register()", sender=who)


def _check(d, name, others, gap, **kw):
    v = O.verdict(d, "C", name, *others)
    if gap is None:
        O.check(d, "C", name, v, **kw)
        assert v.openness == "open" and v.allowed == "now", v
    else:
        params = {p.name for p in O.function(d, "C", name).parameters}
        O.check(d, "C", name, v, open_at=False, samples=({k: 1 for k in params},))
        assert v.openness == "not_determined" and v.gaps, v
        assert gap == ANY or v.gaps == (gap,), v
    return v


@pytest.mark.parametrize(("name", "others", "gap"), ARRANGED_CASES)
def test_an_arranged_or_assumed_open_stands_only_on_the_chain(arranged, name, others, gap):
    kw = {"arrange": _register} if name == "spend" else {}
    v = _check(arranged, name, others, gap, **kw)
    if name == "out4":
        # The deposit each stranger makes first, run on the chain before the withdrawal: reported with it.
        assert [s for s, _ in v.after] == ["dep4(uint256)"], v


@pytest.mark.parametrize(("name", "others", "gap"), DECLARED_CASES)
def test_a_return_size_mismatch_behind_an_assumed_action_is_never_open(declared, name, others, gap):
    _check(declared, name, others, gap)


@pytest.mark.parametrize(("name", "others", "gap"), VALUE_CASES)
def test_an_open_sending_ether_stands_only_on_the_chain(value, name, others, gap):
    v = _check(value, name, others, gap)
    if gap is None:
        assert v.witnesses[O.FRESH].get("msg.value"), v


def _forget(d):
    # What the lowering remembers per contract, so a misread lowering neither reads nor leaves a clean one's.
    for contract in d.slither.values():
        for key in [k for k in contract.__dict__ if k.startswith("_psat_")]:
            del contract.__dict__[key]


@pytest.mark.parametrize("misread", [False, True], ids=["clean", "callee_everyone"])
@pytest.mark.parametrize(("name", "others"), GATED)
def test_a_gate_only_the_allowed_pass_is_never_open(arranged, monkeypatch, name, others, misread):
    if misread:
        from services.logic.lower import Lowerer
        from services.logic.terms import TRUE

        called = Lowerer.called

        def everyone(self, fn, args, view):
            if getattr(getattr(fn, "contract", None), "name", "C") != "C":
                return TRUE, (TRUE,)
            return called(self, fn, args, view)

        monkeypatch.setattr(Lowerer, "called", everyone)
        _forget(arranged)
    try:
        v = O.verdict(arranged, "C", name, *others)
    finally:
        if misread:
            _forget(arranged)
    params = {p.name: 1 for p in O.function(arranged, "C", name).parameters}
    O.check(arranged, "C", name, v, open_at=False, samples=(params,), known=(MEMBER,))
    assert v.openness == "restricted" and not v.complete, v
