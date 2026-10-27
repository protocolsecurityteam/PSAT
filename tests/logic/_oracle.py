"""The oracles the logic engine is checked against, on anvil.

* Semantics (``chain_says`` / ``engine_says``): a function's lowered success formula, evaluated by the decision's own
  evaluator at concrete arguments, against ``eth_call`` of the same call.
* Verdict (``check``): every holder a verdict lists passes ``eth_call`` from its own address (``tx.origin`` too) with
  its witness arguments; "open now" only when each of the five strangers (``decide._STRANGERS``) passes, and an
  open proved for every unconfigured address (not ``witnessed``) only when a further ``UNSEEN`` addresses, none of
  them the engine's, pass too; "open later"
  only where the probe says how a state comes about in which they all do; "restricted" only when no stranger passes
  at the arguments the probe's author knows matter; a list said to be complete leaves
  out no address the probe knows of that passes; "nobody" is refuted by nobody.
* The fail-safe sweep (``test_failsafe``) reruns each probe a test module registers (``PROBES``) under injected faults
  and compares with the clean run (``never_bolder``).

Multi-transaction arrangements run for real inside ``snapshot`` so each test leaves the chain as it found it.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from eth_abi.abi import encode
from eth_utils import keccak

import tests.logic._anvil as A
from services.logic.decide import _STRANGERS, FRESH, Chain, Evaluator, World
from services.logic.lower import Lowerer, parameter
from services.logic.terms import reset_terms
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.support.anvil import ACCOUNT0, rpc, send

STRANGERS = tuple(sorted(_STRANGERS))
OWNER = int(ACCOUNT0, 16)
# anvil's other funded accounts: senders the probes may use as holders.
ACCOUNTS = (
    OWNER,
    0x70997970C51812DC3A010C7D01B50E0D17DC79C8,
    0x3C44CDDDB6A900FA2B585DD299E03D12FA4293BC,
    0x90F79BF6EB2C4F870365E785982E1F101E93B906,
)
OPENNESS = {"not_determined": 0, "restricted": 1, "open": 2}
# Addresses no probe configures and the engine never samples: an open proved for every unconfigured address (not
# ``witnessed``) must let each of them through too.
UNSEEN = tuple(int.from_bytes(keccak(text=f"psat.oracle.unseen.{i}")[:20], "big") for i in range(24))
ALLOWED = {"later_conditional": 0, "conditional": 0, "later": 1, "now": 2}


def slot(key: int, base: int) -> int:
    """The slot of ``mapping[key]`` for a mapping at slot ``base``."""
    return int.from_bytes(keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


def hex20(address: int) -> str:
    return "0x%040x" % address


def selector(signature: str) -> int:
    return int.from_bytes(keccak(text=signature)[:4], "big")


def deployment(url: str, root: Path, source: str, version: str = A.SOLC) -> A.Deployment:
    """``source`` compiled with solc ``version`` (skipped where it isn't installed)."""
    import pytest

    if solc_path(version) is None:
        pytest.skip(f"solc {version} not installed")
    old, A.SOLC = A.SOLC, version
    try:
        sub = root / version
        sub.mkdir(exist_ok=True)
        n = len(list(sub.iterdir()))
        sub = sub / str(n)
        sub.mkdir()
        d = A.Deployment(url, sub, source)
        d.root = root  # where a setup compiles another source (``deployment(d.url, d.root, ...)``)
        return d
    finally:
        A.SOLC = old


def function(d: A.Deployment, contract: str, name: str) -> Any:
    return next(f for f in d.slither[contract].functions_entry_points if f.name == name and not f.is_constructor)


# --- calls -----------------------------------------------------------------------------------------------------------


def _abi_value(value: Any, type_: str) -> Any:
    if type_ == "address":
        return hex20(value % 2**160) if isinstance(value, int) else value
    if type_.startswith("bytes") and type_ != "bytes":
        n = int(type_[5:])
        return value if isinstance(value, bytes) else (value % 2 ** (8 * n)).to_bytes(n, "big")
    if type_ in ("bytes", "string"):
        if isinstance(value, int):
            raise ValueError("a dynamic argument given as a number")
        return value
    if type_ == "bool":
        return bool(value)
    if type_.endswith("]"):
        inner = type_[: type_.rindex("[")]
        return [_abi_value(v, inner) for v in value]
    if type_.startswith("int") and isinstance(value, int) and value >= 2 ** (int(type_[3:] or 256) - 1):
        return value - 2 ** int(type_[3:] or 256)
    return value


def calldata(fn: Any, args: dict[str, Any] | Iterable[Any] = ()) -> bytes:
    """``fn``'s call data, the arguments by name (a verdict's witness; zero, empty or false for the rest) or in order,
    encoded by ``eth_abi`` from the declared types: nothing of the engine's own encoding."""
    terms = [parameter(p, i) for i, p in enumerate(fn.parameters)]
    types = [t[2] for t in terms]
    if isinstance(args, dict):
        values = []
        for t in terms:
            if t[1] in args:
                values.append(args[t[1]])
            elif t[2] == "bool":
                values.append(False)
            elif t[2] in ("bytes", "string"):
                values.append(b"" if t[2] == "bytes" else "")
            elif t[2].endswith("[]"):
                values.append([])
            else:
                values.append(0)
    else:
        values = list(args)
    return keccak(text=fn.solidity_signature)[:4] + encode(types, [_abi_value(v, t) for v, t in zip(values, types)])


def eth_call(url: str, to: int, data: bytes, sender: int, value: int = 0) -> bool:
    call = {"from": hex20(sender), "to": hex20(to), "data": "0x" + data.hex()}
    if value:
        call["value"] = hex(value)
    try:
        rpc(url, "eth_call", [call, "latest"])
        return True
    except RuntimeError:
        return False


def passes(d: A.Deployment, at: int | str, fn: Any, args: Any = None, sender: int = OWNER, value: int = 0) -> bool:
    """Whether ``sender``'s call of ``fn`` at ``at`` (an address, or a deployed contract's name) goes through now:
    ``args`` by name (zero for the rest) or in order."""
    args = {} if args is None else args
    to = d.at[at] if isinstance(at, str) else at
    if isinstance(args, dict) and args.get("msg.value"):
        value = args["msg.value"]
    try:
        data = calldata(fn, args)
    except (ValueError, TypeError, OverflowError) as error:
        raise AssertionError(f"witness {args!r} of {fn.name} can't be encoded: {error}") from error
    if value:
        with snapshot(d):
            rpc(d.url, "anvil_setBalance", [hex20(sender), hex(value + 10**18)])
            return eth_call(d.url, to, data, sender, value)
    return eth_call(d.url, to, data, sender, value)


def strangers_passing(d: A.Deployment, at: int | str, fn: Any, args: Any = None) -> set[bool]:
    """What the five strangers' calls come to (``FRESH`` in the arguments replaced by each one's own address)."""
    out, args = set(), {} if args is None else args
    for who in STRANGERS:
        own = {k: who if v == FRESH else v for k, v in args.items()} if isinstance(args, dict) else args
        out.add(passes(d, at, fn, own, sender=who))
    return out


@contextlib.contextmanager
def snapshot(d: A.Deployment):
    """Whatever runs inside is undone after (``evm_snapshot`` / ``evm_revert``)."""
    taken = rpc(d.url, "evm_snapshot", [])
    try:
        yield
    finally:
        rpc(d.url, "evm_revert", [taken])


def transact(d: A.Deployment, at: int | str, signature: str, types=(), values=(), sender: int = OWNER, value=0) -> bool:
    """A mined transaction from ``sender`` (impersonated and funded); whether it succeeded."""
    values = [_abi_value(v, t) for v, t in zip(values, types)]
    return transact_data(d, at, keccak(text=signature)[:4] + encode(list(types), values), sender, value)


def transact_data(d: A.Deployment, at: int | str, data: bytes, sender: int = OWNER, value: int = 0) -> bool:
    to = d.at[at] if isinstance(at, str) else at
    if sender not in ACCOUNTS:
        rpc(d.url, "anvil_impersonateAccount", [hex20(sender)])
        rpc(d.url, "anvil_setBalance", [hex20(sender), hex(10**21)])
    receipt = send(d.url, hex20(sender), "0x" + data.hex(), to=hex20(to), value=value)
    return receipt["status"] == "0x1"


def set_storage(d: A.Deployment, at: int | str, at_slot: int, word: int) -> None:
    to = d.at[at] if isinstance(at, str) else at
    rpc(d.url, "anvil_setStorageAt", [hex20(to), hex(at_slot), "0x%064x" % word])


# --- the engine ------------------------------------------------------------------------------------------------------


def verdict(d: A.Deployment, contract: str, name: str, *others: str, chain=None, at: int | None = None, **kw) -> Any:
    """The engine's verdict on ``contract.name`` as deployed (at ``at``, else its own address), ``others`` followed."""
    reset_terms()
    c = d.slither[contract]
    where = at if at is not None else d.at[contract]
    contracts = {where: c} | {d.at[o]: d.slither[o] for o in others}
    return function_verdict(c, function(d, contract, name), where, chain or d.chain(), contracts, **kw)[0]


def chain_says(d: A.Deployment, fn: Any, values: Iterable[Any], contract: str = "C", sender: int = OWNER) -> bool:
    return passes(d, contract, fn, list(values), sender=sender)


def engine_says(d: A.Deployment, fn: Any, values: Iterable[Any], contract: str = "C", sender: int = OWNER,
                contracts: dict | None = None) -> tuple[Any, Any]:  # fmt: skip
    """The lowered formula and its truth at ``values`` (bytes for a ``bytesN`` read as its number)."""
    reset_terms()
    formula = Lowerer(d.slither[contract]).success(fn)
    # The contract itself is always known: its own storage is read by its layout.
    known = {d.at[contract]: d.slither[contract], **(contracts or {})}
    world = World(d.chain(), d.at[contract], selector(fn.solidity_signature), known)
    assignment = {}
    for i, (p, v) in enumerate(zip(fn.parameters, values)):
        assignment[parameter(p, i)] = int.from_bytes(v, "big") if isinstance(v, bytes) else v
    return formula, Evaluator(world, {"caller": sender, "signer": sender}, assignment).truth(formula)


def labels(formula: Any) -> set[str]:
    """What the lowering names as left unknown in ``formula``: each ``unknown``'s label, each rejected
    (``unsupported:``) opaque term, ``delegate`` for a delegatecall's code, and ``action:<signature>`` for an action
    handed the caller (unknown unless its callee's code answers, which the semantics harness never wires)."""
    from services.logic.terms import IDENTITY_KINDS, contains, subterms

    named = {str(u[1]) for u in subterms(formula, "unknown")}
    named |= {str(t[1]) for t in subterms(formula, "opaque") if str(t[1]).startswith("unsupported:")}
    named |= {
        f"action:{c[2]}"
        for c in subterms(formula, "call")
        if not c[4] and any(contains(a, IDENTITY_KINDS) for a in c[3])
    }
    return named | ({"delegate"} if subterms(formula, "delegate") else set())


def agrees(formula: Any, engine: Any, chain: bool, where: Any = None) -> None:
    """The semantics oracle at one input: the engine says what the chain says, or it says it doesn't know and the
    lowering names why (``labels``). An unknown named nowhere compares nothing and is a failure."""
    from services.logic.decide import UNK

    if engine is UNK:
        assert labels(formula), (where, "unknown, named nowhere", formula)
    else:
        assert engine == chain, (where, chain, engine, formula)


class Faulty(Chain):
    """The deployment's chain with reads failing as a node under load fails them: ``storage``, ``calls`` and ``code``
    each ``True`` (every such read), a set of addresses (reads at those) or a predicate of the request; ``logs``
    cuts every history in half and marks it partial."""

    def __init__(self, d: A.Deployment, *, storage=False, calls=False, code=False, logs=False):
        self.faults = {"eth_getStorageAt": storage, "eth_call": calls, "eth_getCode": code}
        self.cut_logs = logs
        url = d.url

        def one(method, params):
            fault = self.faults.get(method)
            if fault:
                target = int(params[0]["to"] if method == "eth_call" else params[0], 16)
                if fault is True or (fault(method, params) if callable(fault) else target in fault):
                    raise RuntimeError("injected: upstream timeout")
            return rpc(url, method, params)

        def batch(calls_):
            out = []
            for method, params in calls_:
                try:
                    out.append(one(method, params))
                except RuntimeError:
                    out.append(None)
            return out

        super().__init__(one, int(rpc(url, "eth_blockNumber", []), 16), batch)

    def logs(self, address, topics):
        out = super().logs(address, topics)
        if self.cut_logs and topics:
            self.truncated.add(address)
            self.partial[(address, topics)] = True  # as a scan cut short marks it
            return out[: len(out) // 2]
        return out


# --- the verdict oracle ----------------------------------------------------------------------------------------------


def nobody(v: Any) -> bool:
    """A verdict saying no caller can pass: restricted, complete, nobody listed."""
    return v.openness == "restricted" and v.complete and not v.principals and not v.signers and not v.conditions


def check(d: A.Deployment, contract: str, name: str, v: Any, *, at: int | None = None, samples=({},),
          known: Iterable[int] = (), open_at: Any = None, arrange: Callable | None = None,
          holders_after: Callable | None = None, later: Callable | None = None,
          open_proven: bool | None = None) -> Any:  # fmt: skip
    """``v`` against the chain as it stands (see the module's docstring).

    ``samples``: argument sets (by name) at which a refused caller must fail; ``known``: addresses beyond the strangers
    and anvil's accounts the probe knows of; ``arrange(d, stranger)``: what a stranger does for itself first (a
    deposit, a request, coming to hold what ``requires`` names), run with the verdict's own ``after`` calls before
    that stranger's call; ``open_at``: arguments at which, so arranged, every stranger passes (the verdict must then
    be "open"; checked whatever the verdict), or ``False`` where none can now. With ``open_at=False`` the verdict is
    never "open later" either unless ``later(d)`` says how a state comes about in which every stranger passes (the
    owner unpausing): "open later" claims such a state is reachable, so it is checked there, each stranger's call at
    each of ``samples`` until one passes for all (its own ``after`` calls made first, then at its witness or a sample).
    An "open now" verdict is checked at its own witness unless ``open_at`` is given. ``holders_after(d)``: what has to
    happen first for the listed holders to pass where the verdict lists them on a condition closed now (the owner
    turning it on, code coming to be at an address), run before their calls. ``open_proven``: ``True`` where the
    probe knows every unconfigured address passes and the engine can show it from the formula alone (the verdict
    must be "open" and not ``witnessed``), ``False`` where only a sample can show it (open, if at all, only
    ``witnessed``)."""
    fn = function(d, contract, name)
    where = at if at is not None else d.at[contract]
    if open_proven is not None:
        assert v.openness == "open" or not open_proven, (name, "open, proved", v)
        assert v.openness != "open" or v.witnessed != open_proven, (name, "witnessed" if open_proven else "proved", v)
    proved = v.openness == "open" and v.allowed == "now" and not v.witnessed
    if proved and arrange is None and not v.after and not v.requires:
        # Proved for every unconfigured address: addresses the engine never sampled pass as well.
        args = open_at if isinstance(open_at, dict) else v.witnesses.get(FRESH, {})
        for who in UNSEEN:
            own = {k: who if x == FRESH else x for k, x in args.items()}
            assert passes(d, where, fn, own, sender=who), (name, "proved open, unseen fails", hex(who), v)
    with snapshot(d):
        if holders_after is not None:
            holders_after(d)
        # Those listed on conditions freed pass once ``holders_after`` has opened them.
        for holder in {*v.principals, *(v.conditions if holders_after is not None else ())}:
            assert passes(d, where, fn, v.witnesses.get(holder, {}), sender=holder), (name, hex(holder), v)
    if v.openness == "open" and v.allowed == "now" or isinstance(open_at, dict):
        assert arrange is not None or not v.requires, (name, "say how a stranger comes to hold", v.requires)
        for who in STRANGERS:  # each on its own: what one stranger arranges may stand in another's way
            with snapshot(d):
                if arrange is not None:
                    arrange(d, who)
                if v.openness == "open":
                    for signature, args in v.after:  # the calls a stranger makes first, its own
                        first = next(f for f in d.slither[contract].functions_entry_points
                                     if f.solidity_signature == signature)  # fmt: skip
                        own = {k: who if x == FRESH else x for k, x in args.items()}
                        assert transact_data(d, where, calldata(first, own), who), (name, signature, own)
                args = open_at if isinstance(open_at, dict) else v.witnesses.get(FRESH, {})
                own = {k: who if x == FRESH else x for k, x in args.items()}
                assert passes(d, where, fn, own, sender=who), (name, hex(who), own, v)
    if open_at is False:
        assert not (v.openness == "open" and v.allowed == "now"), (name, v)
        claimed = v.openness == "open" and v.allowed == "later"  # on conditions set aside, it claims none
        assert not claimed or later is not None, (name, "no state the probe knows lets a stranger through", v)
        if claimed and later is not None:
            with snapshot(d):
                later(d)
                if v.after:
                    # Each stranger makes its own first calls, then its call: at its witness, else at a sample.
                    for who in STRANGERS:
                        with snapshot(d):
                            for signature, args in v.after:
                                first = next(f for f in d.slither[contract].functions_entry_points
                                             if f.solidity_signature == signature)  # fmt: skip
                                own = {k: who if x == FRESH else x for k, x in args.items()}
                                assert transact_data(d, where, calldata(first, own), who), (name, signature, own)
                            tries = [v.witnesses.get(FRESH, {}), *samples]
                            assert any(
                                passes(d, where, fn, {k: who if x == FRESH else x for k, x in a.items()}, sender=who)
                                for a in tries
                            ), (name, "later, after its own calls", hex(who), v)
                else:
                    assert any(strangers_passing(d, where, fn, args) == {True} for args in samples), (name, "later", v)
    elif open_at is not None:
        assert v.openness == "open", (name, "every stranger passes", open_at, v)
    if v.openness == "restricted":
        for args in samples:
            assert True not in strangers_passing(d, where, fn, args), (name, "a stranger passes", args, v)
    if v.openness == "restricted" and v.complete:
        listed = set(v.principals) | set(v.signers) | set(v.conditions)
        for who in {*ACCOUNTS, *known, *d.at.values()} - listed:
            for args in samples:
                assert not passes(d, where, fn, args, sender=who), (name, "unlisted passes", hex(who), args, v)
    return v


def chain_sound(d: A.Deployment, contract: str, name: str, v: Any, clean: Any, *, at: int | None = None) -> Any:
    """What a verdict decided under a fault claims beyond the clean verdict ``clean`` (which its module checks against
    the chain, with whatever arrangement the probe knows) holds on the chain as it stands: a holder only it lists
    passes ``eth_call`` from its own address with its witness; an "open now" (nothing to hold first) at a witness of
    its own passes for each of the five strangers, its ``after`` calls made first, unless the clean witness fails
    for them too (an open each stranger arranges first, which the module checks that way). A fault may only lower
    confidence: what it still claims must stand."""
    fn = function(d, contract, name)
    where = at if at is not None else d.at[contract]
    for holder in set(v.principals) - listed(clean) - set(clean.undecided):
        assert passes(d, where, fn, v.witnesses.get(holder, {}), sender=holder), (name, hex(holder), v)

    def all_pass(witness: dict) -> bool:
        for who in STRANGERS:
            with snapshot(d):
                for signature, args in v.after:
                    first = next(f for f in d.slither[contract].functions_entry_points
                                 if f.solidity_signature == signature)  # fmt: skip
                    if not transact_data(d, where, calldata(first, {k: who if x == FRESH else x
                                                                     for k, x in args.items()}), who):  # fmt: skip
                        return False
                if not passes(d, where, fn, {k: who if x == FRESH else x for k, x in witness.items()}, sender=who):
                    return False
        return True

    if v.openness == "open" and v.allowed == "now" and not v.requires:
        witness, clean_witness = v.witnesses.get(FRESH, {}), clean.witnesses.get(FRESH)
        if witness != clean_witness and not all_pass(witness):
            assert clean_witness is not None and not all_pass(clean_witness), (name, "open at its witness", v)
    return v


def sound(v: Any, truth: set[int] | None = None, *, anyone: bool = False) -> None:
    """``v`` claims no more than ``truth`` (the holders, by construction; ``anyone`` where a stranger passes): never
    more open, never a holder outside it, never a complete list missing one."""
    if not anyone:
        assert v.openness != "open" or v.allowed != "now", v
    else:
        assert v.openness != "restricted", v
    if truth is not None:
        assert set(v.principals) <= truth, v
        if v.complete and v.openness == "restricted":
            assert truth <= set(v.principals) | set(v.conditions) | set(v.signers), v


def never_bolder(clean: Any, faulted: Any) -> None:
    """The fail-safe property: a fault never makes a verdict more open, never shrinks a complete list, never makes
    complete what the clean run was not, and never proves an open the clean run only witnessed (proven-open ranks
    above witnessed-open, above not determined), nor drops what the clean open said the call needs (an open that
    requires something, ``stranger_run_failed`` among them, ranks below the same open requiring nothing)."""
    rank, clean_rank = _rank(faulted), _rank(clean)
    assert rank <= clean_rank, (clean, faulted)
    if faulted.complete:
        assert clean.complete, (clean, faulted)
        assert listed(faulted) >= listed(clean), (clean, faulted)


def _rank(v: Any) -> tuple[int, int, int, int]:
    if v.openness != "open":
        return (OPENNESS[v.openness], 0, 0, 0)
    return (OPENNESS["open"], ALLOWED.get(v.allowed, 0), 0 if v.witnessed else 1, 0 if v.requires else 1)


def listed(v: Any) -> set[int]:
    """Who a verdict names: a complete list is these together (``Verdict.conditions``)."""
    return set(v.principals) | set(v.signers) | set(v.conditions)


# --- the probe registry the fail-safe sweep reads ---


@dataclass(frozen=True)
class Probe:
    """Verdict-oracle probes of one source: ``setup`` deploys (and arranges the state), ``functions`` are
    ``(contract, function, followed contracts)``."""

    source: str
    setup: Callable[[A.Deployment], None]
    functions: tuple[tuple[str, str, tuple[str, ...]], ...]
    version: str = A.SOLC
    at: Callable[[A.Deployment, str], int] | None = field(default=None)
