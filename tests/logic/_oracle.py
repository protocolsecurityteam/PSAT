"""The oracles the logic engine is checked against, on anvil.

* Semantics (``chain_says`` / ``engine_says``): a function's lowered success formula, evaluated by the decision's own
  evaluator at concrete arguments, against ``eth_call`` of the same call.
* Verdict (``check``): every holder a verdict lists passes ``eth_call`` from its own address (``tx.origin`` too) with
  its witness arguments; "open now" only when each of the five strangers (``decide._STRANGERS``) passes; "restricted"
  only when no stranger passes at the arguments the probe's author knows matter; a list said to be complete leaves
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
from services.logic.decide import _STRANGERS, FRESH, Evaluator, World
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
        return A.Deployment(url, sub, source)
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


def passes(d: A.Deployment, at: int | str, fn: Any, args: Any = (), sender: int = OWNER, value: int = 0) -> bool:
    """Whether ``sender``'s call of ``fn`` at ``at`` (an address, or a deployed contract's name) goes through now."""
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


def strangers_passing(d: A.Deployment, at: int | str, fn: Any, args: Any = ()) -> set[bool]:
    """What the five strangers' calls come to (``FRESH`` in the arguments replaced by each one's own address)."""
    out = set()
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
    to = d.at[at] if isinstance(at, str) else at
    values = [_abi_value(v, t) for v, t in zip(values, types)]
    data = "0x" + (keccak(text=signature)[:4] + encode(list(types), values)).hex()
    if sender not in ACCOUNTS:
        rpc(d.url, "anvil_impersonateAccount", [hex20(sender)])
        rpc(d.url, "anvil_setBalance", [hex20(sender), hex(10**21)])
    receipt = send(d.url, hex20(sender), data, to=hex20(to), value=value)
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
    world = World(d.chain(), d.at[contract], selector(fn.solidity_signature), contracts or {})
    assignment = {}
    for i, (p, v) in enumerate(zip(fn.parameters, values)):
        assignment[parameter(p, i)] = int.from_bytes(v, "big") if isinstance(v, bytes) else v
    return formula, Evaluator(world, {"caller": sender, "signer": sender}, assignment).truth(formula)


# --- the verdict oracle ----------------------------------------------------------------------------------------------


def nobody(v: Any) -> bool:
    """A verdict saying no caller can pass: restricted, complete, nobody listed."""
    return v.openness == "restricted" and v.complete and not v.principals and not v.signers and not v.conditions


def check(d: A.Deployment, contract: str, name: str, v: Any, *, at: int | None = None, samples=({},),
          known: Iterable[int] = (), open_at: Any = None) -> Any:  # fmt: skip
    """``v`` against the chain as it stands (see the module's docstring).

    ``samples``: argument sets (by name) at which a refused caller must fail; ``known``: addresses beyond the strangers
    and anvil's accounts the probe knows of; ``open_at``: arguments at which the author knows every stranger passes
    (the verdict must then be "open"), or ``False`` where none can (never "open now")."""
    fn = function(d, contract, name)
    where = at if at is not None else d.at[contract]
    for holder in v.principals:
        assert passes(d, where, fn, v.witnesses.get(holder, {}), sender=holder), (name, hex(holder), v)
    if v.openness == "open" and v.allowed == "now":
        assert strangers_passing(d, where, fn, v.witnesses.get(FRESH, {})) == {True}, (name, v)
    if open_at is False:
        assert not (v.openness == "open" and v.allowed == "now"), (name, v)
    elif open_at is not None:
        assert strangers_passing(d, where, fn, open_at) == {True}, (name, "the probe's open arguments", open_at)
        assert v.openness == "open", (name, v)
    if v.openness == "restricted":
        for args in samples:
            assert True not in strangers_passing(d, where, fn, args), (name, "a stranger passes", args, v)
    if v.openness == "restricted" and v.complete:
        listed = set(v.principals) | set(v.signers) | set(v.conditions)
        for who in {*ACCOUNTS, *known, *d.at.values()} - listed:
            for args in samples:
                assert not passes(d, where, fn, args, sender=who), (name, "unlisted passes", hex(who), args, v)
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
    complete what the clean run was not."""
    rank = (OPENNESS[faulted.openness], ALLOWED.get(faulted.allowed, 0) if faulted.openness == "open" else 0)
    clean_rank = (OPENNESS[clean.openness], ALLOWED.get(clean.allowed, 0) if clean.openness == "open" else 0)
    assert rank <= clean_rank, (clean, faulted)
    if faulted.complete:
        assert clean.complete, (clean, faulted)
        assert set(faulted.principals) >= set(clean.principals), (clean, faulted)


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
