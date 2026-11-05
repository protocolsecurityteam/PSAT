"""Independent concrete EVM checks. Samples are counterexample searches, never completeness proofs."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any, Iterable

from eth_abi import encode
from eth_utils import keccak

import tests.logic._anvil as A
from services.logic.formula import compile_function
from services.logic.lower import parameter
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.fuzz.authority import solc_path
from tests.support.anvil import ACCOUNT0, rpc, send

OWNER = int(ACCOUNT0, 16)
ACCOUNTS = (
    OWNER,
    0x70997970C51812DC3A010C7D01B50E0D17DC79C8,
    0x3C44CDDDB6A900FA2B585DD299E03D12FA4293BC,
    0x90F79BF6EB2C4F870365E785982E1F101E93B906,
)
STRANGERS = ACCOUNTS[1:]


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
    except RuntimeError as exc:
        if "revert" not in str(exc).lower():
            raise
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


def chain_says(d: A.Deployment, fn: Any, values: Iterable[Any], contract: str = "C", sender: int = OWNER) -> bool:
    return passes(d, contract, fn, list(values), sender=sender)


def engine_says(d, fn, values, contract="C", sender=OWNER, contracts=None):
    known = {d.at[contract]: d.slither[contract], **(contracts or {})}
    bindings = {CALLER: sender, ORIGIN: sender, mk("callvalue"): 0}
    bindings.update({parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, values))})
    row = compile_function(d.slither[contract], fn, d.at[contract], d.chain(), known, bindings=bindings)
    translated = Translation(d.chain(), known, d.at[contract], row.selector, bindings=bindings)
    answer = translated.truth(row.success)
    # Keep translation limitations visible beside the lowerer's terms in the test diagnosis.
    if answer is None and translated.issues:
        from services.logic.terms import mk_and, unknown

        return mk_and([row.success, *(unknown(f"translation:{i.detail}") for i in translated.issues)]), None
    return row.success, answer


def labels(formula):
    return {str(t[1]) for k in ("unknown", "opaque", "assumed") for t in subterms(formula, k)}


def callers_with_resources(formula, reads, contracts):
    """Test-only caller projection assuming the raw calls have enough execution resources.

    Pair this with EVM execution and keep production's qualified result assertion.
    This does not certify transaction gas feasibility or remove any other unknown.
    """
    from services.logic.solver import project
    from services.logic.terms import TRUE, replace_terms

    resources = {t: TRUE for t in subterms(formula.success, "unknown") if t[1] == "unsupported:raw_call_resources"}
    return project(
        replace_terms(formula.success, resources), Translation(reads, contracts, formula.address, formula.selector)
    )


def agrees(formula, engine, chain, where=None):
    if engine is None:
        assert labels(formula), (where, "unknown without a reason", formula)
    else:
        assert engine == chain, (where, chain, engine, formula)


def analyze_function(contract, fn, address, reads, contracts, limits=None, code_of=None):
    from services.logic.expansion import Selection, expand_formula
    from services.logic.model import Limits

    limits = limits or Limits()
    formula = compile_function(contract, fn, address, reads, contracts, limits, code_of)
    return expand_formula(
        formula, reads, contracts, limits=limits, selection=Selection(effect_indices=tuple(range(len(formula.effects))))
    )
