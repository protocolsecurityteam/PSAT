"""Durable symbolic-expansion checkpoints, using deterministic control-flow replay.

Only JSON data is persisted. Matching verified compiler IR is supplied by the normal
build resolver; completed semantic steps are restored, not lowered again. The walker
reconstructs its Python control stack, including modifiers and nested loop continuations.
"""

from __future__ import annotations

import hashlib
import json
from contextvars import ContextVar
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any, Callable

from .abi_values import abi_signature
from .model import Formula, Limits, decode_value, encode
from .terms import Term, mk, stable

ACTIVE: ContextVar[Any] = ContextVar("logic_expansion_journal", default=None)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _engine():
    root = Path(__file__).parent
    return _digest(
        {
            "modules": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob("*.py"))},
            "packages": {
                p: version(p) for p in ("slither-analyzer", "crytic-compile", "z3-solver", "eth-abi", "eth-utils")
            },
        }
    )


@dataclass(frozen=True)
class PendingCompilation:
    address: int
    block: int
    signature: str
    reason: str
    checkpoint: dict
    blocker: str | None = None


class Suspended(Exception):
    def __init__(self, reason, blocker=None):
        self.reason = reason
        self.blocker = blocker
        super().__init__(reason)


class References:
    """Stable references into a verified compilation unit; never executable object serialization."""

    def __init__(self):
        self.keys: dict[int, str] = {}
        self.objects: dict[str, Any] = {}
        self.manifests: dict[str, dict] = {}
        self.packed_terms: dict[Term, Term] = {}
        self.unpacked_terms: dict[Term, Term] = {}

    def add(self, obj, key):
        if isinstance(obj, (tuple, list)):
            for i, item in enumerate(obj):
                self.add(item, f"{key}/{i}")
            return
        if obj is None or isinstance(obj, (str, int, bool, bytes)):
            return
        if id(obj) not in self.keys:
            self.keys[id(obj)] = key
            self.objects[key] = obj

    def register(self, contract, scope=""):
        unit = contract.compilation_unit
        sources = sorted(hashlib.sha256(s.encode()).hexdigest() for s in unit.core.source_code.values())
        compiler = str(getattr(unit.compiler_version, "version", ""))
        evm = getattr(unit, "context", {}).get("psat_evm_version")
        identity = _digest([sources, compiler, evm, version("slither-analyzer"), scope])
        if identity in self.manifests:
            return identity
        contracts = sorted(unit.contracts, key=lambda c: c.name)
        functions = []
        manifest = []
        for c in contracts:
            self.add(c, f"{identity}/contract/{c.name}")
            for i, var in enumerate(c.state_variables):
                self.add(var, f"{identity}/{c.name}/state/{i}")
            functions.extend(c.functions_and_modifiers)
        functions.extend(getattr(unit, "functions_top_level", ()))
        # Register declarations and destinations before fingerprinting their uses. In particular,
        # abi.encodeCall carries nested argument lists whose default repr embeds process IDs.
        unique = []
        seen = set()
        for i, fn in enumerate(functions):
            if id(fn) in seen:
                continue
            seen.add(id(fn))
            unique.append((i, fn))
            base = f"{identity}/fn/{i}"
            self.add(fn, base)
            for j, var in enumerate([*fn.parameters, *fn.returns, *fn.variables]):
                self.add(var, f"{base}/var/{j}")
            for j, node in enumerate(fn.nodes):
                nkey = f"{base}/node/{j}"
                self.add(node, nkey)
                self.add(getattr(node, "variable_declaration", None), nkey + "/decl")
                for k, ir in enumerate(node.irs):
                    ikey = f"{nkey}/ir/{k}"
                    self.add(ir, ikey)
                    self.add(getattr(ir, "lvalue", None), ikey + "/lvalue")
        attributes = (
            "read",
            "lvalue",
            "arguments",
            "function",
            "function_name",
            "variable",
            "structure",
            "destination",
            "call_value",
            "call_gas",
            "variable_left",
            "variable_right",
            "type",
            "index",
            "event",
            "contract_name",
        )
        for _, fn in unique:
            for node in fn.nodes:
                for ir in node.irs:
                    for name in attributes:
                        self.add(getattr(ir, name, None), self.ref(ir) + "/" + name)
        for _, fn in unique:
            nodes = []
            for node in fn.nodes:
                operations = [
                    [type(ir).__name__, {name: self.operand(getattr(ir, name, None)) for name in attributes}]
                    for ir in node.irs
                ]
                nodes.append(
                    [
                        node.node_id,
                        str(node.type),
                        bool(getattr(node.scope, "is_checked", False)),
                        bool(getattr(node.scope, "is_yul", False)),
                        operations,
                    ]
                )
            manifest.append([fn.canonical_name, nodes])
        self.manifests[identity] = {
            "sources": sources,
            "compiler": compiler,
            "evm_version": evm,
            "ir_hash": _digest(manifest),
        }
        return identity

    def operand(self, value):
        """A structural IR fingerprint: operand identity/order, never Python object repr."""
        from enum import Enum

        from slither.core.solidity_types.type import Type
        from slither.slithir.variables import Constant

        if value is None or type(value) in (str, int, bool):
            return value
        if isinstance(value, bytes):
            return {"bytes": value.hex()}
        if isinstance(value, (tuple, list)):
            return [self.operand(v) for v in value]
        if isinstance(value, Enum):
            return [type(value).__name__, value.name]
        if isinstance(value, Type):
            return [type(value).__name__, str(value)]
        if isinstance(value, Constant):
            return ["Constant", str(value.type), str(value.value)]
        return {
            "kind": type(value).__name__,
            "ref": self.keys.get(id(value)),
            "name": getattr(value, "canonical_name", None) or getattr(value, "name", None),
            "type": self.operand(getattr(value, "type", None)),
        }

    def ref(self, obj):
        try:
            return self.keys[id(obj)]
        except KeyError as exc:
            raise ValueError(f"unregistered compiler object: {type(obj).__name__}") from exc

    def identity(self, key):
        if isinstance(key, int):
            if key not in self.keys:
                raise ValueError("unregistered compiler variable")
            return {"$id": self.keys[key]}
        return key

    def term(self, value, *, packing):
        """Rebind reference payloads anywhere in a shared term, without expanding its DAG."""
        cache = self.packed_terms if packing else self.unpacked_terms
        if isinstance(value, Term) and value in cache:
            return cache[value]
        if isinstance(value, tuple):
            if value and value[0] in ("mref", "sref"):
                reference = ("compiler_ref", self.keys[value[1]]) if packing else id(self.objects[value[1][1]])
                parts = (value[0], reference, *(self.term(v, packing=packing) for v in value[2:]))
            else:
                parts = tuple(self.term(v, packing=packing) for v in value)
            if isinstance(value, Term):
                result = mk(*parts)
                cache[value] = result
                return result
            return parts
        if isinstance(value, frozenset):
            return frozenset(self.term(v, packing=packing) for v in value)
        return value

    def pack(self, value):
        from .lower import Exit, State

        if isinstance(value, (State, Exit)):
            fields = {"pc": value.pc, "store": value.store, "ret": value.ret, "halted": value.halted}
            if isinstance(value, State):
                fields["mem"] = value.mem
            fields["env"] = (
                None if value.env is None else [(self.identity(k), self.pack(v)) for k, v in value.env.items()]
            )
            env = fields.pop("env")
            return {"$state" if isinstance(value, State) else "$exit": self.pack(fields), "env": env}
        if isinstance(value, Term):
            return self.term(value, packing=True)
        if isinstance(value, tuple):
            if value and value[0] in ("mref", "sref"):
                return {"$tuple": [self.pack(value[0]), self.identity(value[1]), *(self.pack(v) for v in value[2:])]}
            return {"$tuple": [self.pack(v) for v in value]}
        if isinstance(value, list):
            return {"$list": [self.pack(v) for v in value]}
        if isinstance(value, (frozenset, set)):
            return {"$set": sorted((self.pack(v) for v in value), key=lambda x: json.dumps(encode(x), sort_keys=True))}
        if isinstance(value, dict):
            return {"$map": [[self.pack(k), self.pack(v)] for k, v in value.items()]}
        if isinstance(value, bytes):
            return {"$bytes": value.hex()}
        if value is None or type(value) in (str, int, bool):
            return value
        return {"$ref": self.ref(value)}

    def unpack(self, value) -> Any:
        from .lower import Exit, State

        if isinstance(value, Term):
            return self.term(value, packing=False)
        if not isinstance(value, dict):
            if value is None or type(value) in (str, int, bool):
                return value
            raise ValueError("invalid checkpoint value")
        if "$state" in value or "$exit" in value:
            cls, tag = (State, "$state") if "$state" in value else (Exit, "$exit")
            fields = self.unpack(value[tag])
            fields["env"] = None if value["env"] is None else {self.unpack(k): self.unpack(v) for k, v in value["env"]}
            return cls(**fields)
        if len(value) != 1:
            raise ValueError("invalid checkpoint tag")
        tag, data = next(iter(value.items()))
        if tag == "$id":
            return id(self.objects[data])
        if tag == "$ref":
            return self.objects[data]
        if tag == "$term":
            return mk(*(self.unpack(v) for v in data))
        if tag in ("$tuple", "$list", "$set"):
            values = [self.unpack(v) for v in data]
            return tuple(values) if tag == "$tuple" else frozenset(values) if tag == "$set" else values
        if tag == "$map":
            return {self.unpack(k): self.unpack(v) for k, v in data}
        if tag == "$bytes":
            return bytes.fromhex(data)
        raise ValueError("invalid checkpoint tag")


# Caches are reconstructible; these fields affect the meaning of the next operation.
_FIELDS = (
    "sender",
    "this",
    "code",
    "_outer_this",
    "_frame_value",
    "_frame_data",
    "_static",
    "_node",
    "_calldata_min",
    "_last_call",
    "_last_returns",
    "_objects",
    "_memory_bases",
    "_object_types",
    "_sliced",
    "_payable",
    "_halts",
    "_arguments",
    "lost",
    "raw_reads",
    "_steps",
    "_stack",
)


class Journal:
    def __init__(self, steps: int, checkpoint: dict | None = None, *, loop_iterations=32, value_steps=50_000):
        if type(steps) is not int or steps < 0:
            raise ValueError("nonnegative expansion step budget required")
        if (
            type(loop_iterations) is not int
            or not 1 <= loop_iterations <= 128
            or type(value_steps) is not int
            or value_steps < 1
        ):
            raise ValueError("invalid loop/value budget")
        self.loop_iterations, self.value_steps = loop_iterations, value_steps
        self.engine = _engine()
        self.remaining = steps
        self.call_depth = 8
        self.references = References()
        self.frames = 0
        self.specialized = False
        self.reused = self.executed = 0
        self.programs = {}
        self.expected = {}
        self.events: list[dict[str, Any]] = []
        self.identity = None
        self.cursor = [(self.events, 0)]
        self.pending = None
        if checkpoint is not None:
            if checkpoint.get("schema") != 1 or checkpoint.get("engine") != self.engine:
                raise ValueError("checkpoint engine changed; start a new generation")
            saved = checkpoint["body"]
            if checkpoint.get("hash") != _digest(saved):
                raise ValueError("checkpoint hash mismatch")
            body = decode_value(saved)
            self.identity, self.events = body["identity"], body["events"]
            self.programs, self.expected = body["programs"], body["manifests"]
            self.cursor = [(self.events, 0)]

    def bind(self, identity):
        if self.identity is not None and self.identity != identity:
            raise ValueError("checkpoint input identity changed")
        self.identity = identity

    def prepare(self, reads, contracts, code_of=None, own_code=None):
        self.reads, self.contracts = reads, contracts
        self.code_of = code_of or (lambda address: address)
        self.own_code = own_code
        for record in self.programs.values():
            at, code = record["address"], record["code"]
            lookup = own_code or getattr(contracts, "own_code", None)
            contract = lookup(code) if lookup is not None else None
            if contract is None:
                contract = contracts.get(code)
            if contract is None or self.code_of(at) != record["resolved"]:
                raise ValueError("checkpoint code context changed")
            ident = self.references.register(contract, code)
            if ident != record["source"] or self.references.manifests[ident] != self.expected[ident]:
                raise ValueError("checkpoint compiler inputs changed")
            if hashlib.sha256(reads.code(code)).hexdigest() != record["runtime"]:
                raise ValueError("checkpoint runtime code changed")
            declaration = self.references.objects.get(record["contract"])
            if declaration is None:
                raise ValueError("checkpoint code declaration changed")
            register = getattr(contracts, "record_code", None)
            if register is not None:
                register(at, code, declaration)

    def attach(self, lowerer):
        scope = lowerer.code[1] if lowerer.code[0] == "const" else str(lowerer.code)
        ident = self.references.register(lowerer.contract, scope)
        if ident in self.expected and self.expected[ident] != self.references.manifests[ident]:
            raise ValueError("checkpoint compiler IR changed")
        if lowerer.this[0] == lowerer.code[0] == "const":
            at, code = lowerer.this[1], lowerer.code[1]
            key = f"{at}:{code}"
            record = {
                "address": at,
                "code": code,
                "source": ident,
                "contract": self.references.ref(lowerer.contract),
                "resolved": self.code_of(at),
                "runtime": hashlib.sha256(self.reads.code(code)).hexdigest(),
            }
            if key in self.programs and self.programs[key] != record:
                raise ValueError("checkpoint program changed")
            self.programs[key] = record
        self.frames += 1
        lowerer._frame_identity = self.frames
        return ident

    def snapshot(self, lowerer):
        from .lower import _STEPS

        fields = {name: getattr(lowerer, name) for name in _FIELDS}
        for name in ("_vars", "_structs"):
            fields[name] = [
                (self.references.identity(k), self.references.pack(v)) for k, v in getattr(lowerer, name).items()
            ]
        maps = {name: fields.pop(name) for name in ("_vars", "_structs")}
        resolvers = []
        resolver = lowerer.resolver
        while resolver is not None:
            resolvers.append(self.references.pack((resolver.cache, resolver.expanded, resolver.state_specialized)))
            resolver = resolver.parent
        return {
            "fields": self.references.pack(fields),
            "maps": maps,
            "value_used": self.value_steps - _STEPS[0],
            "frames": self.frames,
            "specialized": self.specialized,
            "resolvers": resolvers,
        }

    def restore(self, lowerer, snapshot):
        from .lower import _STEPS

        for name, value in self.references.unpack(snapshot["fields"]).items():
            setattr(lowerer, name, value)
        for name, pairs in snapshot["maps"].items():
            setattr(lowerer, name, {self.references.unpack(k): self.references.unpack(v) for k, v in pairs})
        _STEPS[0], self.frames = self.value_steps - snapshot["value_used"], snapshot["frames"]
        self.specialized |= snapshot["specialized"]
        resolver = lowerer.resolver
        for saved in snapshot["resolvers"]:
            if resolver is None:
                raise ValueError("checkpoint resolver context changed")
            resolver.cache, resolver.expanded, resolver.state_specialized = self.references.unpack(saved)
            resolver = resolver.parent
        if resolver is not None:
            raise ValueError("checkpoint resolver context changed")

    def run(self, lowerer, kind, operation, inputs, execute: Callable):
        nodes, index = self.cursor[-1]
        self.cursor[-1] = nodes, index + 1
        before = self.snapshot(lowerer)
        key = [
            kind,
            lowerer._frame_identity,
            self.references.ref(operation),
            self.references.pack(inputs),
            before["fields"],
            before["maps"],
        ]
        event: dict[str, Any]
        if index < len(nodes):
            event = nodes[index]
            if event["key"] != key:
                raise ValueError("checkpoint replay diverged from saved operation/state")
            if "result" in event:
                self.restore(lowerer, event["after"])
                self.reused += 1
                return self.references.unpack(event["result"])
        else:
            event = {"key": key, "children": []}
            nodes.append(event)
        if not event.get("started"):
            if self.remaining <= 0:
                self.pending = key[:3]
                raise Suspended("expansion_steps")
            self.remaining -= 1
            self.executed += 1
            event["started"] = True
        self.cursor.append((event["children"], 0))
        try:
            result = execute()
            children, consumed = self.cursor[-1]
            if consumed != len(children):
                raise ValueError("checkpoint replay skipped saved work")
            event["result"], event["after"] = self.references.pack(result), self.snapshot(lowerer)
            event.pop("children", None)  # a completed parent replaces its completed subtree
            return result
        finally:
            self.cursor.pop()

    def suspend(self, reason, details=None):
        self.pending = {"reason": reason, "operation": self.references.pack(details)}
        blocker = (
            details.get("reason")
            if isinstance(details, dict) and (details.get("kind") == "call" or reason == "operation")
            else None
        )
        raise Suspended(reason, blocker)

    def dump(self, reason):
        body = {
            "identity": self.identity,
            "events": self.events,
            "programs": self.programs,
            "manifests": {**self.expected, **self.references.manifests},
            "pending": self.pending,
            "reason": reason,
        }
        if _engine() != self.engine:
            raise ValueError("engine changed during generation")
        saved = encode(body)
        return {"schema": 1, "engine": self.engine, "body": saved, "hash": _digest(saved)}


def generate_function(
    contract,
    function,
    address,
    reads,
    contracts,
    limits=Limits(),
    *,
    steps=5000,
    checkpoint=None,
    loop_iterations=32,
    value_steps=50_000,
    **kwargs,
) -> Formula | PendingCompilation:
    """Finish a formula or preserve the whole interrupted compilation. No partial formula is published."""
    from .formula import compile_function

    journal = Journal(steps, checkpoint, loop_iterations=loop_iterations, value_steps=value_steps)
    journal.call_depth = limits.callee_depth
    identity = {
        "address": address,
        "block": reads.block,
        "signature": abi_signature(function),
        "solver_ms": limits.solver_ms,
        "storage_steps": limits.storage_steps,
        "bindings": _digest(encode(tuple(sorted((kwargs.get("bindings") or {}).items(), key=lambda p: stable(p[0]))))),
    }
    if journal.identity is not None and {k: v for k, v in journal.identity.items() if k != "snapshot"} != identity:
        raise ValueError("checkpoint input identity changed")
    identity["snapshot"] = reads.snapshot_identity() if callable(getattr(reads, "snapshot_identity", None)) else None
    journal.bind(identity)
    journal.prepare(reads, contracts, kwargs.get("code_of"), kwargs.get("own_code"))
    token = ACTIVE.set(journal)
    try:
        return compile_function(contract, function, address, reads, contracts, limits, journal=journal, **kwargs)
    except Suspended as exc:
        return PendingCompilation(
            address, reads.block, abi_signature(function), exc.reason, journal.dump(exc.reason), exc.blocker
        )
    finally:
        ACTIVE.reset(token)
