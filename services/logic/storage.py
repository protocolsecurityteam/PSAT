"""Read typed storage and account for a snapshot before supplying zero defaults.

Keys and trace words are candidates. Only recomputing their actual storage locations
accounts for slots. Unattributed slots never stand for a count of unknown holders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak

from .layout import _decode_word, _key_bytes, _named_type, _size, _slots, _struct_fields, locate
from .model import BudgetExceeded, Issue, Limits, Reads
from .terms import Term, subterms


@dataclass
class Snapshot:
    entries: dict[Any, list[tuple[tuple, Any]]] = field(default_factory=dict)
    accounted: set[int] = field(default_factory=set)
    unexplained: set[int] = field(default_factory=set)
    issues: list[Issue] = field(default_factory=list)
    preimages: dict[int, bytes] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return not self.unexplained and not self.issues


class Storage:
    def __init__(self, reads: Reads, contracts: Any, limits: Limits, formula: Term):
        self.reads, self.contracts, self.limits = reads, contracts, limits
        self.snapshots: dict[int, Snapshot] = {}
        self.constants = {int(t[1]) for t in subterms(formula, "const") if isinstance(t[1], (int, bool))}
        self.roots: dict[int, set[tuple]] = {}
        self._traced: set[int] = set()
        self._preimages: dict[int, dict[int, bytes]] = {}
        self._steps: dict[int, int] = {}

    def register_root(self, address: int, name: Any) -> None:
        if isinstance(name, tuple) and name[:1] == ("slot",):
            roots = self.roots.setdefault(address, set())
            if name not in roots:
                roots.add(name)
                self.snapshots.pop(address, None)

    def read(self, address: int, name: Any, path: tuple) -> Any:
        contract = self.contracts.get(address)
        where = locate(contract, name, path) if contract is not None else None
        if where is None:
            raise ValueError(f"storage_layout:{address:#x}:{name}")
        slot, offset, type_ = where
        if _size(type_) is None and type_ is not None:
            raise ValueError(f"storage_value:{type_}")
        return _decode_word(self.reads.storage(address, slot), offset, type_)

    def snapshot(self, address: int) -> Snapshot:
        if address in self.snapshots:
            return self.snapshots[address]
        contract = self.contracts.get(address)
        if contract is None:
            raise ValueError(f"storage_layout:{address:#x}")
        result = Snapshot()
        self.snapshots[address] = result
        try:
            dump = self.reads.storage_dump(address)
            words = self.reads.key_words(address) | self.constants | set(dump.values()) | {0, address}
            preimages = self._preimages.get(address, {})
            # An untrusted hint is usable only as a candidate. Its hash is checked locally.
            preimages = {h: p for h, p in preimages.items() if int.from_bytes(keccak(p), "big") == h}
            result.preimages = preimages
            words.update(preimages)
            for p in preimages.values():
                words.update(int.from_bytes(p[i : i + 32], "big") for i in range(0, len(p) - 31, 32))

            def tick() -> None:
                self._steps[address] = self._steps.get(address, 0) + 1
                if self._steps[address] > self.limits.storage_steps:
                    raise BudgetExceeded("storage accounting")

            def visit(name: Any, type_: Any, slot: int, offset: int, path: tuple) -> None:
                from slither.core.declarations import Structure
                from slither.core.solidity_types import ArrayType, MappingType, UserDefinedType

                tick()
                slot %= 2**256
                if isinstance(type_, MappingType):
                    base = slot.to_bytes(32, "big")
                    keys = set(words)
                    for raw in preimages.values():
                        if len(raw) == 64 and raw[32:] == base:
                            k = int.from_bytes(raw[:32], "big")
                            key_type = str(type_.type_from)
                            if key_type.startswith("bytes") and key_type != "bytes32" and key_type[5:].isdigit():
                                k >>= 8 * (32 - int(key_type[5:]))
                            keys.add(k)
                    for key in sorted(keys):
                        tick()
                        size = _size(type_.type_from)
                        if size is None:
                            result.issues.append(Issue("enumeration", f"dynamic key: {type_.type_from}"))
                            return
                        if str(type_.type_from).startswith("int"):
                            key %= 2 ** (size * 8)
                            if key >= 2 ** (size * 8 - 1):
                                key -= 2 ** (size * 8)
                        elif not 0 <= key < 2 ** (size * 8):
                            continue
                        encoded = _key_bytes(key, type_.type_from)
                        if encoded is None:
                            result.issues.append(Issue("enumeration", f"key encoding: {type_.type_from}"))
                            continue
                        child = int.from_bytes(keccak(encoded + base), "big")
                        # Composite values can occupy slots after the base, or a nested hash.
                        if _size(type_.type_to) is not None and child not in dump:
                            continue
                        visit(name, type_.type_to, child, 0, (*path, ("k", key)))
                    return
                if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
                    for member, (extra, off, inner) in _struct_fields(type_.type).items():
                        visit(name, inner, slot + extra, off, (*path, ("f", member)))
                    return
                if isinstance(type_, ArrayType):
                    if type_.length is None:
                        result.accounted.add(slot)
                        n = dump.get(slot, 0)
                        result.entries.setdefault(name, []).append(((*path, ("f", "length")), n))
                        base = int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")
                    else:
                        literal = getattr(type_, "length_value", None)
                        n = int(str(literal.value if literal is not None else type_.length), 0)
                        base = slot
                    size = _size(type_.type)
                    for i in range(n):
                        tick()
                        child = base + (i // (32 // size) if size else i * _slots(type_.type))
                        off = i % (32 // size) * size if size else 0
                        visit(name, type_.type, child, off, (*path, ("k", i)))
                    return
                if str(type_) in ("bytes", "string"):
                    result.accounted.add(slot)
                    word = dump.get(slot, 0)
                    if word & 1:
                        base = int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")
                        for i in range(((word - 1) // 2 + 31) // 32):
                            tick()
                            result.accounted.add((base + i) % 2**256)
                    return
                if _size(type_) is None:
                    result.issues.append(Issue("enumeration", f"storage type: {type_}"))
                    return
                result.accounted.add(slot)
                value = _decode_word(dump.get(slot, 0), offset, type_)
                result.entries.setdefault(name, []).append((path, value))

            for var in contract.state_variables_ordered:
                if var.is_constant or var.is_immutable:
                    continue
                where = locate(contract, var.name, ())
                if where is None:
                    result.issues.append(Issue("enumeration", f"layout: {var.name}"))
                else:
                    visit(var.name, where[2], where[0], where[1], ())
            for root in sorted(self.roots.get(address, ()), key=repr):
                type_ = _named_type(contract, root[2])
                if type_ is None:
                    result.issues.append(Issue("enumeration", f"layout: {root}"))
                else:
                    visit(root, type_, root[1], 0, ())
            result.unexplained = set(dump) - result.accounted
            if result.unexplained and address not in self._traced:
                self._traced.add(address)
                hints = self.reads.preimages(address, result.unexplained)
                if hints:
                    self._preimages[address] = hints
                    self.snapshots.pop(address)
                    return self.snapshot(address)
        except BudgetExceeded as exc:
            result.issues.append(Issue("budget", str(exc)))
        return result
