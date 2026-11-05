"""Read typed storage and account for a snapshot before supplying zero defaults.

Keys and trace words are candidates. Only recomputing their actual storage locations
accounts for slots. Unattributed slots never stand for a count of unknown holders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak

from .abi_values import abi_name
from .layout import _decode_word, _key_bytes, _size, _slots, _struct_fields, locate, storage_name
from .model import BudgetExceeded, Issue, Limits, Reads
from .terms import Term, subterms


@dataclass
class Snapshot:
    entries: dict[Any, list[tuple[tuple, Any]]] = field(default_factory=dict)
    accounted: set[int] = field(default_factory=set)
    unexplained: set[int] = field(default_factory=set)
    issues: list[Issue] = field(default_factory=list)
    preimages: dict[int, bytes] = field(default_factory=dict)
    slot_count: int | None = None

    @property
    def complete(self) -> bool:
        return not self.unexplained and not self.issues


class Storage:
    def __init__(self, reads: Reads, contracts: Any, limits: Limits, formula: Term):
        self.reads, self.contracts, self.limits = reads, contracts, limits
        self.snapshots: dict[Any, Snapshot] = {}
        self.constants = {int(t[1]) for t in subterms(formula, "const") if isinstance(t[1], (int, bool))}
        self.roots: dict[Any, set[tuple]] = {}
        self._traced: set[Any] = set()
        self._preimages: dict[int, dict[int, bytes]] = {}
        self._steps: dict[int, int] = {}
        self.work: dict[int, dict] = {}

    def contract(self, address: int, code: int | None = None):
        own = getattr(self.contracts, "own_code", None)
        return (
            own(code) if code is not None and own is not None else self.contracts.get(address if code is None else code)
        )

    @staticmethod
    def context(address: int, code: int | None):
        return address if code is None else (address, code)

    def register_root(self, address: int, name: Any, code: int | None = None) -> None:
        context = self.context(address, code)
        if isinstance(name, tuple) and name[:1] == ("slot",):
            roots = self.roots.setdefault(context, set())
            if name not in roots:
                roots.add(name)
                self.snapshots.pop(context, None)

    def read(self, address: int, name: Any, path: tuple, code: int | None = None) -> Any:
        contract = self.contract(address, code)
        where = locate(contract, name, path) if contract is not None else None
        if where is None:
            raise ValueError(f"storage_layout:{address:#x}:{name}")
        slot, offset, type_ = where
        if _size(type_) is None and type_ is not None:
            raise ValueError(f"storage_value:{type_}")
        return _decode_word(self.reads.storage(address, slot), offset, type_)

    def read_cell(self, address: int, slot: int, offset: int, width: int, abi: str) -> Any:
        """A placed scalar reads its recorded physical bytes, not another code view's field name."""
        from slither.core.solidity_types import ElementaryType

        type_ = ElementaryType(abi)
        if _size(type_) != width or not (0 <= offset and 0 < width <= 32 and offset + width <= 32):
            raise ValueError("physical_storage_layout")
        return _decode_word(self.reads.storage(address, slot), offset, type_)

    def bytes_header(self, address: int, name: Any, path: tuple, code: int | None = None) -> int:
        contract = self.contract(address, code)
        where = locate(contract, name, path) if contract is not None else None
        if where is None or str(where[2]) not in ("bytes", "string"):
            raise ValueError("ABI bytes storage layout")
        return self.reads.storage(address, where[0])

    def snapshot(self, address: int, code: int | None = None) -> Snapshot:
        context = self.context(address, code)
        if context in self.snapshots:
            return self.snapshots[context]
        contract = self.contract(address, code)
        if contract is None:
            raise ValueError(f"storage_layout:{address:#x}")
        result = Snapshot()
        self.snapshots[context] = result
        work = self.work.setdefault(
            address,
            {
                "address": f"0x{address:040x}",
                "limit": self.limits.storage_steps,
                "steps": 0,
                "passes": 0,
                "by_kind": {},
                "by_root": {},
            },
        )
        work["passes"] += 1
        dump = None

        def tick(kind: str, root=None) -> None:
            if self._steps.get(address, 0) >= self.limits.storage_steps:
                raise BudgetExceeded("storage accounting")
            self._steps[address] = self._steps.get(address, 0) + 1
            work["steps"] = self._steps[address]
            work["by_kind"][kind] = work["by_kind"].get(kind, 0) + 1
            if root is not None:
                label = str(root)
                work["by_root"][label] = work["by_root"].get(label, 0) + 1

        try:
            if self.limits.storage_steps <= 0:
                raise BudgetExceeded("storage accounting")
            dump = self.reads.storage_dump(address)
            result.slot_count = len(dump)
            result.unexplained = set(dump)
            words = self.reads.key_words(address) | self.constants | set(dump.values()) | {0, address}
            preimages = {}
            by_base: dict[bytes, set[bytes]] = {}
            # Verify once and index by the mapping base, rather than scanning every
            # preimage at every nested mapping. Hints still do not establish membership.
            for h, raw in self._preimages.get(address, {}).items():
                tick("preimage_checks")
                if int.from_bytes(keccak(raw), "big") != h:
                    continue
                preimages[h] = raw
                if len(raw) == 64:
                    by_base.setdefault(raw[32:], set()).add(raw[:32])
                words.add(h)
                words.update(int.from_bytes(raw[i : i + 32], "big") for i in range(0, len(raw) - 31, 32))
            result.preimages = preimages
            work["candidate_words"] = max(work.get("candidate_words", 0), len(words))
            work["verified_preimages"] = len(preimages)
            domains: dict[str, tuple[int, ...]] = {}
            sizes: dict[str, int | None] = {}

            def normalize(word: int, type_: Any) -> int | None:
                kind = abi_name(type_) or str(type_)
                if kind not in sizes:
                    sizes[kind] = _size(type_)
                size = sizes[kind]
                if size is None:
                    return None
                bits = 8 * size
                if kind.startswith("int"):
                    word %= 2**bits
                    return word - 2**bits if word >= 2 ** (bits - 1) else word
                return word if 0 <= word < 2**bits else None

            def keys_for(type_: Any, base: bytes) -> tuple[int, ...]:
                kind = abi_name(type_) or str(type_)
                if kind not in domains:
                    accepted = set()
                    for word in words:
                        tick("key_normalizations")
                        key = normalize(word, type_)
                        if key is not None:
                            accepted.add(key)
                        # A fixed bytes key in an ABI/event word is left-aligned. Both
                        # logical constants and canonical encoded words are candidates.
                        if kind.startswith("bytes") and kind != "bytes32" and kind[5:].isdigit():
                            shift = 256 - 8 * int(kind[5:])
                            if 0 <= word < 2**256 and word % 2**shift == 0:
                                accepted.add(word >> shift)
                    domains[kind] = tuple(sorted(accepted))
                known = set()
                for raw in by_base.get(base, ()):
                    tick("indexed_keys")
                    word = int.from_bytes(raw, "big")
                    if kind.startswith("bytes") and kind != "bytes32" and kind[5:].isdigit():
                        word >>= 256 - 8 * int(kind[5:])
                    key = normalize(word, type_)
                    if key is not None and _key_bytes(key, type_) == raw:
                        known.add(key)
                return (*sorted(known), *(key for key in domains[kind] if key not in known))

            def visit(name: Any, type_: Any, slot: int, offset: int, path: tuple) -> None:
                from slither.core.declarations import Structure
                from slither.core.solidity_types import ArrayType, MappingType, UserDefinedType

                tick("visits", name)
                slot %= 2**256
                if isinstance(type_, MappingType):
                    base = slot.to_bytes(32, "big")
                    if _size(type_.type_from) is None:
                        result.issues.append(Issue("enumeration", f"dynamic key: {type_.type_from}"))
                        return
                    for key in keys_for(type_.type_from, base):
                        tick("key_candidates", name)
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
                        tick("array_entries", name)
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
                            tick("byte_slots", name)
                            result.accounted.add((base + i) % 2**256)
                    return
                if _size(type_) is None:
                    result.issues.append(Issue("enumeration", f"storage type: {type_}"))
                    return
                result.accounted.add(slot)
                value = _decode_word(dump.get(slot, 0), offset, type_)
                result.entries.setdefault(name, []).append((path, value))

            for var in contract.storage_variables_ordered:
                name = storage_name(contract, var)
                where = locate(contract, name, ())
                if where is None:
                    result.issues.append(Issue("enumeration", f"layout: {var.name}"))
                else:
                    visit(name, where[2], where[0], where[1], ())
            for root in sorted(self.roots.get(context, ()), key=repr):
                where = locate(contract, root, ())
                if where is None:
                    result.issues.append(Issue("enumeration", f"layout: {root}"))
                else:
                    visit(root, where[2], where[0], where[1], ())
            result.unexplained = set(dump) - result.accounted
            if result.unexplained and context not in self._traced:
                self._traced.add(context)
                hints = self.reads.preimages(address, result.unexplained)
                if hints:
                    self._preimages.setdefault(address, {}).update(hints)
                    self.snapshots.pop(context)
                    result = self.snapshot(address, code)
                    return result
        except BudgetExceeded as exc:
            result.issues.append(Issue("budget", str(exc)))
        except Exception:
            self.snapshots.pop(context, None)  # an aborted read/layout must not leave an empty complete cache entry
            raise
        finally:
            if dump is not None:
                result.unexplained = set(dump) - result.accounted
            work["snapshot_slots"] = result.slot_count
            work["accounted_nonzero_slots"] = (len(dump) - len(result.unexplained)) if dump is not None else None
            work["unattributed_slots"] = len(result.unexplained) if dump is not None else None
            views = work.setdefault("views", {})
            views["default" if code is None else f"{code:#x}"] = (
                result.complete and self.snapshots.get(context) is result
            )
            work["complete"] = all(views.values())
        return result
