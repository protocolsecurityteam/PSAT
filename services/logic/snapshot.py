"""Accounting for a contract's whole storage: what lists a lookup's holders when no event does.

A dump of every nonzero storage word at the block (``Chain.storage_dump``) gives each slot as the hash it sits at,
never the key it was hashed from. Each slot the contract's layout reaches under keys already known (its variables,
mapping entries at those keys two levels deep, struct fields, arrays to their stored length, long bytes) is
accounted for. Whoever holds an entry of a lookup that no known key reaches does so at a slot left over, holding
that slot's word. So a lookup is listed whole once a stranger whose entry held any leftover word still fails
(``decide._snapshot_listed``): the known holders are all its holders that pass.

Keys at a lookup's identity position count only when they are candidates the decision asks about; any other
variable's entries may be reached by any word the contract's events or storage hold (a token's holders), since
reaching them only says whose they are.
"""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

_SPENT = 300_000  # slot computations per accounting, at most: past it the rest stays unaccounted for
_ARRAY_ITEMS = 4096  # items of a dynamic array walked one by one (a composite item type), at most
_ARRAY_SLOTS = 1 << 20  # slots of a dynamic array of plain items marked, at most
_CONSTANT_SPAN = 16  # slots marked from each 32-byte constant in the code (a proxy's slot, a namespace's root)
_DEPTH = 2  # mapping levels followed


def _hash(data: bytes) -> int:
    return int.from_bytes(keccak(data), "big")


def _is_address(type_: Any) -> bool:
    from slither.core.declarations import Contract
    from slither.core.solidity_types import ElementaryType, UserDefinedType

    if isinstance(type_, ElementaryType):
        return str(type_) in ("address", "address payable")
    return isinstance(type_, UserDefinedType) and isinstance(type_.type, Contract)


def code_constants(code: bytes) -> set[int]:
    """The 32-byte constants a bytecode pushes (``PUSH32``): fixed slots it reads directly (an EIP-1967 slot, a
    namespaced root), never anyone's entry."""
    out: set[int] = set()
    i = 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:
            width = op - 0x5F
            if width == 32 and i + 33 <= len(code):
                out.add(int.from_bytes(code[i + 1 : i + 33], "big"))
            i += width
        i += 1
    return out


class Accounting:
    """The slots of ``dump`` the layout reaches. ``target_keys``: the keys allowed at an identity position of a
    ``targets`` variable (the candidates); ``keys``: those allowed anywhere else, ``first`` of them tried first."""

    def __init__(
        self,
        contract: Any,
        dump: dict[int, int],
        keys: set[int],
        target_keys: set[int],
        targets: set,
        first: frozenset[int] = frozenset(),
    ):
        self.contract = contract
        self.dump = dump
        self.keys = sorted(keys, key=lambda k: (k not in first, k))
        self.address_keys = sorted(k for k in keys if k < 2**160)
        self.target_keys = sorted(k % 2**160 for k in target_keys)
        self.targets = targets
        self.reached: set[int] = set()
        self.used: set[int] = set()  # keys that reached a slot holding something
        self.spent = 0
        self.shallow = False

    def run(self, roots: list[tuple[int, Any]] = (), constants: set[int] = frozenset()) -> set[int]:
        from .decide import locate

        variables = [v for v in self.contract.state_variables_ordered if not (v.is_constant or v.is_immutable)]
        located = [(var, locate(self.contract, var.name, ())) for var in variables]
        # Everything but mapping entries first, cheaply; then the lookups in question before the rest: a budget spent
        # on a token's balances leaves only those unaccounted for.
        for shallow in (True, False):
            self.shallow = shallow
            for slot, type_ in roots:
                self._visit(type_, slot, 0, True)
            for var, found in sorted(located, key=lambda vf: vf[0].name not in self.targets):
                if found is not None:
                    self._visit(found[2], found[0], 0, var.name in self.targets)
        for c in constants:
            self.reached.update((c + i) % 2**256 for i in range(_CONSTANT_SPAN))
        return self.reached

    def _mark(self, slot: int) -> None:
        self.reached.add(slot % 2**256)

    def _visit(self, type_: Any, slot: int, depth: int, target: bool) -> None:
        from slither.core.declarations import Structure
        from slither.core.solidity_types import ArrayType, ElementaryType, MappingType, UserDefinedType

        from .decide import _key_bytes, _size, _slots, _struct_fields

        if self.spent > _SPENT:
            return
        self.spent += 1
        if isinstance(type_, MappingType):
            if depth >= _DEPTH or self.shallow:
                return
            if _is_address(type_.type_from):
                keys = self.target_keys if target else self.address_keys
            else:
                keys = self.keys
            base = slot.to_bytes(32, "big")
            simple = _size(type_.type_to) is not None
            for k in keys:
                key = _key_bytes(k, type_.type_from)
                if key is None:
                    continue
                child = _hash(key + base)
                self.spent += 1
                if simple:
                    self._mark(child)
                    if child in self.dump:
                        self.used.add(k)
                    continue
                self._visit(type_.type_to, child, depth + 1, target)
                if any((child + i) % 2**256 in self.dump for i in range(min(_slots(type_.type_to), 64))):
                    self.used.add(k)
                if self.spent > _SPENT:
                    return
            return
        if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
            for extra, _, field_type in _struct_fields(type_.type).values():
                self._visit(field_type, slot + extra, depth, target)
            return
        if isinstance(type_, ArrayType):
            item = type_.type
            size = _size(item)
            if type_.length is not None:
                count = _slots(type_)
                if size is not None:
                    self.reached.update((slot + i) % 2**256 for i in range(count))
                    return
                per = _slots(item)
                for i in range(min(count // max(per, 1), _ARRAY_ITEMS)):
                    self._visit(item, slot + i * per, depth, target)
                return
            self._mark(slot)
            length = self.dump.get(slot % 2**256, 0)
            base = _hash((slot % 2**256).to_bytes(32, "big"))
            if size is not None:
                per = 32 // size
                count = min((length + per - 1) // per, _ARRAY_SLOTS)
                self.reached.update((base + i) % 2**256 for i in range(count))
                return
            per = _slots(item)
            for i in range(min(length, _ARRAY_ITEMS)):
                self._visit(item, base + i * per, depth, target)
            return
        if isinstance(type_, ElementaryType) and str(type_) in ("bytes", "string"):
            self._mark(slot)
            word = self.dump.get(slot % 2**256, 0)
            if word & 1:
                base = _hash((slot % 2**256).to_bytes(32, "big"))
                self.reached.update((base + i) % 2**256 for i in range(min(((word - 1) // 2 + 31) // 32, 1 << 16)))
            return
        self._mark(slot)


def creation_keys(chain: Any, address: int, contract: Any) -> frozenset[int] | None:
    """The addresses the constructor keyed entries by: words the creating transaction's calls carry that account for
    the storage it left (``Chain.creation_trace``). ``None`` unless every slot it left is accounted for, so no key it
    wrote under is missing."""
    from .decide import _LOWEST_SENDER, _runtime_code

    memo = chain._memo
    key = ("creation_keys", address)
    if key in memo:
        return memo[key]
    memo[key] = None
    trace = chain.creation_trace(address)
    if trace is None:
        return None
    words, storage = trace
    # Its own address too (``_grantRole(DEFAULT_ADMIN_ROLE, address(this))``), and the code's constants and zero as
    # the other keys (``PROPOSER_ROLE``, ``DEFAULT_ADMIN_ROLE``), never as an address keyed: tried first, few beside
    # the trace's words.
    words = {*words, address}
    constants = code_constants(_runtime_code(contract))
    code = chain.code(address)
    if isinstance(code, bytes):
        constants |= code_constants(code)
    every = {v.name for v in contract.state_variables_ordered}
    accounting = Accounting(contract, storage, words | constants | {0}, words, every, frozenset(constants | {0}))
    reached = accounting.run((), constants)
    if any(slot not in reached for slot in storage):
        return None
    memo[key] = frozenset(k % 2**160 for k in accounting.used if k in words and _LOWEST_SENDER <= k % 2**160)
    return memo[key]
