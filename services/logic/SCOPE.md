# Effect scope

Principle: the rule is conservative. A function is `self` only when every write it can make is shown, from the
lowering alone, to stay inside a position the caller holds; whatever can't be shown is `shared`. A false `shared`
costs enumeration time; a false `self` hides holders. Nothing is matched by name, interface or token shape.

## Contract facts (`scope.contract_facts`, once per contract)

Every entry point is lowered, views, pure functions and the constructor included, and each way it returns read:

- **checked**: every storage location (variable and field path) read in any exit's path condition, whatever the
  condition is about. Each exit counts on its own, so an early return's guard (`if (blocked[caller]) return;`)
  counts though the union of the exits drops it.
- **everything checked**: when any exit's condition reads a raw slot (`rawload`), when any function's inline
  assembly contains `sload(`, or when an entry point can't be lowered. Then no write in the contract is `self`.
- **public**: public state variables (other contracts can read their getters) and every variable a view or pure
  entry point returns.
- **forgeable**: variables some entry point writes keyed first by anything but the caller. If any write is lost
  to the lowering or lands on a raw slot, every variable counts as forgeable.

## Classing one function's writes (`scope.classify`)

The function is `shared` outright when the lowering lost track of a write or its nodes can't be read, or its
inline assembly calls out, creates, destroys or delegatecalls. Exits whose path condition is false are skipped
(`selfdestruct` is a successful exit). Per remaining exit, per write to `E[k, rest...]` (`k` its first key):

- An event or transient write is ignored. A call out with an effect (ether sent, a contract created,
  `selfdestruct`), a raw slot, another contract's storage, or any delegatecall is **shared**.
- A write of the value already there is ignored; a constant the same path condition requires the location to hold
  (`locked == 1` then `locked = 1`) is **unchanged**.
- A write to checked storage is **shared** (same variable, one field path a prefix of the other).
- **own** position: `k` is the caller, or a hash whose first input is the caller and whose other inputs name
  nobody. **held** position: `k` names no identity and a conjunct of the path condition requires the caller to
  hold it: `caller == O[...]` where `O`'s keys are `k`, constants or the caller (never a key the caller picks);
  or a disjunction with such a branch whose other branches each require `G[O[...]][caller]` set; or `k` is an
  address argument and a conjunct requires `G[k][caller]` set. `G` must not be forgeable. "Set" means the flag
  itself, `G != 0`, or `x < G`; `x <= G` is not (x may be zero).
- A **decrease** is `E - d` where the value is an unsigned integer by its declared type, and either every node of
  the function is checked arithmetic (solc 0.8 or later, no `unchecked`) or the path requires `d <= E`.
- own or held and a decrease: **own** / **authorized**, and the debit `d` is recorded for
  (variable, fields, keys after the first).
- own or held, not public, value zero: **own** / **authorized**.
- held, not public, a replacement that reads no storage and is no sum (an approval, a new owner): **authorized**.
- Otherwise a credit `E + d` (or `ite(caller == to, ...)` over a write this exit already made) matched to one
  recorded debit of `d` at the same variable, fields and keys after the first is a **credit**; each debit pays
  for one credit. Anything else is **shared**.

`self`: no shared write and at least one that is not unchanged. `none`: nothing written besides unchanged.

## What scope changes (`decide`)

Only `self`, and only when the stranger fails in every state of the `when` conditions, unseen addresses are shown
to fail like it (representative coverage, or a decisive conjunct), and whether a stranger could arrange its own
entries first is known (`world.arrange_unknown` false). Then holders are not tested one by one: the builder still
runs, and a list it shows empty gives restricted, complete, nobody; else the row is restricted with gap
`self_scoped`, its gate (`Verdict.gate`: the success condition minus `when` conditions that read nothing the
caller sends) and, when the list is shown whole, how many it names (`Verdict.members`). Every other case, and
`shared` and `none`, keeps full enumeration.

Python lines in the engine and its tests, and this note's lines, are at most 120 columns (the repo's ruff setting).
