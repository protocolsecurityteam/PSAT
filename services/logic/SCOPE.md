# Effect scope

**Status: unverified label, no oracle.** The `self` / `shared` / `none` label below has no independent oracle (no
chain run can say whose positions a write touches in every state), so nothing tests it and nothing may rest on it:
its label tests were deleted on 2026-10-24. The classifier stays in code, off by default (`PSAT_LOGIC_SCOPE_SKIP`
unset); a verdict's `scope` field is informational only. The one test left (`test_scope_review`) checks only that
facts a budget cut off are cached as "everything checked", the conservative side. The skip path itself is tested
without trusting the label (`test_scope_skip`, and two fault columns of `test_failsafe`: skipping on with the
classifier's labels, and with every function labelled `self`): the worst a wrong label can do is lose holders into
a list never complete that says `self_scoped`.

Principle: the rule is conservative. A function is `self` only when every write it can make is shown, from the
lowering alone, either to stay in an entry the caller holds or to move value out of one with the total conserved;
whatever can't be shown is `shared`. A false `shared` costs enumeration time; a false `self` would hide holders.
Nothing is matched by name, interface or token shape. Skipping enumeration on `self` is opt-in and off by default
(see the last section), so by default scope is only reported.

## Contract facts (`scope.contract_facts`, once per contract)

Every entry point is lowered, views, pure functions and the constructor included, and each way it returns read:

- **checked**: every storage location (variable and field path) read in any exit's path condition, whatever the
  condition is about, and every location the values it writes read from other variables (value flow:
  `balances[u] = balances[u] * price[r]` makes `price` checked). Each exit counts on its own, so an early return's
  guard (`if (blocked[caller]) return;`) counts though the union of the exits drops it. A conjunct `d <= E` on an
  exit that itself debits `E` by `d` is a bound on that entry, not a check of anyone, and is not counted.
- **everything checked**: when any exit's condition reads a raw slot, when an entry point was lowered only in part
  (a write lost, recursion or depth leaving an `unanalysed` call in a condition, assembly `sload` it couldn't
  place), or when the facts can't be had at all (a lowering that raises or runs out of time; this is cached, so
  the cost is paid once per contract). Then no write in the contract is `self`.
- **public**: public state variables (other contracts can read their getters) and every variable any entry point
  returns (views or not).
- **forgeable**: variables some entry point writes with a first key that is not the caller's own position (the
  caller, or a hash whose first input is the caller and whose other inputs name nobody). If any write is lost to
  the lowering or lands on a raw slot (an assembly `sstore`), every variable counts as forgeable.

Assembly is seen through the lowering: Yul and legacy `call`, `callcode`, `delegatecall`, `create`, `create2` and
`selfdestruct` record a call-out mark like their Solidity equivalents, `sstore` a raw write, `log0`..`log4` an
event, `sload` a raw read. `staticcall` changes no state and records none.

## Classing one function's writes (`scope.classify`)

The function is `shared` outright when the lowering lost track of a write or its nodes can't be read. Exits whose
path condition is false are skipped (`selfdestruct` is a successful exit). Per remaining exit, per write to
`E[k, rest...]` (`k` its first key):

- An event or transient write is ignored. A call-out mark (a call with an effect, ether sent, a contract created,
  `selfdestruct`, a delegatecall), a raw slot, or another contract's storage is **shared**.
- A write of the value already there is ignored; a constant the same path condition requires the location to hold
  (`locked == 1` then `locked = 1`) is **unchanged**.
- A write to checked storage is **shared** (same variable, one field path a prefix of the other).
- **own** position: `k` is the caller, or a hash whose first input is the caller and whose other inputs name
  nobody. **held** position: `k` is no constant and mentions no caller, origin or signer (an address argument or
  an id qualifies), and a conjunct of the path condition requires the caller to hold it: `caller == O[...]` where
  `O`'s keys are `k`, constants or the caller (never a key the caller picks) and `O` is not forgeable; or a
  disjunction with such a branch whose other branches each require `G[O[...]][caller]` set; or `k` is an address
  argument and a conjunct requires `G[k][caller]` set. `G` must not be forgeable. "Set" means the flag itself,
  `G != 0`, or `x < G`; `x <= G` is not (x may be zero).
- A **decrease** is `E - d` where the value is an unsigned integer by its declared type, and either every node of
  the function is checked arithmetic (solc 0.8 or later, no `unchecked`) or the same exit requires `d <= E`.
- own or held and a decrease: **own** / **authorized**, and the debit `d` is recorded for
  (variable, fields, keys after the first).
- own or held, not public, value zero: **own** / **authorized**.
- held, not public, a replacement that reads no storage (no `load`, no `rawload`) and is no sum (an approval, a
  new owner): **authorized**.
- Otherwise a credit `E + d` (or `ite(caller == to, ...)` over a write this exit already made) matched to one
  recorded debit of `d` at the same variable, fields and keys after the first is a **credit**, whoever receives
  it (another holder, this contract, a treasury): value moved, total conserved. Each debit pays for one credit.
  Anything else is **shared**.

`self`: no shared write and at least one that is not unchanged. `none`: nothing written besides unchanged.

## Known limits

- **Readers outside the entry points**: storage read only by an internal function no entry point reaches, or only
  by another contract that doesn't go through a getter or return value, isn't checked (`Internal.lowerLimit`).
- **Value flow beyond storage writes**: a value pushed to another contract as a call argument, or returned, is
  not flow (a return makes the variable public instead). Flow into this contract's own writes is counted
  (`Oracle2.retract` and `lower` are shared because `settle` writes `balances[u] * price[r]`).
- **Holders by sybil**: a held lookup that every account sets for itself is not forgeable, so a new account can
  hold it; the decision (not scope) is what says whether a stranger gets through.

## What scope changes (`decide`)

By default nothing: scope, the classified writes and the gate (`Verdict.gate`, the success condition minus `when`
conditions that read nothing the caller sends) are reported for a `self` function, and its holders are enumerated
as for any function. With `PSAT_LOGIC_SCOPE_SKIP=1` (`decide.SKIP_SELF_SCOPED`), a `self` function skips testing
holders one by one, and only when the stranger fails in every state of the `when` conditions, unseen addresses are
shown to fail like it (representative coverage, or a decisive conjunct), and whether a stranger could arrange its
own entries first is known (`world.arrange_unknown` false). Every open the decision reaches (a stranger passing,
on the formula or on the chain, an arrangement, a call of its own first) comes before the skip and is untouched by
it. The builder still runs: a list it shows empty is decided in full (nobody, ever, at no cost), never skipped.
Before skipping, every stranger's own call (`_STRANGERS`) is run on the chain: one going through where the formula
refuses all is the formula being wrong, not determined (`self_scoped`, `self_scoped_ran`). Else the row is
restricted, never complete, with gap `self_scoped`, its gate and, when the list is shown whole, how many it names
(`Verdict.members`). The pass script's `--scope-skip` says both runs skipped; it always prints how many new rows were
skipped and each skipped row where a holder the harness replayed (prod's) goes through, so a wrong label shows in
the corpus diff.

Python lines in the engine and its tests, and this note's lines, are at most 120 columns (the repo's ruff setting).
