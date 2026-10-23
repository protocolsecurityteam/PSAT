# Effect scope

`scope.classify` reads each way a function returns (`Lowerer.exits`: path condition and storage writes) and classes
every write; nothing is matched by name, interface or token shape. Exits whose path condition is false are skipped
(`selfdestruct` is a successful exit, not one of them). For a write to entry `E[k, ...]`, `k` its first key:

- **own**: `k` is the caller, or a hash whose first input is the caller and whose other inputs name nobody; and the
  value is a debit `E - d` or zero. Anything else written there (a raise, a flag set) is shared.
- **authorized**: `k` names no identity and the exit's path condition requires the caller to hold it: a conjunct
  `caller == O[..k..]`; or a disjunction with such a branch whose other branches each require an entry
  `G[O[..k..]][caller]` set (the holder's grant); or `k` is an address argument and a conjunct requires
  `G[k][caller]` set (`G`, `G != 0`, or `x < G` / `x <= G`). The value is a debit, zero, or a plain replacement
  that reads no storage (an approval, a new owner).
- **credit**: `E[x] = E[x] + d` matched by one debit of `d`, on the same exit, of an own or authorized entry of the
  same variable and fields; each debit pays for one credit.
- **unchanged**: a constant the same path condition requires the location to already hold (`locked == 1` then
  `locked = 1`). Read off the condition, never off the chain.
- **shared**: everything else: globals, entries keyed by arguments or other principals, raw slots, a call out with
  an effect, ether sent, a contract created, `selfdestruct`, delegatecalls, assembly calls, and any write the
  lowering may have lost.

Then every own, authorized or credit write to a variable that any entry point's caller checks read (any conjunct
of its success condition that involves who calls, the function itself included) becomes shared: writing it changes
who passes some check (`approvedHashes[caller][h]`, `roles[r][caller]`). If an entry point can't be lowered, all
writes are shared.

`self`: no shared write and at least one that isn't unchanged. `none`: nothing written besides unchanged. Only
`self` changes the decision: holders aren't enumerated, and the row is restricted with gap `self_scoped` and its
gate (`Verdict.gate`). A stranger who may pass in some state, or unseen addresses not shown to fail like a
stranger, sends it to full enumeration. `shared` and `none` keep full enumeration.
