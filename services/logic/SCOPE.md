# Effect scope

A function is **self-scoped** when every effect a successful call can have stays inside positions the caller holds;
anything else is **shared**. Scope is read off the lowered exits (`Lowerer.exits`: each way the call returns, with its
path condition and storage writes), never from names, interfaces or token shapes. Each write on each exit is one of:

- **own**: an entry keyed by the caller (a key is `msg.sender`, or a hash whose one identity input is the caller).
- **authorized**: an entry keyed by `k` where that exit's path condition requires the caller to hold `k`: a conjunct
  `caller == O[..k..]`, or a disjunction whose every branch is that or an entry the holder `O[..k..]` keeps for the
  caller (`approvals[O[k]][caller]`); or `k` is an address argument and the condition reads an entry keyed
  `[k][caller]` (what `k` granted the caller).
- **credit**: `E[x] = E[x] + d` where the same exit debits an own or authorized entry of the same variable and field
  by the same `d`: value moved out of the caller's position, not created.
- **unchanged**: a constant equal to what the location holds at the block (a lock set and reset), read on chain.
- **shared**: everything else: globals (totals, parameters, pause flags, implementation slots), entries keyed by
  arguments or other principals without the above, raw slots, calls out with an effect, delegatecalls, ETH sent,
  and any write the lowering may have lost (code not followed, assembly calls).

Self-scoped means no shared write on any exit and at least one write that changes something. Its gate is reported
as a condition (`Verdict.gate`) with `scope="self"` and the classified writes; holders are not enumerated (no
per-candidate tests, storage dumps or traces), so the row is restricted with gap `self_scoped`, never a complete
list. Open and undetermined are still decided as for any function; a state where a stranger may pass, or an unseen
address not shown to fail like a stranger, falls back to full enumeration. Shared functions, and `none` (nothing
written that the lowering sees, which is no proof of no effect), keep full enumeration.
