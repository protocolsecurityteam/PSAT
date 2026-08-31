# PSAT assessment model

PSAT has one durable analytical document: `Assessment` in
`schemas/assessment.py`. Static IR and raw chain data are inputs; database rows
are query indexes. Neither is a second claim ledger.

## Types

```text
Assessment
├── Account, Contract, Function, Controller, Entity
├── Evidence
├── Claim
│   ├── proposition
│   └── Basis (rule + evidence ids + prior claim ids)
├── Analysis
│   ├── Coverage
│   ├── Omission
│   └── Diagnostic
├── AuthorityEdge
└── DependencyEdge
```

A claim contains only a supported proposition. A failed detector, rejected
candidate, missing RPC response, or unsupported code shape is not a claim. It is
recorded by the relevant `Analysis` receipt.

Example:

```text
Evidence: pause() writes paused = true
Evidence: withdraw() necessarily reads that latch
Basis:    pause-latch/v1 over those evidence ids
Claim:    pause() has pause.set and affects withdraw()
```

Authority is independent of effect. The effect above can be paired with an
`AuthorityCapability` saying that an entity, role, controller, or the public can
invoke it.

## Absence

There is no `Determination[T]` wrapper and no failure-shaped claim.

```text
pause.set claim exists                         -> true
no claim + pause.set analysis fully completed -> false
no claim + partial/failed/missing analysis     -> null
```

`services.assessment.views` owns these projections. A consumer must not infer
false from a missing claim without checking coverage.

## Pipeline boundary

```text
static facts + predicate/effect IR
              |
              v
          Assessment  <--- controller observations
              |
              +------ <--- resolved entities and relationships
              |
              +------ <--- authority-capability derivation
              v
      relational query indexes / UI views
```

Workers read and update `assessment`; they do not persist separate snapshot,
control-graph, effective-permissions, or principal-label documents. Algorithms
that still operate on batch dictionaries receive transient projections from
`services.assessment.runtime`.

The assessment loader validates both the TypedDict shape and every stable-id
cross-reference. Unknown fields survive validation so a newer producer is not
silently truncated by an older reader.
