# PSAT Assessment model

PSAT has one durable analytical document: `Assessment`. Static IR and chain
reads are inputs; database rows and API shapes are projections, not competing
claim ledgers.

Static facts, predicate trees, and effects are embedded in the static Evidence
record. They are never emitted as parallel job artifacts.

## Twelve records

```text
Assessment
├── Contract
├── Function
├── Controller
├── Entity
├── Effect
├── Authority
├── Proposition
├── Evidence
├── Claim
├── Analysis
└── Diagnostic
```

Domain maps use natural keys:

- functions use their canonical signature;
- controllers use their analyzer/controller key;
- entities use `chain_id:normalized_address`.

There are no `*Id`, `*Ref`, or `*Model` types and no duplicate `id` inside a
map value. Claims and evidence alone use deterministic content keys because
claims cite evidence and prior claims without embedding duplicate derivation
graphs.

`Claim` contains a supported proposition, its rule, and its evidence/prior
claim keys. A failed detector, rejected candidate, missing RPC response, or
unsupported code shape is never a claim; it belongs to `Analysis` as an
omission or `Diagnostic`.

Function identity stays source-readable without confusing source types with
ABI types. The function map key is the analyzer's source signature; each
`Function` also carries its canonical ABI signature when known and its selector.
Policy and execution joins use the same resolver: source signature first, exact ABI identity, then a unique
selector. A selector collision is an omission, never an arbitrary match.

Calling authority and effects are separate propositions:

```text
function_authority:  role 8 may call setAuthority(Authority)
function_effect:     setAuthority(Authority) replaces authority
authority_capability cites both claims
```

This separation lets Assessment represent a proven caller even when the
function's effect is not classified. Relational `FunctionPrincipal` rows are
projected from the policy evidence owned by these claims rather than from a
second resolver output. The permission projection takes only Assessment; it
cannot retain a rejected function from a second input. Unresolved attempts
remain observations and omissions, with no positive caller claim.

Controller read and tracking fields reuse the structured analyzer types. Root
and recursive analysis use one monitoring-plan compiler. Validation is strict
at the read and write boundary, retaining extension fields without coercing
incorrect values into the declared types.

```text
pause.set claim exists                     -> true
no claim + detector completed full scope   -> false
no claim + partial/failed/missing analysis -> null
```

Authority is one recursive record. Its `kind` preserves public, entity,
controller, role, `any`, `all`, and exact conditional/threshold expressions.
Reducing the type surface must never flatten those semantics.

## Pipeline boundary

```text
static facts and effect IR
            |
            v
        Assessment <--- observations
            |
            +------ <--- resolved entities and relationships
            |
            +------ <--- authority capability derivation
            v
 relational indexes and UI projections
```

Each stage atomically replaces the claims and evidence named by its previous
Analysis receipt. Withdrawing a prerequisite retracts dependent claims and
marks their analysis incomplete. Execution refreshes include all stored
verdicts for the affected contract, including functions outside the current
scheduling batch. Unknown fields survive validation, but malformed references
and incorrectly typed values fail at the artifact boundary.

## Cutover

The wire is `assessment/5`; static materializations use schema version 10.
Older analytical documents must be regenerated.

Migration `d58b239c7e10` removes the retired physical columns and normalizes
retired monitored-contract categories to `regular`. It has no data-restoring
downgrade. For an existing deployment, back up the database, stop old API,
worker, browser, and monitor processes, run migrations, and start the new
application. Use a fresh preview database or reanalyze its contracts before
assessing the new results. This cutover must not run alongside old processes.
