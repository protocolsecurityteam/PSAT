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
Policy joins by source signature first, then exact ABI identity, then a unique
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
second resolver output.

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
Analysis receipt. Unknown fields survive validation, but malformed references
fail at the artifact boundary.
