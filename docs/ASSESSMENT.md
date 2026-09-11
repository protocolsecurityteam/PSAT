# PSAT Assessment model

PSAT has one canonical analytical ledger, `Assessment`. It consists of four
immutable row families: Subject, Evidence, Claim, and Analysis. Current state,
history, and proposal scenarios are selections over those same rows; relational
indexes and UI payloads are rebuildable projections.

| Row | Meaning |
| --- | --- |
| Subject | Stable identity such as an address, code version, function, controller, role, proposal, or operation |
| Evidence | One immutable observation with content-addressed bytes and exact provenance |
| Claim | A typed proposition with code, point, interval, scenario, or reported scope and all proof inputs |
| Analysis | One actual attempt with implementation identity, inputs, outputs, coverage, and diagnostics |

Supporting tables store payload bytes, reusable contexts, implementation
manifests, proof edges, publication membership, corrections, coverage, and
diagnostics. They are relationships or metadata, not competing truth stores.

There is no schema-version field in the public Assessment response or on its
analytical rows. Controlled categories are enums. IDs, hashes, addresses,
timestamps, amounts, paths, and messages remain data.

## Updates and history

An update never mutates an earlier observation or claim. A new block produces
new Evidence and a new scoped Claim. The publication at block 100 can therefore
say owner A, block 200 can say owner B, and block 300 can say owner A again
without inventing one continuous A interval.

A block number alone is not an exact chain point. Exact point selection requires
the block hash; imported reports without one use `reported` scope. Event-derived
intervals retain block, transaction, and log ordering at both boundaries.

Corrections and reorgs append a correction Analysis. They preserve the target
rows but make the corrected proof and all transitive dependants ineligible at
the selected knowledge time. An older knowledge-time query still reproduces
what was known before the correction.

Identical claims are content-addressed independently of run ID and publication
time. A rerun creates a new Analysis and `analysis_outputs` link while reusing
the Claim. Independent proofs remain separate Claims, so correcting one does
not erase another.

## Governance and scenarios

Configuration parameters, proposal states, operation states, and proposal-to-
configuration bindings use typed Claim kinds. A proposal binding cites the
exact configuration Claim consulted at creation, snapshot, scheduling, or
execution; a later global configuration update does not rewrite that binding.

A scenario context is content-addressed from its concrete baseline, ordered
top-level actions, and explicit assumptions. Scenario claims name the context
and step. Scenario publications are excluded from observed-current selection
unless their context ID is explicitly requested. Repeating the same scenario
reuses its context and claims while retaining every Analysis attempt.

## Pipeline boundary

```text
source/code + chain/event/execution inputs
                    |
                    v
       Subject -> Evidence -> Claim
                    ^           |
                    |           v
                 Analysis -- analysis_outputs
                                |
                                v
              functions / principals / graph / API
```

Policy conclusions include controller observations and prerequisite claims.
Principal classification occurs before projection; permission and label writers
perform no fresh classification. Function-principal graph nodes are published
as `policy.principal_graph` evidence before graph tables are rebuilt.

Principal history is event-backed where transaction ordering and hashes are
available. Old reports are retained as source payloads and `reported` evidence
rather than being upgraded into stronger facts. Failures, omissions, unsupported
semantics, and incomplete coverage belong to Analysis, never to positive Claim.

The public assessment endpoint returns row arrays plus context, implementation,
payload metadata, and correction tables. Evidence refers to shared payload IDs
instead of copying large bodies. See the [complete schema](ASSESSMENT_SCHEMA_PROPOSAL.md)
and [cutover guide](ASSESSMENT_CUTOVER.md).
