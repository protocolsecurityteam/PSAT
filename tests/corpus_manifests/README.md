# Corpus manifests

YAML files in this directory pin the **expected semantic predicate-pipeline
output** for representative real-protocol contract shapes. The harness
in `tests/static/test_corpus_manifests.py` parametrizes one test per manifest:

1. Compile the contract source (inline in the YAML or a path to
   `tests/corpus_manifests/contracts/*.sol`).
2. Run `build_predicate_artifacts` on the subject contract.
3. Assert each function listed in `expected_functions` has the
   declared `authority_role` / `kind` / `confidence` / `unsupported_reason`.
4. Assert any function listed under `unguarded` is absent from the
   semantic trees dict.

These are the **cutover-gate fixtures** for #18 — when a manifest's
expected output stops matching, either the semantic pipeline regressed
or a real-world shape changed. Add manifests as the pipeline grows
to cover new protocols.

## Schema

```yaml
contract_name: C                # required — name of the subject contract
description: short text         # optional — human-readable summary
source: |                       # required (or `source_path:`)
  pragma solidity ^0.8.19;
  contract C { ... }
source_path: contracts/oz_role.sol  # alternative to inline `source`

expected_functions:
  "f()":
    authority_role: caller_authority   # required
    kind: equality                     # optional, "membership"|"equality"|...
    confidence: high                   # optional
    operator: eq                       # optional
    unsupported_reason: opaque_try_catch  # optional, only for unsupported leaves
    references_msg_sender: true        # optional
    parameter_indices: [0]             # optional, exact list

unguarded:                             # optional — these functions must NOT
  - "open()"                           #   appear in semantic trees (resolver = public)
```

Field semantics:
- `expected_functions` keys are full function signatures (e.g. `"transfer(address,uint256)"`).
- Per-function fields are matched against the semantic leaf for that function.
  When the function's tree is composite (AND/OR), the harness walks
  every leaf and picks the **first** matching one — multi-leaf
  expectations need explicit handling per manifest (see
  `oz_pausable.yaml` for the pattern).
- Listing a function in `unguarded` and `expected_functions` simultaneously
  is a manifest error and the harness will fail the test.

## Adding a manifest

1. Create `<protocol>.yaml` here.
2. Drop your Solidity in either inline `source:` or
   `contracts/<protocol>.sol` and reference via `source_path:`.
3. Run `pytest tests/static/test_corpus_manifests.py::test_corpus_manifest -k <name>`.
4. The test fails on the first divergence — iterate on the manifest
   or extend the semantic pipeline until it passes.
