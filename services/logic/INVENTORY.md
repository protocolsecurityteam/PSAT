# Restructure inventory

The old decision policy is preserved in Git at `5d7bca54`, not in a second runtime implementation.

| Area | Result |
| --- | --- |
| `lower.py`, `terms.py`, `yul.py`, `immutables.py` | Retained compiler/value machinery; typed return and assembly word improvements folded in; conservative unknown handling |
| `layout.py` | Extracted physical storage packing and addressing from old `decide.py` |
| `model.py`, `formula.py` | Full predicates, effect guards and guarded updates; verified read-only callee following |
| `solver.py`, `expansion.py` | Explicit expansion of saved predicates; finite/cofinite/symbolic projections |
| `storage.py` | Snapshot attribution, candidate keys, verified trace preimages and composite-key matches |
| `clients/logic_reads.py` | Transport, retries and bounded acquisition outside the core |
| `resolution/logic_composition.py` | Explicit-sequence symbolic state composition outside the core |
| `deployment.py` and resolution worker | Formula-only artifact by default; no automatic expansion |
| `resolution/logic_selection.py` | Access evidence only; no selection policy or model calls |
| `resolution/logic_impact.py`, `logic_assessment.py` | One function rating, then one final expansion-selection policy |
| `source_context.py` | One compiler-file bundle and function source references |
| `scripts/logic.py` | Generate, assess, enumerate; explicit manual mode retained |
| Old `decide.py`, `verdict.py`, `holders.py` | Removed: sampled opens, relaxed conditions, arranged journeys, witness confirmation and provenance policies |
| `scope.py`, `SCOPE.md`, `taint.py`, `report.py` | Removed old scope/provenance/presentation policy; semantic dependency tracking remains in the translator |
| `snapshot.py`, `logged.py`, `versions.py`, `writer_events.py` | Replaced for this engine by snapshot/preimage accounting; event words are candidates, never a complete-list proof |
| Old verdict tests | Their Solidity examples retained in `tests/logic/fixtures/regressions.json`; policy assertions retired |
| Compiler differential tests | Retained and connected to the new evaluator; expanded by new independent relation tests |

Historical JSON comparison scripts remain useful for v45–v53 data. They do not validate schema-2 formulas.
