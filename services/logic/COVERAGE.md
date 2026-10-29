# Coverage and limitations

Classification of a Slither operation is dispatch coverage, not a semantic proof. The executable classifier
is `tests/logic/test_ir_coverage.py`; the compiler's declarations remain in `lower.py`.

| Component | Evidence | Boundary |
| --- | --- | --- |
| Arithmetic/conversions | `test_language.py` compares concrete inputs to Anvil | Unsupported symbolic operations remain qualified |
| Loop control and memory carried across iterations | `test_loop_control.py` | Unroll/depth limits yield named unknowns |
| Declaration/modifier scope | `test_declaration_scope.py`, multiple solc versions | Unreadable compiler versions remain unsupported |
| Yul name binding | `test_yul_siblings.py` | Ambiguous reads are unknown; equal diagnostic names are not equal values |
| Selection reports | `test_selection_report.py`, `test_logic_workflow.py` | Access evidence is separate from model ratings; no automatic expansion |
| Caller projection | `test_projection.py`, exhaustive finite caller/argument domains | Samples never certify complete sets |
| State and delegated gates | `test_formula_engine.py` | Stateful calls, unresolved proxy dispatch and unknown call targets remain qualified |
| Composite keys | `test_hashed_storage.py`, a hash of two addresses with no events | Verified preimages and explicit cryptographic assumptions required |
| Transaction composition | `test_formula_engine.py` | Explicit sequences of local guarded updates; no arbitrary future-state claim |
| Transport and trace input | `test_reads.py` | RPC failure aborts; cut acquisition is incomplete, never an empty snapshot |
| Concrete signature recovery | `test_formula_engine.py` | Symbolic signature feasibility is retained, not guessed |

Known lowerer limitations from the previous audit still matter. In particular, assembly memory/low-level-call corners need dedicated semantics work. Legacy super-call argument
binding now has an executable regression and binds arguments to the resolved implementation parameters. The new evaluator never
interprets `assumed` as successful, but removing that old policy is not a proof that all lowerings are correct.
The regression fixture archive preserves the earlier examples. Its existence is not counted as executed coverage.

There is no claim of 100% soundness, 100% language semantics or 100% corpus coverage. Unknown semantics,
unsolved queries, incomplete enumeration and operational errors are represented distinctly as described in SPEC.md.
