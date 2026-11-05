# Coverage and limitations

Classification of a Slither operation is dispatch coverage, not a semantic proof. The executable classifier
is `tests/logic/test_ir_coverage.py`; the compiler's declarations remain in `lower.py`.

| Component | Evidence | Boundary |
| --- | --- | --- |
| Arithmetic/conversions | `test_language.py` compares concrete inputs to Anvil | Unsupported symbolic operations remain qualified |
| Loop control and memory carried across iterations | `test_loop_control.py`, `test_loop_conditions.py`, `test_loop_state.py`: complementary bounds, tracked storage, condition effects, resume | Resumable generation retains loop/depth checkpoints; legacy direct lowering qualifies unfinished loops |
| Declaration/modifier scope | `test_declaration_scope.py`, multiple solc versions | Unreadable compiler versions remain unsupported |
| Yul name binding | `test_yul_siblings.py` | Ambiguous reads are unknown; equal diagnostic names are not equal values |
| Selection reports | `test_selection_report.py`, `test_logic_workflow.py` | Access evidence is separate from model ratings; no automatic expansion |
| Caller projection | `test_projection.py`, exhaustive finite caller/argument domains | Samples never certify complete sets |
| Single-write outcome control | `test_write_power.py`, `test_effect_assessment.py`: owner/public values, bounds, reparameterized inputs, distinct targets, exact scope routing and Anvil observations | Same pinned state and independent bounded inputs in both calls; unresolved queries remain symbolic. This does not prove joint control of multiple writes or origin/signing authority |
| State and delegated gates | `test_formula_engine.py`, `test_call_transitions.py`, `test_transition_boundaries.py` | Known zero-value high-level calls share ordered storage, with separate frames and rollback; explicit gas/value, stateful try/catch and unknown targets remain qualified |
| Deferred storage projection | `test_deferred_storage.py` | An UNSAT equivalence check must prove the caller projection independent of deferred state; otherwise ordinary state acquisition applies |
| Typed raw-call transitions | `test_raw_call_transitions.py`, `test_external_dispatch.py`: state retention, callback/revert rollback, per-call resources, typed success decoding, mutated buffers, resume | Resource-dependent outcomes remain qualified; no gas solver or arbitrary-target enumeration |
| Typed delegate transitions | `test_delegate_transitions.py`: caller storage, original sender/value, nonpayable checks, nested frames, independent memory, failure rollback, effect guards and JSON checkpoint resume | Known targets and typed ABI byte payloads; raw-call resource outcomes remain qualified. Unplaced assembly regions, dynamic input layouts and symbolic targets remain retained |
| Assembly call execution | `test_assembly_call_execution.py`, `test_assembly_call_boundaries.py`, `test_delegate_payload.py`: static ABI bytes, truncated/dirty inputs, arrays/structs, bounded short decode, CALL/STATICCALL/DELEGATECALL, output fragments and resume | Dynamic input layouts, missing dispatch entries and unplaced memory remain retained. Resource failure and unsupported revert bytes remain qualified |
| Runtime fallback execution | `test_fallback_execution.py`, `test_fallback_boundaries.py`: fallback/receive/default dispatch, native clashes, transformed calldata/returns, pre/post writes, rollback, raw RETURN/STOP, source contexts and resume | Callee runtime bodies execute; top-level proxy entry routing is still structural. Static restrictions, symbolic targets, dynamic inputs and gas/resource uncertainty remain explicit |
| Short-circuit evaluation | `test_retained_operations.py`: skipped calls, RHS local/storage/memory mutations and assignments; existing language and loop oracles | RHS source spans or unambiguous dataflow; unsupported interleaving stays qualified |
| Retained calls and execution frames | `test_retained_operations.py`: pre-call state, nested/proxy static contexts, native calls, same-snapshot source supply, fresh-process replay, compiler/EVM call mode | Unmodeled root dispatch and symbolic targets remain unexpanded call programs; assessment names the blocker |
| Scalar public getters | `test_public_getter_calls.py`: mapping/array keys, declared ABI types, bounds, prior writes, shadowed declarations, dynamic keys, singleton enum packing and failed-read cache | Struct returns remain deferred; packing uses the shared compiler-type layout |
| Physical storage expressions | `test_symbolic_storage_locations.py`: EVM words for packed fields, nested mappings/arrays/structs, namespace wrap, renamed declarations, scalar aliases and pointer packing across compiler versions | Same layout walk for concrete and symbolic paths; array bounds belong to execution. Aggregate byte views and general delegates still pending |
| Physical scalar overlay | `test_physical_overlay.py`, `test_storage_word_boundaries.py`: packed/raw updates, order, code views, budgets, volatile locations, pointer identities, transaction scopes and retained incompatible views | Root proxy dispatch and unplaced aggregate byte views still pending |
| Symbolic byte inputs | `test_symbolic_byte_stream.py`: overlap, unaligned/symbolic offsets, zero padding, separate streams, reference-array equivalence and caller projection | Finite read-only stream semantics; whole-value string conversions and root raw-calldata routing remain unfinished |
| Legacy ABI boundaries | `test_legacy_abi_boundaries.py`: three compiler versions, coder modes, short scalar/array inputs, budgets and caller EVM targets | Legacy short returndata needs the caller memory buffer and remains pending |
| Legacy text assembly | `test_legacy_memory.py`: shared memory, words, lexical scopes, compiler references, RETURN/STOP | Unsupported control flow/calls retain the entire operation; no regex recovery |
| Unplaced allocator operations | `test_allocator_retention.py`: actual counterexamples, saved states and resume | Allocation/return encoding remains pending until memory placement is resolved |
| Symbolic memory and return buffers | `test_free_memory_address.py`, `test_symbolic_memory.py`, `test_returndata_memory.py`: relative aliases, byte fragments, static ABI words, branches, caught failures and allocator invalidation | Numeric pointer values, dynamic returndata, revert bytes and unplaced compiler allocations remain qualified |
| Resumable expansion | `test_continuation.py`: uninterrupted/resumed equality, fresh-process JSON reload, completed-operation reuse, nested loops/calls/modifiers, rollback, binding/block validation; API tests cover durable resume jobs | Pending compilation is distinct from a formula; frontend IR must match. Unsupported semantics remain unsupported; no claim that repeated resumption resolves arbitrary loops |
| Yul scalar register representation | `test_language.py`, fixed-bytes call regression in `test_call_transitions.py` | Raw EVM words and logical typed values remain distinct; unsupported dirty-register operations carry named unknowns |
| Proxy dispatch | `test_proxy_dispatch.py`, `test_proxy_shapes.py`, `test_proxy_review_regressions.py`: independent execution of forwards, collisions, extra delegates, copy bounds and call frames | Pre-0.6 text assembly, rewritten calldata or return data, explicit gas caps, selector clashes and fallback writes stay qualified |
| Proxy discovery and saved layouts | `test_proxy_discovery.py`: cold addresses, stale hints, native admin and implementation owner, generation/assessment/expansion | Finite concrete targets only; no caller enumeration during discovery |
| ABI coder per side | `test_abi_coder.py`, `test_external_abi.py`: dirty words under coder v1 and v2 | Source scope is tracked across library/free helpers and modifiers; unresolved scopes, v1 enums and user-defined value types stay unsupported |
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

Byte containers and literal provenance are checked by `test_byte_container_semantics.py`: UTF-8 lengths, EVM word alignment, hex/escaped bytes, genuine `0x` text, and compiler-span ambiguity. Raw literal bytes come from the compiler AST; ambiguous or unavailable provenance is explicitly unsupported.


### Root runtime increment (2026-11-04)

- Deployment queries execute native/fallback runtime for an inventoried selector using raw
  prefix-plus-tail bytes, actual sender/value/storage, and the runtime entry's ABI decoder.
  `test_root_runtime` and `test_root_runtime_review` compare successful execution and storage
  effects, rollback, old/new decoder behavior, empty receive data, native selector precedence,
  arbitrary raw return sizes and checkpoint/resume against Anvil.
- `test_prefixed_bytes` covers byte boundaries, nested prefixes, symbolic offsets and the EVM
  length domain. Forwarding a symbolic-length copy preserves the byte stream only while the
  complete copy remains intact.
- Fallback domains and repeated symbolic selector dispatch are represented as disjoint guarded
  entries, including short inputs, receive, getters and default reverts. Dynamic root ABI decoding
  and symbolic-length memory overlays remain retained work. This is not full arbitrary proxy
  execution or a gas proof.
- Raw byte length/chunk inputs participate in single-write control with the same finite-read
  consistency bounds. `test_write_power` keeps shared public outcomes distinct from exclusive
  owner outcomes. Multi-write outcome control remains separate work.


### Dispatch-domain review (2026-11-04)

`test_runtime_domains` and `test_runtime_domains_review` compare dispatch and persistent writes
with mined EVM calls. They cover zero selectors on Solidity0.4.19/0.5.14/0.8.27, native exclusion,
receive precedence, decoder failure without fallback, missing entries, static return copying,
caller-frame guards, excluded dynamic decoders/getters, and durable multi-branch replay.
`test_runtime_inventory` preserves an effectful legacy constant entry and a pure implementation
selector whose proxy writes storage. Explicit view/pure functions are generated instead of
being discarded by their mutability annotation. These tests do not prove general dynamic ABI
layout support, arbitrary call targets, loop invariants or transaction gas feasibility.


### Shared byte-view and modern dynamic-byte input increment (2026-11-04)

- `bytes_slice` and `bytes_patch` preserve shared-source reads and ordered in-extent overwrites.
  `test_byte_views` compares concrete byte operations and constrained symbolic reads;
  `test_input_memory_overlays` mines proxy rewrites and checks storage, including short inputs.
- Modern0.8 coder-v2 top-level bytes/string inputs decode with explicit bounds and allocation
  guards. `test_dynamic_byte_inputs` checks malformed offsets, overlaps, missing tails, memory
  copies and string/bytes aliases against0.8.10 and0.8.27. Other dynamic kinds and missing
  data-location metadata remain unsupported; no general dynamic-array decoder is claimed.
- Compiler common operand types and implicit widening close the literal/mixed-width and mixed
  fixed-byte mis-lowerings. `test_binary_compiler_types` checks four compiler versions and the
  pre0.5 signed-shift/count rules. The metadata pass shares the existing compiler-source index.
- Some unbounded byte-mask equivalence and power queries still time out. Concrete agreement is
  not presented as a universal solver proof, and production query limits are unchanged.
