# Lowering coverage

What the logic engine's lowering (``lower.py``, ``yul.py``, with the term vocabulary in ``terms.py`` and the
evaluation in ``decide.py``/``verdict.py``) does with each construct of the language it reads: every Slither IR
operation class, every builtin Slither names, every special variable, each conversion / member / index kind, the
panics the language raises, and the Yul the legacy front end accepts.

Each entry is one of

* **HANDLED**: lowered with defined semantics, pinned by the named test;
* **REJECTED**: lowered to a named ``unknown`` (gap ``unknown:<label>``), so a verdict that depends on it is never
  complete and never "provably nobody";
* **APPROXIMATED**: lowered to a plausible but wrong term (the defect list). The forbidden state.

## 2026-10-23: before (HEAD 138a8c4b, slither-analyzer 0.11.5)

The honest starting point, written before any change. "no test" means the behaviour is real but nothing pins it.

### Slither IR operation classes (``slither.slithir.operations``)

| class | state | what happens / defect |
|---|---|---|
| Assignment | HANDLED, APPROXIMATED (A1) | values copied; storage pointer binding; ``$.slot :=``. **A1**: a memory reference (array/struct) assigned to a second memory variable is copied, not aliased: a write through one name leaves the other stale |
| Binary (arith) | APPROXIMATED (A2, A3, A4) | ``mk_op`` over 256-bit words whatever the operand type. **A2** narrow unsigned types wrap at 2^256, not 2^N, when unchecked (``uint8 x + 1``, ``~x``); **A3** signed operands: ``lt``/``le``/``div``/``mod``/``shr`` read as unsigned, signed results as unsigned words while storage decodes signed ints as negative numbers; **A4** checked (>= 0.8) overflow/underflow and division/modulo by zero are not in the path condition |
| Binary (compare, ``&&``, ``||``) | HANDLED | ``mk_cmp``/short-circuit (``test_lower_shapes``, ``test_core``); signed compares fall under A3 |
| Condition | HANDLED | path split (every test) |
| Delete | HANDLED, APPROXIMATED (A5) | zero written; **A5**: a whole struct/array deleted, then a field or the length read, reads the pre-call value (see S2) |
| EventCall | HANDLED | ``emit`` mark (``test_logged``) |
| HighLevelCall | HANDLED | ``call`` term + ``ok`` conjunct (``test_core``, ``test_callee_*``) |
| Index | APPROXIMATED (A6, A7, A8, A9) | **A6** (the lido defect) an index into a memory copy of a storage array (``T[] memory xs = f()``, rendered ``InitArray``) dropped: ``xs[i]`` became the whole array; **A7** a symbolic-index write into a tracked memory array is lost (array unchanged); **A8** ``bytes``/``msg.data`` index (one byte) and ``calldataload`` (a word) both lowered to ``elem``; **A9** out-of-bounds Panic (0x32) not in the path condition |
| InitArray | APPROXIMATED (A6) | one init value always read as a one-item literal ``[v]``, also where it is a copy of an array of the same rank |
| InternalCall | HANDLED, APPROXIMATED (A10) | inlined (every test). **A10** memory reference arguments passed by value: a callee's writes into a memory array/struct parameter never reach the caller |
| InternalDynamicCall | APPROXIMATED (A11) | value ``opaque``, but the pointed-to function's reverts and writes ignored: assumed to succeed with no effect |
| Length | HANDLED | memory array, storage length slot, calldata size, code length (``test_lower_shapes``) |
| LibraryCall | HANDLED | as InternalCall, ``storage`` parameters by location (``test_library_writers``) |
| LowLevelCall | HANDLED, APPROXIMATED (A12) | ``.call``/``.delegatecall``. **A12** ``.staticcall`` (a query, no action) taken as an arranged action: success and returned data ``assumed``, so an ERC-1271 / permission check through ``staticcall`` passes for everyone; ``.call`` whose data hands the caller to the callee also assumed |
| Member | HANDLED | storage/memory/argument/call-result/loaded struct fields, enum members, library constants, ``I.f``, ``.code``/``.codehash`` (``test_lower_shapes``); anything else ``op field`` (evaluates unknown) |
| NewArray | HANDLED | zeroed items for small constant lengths (``test_lower_shapes``); Panic 0x41 (too large) not modelled (A9 family) |
| NewContract | HANDLED | action mark, address ``unknown:created`` (no test) |
| NewElementaryType | HANDLED | ``new bytes(n)`` length (``test_lower_shapes``) |
| NewStructure | HANDLED | fields by name; arity mismatch ``unknown:NewStructure`` (``test_lower_shapes``) |
| Nop | HANDLED | no effect (implicit, no test) |
| Phi, PhiCallback | REJECTED (implicit) | SSA-only, never in ``node.irs``; would fall to ``unknown:<class>`` (implicit) |
| Return | HANDLED | every test |
| Send | REJECTED | result ``unknown:Send`` (``test_origin_shapes``) |
| SolidityCall | see builtins | |
| Transfer | HANDLED | arranged action (``test_actions``) |
| TypeConversion | APPROXIMATED (A13) | see conversion kinds |
| Unary | HANDLED, APPROXIMATED (A2) | ``!`` exact; ``~`` 256-bit whatever the width |
| Unpack | HANDLED | tuple items (``test_lower_shapes``) |
| CodeSize (``operations.codesize``) | HANDLED | ``a.code.length`` (``test_pool_shapes``) |
| Call, Operation, OperationWithLValue | n/a | abstract bases; anything unmatched falls to ``unknown:<class>`` |
| BinaryType, UnaryType | n/a | enums (members covered under Binary/Unary) |

### Builtins (``SOLIDITY_FUNCTIONS``)

Solidity-level:

| builtin | state | |
|---|---|---|
| ``require(bool)``, ``require(bool,string)``, ``assert(bool)`` | HANDLED | path condition (every test) |
| ``require(bool,error)`` | HANDLED | IR form, or the expression when the IR drops it (``test_lower_shapes``) |
| ``revert()``, ``revert(string)``, ``revert `` | HANDLED | path ends |
| ``keccak256(bytes)``, ``sha256(bytes)``, ``ripemd160(bytes)``, ``keccak256()``, ``sha256()``, ``ripemd160()``, ``sha3()`` | HANDLED | ``hash`` (``test_logged``, ``test_engine_pieces``); ripemd160 evaluates unknown |
| ``ecrecover(bytes32,uint8,bytes32,bytes32)`` | HANDLED | ``signer`` (``test_lower_shapes``, ``test_actions``) |
| ``addmod``, ``mulmod`` | HANDLED, APPROXIMATED (A14) | evaluated exactly; **A14** Solidity's form reverts (Panic 0x12) on a zero modulus, Yul's returns 0: both read as 0 |
| ``selfdestruct(address)``, ``suicide(address)`` | HANDLED | halts successfully, action (``test_selfdestruct``) |
| ``gasleft()`` | REJECTED | ``unknown:gasleft()`` (``test_core``) |
| ``blockhash(uint256)``, ``blobhash(uint256)`` | REJECTED | ``opaque`` (no test) |
| ``log0..log3(bytes32...)`` (Solidity's) | HANDLED | no effect on success (no test) |
| ``abi.encode()``, ``abi.encodePacked()`` | HANDLED, APPROXIMATED (A15) | ``enc`` (``test_logged``, ``test_lower_shapes``). **A15** hashing ``abi.encode`` of a ``bytesN`` (N < 32) right-aligns it (the ABI left-aligns) |
| ``abi.encodeWithSelector()``, ``abi.encodeWithSignature()`` | APPROXIMATED (A15) | ``enc``; hashed, the selector/signature is encoded as a whole word instead of 4 bytes |
| ``abi.encodeCall()`` | HANDLED, APPROXIMATED (A15) | as ``encodeWithSignature``; the fallback ``enc("abi.encodeCall")`` hashes as plain words |
| ``abi.decode()`` | HANDLED | of an ``abi.encode``, of an arranged return; else ``opaque`` (``test_lower_shapes``) |
| ``bytes.concat()``, ``string.concat()`` | REJECTED | ``opaque`` (no test) |
| ``type(address)``, ``type()`` | REJECTED | ``opaque`` (constants are folded by Slither) |
| ``this.balance()`` | REJECTED | ``opaque`` |
| ``balance(address)`` | HANDLED | ``balance`` (``test_actions``) |
| ``code(address)`` | HANDLED | ``code`` |
| ``codehash(address)`` | REJECTED | ``opaque`` |
| Vyper builtins: ``create_from_blueprint()``, ``create_minimal_proxy_to()``, ``empty()``, ``convert()``, ``len()``, ``method_id()``, ``unsafe_sub()``, ``unsafe_add()``, ``unsafe_div()``, ``unsafe_mul()``, ``pow_mod256()``, ``max_value()``, ``min_value()``, ``concat()``, ``ecrecover()``, ``isqrt()``, ``range()``, ``min()``, ``max()``, ``shift()``, ``abs()``, ``raw_call()``, ``_abi_encode()``, ``slice()``, ``uint2str()``, ``send()`` | APPROXIMATED (A16) | ``opaque`` values with no effect: ``raw_call``/``send``/``create_*`` (calls out, revert on failure) silently dropped; ``unsafe_*``/``convert`` values unknown but unnamed as Vyper |

Yul builtins (Solidity >= 0.6 assembly, lowered by Slither to ``SolidityCall``):

| builtin | state | |
|---|---|---|
| ``mstore``, ``mload`` | HANDLED | constant-offset memory words; lost words ``opaque(mload, unknown memory)`` (``test_lower_shapes``, ``test_core_soundness``) |
| ``mstore8``, ``calldatacopy``, ``codecopy``, ``extcodecopy``, ``mcopy`` | HANDLED | memory forgotten (later ``mload`` lost) |
| ``returndatacopy`` | HANDLED | first word of the last call, else memory forgotten (``test_pool_shapes``) |
| ``keccak256(uint256,uint256)`` | HANDLED | hash of the bytes earlier ``mstore`` left (``test_logged``) |
| ``sload``, ``sstore``, ``tload``, ``tstore`` | HANDLED | ``rawload``/raw writes; transient zero at start (``test_callee_actions``, ``test_arranged``) |
| ``calldataload``, ``calldatasize`` | HANDLED | argument words / ``elem(msg.data, off)`` (``test_snapshot``) |
| ``extcodesize``, ``extcodehash``, ``balance(uint256)``, ``selfbalance()`` | HANDLED | ``codesize``/``codehash``/``balance`` |
| ``returndatasize`` | HANDLED | ``retsize`` of the last call (``test_pool_shapes``) |
| ``call``, ``callcode`` | HANDLED | arranged action, or the action ``abi.encode*`` data names (``test_pool_shapes``) |
| ``staticcall`` | HANDLED | the view call encoded data makes, else ``opaque`` (``test_lower_shapes``) |
| ``delegatecall`` | HANDLED | ``delegate`` (``test_versions``) |
| ``create``, ``create2`` | HANDLED | action, ``unknown:created`` |
| ``return``, ``stop``, ``revert(uint256,uint256)``, ``invalid()``, ``selfdestruct(uint256)`` | HANDLED | halt / path ends |
| ``log0..log4(uint256...)`` | HANDLED | ``emit`` marks |
| ``pop(uint256)`` | HANDLED | discarded |
| ``byte(uint256,uint256)`` | HANDLED / REJECTED | packed-signature ``v``; else ``opaque`` |
| ``timestamp()``, ``number()``, ``chainid()``, ``basefee()``, ``coinbase()``, ``gaslimit()``, ``difficulty()``, ``prevrandao()``, ``gasprice()``, ``blobbasefee()`` | REJECTED | ``opaque`` (same for every caller: not wrong, never resolved) |
| ``address()`` | REJECTED | ``opaque`` (should be ``this``) |
| ``caller()``, ``origin()``, ``callvalue()`` | HANDLED | Slither rewrites them to ``msg.sender``/``tx.origin``/``msg.value`` |
| ``gas()``, ``msize(uint256)``, ``pc()``, ``codesize()``, ``clz(uint256)``, ``signextend(uint256,uint256)`` | REJECTED | ``opaque`` |
| ``sdiv``, ``smod``, ``slt``, ``sgt``, ``sar`` | APPROXIMATED (A3) | Slither rewrites them to ``int256`` conversions around an ordinary ``Binary``: read as unsigned |

### Special variables (``SOLIDITY_VARIABLES``, ``SOLIDITY_VARIABLES_COMPOSED``)

| variable | state | |
|---|---|---|
| ``msg.sender``, ``tx.origin``, ``this``, ``msg.value``, ``msg.sig``, ``msg.data`` | HANDLED | ``caller``/``origin``/``this``/``callvalue``/``sig``/``msg.data`` (``test_core``, ``test_origin_*``, ``test_lower_shapes``) |
| ``now``, ``block.timestamp``, ``block.number``, ``block.chainid``, ``block.basefee``, ``block.prevrandao``, ``block.difficulty``, ``block.coinbase``, ``block.gaslimit`` | HANDLED | ``time`` terms (``test_arranged``, ``test_governance``) |
| ``tx.gasprice`` | APPROXIMATED (A17) | read as ``block.basefee``; the caller picks any price at or above it |
| ``block.blobbasefee``, ``block.blockhash``, ``msg.gas`` | REJECTED | ``unknown:<name>`` |
| ``self``, ``chain``, ``ZERO_ADDRESS``, ``chain.id``, ``block.prevhash``, ``self.balance`` (Vyper) | REJECTED | ``unknown:<name>``, but see A16 |
| ``abi``, ``msg``, ``tx``, ``block``, ``super`` | n/a | namespaces, never values |

### Conversion kinds (``TypeConversion``)

| kind | state | |
|---|---|---|
| unsigned widening, address <-> uint160/bytes20, contract <-> address, UDVT wrap/unwrap, ``bytesN`` <-> ``uint(8N)`` | HANDLED | value unchanged (``test_lower_shapes``) |
| unsigned narrowing (``uint16(x)``) | APPROXIMATED (A13) | lowering folds only address/uint160/8/32/64 constants; the evaluator and solver mask only address/uint160/8/32/64/128: ``uint16``, ``uint24``, ``uint96`` ... pass through unmasked |
| ``bytesM`` -> ``bytesN`` | APPROXIMATED (A13) | value unchanged (narrowing keeps the high bytes, widening shifts left); a ``bytes32`` constant to ``bytes4`` keeps the low bytes |
| signed <-> unsigned, signed narrowing | APPROXIMATED (A3) | unchanged / unmasked |
| ``bytes``/``string`` -> ``bytesN`` | APPROXIMATED (A13) | unchanged (except ``bytes4(msg.data)``, the selector) |
| ``uint`` -> enum | HANDLED, APPROXIMATED (A9) | unchanged; Panic 0x21 out of range not modelled |
| calldata slice ``x[a:b]`` | APPROXIMATED (A18) | Slither drops the slice: ``x[4:]`` is ``x`` (``msg.data[4:]`` alone is recovered from the source) |

### Storage, memory, loops

| construct | state | |
|---|---|---|
| storage read after an exact write | HANDLED | ``_read_at`` (``test_engine_pieces``) |
| S2: field read after the whole struct/array written (``cfg = Cfg(..)``, ``delete cfg``) | APPROXIMATED (A5) | ``_read_at`` only compares paths of equal length: the pre-call value |
| S3: whole value read after an element/field written | APPROXIMATED (A5) | same |
| memory nested writes (``g[1][0] = x``, ``s.arr[i] = x``) | APPROXIMATED (A19) | written into the temporary reference, not the outer value |
| loop-carried values after the unrolled iterations | APPROXIMATED (A20) | only what the last unrolled iteration changed is forgotten: a variable a later iteration writes (``if (i == 5) x = 1``, a ``found = true; break``) keeps its pre-loop value; storage written at keys of later iterations is never forgotten |
| exits from later iterations (``return``/``break`` past the unrolled ones) | APPROXIMATED (A21) | not modelled: a ``for (...) if (list[i] == msg.sender) return true;`` loop lists only the unrolled entries, completely |
| ``do { } while (c)`` | APPROXIMATED (A22) | the back edge goes to the body, not to a loop header: every path that iterates twice or more is dropped |
| irreducible control flow | APPROXIMATED (A23) | nodes never scheduled, paths through them dropped |
| ``latched_atoms`` / ``_codeless`` | APPROXIMATED (A24) | a call whose target is computed from mutable storage, reading no code now, is latched "never passes": "provably nobody" (the lido row) |

### Legacy Yul front end (``yul.py`` + ``Lowerer._yul``, Solidity < 0.6)

| construct | state | |
|---|---|---|
| ``let``, assignment, blocks, call statements | HANDLED | ``test_yul`` |
| ``add sub mul div mod exp and or xor shl shr lt gt eq iszero not`` | HANDLED | unsigned word ops |
| ``sload``, ``sstore``, ``caller``, ``address``, ``callvalue``, ``timestamp``, ``number``, ``extcodesize``, ``calldataload`` | HANDLED | as their Solidity forms |
| ``log1..log4``, ``revert``, ``invalid``, ``pop`` | HANDLED | |
| ``mstore``, ``mstore8``, ``calldatacopy``, ``codecopy``, ``returndatacopy`` | HANDLED | memory forgotten |
| ``mload``, ``byte``, ``keccak256``, ``sar``, ``signextend``, ``addmod``, ``mulmod``, ``sdiv``, ``smod``, ``gas``, ``returndatasize``, ``calldatasize``, ``chainid``, ``selfbalance``, ``balance``, ``msize`` | REJECTED | ``opaque``/lost word |
| ``slt``, ``sgt``, control flow, functions, string literals, anything else | REJECTED | ``Unsupported``: the regex fallback |
| regex fallback over text with control flow | APPROXIMATED (A25) | ``x := y``, ``x := sload(s)``, ``sstore(s, v)`` read as unconditional even inside ``if``/``switch`` |

### Evaluation of encodings (``decide.Evaluator._encoded``) — see A15.

**Count (before):**

* operation classes: 33 names in the module, 3 abstract bases (Call, Operation, OperationWithLValue) and 2 enums
  (BinaryType, UnaryType); of the 28 concrete classes plus ``CodeSize`` (its own module) = 29: **15 HANDLED, 3
  REJECTED** (Phi, PhiCallback implicitly; Send), **10 APPROXIMATED** at least in part (Assignment, Binary, Delete,
  Index, InitArray, InternalCall, InternalDynamicCall, LowLevelCall, TypeConversion, Unary), SolidityCall per builtin.
* builtins (123 names: 41 Solidity, 26 Vyper, 56 Yul): **65 HANDLED, 26 REJECTED, 32 APPROXIMATED** (addmod, mulmod,
  abi.encode, abi.encodeWithSelector, abi.encodeWithSignature, abi.encodeCall, and all 26 Vyper builtins).
* special variables (30 names): **15 HANDLED, 9 REJECTED, 1 APPROXIMATED** (tx.gasprice), 5 namespaces.
* 25 distinct approximations (A1-A25) across operations, builtins, variables, conversions, storage/memory/loops,
  latching and the legacy Yul reader.

## 2026-10-23: after

Every entry is HANDLED or REJECTED; the explicit sets are ``HANDLED_OPERATIONS``/``REJECTED_OPERATIONS``,
``HANDLED_BUILTINS``/``REJECTED_BUILTINS``, ``HANDLED_VARIABLES``/``REJECTED_VARIABLES`` and the ``LEGACY_YUL_*`` sets in
``lower.py``. ``tests/logic/test_ir_coverage.py`` computes Slither's own enumeration at test time and fails on anything
unclassified (a new Slither); it also exercises every REJECTED entry and checks its label reaches the verdict's gaps
(not complete) where Solidity 0.8.27 can express it, else the term the lowering builds. Anything outside every set is
rejected by default as ``unsupported:<name>``. ``tests/logic/test_language.py`` evaluates the lowered formula of ~80
probes with the decision's own evaluator and compares each with ``eth_call`` on anvil (arithmetic, conversions,
builtins, encodings, custom errors, halting assembly); ``tests/logic/test_elements.py`` pins element reads, memory,
storage and loops; ``tests/logic/test_latching.py`` the latch.

**Count (after):** operation classes 25 HANDLED, 4 REJECTED (Phi, PhiCallback, InternalDynamicCall, Send), 5 abstract or
enum, 0 APPROXIMATED; builtins 85 HANDLED, 38 REJECTED, 0 APPROXIMATED; special variables 15 HANDLED, 15 REJECTED
(namespaces now rejected by name too), 0 APPROXIMATED; legacy Yul builtins 50 HANDLED, 5 REJECTED as named unknowns,
33 REJECTED to the fallback reader.

### What each approximation became

| # | was | now | pinned by |
|---|---|---|---|
| A1 | memory aliasing copied | HANDLED: values memory keeps by reference are objects (``("heap", n)``) behind pointers; every name sees every write | ``test_elements::test_two_names_for_one_memory_object_see_each_others_writes`` |
| A2 | narrow unsigned wrap at 2^256, ``~`` 256-bit | HANDLED: unchecked results converted to their width; ``~`` in its width | ``test_language`` (``wrapped``, ``wrappedShift``, ``flipped``) |
| A3 | signed read as unsigned | HANDLED: operands and results sign-normalized (``conv("intN")``), ``sdiv``/``smod``/``sar`` exact, signed compares, Yul ``slt``/``sgt``/``sdiv`` as Slither renders them; evaluator and solver convert by width | ``test_language`` (``negative``, ``signedDiv``, ``signedMod``, ``signedShift``, ``signedAdd``, ``yulSigned``, ``negativeConstant``) |
| A4 | checked overflow, division by zero not in the path | HANDLED: unsigned ``a - b`` requires ``b <= a``; other checked operations ``fits(op, a, b, bits, signed)`` (exact, evaluated and encoded for z3); ``/``, ``%`` require a nonzero divisor outside Yul | ``test_language`` (``checked*``, ``divided``, ``remainder``, ``yulDivZero``) |
| A5 | storage read under / around a whole write | HANDLED: ``read_store`` projects a whole write onto the part read, and reads a whole value written in part as ``upd`` | ``test_elements::test_a_field_reads_back_what_a_whole_struct_write_or_delete_left``, ``test_an_item_pushed_then_copied_reads_back_as_pushed`` |
| A6 | lido: memory copy of a storage array indexed as the array | HANDLED: copy vs literal by type rank; item ``k`` of a copy is ``load(..., k)`` | ``test_elements::test_a_storage_list_copied_to_memory_calls_each_item_not_the_list`` and the lido row |
| A7 | symbolic-index write into a tracked memory array lost | HANDLED: ``update`` item by item (``ite``), else ``upd`` | ``test_elements::test_a_write_at_a_symbolic_index_lands_on_that_item`` |
| A8 | bytes index as a word | HANDLED: one byte (``slice(elem(x, k), 0, 1)``) | ``test_elements::test_a_bytes_index_is_one_byte_not_a_word`` |
| A9 | Panics not in the path | HANDLED: index out of range (0x32, memory, calldata and storage arrays; not mappings), enum conversion and enum arguments (0x21), allocation past 2**64 (0x41), pop on empty (through checked ``-``) | ``test_elements`` (literal, storage), ``test_language`` (``member``, ``enumArgument``, ``allocated``) |
| A10 | callee writes into memory parameters lost | HANDLED: parameters hold the caller's object; reassigning a parameter points it elsewhere | ``test_elements::test_a_callee_writes_into_the_callers_object_but_reassigning_its_parameter_does_not`` |
| A11 | function pointer call assumed to succeed | REJECTED: ``unsupported:InternalDynamicCall`` on the path, value and writes unknown | ``test_ir_coverage`` (``viaPointer``) |
| A12 | ``.staticcall`` and caller-naming ``.call`` assumed | HANDLED: the view call / action the ``abi.encodeWith*`` data names (``ok``, decoded words); undecodable staticcall data ``unsupported:staticcall``, undecodable call data naming the caller ``unsupported:call_data`` | ``test_language::test_a_low_level_call_is_the_call_its_data_encodes``, ``test_origin_shapes::test_a_low_level_staticcall_in_followed_code_is_the_view_call_its_data_encodes`` |
| A13 | conversions unmasked / bytes misaligned | HANDLED: every integer width, address, ``bytesM`` -> ``bytesN`` as a shift, ``bytes`` -> ``bytesN`` its first N bytes; same in evaluator and solver (``converted``) | ``test_language`` (``narrowed``, ``cut``, ``padded``, ``unsignedOf``, ``signedOf``, ``tiny``) |
| A14 | Solidity mulmod/addmod by zero | HANDLED: nonzero modulus required outside Yul (>= 0.5) | ``test_language`` (``modulus``) |
| A15 | encodings hashed wrongly | HANDLED: ``bytesN`` left-aligned in ``abi.encode``, 4-byte selector for ``encodeWithSelector``/``encodeWithSignature``, other kinds not encoded | ``test_language`` (``hashed*``, ``concatenated``) |
| A16 | Vyper builtins dropped | REJECTED: ``unsupported:vyper:<name>`` on the path, writes lost | ``test_ir_coverage::test_each_rejected_builtin_lowers_to_its_label`` |
| A17 | ``tx.gasprice`` read as base fee | REJECTED: ``unsupported:tx.gasprice`` | ``test_ir_coverage`` (``viaGasprice``) |
| A18 | calldata slices dropped | HANDLED for ``msg.data[4:]`` and ``bytesN(x[:N])`` (``bytesN(x)``, with ``N <= x.length`` on the path); REJECTED otherwise: in a statement slicing anything else, dynamic calldata reads ``unsupported:slice`` (``unsupported:slice_source`` where the source can't be read faithfully, A47) | ``test_ir_coverage`` (``viaSlice``), ``test_slice_source`` |
| A19 | nested memory writes lost | HANDLED: an item or field written in place is written back where its holder lives | ``test_elements::test_nested_memory_writes_reach_the_outer_value`` |
| A20 | loop-carried values kept from unrolled iterations | HANDLED: the widened state forgets every local, object and storage variable the body's operations (and callees) may write; storage reads past it are ``opaque(loop:N, ...)`` (``havoc`` marks) | ``test_elements::test_a_variable_a_later_iteration_writes_is_forgotten``, ``test_what_only_a_later_iteration_writes_is_never_taken_as_unwritten`` |
| A21 | exits from later iterations | HANDLED: a loop that may return (or halt) past the iterations followed exactly also exits with unknown values, and one that may ``break`` leaves with what it writes forgotten; a list is followed exactly up to the bound (three entries named, nothing forgotten) and past it the answer is left open (``unknown:loop``), never cut | ``test_elements::test_a_member_past_the_iterations_followed_is_never_left_out_of_a_complete_list`` (``viaReturn``, ``viaBreak``, ``viaDoWhile``), ``test_elements::test_a_list_is_followed_exactly_up_to_the_bound_and_never_past_it``, ``test_elements::test_a_return_or_break_past_the_iterations_followed_is_never_dropped`` |
| A22 | ``do``/``while`` back edges dropped | HANDLED: unrolled, then widened like any loop; the scheduler orders them | same test (``viaDoWhile``) |
| A23 | irreducible flow dropped | REJECTED: ``unsupported:irreducible_cfg`` / ``unsupported:loop_shape`` exits, now only for flow no structured loop explains (nested loops and ``for (;;)``, which produced them, are A44/A45) | known REJECTED: 1 row of the 177-row regression subset (Lido ``proveWCAndActivate``, ``unsupported:irreducible_cfg``), none ``loop_shape``; no Solidity probe produces one |
| A24 | codeless storage-computed target latched | HANDLED: "no code at an address" latches only for this contract or a precompile (0x01-0x11) the code names, for a call's target and a ``code``/``codesize``/``codehash`` read alike; a constant or an immutable with no code now may be where a contract is created later, so the condition reads as it stands and whoever passes once it opens is named; ``_values_at`` counts writes around, within, and past loops | ``test_latching`` (``a_codeless_constant_target_is_how_the_condition_reads_now``, ``a_codeless_immutable_target_is_never_latched``, ``no_code_at_a_precompile_stays_latched``) |
| A25 | legacy regex bindings past control flow | HANDLED: bindings and writes only from text before any control flow; past it, unknown and ``lost`` | ``test_language::test_legacy_assembly_assigns_nothing_for_sure_past_control_flow`` |

Found while working, not in the before table:

| # | was | now | pinned by |
|---|---|---|---|
| A26 | ``sload`` ignored an earlier ``sstore`` in the same call; named and raw writes never aliased | HANDLED: raw and transient slots read through earlier writes; a small or unhashed raw slot written makes named reads ``unsupported:raw_named_alias`` (and back) | ``test_elements::test_a_raw_slot_reads_back_what_this_call_stored_there`` |
| A27 | a location written again kept its first position; merges took one path's write order | HANDLED: writes move to the end; merges reread each path's final value where orders differ or a path left the key alone | ``test_elements::test_writes_two_branches_make_in_opposite_orders_read_back_per_branch`` |
| A28 | ``delete a[i]`` in memory zeroed the whole array | HANDLED | ``test_language`` (``deletedItem``) |
| A29 | a struct built without its mapping fields left its variable unset (zero) | REJECTED: ``unsupported:NewStructure`` | (Solidity >= 0.7 refuses to compile one) |
| A30 | a storage pointer chosen by branch merged into a value; writes through it lost | REJECTED: ``unsupported:storage_pointer_choice``, writes mark all storage unknown | ``test_elements::test_a_storage_pointer_chosen_by_branch_reads_and_writes_unknown`` |
| A31 | storage after a call into this contract's own entry point (``this.f()``) or a delegatecall read as before | HANDLED: reads unknown past it (``selfcall:<sig>``, ``delegatecall``) | ``test_elements::test_storage_after_a_call_into_this_contracts_own_code_reads_unknown`` |
| A32 | ``msg.value`` free in a function that isn't payable | HANDLED: zero (a call with ether reverts) | ``test_language`` (``sent``) |
| A33 | an assembly ``return`` inside an internal function returned to its caller | HANDLED: it ends the whole call (``Exit.halted``) | ``test_language`` (``halted``) |
| A34 | a short-circuit operand not separable from the rest ran unconditionally | REJECTED: ``unsupported:short_circuit`` | (no probe found that Slither renders so) |
| A35 | operations after an internal call in the same statement took the callee's last node (checked/Yul scope, slices) | HANDLED: the statement's node restored | the checked-arithmetic probes |
| A36 | ``abi.decode`` of an encoded word as a narrower type | REJECTED: ``unsupported:abi.decode:<from>-><to>``; same or wider integer types decode exactly | ``test_lower_shapes`` |
| A37 | a field of any other value read as an unnamed ``op field`` | REJECTED: ``unsupported:member:<field>``; a field of an item of a calldata struct array is the caller's per-item choice | ``test_ir_coverage`` (``viaMember``) |
| A38 | ``this.balance``, ``codehash(a)``, Yul ``address()``/``timestamp()``/... opaque; ``bytes.concat``/``string.concat`` opaque | HANDLED: their values (``balance``, ``codehash``, ``this``, ``time``), concat as ``encodePacked`` | ``test_ir_coverage::test_handled_environment_builtins_are_their_values``, ``test_language`` (``concatenated``) |
| A39 | a followed callee read ``msg.value``, ``msg.data``, ``msg.sig`` and ``calldatasize`` as the outer call's (its guessed ``msg.value`` let a stranger through a view callee that sees none) | HANDLED: ``Lowerer.called`` lowers a callee in its own frame: ``msg.value`` zero for a view call, ``unknown:callee:msg.value`` for an action, ``msg.sig`` its own selector, ``msg.data`` (but ``msg.data[4:]``, its arguments) and ``calldatasize`` ``unknown:callee:*``; what the caller hands it keeps the caller's terms | ``test_callee_frame`` (``a_view_callee_reads_no_value``, ``a_callee_reads_its_own_selector``) |
| A40 | a callee's own calls were lowered and asked of the chain as made by the contract decided (``msg.sender`` two levels down was the outer contract) | HANDLED: a call made by followed code carries who makes it (``("call", ..., view, sender)``); its callee is lowered with that sender and the chain asked from it, unless the callee's code provably answers alike for every asker (lowered with a stand-in sender that never shows, nothing unread, no ``tx.origin`` reached: ``verdict.asker_free``), where it is asked as this contract | ``test_callee_frame::test_a_callee_of_a_callee_sees_the_callee_asking_as_its_sender`` |
| A41 | a word or the size of the call's own ``msg.data`` was guessed apart from the arguments it encodes (``calldataload`` at an offset an argument picks) | HANDLED: inside the arguments' encoding a word is what the guessed arguments put there (every argument guessed with it); past it, bytes the caller may append, guessed; the size never below the encoding | ``test_callee_frame::test_a_word_of_the_call_data_inside_the_arguments_is_what_they_encode`` |
| A42 | a ``bytesN`` Slither computes (``f.selector``, ``type(I).interfaceId``) kept as the text of its decimal number, never equal to a number | HANDLED: read as the number (a literal is typed ``string`` until converted); text compared with a number evaluates unknown, never false | ``test_callee_frame::test_a_callee_reads_its_own_selector`` |
| A43 | ``continue`` in a ``while`` or ``do``/``while`` body, or a ``for`` without an increment, jumped to the body's last statement (Slither takes any statement leading into the condition for a ``for``'s increment); in a ``for`` without a condition, past the increment: wrong answers both ways | HANDLED: ``_continue_target`` sends it to the increment of a ``for`` that has one (a statement of the loop's own before its body in the source), else the condition, else the loop's start; ``unsupported:continue`` where the loop can't be told apart | ``test_loop_control`` (``whileBreakContinue``, ``whileContinue``, ``doContinue``, ``forWithoutIncrement``, ``forWithoutCondition``, ``forever``, ``forContinue``) |
| A44 | every loop nested in another, once its inner loop was followed an iteration further, rejected as ``unsupported:irreducible_cfg`` (the iteration ran on from the inner header, entering the outer loop half way) | HANDLED: an iteration of a loop whose exit leads back to its header runs as a region, its leaving states handed back to the run that asked | ``test_loop_control`` (``nestedPlain``, ``nestedBreak``, ``nestedContinue``, ``nestedSymbolic``) |
| A45 | ``for (;;)`` (no condition) rejected as ``unsupported:loop_shape``; once handled, a ``break`` in a ``for (;;)`` nested in a loop with a condition followed Slither's edge to the OUTER loop's ``ENDLOOP`` (a stranger let through read as owner-only) | HANDLED: a loop whose condition is always true; every ``break`` (Solidity's and Yul's) goes to the ``ENDLOOP`` of the innermost loop whose source (compiler offsets) holds it (``_break_target``), never Slither's edge; ``unsupported:break`` where no span tells the loop | ``test_loop_control`` (``forWithoutCondition``, ``forever``, ``foreverInFor``, ``foreverInWhileInFor``, ``foreverInForever``, ``doBreakInFor``, ``a_break_whose_loop_cant_be_told_from_the_source_is_rejected_by_name``) |
| A46 | a value-type local declared without a value (``uint256 j;``) read as ``unknown:unset`` where branches merged, and kept the previous iteration's value when its declaration ran again (an inner loop's counter); once zeroed at every declaration, that was wrong before solc 0.5, where locals are function-scoped and the declaration emits no code | HANDLED by the compilation unit's solc version: >= 0.5 zero (a fresh zeroed object in memory) each time the declaration runs; < 0.5 every value local zero at the function's (or modifier's) entry and the declaration keeps what it holds (a memory local's object made on first touch, kept after); version unread: a local holding anything but zero is ``unsupported:declaration_scope`` | ``test_loop_control`` (``declaredInLoop``, ``nested*``), ``test_declaration_scope`` (0.4.19 and 0.5.14 against the chain) |
| A47 | where a statement's source couldn't be read (Slither's slice cut a character in two, offsets shifted), any reading without ``:`` counted as "no slice": ``x[a:b]`` read as ``x``, ``msg.data[4:]`` as the whole ``msg.data``; likewise a Yul ``sload(SLOT)`` read as ``SLOT`` and a ``hex`` literal's bytes as its text | REJECTED by name: a reading counts only when faithful (every calldata value the statement reads named in it, brackets balanced); else its dynamic calldata reads ``unsupported:slice_source``, the Yul assignment ``unsupported:yul_source``, the literal is not folded; a statement reading no calldata needs no source | ``test_slice_source`` |
| A48 | Yul ``for`` loops (Solidity >= 0.6 assembly, Slither's graph): the condition node's sons are ordered [exit, body], so the body never ran (``t`` stayed 0, definite); a Yul ``continue`` read as a ``do``/``while``'s (init before the condition) and skipped the post block; a Yul ``break``/``continue`` edge leads to the end of its ``if`` | HANDLED: a loop condition's exit is its loop's ``ENDLOOP`` by source, the other son the body (``_loop_exit``/``_loop_body``), for every loop; ``do``/``while`` told by its body written before the condition; ``continue`` to the post block's first statement (several chained in source order), else the condition; ``break`` as A45; ``unsupported:loop_shape`` where a condition node's sons aren't one exit and one body | ``test_loop_control`` (``yulFor``, ``yulContinueBreak``, ``yulNested``, ``yulPost``, ``yulInFor``), ``test_yul::test_a_yul_loop_slither_parses_runs_its_body`` |
| A49 | a stranger let through only once a condition the function consumes itself is back (a spent initializer's version), or only where its call does nothing: where the formula may single someone out it fell through to a confident "nobody", where it can't it was not determined | HANDLED: "nobody, ever" only where no entry point can write the condition back, which latching proves (the condition then reads as it stands); otherwise not determined, ``inert_when_allowed``, whichever branch decides | ``test_consumed_conditions`` (``initAnyone``, ``initUnbanned``), ``test_arranged::test_what_anyone_may_redo_once_holders_did_it_is_not_open`` |

### Stated assumptions (not constructs)

* An external call does not re-enter this contract's state-changing code before it returns (reentrancy is not
  modelled); gas is the caller's to supply (out-of-gas is not a condition).
* A non-view external call not shown to hand the callee the caller's identity is an action the caller arranges
  (``assumed``, ``decide._action``), whatever value it forwards; one shown to hand it the caller is checked against the
  callee's code where followed.
* ``logged.py`` (outside the lowering) argues that every iteration of a loop writes as the unrolled ones do; the
  lowering's ``havoc`` marks are not read there.

### Bounds and decision costs the exact lowering brought (found on the 177-row regression subset)

* Value operations (``element``, ``update``, ``length_of``, ``project``, ``byte_at``) are remembered per argument
  tuple and share a step budget per lowering (``VALUE_STEPS``); past it they answer ``opaque(budget:value_steps)``
  (a named gap), never a value. Reading memory objects out (``_deep``) is remembered per value and the objects it
  reaches; ``substitute`` skips subterms holding none of the kind replaced.
* A loop's forgotten values carry which identities they depended on, not every identity subterm (the same taint).
* ``decide._decide_one``: a conjunct a guess fails refutes every guess that agrees on the assignment entries its
  evaluation actually consulted (``_Reads``; ``msg.data`` consults every argument, followed callee code whatever it is
  handed), never just those it names (``amount <= balance`` refuting an amount whatever the recipient). A view call over
  guessed arguments whose callee is followed is answered by the callee's own code (in its own frame, A39/A40) first,
  the chain only when that is unknown. The code ranks and skips guesses, and is never trusted for an answer: a pass
  resting on it is asked again with every such call put to the chain (``confirmed``), and the choice never depends on
  what the chain has cached. Without these, the exact checked-subtraction conditions spent Maple ``Pool.transfer``'s
  read budget on one ``hasPermission`` call per guessed recipient (``test_callee_frame``).
* Callee code never refutes on its own (fail-safe under any mis-lowering of a callee). A refusal it gives a guess only
  skips that guess. A ``False`` asked from outside any evaluation (``Evaluator.truth``) that some callee's code went
  into (a view call over guessed or unknown arguments answered by it, an action's return value, a ``try``'s outcome;
  memoized values carry the mark, ``_coded_terms``) is asked again with no callee code: each such call put to the
  chain (cache first, then a read within the function's budget) or left unknown. A solver "nothing satisfies it" that
  inlined a callee's code (``solve``) is asked again with each view call a value of its own, tied to what the chain
  answers at the inputs the models reach (``_chain_lemmas``, at most ``_CHAIN_ROUNDS`` inputs): still unsatisfiable,
  the chain refuted it; a model every answer agrees with is checked like any other and may pass; anything else is
  unknown. A candidate the loosened formula refuses only through a callee's code, and not without it, is undecided and
  never searched (the code's refusal spares the search, so it never costs the others the budget); gathering reads and
  asking whether the state alone settles a question (``base_only``) take the code's answer as it is, since neither
  answers. What only the code showed is unknown, counted (``world.code_refuted``), and a verdict left incomplete by it
  names ``callee_code_refutation``. Cost: "nobody, ever" over an argument the callee is handed with infinitely many
  values (``require(guard.flagged(x) || owner)``) is no longer claimed from the callee's code; one whose call inputs
  are few (the caller, a flag picked between two values) still is, from the chain (``test_callee_refutation``).
  Not covered: a callee inlined into the formula because it is handed the caller (``verdict.bind_callers``) is lowered
  and trusted like the contract's own code.
* ``decide._screened``: candidates are asked about in the order the state as it stands suggests: those it already
  lets through (the formula, or it with every condition not about who calls freed) first, those it refuses last,
  within each those holding more of the formula's lookups keyed by who calls; the screen's evaluation is off the
  decision's budget (bounded apart, ``_SCREEN_WORK``) and leaves no trace (``decide.detached``): the chain reads
  nothing (a word or call not yet answered reads unknown, any other unanswered read leaves the candidate unscreened),
  and the world and chain are put back as they were, every memo (``solver_record``, ``_brought``), count and budget
  included, so an unknown read in the screen never reaches a later question. Each
  candidate's questions may spend at most half the work left when it is asked (``_SHARE``); what every candidate
  shares (the stranger's chances) is asked under the decision's own limit. The order only: every candidate is asked
  about in turn, and one a budget leaves unasked is counted (``untested_candidates``)
  (``test_budgets::test_candidates_the_state_refuses_are_asked_about_last``,
  ``test_budgets::test_the_screen_reads_nothing_and_leaves_no_trace``).
* A delegatecall or a call into this contract's own entry point inside a loop marks storage unknown past the loop
  (``*elsewhere``) without counting as lost writes: those writes are that code's (``logged.py`` and the latch account
  for them there).
