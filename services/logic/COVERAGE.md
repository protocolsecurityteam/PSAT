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
| Length | HANDLED | memory array, storage length slot, calldata size, code length (``test_elements`` stored/calldataArray/firstBytes, ``test_lower_shapes`` made/onlyAccounts, ``test_constructs`` storageLength/calldataLength/ownCodeLength/dataLength, against the chain) |
| LibraryCall | HANDLED | as InternalCall, ``storage`` parameters by location (``test_library_writers``) |
| LowLevelCall | HANDLED, APPROXIMATED (A12) | ``.call``/``.delegatecall``. **A12** ``.staticcall`` (a query, no action) taken as an arranged action: success and returned data ``assumed``, so an ERC-1271 / permission check through ``staticcall`` passes for everyone; ``.call`` whose data hands the caller to the callee also assumed |
| Member | HANDLED | storage/memory/argument/loaded struct fields, enum members, library constants, ``I.f``, ``.code``/``.codehash`` (``test_lower_shapes``); fields of a struct a call returns: every field in place (of an all-static struct, a nested struct, beside a dynamic field, of a struct among several return values) as the item of the ABI-decoded return data, ``("abi", call, returns, path, type)``, decoded by its type from the chain's answer (a ``bytes4`` right-aligned, a signed field as its two's complement word, a bool, an enum; never the raw word, which the earlier one-word ``item`` path took, left-aligned for ``bytesN``, flipping a ``!=`` gate's polarity: round ten-b H3) and read from a followed callee's own returned struct; an item of a fixed-size array field (``xs[1]``, ``pair[1].sel``) is the item one path step down, by a constant in the lowering (``lower.abi_element``) or by an argument's value in the evaluator, its length the declared one (H4); ``test_call_structs`` differentials over bytes1/bytes4/bytes32/bool/int8/int128/uint8/enum/address in static and dynamic structs, followed and unfollowed, each against ``eth_call``; a dynamic field (``bytes``, ``string``, a dynamic array) refused by name, ``unsupported:member:<field>``; anything else ``op field`` (evaluates unknown) |
| NewArray | HANDLED | zeroed items for small constant lengths (``test_lower_shapes``); Panic 0x41 (too large) not modelled (A9 family) |
| NewContract | HANDLED | action mark, address ``unknown:created`` (``test_constructs`` created/created2/createdOk: the address rejected by name, success against the chain) |
| NewElementaryType | HANDLED | ``new bytes(n)`` length (``test_lower_shapes``) |
| NewStructure | HANDLED | fields by name; arity mismatch ``unknown:NewStructure`` (``test_constructs`` built, against the chain; an arity mismatch no longer compiles, A29) |
| Nop | HANDLED | no effect (Slither emits it only in a constructor calling a base without one: never in an entry point decided) |
| Phi, PhiCallback | REJECTED (implicit) | SSA-only, never in ``node.irs``; would fall to ``unknown:<class>`` (implicit) |
| Return | HANDLED | every test |
| Send | REJECTED | result ``unknown:Send`` (``test_ir_coverage`` viaSend) |
| SolidityCall | see builtins | |
| Transfer | HANDLED | arranged action (``test_actions::test_paying_ether_out_lowers_as_an_action``, against ``eth_call``) |
| TypeConversion | APPROXIMATED (A13) | see conversion kinds |
| Unary | HANDLED, APPROXIMATED (A2) | ``!`` exact; ``~`` 256-bit whatever the width |
| Unpack | HANDLED | tuple items (``test_lower_shapes``) |
| CodeSize (``operations.codesize``) | HANDLED | ``a.code.length`` (``test_pool_shapes::test_a_pull_built_at_the_free_memory_pointer_is_the_transfer_it_encodes``, ``test_constructs`` otherCodeLength/eoaCodeLength, against the chain) |
| Call, Operation, OperationWithLValue | n/a | abstract bases; anything unmatched falls to ``unknown:<class>`` |
| BinaryType, UnaryType | n/a | enums (members covered under Binary/Unary) |

### Builtins (``SOLIDITY_FUNCTIONS``)

Solidity-level:

| builtin | state | |
|---|---|---|
| ``require(bool)``, ``require(bool,string)``, ``assert(bool)`` | HANDLED | path condition (every test) |
| ``require(bool,error)`` | HANDLED | IR form, or the expression when the IR drops it (``test_language`` requiredError) |
| ``revert()``, ``revert(string)``, ``revert `` | HANDLED | path ends |
| ``keccak256(bytes)``, ``sha256(bytes)``, ``ripemd160(bytes)``, ``keccak256()``, ``sha256()``, ``ripemd160()``, ``sha3()`` | HANDLED | ``hash`` (``test_language`` hashed*, ``test_engine_pieces``); ripemd160 rejected by name (``test_constructs`` ripemd); sha256 of known bytes unknown unnamed: A54 |
| ``ecrecover(bytes32,uint8,bytes32,bytes32)`` | HANDLED | ``signer`` (``test_lower_shapes::test_a_packed_signature_reads_back_as_the_signer_check``, ``test_actions::test_a_signed_deposit_pulling_chosen_amounts_is_open_to_any_signer``, ``test_constructs`` recovered; a signature of another digest still recovers the sender: A53) |
| ``addmod``, ``mulmod`` | HANDLED, APPROXIMATED (A14) | evaluated exactly; **A14** Solidity's form reverts (Panic 0x12) on a zero modulus, Yul's returns 0: both read as 0 |
| ``selfdestruct(address)``, ``suicide(address)`` | HANDLED | halts successfully, action (``test_selfdestruct``, ``test_constructs`` destroyed, against the chain) |
| ``gasleft()`` | REJECTED | ``unknown:gasleft()`` (``test_core``) |
| ``blockhash(uint256)``, ``blobhash(uint256)`` | REJECTED | ``opaque`` (no test) |
| ``log0..log3(bytes32...)`` (Solidity's) | HANDLED | no effect on success (``test_constructs::test_solidity_s_own_logs_change_nothing_about_success``, 0.4.19) |
| ``abi.encode()``, ``abi.encodePacked()`` | HANDLED, APPROXIMATED (A15) | ``enc`` (``test_logged``, ``test_lower_shapes``). **A15** hashing ``abi.encode`` of a ``bytesN`` (N < 32) right-aligns it (the ABI left-aligns) |
| ``abi.encodeWithSelector()``, ``abi.encodeWithSignature()`` | APPROXIMATED (A15) | ``enc``; hashed, the selector/signature is encoded as a whole word instead of 4 bytes |
| ``abi.encodeCall()`` | HANDLED, APPROXIMATED (A15) | as ``encodeWithSignature``; the fallback ``enc("abi.encodeCall")`` hashes as plain words |
| ``abi.decode()`` | HANDLED | of an ``abi.encode``, of an arranged return; else ``opaque`` (``test_lower_shapes``) |
| ``bytes.concat()``, ``string.concat()`` | REJECTED | ``opaque`` (no test) |
| ``type(address)``, ``type()`` | REJECTED | ``opaque`` (constants are folded by Slither) |
| ``this.balance()`` | REJECTED | ``opaque`` |
| ``balance(address)`` | HANDLED | ``balance`` (``test_constructs`` ownBalance/otherBalance, against the chain) |
| ``code(address)`` | HANDLED | ``code`` (``test_constructs`` ownCodeLength) |
| ``codehash(address)`` | REJECTED | ``opaque`` |
| Vyper builtins: ``create_from_blueprint()``, ``create_minimal_proxy_to()``, ``empty()``, ``convert()``, ``len()``, ``method_id()``, ``unsafe_sub()``, ``unsafe_add()``, ``unsafe_div()``, ``unsafe_mul()``, ``pow_mod256()``, ``max_value()``, ``min_value()``, ``concat()``, ``ecrecover()``, ``isqrt()``, ``range()``, ``min()``, ``max()``, ``shift()``, ``abs()``, ``raw_call()``, ``_abi_encode()``, ``slice()``, ``uint2str()``, ``send()`` | APPROXIMATED (A16) | ``opaque`` values with no effect: ``raw_call``/``send``/``create_*`` (calls out, revert on failure) silently dropped; ``unsafe_*``/``convert`` values unknown but unnamed as Vyper |

Yul builtins (Solidity >= 0.6 assembly, lowered by Slither to ``SolidityCall``):

| builtin | state | |
|---|---|---|
| ``mstore``, ``mload`` | HANDLED | constant-offset memory words; lost words ``opaque(mload, unknown memory)`` (``test_lower_shapes``, ``test_core_soundness``) |
| ``mstore8``, ``calldatacopy``, ``codecopy``, ``extcodecopy``, ``mcopy`` | HANDLED | memory forgotten (later ``mload`` lost) |
| ``returndatacopy`` | HANDLED | first word of the last call, else memory forgotten (``test_pool_shapes``, ``test_constructs`` returnCopyKnown/returnCopy, against the chain) |
| ``keccak256(uint256,uint256)`` | HANDLED | hash of the bytes earlier ``mstore`` left (``test_logged``) |
| ``sload``, ``sstore``, ``tload``, ``tstore`` | HANDLED | ``rawload``/raw writes; transient zero at start (``test_constructs`` transient/transientFresh, ``test_callee_actions``, ``test_arranged``) |
| ``calldataload``, ``calldatasize`` | HANDLED | argument words / ``elem(msg.data, off)`` (``test_constructs`` dataLength/dataByte, ``test_callee_frame`` words, against the chain) |
| ``extcodesize``, ``extcodehash``, ``balance(uint256)``, ``selfbalance()`` | HANDLED | ``codesize``/``codehash``/``balance`` (``test_constructs`` yulCodeSize/yulCodeHash/yulBalance/yulSelfBalance) |
| ``returndatasize`` | HANDLED | ``retsize`` of the last call (``test_pool_shapes``, ``test_constructs`` returnSizeKnown; with no call placed before it, ``unsupported:returndatasize()``, returnSize) |
| ``call``, ``callcode`` | HANDLED | arranged action, or the action ``abi.encode*`` data names (``test_pool_shapes``, ``test_constructs`` yulCallOk; a callee that always reverts read as success: A52) |
| ``staticcall`` | HANDLED | the view call encoded data makes, else ``opaque`` (``test_lower_shapes::test_an_assembly_staticcall_of_encoded_data_is_the_view_call_it_makes``, ``test_constructs`` yulStaticcallEncoded/yulStaticcall) |
| ``delegatecall`` | HANDLED | ``delegate`` (``test_versions``, ``test_constructs`` yulDelegatecall: unknown) |
| ``create``, ``create2`` | HANDLED | action, ``unknown:created`` (``test_constructs`` created/created2) |
| ``return``, ``stop``, ``revert(uint256,uint256)``, ``invalid()``, ``selfdestruct(uint256)`` | HANDLED | halt / path ends (``test_constructs`` yulStop/yulInvalid, ``test_language`` halted) |
| ``log0..log4(uint256...)`` | HANDLED | ``emit`` marks (``test_constructs`` yulLogs) |
| ``pop(uint256)`` | HANDLED | discarded (``test_constructs`` yulPop) |
| ``byte(uint256,uint256)`` | HANDLED / REJECTED | packed-signature ``v``; else ``opaque`` |
| ``timestamp()``, ``number()``, ``chainid()``, ``basefee()``, ``coinbase()``, ``gaslimit()``, ``difficulty()``, ``prevrandao()``, ``gasprice()``, ``blobbasefee()`` | REJECTED (since A38 HANDLED: ``test_ir_coverage::test_handled_environment_builtins_are_their_values``, ``test_constructs`` timestamp/number/chain) | ``opaque`` (same for every caller: not wrong, never resolved) |
| ``address()`` | REJECTED | ``opaque`` (should be ``this``); since A38 ``this`` (``test_constructs`` yulAddress, ``test_ir_coverage::test_handled_environment_builtins_are_their_values``) |
| ``caller()``, ``origin()``, ``callvalue()`` | HANDLED | Slither rewrites them to ``msg.sender``/``tx.origin``/``msg.value`` |
| ``gas()``, ``msize(uint256)``, ``pc()``, ``codesize()``, ``clz(uint256)``, ``signextend(uint256,uint256)`` | REJECTED | ``opaque`` |
| ``sdiv``, ``smod``, ``slt``, ``sgt``, ``sar`` | APPROXIMATED (A3) | Slither rewrites them to ``int256`` conversions around an ordinary ``Binary``: read as unsigned |

### Special variables (``SOLIDITY_VARIABLES``, ``SOLIDITY_VARIABLES_COMPOSED``)

| variable | state | |
|---|---|---|
| ``msg.sender``, ``tx.origin``, ``this``, ``msg.value``, ``msg.sig``, ``msg.data`` | HANDLED | ``caller``/``origin``/``this``/``callvalue``/``sig``/``msg.data`` (``test_constructs`` origin/self/sig/dataLength/dataByte, ``test_core``, ``test_origin_*``, ``test_lower_shapes``) |
| ``now``, ``block.timestamp``, ``block.number``, ``block.chainid``, ``block.basefee``, ``block.prevrandao``, ``block.difficulty``, ``block.coinbase``, ``block.gaslimit`` | HANDLED | ``time`` terms (``test_constructs`` timestamp/number/chain, ``test_arranged``, ``test_governance``) |
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
| storage read after an exact write | HANDLED | ``_read_at`` (``test_elements`` wholeThenField/crossed/rawAgain) |
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
| ``add sub mul div mod exp and or xor shl shr lt gt eq iszero not`` | HANDLED | unsigned word ops (``test_yul::test_legacy_assembly_arithmetic_is_the_evm_s``, ``test_constructs::test_the_legacy_assembly_reader_computes_words_as_the_evm_does``, 0.4.19 and 0.5.14 against the chain) |
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
| A8 | bytes index as a word | HANDLED: one byte (``slice(elem(x, k), 0, 1)``) | ``test_elements::test_a_bytes_index_is_one_byte_not_a_word``, ``test_the_first_bytes_of_a_slice_*`` (against the chain) |
| A9 | Panics not in the path | HANDLED: index out of range (0x32, memory, calldata and storage arrays; not mappings), enum conversion and enum arguments (0x21), allocation past 2**64 (0x41), pop on empty (through checked ``-``) | ``test_elements`` (literal; ``test_calldata_items_are_*``, ``test_storage_items_are_bounded_*`` against the chain), ``test_constructs`` (storageItem, calldataItem), ``test_language`` (``member``, ``enumArgument``, ``allocated``) |
| A10 | callee writes into memory parameters lost | HANDLED: parameters hold the caller's object; reassigning a parameter points it elsewhere | ``test_elements::test_a_callee_writes_into_the_callers_object_but_reassigning_its_parameter_does_not`` |
| A11 | function pointer call assumed to succeed | REJECTED: ``unsupported:InternalDynamicCall`` on the path, value and writes unknown | ``test_ir_coverage`` (``viaPointer``) |
| A12 | ``.staticcall`` and caller-naming ``.call`` assumed | HANDLED: the view call / action the ``abi.encodeWith*`` data names (``ok``, decoded words); undecodable staticcall data ``unsupported:staticcall``, undecodable call data naming the caller ``unsupported:call_data`` | ``test_language::test_a_low_level_call_is_the_call_its_data_encodes`` (against a real target; a ``.call`` handing the caller is an action handed the caller: with no callee code answering it is unknown for every sender, never assumed, M3), ``test_an_undecodable_staticcall_is_rejected_by_name``, ``test_origin_shapes::test_a_low_level_staticcall_in_followed_code_is_the_view_call_its_data_encodes`` |
| A13 | conversions unmasked / bytes misaligned | HANDLED: every integer width, address, ``bytesM`` -> ``bytesN`` as a shift, ``bytes`` -> ``bytesN`` its first N bytes; same in evaluator and solver (``converted``) | ``test_language`` (``narrowed``, ``cut``, ``padded``, ``unsignedOf``, ``signedOf``, ``tiny``) |
| A14 | Solidity mulmod/addmod by zero | HANDLED: nonzero modulus required outside Yul (>= 0.5) | ``test_language`` (``modulus``) |
| A15 | encodings hashed wrongly; an ``abi.encode`` item read from storage, computed, or handed into an inlined function no longer said its type, so a storage ``bytes4`` was right-aligned (and, handed on as ``bytes`` to an unfollowed callee, sent to the chain wrong) | HANDLED: every ``abi.encode``/``encodeWithSelector``/``encodeWithSignature``/``encodeCall`` item takes its argument's declared one-word type (a contract an address, an enum a ``uint8``; ``Lowerer``'s ``_typed_word``, as ``abi.encodePacked`` items already did): ``bytesN`` left-aligned, signed integers sign-extended, ``msg.sig`` a ``bytes4``; an item of unknown or dynamic type is refused (the encoding unknown), never laid out as a guess, and named: an item whose declared type is not one word and whose value isn't an argument or a literal (a struct, an array, ``bytes``/``string`` from storage, a function, a user-defined value type), a signature read from storage, and an ``abi.encodeCall`` Slither didn't render as its parts are ``unknown:unsupported:abi_item:<type>`` (it was an unnamed ``read_failed:condition``, review 5 ``q3b``); 4-byte selector for ``encodeWithSelector``/``encodeWithSignature``, other kinds not encoded | ``test_language`` (``hashed*``, ``concatenated``), ``test_abi_encode_types`` (storage, expression, literal and inlined-argument ``bytesN``, ``int8``/``int16``, address, bool, ``uint8``/``uint64``/``uint256``, a refused ``string``, followed and unfollowed, against the chain; review 5's sixteen item kinds and five wrong layouts, seeded and not, ``test_every_kind_of_item_is_laid_out_as_the_chain_does_or_refused_by_name``) |
| A16 | Vyper builtins dropped | REJECTED: ``unsupported:vyper:<name>`` on the path, writes lost | ``test_ir_coverage::test_each_rejected_builtin_lowers_to_its_label`` |
| A17 | ``tx.gasprice`` read as base fee | REJECTED: ``unsupported:tx.gasprice`` | ``test_ir_coverage`` (``viaGasprice``) |
| A18 | calldata slices dropped | HANDLED for ``msg.data[4:]`` and ``bytesN(x[:N])`` (``bytesN(x)``, with ``N <= x.length`` on the path); REJECTED otherwise: in a statement slicing anything else, dynamic calldata reads ``unsupported:slice`` (``unsupported:slice_source`` where the source can't be read faithfully, A47) | ``test_ir_coverage`` (``viaSlice``), ``test_slice_source`` |
| A19 | nested memory writes lost | HANDLED: an item or field written in place is written back where its holder lives | ``test_elements::test_nested_memory_writes_reach_the_outer_value`` |
| A20 | loop-carried values kept from unrolled iterations | HANDLED: the widened state forgets every local, object and storage variable the body's operations (and callees) may write; storage reads past it are ``opaque(loop:N, ...)`` (``havoc`` marks) | ``test_elements::test_a_variable_a_later_iteration_writes_is_forgotten``, ``test_what_only_a_later_iteration_writes_is_never_taken_as_unwritten`` |
| A21 | exits from later iterations | HANDLED: a loop that may return (or halt) past the iterations followed exactly also exits with unknown values, and one that may ``break`` leaves with what it writes forgotten; a list is followed exactly up to the bound (three entries named, nothing forgotten) and past it the answer is left open (``unknown:loop``), never cut | ``test_elements::test_a_member_past_the_iterations_followed_is_never_left_out_of_a_complete_list`` (``viaReturn``, ``viaBreak``, ``viaDoWhile``), ``test_elements::test_a_list_is_followed_exactly_up_to_the_bound_and_never_past_it``, ``test_elements::test_a_return_or_break_past_the_iterations_followed_is_never_dropped`` |
| A22 | ``do``/``while`` back edges dropped | HANDLED: unrolled, then widened like any loop; the scheduler orders them | same test (``viaDoWhile``) |
| A23 | irreducible flow dropped | REJECTED: ``unsupported:irreducible_cfg`` / ``unsupported:loop_shape`` exits, now only for flow no structured loop explains (nested loops and ``for (;;)``, which produced them, are A44/A45) | known REJECTED: none of the 177-row regression subset since the loop-control fixes (A45, A48, ``_schedule`` ordering a back edge by its own source; Lido ``proveWCAndActivate`` was the one ``unsupported:irreducible_cfg`` row), none ``loop_shape``; no Solidity probe produces one |
| A24 | codeless storage-computed target latched | HANDLED: "no code at an address" latches only for this contract or a precompile (0x01-0x11) the code names, for a call's target and a ``code``/``codesize``/``codehash`` read alike; a constant or an immutable with no code now may be where a contract is created later, so the condition reads as it stands and whoever passes once it opens is named; ``_values_at`` counts writes around, within, and past loops | ``test_latching`` (``a_codeless_constant_target_is_how_the_condition_reads_now``, ``a_codeless_immutable_target_is_never_latched``, ``no_code_at_a_precompile_stays_latched``) |
| A25 | legacy regex bindings past control flow | HANDLED: bindings and writes only from text before any control flow; past it, unknown and ``lost`` | ``test_language::test_legacy_assembly_assigns_nothing_for_sure_past_control_flow`` (0.4.19 against the chain) |

Found while working, not in the before table:

| # | was | now | pinned by |
|---|---|---|---|
| A26 | ``sload`` ignored an earlier ``sstore`` in the same call; named and raw writes never aliased | HANDLED: raw and transient slots read through earlier writes; a small or unhashed raw slot written makes named reads ``unsupported:raw_named_alias`` (and back) | ``test_elements::test_a_raw_slot_reads_back_what_this_call_stored_there`` (the ``unsupported:raw_named_alias`` direction has no test) |
| A27 | a location written again kept its first position; merges took one path's write order | HANDLED: writes move to the end; merges reread each path's final value where orders differ or a path left the key alone | ``test_elements::test_writes_two_branches_make_in_opposite_orders_read_back_per_branch`` |
| A28 | ``delete a[i]`` in memory zeroed the whole array | HANDLED | ``test_language`` (``deletedItem``) |
| A29 | a struct built without its mapping fields left its variable unset (zero) | REJECTED: ``unsupported:NewStructure`` | (Solidity >= 0.7 refuses to compile one) |
| A30 | a storage pointer chosen by branch merged into a value; writes through it lost | REJECTED: ``unsupported:storage_pointer_choice``, writes mark all storage unknown | ``test_elements::test_a_storage_pointer_chosen_by_branch_reads_and_writes_unknown`` |
| A31 | storage after a call into this contract's own entry point (``this.f()``) or a delegatecall read as before | HANDLED: reads unknown past it (``selfcall:<sig>``, ``delegatecall``) | ``test_elements::test_storage_after_a_call_into_this_contracts_own_code_reads_unknown`` |
| A32 | ``msg.value`` free in a function that isn't payable | HANDLED: zero (a call with ether reverts) | ``test_language`` (``sent``) |
| A33 | an assembly ``return`` inside an internal function returned to its caller | HANDLED: it ends the whole call (``Exit.halted``) | ``test_language`` (``halted``) |
| A34 | a short-circuit operand not separable from the rest ran unconditionally | REJECTED: ``unsupported:short_circuit`` | (no probe found that Slither renders so) |
| A35 | operations after an internal call in the same statement took the callee's last node (checked/Yul scope, slices) | HANDLED: the statement's node restored | the checked-arithmetic probes |
| A36 | ``abi.decode`` of an encoded word as a narrower type | REJECTED: ``unsupported:abi.decode:<from>-><to>``; same or wider integer types decode exactly | no test of the narrowing itself (``test_lower_shapes`` deposit decodes at the same width) |
| A37 | a field of any other value read as an unnamed ``op field`` | REJECTED: ``unsupported:member:<field>`` (a dynamic field of a struct a call returns, a field of a value the lowering couldn't follow); a field of an item of a calldata struct array is the caller's per-item choice. Fields of structs a call returns are items of its decoded return data (2026-10-26): before, a struct with a dynamic field was read by word, its offset word taken for its first field, and several return values with a struct among them were read by position, the words after the struct shifted (``taggedNonce(32)``, ``mixed`` in ``test_call_structs`` fail at e2f2cb1e) | ``test_ir_coverage`` (``viaMember``), ``test_call_structs`` |
| A38 | ``this.balance``, ``codehash(a)``, Yul ``address()``/``timestamp()``/... opaque; ``bytes.concat``/``string.concat`` opaque | HANDLED: their values (``balance``, ``codehash``, ``this``, ``time``), concat as ``encodePacked`` | ``test_ir_coverage::test_handled_environment_builtins_are_their_values``, ``test_language`` (``concatenated``) |
| A39 | a followed callee read ``msg.value``, ``msg.data``, ``msg.sig`` and ``calldatasize`` as the outer call's (its guessed ``msg.value`` let a stranger through a view callee that sees none) | HANDLED: ``Lowerer.called`` lowers a callee in its own frame: ``msg.value`` zero for a view call, ``unknown:callee:msg.value`` for an action, ``msg.sig`` its own selector, ``msg.data`` (but ``msg.data[4:]``, its arguments) and ``calldatasize`` ``unknown:callee:*``; what the caller hands it keeps the caller's terms | ``test_callee_frame`` (``a_view_callee_reads_no_value``, ``a_callee_reads_its_own_selector``) |
| A40 | a callee's own calls were lowered and asked of the chain as made by the contract decided (``msg.sender`` two levels down was the outer contract) | HANDLED: a call made by followed code carries who makes it (``("call", ..., view, sender)``); its callee is lowered with that sender and the chain asked from it, unless the callee's code provably answers alike for every asker (lowered with a stand-in sender that never shows, nothing unread, no ``tx.origin`` reached: ``verdict.asker_free``), where it is asked as this contract | ``test_callee_frame::test_a_callee_of_a_callee_sees_the_callee_asking_as_its_sender`` |
| A41 | a word or the size of the call's own ``msg.data`` was guessed apart from the arguments it encodes (``calldataload`` at an offset an argument picks) | HANDLED: inside the arguments' encoding a word is what the guessed arguments put there (every argument guessed with it); past it, bytes the caller may append, guessed; the size never below the encoding | ``test_callee_frame::test_a_word_of_the_call_data_inside_the_arguments_is_what_they_encode`` |
| A42 | a ``bytesN`` Slither computes (``f.selector``, ``type(I).interfaceId``) kept as the text of its decimal number, never equal to a number | HANDLED: read as the number (a literal is typed ``string`` until converted); text compared with a number evaluates unknown, never false | ``test_callee_frame::test_a_callee_reads_its_own_selector`` |
| A43 | ``continue`` in a ``while`` or ``do``/``while`` body, or a ``for`` without an increment, jumped to the body's last statement (Slither takes any statement leading into the condition for a ``for``'s increment); in a ``for`` without a condition, past the increment: wrong answers both ways | HANDLED: ``_continue_target`` sends it to the increment of a ``for`` that has one (a statement of the loop's own before its body in the source), else the condition, else the loop's start; ``unsupported:continue`` where the loop can't be told apart | ``test_loop_control`` (``whileBreakContinue``, ``whileContinue``, ``doContinue``, ``forWithoutIncrement``, ``forWithoutCondition``, ``forever``, ``forContinue``) |
| A44 | every loop nested in another, once its inner loop was followed an iteration further, rejected as ``unsupported:irreducible_cfg`` (the iteration ran on from the inner header, entering the outer loop half way) | HANDLED: an iteration of a loop whose exit leads back to its header runs as a region, its leaving states handed back to the run that asked | ``test_loop_control`` (``nestedPlain``, ``nestedBreak``, ``nestedContinue``, ``nestedSymbolic``) |
| A45 | ``for (;;)`` (no condition) rejected as ``unsupported:loop_shape``; once handled, a ``break`` in a ``for (;;)`` nested in a loop with a condition followed Slither's edge to the OUTER loop's ``ENDLOOP`` (a stranger let through read as owner-only) | HANDLED: a loop whose condition is always true; every ``break`` (Solidity's and Yul's) goes to the ``ENDLOOP`` of the innermost loop whose source (compiler offsets) holds it (``_break_target``), never Slither's edge; ``unsupported:break`` where no span tells the loop | ``test_loop_control`` (``forWithoutCondition``, ``forever``, ``foreverInFor``, ``foreverInWhileInFor``, ``foreverInForever``, ``doBreakInFor``, ``a_break_whose_loop_cant_be_told_from_the_source_is_rejected_by_name``) |
| A46 | a value-type local declared without a value (``uint256 j;``) read as ``unknown:unset`` where branches merged, and kept the previous iteration's value when its declaration ran again (an inner loop's counter); once zeroed at every declaration, that was wrong before solc 0.5, where locals are function-scoped and the declaration emits no code | HANDLED by the compilation unit's solc version: >= 0.5 zero (a fresh zeroed object in memory) each time the declaration runs; a Yul ``let`` without a value zero each time it runs in every version (Slither marks Yul locals ``memory``; a Yul function's parameters, declared the same way, keep what they are handed); sibling Yul blocks each declaring ``let x`` get two Slither variables named alike with every use bound to one of them (a read after the second ``let x`` read the first block's value): where all the declarations are Yul's and the uses name at most one of the variables, the name is one cell each declaration starts again (Yul forbids shadowing a name in scope, so lifetimes never overlap), else a read of any of them is ``unknown:shadowed:<name>`` (also for same-named Solidity locals unless the uses name each one, ``Lowerer._same_named``; and, since review 5, for every Solidity local of a base name declared more than once, ``x`` / ``x_scope_0``, wherever assembly names one of them: Slither binds the assembly's ``x`` to the first declaration even where the second is in scope); < 0.5 every value local zero at the function's (or modifier's) entry and the declaration keeps what it holds, a modifier's ``_`` run again included (A50) (a memory local's object made on first touch, kept after); version unread: a local holding anything but zero is ``unsupported:declaration_scope`` | ``test_loop_control`` (``declaredInLoop``, ``nested*``, ``yulLet*``, ``yulFunctionLet``), ``test_declaration_scope`` (0.4.19 and 0.5.14 against the chain), ``test_yul_siblings`` (``sib*`` against the chain; the unknown-by-name rule; ``solSolYul``, ``solYulSol``, ``yulWritesSecond`` unknown and ``solThenYul``, ``solSol`` definite, against the chain) |
| A47 | where a statement's source couldn't be read (Slither's slice cut a character in two, offsets shifted), any reading without ``:`` counted as "no slice": ``x[a:b]`` read as ``x``, ``msg.data[4:]`` as the whole ``msg.data``; likewise a Yul ``sload(SLOT)`` read as ``SLOT`` and a ``hex`` literal's bytes as its text | REJECTED by name: a reading counts only when faithful (every calldata value the statement reads named in it, brackets balanced); else its dynamic calldata reads ``unsupported:slice_source``, the Yul assignment ``unsupported:yul_source``, the literal is not folded; a statement reading no calldata needs no source | ``test_slice_source`` |
| A48 | Yul ``for`` loops (Solidity >= 0.6 assembly, Slither's graph): the condition node's sons are ordered [exit, body], so the body never ran (``t`` stayed 0, definite); a Yul ``continue`` read as a ``do``/``while``'s (init before the condition) and skipped the post block; a Yul ``break``/``continue`` edge leads to the end of its ``if`` | HANDLED: a loop condition's exit is its loop's ``ENDLOOP`` by source, the other son the body (``_loop_exit``/``_loop_body``), for every loop; ``do``/``while`` told by its body written before the condition; ``continue`` to the post block's first statement (several chained in source order), else the condition; ``break`` as A45; ``unsupported:loop_shape`` where a condition node's sons aren't one exit and one body | ``test_loop_control`` (``yulFor``, ``yulContinueBreak``, ``yulNested``, ``yulPost``, ``yulInFor``) |
| A49 | a stranger let through only once a condition the function consumes itself is back (a spent initializer's version), or only where its call does nothing: where the formula may single someone out it fell through to a confident "nobody", where it can't it was not determined | HANDLED: a consumed condition latching proves no entry point can write back reads as it stands; otherwise not determined, ``inert_when_allowed``, whichever branch decides. "Nobody, ever" itself is meant to be claimed only on what never changes (A51), which does not yet hold for a condition inside a disjunction or behind an early exit, nor for slots a redeploy can write (KNOWN GAPS G1, G2's residue; slots a delegatecall or a proxy upgrade can write are no longer constant, D1) | ``test_consumed_conditions`` (``initAnyone``, ``initUnbanned``), ``test_arranged::test_what_anyone_may_redo_once_holders_did_it_is_not_open`` |
| A50 | a modifier's ``_`` run more than once (``_; _;``, ``_`` in a loop) ran the function body each time from the frame at the modifier's entry: parameters and return variables an earlier run wrote were reset (every version), and before 0.5 so were the function-scoped locals | HANDLED: the function's frame (its parameters, return variables and locals, by variable) rides in the modifier's state; each run of ``_`` starts from what the last left (a ``return x`` assigns the return variables first), a local declared again zeroed there by A46's rule; a run not followed to its end (an unfollowed path, a widened loop's return) leaves the next run's frame unknown (``unknown:modifier_frame``) | ``test_declaration_scope`` (``twice*``, ``loopAcc`` on 0.4.19, 0.5.14 and 0.8.27 against the chain) |
| A51 | a condition not about who calls that reads settable state, false now for every argument (``amount >= lo && amount <= hi`` with ``lo > hi``, both owner-settable), refuted everyone as it read now: restricted, complete, nobody | PARTIAL (see KNOWN GAPS G1, G2, G4 below: the claim below holds only for conditions that are top-level conjuncts of a single-exit formula, and only as far as ``constant_load`` sees every writer: since D1 no slot is constant where a delegatecall of the contract's own or a proxy can write it, ``verdict._delegating``): "nobody, ever" (restricted, complete, nobody listed) stands only where the conditions not about who calls that refute everyone read nothing a transaction may change: constants, immutables, ``this``, a slot of this contract no entry point can leave holding anything else from here (``verdict.constant_load``, as latching asks), or a latched condition. Otherwise those conditions are set aside: whoever the identity core then lets through is named holding only on them (``conditions``, ``allowed`` conditional; complete only where the core's own list is, every holder of the whole formula being one of the core's); where the rest still lets nobody through, completely, the claim stands (who they are refutes them); otherwise (no core, the rest open or undetermined) not determined; each variable named, ``state_blocks_everyone:<variable>`` | ``test_state_blocked`` |

| A52 | a Yul ``call`` to a callee that always reverts (no fallback, or a function that reverts) read as an arranged success: ``ok`` true where the chain returns 0 | OPEN (found 2026-10-24) | ``test_constructs`` (``yulCall``, ``yulCallFails``, strict xfail) |
| A53 | ``ecrecover(h, v, r, s)`` evaluated as the signer identity whatever digest and signature it is handed: a signature of another digest still "recovers" the sender | OPEN (found 2026-10-24) | ``test_constructs`` (``recovered-2``, strict xfail) |
| A54 | ``sha256`` of known bytes evaluates unknown with no label (neither computed nor rejected by name) | OPEN (found 2026-10-24) | ``test_constructs`` (``hashed``, strict xfail) |
| A55 | ``super.transfer`` into the next body of the linearization (solc 0.4.19 ``LinkToken.transferAndCall``) lowers the base's balance check without the amount (``0 <= balances[caller]``): a pass where the chain reverts | OPEN (found 2026-10-24) | ``test_lower_shapes::test_super_runs_the_next_body_in_the_deployed_contracts_order`` (strict xfail) |
| A56 | storage written inside a loop through a reference whose place moves (a pointer reassigned each iteration, ``Op storage o = $.ops[ids[i]]``; a part of storage handed to an internal function; a temporary holding a ``pure`` getter's pointer) marked every write of the contract lost (``Lowerer.lost``): no lookup of the contract was ever shown logged, so no holder list built from events was ever whole (Lido CSModule v3, 2026-10-26) | HANDLED: ``_loop_effects`` places each such write in the variable the reference roots in: a state variable, or a reference holding one place throughout its function (a parameter, or assigned only from a ``pure`` call with constant arguments or another such reference: ``_fixed_place``); a pointer the loop moves, wherever each of its assignments in the loop roots, and where its place on entry is a choice by branch, wherever each of its assignments in its function roots (``_pointer_places``). Anything else still marks everything | ``test_chosen_key_crowd`` (``Moved``, ``Handed``) |
| A57 | a storage pointer set on one branch and unset on the other merged into ``unsupported:storage_pointer_choice`` (its writes lost) | HANDLED for solc >= 0.5 (a storage pointer is assigned before it is read; a temporary where it is made): the branch that never set it never reads it, so the merge keeps the one place (``merge(defined=True)``); before 0.5 an unassigned storage pointer points at slot 0, and the choice stays | ``test_chosen_key_crowd`` (``Handed``) |
| A58 | ``continue`` in a ``for`` loop whose body opens with a tuple declaration: Slither's tuple statement starts a byte before the body's first node, so it was taken for a second increment and the loop "couldn't be told apart" (``unsupported:continue``, writes lost) | HANDLED: an increment lies wholly before the body (its span ends before the body begins) | ``test_chosen_key_crowd`` (``Continued``) |
| A59 | an assembly ``sstore`` at ``add(c ? keccak256(96 bytes) : keccak256(96 bytes), k)`` read as a write that may land on any mapping's entry, so no lookup of the contract was logged | HANDLED: ``logged._may_be_entry`` reads a choice between hashes by branch as either hash; neither of 96 bytes is an entry (``keccak256(key . slot)`` is 64) | ``test_chosen_key_crowd`` (``Keyed``) |
| A60 | a call whose target address no read gives (an argument the caller picks, another call's result, a value memory holds) reported ``read_failed:target:<sig>`` / ``read_failed:call_target:<sig>``, as though the node had failed a read: v51 carried them on 276/51/329 and 105/71/252 rows (Lido/Maple/Aave) with no RPC failure logged | HANDLED (labels only; the verdicts are those of before the relabelling, since round ten-c: the relabelling had flipped a function whose only unknown is a call to an address the caller names from not determined to open/conditional, since ``_opaque_conditions`` set aside any conjunct whose gaps all began ``unknown:``; it now decides on the terms, ``_rests_on_code_not_followed``: a call whose target no read gives, whose callee isn't followed or lies past ``IDENTITY_DEPTH``, or an unknown standing in for one (``taint.CALL_STAND_INS``) is never a condition every caller faces alike, whatever its label; probe q5, ``test_target_gaps`` ``Picky``): ``decide.target_unread`` reads why from the reads already made (``Chain.failed_keys``, ``refused_keys``; nothing read again): ``read_failed:*`` only where a word or call the target comes from went unanswered by the node; ``unknown:target:<why>:<sig>`` / ``unknown:call_target:<why>:<sig>`` otherwise, ``<why>`` one of ``keyed`` (stored behind a mapping key or at a slot the caller picks, ``tokens[k]``; round ten-c, probe q2), ``argument``, ``call_result``, ``memory``, ``budget`` (a read not sent for the budget), ``unresolved`` | ``test_target_gaps`` (``_oracle.Faulty`` brings ``read_failed`` back, ``never_bolder``) |

### KNOWN GAPS (open, documented 2026-10-24; reviewer probes in ``scratchpad/probe_audit4/``)

Each is a shape where a verdict is wrong or over-claims. Those marked FIXED say what was done and what remains.

* **G1. ``_state_blocked`` (F6) looks only at top-level conjuncts** (``decide._state_blocked``, the
  ``for part in conjuncts(formula)`` loop). A settable condition that refutes everyone, when it sits inside a
  disjunction with an identity check, or when the function has more than one exit, is never set aside: the verdict
  stays "restricted, complete, nobody" although the owner can make it pass for anyone. Probe ``c3.py``:
  ``orPending(a)`` = ``require((a >= lo && a <= hi) || msg.sender == pending)`` and ``branchy(a)`` =
  ``if (msg.sender == pending) { x = 1; return; } require(a >= lo && a <= hi)``, with ``lo = 10 > hi = 5`` and
  ``setRange`` owner-only: both "restricted complete nobody"; after ``setRange(0, 100)`` a stranger passes both.
  (``act``, the plain conjunct, is handled: not determined, ``state_blocks_everyone:hi/lo``.) A51's "HANDLED" was
  false for these shapes. **Extended (review 5, ``probe_audit4/f2.py``):** the same holds where the other side of a
  disjunction is a callee's answer another contract's owner can change: ``e10`` =
  ``require(msg.sender == owner || !g.blocked(abi.encode(tag)))`` is "restricted, complete, {owner}" though the
  blocklist's owner can unblock the tag for every stranger. Strict xfails:
  ``test_known_gaps::test_g1_a_settable_condition_beside_an_identity_check_is_never_nobody_ever``,
  ``test_g1_extended_an_owner_or_a_changeable_callee_answer_is_never_a_complete_list``.
* **G2. ``constant_load`` and writers outside the contract's own entry points** (``verdict.constant_load``).
  PARTLY FIXED 2026-10-24 (decision D1): a slot no entry point writes is changeable unless the contract makes no
  delegatecall (or callcode) of its own and runs at its own address (``verdict._delegating``: no low-level or
  assembly delegatecall, nor a call to a library's external or public function (run by ``DELEGATECALL``; before
  this an external library was caught only because crytic's unlinked ``__$...$__`` placeholder fails to parse), in
  any function or modifier, ``test_state_blocked::test_a_slot_an_external_library_can_write_is_never_nobody_ever``;
  no ``code_of`` naming other code; the deployed code is readable, is no EIP-7702 delegation, and has no ``DELEGATECALL``/``CALLCODE`` opcode the compiled contract lacks,
  nor a different length from it). Where it isn't, no slot is constant: "nobody, ever" never rests on one, and a
  precompile address read from storage is latched only where the slot is (``_fixed_target``). Probe ``c1.py``'s two
  rows are now not determined, ``state_blocks_everyone:hi/lo`` (``test_state_blocked::
  test_a_condition_on_a_slot_a_delegatecall_can_write_is_never_nobody_ever``, ``test_a_condition_behind_a_proxy_is_
  never_nobody_ever``, ``test_latching::test_a_precompile_in_a_slot_*``). **Residue:** a ``selfdestruct`` followed by
  a ``CREATE2`` redeploy of other code at the same address (same transaction since Cancun, any time before) can
  still change a slot read as constant; not modelled.
* **G3. "open" means "the call does not revert", not "the privileged effect happens".** ``world.effective`` (whether
  the call does anything) is consulted only for "open later" (``_acts_once_allowed``), never for "open now". A function
  that returns early before its gate for some argument is "open" with that argument as the witness, though nothing
  privileged happens on that path. Probe ``b1.py``: ``f1(v)`` = ``if (v == 0) return; require(g.ok()); x = v;`` is
  "open complete" with witness ``v = 0`` while only the origin ``g`` names can set ``x`` (``f2``, the gate first, is
  handled). A design gap: "open" should be claimed on the effect, not on not reverting. Kept for now (decision
  D3); strict xfail ``test_known_gaps::test_g3_open_is_claimed_on_the_privileged_effect``, today's meaning checked
  by ``test_g3_an_early_return_before_the_gate_is_open_as_the_call_does_not_revert``. **Extension (review 5,
  ``q1g3``):** with every stranger's own call run on the chain first (``strangers_run``), rows a failed read once
  left undecided are now settled "open" on the same meaning: ``e11`` = ``if (g.exempt(msg.sender)) return;
  require(msg.sender == owner); x = v;`` is "open" (every stranger returns early, nothing written) clean and with
  every call to ``g`` failing (``test_g3_extension_strangers_run_first_settle_open_where_reads_fail``).
* **G4. "Nobody, ever" vs "nobody now" for identity state.** A51 sets aside only conditions *not* about who calls.
  An identity check against settable state with nobody in it now (``msg.sender == pending`` with ``pending == 0``,
  owner-settable) is reported "restricted, complete, nobody", which reads as "nobody, ever" although the owner can
  name anyone. Probe ``c2.py``: ``accept`` and ``acceptCapped`` (``msg.sender == pending && v <= cap && v > 0``,
  ``cap == 0``): both "restricted complete nobody". The wording should be "nobody now" (or the setter's holders named
  as able to grant it), not "nobody, ever". The same where a stranger's own call sets the state (an owner never set
  that ``claim()`` takes). Strict xfails: ``test_known_gaps::test_g4_identity_state_nobody_holds_now_is_never_nobody_
  ever``, ``test_arranged::test_a_lone_owner_anyone_may_still_claim_is_each_strangers_to_take``.
* **G5. ``_free_sat`` relaxed mode takes a callee-code ``True`` as given** (``decide._free_sat``: each atom read by
  ``ev.truth``, which asks a ``False`` again without callee code but not a ``True``). Freeing business logic, an atom
  a followed callee's code answers ``True`` is trusted, so a candidate can be listed (over-listing, never a missed
  holder) on a mis-lowered callee's word. Fail-safe in direction (more listed, never fewer), but the list is not
  proven; ``Evaluator.passes``/``confirmed`` should be used there as elsewhere.
* **G7. A mis-lowered followed callee could make a verdict bolder than the clean run** (found by the fail-safe
  sweep, ``test_failsafe``, 2026-10-24; reproduced without fault injection, ``scratchpad/probe_audit6/``). FIXED
  2026-10-24 (all thirteen probes, under every callee fault, are never bolder; the natural reproductions are oracle
  tests in ``test_callee_misread``). The paths ran around ``strangers_run``, ``_inlined_verdict`` and ``runs``
  altogether. Three mechanisms, and a backstop:
  * **M1, origin decided from the lowering alone** (``verdict.caller_bound``, ``decide._reads_origin``). Whether a
    followed callee reads ``tx.origin`` was read off its lowering, so a read the lowering missed (a local declared
    twice and named in assembly, lowered ``unknown:shadowed:o``) made ``require(guard.ok())`` "open later, complete"
    where only the admin passes. Now its runtime code, deployed (and at the address whose code runs there) and as
    compiled, must hold no ``ORIGIN`` opcode too (``hidden`` where it does, ``unfollowed`` where it can't be read);
    ``_reads_origin`` reuses ``caller_bound``. The opcodes are those of the instructions a run can reach from offset 0
    (``verdict._reachable_code``: the ``JUMPDEST``s each stack entry holds from a ``PUSH``, moved by ``DUP``/``SWAP``,
    followed per way into a block; a target computed or loaded, or more than ``_WALK`` steps, makes every
    ``JUMPDEST`` a target), the trailer stripped only where it is, byte for byte, a compiler's CBOR metadata map of
    the known keys (``verdict._metadata_map``; else its bytes are code, a ``JUMPDEST`` among them a target): bytes
    that are data (a revert string's ``2``, the creation code of a contract it deploys, a child's ``bzzr0`` hash after
    ``INVALID``) no longer read as ``ORIGIN`` (nor as ``DELEGATECALL``, ``_delegating``). Before (review 7, F4), 87 of
    the 1,452 corpus contracts with code were flagged, 70 with no source reading ``tx.origin``; now 17, each with one
    (``scratchpad/probe_audit7/q4_origin_scan.py``, source grep only), none flagged before with a source lost
    (``test_origin_scan``).
    Cost: a callee contract reading the origin in any function it can reach is never read as the same for every
    caller (``test_core_soundness``, ``test_origin_shapes`` keep their origin-free callees in contracts of their own).
    Probes p9, p9e, p9r, q4, a10 (both), a11, mo, originBit.
  * **M2, a callee's code alone saying it reads the caller alike** (``decide._decide``, the branch where nobody is
    singled out). ``_singles_out`` records those calls (``coded``), but only "restricted" used it: one stranger passing
    made it "open now", a state letting one through "open later". Now "open now" there needs ``runs(FRESH)`` and
    ``strangers_run``; "open later" is not determined; both name ``callee_unsingled:<signature>``. Probe callerBit;
    natural: a check made by a call in assembly whose outcome the lowering assumes (``lowBit``).
  * **M3, an action handed the caller assumed to pass** (``Evaluator._action``, ``_returned_size``). Unfollowed, it
    was ``ASSUMED``; followed, a pass its lowering showed was taken unmarked, so ``passes``/``confirmed`` never asked it
    again (``Minter.mint`` open now, complete, while the chain refuses every stranger; likewise with A52 inside
    ``Supply.canMint``). Now an unfollowed one is unknown, a followed one's pass is marked as resting on callee code
    (unknown with no callee code answering), and ``decide`` runs every stranger's own call before opening on either
    (``_handed_actions``); candidates left undecided where the stranger is unknown are confirmed by their own call.
    An action's return-data size is its callee's declaration (``World.declared_size``), never its lowering. Probes
    Minter.mint, PullerListing.deposit, GPv2Listing.supply.
  * **Backstop** (``decide._confirmed_open``): every "open now" with nothing to hold first (no ``requires``) stands
    only on the chain; review 7 (F2/F3) removed its two exemptions, an open resting on what the stranger arranges and
    one sending ether. Every stranger's own call must go through as the chain stands (``runs`` with the witness or a
    search of its own, then ``strangers_run``: five calls run), sending the witness's ether with its balance set to it
    by a state override (``Chain.call_value``). An open on the stranger's own entries here (``arranged_atoms``) needs a
    call of its own that brings them about (``after_own_call``, also over entries keyed by an address it passes or
    naming it at a key it picks, its first call's arguments made concrete, then those that leave an entry nonzero,
    the key the first call wrote named by this one): each stranger's first call runs as the chain stands, then this
    one on the words it leaves (state overrides), and the verdict names that call (``after``). An open on an action
    handed the caller that its callee refuses only on entries the caller brings about there runs, as each stranger,
    the calls that bring them about (``verdict._arrangeable`` records them), then this call with those entries set by
    state overrides (``_brought_runs``); the words those calls leave are worked out from their lowering
    (``verdict.writer_words``), so an entry a stranger can only bring to 1 where 2 is wanted is never confirmed
    (``climb``). An action taking what the caller holds (a balance holders move to anyone) that no stranger holds is
    open on that holding (``requires``). A writer needing the very entry it would grant (a transfer to oneself) never
    counts as bringing it about (``_arrangeable``). Otherwise not determined, the proposal kept as data:
    ``open_value_unconfirmed`` (ether), ``open_arranged_unconfirmed`` (own entries arranged first),
    ``open_assumed_action_unconfirmed`` (an action assumed, or handed the caller: the contract's own Yul call into
    always-reverting code whose result it checks, A52, ``selfCall``; a creation; a ``transfer``), else
    ``open_unconfirmed`` (the code itself misread; probes ``q2_arranged``, ``q2c``, ``q5_declared``, ``q2d_value``:
    ``test_open_confirmed``), plus ``read_failed:run`` where the node left a stranger's own call unanswered (a
    timeout, an abort, a cap: never read as a refusal, ``decide._is_revert``). A node that refuses state overrides
    answers with an error, read as unknown: not determined, never open. "Open later" never rests on a callee's answer
    (see G6).
    An open once the conditions allow (or only with some set aside) on the stranger's own entries arranged
    (``decide._arranged_later``, review 8, F1) needs the same call of its own that brings them about: each
    stranger's first call runs on the chain as it stands, and this one passes on the words it leaves in a state of
    the conditions that lets a stranger through (``after_own_call`` with those states); the verdict is then witnessed
    and names that call (``after``), else not determined, ``open_arranged_later_unconfirmed``. Before, the entries
    arranged for the question stayed arranged once the stranger failed now, and a paused withdraw whose deposit locks
    what it fills was "open later, complete", proven, though nobody can ever pass (``probe_audit8/q3d_later.py`` w1,
    w3; ``test_arranged::test_an_open_once_unpaused_*``). The entries are put back whenever ``_decide`` returns, and
    an open now reached past that point rests on them (``open_arranged_unconfirmed`` unless the chain confirms it).
  * **Residue.** An open on holdings (``requires``: a balance holders move to anyone, a holding in another contract)
    is not run, the stranger lacking the holding: it is checked by the oracle's arrangement, not by the engine. And
    what no stranger can run is never confirmed, whatever its truth: a deposit relaying a holder's signature
    (``test_actions::test_a_signed_deposit_pulling_chosen_amounts_is_open_to_any_signer``, a strict xfail: the cost)
    is not determined. "Restricted" and lists are untouched by the backstop (lists already never rest on callee code;
    ``callee_code_list``).
* **G10. Balances only an owner credits read as the stranger's to arrange** (review 7, F1, pre-existing). FIXED
  2026-10-24. ``credit(w, a) onlyOwner { bal[w] += a }`` beside ``withdraw(a) { require(bal[msg.sender] >= a && a >
  0); bal[msg.sender] -= a; }`` was "open now, complete" (witness ``a = 1``) while no stranger passes: (1)
  ``verdict._arrangeable`` counted the decrement as a write that can leave the caller's entry nonzero; (2) asking
  whether a stranger gets past that writer's guard, ``a > 0`` was set aside as a free condition while ``bal >= a`` was
  met with ``a = 0``. Now (1) a write the constants of which aren't known counts as a grant only where it can turn
  the stranger's entry, zero now, nonzero: a checked decrement reverts below zero or leaves zero, an unchecked one
  (an ``unchecked`` block, solc before 0.8) wraps into a grant; and (2) in every relaxed question a condition on a
  value the caller chooses is set aside only jointly with every other condition reading the same value
  (``decide._jointly_freed``). ``test_self_credit`` (SRC1/2/3, strict and non-strict, the vesting ``claim``, an
  unchecked block and solc 0.7, both ways).
* **G6. "Open later" on a callee no transaction can make pass** (review 5, ``probe_audit5/q7.py``). FIXED 2026-10-24
  for callees: "open later" never rests on a callee's answer changing (``decide._acts_once_allowed``): a state that
  lets the stranger through only with a condition reading a call answering otherwise than it does now (asked of the
  chain, no callee code) shows nothing, not determined, ``later_on_callee:<signature>``; with every condition free
  (past ``_MAX_WHEN``) such conditions read as they stand. ``test_known_gaps::test_g6_*`` pass. **What remains:** the
  cost, a callee answer that can change (a blocklist its owner can clear, ``e9``) is not determined too, where "open
  later" was true (``test_g1_extended_a_callee_answer_its_owner_can_change_is_never_open_later_on_its_word``); and "open
  later" on this contract's own state still rests on latching and ``_reachable`` (a flag written only on a path no
  transaction reaches, a time no block reaches) and on ``world.effective``, as before.

* **G8. A stranger's own first call through a legacy storage array is not found** (found 2026-10-24 restoring the
  governance coverage, ``test_governance_shapes``). ``require(balances[msg.sender].length > 0)`` on solc 0.4.19, where
  any caller's own ``record`` raises the length in place (``checkpoints[checkpoints.length++]``) or ``add`` pushes
  through a storage pointer, is "restricted" (not complete, ``storage:balances``) though every stranger passes once its
  own call made the entry: ``after_own_call`` doesn't propose those writers. Under-claims openness, never "nobody,
  ever" (the length writes are seen). Strict xfail
  ``test_governance_shapes::test_a_strangers_own_legacy_array_write_opens_what_it_unlocks``.

* **G9. "Nobody" from a lookup whose writes log only the key** (found 2026-10-24 adding budget probes,
  ``test_budget_bites``). FIXED. ``require(managers[id] == msg.sender)`` with ``ManagerSet(uint256 indexed id)`` was
  "restricted, complete, nobody" while the managers pass: ``Evaluator._owned`` asked ``World.inverse`` which keys
  hold the caller, and that replayed value events that don't exist (only the key is logged) into an empty answer.
  ``verdict.inverse`` now answers only where every write's event names the value it leaves (as ``latest`` asks);
  the managers are listed from storage, key by key (``holders.stored``).

* **G11. "Open" resting on five strangers read as proven for every address** (2026-10-25, user decision). FIXED in
  vocabulary. Every "open now" stands on the chain (G7), but five strangers' calls going through is a sample: a gate
  admitting nine addresses in ten (``uint160(msg.sender) % 10 != 0``) passes all five (``FRESH ^ 1, 2, 4, 8``, none a
  multiple of ten), and was "open" like a function anyone calls. Now ``Verdict.witnessed`` marks an open resting on
  samples, reported ``open_witnessed`` (``report.openness_label``, ``deployment_verdicts``' ``witnessed`` and
  ``label``, ``corpus_parity``'s ``lego_witnessed``); "open" unqualified only where the formula proves it for every
  unconfigured address (``decide._alike_for_strangers``: the caller, origin or signer only as a mapping key or one side
  of an equality whose other side no identity reaches or is that same identity (``msg.sender == tx.origin`` is never
  alike: a contract a stranger calls through fails it; review 8, F2), through conversions keeping addresses apart; no call, hash or
  encoding handed it; no view call that may reach ``tx.origin``, a callee unfollowed counting as one; no unknown
  that may single anyone out) and nothing sampled reached it (``World.sampled``: ``strangers_run`` or ``runs``
  settling an unknown stranger, a callee's code saying it reads everyone alike, an inlined callee's proposal, a call
  of the stranger's own first (``after``), an action assumed or handed the caller, entries arranged, an open later
  on them only once a call of the stranger's own that brings them about has run on the chain (G7); the chain
  merely confirming a proof keeps it proven). ``complete`` is unchanged. The machinery is not: the parity gate
  (``% 2 == 0``, the strangers' low bits differ) stays not determined, the mint/USDT/A52 probes too. The oracle checks
  a proven open at 24 further addresses the engine never samples (``_oracle.UNSEEN``) and takes ``open_proven``; the
  sweep ranks proven above witnessed (``never_bolder``); ``scripts/logic_run_passes.py`` fails a witnessed open turning
  proven under ``--faulty`` or ``--budget-only`` and prints the reverse as a confidence-only move
  (``test_witnessed``). Cost: an open on a callee's answer, an action (``sink.poke()``) or an ordering of addresses is
  witnessed even where it holds for everyone.

* **G12. Signature-recovered identities** (2026-10-26, from v51). KNOWN GAP: the next build item, no engine change
  this round. ``ecrecover`` in the source lowers to ``("signer", digest, v, r, s)``, an identity beside the caller
  (listed in ``Verdict.signers``; A53 leaves the digest unchecked). The corpus's signature gates mostly don't reach
  it: OpenZeppelin's ``SignatureChecker``/``ECDSA`` recover through assembly and ask a contract account by ERC-1271
  (``staticcall`` with ``gas()``, ``returndatasize()``, ``mload``), which the lowering refuses by name, so the row
  carries ``unknown:unsupported:gas()`` + ``unknown:unsupported:returndatasize()`` + ``unknown:staticcall(...)`` +
  ``unknown:memory`` together: v51 Aave 140 rows (``depositWithSig``, ``mintWithSig``, ``redeemWithSig``,
  ``withdrawWithSig`` 30 each, ``setUserPositionManagersWithSig`` 11, ``grantRole``/``revokeRole``/``setRole``), Lido
  and Maple none. Rows that were "open" and are now not determined carrying ``chosen_identity`` + ``now_unknown`` +
  ``read_failed:*`` + ``unknown:*``: Aave 188, Lido 4, Maple 7. ``permit``-shaped rows (the signer compared with the
  ``owner`` argument, a nonce consumed) are ``open_unconfirmed``: Aave 63, Maple 21. They stay so (G13 keeps no open
  the chain refuses): the stranger's run fails because its witness carries no signature that recovers to the account
  it names,
  and the engine holds no key for the addresses it makes up.
  A sound lowering gives one of three verdicts, each a construct the engine already has:
  (1) the signer is read in a stored set (``isGuardian[signer]``, a signer list): restricted to that set, the members
  listed as ``signers`` (holders of the keys), with the set's completeness as for any lookup (G1-G5);
  (2) the signer is compared with an argument the caller picks (``permit(owner, ...)``, ``*WithSig(user, ...)``):
  open, for the account whose key signs, with a business condition (``valid_signature`` in ``requires``, confirmed on
  the chain with a signature the strangers' own keys make) rather than ``open_unconfirmed``; the ERC-1271 branch is a view call
  ``isValidSignature(bytes32,bytes)`` handed that account, followed or named like any call target;
  (3) the signature only has to be well formed (checked against nothing stored and no argument that gates): open.
  Build: lower ``SignatureChecker``'s assembly shape as that view call and ``ECDSA.recover`` as ``signer`` (the
  assembly ``staticcall`` to the precompile at 1 is ``ecrecover``); give the strangers keys (an address derived from
  a known private key for ``FRESH`` and the samples) so the witness can carry a signature of the digest the code
  hashes (the ``hash``/``enc`` terms, evaluated at the witness), which confirms (2) on the chain and closes A53.

* **G13. A proved open turned not determined by the stranger's business** (2026-10-26, user decision; REVERTED
  2026-10-27, round ten-b H1, anvil probes). KNOWN GAP. Every "open now" is confirmed by the stranger's own call on the
  chain (G7); v51 turned 42/28/75 opens (Lido/Maple/Aave) into not determined this way, Aragon's
  ``newAppProxy(kernel, appId)`` among them (a proxy created for an app id the stranger's guess doesn't name). The
  2026-10-26 rule kept such an open, proved, with ``stranger_run_failed`` in ``requires``, when the formula was the
  contract's own code alone and every action it assumed succeeds was handed something the caller picks, "so the
  refusal can turn on the arguments". That rule was unsound: an assumed action's success is its callee's decision, on
  whatever that callee reads, whoever hands it what. A child constructor, a receive hook or a low-level callee checking
  ``tx.origin`` lets the admin through and nobody else, and the engine, not following it, said ``open``
  (``test_open_business::ORIGIN``: ``exec``, ``execYul``, ``pay``, ``spawn``). Now: a creation (``new C(...)``) and a
  ``transfer`` put their ``assumed`` mark in the path (``lower._assumed(required=True)``: the call reverts when they
  fail), as ``require(ok)`` of a low-level or assembly call always did; evaluating an ``assumed`` mark records that the
  pass rests on it (``rests_on``), so such an open is witnessed at best, and one whose stranger's call the chain
  refuses is not determined, ``open_assumed_action_unconfirmed``, never kept on an account of what refused it.
  ``World.assumed``, ``Lowerer.action_inputs``, ``decide._proven_by_code`` and ``stranger_run_failed`` are gone. An
  action whose outcome the code doesn't require (an unchecked low-level call; assembly ``create``, which returns zero
  rather than reverting) marks the writes alone, and the function stays open once the strangers' own calls go through
  (``fire``). Cost: ``Kernel.newAppProxy(address,bytes32)`` at 0xb8ffc3cd…88dc is ``not_determined`` +
  ``open_assumed_action_unconfirmed`` again (re-decided 2026-10-27 against the warm cache, ``requires`` empty), with
  the v51 rows; the way back is following the constructor's code like a callee's (its contract is in the same
  compilation unit), a construct to build, not a rule. ``selfCall``/``payInFree`` (``test_open_confirmed``) and
  ``test_callee_misread``'s ``selfCall`` name ``open_assumed_action_unconfirmed`` where they named
  ``open_unconfirmed``. ``never_bolder`` ranks an open carrying a condition below the same open carrying none.
  Not covered: ``permit`` and the other signature rows (ecrecover is A53; see G12).

* **G14. A node's timeout read as the chain's refusal** (2026-10-27, round ten-b H2). FIXED. ``decide._is_revert``
  matched the bare word "execution", so geth's "execution aborted (timeout = 5s)" on the stranger's ``eth_call`` was
  REVERTED: a refusal the chain never gave (under G13 it made a business condition; anywhere it makes a candidate
  look refused). Now it matches the clients' whole phrases (geth/erigon/reth "execution reverted", "invalid opcode",
  "out of gas", "invalid jump", "stack underflow"; nethermind "VM execution error", "Reverted 0x"; anvil "EVM error";
  hardhat/ganache "VM Exception"; "revert"/"reverted" as words) and only after no word of the node's own trouble
  (timeout, timed out, aborted, deadline, cancelled, rate limit, exceeds allowance, gas cap, unavailable, connection,
  internal error) is in the message: such a call is unanswered, ``read_failed:run`` on an unconfirmed open, never
  determined (``test_open_business``: the vocabularies, a timing-out chain, ``_oracle.Faulty``).

### Stated assumptions (not constructs)

* "Open" is as the entries stand. A gate on a lookup the caller is read in (``require(!blocked[msg.sender])``, empty
  or with one entry no unconfigured address holds) is open, proven, whoever can change the entries; where an entry
  point gated on who calls writes that lookup, the verdict records it, ``("configurable", "<lookup> by <writer>")`` in
  ``condition_terms`` (``verdict._configurable``, review 8, D1), and its openness is unchanged
  (``test_conditions::test_an_open_blocklist_records_the_restricted_writer_that_configures_it``).
* An external call does not re-enter this contract's state-changing code before it returns (reentrancy is not
  modelled); gas is the caller's to supply (out-of-gas is not a condition).
* A non-view external call not shown to hand the callee the caller's identity is an action the caller arranges
  (``assumed``, ``decide._action``), whatever value it forwards; an "open now" resting on one stands only once every
  stranger's own call goes through on the chain (G7, backstop). One shown to hand it the caller is never assumed: its
  callee unfollowed, it is unknown; followed, a pass its code shows is marked as resting on that code (unknown with no
  callee code answering), and a refusal there only on entries the caller can bring about is what the caller must
  hold (``requires``). Either way a stranger is let through only once every stranger's own call goes through on the
  chain (``decide.strangers_run``, M3). Its return-data size is what its callee's function declares, never its
  lowered code (``World.declared_size``).
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
  resting on it is asked again with no callee code at all (``confirmed``), each such call put to the chain where its
  input is known whole and unknown otherwise, and the choice never depends on what the chain has cached. Without these, the exact checked-subtraction conditions spent Maple ``Pool.transfer``'s
  read budget on one ``hasPermission`` call per guessed recipient (``test_callee_frame``).
* Callee code never decides on its own, followed or inlined: fail-safe under any mis-lowering of a callee.
  * Answers. A refusal it gives a guess only skips that guess. A ``False`` asked from outside any evaluation
    (``Evaluator.truth``), and a ``True`` a decision rests on (``Evaluator.passes``, ``confirmed``), that some
    callee's code went into (a view call over guessed or unknown arguments
    answered by it, an action's return value, a ``try``'s outcome; memoized values carry the mark, ``_coded_terms``)
    is asked again with no callee code at all: each such call whose input is known whole put to the chain (cache
    first, then a read within the function's budget; an ``abi.encode`` of known static values, each laid out by its declared type (A15), handed on as ``bytes`` is known,
    ``Evaluator._argument``), any other unknown. What fails there fails, what passes there passes, the rest is unknown,
    counted (``world.code_refuted``, ``world.code_passed``), and a verdict left incomplete names
    ``callee_code_refutation`` or ``callee_code_pass``; a stranger left undecided by a pass only callee code showed
    has its own call run on the chain, open only when every stranger's goes through (``FRESH`` and the four with
    different low bits, ``decide.strangers_run``, as ``_strangers_pass`` asks on the engine's side; otherwise not open,
    ``strangers_differ``). A solver "nothing satisfies it"
    that inlined a callee's code (``solve``) is asked again with each view call a value of its own, tied to what the
    chain answers at the inputs the models reach: the target, the arguments and, where the answer may depend on who
    asks, the callee making the call (``_chain_lemmas``, at most ``_CHAIN_ROUNDS`` inputs; an input that isn't one
    number, a ``bytes``, leaves it unknown). Still unsatisfiable, the chain refuted it; a model every answer agrees
    with is checked like any other and may pass; anything else is unknown. A candidate the loosened formula refuses
    only through a callee's code, and not without it, is undecided and never searched (the code's refusal spares the
    search, so it never costs the others the budget); gathering reads and asking whether the state alone settles a
    question (``base_only``) take the code's answer as it is, since neither answers.
  * Who. A holder list built through a callee's code (``holders``' walk into a call handed the caller: an
    ``isPoolAdmin`` in an ACL manager) is never shown to be all, since no chain answer shows a mis-lowered callee
    named too few: its members are the likely ones, each asked of the chain like any candidate, and the verdict names
    ``callee_code_list:<signature>``; a list the contract's own checks bound (``msg.sender == owner && acl.check``)
    stays shown whole. A callee's code saying it reads the caller it is handed alike for everyone (Maple's
    ``canCall(id, msg.sender, data)``) never makes "nobody, ever": a stranger failing in every state is restricted,
    not complete, ``callee_unsingled:<signature>``.
  * Inlined. A view call whose followed code reads ``tx.origin`` (itself or a callee it asks, ``verdict.caller_bound``;
    one whose runtime code has an ``ORIGIN`` opcode its lowering doesn't show is an unknown, ``origin:``, G7 M1),
    whether or not it is handed the caller, is inlined into the formula (``verdict.bind_callers``), since the chain
    would answer it with this contract as the origin. Its code is trusted for nothing: the verdict is decided on the
    formula with each such call an unknown (``verdict._inlined_verdict``); the inlined formula only proposes, and the
    chain confirms by running the whole call (``decide.runs``): every stranger's pass (``decide.strangers_run``) makes
    it open; each holder it names whose own call goes through is listed; the list is never complete on its word, and the
    verdict names ``inlined_callee:<signature>``.
  * Cost: "nobody, ever" over an argument the callee is handed with infinitely many values
    (``require(guard.flagged(x) || owner)``) is no longer claimed from the callee's code; one whose call inputs are
    few (the caller, a flag picked between two values) still is, from the chain. A function whose holders only a
    callee's code bounds lists them, each confirmed, but never completely; one gated by a callee reading the origin
    likewise (``test_callee_refutation``, ``test_origin_callees``, ``test_origin_shapes``, ``test_callee_depth``).
  * Not covered: none of this class. What remains trusted is the lowering of the contract's own code, as everywhere.
* ``decide._screened``: candidates are asked about in the order the state as it stands suggests: those it already
  lets through (the formula, or it with every condition not about who calls freed) first, those it refuses last,
  within each those holding more of the formula's lookups keyed by who calls; the screen's evaluation is off the
  decision's budget (bounded apart, ``_SCREEN_WORK``) and leaves no trace (``decide.detached``): the chain reads
  nothing (a word or call not yet answered reads unknown, any other unanswered read leaves the candidate unscreened),
  and the world and chain are put back as they were, every memo (``solver_record``, ``_brought``, and the verdict's own
  lookups: where a call goes, how a call is bound to its asker, which slots are constant), count and budget included,
  so an unknown read in the screen never reaches a later question. Each
  candidate's questions may spend at most half the work left when it is asked (``_SHARE``); what every candidate
  shares (the stranger's chances) is asked under the decision's own limit. The order only: every candidate is asked
  about in turn, and one a budget leaves unasked is counted (``untested_candidates``)
  (the order itself has no oracle and no test;
  ``test_budgets::test_the_screen_reads_nothing_and_leaves_no_trace``).
* Candidates of an unproven list (``decide.UNPROVEN_CANDIDATES``, ``UNPROVEN_READS``, ``UNPROVEN_BATCH``): where the
  holder list is unproven (hints: a callee's code, log words, constants) and no state of the conditions shows a
  stranger refused, no candidate can be singled out and the list can never be complete, so asking about candidates
  only lengthens an incomplete list. There every stranger's own call is run on the chain first and settles it "open"
  when all of them go through (``strangers_run``); otherwise at most ``UNPROVEN_CANDIDATES`` (48) are asked about, the
  likeliest first (``_screened``), in batches of ``UNPROVEN_BATCH`` (8), under a hard sub-budget of
  ``UNPROVEN_READS`` (300) chain reads past which a read answers unknown (the candidate undecided, the verdict naming
  ``budget:unproven_reads``); the rest are counted (``untested_candidates:<n>``). A proven list keeps the whole
  budget, where completeness is reachable. Changing these constants never changes the openness, only shortens the
  never-complete list with a gap saying so (``test_budgets::test_the_unproven_candidate_budgets_*``,
  ``test_a_proven_list_keeps_the_whole_budget``). On Maple ``Pool.redeem`` (0x356b8d89, 3,335 hints from
  ``callee_code_list``, cache-only run) reads went from 2,003 to 402, decision time 40 s to 19 s, verdict unchanged
  (not determined), ``untested_candidates:3334`` (the first candidate's own search spends the 300).
* Entries read to list ``caller == E[k]`` at keys the caller picks (``holders._STORED_ROWS``, 2,048): every key tuple
  the logged writes name is an entry whose stored address is read, in batches, up to half the reads the decision has
  left and at most 2,048; the entries past that, and any whose read the budget refused, are counted
  (``untested_candidates:<n>``, summed with the candidates left unasked) and the list is not complete. It was a flat
  256 past which nothing was listed (Lido CSModule's 295 node operators: no reward address listed, 276 now)
  (``test_chosen_key_crowd::test_entries_past_the_read_budget_are_counted_untested``: listed and untested are every
  manager, none undecided).
* Reads per function: ``verdict.READS_PER_FUNCTION`` (2,000), lowered where a cap on all the reads a chain may send is
  supplied (``function_verdict(read_cap=...)``, else the ``PSAT_LOGIC_READ_CAP`` environment variable, both counted
  against ``chain.sent``) to ``READ_CAP_SHARE`` (a quarter) of what is left of it (``verdict.function_reads``), so one
  function never spends a whole run's cap; past its budget a read answers unknown (``budget:reads``)
  (``test_budgets::test_one_function_takes_a_share_of_a_supplied_read_cap``,
  ``test_a_supplied_read_cap_bounds_what_one_function_sends``).
* A delegatecall or a call into this contract's own entry point inside a loop marks storage unknown past the loop
  (``*elsewhere``) without counting as lost writes: those writes are that code's (``logged.py`` and the latch account
  for them there).
