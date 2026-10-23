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
