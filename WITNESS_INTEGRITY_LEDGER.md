# Witness Integrity — Findings Ledger

Real, reproduced defects surfaced by wave reviews that are **outside the
rejecting item's scope**. Recorded here instead of being rejection grounds
(scope-discipline adjudication, 2026-07-27). Each entry names the wave leg that
owns it. Nothing here is closed by being listed.

## L-1 · upgrade_history 404 is not a proven negative (producer + consumer)

**Found by:** W0-1 round-9 review (rejecting a frontend commit; the defect is in
the producer and the endpoint semantics, not that commit).

**Producer half:** `workers/static_worker.py:488-502` writes no
`upgrade_history` artifact row in two indistinguishable cases — the stage found
no proxies, and the stage **raised** (`uh_pre = None`, `:1670-1686`, logged via
`record_degraded(phase="dependency_upgrade_history")`). `routers/analyses.py:287-288`
then 404s for both when `synthesize_from_events` also returns None. The 404 is
consumed by the SPA as proven absence.

**Falsified on real data:** `monitored_contracts` row
`0x3c55986cfee455e2533f4d29006634ecf9b7c03f` (`contract_type='proxy'`,
`enrollment_block=25619200`; `contracts.is_proxy=False` but
`proxy_type='beacon'`): job `e8ce8053-a1d4-4a73-b104-25acce22c1f9` has 0
upgrade_history rows and 0 UpgradeEvents, the endpoint returns 404, and the
address has **14 `Upgraded(address)` logs at or before block 25619159** — 14
pre-enrollment upgrades the "No activity before the line." prose denies.
(Reproduction in the round-9 review, task `w95f7wial`.) Note the `!isProxy`
shortcut maps this beacon proxy to the same `absent` render.

**Blocked-by note:** two green tests pin the 404→absence-prose render
(`ActivityPanel.test.jsx` "keeps the absence prose for a 404", "keeps the
no-boundary empty state for a 404"). Whoever fixes this must invert them (R4)
— they currently pin the defect as correct.

**Owner:** producer half sits beside **W0-9**'s upgrade-event integrity work
(same plane: upgrade-history writers must not collapse "none found" with
"stage failed" — split the value, e.g. always write the artifact with an
explicit `not_determined` payload on a raised stage); consumer half (404 →
`not_determined` vs `absent` at the endpoint + SPA) is **W3-E**. Also: the
`is_proxy=False`-with-`proxy_type='beacon'` inconsistency deserves its own
look during W3-E — it changes which render path a real beacon proxy takes.

## L-2 · EntityActivity event rail clobbers proven events on a failed poll

**Found by:** W0-1 round-7 review (deferral check; pre-existing, `6cb57f2b`,
PR #150). `EntityActivity.jsx:58` `catch { setEvents([]) }` — the event rail in
the same panel as the now-hedged upgrade rail still substitutes an empty list
for an unread one, and a failed 30s poll replaces events a previous tick had
proven present. Same three-state class. **Owner: W3-E.**

## L-3 · scoped-out storage-adjacent notes from W0-1 rounds 3–5

- `artifacts_not_determined` (analysis-detail payload) has zero consumers in
  `site/` — disclosed, allowed; wire a consumer or note it in W3-E.
- Legacy persisted `monitoring_config` rows carry no
  `tracking_plan_not_determined` key until re-enrollment rewrites them
  (`services/monitoring/enrollment.py:315` updates in place; heals on next
  enroll). Watch that W1/W2 queries do not read key-absence as determined.

## Adjudication record — W0-1 closeout (2026-07-27)

W0-1 ran 9 review rounds. The storage core (commit `cd2f9671`) was validated in
round 2 and survived every later round's independent reproduction; rounds 3–9
each fixed real defects progressively further along the consumer graph (API
router → SPA fetch → component state → render prose → producer semantics).
Rejection scope was unbounded while each round's mandate was bounded — that
cannot converge, so the driving agent closed the item: accepted as scoped
(commits `cd2f9671..52061e40`), the last trivial residual (JSON-array body
guard) fixed directly in `52061e40`, and the remaining reproduced findings
moved here. Review charter for subsequent items now requires violations to be
in the item's declared scope; out-of-scope discoveries are recorded as
findings, not rejection grounds.

---

# Wave 0 out-of-scope findings (swept 2026-07-27, W0-2..W0-5 reviews)

## L-4 · (found by W0-2 review)

`_principals_by_function` (services/effects/selection.py:~815) issues `select(FunctionPrincipal.function_id, FunctionPrincipal.address).where(function_id.in_(...))` with NO `ORDER BY`, and the resulting list's FIRST element becomes the probe's caller identity at services/effects/calldata.py:1377, 1419, 1702 and 2224 (`candidate.principal_addresses[0] if candidate.principal_addresses else None`). The multi-principal population is non-empty in the local corpus: fid 2527 has 33 principals, fids 801 and 811 have 27, fids 2908/2909 have 15. Which address is `[0]` — i.e. WHO the fork probe impersonates — is therefore left to the query plan / heap order rather than being a function of the data. This is a DIFFERENT determinism class from the one W0-2 declares (plan order, not PYTHONHASHSEED), it is outside the handoff §4 W0-2 problem/fix surface (reachable_value / Decimal balances / _token_holdings_by_contract), and the implementer disclosed it as item 1 of 'what I did not check'. HONEST CAVEAT: I confirmed the total order is absent and that its first element is load-bearing, but I could NOT make Postgres actually return a different order — neither `enable_seqscan=off`, `enable_indexscan/bitmapscan=off`, nor a rolled-back no-op UPDATE of the first row flipped it. So this is an unpinned-order hazard with a proven-nonempty affected population, NOT an observed flip. It deserves its own item with its own controls, exactly as the implementer proposed.

**Reproduction:** `cd /home/riley/PSAT && grep -n 'principal_addresses\[0\]' services/effects/calldata.py && sed -n '/def _principals_by_function/,/^def select_candidates/p' services/effects/selection.py && set -a && source .env && set +a && uv run python -c "import os;from sqlalchemy import create_engine,text;e=create_engine(os.environ['DATABASE_URL']);c=e.connect();print(c.execute(text('select function_id,count(*) n from function_principals group by 1 having count(*)>1 order by n desc limit 8')).fetchall())"`

## L-5 · (found by W0-3 review)

PRE-EXISTING, unchanged by this commit — reported for the ledger, not as rejection grounds. `_definitions` marks a state variable UNDETERMINED via `isinstance(lvalues[key], StateVariable)`, which only sees a state variable written as a WHOLE (`route = a`). A write through a REFERENCE — array element, mapping value, struct member — has a `ReferenceVariable` lvalue, so the guard never fires, and the destination still publishes `destination_kind: "state_var"`: a PROVEN ABSENCE of a caller-chosen destination over a function whose caller supplies it one statement earlier. Reproduced on three shapes (`routes[0] = a; IExec(routes[0]).exec(a,d)`, the mapping form, the struct-member form) — all three answer `state_var`, byte-identical to the control `pureStorageDestination` where `state_var` is CORRECT, so a consumer cannot tell them apart. This is the same defect class as the `branchedStateOrParam` / `stateWrittenAfterCall` shapes the commit fixes; the scalar sibling `scalarStateWrittenThenCalled` is correctly hedged to `not_determined` by this commit. Confirmed pre-existing: the identical three `state_var` answers come out of `c7d7b157` (this commit's parent), so the commit neither introduces nor worsens it — it strictly improves the scalar case. Not observed on the two production compilation units I re-materialised (BoringVault, LRTSquaredAdmin).

**Reproduction:** `cd /home/riley/PSAT && mkdir -p /tmp/w03probe/src && cat > /tmp/w03probe/src/P.sol <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;
interface IExec { function exec(address who, bytes calldata payload) external; }
contract P {
    address public route;
    address[] public routes;
    mapping(uint256 => address) public routeOf;
    struct S { address dest; }
    S public s;
    function arraySlotWrittenThenCalled(address a, bytes calldata d) external { routes[0] = a; IExec(routes[0]).exec(a, d); }
    function mappingSlotWrittenThenCalled(address a, bytes calldata d) external { r`

## L-6 · (found by W0-3 review)

PRE-EXISTING, unchanged by this commit. `conditionalSingleDef(address a, bytes d, bool flag) { address t; if (flag) t = a; IExec(t).exec(a,d); }` defines `t` exactly once, so the resolver publishes `destination_param "a", destination_kind "param"` — a proof, although on the `!flag` path the destination is `address(0)`. Defensible (the only caller-choosable candidate is `a`) and identical at `c7d7b157`, so out of this commit's surface; noting it because the definition COUNT is the whole guard and a single conditional definition is the one shape where the count does not imply a forced value.

**Reproduction:** `Same probe as above (`conditionalSingleDef` is in the fixture written by that command); the row prints destination_kind "param", destination_param "a" at both HEAD and c7d7b157.`

## L-7 · (found by W0-4 review)

`Operand` TypedDict (`/home/riley/PSAT/services/static/contract_analysis_pipeline/predicate_types.py:68-70`) states the invariant "Present on every ``source == \"computed\"`` operand and on no other, so absence means the question does not apply." That is false for the 92 NESTED computed origins inside `derived_from` lists: `_source_to_operand(..., nested=True)` deliberately suppresses the key on them (correctly — the inline comment at predicates.py:2290-2295 explains why), so a consumer that walks `derived_from` recursively and applies the TypedDict rule reads 92 real computed operands as "not a computed operand". Distinguishability is preserved by POSITION (nested operands only occur inside a `derived_from` list), so this is a defect in the consumer-facing contract prose, not an unrepresentable state — hence not an R1 rejection. The commit message itself states the invariant correctly; only the TypedDict does not.

**Reproduction:** `cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/w04 && python3 -c "
import json,pathlib,collections
c=collections.Counter()
def walk(o,inside=False):
    if isinstance(o,dict):
        if o.get('source')=='computed' and 'derived_from' not in o: c['computed_operand_without_key']+=1
        for k,v in o.items(): walk(v)
    elif isinstance(o,list):
        for v in o: walk(v)
for p in pathlib.Path('patch').glob('*.json'): walk(json.load(open(p)))
print(dict(c))"
# -> {'computed_operand_without_key': 92}`

## L-8 · (found by W0-4 review)

`arg_origins` (`/home/riley/PSAT/services/static/contract_analysis_pipeline/provenance.py:191-212`) cannot distinguish "this argument is a constant" from "this argument's provenance set is EMPTY (unresolved)". `_sources_for_value` returns `EMPTY` for a Local/Temporary/Reference variable with no entry in the provenance map, `_union_of_args` folds it away, and the resulting `frozenset()` is published as `[]` = "determined: only constants reached it" — a proven-absent claim manufactured from a not-determined input, which is the governing rule's exact failure shape. Reproducible synthetically; NOT observed on the 88-unit production corpus (all 12 real `[]` operands are `mload(uint256)` with a constant offset arg or zero-arg `returndatasize()`), and the only shapes I could find that DO hit an empty-provenance non-constant argument on real code are `abi.decode(data,(uint256))` type-literal args and `type()` args, which legitimately carry no origin. Because the corpus does not exhibit a false `[]`, I did not treat it as an R1 rejection — but the mapping is unsound and a later handler that widens `derived_from` (the handoff's `_handle_binary`/`_unary`/`_member` follow-up) will make it reachable.

**Reproduction:** `cat > /tmp/dfprobe.py <<'EOF'
import sys,textwrap,tempfile
from pathlib import Path
sys.path.insert(0,"/home/riley/PSAT")
from slither import Slither
from services.static.contract_analysis_pipeline.provenance import ProvenanceEngine
d=Path(tempfile.mkdtemp()); f=d/"C.sol"
f.write_text(textwrap.dedent('''
pragma solidity ^0.8.19;
contract C {
    mapping(bytes32 => bool) public used;
    function f() external view returns (bool) {
        bytes memory blob;
        require(used[keccak256(blob)], "no");
        return true;
    }
}
''').strip()+"\n")
sl=Slither(str(f))
fn=[x for c in sl.contract`

## L-9 · (found by W0-4 review)

On 8 real corpus operands (`0x3b44a093` RoleRegistry grantRole/revokeRole/revokeFast/setRole; `0x05a1552c`, `0x7223442c`, `0xd445c65e` Solmate `callOptionalReturn`) a `computed_kind: "mload(uint256)"` operand publishes `derived_from: []`. Under the field's stated argument-scoped definition this is literally true (the argument is the constant offset `0x00`/`0x40`), but the state's own label in both `predicate_types.py:76` and `provenance.py:126` is the unqualified "determined: only constants reached it". The mload's actual value is external-call returndata copied into memory by `returndatacopy`, which the engine does not model; a W1-C consumer taking `[]` at the labelled meaning would conclude the value has no non-constant origin. Not a rejection: the header sentence of both comments does scope the field to arguments, and `computed_kind` is published alongside so the shape is visible.

**Reproduction:** `cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/w04 && python3 -c "
import json,pathlib
def lv(n):
    if not isinstance(n,dict): return
    if n.get('op')=='LEAF' and n.get('leaf'): yield n['leaf']
    for c in n.get('children') or []: yield from lv(c)
for p in sorted(pathlib.Path('patch').glob('*.json')):
    d=json.load(open(p))
    for g in ('trees','check_trees'):
        for sig,t in (d.get(g) or {}).items():
            for lf in lv(t):
                for o in lf.get('operands') or []:
                    if o.get('source')=='computed' and o.get('de`

## L-10 · (found by W0-4 review)

`_normalize_operand_for_call_arg` (`/home/riley/PSAT/services/resolution/predicate_evaluator.py:2279-2327`) renormalizes a `parameter` operand into the caller's frame via `_bound_parameter_operand`, but for a `computed` operand falls through to `deepcopy(operand)` — which now carries `derived_from` members holding `parameter_index`/`parameter_name` relative to the INLINED CALLEE's frame. After cross-contract inlining an inlined leaf can therefore publish `derived_from: [{"source":"parameter","parameter_index":1,...}]` where index 1 belongs to a different function's signature. No consumer reads `derived_from` today (grep confirms: only the producer and the new tests), so this is latent, not a live regression — but the implementer states W1-C must read `operands[].derived_from`, and this path will hand it wrong-frame indices. Outside this item's declared scope (`provenance.py` argument union), and this commit does not change any field `predicate_evaluator` reads.

**Reproduction:** `cd /home/riley/PSAT && grep -n 'source == "parameter"' -A 12 services/resolution/predicate_evaluator.py | sed -n '1,20p'; grep -n 'return deepcopy(operand)' services/resolution/predicate_evaluator.py
# -> parameter operands are rebound to the caller frame (2312-2321); every other source, including computed, is returned via deepcopy at :2327 with derived_from intact and unrenormalized
grep -rn 'derived_from' --include=*.py services routers workers db | grep -v contract_analysis_pipeline | grep -v '^db/.*SCHEMA'
# -> no consumer reads it yet`

## L-11 · (found by W0-5 review)

gate.sh FAILs on pyright at HEAD with 5 errors, all in tests/test_predicate_builder.py:1452/1457/1488 — inside the 90-line block ADDED by 940bb23b (W0-4). 226ec3ee does not touch that file (git diff --name-only HEAD~1 HEAD lists 5 files, none of them test_predicate_builder.py), so the failure is not attributable to W0-5. Notably W0-4's own commit message asserts 'pyright 0 errors', which is false at the tree it produced — a leg self-reported a gate it did not pass. Errors: reportTypedDictNotRequiredAccess on Operand['computed_kind'] and Operand['derived_from'], plus reportOptionalMemberAccess/reportOptionalIterable on the same accesses.

**Reproduction:** `cd /home/riley/PSAT && uv run pyright tests/test_predicate_builder.py && git show --stat 940bb23b | grep predicate_builder && git diff --name-only HEAD~1 HEAD`

## L-12 · (found by W0-5 review)

reconcile_deferred_resolutions() (services/resolution/deferred_reconciler.py:159-169) inner-joins Contract on Contract.job_id == Job.id. On the local production-shaped DB, 32 effective_functions rows across 2 contracts carry the DEFERRED_MARKER 'deferred_pending_index' in capability_expr while contracts.job_id IS NULL, so the inner join drops all 32 and the reconciler can NEVER reach them — deferred authority resolution silently never completes for those functions. Pre-existing (identical at HEAD~1); W0-5's predicate change is orthogonal and does not affect it. This is why the implementer's stated control for line 162 reads '0 rows'; their parenthetical 'no row carries that marker' is inaccurate — 32 rows carry it, they are structurally unreachable. Matches the known protocol_id/orphaning family in project memory.

**Reproduction:** `cd /home/riley/PSAT && set -a && source .env && set +a && uv run python -c "import os,psycopg2; c=psycopg2.connect(os.environ['DATABASE_URL'].replace('postgresql+psycopg2','postgresql')).cursor(); c.execute(\"select ct.job_id is null, count(distinct ct.id), count(*) from effective_functions ef join contracts ct on ct.id=ef.contract_id where ef.capability_expr::text ilike '%deferred_pending_index%' group by 1\"); print(c.fetchall())"   # -> [(True, 2, 32)]`

## L-13 · (found by W0-5 review)

db/effect_cache.py:461 writes observed_residue with an explicit null() precisely because a JSONB column turns a Python None into the jsonb scalar null, but witness=witness on line 462 does not get the same treatment. A None witness would therefore land as written-null rather than SQL NULL, i.e. as a recorded value. Zero such rows exist today (effect_verdicts.witness is 'object' on 248/248), so this is latent, not live. It is a WRITER-side instance of the same defect class; W0-5's declared surface is the query side only, and the implementer flagged it explicitly as not-changed.

**Reproduction:** `cd /home/riley/PSAT && sed -n '455,463p' db/effect_cache.py && set -a && source .env && set +a && uv run python -c "import os,psycopg2; c=psycopg2.connect(os.environ['DATABASE_URL'].replace('postgresql+psycopg2','postgresql')).cursor(); c.execute(\"select coalesce(jsonb_typeof(witness),'unset'), count(*) from effect_verdicts group by 1\"); print(c.fetchall())"   # -> [('object', 248)]`

---

# Wave 0 exit sweep (2026-07-27, W0-6..W0-9 reviews + tier-3 verifier findings)

## L-14 · (found by W0-6 review)

`writer_selectors` publishes a FABRICATED selector as proven-present on 15 fallback/receive records, and on 4 of them the value cannot do what the column comment says it does. `_writer_selectors_for` (services/static/contract_analysis_pipeline/effects.py:3294) calls `_selector_for(full_name)`, which for `fallback()` returns keccak("fallback()")[:4] = 0x552079dc (11 records) and for `receive()` returns 0xa3e76c0f (4 records). Neither is an ABI selector. The migration's own column comment says writer_selectors are "selectors to replay when attributing the state writes of this function". For the 4 `receive()` records — WstETH (writes _totalSupply, _balances), PriorityWithdrawalQueue (ethAmountLockedForPriorityWithdrawal), WithdrawRequestNFT (ethAmountLockedForWithdrawal), LiquidityPool (totalValueOutOfLp, totalValueInLp) — I confirmed NONE of the four contracts has a `fallback()` record in its own effects artifact, so a call carrying 4 bytes of calldata 0xa3e76c0f cannot reach `receive()` (Solidity dispatches `receive()` only on empty calldata) and reverts. The write is therefore unattributable by the selector published beside it. The 11 `fallback()` cases are right-by-accident (any unmatched selector reaches a fallback). OUT OF SCOPE because the fabrication originates in effects.py `_selector_for`/`_writer_selectors_for`, outside W0-6's file surface (services/policy + db + schemas + alembic), is pre-existing (the same value is already stored in `effective_functions.selector`), and §4 W0-6 asks for verbatim persistence. The implementer disclosed it in the commit message and in the report. Suggested fix location: a third suppression in `_mutability_fields` (null writer_selectors on unselectored entry points) or, better, `_writer_selectors_for` returning [] when `_is_state_changing_entry_point` is False.

**Reproduction:** `cd /home/riley/PSAT && set -a && source .env && set +a && uv run python -c "
import json,pathlib,boto3,os,psycopg2,gzip
c=psycopg2.connect(os.environ['DATABASE_URL']);cur=c.cursor()
cur.execute(\"select job_id,storage_key from artifacts where name='effects'\")
s3=boto3.client('s3',endpoint_url=os.environ['ARTIFACT_STORAGE_ENDPOINT'],aws_access_key_id=os.environ['ARTIFACT_STORAGE_ACCESS_KEY'],aws_secret_access_key=os.environ['ARTIFACT_STORAGE_SECRET_KEY'])
for job,key in cur.fetchall():
    b=s3.get_object(Bucket=os.environ['ARTIFACT_STORAGE_BUCKET'],Key=key.split('pr-160/',1)[-1])['Body'].read`

## L-15 · (found by W0-6 review)

The withholding rule for view/pure records contradicted by their own derived writes also nulls 89 legitimate `external_call` sinks on 14 of the 100 records (all LRTSquaredCore views: previewDeposit, previewRedeem, assetOf, assetsOf, assetForVaultShares, assetsForVaultShares, fairValueOf, positionWeightLimit, ...). Not a rule violation — not-determined is the conservative direction and R1 is satisfied — but it is a real recall cost that Wave 3's planned retarget of `services/effects/selection.py:691` onto sinks will see as NULL on those rows, and it is not mentioned in the commit message. Recording it so the ledger has the number before the retarget is measured.

**Reproduction:** `cd /home/riley/PSAT && uv run python /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/probe6.py   # prints: view-contradiction records: 100 -> of these, records whose NON-state_write sinks are now withheld: 14 / Counter({'external_call': 89})`

## L-16 · (found by W0-7 review)

PRODUCER DEFECT (Leg D / A7, not W0-7's remit) — `read_max_pause_duration`'s positive branch is unreachable from any compiled source. `services/effects/calldata.py:1823-1839` (`_duration_from_trees`) requires ONE guard leaf whose operand set holds all three of `block_context_kind=='timestamp'`, a `state_variable_name` in `latch_vars`, and a parseable `constant_value`. I compiled 10 independent guard shapes through the production `build_predicate_artifacts_with_pause_info` path and the builder never co-emits all three: whenever `block.timestamp` survives as an operand the literal is absorbed into the arithmetic (s1,s2,s4,s5,s6,s7 -> operands are [block_context, state_variable]), and whenever the literal survives `block.timestamp` is gone (s3, s9-leaf2 -> operands are [state_variable, constant]). Every shape returns None. The reader's only passing positive test (tests/test_effects_calldata.py:919, ==2592000) builds its predicate trees by hand. Consequence: `duration_bound_seconds` is structurally always None from real contracts, and the scorer's severity-REDUCER branch that reads a bound has never executed on real input. Nothing false is published, so this is a reachability defect, not a correctness one. The implementer pinned it as found and routed it rather than fixing it, which I agree is correct; W0-7 item 5's fixture 'a timed latch with a READABLE duration bound' is therefore not buildable as the plan specified.

**Reproduction:** `cd /home/riley/PSAT && set -a && source .env && set +a && PYTHONPATH=/home/riley/PSAT uv run python /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/probe_bound.py   # 10 compiled guard shapes, all print '-> None'; the operand dumps show constant and block.timestamp are never in the same leaf`

## L-17 · (found by W0-7 review)

PRODUCER DEFECT (cross-contract join, no wave assigned) — `build_callee_claim_map` (services/static/cross_contract.py:148-152) keys a callee's claims by `fn_record['selector']` from the effects artifact, which is keccak of the DECLARED signature, while the caller's body sink records the ABI selector. Reproduced inside the corpus itself: AssetRecovery's effects record gives `sweepTo(IERC20,address,uint256) -> 0x38541c00` (keccak of the declared name) and the callee map is keyed on that, while PolicyCaller's sink for the same call records `0x0aeef8c8` (keccak of `sweepTo(address,address,uint256)`, the ABI form). The join misses, and `recoverVia` derives no claim even though the callee's `flow.out` is standard_exact and `_propagatable` returns True. Every callee taking an interface- or contract-typed parameter is invisible to the cross-contract pass. Note the two planes disagree WITHIN the golden as well: the golden's `selector` column for that function is 0x0aeef8c8 (it goes through `_selector_for_signature` canonicalisation) while the effects record the join reads says 0x38541c00. This is a strong candidate for why `policy_derived` has zero producers in 679 DB-wide claims. The commit pins the empty row deliberately and does not fix it; routing is the driving agent's call.

**Reproduction:** `cd /home/riley/PSAT && set -a && source .env && set +a && PYTHONPATH=/home/riley/PSAT uv run python -c "import tempfile;from pathlib import Path;from tests.support import label_corpus as h;from services.static.cross_contract import build_callee_claim_map,_propagatable;e={x['address']:x for x in h.corpus_entries()};o={};\ntmp=tempfile.mkdtemp()\nfor a in ('0x0000000000000000000000000000000000000070','0x0000000000000000000000000000000000000100'):\n    _s,eff,_t=h._compile_and_attach(e[a],Path(tmp)); o[a]=eff\nprint([ (s,i.get('selector')) for s,i in o['0x0000000000000000000000000000000000000070'`

## L-18 · (found by W0-7 review)

R3 PROSE-COPY BLINDNESS IN THE CORPUS — `action_summary` sits in the very effects record the golden flattens (`effects['functions'][sig]['action_summary']`) and the golden does not pin it. The golden's per-function pinned keys are exactly ['claims','delegatecall_sinks','effect_labels','effect_targets','external_calls','full_name','predicate_tree','selector','value_flows']. Meanwhile W0-7 raised the number of corpus functions carrying the flat prose over-claim 'Executes arbitrary external calldata from the contract.' from 1 to 13 — including `branchedParams`, `reassignedLocal` and `paramWrittenAfterCall`, whose STRUCTURED witness this same commit pins as `destination_kind: not_determined`. So the corpus now holds rows where the structured field hedges and the quotable prose does not, and the gate can only see the former. When Leg A/C narrows `exec.arbitrary`, the golden will go red on the witness and stay green on the prose copy — precisely the failure §2 R3 warns about. NOT a rejection ground: `action_summary` is not in §4 W0-7's declared blindness list (which names the unpinned witness, zero delegatecall rows, all-unconstrained param destinations, and the missing multi-address-param exec fixture), and R3's same-commit obligation does not bite because this commit changed no published field. But it is a one-line addition to `_flatten_record` in the file this commit already rewrote, and worth the ledger.

**Reproduction:** `cd /home/riley/PSAT && set -a && source .env && set +a && PYTHONPATH=/home/riley/PSAT uv run python -c "import json,tempfile;from pathlib import Path;from tests.support import label_corpus as h;e=next(x for x in h.corpus_entries() if x['address'].endswith('00d0'));_s,eff,_t=h._compile_and_attach(e,Path(tempfile.mkdtemp()));print([(s,f.get('action_summary')) for s,f in eff['functions'].items() if any(c['claim_id']=='exec.arbitrary' for c in f.get('claims') or [])]);g=json.load(open('tests/fixtures/label_corpus/golden.json'));print('pinned keys:',sorted({k for c in g['contracts'] for f in c['fun`

## L-19 · (found by W0-9 review)

site/src/surface/sidebar/activity/buildTimeline.js:25 `implEras()` folds an unknown `block_introduced` to 0 (`typeof im.block_introduced === "number" ? im.block_introduced : 0`) — the IDENTICAL NULL->0 fold this commit removed from services/audits/coverage.py:262. It is fed by services/discovery/upgrade_history.py:933 `synthesize_from_events`, which now emits `block_number: None` for a poll row. Currently INERT and therefore not a rejection ground: NULLS LAST keeps the block-less impl last in the list, and the preceding impl's `block_replaced` is also absent so its era already runs to Infinity and wins the `implAt` linear scan first. The commit strictly improves this surface (pre-fix the poll impl sorted to index 0 and rendered as "First deployment" with isCurrent=true). But the fold is the same defect class, one file away from the one that was fixed, and it becomes live the moment a block-less impl can precede a block-carrying one.

**Reproduction:** `sed -n '20,35p' /home/riley/PSAT/site/src/surface/sidebar/activity/buildTimeline.js; sed -n '925,940p' /home/riley/PSAT/services/discovery/upgrade_history.py`

## L-20 · (found by W0-9 review)

services/chat/data.py:175 selects "the last upgrade event" with `order_by(UpgradeEvent.block_number.desc().nullslast())`. A poll-detected upgrade (block NULL) sorts LAST under DESC+NULLS LAST, i.e. is reported as the OLDEST event, so `last_event` is the last block-carrying upgrade rather than the actual latest one. Not a regression — pre-fix `block_number=0` also sorted last under DESC — so out of scope. But the commit message's claim that "all three consumers order by block_number ASC NULLS LAST" is incomplete: this fourth consumer has the opposite polarity and the fix does not reach it.

**Reproduction:** `sed -n '172,178p' /home/riley/PSAT/services/chat/data.py`

## L-21 · (found by W0-9 review)

services/aggregations/contract_audit_timeline.py:240 infers "this coverage row covers the currently-open impl window" from `r.covered_to_block is None` — precisely the inference this commit's own ImplWindow docstring declares invalid ("``to_block=None`` alone does NOT mean 'still current' — ``successor`` is what says that"). It is not reachable as a misbadge today: a half-known window's impl is by construction no longer `contract.implementation`, so its rows never land in `current_cov`. No rejection. But the invariant the commit introduced now exists in two places and only one of them enforces it; AuditContractCoverage carries no `successor`-equivalent column, so the published plane cannot express the distinction the internal plane now can.

**Reproduction:** `sed -n '236,246p' /home/riley/PSAT/services/aggregations/contract_audit_timeline.py; sed -n '78,92p' /home/riley/PSAT/services/audits/coverage.py`

## L-22 · (found by W0-9 review)

services/audits/coverage.py:543 (`_resolve_impl_for_address`) returns None for the ENTIRE proxy if any single UpgradeEvent has a NULL timestamp (`if audit_ts is None or any(ev.timestamp is None for ev in proxy_events): return None`). The event-scan writer (unified_watcher.py:1143) still writes NULL timestamps by design, so one log-detected upgrade silently stops every address-anchored audit from binding on that proxy. Pre-existing and fail-closed; this commit strictly IMPROVES it by giving poll rows a timestamp. Already stated by the implementer under "what I did not check"; recording it so it is in the ledger.

**Reproduction:** `sed -n '540,550p' /home/riley/PSAT/services/audits/coverage.py; sed -n '1140,1156p' /home/riley/PSAT/services/monitoring/unified_watcher.py`

## L-23 · (found by W0-9 review)

services/audits/coverage.py:89 `ImplWindow.successor: str = "none"` defaults to the STRONGEST claim ("nothing replaced this impl; the window is open"). Only one production construction site exists (coverage.py:302) and it always passes the value explicitly, so there is no realized defect. But a future construction site that omits the kwarg over-claims an open window silently instead of failing — the default should be the not-determined value, not the confident one.

**Reproduction:** `grep -rn 'ImplWindow(' --include=*.py /home/riley/PSAT | grep -v node_modules`

## L-24 · (found by Wave 0 tier-3 verifier lens 1)

derived_from misbinds one origin on the flagship W0-4 gate: Teller-A refundDeposit's keccak commitment publishes state_variable nativeWrapper as an origin and omits the genuinely committed depositAsset (param idx 2). Cause is flow-insensitive handling of a local reassigned AFTER the hash (depositAsset = ternary(nativeWrapper) at line ~334, hash at ~323-327). Pre-existing engine behavior (same substitution visible on the pre-fix exit(...) leaf), surfaced into the new evidence field. receiver binding itself is correct. Not in the ledger; W1-C will read this field. Route to ledger with an owner.

**Evidence:** Post-fix rebuild of job 178eceda-a278-479b-bb64-b87168e43aee from production source_files bytes: derived_from = [abi.encode(), receiver(1), depositAmount(3), shareAmount(4), depositTimestamp(5), shareLockUpPeriodAtTimeOfDeposit(6), state_variable nativeWrapper] — depositAsset(2) absent. Source order confirmed in substrate src 0x929b44db.../TellerWithMultiAssetSupport.sol lines 318-336. grep of WITNESS_INTEGRITY_LEDGER.md for reassign/nativeWrapper/depositAsset: no entry.

## L-25 · (found by Wave 0 tier-3 verifier lens 1)

A third nondeterminism surface survives Wave 0 outside the W0-8 gate's two classes: _operand_for_value breaks ties between competing computed sources on callee_args_digest (hash() of a frozenset), flickering 37-46 operand slots across 25/88 production units per the W0-4 commit's own measurement. Disclosed as an unowned defect in the commit body but NOT entered in the ledger with an owner. Wave 1-3 predicate-tree byte-differentials will carry this noise and misattribute unless it is owned or excluded — the exact attribution risk section 0 exists to prevent. (L-4 already ledgers a fourth, plan-order surface in _principals_by_function.)

**Evidence:** I reproduced one instance on my single rebuild: deposit(ERC20,uint256,uint256) root.6 operand computed_kind flipped BinaryType.AND -> call(uint256,...) with kind/operator/authority_role/confidence/parameter_indices unchanged. W0-4 commit 940bb23b declares it 'unowned defect ... deliberately NOT fixed here'; grep callee_args_digest WITNESS_INTEGRITY_LEDGER.md returns nothing.

## L-26 · (found by Wave 0 tier-3 verifier lens 2)

W0-9's NULL block_number relocates into an unfixed consumer branch: synthesize_from_events -> _build_implementation_timeline publishes block_introduced/block_replaced None for a poll-detected upgrade, and site/src/auditMatching.js:51-55 folds those to -Infinity/+Infinity in the hard block-range branch, so a fully block-bounded audit spreads onto the poll-introduced era — the same '+infinity spread' class _publishable_block_bounds closed on the coverage side. Second site, same class: contract_audit_timeline.py:70-71 still publishes to_block:None for a window closed by a block-less successor (impl_windows has no production consumer today). Latent — 0 NULL-block rows exist, 23 pollers armed — and strictly less wrong than the pre-fix block-0 corruption. Needs a WITNESS_INTEGRITY_LEDGER.md entry with an owner (W0-9 sibling / W3-E), not a wave halt.

**Evidence:** services/discovery/upgrade_history.py:867-940 orders nullslast and emits events with block_number None; :334-361 sets block_introduced/block_replaced from those values with no successor discriminator; site/src/auditMatching.js matchesEra: 'const eraFrom = impl?.block_introduced ?? -Infinity; const eraTo = impl?.block_replaced ?? Infinity' — overlap test then admits any bounded audit against a None-introduced era. grep shows impl_windows consumed only by tests. The W0-9 commit message updated coverage.py both sites and auditMatching's covered_* reading but not this era-side route.

---

# Wave 1 exit sweep (2026-07-28: leg reviews + tier-3 verifier findings)

## L-27 · (found by W1 Leg A review)

PRE-EXISTING structural is_pausable false positive on EigenStrategy (contract 607): the Plane-0 PauseAnalyzer admits `totalShares` as a pause state variable, so is_pausable is True and pause_functions lists `deposit`/`withdraw`. Present identically at BASE and at HEAD (byte-identical replay output), so the leg neither introduced nor widened it — but it is the reason one of the 8 bitmap-family contracts reads pausable, which could be misread as a breach of the Leg A ordering constraint.

**Reproduction/evidence:** `set -a; source /home/riley/PSAT/.env; set +a; cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/work; for R in /home/riley/PSAT /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/wave1/leg-a; do REPO=$R PYTHONHASHSEED=0 /home/riley/PSAT/.venv/bin/python -c "import sys;sys.path.insert(0,'.');import replay;a,t,e=replay.analyze(607);print(a['summary']['is_pausable'], a['pausability']['pause_variables'])"; done   # both print: True ['`

## L-28 · (found by W1 Leg A review)

CONSEQUENT of the above, and the worse half: `_maybe_classify_guard_leaf` relabels leaves that read the mis-identified pause variable, so on EigenStrategy 2 predicate-tree leaves (on `deposit(IERC20,uint256)` and `withdraw(address,IERC20,uint256)`) are published with authority_role="pause" when the underlying guard is a share-accounting invariant over `totalShares`. Pre-existing; unchanged by the leg.

**Reproduction/evidence:** `set -a; source /home/riley/PSAT/.env; set +a; cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/work; REPO=/tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/wave1/leg-a PYTHONHASHSEED=0 /home/riley/PSAT/.venv/bin/python -c "import sys;sys.path.insert(0,'.');import replay;a,t,e=replay.analyze(607);h=[];\nimport json\ndef w(n,s):\n  if not isinstance(n,dict):return\n  if n.get('op')=='LEAF':\n    if (n.get('leaf') or {}).get('autho`

## L-29 · (found by W1 Leg A review)

NEW but inert consequence of the widening: on the ERC-7201 namespaced family the claim flag resolves to the SLOT CONSTANT, so `pause_variables` publishes `PAUSABLE_STORAGE_SLOT` / `PAUSABLE_UNTIL_STORAGE_SLOT` (contracts 537, 629 and the other 13 namespaced rows) — a name no getter can resolve. Mitigating fact the implementer's report did not state: the only field these flow into is `analysis['tracking_hints']`, and `grep -rn tracking_hints` over services/workers/routers/db/site/src finds NO consumer anywhere in the repo, so nothing false is published today. Ledger it for whichever wave gives tracking_hints a reader.

**Reproduction/evidence:** `set -a; source /home/riley/PSAT/.env; set +a; cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/work; REPO=/tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/wave1/leg-a PYTHONHASHSEED=0 /home/riley/PSAT/.venv/bin/python -c "import sys;sys.path.insert(0,'.');import replay;a,t,e=replay.analyze(629);print(a['pausability']['pause_variables'])"   # ['PAUSABLE_STORAGE_SLOT','PAUSABLE_UNTIL_STORAGE_SLOT'] ;  then: cd /tmp/claude-1000/-h`

## L-30 · (found by W1 Leg A review)

NULL-FOLDING CONSUMERS of the values the leg made three-state (distinct from the row-ABSENCE default at company_overview.py:1264-1267 that constraint (c) already carves out to Wave 3). `company_overview.py:1252` `if summary_row.is_pausable: caps_set.add("pause")` and `:1276` `elif has_timelock or control_model == "governance"` fold a not-determined `None` to the same outcome as a proven `False`; likewise `site/src/surface/sidebar/activity/helpers.js:32` and `site/src/surface/layout/elkLayout.js:854`. The JSON payload itself DOES preserve the three states (`"is_pausable": is_pausable` passes the null through), so only the derived `role`/`capabilities`/band folds lose it, and realised None rows are currently zero. Not a rejection ground: the leg correctly declined to edit site/ to avoid a concurrent write with the parallel legs, and this is Wave 3 Leg E's surface.

**Reproduction/evidence:** `cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/wave1/leg-a && sed -n '1250,1280p' services/aggregations/company_overview.py && sed -n '30,34p' site/src/surface/sidebar/activity/helpers.js && sed -n '852,856p' site/src/surface/layout/elkLayout.js`

## L-31 · (found by W1 Leg A review)

`site/src/surface/layout/elkLayout.js:857-865` prose is now factually stale: it states "Has-timelock is a property assigned to contracts *controlled by* a timelock, not the timelock itself, which is why we need the explicit name check." The leg inverts that semantics — has_timelock now means THIS CONTRACT IS A TIMELOCK — so `bandFor` already returns 0 at :854 for TimelockController rows and the name regex is redundant for them. Harmless (both paths return 0) but it is a stale prose copy of the old contract, exactly the R3 relocation shape. Confirmed the semantics flip does NOT reach the scorer: site/src/protocolScore.js keys on `principalType(principal)`/`principal.details.delay` from the resolution plane, never on `summary.has_timelock`, so no fabricated protective credit enters scoring.

**Reproduction/evidence:** `cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/wave1/leg-a && sed -n '845,870p' site/src/surface/layout/elkLayout.js && grep -n 'has_timelock' site/src/protocolScore.js   # no hits in the scorer`

## L-32 · (found by W1 Leg A review)

`Summary.is_upgradeable` is left two-state (`bool`) while reading the same effects artifact `is_factory` does, so a degraded effects stage publishes a proven-absence of upgradeability. Outside the declared six columns; pre-existing shape. Additionally, `schemas/contract_analysis.py` now declares `Summary.standards: list[str] | None` and `Summary.is_nft: bool | None`, but the producer can never emit None for either (both are IR-derived and unconditional) — a nullable the producer cannot reach, which is the inverse of the R2 dead-sentinel hygiene rule. Schema hygiene only; nothing false is published.

**Reproduction/evidence:** `cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/wave1/leg-a && sed -n '62,82p' schemas/contract_analysis.py && grep -n 'is_upgradeable' services/static/contract_analysis_pipeline/core.py services/static/contract_analysis_pipeline/summaries.py | head && grep -n '"standards": classification' services/static/contract_analysis_pipeline/core.py`

## L-33 · (found by W1 Leg F review)

IN-SCOPE RESIDUAL, not a rejection ground (not realised on the corpus). `call_target` can still be minted for an address the caller IS provably checked against, when the gate lowers into a leaf whose operand resolves to `computed`: the leaf then gets `authority_role="business"`, the state var is named only under `operands[].derived_from`, `_collect_state_var_authority_roles` reads direct operands only, and `guard_extraction_uncertain` never fires (a subtree WAS built), so the round-2 blind-spot arm never sees the function. This is a DIFFERENT mechanism from the residual the implementer declared (per-gate lowering completeness), and unlike that one it is fixable entirely inside the leg's own file (tracking.py could union `derived_from` state-var names of any leaf with `references_msg_sender=true` into the unanswered set) — it does NOT need Leg A's predicate_artifacts.py. Measured blast radius on the local corpus: ZERO. I ran the narrow query over all 129 stored predicate_trees artifacts: 0 addresses have a msg.sender-referencing, non-authority-role leaf naming a state var via derived_from that is missing from caller_gate_vars. Broadening to direct state-var operands gives 4 contracts / 81 edge rows, all of which I inspected and all are `safeTransferFrom(...)` external-call-revert leaves on genuine callees (eETH/weETH) — true negatives, not gates. I also tried 11 natural Solidity gate shapes (struct member, array index, mapping index, internal helper, branchy helper, local reassignment, loop, OR-mix, inline assembly sload, assembly caller(), delegated canCall) and the builder lowered ALL of them to `caller_gate`; only the contrived abi.decode(abi.encode(x)) round-trip reproduces. Recommend a ledger entry, not a fix.

**Reproduction/evidence:** `cd <leg-f worktree>; set -a; source .env; set +a; uv run --project . python /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/probe5.py   # dumps the leaf: authority_role=business, references_msg_sender=true, derived_from names `registry`
uv run --project . python /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/probe3.py | grep encoded_roundtrip   # -> registry_prov=call_target on a contract whose ONLY caller gate is on registry
u`

## L-34 · (found by W1 Leg F review)

IN-SCOPE, non-blocking vocabulary defect on the new `analysis_state` field: `_analysis_state` stamps `not_a_contract` on every node whose `resolved_type` is outside ANALYZABLE_TYPES = {contract, timelock, proxy_admin}. On the local corpus that is 230 Gnosis **Safe** nodes (plus 945 eoa, 61 zero) out of 1,236. A Safe is a contract; the token published on the /api analysis-detail payload (services/aggregations/analysis_detail.py:394) therefore states something literally false about 230 addresses. The intended meaning ('not an ANALYZABLE type') is documented correctly in schemas/resolved_control_graph.ResolvedAnalysisState, and the handoff §5 itself named this population 'not-a-contract', so this is inherited vocabulary rather than leg invention — but nothing downstream reads the schema comment. Suggested rename at closeout: `not_analyzable`. No frontend consumer reads the field yet, so the rename is still free.

**Reproduction/evidence:** `cd <leg-f worktree>; set -a; source .env; set +a; uv run --project . python /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/repro_not_a_contract.py
# -> analysis_state ...: {'analyzed': 1183, 'not_a_contract': 1236, None: 55, 'attempt_failed': 28, 'beyond_depth_horizon': 29}
# -> resolved_type of nodes stamped not_a_contract: {'zero': 61, 'eoa': 945, 'safe': 230}`

## L-35 · (found by W1 Leg F review)

IN-SCOPE residual, fail-open on an exception path. `_recursive_read` (services/static/contract_analysis_pipeline/tracking.py:461-479) catches any exception from the Slither accessor (all_state_variables_read / all_solidity_variables_read) and silently degrades to the NON-recursive attribute (state_variables_read / solidity_variables_read). That is a strictly narrower set, so a gate reached through an internal call becomes invisible, the name drops out of the blind spot, and `call_target` — a proven-absence claim — is minted from a failure to determine. The safe direction is to propagate not-determined (return None from `_caller_gate_blind_spot_vars`, as it already does when `functions_entry_points` cannot be enumerated). Marked `# pragma: no cover`; I did not observe it firing.

**Reproduction/evidence:** `Inspection + mutation: in the leg-f worktree, make the `except Exception` branch reachable (insert `raise RuntimeError('x')` before `values = accessor()` in _recursive_read), then run `uv run --project . pytest -m "not live" -q tests/test_controller_provenance_split.py::test_gate_in_an_unlowered_function_is_not_published_as_a_callee` — the fixture's receive() gate is only found via the recursive accessor.`

## L-36 · (found by W1 Leg F review)

Test-coverage gap at the persistence boundary. The three new persisted columns (controller_values.authority_provenance, control_graph_nodes.analysis_state, control_graph_nodes.graph_max_depth) are written in workers/resolution_worker.py:204,296-301 and asserted nowhere: tests/test_resolution_worker.py was not touched, and every new assertion stops at the in-memory artifact. That is exactly the boundary where 'absent in the snapshot => SQL NULL' must hold, and where the jsonb-null trap lives (the leg correctly added JSONB(none_as_null=True) on ControllerValue.details and pinned it with db.jsonb.jsonb_state, but only for the watcher path). This is a 'trivial residual — a missing test arm' per WITNESS_INTEGRITY_OPERATIONS.md §2 and can be closed directly by the driving agent.

**Reproduction/evidence:** `cd <leg-f worktree>; grep -rn "authority_provenance\|analysis_state\|graph_max_depth" tests/test_resolution_worker.py   # no matches`

## L-37 · (found by W1 Leg F review)

Bookkeeping only, no shipped code affected: the implementer's scratchpad script /tmp/.../wave1/measure_blindspot.py prints `not-determined round2 : 639  (+533 restored)`, which double-counts (n_undet_r2 already includes the 106 artifact-level not-determined). The figures in the ROUND 2 report table (533 not-determined, +427 restored) are the arithmetically correct ones and match `call_target 1200 -> 773`. Flagging so a later reader diffing the script against the report does not conclude the report inflated the restore count.

**Reproduction/evidence:** `cd <leg-f worktree>; set -a; source .env; set +a; uv run --project . python ../measure_blindspot.py   # line 'not-determined round2 : 639  (+533 restored)' vs 'call_target round1 1200 / round2 773'`

## L-38 · (found by W1 Leg C final review)

PREDICATE-TREE OMISSION OF INTERNAL-CALLEE MODIFIER GATES -> a false `unconstrained_proven` on real production rows. EigenLayer StrategyManager (job 664aa2be-8623-46f1-8401-53b7f8b91721) routes both deposit entries through `_depositIntoStrategy(...) internal onlyStrategiesWhitelistedForDeposit(strategy)` whose body is `require(strategyIsWhitelistedForDeposit[strategy], StrategyNotWhitelisted())` -- a mapping-allowlist on parameter 0 -- but neither entry's predicate tree carries any leaf for it (2 and 3 mandatory leaves: pause + reentrancy [+ signature] only). `param_constraints()` therefore publishes {'state': 'unconstrained_proven'} for the destination parameter of depositIntoStrategy(IStrategy,IERC20,uint256) and depositIntoStrategyWithSignature(...) -- a positive proof of absence over a gate that exists. This is a DIFFERENT lossiness layer from the three projection-completeness checks the leg added (those are leaf-projection lossiness); nothing in the persisted artifacts lets the claims plane detect it. Fix belongs to predicate extraction (walk internal-call modifiers the way body requires already are). Failure direction is a false ADVERSE, not a false credit (unconstrained_proven renders as the caller-chosen hazard tint), so it does not inflate safety. Identified by an earlier Leg C review round; re-reproduced here. 2 of the 12 `unconstrained_proven` rows in the local DB are this.

**Reproduction/evidence:** `cd /tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/wave1/leg-c && set -a && source .env && set +a && uv run python ../oos_tree_omission_repro.py   # prints: tree leaves 2/3, any whitelist leaf: False, param 0 verdict {'state': 'unconstrained_proven'}, plus the source modifier text`

## L-39 · (found by W1 tier-3 verifier)

Leg F's committed judgment-free regression metric does not reproduce from the production code path: commit faef37cd states 'mutual directed control edges 66 -> 28, distinct directed pairs 372 -> 296' with '13 genuine bidirectional gate pairs plus 2 self-loops', but projecting the production build_controller_tracking output over the 4,882 persisted edges gives 66 -> 32, 372 -> 306, with 17 unordered survivors (15 genuine pairs + 2 mapping:_roles self-loops). The committed number came from the scratchpad gate_vars() re-implementation. Direction and the >= halving hold either way and no test pins 28, but the commit's stated number must be restated (32/306) or the discrepancy recorded in the ledger.

**Reproduction/evidence:** `Base re-derived by my own SQL over control_graph_edges (relations controller_value/mapping_member/safe_owner): 372 directed pairs, 66 mutual. Head reproduced by running legf_diff.py over 88-contract replay projections I validated (fresh replays of cids 499/559/537 byte-identical to stored head_full/*.json): 'MUTUAL directed control edges: base=66 head=32; distinct directed control pairs: base=372 head=306; surviving mutual pairs at head: 17 unordered' incl. LiquidityPool<->EETH, LiquidityPool<->`

## L-40 · (found by W1 tier-3 verifier)

Unowned A-into-F merge interaction (differential finding E1, independently confirmed): Leg A's class-F/R tree widening creates 37 NEW controller-tracking targets across 15 contracts at head (0 removed), every one with authority_provenance ABSENT and a polling read_spec, including pure constants (MAX_SHARE_AMOUNT, TYPE_3, HUNDRED_PERCENT_IN_BPS) and non-authority mappings (_balances, peers, assetData). Because Leg F's rule is 'not-determined does NOT demote', each would persist as relation=controller_value — a control claim feeding the selection.py authority closure — on the next resolution run. Possibly partially mitigated by the existing primitive-scalar guard for non-address values, which cannot be verified without running resolution (cost boundary). Needs an explicit owner (Wave 2 item or a kind/type guard in tracking.py) before any resolution run.

**Reproduction/evidence:** `My own recount over the validated projections: 'NEW targets at head: 37; by provenance: {<ABSENT>: 37}; by kind: {state_variable: 35, role_identifier: 2}; REMOVED targets at head: 0' — e.g. (167, state_variable:MAX_SHARE_AMOUNT, read_spec=True), (22, state_variable:_balances), (62, state_variable:HUNDRED_PERCENT_IN_BPS). tracking.py _provenance_for returns None (absent) for names in no lowered gate leaf, and faef37cd demotes only authority_provenance == 'call_target'.`

## L-41 · (found by W1 tier-3 verifier)

Cross-leg A→F interaction confirmed and refined: 37 new provenance-absent controller-tracking targets appear at head (0 disappear); 9 are dropped by the primitive-scalar skip, but 28 survive and would persist as relation='controller_value' control edges on the next resolution run. Unowned over-claim surface created by the merge.

**Reproduction/evidence:** `Recomputed from base_full/head_full dumps: 37 new, 37/37 authority_provenance absent, all with read_specs. Applied services.resolution.tracking_plan.is_primitive_scalar_read_spec: 9 skipped, 28 survive (incl. mappings peers/assetData/strategyIsWhitelistedForDeposit, address var REWARDS_COORDINATOR). services/resolution/recursive.py:1265-1270: provenance absent -> EDGE_RELATION_CONTROLLER_VALUE ('not-determined must not silently demote'). Mechanism: _collect_state_var_operands enrolls ANY tree-le`

## L-42 · (found by W1 tier-3 verifier)

Leg F's committed regression metric is stale in three inconsistent versions and none reproduces from the production path: faef37cd/8ec22c04 claim 66->28, f9a4a02e supersedes with 66->44 'the honest number', production build_controller_tracking at merged HEAD gives 66->32 (372->306). The v21 cache comment still states 66->28 with only the 427/1,200 figure annotated stale.

**Reproduction/evidence:** `git log bodies: faef37cd 'mutual directed control edges 66 -> 28'; f9a4a02e 'mutual directed edges 66 -> 28 -> 44 ... 44 is the honest number'; db/effect_cache.py v21 entry 'drops mutual control pairs 66 -> 28' with merge note covering only the 427 figure. legf.txt production-path replay: base=66 head=32 (17 unordered pairs incl. 2 self-loops). Direction and >=halving hold in every variant; no test pins any stale number (grep clean). Restate as 32 or re-derive.`

## L-43 · (found by W1 tier-3 verifier)

exec.arbitrary narrowing lands 8 of the expected 9; the EndpointV2.lzCompose miss is upstream of Leg C — the mandatory-leaf operand extraction discards the _to operand, so param_constraints honestly answers not_determined. L-24 cousin; needs a ledger owner.

**Reproduction/evidence:** `full_claims.txt cid=457: destination_constraint -> {state: not_determined}; head census: constrained 7 + removed 1 = 8 narrowed of 20. The pre-Wave-0 misbinding (_from as destination) would have read 'constrained' for the wrong reason had W0-3 not fixed it. This is the definitive collapsed-input instance for Leg C.`

## L-44 · (found by W1 tier-3 verifier)

Harness invalidation extends to Leg C's own commit-message measurements: ee46c314's census (4/31/45 param states; 11 unconstrained_proven exec rows; forwardExternalCall 'constrained/mapping_allowlist') came from the artifact-only build_claims(None,...) recompute and does not match merged HEAD (16/15/49; exec unconstrained_proven 0/19; forwardExternalCall constrained via external_call_revert). States held; the numbers must not be re-cited.

**Reproduction/evidence:** `ee46c314 commit body vs full replay full_claims.txt: cid=586 forwardExternalCall {binding: operand, guard: external_call_revert}; exec census head = {constrained 7, not_determined 12, unconstrained_proven 0}; param census 16/15/49. Differential's flagged item 4 (scratchpad/recompute_legc.py drops every idiom-tier exec.arbitrary under contract=None) is the same defect; any future A3/A4 re-derivation must use the full-replay substrate.`

---

# Wave 2 exit sweep (2026-07-28: leg reviews + tier-3 verifier findings)

## L-45 · (found by W2 Leg D review)

`get_token_balances` now returns a `decimals_reported` key, but neither writer persists it: `workers/resolution_worker.py:458-470` and `services/monitoring/tvl.py:258-269` construct ContractBalance field-by-field and there is no such column. The "Etherscan reported nothing" fact is discarded at the DB boundary, and the surviving discriminator is `price_usd IS NULL` — which the same commit gives a SECOND meaning (`price_usd if decimals is not None else None`), so a NULL `price_usd` now means either "no divisor reported" or the older "unpriced". `company_overview.py:1298` republishes `price_usd` verbatim and cannot tell them apart. The leg strictly improves the prior state (no money derived from a guessed divisor). **Owner: W3-E** (balance-table consumer must disclose both meanings, or the producer plane gains the column).

**Reproduction:** `grep -rn 'decimals_reported' --include=*.py /home/riley/PSAT   # only utils/etherscan.py; no column in db/models.py, no reader`

## L-46 · (found by W2 Leg D review)

The reach-vs-TVL ceiling is applied only on the `reach_determined: True` path in `_add_reach`. The unvalued branch returns before it, so `observed_reach_priced_usd` — published as a "partial floor" — is never checked against `protocol_tvl_usd`, and a floor above the protocol's own measured TVL is publishable with no `reach_tvl_check` at all. Same contradiction the ceiling was added to catch, on the sibling key. **Owner: Wave 4** (admission test met: a false floor can reach the witness plane).

**Reproduction:** `Read services/effects/recipes.py::_add_reach: the "if unvalued_assets:" block sets observed_reach_priced_usd and returns above the _reach_tvl_state(...) call.`

## L-47 · (found by W2 Leg D review)

A MEASURED reach of exactly $0 (`reach_determined: True`, `observed_reach_value_usd: 0.0`) renders no Reach row at all in `claimWitnessFacts`: `formatUsdUpperBound(0)` is falsy, so a measured zero reads as silence — the "never attempted" state D3 just built a discriminator for, in the one renderer branch that does not consult it. Pre-existing; the backend payload is pinned correct by `test_zero_reach_without_the_flag_is_a_measured_zero_not_a_floor`; only the renderer is blind. **Owner: W3-E.**

**Reproduction:** `node -e "import('./site/src/claimsVocab.js').then(m=>...)" with a flow.out witness carrying reach_determined:true, observed_reach_value_usd:0 — no Reach fact emitted.`

## L-48 · (found by W2 Leg D review)

`SENTINEL_ADDRESS` (`calldata.py`) and `NATIVE_ASSET_LOG_EMITTER` (`config.py`) are the SAME address (`0xee`×20). A2 compares that value against a log EMITTER while `_is_invented_identity` compares it against a log RECIPIENT; the two uses do not currently meet, but they are one field-name away from conflating "the attacker stand-in received the money" with "the asset that moved was native ETH". The emitter fact itself was independently verified live (4 sanctioned reads incl. pinned 25619159; WETH `deposit()` control discriminates). **Owner: record** (naming hygiene; split the constants when either is next touched).

**Reproduction:** `grep -n '^SENTINEL_ADDRESS' services/effects/calldata.py && grep -n '^NATIVE_ASSET_LOG_EMITTER' services/effects/config.py   # same literal`

## L-49 · (found by W2 Leg D review, verifier-confirmed)

`effect_transcripts` record calls and success/revert only — no logs — so no reach or value verdict is re-derivable from persisted evidence. Every A2-plane differential is therefore a projection or a fixture, never a recomputation over the 41 published rows; an earlier "41 changed / $0.00" projection was an artifact of empty log lists and must never be cited. Blocks inv 11's replay story for the effects plane. **Owner: record** (a transcript-plane logs column is a schema change outside every wave surface).

**Reproduction:** `psql "$DATABASE_URL" -c "select distinct jsonb_object_keys(payload) from effect_transcripts;"   # no logs key`

## L-50 · (found by W2 Leg B review)

Leg B extends `derived_from` to view_call/external_call/Unary operands and replaces a bare-bool leaf with an `external_set` leaf carrying `authority_role="delegated_authority"`. The effects plane does not read `derived_from` (only `services/resolution/permissionless_shapes.py` does) and `gate_ref` is part of the cache key so changed roles cold-miss — but one residual route was NOT proven cold: `calldata.py` `_authority_gate_target` and the pauser probe select OTHER functions to probe based on `_authority_roles(tree)`, a cross-function dependency the cache key does not capture. Unreproduced as a stale serve; every local row predates v21 anyway. **Owner: record** (re-examine if a cache row is ever served across an analysis-schema boundary).

**Reproduction:** `grep -rn 'derived_from' services/effects services/policy services/resolution | grep -v permissionless_shapes; grep -n '_authority_gate_target' services/effects/calldata.py`

## L-51 · (found by W2 Leg B review)

The "tree-absent population G3 measured is closed" claim is instrument-limited: the measurement asks `RevertDetector(fn).run()` for every tree-less predicate target (828 at HEAD, 0 with a visible gate — independently reproduced with tree-bearing positive controls 22/22, 29/29). L-38's class (internal-callee-modifier gates) is exactly what that detector cannot see, so the honest statement is "0 tree-less functions carry a gate the RevertDetector can see". Verified not to bite here: StrategyManager's tree-less set is 20 view getters; the L-38 functions are tree-bearing. **Owner: record beside L-38.**

**Reproduction:** `see W2 Leg B round-3 review; recount script over the 88 replay outputs gives 828/0, with cids 568/577 as positive controls.`

## L-52 · (found by W2 Leg B review)

`ControlGraphEdge.relation` has three readers beyond the enumerated set: `principal_enrichment.py:465-491` (label dispatch — `controller_value_unattributed` matches no arm, so no `controller_*` label is minted: strictly better than the pre-fix over-claim), `analysis_detail.py:439` and `company_overview.py:1358` (publish the raw relation string). All three verified correct by fall-through, but nothing pins the new relation's non-participation in the principal-label chain — a future arm added there silently re-admits unattributed edges. **Owner: Wave 4** (one pin test).

**Reproduction:** `grep -rn '\.relation\b|"relation"' --include=*.py --include=*.js services routers site/src db schemas | grep -v test`

## L-53 · (found by W2 Leg B final review)

The `build_effective_permissions` half of the `authority_openness` R1 fix is UNPINNED: reverting both added blocks in `effective_permissions.py` leaves the relevant suite green (41 passed), because `effective_permissions_writer.py` independently derives openness from the record's capability. No behavioural harm today (both paths compute the same value), but the payload-plane `authority_openness` key (`schemas/effective_permissions.py:63`) can be silently dropped by a future edit. **Owner: Wave 4** (one mutation-pinning test).

**Reproduction:** `revert the two blocks in services/policy/effective_permissions.py; tests stay green (41 passed) — see W2 Leg B round-3 review for the exact revert.`

## L-54 · (found by W2 Leg B review — CLOSED at wave close)

R5 note was missing in `db/effect_cache.py` for Leg B's predicate-tree shape changes (v10/v20 precedent). Closed by the driving agent in the Wave 2 closeout commit: a no-bump NOTE under the unreleased v31 entry, per the file's own "same version, second correction" precedent (`ANALYSIS_SCHEMA_VERSION` 3→4 already gates the materialization plane; `gate_ref` cold-misses; every local row predates v21).

## L-55 · (found by W2 Leg B review)

The `guard_extraction_uncertain` marker is written into the predicate artifact only when non-empty, so artifact ABSENCE of the key collapses "the builder looked and found no missed guards" with "this artifact predates the marker". Every downstream reader (`effective_permissions.py`, `tracking.py`) reads absence as the former. Same absent-vs-empty shape R1 targets, one level up in the artifact plane. Pre-existing; unchanged by the leg. **Owner: record** (bites only when a reader must distinguish marker eras; today all 107 artifacts predate it uniformly).

**Reproduction:** `sed -n '413,418p' services/static/contract_analysis_pipeline/predicate_artifacts.py   # emit-when-non-empty`

## L-56 · (found by W2 Leg B review)

`capability_role_grants` returns `None` (not-determined) whenever ANY not-determined signal appears in the tree, discarding a witnessed single-role grant in e.g. `AND(finite_set role 8, unsupported)`. Defensible for a whole-field verdict with no partial state; zero realised rows (witnessed count 200 before and after the round-2 `unsupported` change). Latent over-hedge, adverse direction. **Owner: record.**

**Reproduction:** `census script over the 1,773 capability_expr rows — witnessed stays 200; construct AND(role-grant, unsupported) to see the discard.`

## L-57 · (found by W2 Leg B review)

cid 570 `DelegationManager.undelegate(address)` now correctly projects public (self-keyed arm verified in source), but `protocolScore` scores it as a plain public action, losing the distinction that an operator/approver may FORCE-undelegate a third party (the `msg.sender != staker` arm). A scoring-vocabulary gap, not a resolution error. **Owner: W3-E** (protocolScore reads the surface Leg E owns).

**Reproduction:** `stored source for cid 570: if (msg.sender != staker) { require(_canCall(operator) || msg.sender == delegationApprover(operator)) } — the earned-public algebra reads the self-keyed arm as open, which is correct; the score treats both arms identically.`

## L-58 · (found by W2 Leg D final review)

`_duration_from_trees`'s `guard_constant` branch harvests any plausible constant from `operands ∪ absorbed_operands`, discarding which SIDE of the comparison the constant sat on and the operator: `require(block.timestamp + 3600 < pausedUntil)` → `(3600,'guard_constant')` and `require(block.timestamp > pausedUntil + 300)` → `(300,'guard_constant')` — a lead time or cooldown offset published as the freeze window, for a latch whose real expiry is a storage timestamp (the etherfi shape the docstring says must be `not_determined`). New in the leg (base read `operands` only). Error direction flips over-severe → MITIGATING, but it is CONTAINED: every consumer (both prose copies + the claims_bridge scorer contract) trusts a bound only with `auto_expiry === true`, and the fork cross-check (anvil warps `max_pause_duration+1`) sets `auto_expiry=False` when the freeze does not lift. The fabricated number reaches `effect_verdicts.witness` and the cache details plane but renders nothing and scores nothing without fork confirmation. **Owner: Wave 4** (harvest should be side/operator-aware; the fork containment must gain a pin test so it cannot be loosened).

**Reproduction:** `uv run python <scratchpad>/rv2/window_shapes.py   # compiled shapes print (3600,'guard_constant') / (300,'guard_constant')`

## L-59 · (found by W2 tier-3 verifiers, both lenses)

Wave-record corrections that supersede earlier stated figures — the corrected numbers are the citable ones: (1) `resolved_empty → not_determined` has **1** projectable transition (cid 577 `WithdrawRequestNFT.requestWithdraw`), not "3 of 80" — the `_intersect_finite` half is unobservable by re-projection because persisted `capability_expr` is the collapsed output; the fix is demonstrated on reconstructed conjuncts with an inherited-empty control. (2) Commit `673adc95`'s "the one row with no resolved principals carries `0x1111…1111`" has **0** realised rows (all 35 `caller_arbitrary` destinations are same-function principal echoes); docstring corrected at wave close. (3) The self-audit floor refuses **78/150** rows (49 `authority_change` + 29 `freeze_pause`), not 49; docstring corrected at wave close. (4) The public→gated flip population is exactly **2** (cid 568), gated→public exactly **3** — "sample 3 rerouted rows" was not satisfiable. (5) `f60b931a` says "42 latch-carrying rows"; the differential measures 52 evaluable (slicing stated; published quantities agree: 0 bounds, 0 `no_time_reference`).

## L-60 · (found by W2 tier-3 verifier lens 1)

Units-trap residual, pre-existing relative to the adjudication (not a regression): a leaf whose operand union carries BOTH a seconds clock and a block-number clock plus a block-count constant harvests the block count as seconds (the harvest loop is entered via the seconds clock and takes the max constant blind to which clock each constant was compared against). No compiled shape produced it (a comparison leaf holds one comparison); reachable only through operand absorption across a mixed expression. **Owner: record beside L-58** (the same side/operator-aware harvest fix closes both).

## L-61 · (found by W2 tier-3 verifier lens 1 — substrate hygiene, RESOLVED at wave close)

Two measurement-substrate mutations during Wave 2, both resolved by the driving agent at wave close: (1) a synthetic `contract_materializations` row (`0xaaaa…aaaa`/`TestContract`, schema v4) leaked into the local dev DB `psat` during Leg B verification — deleted (81 real rows remain); it also invalidated the letter of `0e60ce0d`'s "only v2/v3 rows" claim while leaving its substance intact (no v4 row carried pre-purity trees). (2) Migration `c4b81e2a90fd` (`authority_openness`) was unapplied on `psat`, so ORM entity loads of `EffectiveFunction` raised `UndefinedColumn` — `alembic upgrade head` run on the dev DB (Wave-1 precedent: dev DB tracks the branch's additive migrations).

## L-62 · (found by W2 tier-3 verifier lens 1)

The cache deployment/code plane split is a hand-enrolled denylist of exactly the spec's six `DEPLOYMENT_PLANE_KEYS`; any future deployment-plane key must be enrolled by hand or it leaks cross-deployment on a hit. **Owner: record** (a naming-convention or schema-level split is the durable fix; out of every wave surface now that G6-C1 landed).

## Adjudication record — Wave 2 Leg D closeout (2026-07-28)

Leg D hit the 3-round cap. Rounds 1–2 rejections were fixed and verified closed by the round-3 reviewer, whose sole remaining violation was the A7 clock-spelling gap (`now`/`block.number` latches still published proven-indefinite). Per OPERATIONS §2 the driving agent applied the reviewer's minimal prescription directly (`witness/leg-d` `0a7fa43e`): demotion counts `timestamp|now|number`, seconds harvest counts `timestamp|now` only. Mutation-checked (4 new arms red with the split reverted; 4 module controls green), 160 relevant tests pass, v31 comment amended (unreleased version). The differential re-verified the split empirically (0 realised corpus delta; monotone away from the proven state) and both tier-3 lenses confirmed the adjudication implements the prescription exactly. L-12 and L-38 remain OPEN with stated cause: Leg B neither fixed nor worsened them (verified byte-identical differential on an internal-callee-modifier shape); L-38's owner remains the predicate-extraction plane; L-12's the reconciler.

---

# Wave 3 exit sweep (2026-07-28: leg reviews + differential + tier-3 verifier findings)

## L-63 · (found by W3 Leg E review — CLOSED at wave close)

`auditMatching.matchesEra`'s temporal successor discriminator keyed on `hasOwnProperty("timestamp_replaced")` alone, but the producer writes `timestamp_replaced` only when the successor's log carried a timestamp while `block_replaced` is written for every era with a successor — so an era that provably ended (block known, timestamp unrecorded) Infinity-folded the containment question, the exact fold the commit removed elsewhere. Closed by the driving agent (`9e0c7f80`): the discriminator accepts either sibling key; discriminating vitest arm added.

## L-64 · (found by W3 Leg E review)

`role_holders`' `holders_state: "not_determined"` arm is structurally unreachable from the live derivation path, not merely unrealised: `capability_role_grants` ends with `if members`, so a memberless grant is dropped before the consumer sees it, and the only route to the arm is the `authority_roles` column fallback, which cannot fire while every row's `capability_expr` is a non-empty object. Fails safe (fixture-covered), but it is a dead hedge by construction on the live source. **Owner: record** (becomes reachable only if the grant algebra gains a partial state).

**Reproduction:** `read capability_role_grants' final comprehension in services/policy/capability_surface.py; grep the fallback condition in services/chat/tools.py role derivation.`

## L-65 · (found by W3 Leg E review)

2 of the 229 control-graph nodes gaining `details.terminal_principal` are typed `proxy_admin` in the control-graph plane while the `PrincipalLabel` row that produced the walk is typed `contract` (the producer writes the walk only for `resolved_type == "contract"`). Inert today (no `proxy_admin` node is reachable as an indirect principal; 0 of 857 principal instances change their note), and the failure direction is a hedge, not an over-claim. The declared negative control covered only Safe/EOA. **Owner: record.**

## L-66 · (found by W3 Leg E review)

`BalanceTable.coverageNote` returns the truncation sentence and RETURNS EARLY on `holdings_coverage.state === "may_be_incomplete"`, so a contract both at the 100-row page cap and partly unpriced loses the `unvalued_rows` disclosure — two independent facts, one suppressed. 0 realised (all 7 at-cap contracts carry `protocol_id IS NULL`); live the first time an enrolled contract holds a full page. **Owner: Wave 4** (compose the sentences; disclosure suppression is the admission-test shape in the disclosure direction).

**Reproduction:** `read coverageNote in site/src/surface/lanes/BalanceTable.jsx — early return on may_be_incomplete before the unvalued_rows sentence.`

## L-67 · (found by W3 Leg E review, reproduced by accident)

`tests/test_artifact_storage_integration.py` is not idempotent against a reused test DB: a second run against the same DB fails `test_materialization_blobs_written_under_a_foreign_prefix_are_still_readable` and `test_hydrate_keeps_outage_absence_and_payload_apart`. The documented drop+recreate workflow hides it. **Owner: Wave 4.**

**Reproduction:** `run the file twice against one psat_test_* DB without recreating it.`

## L-68 · (found by W3 Leg D1 review, implementer-disclosed)

`Candidate.effect_targets` (selection.py:143, populated at :1268) is WRITE-ONLY — no production code and no test reads it — and it carries the conflated display list D1 just removed from the selection decision into the dataclass the effects worker passes around: the next reader's trap. Correctly not fixed in the isolated leg. **Owner: Wave 4** (drop the field or rename it to its display meaning).

**Reproduction:** `grep -rn 'effect_targets' services/effects workers | grep -v selection.py:1268-adjacent — no reader of cand.effect_targets.`

## L-69 · (found by W3 Leg D1 review + differential)

The protocol_id-NULL orphaning family, quantified on this plane: 594 of 1,773 `effective_functions` rows can never enter the cascade (their contracts carry `protocol_id IS NULL`, 474 such contracts), and 26 of the 107 persisted `effects` artifacts hang off `jobs` rows with SQL-NULL `protocol_id` although 18+ of those addresses are protocol-1 contracts — any projection scoped by `jobs.protocol_id` silently loses them (measured: 955/1179 coverage scoped by protocol vs 969/1179 by address). Every Wave 0-3 count on these planes is a lower bound for this reason too. **Owner: record** (discovery/orchestration plane, outside every wave surface; the known family from project memory).

## L-70 · (found by W3 Leg D1 review)

Latent `resource_cap` displacement: `PSAT_EFFECTS_RESOURCE_CAP` is set nowhere, so no cap fires today, but the 38 newly-admitted zero-plan candidates land at ranks 12-278 of the 481-long value-ordered queue — the first cap below ~90 displaces plan-bearing candidates with receiver-hook ones. `_log_dropped` names what it drops (not silent). 36 of the 38 are ERC-receiver hooks: fork-budget sizing note for the effects stage. **Owner: record (ops).**

## L-71 · (found by W3 Leg D1 review + verifier lens 1)

Instrument limits on D1's descriptive splits — the load-bearing numbers reproduce, the finer ones bracket: the 156-population's `state_changing` split "147 TRUE / 8 NULL / 1 FALSE" is join-rule-dependent (signature-only gives 125/30/1; +name fallback gives 153/2/1; FALSE=1 = fid 2344 is stable under every rule); the docstring's "11 of the 49" guard-origin admits measures 10 (corrected at wave close, `9e0c7f80`); SCORING_INVARIANTS' three-way split (219/84/42) tightens to 241/86/18 under the better join. The candidate delta (443→481, +38/−0) is invariant under all rules. Any later recount must state its artifact-join rule (per-JOB artifacts, keyed by jobs.address, pre-canonicalization signatures — see the Wave-3 method cautions). **Owner: record.**

## L-72 · (found by W3 Leg D1 review)

fids 2893 `alertBatchMetadataUpdate(uint256,uint256)` and 2894 `alertMetadataUpdate(uint256)` carry `selector = ''` (empty string) in `effective_functions` beside well-formed `abi_signature`s — the L-27 fallback/receive empty-selector convention on NAMED functions (pre-existing data defect). Both are in D1's entering set; both plan 0 probes today, so nothing is published, but an empty selector reaching `find_cached_verdict`/`_selector_key` is the L-27 collision class. **Owner: Wave 4** (one look: producer or backfill).

**Reproduction:** `select id, abi_signature, selector from effective_functions where selector = '' and abi_signature not like 'fallback%' and abi_signature not like 'receive%';`

## L-73 · (found by W3 differential + verifier lens 2)

Wrong-chain `classify_address` residual: the chain predicate landed on the CGN `details` read, but `_resolve_contract` falls back to an address-only lookup across all chains and the name-hint promotion then fires — so a wrong-chain query still publishes `kind='timelock'` and `label='EtherFiTimelock'` from cross-chain rows; only the details-derived facts (delay_seconds, threshold) are chain-scoped. Stated-with-cause in the leg's commit (the label/CGN plane has no chain column — the handoff §3 known gap). **Owner: record beside the §3 deployment-key item** (structural on the first multichain run).

## L-74 · (found by W3 differential)

`contract_brief`'s "last upgrade" exact-timestamp tie prefers the poll-detected row (block NULL, tx NULL) over an equally-timestamped log-indexed event — deliberate per the comment (a NULL block is not evidence of being older) and honestly labelled by the `detection` discriminator, but the tie arm publishes the less-provenanced of two equal candidates. 0 realised. **Owner: record.**

## Adjudication record — Wave 3 closeout (2026-07-28)

Both tier-3 verdicts returned **PASS** (`controls_held`, `differential_reconciled` true on both) while the tier-0 gate returned FAIL on `no-new-jsonb-isnull` — identified by BOTH verifiers as a grep false positive: the flagged line was the correct compound guard (SQL-NULL + `jsonb_typeof` CASE), pre-existing on main, re-split across physical lines by D1's SQLAlchemy rewrite so the line-based grep lost sight of the guard. Disposed per the adjudication-economics rule (mechanically re-provable criterion): the redundant `IS NULL OR` was dropped from the test predicate (`jsonb_typeof(SQL NULL)` is SQL NULL, so the CASE ELSE arm already folds it — semantics identical, verified by the 66-test file), the gate re-run mechanically, and no verifier re-run spawned. The same closeout commit (`9e0c7f80`) fixed the four reviewer-flagged trivial residuals (L-63; the unpinned `state_changing IS NULL` disjunct with a mutation-checked sole-pin arm; StatusStrip's proven-state default; the role-source prose) and corrected the two stated-magnitude comments (L-71, the "62 of 147" figure). Playwright visual baselines — the one unexercised gate both verifiers flagged — were run at HEAD: **4/4 passed**. The two public-payload key removals (`confidence` → `naming_rule`; duplicate `label` suppressed) are called out prominently in WAVE_3_REPORT.md per §10. SCORING_INVARIANTS.md remains tracked (deliberate: it is D1's deliverable); the eight sibling witness docs remain untracked (an accidental `git add -A` staging of them was caught and amended out).

---

# Wave 4 exit sweep (2026-07-28: leg reviews + differential + tier-3 verifier findings)

## L-75 · (found by W4 Leg A review; implementer-disclosed)

The `reach_indeterminate` branch of `_add_reach` publishes `observed_reach_floor_usd = acting_balance_usd` with no `_reach_tvl_state` call and no `reach_tvl_check` at all — the identical L-46 asymmetry one branch further up, fixed on the priced-floor branch this wave. 0 realised locally (0 of 248 rows carry `reach_tvl_check`). **Owner: effects plane, next touch of `_add_reach`** (same one-guard shape as e88ebf3d).

## L-76 · (found by W4 Leg A review)

Trap-note beside L-58's before-figure: 4 of the 248 `effect_verdicts` rows DO carry the KEY `duration_bound_seconds` with a jsonb-null value (ids 169/180/202/243, all freeze_pause/proven) while `duration_bound_source` is absent on all 248 — "0 rows publish a bound" is true under publishes-a-NUMBER. The jsonb-null-vs-key-absence distinction sits inside the headline count; the consumer contract (absent source ⇒ not_determined) already handles it. **Owner: record.**

## L-77 · (found by W4 Leg A review)

The label-corpus gate silently disappears from the offline suite in a fresh worktree whose `.venv/.solc-select` lacks the pinned solc: `tests/test_label_corpus.py:37-38` and `test_label_corpus_discrimination.py:354-355` catch `SolcNotInstalled` and `pytest.skip`, contradicting `tests/support/label_corpus.py:13`'s own "so the gate runs (never skips)" comment — CI runs it, a local run may not, and a green local run is then not the gate it appears to be. (`test_pause_duration_clock_opacity.py` has no such guard — it errors loudly, which is the right direction.) **Owner: Wave-4 deferral register** (make the skip loud or provision-checked; a harness change, not a claim-plane change).

## L-78 · (found by W4 Leg C review)

`workers/selection_worker.py:163` uses `Contract.job_id IS NULL` as a synonym for "never analyzed" when building the analysis candidate pool, but `contracts.job_id` is ON DELETE SET NULL — every contract whose job was deleted re-enters the pool and can be re-analyzed at full Etherscan/OpenRouter/eRPC cost while its policy rows still exist. Locally 511 of 641 contracts sit in that pool, 4 carrying policy rows. This is also the one consumer whose behaviour the L-12 repair changes (a repaired orphan leaves the pool — the correct direction). **Owner: orchestration plane** (cost hazard, not a false published claim — outside the Wave-4 admission test, recorded with cause).

**Reproduction:** `sed -n '160,166p' workers/selection_worker.py; psql: select count(*) from contracts where job_id is null;`

## L-79 · (found by W4 Leg C; implementer-disclosed, reviewer-confirmed)

`reconcile_role_set_drift` (`services/resolution/deferred_reconciler.py:458`) carries the identical orphan blind spot L-12 fixed in its sibling — same `.join(Contract, Contract.job_id == Job.id)` — so role-store drift on an orphaned contract can never be reconciled. Separate population (ROLE_STORE_TRACE_STEP), no ledger item admitted it, leg correctly did not widen scope. **Owner: next reconciler touch** (same one-line rekey as d862a759).

## L-80 · (found by W4 Leg C; implementer-disclosed, reviewer-confirmed)

A parameterised fallback earns a fabricated selector: `has_no_selector('fallback(bytes)')` is False (the sentinel set is exactly `{'fallback()','receive()'}`) while the signature is canonical, so `effective_permissions.py` mints `keccak('fallback(bytes)')[:4] = 0x19198595` for an entry point with no dispatch selector — the L-14 class. 0 realised; structural on the first `fallback(bytes calldata)` contract (valid ≥0.6). Caveat: rests on Slither rendering the signature as `fallback(bytes)`. **Owner: predicate/effects producer plane.**

## L-81 · (found by W4 Leg C; implementer-disclosed, reviewer-confirmed)

The persisted fallback()/receive() rows still carry the pre-Wave-1 fabricated selectors (3× `0x552079dc`, 4× `0xa3e76c0f` in psat): the producer is fixed (empty-string sentinel), so the next real policy run rewrites them; until then `_selector_key` folds those rows onto the fabricated identity, not the documented sentinel. **Owner: record — resolves on the next pipeline run** (writing the DB by hand is out of bounds).

## L-82 · (found by W4 Leg C; implementer-disclosed, reviewer-confirmed — L-67 family)

`tests/test_resolution_worker.py`'s teardown deletes Job/Artifact/JobDependency but never Contract, so every run manufactures L-12's exact orphan shape in the test DB via the SET NULL FK — any population assertion against a reused test DB is harness-contaminated. **Owner: next touch of that conftest** (same idempotence shape as 52126cf9).

## L-83 · (found by W4 Leg B review + both tier-3 verifiers — STANDING METHOD CAUTION, supersedes every seed-grouping claim)

**The pre-fix (base) tree plane was never reproducible under PYTHONHASHSEED pinning**: the `_operand_for_value` tie-break varied run-to-run at a FIXED seed (allocation history participates in `hash()` of the Source set) — cid 537 yields two distinct byte forms across three runs at seed 0; 19/92 units flicker across fresh processes at one seed. Consequences, binding on any future reader: (1) every BASE-side tree count in the Wave 1–4 differentials is one sample of a distribution, not a measurement (the head side after 3655d3e1/f3c0da4b IS byte-stable — verified across seeds and processes); (2) commit 3655d3e1's "flips at seeds 2/3 vs 0" grouping and the "12 verdicts on 6 units" magnitude (persisted in two db/ comments, corrected at final closeout) are sample-dependent restatements of the right diagnosis (L-39/L-42 class); (3) the L-25 noise bucket is now provably empty at HEAD rather than bucketed.

## L-84 · (found by W4 Leg B review)

Pre-existing guard-word mislabel: `_facts._classify_constraining_leaf`'s `via_derived` branch returns the literal `"hash_commitment"` UNCONDITIONALLY for equality/comparison leaves bound through `derived_from` — no hashing need appear (observed on a SafeTransferLib `require(success)` returndata check publishing `guard: hash_commitment`). Reaches the published surface (claimsVocab renders the guard word); the hedge is right (`pins` capped at null for derived_from bindings), the word is wrong. The L-25 settle retired the observed instance by picking a different operand; the class is live wherever a computed operand's derived_from names a parameter on a require-shaped mandatory leaf. **Owner: claims/matchers plane, post-effort** (a guard-vocabulary fix with corpus arms).

## L-85 · (found by W4 Leg B; implementer-disclosed, count re-derived by reviewer)

`effects.py _own_selector` publishes keccak of the DECLARED signature in the effects record's `selector` field whose docstring claims msg.sig semantics — false for **317 of 2,247** function records on the 88 replayable units (every enum/interface/struct-typed parameter), and the same declared-form value feeds `effective_functions.selector`. L-17 correctly added `abi_selector` beside it rather than rewriting; the root fabrication survives with its docstring. **Owner: effects-record producer, post-effort** (L-27/L-72-family; the L-72 refutation shows the *policy* writer canonicalizes correctly — this is the artifact-plane sibling).

## L-86 · (found by W4 Leg B review)

Surviving nondeterminism in a published predicate-tree field at HEAD, outside L-25's surface: `trees.<sig>.leaf.expression` carries the Slither SSA temp name (`return result_3` at seed 0 vs `result_2` at seed 1 on cid 568), stable within a seed, and PYTHONHASHSEED is pinned nowhere in production (Dockerfile/fly.toml/workflows grep clean) — this will pollute future predicate-tree differentials the way L-25 did. **Owner: predicate-extraction plane, post-effort** (same family as L-4/L-25; consider pinning the seed in production images as the cheap half).

## L-87 · (found by W4 tier-3 verifier lens 2)

Committed perf figures restated: f3c0da4b's "back at 24.3s on cid 537" does not reproduce paired on a quiet machine — base 17.2s vs head 19.6–21.3s on the heaviest unit, a real +15–25% on that unit, not parity (figures were presumably taken under concurrent-leg load). The substantive claims hold: no minutes-scale blow-up, the lru_cache storm is gone, the full 92-unit sweep completes on both sides. **Owner: record** (restatement, not a defect).

## L-88 · (final-closeout corrections — CLOSED in the Wave 4 closeout commit)

Driving-agent direct fixes after the Wave-4 verdicts: the "12 verdicts on 6 units" magnitude in `db/effect_cache.py` and `db/contract_materializations.py` restated as base-sample-dependent per L-83 (both verifiers demanded it); `policy_caller.sol`'s stale "derives nothing" inline comment updated to the post-L-17 truth. Also recorded here: 8c7b8fdf's commit body says "120 added lines, 2 removed" where numstat disagrees (bookkeeping only), and L-58's "0 of 248 publish a bound" carries the L-76 nuance.

## Adjudication record — Wave 4 closeout (2026-07-28)

All three legs accepted within cap (A and C round 1, B round 2 — per the workflow log). Exit PASS: gate green (suite 5,439 / vitest 615 / determinism both classes / R5 v32→v34 ordinal with one reason each), both tier-3 verdicts PASS with controls held and the differential reconciled line-by-line (179 operand-plane leaf diffs all attributed to L-25's settle; +2,220 `abi_selector` keys to L-17; 0 published-claims / controller-tracking / summary diffs; the one initially-unattributed row resolved to L-86's expression-field noise). Outcome notes: **L-38 closed by attribution** — the producer fix had already landed in Wave 1 (`a96b2ca3`); Wave 4 added the four mutation-checked pin arms and the source-quoted attribution; the two StrategyManager rows read `constrained/mapping_allowlist` at base AND head, so the ledger's "false unconstrained_proven on real rows" was stale against the merged branch. **L-72 REFUTED on data** (`eeee8a31`): no empty-selector named row exists in any local DB; the population-level invariant is now pinned instead. **L-34 corrected** (`47e1a234`): the legacy token was never persisted, so the rename shipped without a data migration and the legacy enum member was dropped. **L-12 landed as reachability + honest deferral**: the rekeyed join makes orphaned marker rows reachable in principle, but both orphaned contracts have zero jobs at their address, so convergence needs a fresh analysis job (cost boundary) — deferral cause verified true by lens 1.
