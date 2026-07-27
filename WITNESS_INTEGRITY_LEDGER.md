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
