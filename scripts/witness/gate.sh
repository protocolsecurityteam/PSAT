#!/usr/bin/env bash
# Tier-0 mechanical gate for the witness-integrity fix waves.
#
# Pure command execution + greps. NO model judgment lives here — that is the
# whole point. Anything requiring a correctness call belongs to a tier-2 (Opus)
# or tier-3 (Fable) reviewer, not to this script.
#
# Usage:
#   scripts/witness/gate.sh [--base <ref>] [--skip-suite]
#
# Exit 0 = every check passed. Exit 1 = at least one FAIL.
# SKIP is not a failure but is reported loudly; a SKIP on the determinism gate
# before Wave 0 exits IS a failure (see W0-8).

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

BASE="${BASE:-main}"
SKIP_SUITE=0
REQUIRE_DET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --base) BASE="$2"; shift 2 ;;
    --skip-suite) SKIP_SUITE=1; shift ;;
    --require-determinism) REQUIRE_DET=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

FAILED=0
declare -a RESULTS=()

record() { # name status detail
  RESULTS+=("$1|$2|$3")
  [ "$2" = "FAIL" ] && FAILED=1
  printf '%-28s %-6s %s\n' "$1" "$2" "$3"
}

echo "=== witness tier-0 gate (base=$BASE) ==="

# --- 1. formatting -----------------------------------------------------------
if out=$(uv run ruff format --check . 2>&1); then
  record ruff-format PASS ""
else
  record ruff-format FAIL "$(echo "$out" | tail -3 | tr '\n' ' ')"
fi

# --- 2. lint -----------------------------------------------------------------
if out=$(uv run ruff check . 2>&1); then
  record ruff-check PASS ""
else
  record ruff-check FAIL "$(echo "$out" | tail -3 | tr '\n' ' ')"
fi

# --- 3. types ----------------------------------------------------------------
# Scope to GIT-TRACKED files only. Local-only scratch dirs (e.g. issue-fixes-*/,
# excluded via .git/info/exclude) are invisible to CI but visible to a local
# pyright run, so an unscoped check fails on a clean checkout and would block
# every wave for a reason CI does not care about.
pyout=$(uv run pyright 2>&1)
pyerrs=$(printf '%s\n' "$pyout" | grep -E '^\s+/.*- error:' || true)
tracked_errs=""
if [ -n "$pyerrs" ]; then
  while IFS= read -r line; do
    f=$(printf '%s' "$line" | sed -E 's|^[[:space:]]*([^:]+):.*|\1|')
    rel=${f#"$PWD/"}
    if git ls-files --error-unmatch "$rel" >/dev/null 2>&1; then
      tracked_errs="${tracked_errs}${line}"$'\n'
    fi
  done <<< "$pyerrs"
fi
if [ -z "$tracked_errs" ]; then
  untracked_n=$(printf '%s\n' "$pyerrs" | grep -c . || true)
  record pyright PASS "$( [ "${untracked_n:-0}" -gt 0 ] && echo "${untracked_n} error(s) in untracked-only paths, ignored (CI parity)" )"
else
  record pyright FAIL "$(printf '%s' "$tracked_errs" | head -3 | tr '\n' ' ')"
fi

# --- 4. offline suite --------------------------------------------------------
# CLAUDE.md: never use -k "not live"; use the marker. run_tests_fast.sh exports
# its own CI-faithful env, so do NOT source .env here.
if [ "$SKIP_SUITE" = "1" ]; then
  record offline-suite SKIP "--skip-suite passed"
elif [ -x ./run_tests_fast.sh ]; then
  if out=$(./run_tests_fast.sh 2>&1); then
    record offline-suite PASS "$(echo "$out" | grep -Eo '[0-9]+ passed[^,]*' | tail -1)"
  else
    record offline-suite FAIL "$(echo "$out" | grep -E '^(FAILED|ERROR)' | head -5 | tr '\n' ' ')"
  fi
else
  # run_tests_fast.sh is untracked, so a fresh worktree does not have it. Falling
  # back to CLAUDE.md's canonical serial command keeps wave-exit criterion 1 from
  # being vacuously satisfiable outside the main checkout.
  set -a; . ./.env 2>/dev/null; set +a
  if out=$(PSAT_LLM_STUB_DIR=tests/fixtures/scope_extraction/llm_responses \
           uv run pytest -m "not live" -q 2>&1); then
    record offline-suite PASS "serial fallback: $(echo "$out" | grep -Eo '[0-9]+ passed[^,]*' | tail -1)"
  else
    record offline-suite FAIL "serial fallback: $(echo "$out" | grep -E '^(FAILED|ERROR)' | head -5 | tr '\n' ' ')"
  fi
fi

# --- 5. frontend -------------------------------------------------------------
if [ -d site ]; then
  if out=$(cd site && npm test --silent 2>&1); then
    record frontend-vitest PASS ""
  else
    record frontend-vitest FAIL "$(echo "$out" | tail -5 | tr '\n' ' ')"
  fi
else
  record frontend-vitest SKIP "no site/"
fi

# --- 6. determinism gate (created by W0-8) -----------------------------------
# Two CLASSES. A gate covering one silently passes the other:
#   string-hash    -> pinnable by PYTHONHASHSEED   (D6 / AuthorityGraph)
#   allocation-order-> NOT pinnable by any seed    (_taint.py / Slither vars)
if [ -x scripts/witness/determinism_gate.sh ]; then
  if out=$(scripts/witness/determinism_gate.sh 2>&1); then
    record determinism PASS "$(echo "$out" | tail -1)"
  else
    record determinism FAIL "$(echo "$out" | tail -3 | tr '\n' ' ')"
  fi
elif [ "$REQUIRE_DET" = "1" ]; then
  # At Wave 0 exit the gate must FAIL, not SKIP: the haiku runner is bound to the
  # "GATE: PASS" string and is explicitly forbidden from exercising judgment, so a
  # prose note that "SKIP means FAIL here" would be unenforceable.
  record determinism FAIL "REQUIRED but scripts/witness/determinism_gate.sh is absent or not executable (W0-8)"
else
  record determinism SKIP "not yet built (W0-8) -- pass --require-determinism at Wave 0 exit to make this a FAIL"
fi

# --- 7. regression greps over the DIFF ONLY ----------------------------------
# Pre-existing occurrences are the waves' work; these catch NEW ones.
DIFF=$(git diff "$BASE"...HEAD -- '*.py' '*.js' '*.jsx' 2>/dev/null | grep '^+' | grep -v '^+++' || true)

grep_new() { # name pattern human
  if [ -z "$DIFF" ]; then record "$1" SKIP "empty diff vs $BASE"; return; fi
  hits=$(printf '%s\n' "$DIFF" | grep -nE "$2" || true)
  if [ -n "$hits" ]; then
    record "$1" FAIL "$(printf '%s' "$hits" | head -3 | tr '\n' ' ')"
  else
    record "$1" PASS ""
  fi
}

# SQL NULL != JSON null. conditions is JSON-null on 780/1773; artifacts.data on 5770/5770.
# Scoped to the actual jsonb columns; an unscoped IS NULL grep fires on correct
# SQL over ordinary columns and trains the agent to ignore the check.
grep_new no-new-jsonb-isnull   '(claims|conditions|capability_expr|authority_roles|witness|details|observed_residue|predicate_trees|analysis|tracking_plan|data|findings|scope_entries|monitoring_config|last_known_state|chain_breakdown|contract_breakdown|graph_context)[^\n]{0,40}IS +(NOT +)?NULL' "jsonb IS NOT NULL"
# Unordered picks: identity-hashed Slither vars are NOT pinned by PYTHONHASHSEED.
grep_new no-new-set-pick       'next\(iter\('                       "next(iter(...))"
# Defaults that collapse "no evidence" into a value. NARROW on purpose: bare
# `or []` / `or 0` are ubiquitous legitimate idioms (label_corpus.py uses `or []`
# four times), and a check that cries wolf gets ignored. Tier-2 review owns the
# general case; this catches only the boolean-default form.
grep_new no-new-evidence-default '\.get\([^,]+, *False\)' "evidence default (bool)"

# --- 7b. R5: witness-shape change requires a cache schema bump ----------------
# db/effect_cache.py EFFECT_CACHE_SCHEMA_VERSION. Without a bump, existing rows
# keep serving the pre-fix witness payload and the fix never reaches them --
# invisible to the suite and to the corpus.
# db/contract_materializations.py is in the list because hydrate_analysis /
# hydrate_tracking_plan / hydrate_predicate_trees ARE the analysis payload the
# probe is seeded from -- W0-1 changed all three from None to the real blob on
# 75/75 rows without touching a single services/effects/ file, and this check
# reported "witness path untouched".
WITNESS_TOUCHED=$(git diff --name-only "$BASE"...HEAD -- \
  services/effects/recipes.py services/effects/claims_bridge.py \
  services/effects/calldata.py services/effects/anvil.py \
  services/effects/simulate.py services/effects/seeding.py \
  services/effects/selection.py services/effects/orchestrator.py \
  workers/effects_worker.py db/contract_materializations.py 2>/dev/null | wc -l)
CACHE_BUMPED=$(git diff "$BASE"...HEAD -- db/effect_cache.py 2>/dev/null \
  | grep -cE '^\+EFFECT_CACHE_SCHEMA_VERSION' || true)
if [ "${WITNESS_TOUCHED:-0}" -gt 0 ] && [ "${CACHE_BUMPED:-0}" -eq 0 ]; then
  record r5-cache-version FAIL "witness path changed in ${WITNESS_TOUCHED} file(s), EFFECT_CACHE_SCHEMA_VERSION not bumped"
elif [ "${WITNESS_TOUCHED:-0}" -gt 0 ]; then
  record r5-cache-version PASS "witness path changed, version bumped"
else
  record r5-cache-version PASS "witness path untouched"
fi

# --- 8. deleted/inverted tests must be called out ----------------------------
# Four tests are known to PIN defects as correct; expect deletions. They must be
# declared, not silent.
TESTDEL=$(git diff "$BASE"...HEAD -- 'tests/*' 'site/src/**/*.test.js' 2>/dev/null \
          | grep -cE '^-\s*(def test_|it\(|test\()' || true)
if [ "${TESTDEL:-0}" -gt 0 ]; then
  MSGS=$(git log "$BASE"..HEAD --format=%B 2>/dev/null || true)
  if printf '%s' "$MSGS" | grep -qiE 'invert|delete|pins? the defect'; then
    record test-deletions-declared PASS "$TESTDEL removed, declared in a commit message"
  else
    record test-deletions-declared FAIL "$TESTDEL test(s) removed with no commit-message declaration"
  fi
else
  record test-deletions-declared PASS "none removed"
fi

# --- summary -----------------------------------------------------------------
echo
echo "=== summary ==="
printf '%s\n' "${RESULTS[@]}"
echo
if [ "$FAILED" = "1" ]; then echo "GATE: FAIL"; exit 1; fi
echo "GATE: PASS"
