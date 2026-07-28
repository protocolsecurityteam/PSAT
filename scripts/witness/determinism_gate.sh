#!/usr/bin/env bash
# The determinism gate — BOTH classes.
#
# Two different defects wear the same word, and a gate covering one silently
# passes the other:
#
#   class A  string-hash      set[str] iteration           PINNABLE by PYTHONHASHSEED
#            (AuthorityGraph.reachable_value)
#   class B  allocation-order object.__hash__ on Slither   NOT pinnable by ANY seed
#            (_taint.py binding)  variables -> id()
#
# Each check below names the class it covers. A check that cannot name its class
# is not evidence about determinism, it is evidence about one workload.
#
# MEASURED, and the reason this script is not the obvious one: the obvious check
# for class B — "3 fresh processes at a fixed seed -> byte-identical output" —
# does not discriminate. Run against the pre-fix `_taint.py`, eight fresh
# processes at PYTHONHASHSEED=0, with and without varied preamble parses,
# produced BYTE-IDENTICAL output while the published binding was wrong on two of
# the twelve functions (`compose` named `from`, a source, as its destination;
# `rebalance` named `fromAsset` when the destination is a storage variable and no
# parameter is the destination at all). Under pymalloc an object's address is a
# deterministic function of the allocation sequence; pools are page-aligned, so
# the low bits that decide a small set's probe order survive ASLR unchanged.
# `PYTHONMALLOC=malloc` routes allocation through glibc, whose addresses ASLR does
# move, and the same pre-fix code then answers differently (`compose` calldata
# `extra` -> `message`, `rebalance` destination `fromAsset` -> `toAsset`). The
# allocator, not the repetition, is the knob. The three plain repeats are still
# run — they cost nothing — but they are reported as what they are.
#
# Both probes publish an `unordered_control`: the removed idiom, recomputed live
# over the same real data. The gate requires it to VARY. A control is only
# evidence while it still discriminates, so that is enforced continuously rather
# than once at commit time — a sweep whose control has gone constant has lost its
# discriminating power, and this script fails rather than reporting a green it
# did not earn.
#
# Neither probe may be satisfied by an empty answer. Each carries an ANCHOR it
# refuses to lose: `sweepDust` (function_id 2771, $4,024,163,604.46, inside the
# 84-member tied cluster) for class A, `singlyAssignedLocal`'s PROVED
# `destination_param: "a"` for class B. Suppression is the failure mode that got
# past every test the last time: a proposal that resolved every binding to
# `not_determined` passed the whole suite while erasing the positive control. See
# tests/test_determinism_gate.py::test_the_proved_binding_is_present_and_not_hedged.
#
# Usage: scripts/witness/determinism_gate.sh [--quick]
#   --quick  4 seeds instead of 8 (local iteration only; not a gating run)

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

SEEDS=(0 1 2 3 4 5 6 7)
[ "${1:-}" = "--quick" ] && SEEDS=(0 1 2 3)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The class-A workload is the real corpus database, so DATABASE_URL is required.
# Reading .env, never writing it.
if [ -z "${DATABASE_URL:-}" ] && [ -f ./.env ]; then
  set -a; . ./.env; set +a
fi

FAILED=0
say() { printf '%-42s %-6s %s\n' "$1" "$2" "${3:-}"; [ "$2" = "FAIL" ] && FAILED=1; return 0; }

echo "=== determinism gate ==="
echo

# ---------------------------------------------------------------------------
# CLASS A -- string-hash. Pinnable by PYTHONHASHSEED, so sweep the seed.
# Workload: the real candidate queue over the corpus DB (protocol 1).
# ---------------------------------------------------------------------------
echo "--- class A: string-hash (set[str] iteration; PYTHONHASHSEED-pinnable) ---"
a_ok=1
for seed in "${SEEDS[@]}"; do
  PYTHONHASHSEED="$seed" uv run python scripts/witness/determinism_probe_selection.py \
      >"$WORK/a_$seed.json" 2>"$WORK/a_$seed.err"
  rc=$?
  # 4 = anchor violated but the payload is intact and still worth comparing.
  case "$rc" in
    0) ;;
    4) say "A0 anchor held (seed=$seed)" FAIL "$(tail -1 "$WORK/a_$seed.err" | tr '\n' ' ')" ;;
    *) say "class-A probe seed=$seed" FAIL "$(tail -2 "$WORK/a_$seed.err" | tr '\n' ' ')"; a_ok=0 ;;
  esac
done

if [ "$a_ok" = "1" ]; then
  # The queue+anchor half must be constant; the control half must not be.
  readarray -t a_split < <(
    uv run python - "$WORK" "${SEEDS[@]}" <<'PY'
import hashlib, json, sys
work, seeds = sys.argv[1], sys.argv[2:]
queue, control = set(), set()
for s in seeds:
    d = json.load(open(f"{work}/a_{s}.json"))
    # The anchor's RANK is part of the ordering under test; its violation text is
    # reported by A0 and would only double-count here.
    queue.add(
        hashlib.sha256(json.dumps({"rank": d["anchor"]["rank"], "q": d["queue"]}, sort_keys=True).encode()).hexdigest()
    )
    control.add(hashlib.sha256(json.dumps(d["unordered_control"], sort_keys=True).encode()).hexdigest())
print(len(queue)); print(len(control)); print(json.load(open(f"{work}/a_{seeds[0]}.json"))["anchor"]["rank"])
PY
  )
  n_queue=${a_split[0]:-0}; n_control=${a_split[1]:-0}; anchor_rank=${a_split[2]:-?}
  if [ "$n_queue" = "1" ]; then
    say "A1 queue identical across ${#SEEDS[@]} seeds" PASS "anchor sweepDust at rank $anchor_rank"
  else
    say "A1 queue identical across ${#SEEDS[@]} seeds" FAIL "$n_queue distinct payloads"
  fi
  if [ "${n_control:-0}" -gt 1 ]; then
    say "A2 sweep still discriminates" PASS "removed float fold gives $n_control distinct payloads"
  else
    say "A2 sweep still discriminates" FAIL "control is CONSTANT across seeds -- this sweep proves nothing"
  fi
fi
echo

# ---------------------------------------------------------------------------
# CLASS B -- allocation-order. NOT pinnable by any seed, so vary the allocator.
# Workload: the real static pipeline over exec_arbitrary_binding.sol.
# The seed is held FIXED throughout: this class is not about the seed.
# ---------------------------------------------------------------------------
echo "--- class B: allocation-order (object.__hash__ -> id(); NO seed pins it) ---"
# 3 plain repeats (the obvious check) + the allocator dimension
# that actually moves identity hashes + a preamble that changes heap history.
#
# Sizing is measured, not guessed. Consecutive runs of each column at a fixed
# seed over the same workload, counting distinct `unordered_control` payloads:
#   pymalloc  1 distinct / 30, and 1 / 20 in an earlier session   (inert)
#   malloc    2 distinct / 30, and 4 / 20 in an earlier session
# The malloc distribution shifts between sessions; in one of them its most common
# value coincided with pymalloc's on 7 runs of 20. Taking p≈0.35 as the
# conservative chance that a single malloc run agrees, eight of them agree
# together with p≈2e-4. The miss is fail-CLOSED regardless: if every malloc run
# happened to agree, B2 sees a constant control and FAILS the gate rather than
# passing it.
B_CONFIGS=(
  "pymalloc|"
  "pymalloc|"
  "pymalloc|"
  "pymalloc|boring,safe"
  "malloc|"
  "malloc|"
  "malloc|"
  "malloc|"
  "malloc|boring"
  "malloc|safe"
  "malloc|plain"
  "malloc|safe,boring,timelock"
)
b_ok=1
i=0
for cfg in "${B_CONFIGS[@]}"; do
  alloc=${cfg%%|*}; pre=${cfg#*|}
  PYTHONMALLOC="$alloc" PYTHONHASHSEED=0 \
      uv run python scripts/witness/determinism_probe_taint.py --preamble "$pre" \
      >"$WORK/b_$i.json" 2>"$WORK/b_$i.err"
  rc=$?
  case "$rc" in
    0) ;;
    4) say "B0 anchor held [$alloc|$pre]" FAIL "$(tail -1 "$WORK/b_$i.err" | tr '\n' ' ')" ;;
    *) say "class-B probe [$alloc|$pre]" FAIL "$(tail -2 "$WORK/b_$i.err" | tr '\n' ' ')"; b_ok=0 ;;
  esac
  i=$((i + 1))
done

if [ "$b_ok" = "1" ]; then
  readarray -t b_split < <(
    uv run python - "$WORK" "$i" <<'PY'
import hashlib, json, sys
work, n = sys.argv[1], int(sys.argv[2])
binding, control, plain = set(), set(), set()
for k in range(n):
    d = json.load(open(f"{work}/b_{k}.json"))
    binding.add(hashlib.sha256(json.dumps(d["binding"], sort_keys=True).encode()).hexdigest())
    h = hashlib.sha256(json.dumps(d["unordered_control"], sort_keys=True).encode()).hexdigest()
    control.add(h)
    if k < 3:  # the three plain repeats, reported separately
        plain.add(h)
print(len(binding)); print(len(control)); print(len(plain))
PY
  )
  n_bind=${b_split[0]:-0}; n_ctl=${b_split[1]:-0}; n_plain=${b_split[2]:-0}
  if [ "$n_bind" = "1" ]; then
    say "B1 binding identical across $i allocation envs" PASS "anchor singlyAssignedLocal -> param/a"
  else
    say "B1 binding identical across $i allocation envs" FAIL "$n_bind distinct payloads"
  fi
  if [ "${n_ctl:-0}" -gt 1 ]; then
    say "B2 matrix still discriminates" PASS "removed next(iter(set)) pick gives $n_ctl distinct payloads"
  else
    say "B2 matrix still discriminates" FAIL "control is CONSTANT -- this matrix cannot see class B at all"
  fi
  # Not a pass/fail. It is the measurement that justifies the allocator column,
  # and it is printed on every run so nobody re-derives it from first principles.
  say "B3 plain repeats alone (3x, fixed seed)" INFO "$n_plain distinct control payloads (1 in 30 consecutive runs; it does drift when __pycache__ is cold) -- the obvious check, and on its own it cannot be relied on to see class B"
fi
echo

if [ "$FAILED" = "1" ]; then echo "DETERMINISM GATE: FAIL"; exit 1; fi
echo "DETERMINISM GATE: PASS (class A string-hash + class B allocation-order)"
