# Labels redesign — investigation artifacts

Evidence base for `../LABELS_REDESIGN_SPEC.md` (the design spec produced by the
2026-07-03 two-agent investigation per `../LABELS_REDESIGN_HANDOFF.md`). Everything here
was produced read-only against `main` @ `90d8774`; nothing under this directory is imported
by production code. The per-contract source scaffolds double as the seed for the frozen
fixture corpus required by the spec's anti-creep gate (§6.3).

## Layout

- `agent_outputs/` — the two investigators' full structured outputs, one file per schema
  field (`evidenceFirst.*` = evidence-first prior, `cleanSlate.*` = clean-slate prior),
  plus `result.json` (both outputs, raw). The spec's §2/§4/§5 tables are synthesized from
  these; consult them for per-hypothesis hard-case detail that the spec summarizes.
- `agent1/` — evidence-first investigator (21-contract sample):
  - `run_pipeline.py` — in-process runner of the exact static sequence
    (Slither → `build_predicate_artifacts_with_pause_info` → `build_effects` →
    `apply_authority_effect_labels`); dumps per-function labels + internals per contract.
  - `prototype_h1.py` / `prototype_h1_v2_patch.py` — the H1-derivation prototypes
    (v2 adds the four pause fixes incl. the struct member-path derivation verified in
    spec §8 D1).
  - `runs/` — current-code baseline label output per contract;
    `h1_results/` / `h1v2_results/` — prototype output (v1/v2);
    `targets_batch*.json` — the contract sample; `prod_ef_rows.psv` — prod
    `effective_functions` label-row dump used for corpus-scale numbers.
  - `projects/<address>/` — Foundry scaffolds of the fetched verified sources
    (`src/`, `etherscan_standard_input.json`, `contract_meta.json`; solc `out/`/`cache/`
    stripped — recompile reproduces them).
- `agent2/` — clean-slate investigator (27-contract sample):
  - `harness.py` — same in-process runner, one contract per invocation
    (`harness.py <address> <ContractName> [chain_prefix]`), results in `runs/`.
  - `score_labels.py` — per-function ground-truth grading (the auditable verdicts behind
    the accuracy table); `control_labels_*.txt`, `value_labels.txt` — grading worksheets.
  - `h1sim.py` → `h1/` (unguarded) and `h1g/` (`is_constant`-guarded) — the measurement
    that killed tree-only ownership on OZ v5 (spec §8 D2).
  - `h3sim.py` — the standards/idiom gate matcher (154/415 exact claims, 0 observed FPs);
    its 18 matchers are the seed of the spec's claim registry.
  - `derive_sim.py` — the naive facts-only lane derivation (the H2 starvation lower bound).
  - `crytic-export/` — fetched verified sources (crytic-compile cache; re-runs hit this
    cache, no API key needed for these contracts).

## Re-running

From the repo root, with the offline-test services up (scripts import repo modules;
they set a dead `DATABASE_URL` so nothing touches a database):

```bash
uv run python labels_redesign/agent2/harness.py 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 WETH9
uv run python labels_redesign/agent1/run_pipeline.py   # batch mode over targets_batch*.json
```

Fetching a contract not already cached needs `ETHERSCAN_API_KEY` from `.env`. The prod
queries behind `prod_ef_rows.psv` need the fly-derived `DATABASE_URL` (see
`reference_prod_data_access`); the credential files were deliberately **not** copied here.

Outputs are deterministic given the same Slither version (`uv.lock`); label diffs against
`runs/` are the manual precursor of the CI A/B gate the spec specifies.
