# Effect-labels frozen fixture corpus + A/B golden gate

Phase-0 accuracy harness for the labels redesign (`../../LABELS_REDESIGN_SPEC.md`
§6.3): a checked-in corpus of real, Etherscan-verified contracts, run through the
**current** production static label pipeline, with a golden that CI diffs on every
change. A producer edit that silently relabels a corpus function cannot merge
unless the PR carries the regenerated, reviewed golden.

## Files

- `manifest.json` — single source of truth for corpus membership. Per contract:
  `address`, `name`, `chain`, `solc_version` (the Foundry pin the harness compiles
  against — also the exact set CI installs via solc-select), `etherscan_compiler`,
  `source_kind`, and `source_path` (relative to the repo root).
- `golden.json` — the expected `(contract, address, function, selector,
  effect_labels, claims)` tuples, sorted deterministically. `effect_labels` is
  now the projection of each function's Plane-1 claims (registry `legacy_projection`
  strings) unioned with the retained fact-tier labels; each row also pins the
  `{claim_id, tier}` of every claim.
- `harness.py` — compiles one contract (Slither →
  `build_predicate_artifacts_with_pause_info` → `build_effects` →
  `build_claims` → `project_effect_labels`) and flattens the effects artifact into
  golden rows. Compilation is pinned to the solc-select binary named by `solc_version`
  via `FOUNDRY_SOLC` + `FOUNDRY_OFFLINE=true`, so the gate is deterministic and
  makes zero network calls.
- `regenerate.py` — rewrites `golden.json` from current behavior; `--check`
  recomputes and diffs without writing (exit 1 on drift).
- `../test_label_corpus.py` — the pytest gate.

## Sources

`source_path` points into `labels_redesign/agent1/projects/<address>/` — the
scaffolded Foundry projects from the investigation (spec Appendix C). **Those
source trees must be committed** for the gate to run in CI (their `out/`/`cache/`
build dirs are git-ignored and regenerated on compile; everything else is source).

## Running

```bash
# Fast smoke subset — part of the default offline suite:
uv run pytest tests/test_label_corpus.py

# Full corpus (slow; its own CI job). Marked + env-gated so it stays out of the
# default suite:
PSAT_LABEL_CORPUS_FULL=1 uv run python -m pytest tests/test_label_corpus.py -m label_corpus

# Regenerate after an intended, reviewed producer change:
uv run python tests/label_corpus/regenerate.py
```

CI installs the manifest's `solc_version` set with solc-select, so extending the
corpus is a manifest edit + `regenerate.py` — no CI change.
