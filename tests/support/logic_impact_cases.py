"""Build a small labeled development set on local Anvil; this is not a corpus benchmark."""

from __future__ import annotations

import json
from pathlib import Path

from services.logic.formula import compile_function
from services.logic.model import encode
from services.logic.source_context import build_bundle, build_context
from services.resolution.logic_selection import selection_report
from tests.logic import _oracle as O
from tests.support.anvil import _start_anvil, _terminate

SOURCE = Path(__file__).parents[1] / "fixtures" / "contracts" / "logic_impact_vault.sol"
CASES = {
    "deposit": (0, 1, "Funding and new credits match in the same atomic operation."),
    "withdrawOwn": (0, 1, "The caller's own credit is debited before paying the caller."),
    "seize": (3, 3, "Owner can redirect the vault's entire balance without debiting user claims."),
    "issue": (3, 3, "Owner can create arbitrary redeemable credits without funding them."),
    "nominate": (3, 3, "Owner can transfer root authority over shared vault assets."),
    "halt": (3, 3, "Owner alone can sustain a block on user withdrawals indefinitely."),
    "boundedFee": (0, 1, "Fee is bounded to 10/10000 of a withdrawal; the cap is not caller-changeable."),
    "changeCaption": (0, 1, "In the supplied system the string is only returned by its public getter."),
}


def build(directory: Path, *, source: str | None = None, cases: dict | None = None) -> tuple[dict, dict, list]:
    cases = CASES if cases is None else cases
    directory.mkdir(parents=True, exist_ok=True)
    proc, port = _start_anvil()
    try:
        d = O.deployment(f"http://127.0.0.1:{port}", directory, source if source is not None else SOURCE.read_text())
        d.deploy("ImpactVault")
        assert O.transact(d, "ImpactVault", "deposit()", sender=O.ACCOUNTS[1], value=10**18)
        reads, contracts = d.chain(), d.contracts("ImpactVault")
        formulas, contexts, expected = {}, {}, []
        bundle = build_bundle(contracts)
        for fn in d.slither["ImpactVault"].functions_entry_points:
            if fn.name not in cases:
                continue
            f = compile_function(d.slither["ImpactVault"], fn, d.at["ImpactVault"], reads, contracts)
            formulas[f.signature] = encode(f)
            contexts[f.signature] = build_context(f, fn, bundle)
            low, high, rationale = cases[fn.name]
            expected.append(
                {
                    "function": f.signature,
                    "expected_min": low,
                    "expected_max": high,
                    "rationale": rationale,
                }
            )
        artifact = {
            "schema": 2,
            "kind": "formulas",
            "chain_id": 31337,
            "address": O.hex20(d.at["ImpactVault"]),
            "block": reads.block,
            "functions": formulas,
            "contexts": contexts,
            "source_bundle": bundle,
        }
        report = selection_report(artifact, reads=reads, contracts=contracts)
        for filename, value in (("formulas.json", artifact), ("selection.json", report), ("expected.json", expected)):
            (directory / filename).write_text(json.dumps(value, indent=2) + "\n")
        return artifact, report, expected
    finally:
        _terminate(proc)
