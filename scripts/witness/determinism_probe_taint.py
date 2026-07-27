"""Allocation-order determinism probe (W0-8, class B).

Runs the REAL static pipeline over the ``exec_arbitrary_binding.sol`` corpus
fixture and prints a canonical JSON payload with two halves:

``binding``
    the ``exec.arbitrary`` witness the pipeline publishes. Every run of this
    probe, under every allocation environment, must produce byte-identical
    bytes here. Variation is the defect.

``unordered_control``
    the *removed* idiom — ``next(iter(<set intersection of Slither variables>))``,
    copied verbatim from ``services/static/claims/matchers/_taint.py`` as it
    stood on ``main`` before W0-3 — recomputed live over the same IR and
    published beside the real answer. It is an instrument, never a product: the
    gate requires it to **vary** across the allocation matrix. If it stops
    varying, the matrix has lost its discriminating power and the gate says so
    instead of reporting a green it has not earned (R2 — two sentinels in this
    codebase were built, wired, and dead; this one proves itself on every run).

Why an allocation matrix and not just repeated processes: Slither's variable
classes inherit ``object.__hash__``, so set iteration follows allocation
addresses. Under pymalloc those addresses are a deterministic function of the
allocation *sequence* — pools are page-aligned, so the low bits that decide a
small set's probe order survive ASLR unchanged. Measured: the pre-W0-3 code
produced byte-identical output across 8 fresh processes at a fixed
``PYTHONHASHSEED``, with and without varied preamble parses, and this probe's
own control instrument is constant across 30 consecutive pymalloc runs.
``PYTHONMALLOC=malloc``
routes object allocation through glibc, whose addresses ASLR does move, and the
same pre-fix code then answers differently. Re-running processes is not the
knob; changing the allocator is.

Usage:
    determinism_probe_taint.py [--preamble name,name]

``--preamble`` parses other corpus fixtures first, so the target parse starts
from a different heap. Kept because it costs nothing and is the perturbation
that flipped the real ``LRTSquaredAdmin.rebalance`` pick during W0-3.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

FIXTURES = REPO / "tests" / "fixtures" / "contracts" / "claims_upgrade_exec"

TARGET = ("exec_arbitrary_binding.sol", "ExecBinding")

# Other corpus fixtures, only ever parsed to leave a heap behind.
PREAMBLE_FIXTURES: dict[str, tuple[str, str]] = {
    "boring": ("boring_vault_manage.sol", "BoringVault"),
    "safe": ("safe_wallet.sol", "SafeWallet"),
    "timelock": ("oz_timelock.sol", "TimelockController"),
    "plain": ("plain_transfer_call.sol", "PlainTransfer"),
}

# The published binding this probe refuses to lose. A gate that can be satisfied
# by emitting nothing is not a gate: if the pipeline stops proving a destination
# on the one fixture function where the destination IS provable, the comparison
# below would go green on an empty payload. See the sweepDust precedent — a
# proposal that suppressed the positive control passed every test it was shown.
ANCHOR_SIGNATURE = "singlyAssignedLocal(address,bytes)"
ANCHOR_EXPECTED = {"destination_kind": "param", "destination_param": "a"}


def _prefix_idiom_pick(taint_module: Any, ctx: Any, signature: str) -> dict[str, str] | None:
    """``_taint.arbitrary_exec_taint`` as it stood on ``main`` before W0-3.

    Verbatim, including ``next(iter(...))`` over a set of Slither variables —
    that is the whole point. Only the return shape is narrowed to the two names.
    """
    from slither.slithir.operations import HighLevelCall, LibraryCall, LowLevelCall

    function = taint_module._slither_function(ctx, signature)
    if function is None:
        return None
    parameters = getattr(function, "parameters", None) or []
    address_params = {p for p in parameters if taint_module._is_address(p)}
    bytes_params = {p for p in parameters if taint_module._is_dynamic_bytes(p)}
    if not address_params or not bytes_params:
        return None
    argument_address_params = {p for p in address_params if not taint_module._is_array(p)}

    for node in getattr(function, "nodes", None) or []:
        for ir in getattr(node, "irs", None) or []:
            if not isinstance(ir, (LowLevelCall, HighLevelCall, LibraryCall)):
                continue
            reads = {taint_module._origin(v) for v in getattr(ir, "read", None) or []}
            destination = taint_module._origin(getattr(ir, "destination", None))
            dest_tainted = destination in address_params or bool(reads & argument_address_params)
            data_tainted = bool(reads & bytes_params)
            if dest_tainted and data_tainted:
                dest_param = next((p for p in address_params if p is destination), None) or next(
                    iter(reads & argument_address_params), None
                )
                data_param = next(iter(reads & bytes_params), None)
                return {
                    "destination_param": getattr(dest_param, "name", "") or "",
                    "calldata_param": getattr(data_param, "name", "") or "",
                }
    return None


def _install_control(sink: dict[str, dict[str, str]]) -> None:
    """Wrap the matcher's taint entry so each call also records the old pick."""
    from services.static.claims.matchers import _taint as taint_module
    from services.static.claims.matchers import exec_arbitrary as exec_module

    real = taint_module.arbitrary_exec_taint

    def wrapper(ctx: Any, signature: str) -> Any:
        try:
            old = _prefix_idiom_pick(taint_module, ctx, signature)
        except Exception as exc:  # instrument failure must be visible, not silent
            old = {"error": type(exc).__name__}
        if old is not None:
            sink[signature] = old
        return real(ctx, signature)

    # exec_arbitrary.py binds the name at import time, so patching the defining
    # module alone would leave the live call site untouched.
    exec_module.arbitrary_exec_taint = wrapper


def _run(fixture: str, contract: str) -> Mapping[str, Any]:
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
    from tests.support.foundry_project import write_foundry_project

    source = (FIXTURES / fixture).read_text()
    with tempfile.TemporaryDirectory() as tmp:
        project = write_foundry_project(Path(tmp), contract, source)
        _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project)
    return effects or {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preamble", default="")
    args = parser.parse_args()

    control: dict[str, dict[str, str]] = {}
    _install_control(control)

    for key in [k for k in args.preamble.split(",") if k]:
        _run(*PREAMBLE_FIXTURES[key])
    control.clear()  # only the target parse is compared

    effects = _run(*TARGET)
    binding: dict[str, Any] = {}
    for signature, record in (effects.get("functions") or {}).items():
        for claim in record.get("claims") or []:
            if claim.get("claim_id") == "exec.arbitrary":
                binding[signature] = claim.get("witness")

    if not binding:
        print(
            "EMPTY WORKLOAD: no exec.arbitrary claim minted on the binding fixture. "
            "An empty payload is byte-identical under every allocator and proves nothing.",
            file=sys.stderr,
        )
        return 3

    # Exit 4, not 3: the payload is still printed and still worth comparing. A
    # lost anchor is a separate fact from a varying binding, and the gate reports
    # both rather than letting the first hide the second.
    anchor = binding.get(ANCHOR_SIGNATURE) or {}
    violation = next(
        (
            f"ANCHOR LOST: {ANCHOR_SIGNATURE}.{field} = {anchor.get(field)!r}, expected {expected!r}"
            for field, expected in ANCHOR_EXPECTED.items()
            if anchor.get(field) != expected
        ),
        None,
    )

    print(
        json.dumps(
            {"binding": binding, "unordered_control": control, "anchor_violation": violation},
            sort_keys=True,
            indent=1,
        )
    )
    if violation:
        print(violation, file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
