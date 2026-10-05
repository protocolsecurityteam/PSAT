"""Allocation-order determinism probe (class B).

Runs the real static pipeline over ``exec_arbitrary_binding.sol`` and prints:

``binding``
    the published ``exec.arbitrary`` witness; must be byte-identical across the allocation matrix.

``unordered_control``
    the removed ``next(iter(<set of Slither variables>))`` idiom (verbatim from pre-fix ``_taint.py``), which must vary,
or the matrix has lost its power.

Why an allocation matrix: Slither variables hash by address. Under pymalloc, addresses follow the allocation sequence
and the low bits survive ASLR, so repeated processes agree (measured). ``PYTHONMALLOC=malloc`` routes through glibc,
which ASLR moves.

Usage:
    determinism_probe_taint.py [--preamble name,name]

``--preamble`` parses other fixtures first to perturb the heap; it once flipped the real ``LRTSquaredAdmin.rebalance``
pick.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

FIXTURES = REPO / "tests" / "fixtures" / "contracts" / "claims_upgrade_exec"

TARGET = ("exec_arbitrary_binding.sol", "ExecBinding")

PREAMBLE_FIXTURES: dict[str, tuple[str, str]] = {
    "boring": ("boring_vault_manage.sol", "BoringVault"),
    "safe": ("../authorization/generic_quorum_wallet.sol", "GenericQuorumWallet"),
    "timelock": ("oz_timelock.sol", "TimelockController"),
    "plain": ("plain_transfer_call.sol", "PlainTransfer"),
}

# Positive control: without it, an empty payload passes. A proposal resolving every binding to ``not_determined`` once
# passed the whole suite.
ANCHOR_SIGNATURE = "singlyAssignedLocal(address,bytes)"
ANCHOR_EXPECTED = {"destination_kind": "param", "destination_param": "a"}


def _prefix_idiom_pick(taint_module: Any, ctx: Any, signature: str) -> dict[str, str] | None:
    """``_taint.arbitrary_exec_taint`` before the fix, verbatim."""
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

    # exec_arbitrary.py binds the name at import time.
    exec_module.arbitrary_exec_taint = wrapper


def _run(fixture: str, contract: str) -> Mapping[str, Any]:
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
    from tests.support.foundry_project import write_foundry_project

    source = (FIXTURES / fixture).read_text()
    with tempfile.TemporaryDirectory() as tmp:
        project = write_foundry_project(Path(tmp), contract, source)
        _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project)
    return effects or {}


def _suppressions(fixture: str, contract: str) -> dict[str, Any]:
    """Fragments that resolved a proven-absent destination (``state_var``), so no claim was minted.

    Published because this is now the only place the fact is observable.
    """
    from slither import Slither

    from services.static.claims.context import ClaimContext
    from services.static.claims.matchers._taint import arbitrary_exec_taint
    from services.static.contract_analysis_pipeline.effects import build_effects
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract
    from tests.support.foundry_project import write_foundry_project

    source = (FIXTURES / fixture).read_text()
    with tempfile.TemporaryDirectory() as tmp:
        project = write_foundry_project(Path(tmp), contract, source)
        subject = _select_subject_contract(Slither(str(project)), contract)
        if subject is None:
            return {}
        ctx = ClaimContext(subject, build_effects(subject), {})
        out: dict[str, Any] = {}
        for signature in ctx.function_signatures():
            fragment = arbitrary_exec_taint(ctx, signature)
            if fragment is not None and fragment["destination_kind"] == "state_var":
                out[signature] = fragment
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preamble", default="")
    args = parser.parse_args()

    from utils import claim_ids as C
    from utils.logging import configure_logging

    # So library logs go through the JSON handler rather than lastResort (WARNING-only, unscrubbed).
    configure_logging()

    control: dict[str, dict[str, str]] = {}
    _install_control(control)

    for key in [k for k in args.preamble.split(",") if k]:
        _run(*PREAMBLE_FIXTURES[key])
    control.clear()  # only the target parse is compared

    effects = _run(*TARGET)
    binding: dict[str, Any] = {}
    for signature, record in (effects.get("functions") or {}).items():
        for claim in record.get("claims") or []:
            if claim.get("claim_id") == C.EXEC_ARBITRARY:
                binding[signature] = claim.get("witness")

    if not binding:
        print(
            "EMPTY WORKLOAD: no exec.arbitrary claim minted on the binding fixture. "
            "An empty payload is byte-identical under every allocator and proves nothing.",
            file=sys.stderr,
        )
        return 3

    # A lost anchor is separate from a varying binding; report both.
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
            {
                "binding": binding,
                "suppressed_state_var": _suppressions(*TARGET),
                "unordered_control": control,
                "anchor_violation": violation,
            },
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
