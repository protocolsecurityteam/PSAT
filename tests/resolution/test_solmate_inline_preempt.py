"""Inlining a RolesAuthority's own ``canCall`` must not preempt the Solmate adapter when the delegated check can't
be materialized. The inline runs first and produced an ``external_check_only`` dead-end, giving zero adapter
activations across 15 RolesAuthority + 52 Veda contracts. ``test_solmate_end_to_end.py`` misses this because
it seeds no Job/Artifact for the authority.
"""

from __future__ import annotations

from types import SimpleNamespace

import db.queue as DQ
from services.resolution import capability_resolver as CR
from services.resolution.predicate_evaluator import core as PE

_TELLER = "0x" + "11" * 20
_ROLES_AUTH = "0x" + "a2" * 20
_JOB_ID = "00000000-0000-0000-0000-000000000001"


def _callee_artifact_with_unmaterializable_cancall() -> dict:
    """The callee signature matches no adapter, so dispatch falls to ``external_check_only``, which needs
    materialization.
    """
    return {
        "schema_version": "semantic",
        "trees": {
            "canCall(address,address,bytes4)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "set_descriptor": {
                        "kind": "external_set",
                        "callee_signature": "unhandledMappingCheck(bytes32)",
                    },
                },
            },
        },
    }


def test_inline_returns_none_when_materialization_fails(monkeypatch):
    fake_job = SimpleNamespace(id=_JOB_ID, address=_ROLES_AUTH)
    fake_lookup = SimpleNamespace(analysis_job=fake_job, runtime_job=fake_job)

    monkeypatch.setattr(CR, "find_analysis_job_for_address", lambda *a, **k: fake_lookup)
    monkeypatch.setattr(DQ, "get_artifact", lambda *a, **k: _callee_artifact_with_unmaterializable_cancall())
    monkeypatch.setattr(CR, "_load_state_var_values", lambda *a, **k: {})

    monkeypatch.setattr(PE, "_materialize_external_check_from_candidates", lambda **_: None)

    descriptor = {
        "kind": "external_set",
        "callee_signature": "canCall(address,address,bytes4)",
        "authority_contract": {
            "address_source": {"source": "state_variable", "state_variable_name": "authority"},
        },
    }
    leaf = {"kind": "membership", "set_descriptor": descriptor}

    outer = SimpleNamespace(
        chain_id=1,
        state_var_values={"authority": _ROLES_AUTH},
        evaluation_stack=set(),
        session=object(),
        contract_address=_TELLER,
        block=None,
        rpc_url=None,
        finality_depth=12,
        event_log_repo=None,
        bytecode=None,
        recursive_resolver=None,
        meta={},
        call_frame=None,
    )
    ctx = SimpleNamespace(adapter=SimpleNamespace(_outer_ctx=outer))

    result = PE._maybe_inline_cross_contract_call(leaf, descriptor, ctx)  # pyright: ignore[reportArgumentType]
    assert result is None, (
        "Inlining must return None when the delegated check can't be materialized, "
        "so the caller's external_set adapter dispatch gets a turn "
        "(SolmateRolesAuthorityAdapter folds canCall from indexed role events). "
        f"Got: kind={getattr(result, 'kind', None)} — would preempt the adapter "
        "for every Solmate-protected contract in a complete run."
    )
