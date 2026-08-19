"""Regression: cross-contract inlining of ``canCall`` must NOT preempt the
Solmate adapter when the inlined delegated check can't be materialized.

PR #104 wired ``SolmateRolesAuthorityAdapter`` into the ``external_set``
dispatch in ``predicate_evaluator.py`` (line 317), but
``_maybe_inline_cross_contract_call`` runs first (line 312-316). For a Solmate-
protected contract analyzed alongside its ``RolesAuthority``, inlining the
authority's own ``canCall`` produces an ``external_check_only`` that the
generic materializer can't satisfy — ``canCall`` is a role-mapping join, not
expressible from event candidates. The pre-fix code returned an
``external_check_only`` dead-end (``basis=["delegated_check_not_materialized"]``)
from that branch, which is non-None — so the caller short-circuited at line
313 and the Solmate adapter at line 317 was never reached. Empirically: zero
adapter activations across an entire complete run with 15 RolesAuthority +
52 ``canCall``-protected Veda contracts analyzed.

``test_solmate_end_to_end.py`` doesn't catch this because it doesn't seed a
``Job`` / ``Artifact`` for the RolesAuthority — so the inline function's
session-lookup short-circuits and the adapter wins by default. This test
drives ``_maybe_inline_cross_contract_call`` into the materialize-fail branch
(via monkeypatched lookups + a materializer that returns ``None``) and asserts
the function now returns ``None``, so the caller's ``external_set`` adapter
dispatch will run instead of being preempted.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import db.queue as DQ  # noqa: E402
from services.resolution import capability_resolver as CR  # noqa: E402
from services.resolution import predicate_evaluator as PE  # noqa: E402

_TELLER = "0x" + "11" * 20
_ROLES_AUTH = "0x" + "a2" * 20
_JOB_ID = "00000000-0000-0000-0000-000000000001"


def _callee_artifact_with_unmaterializable_cancall() -> dict:
    """A ``canCall`` tree the resolver evaluates to ``external_check_only``.

    The LEAF wraps an ``external_set`` descriptor with a callee signature no
    adapter handles — so the dispatch at predicate_evaluator.py:317 falls
    through to ``_external_check_from_descriptor`` → ``external_check_only``.
    ``_inline_result_needs_materialization(external_check_only) == True``
    (line 1163-1164), so the materializer is invoked next. Stubbing it to
    ``None`` is what trips the branch this test guards.
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
    """Pre-fix this returned an ``external_check_only`` dead-end (preempting
    the Solmate adapter); post-fix it returns ``None`` so the adapter runs."""
    fake_job = SimpleNamespace(id=_JOB_ID, address=_ROLES_AUTH)
    fake_lookup = SimpleNamespace(analysis_job=fake_job, runtime_job=fake_job)

    monkeypatch.setattr(CR, "find_analysis_job_for_address", lambda *a, **k: fake_lookup)
    monkeypatch.setattr(DQ, "get_artifact", lambda *a, **k: _callee_artifact_with_unmaterializable_cancall())
    monkeypatch.setattr(CR, "_load_state_var_values", lambda *a, **k: {})

    # The trigger: generic materializer can't satisfy ``canCall``'s role-mapping
    # join. Pre-fix the surrounding function dead-ends with
    # ``delegated_check_not_materialized``; post-fix it returns ``None``.
    monkeypatch.setattr(PE, "_materialize_external_check_from_candidates", lambda **_: None)

    descriptor = {
        "kind": "external_set",
        "callee_signature": "canCall(address,address,bytes4)",
        "authority_contract": {
            "address_source": {"source": "state_variable", "state_variable_name": "authority"},
        },
    }
    leaf = {"kind": "membership", "set_descriptor": descriptor}

    # Outer ctx exposes the inlining preconditions (session truthy, state-var
    # resolves the authority address) plus the fields ``child_outer``
    # construction at line 1111-1126 reads directly.
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

    # Intentional duck-typing: the function uses ``.get`` on the leaf/descriptor
    # dicts and ``getattr`` on the ctx, so passing plain dicts + a SimpleNamespace
    # exercises the production code paths without instantiating the real
    # ``LeafPredicate`` / ``SetDescriptor`` / ``EvaluationContext`` classes.
    result = PE._maybe_inline_cross_contract_call(leaf, descriptor, ctx)  # pyright: ignore[reportArgumentType]
    assert result is None, (
        "Inlining must return None when the delegated check can't be materialized, "
        "so the caller's external_set adapter dispatch gets a turn "
        "(SolmateRolesAuthorityAdapter folds canCall from indexed role events). "
        f"Got: kind={getattr(result, 'kind', None)} — would preempt the adapter "
        "for every Solmate-protected contract in a complete run."
    )
