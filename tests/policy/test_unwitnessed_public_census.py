"""Pin the unwitnessed-public census population definition.

``status='public' AND jsonb_typeof(conditions)='null'`` selects exactly the
fall-through public population (351 rows on the production-shaped local DB) —
but that shape was incidental: nothing enforced it and any refactor giving an
unwitnessed function an empty ARRAY instead of JSON null would break the
census silently. These tests make the shape a contract:

* a fall-through public row (no capability, no tree, sink-bearing) persists
  ``conditions`` as JSON null — never ``[]``;
* a witnessed public row whose capability carries real conditions persists the
  non-empty array (so the census predicate excludes it).
"""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy import text

from db.models import Contract
from services.policy.permission_index import build_permission_index
from services.policy.permission_index_writer import write_permission_rows
from tests.conftest import requires_postgres
from tests.support.policy_builders import resolved_records

_TARGET = {"subject": {"address": "0x" + "ce" * 20, "name": "CensusTarget"}}


def _effects(signature: str) -> dict:
    return {
        "functions": {
            signature: {
                "function": signature,
                "state_changing": True,
                "state_writes": [],
                "sinks": [{"kind": "external_call", "target": "token.transfer"}],
                "writer_selectors": [],
            }
        }
    }


def _conditions_typeof(session, contract_id: int, function_name: str) -> str | None:
    row = session.execute(
        text(
            "select jsonb_typeof(conditions) from effective_functions where contract_id = :cid and function_name = :fn"
        ),
        {"cid": contract_id, "fn": function_name},
    ).first()
    assert row is not None
    return row[0]


@requires_postgres
def test_fall_through_public_persists_json_null_conditions_never_empty_array(db_session):
    contract = Contract(address=_TARGET["subject"]["address"], chain="ethereum")
    db_session.add(contract)
    db_session.flush()

    payload = build_permission_index(
        _TARGET,
        capability_resolver_output={},
        effects=_effects("sweep(address)"),
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )
    fn = next(f for f in payload["functions"] if f["function"] == "sweep(address)")
    assert fn.get("status") == "public"

    write_permission_rows(
        db_session,
        contract_id=contract.id,
        function_records=cast("list[dict[str, Any]]", payload["functions"]),
    )
    db_session.flush()
    assert _conditions_typeof(db_session, contract.id, "sweep") == "null"


@requires_postgres
def test_witnessed_public_with_conditions_persists_the_array(db_session):
    contract = Contract(address=_TARGET["subject"]["address"], chain="ethereum")
    db_session.add(contract)
    db_session.flush()

    capability = {
        "kind": "conditional_universal",
        "conditions": [{"kind": "time", "description": "after cooldown"}],
        "membership_quality": "exact",
        "confidence": "enumerable",
    }
    payload = build_permission_index(
        _TARGET,
        capability_resolver_output={"sweep(address)": capability},
        effects=_effects("sweep(address)"),
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )
    write_permission_rows(
        db_session,
        contract_id=contract.id,
        function_records=resolved_records(
            cast("list[dict[str, Any]]", payload["functions"]), {"sweep(address)": capability}
        ),
    )
    db_session.flush()
    assert _conditions_typeof(db_session, contract.id, "sweep") == "array"


@requires_postgres
def test_policy_minted_rows_carry_openness_and_roles_on_the_production_path(db_session):
    """Every row the POLICY layer mints (the fall-through publics, the
    assembly fail-closed rows, the ``guard_extraction_uncertain``
    reroute) must reach the table with ``authority_openness`` and
    ``authority_roles`` PROJECTED FROM the capability_expr the row itself
    publishes — never the NULL that is documented as "written before the
    column existed". Exercises the real path: ``build_permission_index``
    → ``write_permission_rows`` with an EMPTY resolver output, which
    is exactly the branch that dropped the answers.

    Input-shape → published-state table this test pins:

      fall-through public   → openness 'open',           roles ``[]`` (proven absent)
      assembly fail-closed  → openness 'not_determined', roles ``None``
      guard-uncertain reroute → openness 'not_determined', roles ``None``
    """
    contract = Contract(address="0x" + "cf" * 20, chain="ethereum")
    db_session.add(contract)
    db_session.flush()

    effects = {
        "functions": {
            "sweep(address)": {
                "function": "sweep(address)",
                "state_changing": True,
                "state_writes": [],
                "sinks": [{"kind": "external_call", "target": "token.transfer"}],
                "writer_selectors": [],
            },
            "asmMutator()": {
                "function": "asmMutator()",
                "state_changing": True,
                "state_writes": [],
                "sinks": [],
                "assembly_state_access": True,
                "writer_selectors": [],
            },
            "gated(address)": {
                "function": "gated(address)",
                "state_changing": True,
                "state_writes": [],
                "sinks": [{"kind": "external_call", "target": "t"}],
                "writer_selectors": [],
            },
        }
    }
    payload = build_permission_index(
        _TARGET,
        capability_resolver_output={},
        effects=effects,
        predicate_trees={
            "schema_version": "semantic",
            "trees": {},
            "guard_extraction_uncertain": ["gated(address)"],
        },
    )
    write_permission_rows(
        db_session,
        contract_id=contract.id,
        function_records=cast("list[dict[str, Any]]", payload["functions"]),
    )
    db_session.flush()
    rows = {
        name: (status, openness, roles)
        for name, status, openness, roles in db_session.execute(
            text(
                "select function_name, status, authority_openness, authority_roles"
                " from effective_functions where contract_id = :cid"
            ),
            {"cid": contract.id},
        ).all()
    }
    assert rows["sweep"] == ("public", "open", [])
    assert rows["asmMutator"] == ("unsupported", "not_determined", None)
    assert rows["gated"] == ("unsupported", "not_determined", None)
    # The census predicate itself is unaffected: openness rides alongside,
    # conditions stays JSON null on the fall-through public.
    assert _conditions_typeof(db_session, contract.id, "sweep") == "null"


@requires_postgres
def test_rewrite_retracts_selectorless_claims_absent_from_assessment_projection(db_session):
    from services.effects import claims_bridge

    contract = Contract(address="0x" + "fb" * 20, chain="ethereum")
    db_session.add(contract)
    db_session.flush()

    observed = {
        "claim_id": "flow.out",
        "tier": claims_bridge.OBSERVED_TIER,
        "witness": {"probe": "fallback-only"},
    }

    def _write(fallback_claims):
        write_permission_rows(
            db_session,
            contract_id=contract.id,
            function_records=cast(
                "list[dict[str, Any]]",
                [
                    {
                        "function": "fallback()",
                        "abi_signature": "fallback()",
                        "selector": "",
                        "claims": fallback_claims,
                    },
                    {
                        "function": "receive()",
                        "abi_signature": "receive()",
                        "selector": "",
                        "claims": [],
                    },
                ],
            ),
        )
        db_session.flush()

    _write([observed])
    # A new Assessment projection carries no claims, so both old rows retract.
    _write([])

    rows = db_session.execute(
        text("select function_name, claims from effective_functions where contract_id = :cid"),
        {"cid": contract.id},
    ).all()
    by_name = {name: claims for name, claims in rows}
    assert (by_name["fallback"] or []) == []
    assert (by_name["receive"] or []) == []
