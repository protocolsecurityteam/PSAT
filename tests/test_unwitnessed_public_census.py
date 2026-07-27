"""Pin the unwitnessed-public census population definition (W2-B constraint b).

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

import sys
from pathlib import Path
from typing import Any, cast

from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Contract  # noqa: E402
from services.policy.effective_permissions import build_effective_permissions  # noqa: E402
from services.policy.effective_permissions_writer import write_effective_function_rows  # noqa: E402
from tests.conftest import requires_postgres  # noqa: E402

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

    payload = build_effective_permissions(
        _TARGET,
        capability_resolver_output={},
        effects=_effects("sweep(address)"),
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )
    fn = next(f for f in payload["functions"] if f["function"] == "sweep(address)")
    assert fn.get("status") == "public"

    write_effective_function_rows(
        db_session,
        contract_id=contract.id,
        function_records=cast("list[dict[str, Any]]", payload["functions"]),
        capability_by_function=None,
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
    payload = build_effective_permissions(
        _TARGET,
        capability_resolver_output={"sweep(address)": capability},
        effects=_effects("sweep(address)"),
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )
    write_effective_function_rows(
        db_session,
        contract_id=contract.id,
        function_records=cast("list[dict[str, Any]]", payload["functions"]),
        capability_by_function={"sweep(address)": capability},
    )
    db_session.flush()
    assert _conditions_typeof(db_session, contract.id, "sweep") == "array"
