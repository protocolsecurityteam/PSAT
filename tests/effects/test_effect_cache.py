from __future__ import annotations

from typing import Any

from db.effect_cache import (
    record_effect_verdict,
)
from db.models import Contract, EffectiveFunction, EffectVerdict
from tests.cache_helpers import requires_postgres
from tests.support.effects_worker_harness import clean_effects  # noqa: F401  (fixture, registered by import)

# Identity is the deployment coordinates; function_id is a convenience join, so a replace mid-run must not fail the
# write.


def _seed_function_row(session, address: str, selector: str) -> int:
    contract = Contract(address=address, chain="ethereum", is_proxy=False)
    session.add(contract)
    session.flush()
    ef = EffectiveFunction(
        contract_id=contract.id,
        deployment_address=address,
        function_name="pause",
        selector=selector,
        abi_signature="pause()",
        effect_labels=[],
        authority_public=False,
    )
    session.add(ef)
    session.flush()
    return ef.id


@requires_postgres
def test_fk_vanish_fallback_warns_and_records_degraded(clean_effects, caplog):
    """The FK-violation fallback inside the check-insert window is a known orphaned-row bug class."""
    import logging

    from sqlalchemy import delete

    from utils.logging import degraded_errors_var

    session = clean_effects
    address = "0x" + "55" * 20
    fn_id = _seed_function_row(session, address, "0x8456cb59")
    session.commit()

    injected = {"done": False}
    orig_execute = session.execute

    def execute_then_delete(statement, *args, **kwargs):
        result = orig_execute(statement, *args, **kwargs)
        if not injected["done"] and "effective_functions" in str(statement).lower():
            injected["done"] = True
            orig_execute(delete(EffectiveFunction).where(EffectiveFunction.id == fn_id))
        return result

    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    session.execute = execute_then_delete
    try:
        with caplog.at_level(logging.WARNING, logger="db.effect_cache"):
            record_effect_verdict(
                session,
                chain_id=1,
                contract_address=address,
                selector="0x8456cb59",
                effect_class="freeze_pause",
                verdict="proven",
                tier="tier2",
                function_id=fn_id,
            )
    finally:
        del session.execute
        degraded_errors_var.reset(token)
    session.commit()

    assert injected["done"], "FK-vanish injection never fired — the test would be vacuous"
    row = session.query(EffectVerdict).one()
    assert row.function_id is None and row.verdict == "proven"
    rec = next(r for r in caplog.records if r.name == "db.effect_cache")
    assert rec.levelno == logging.WARNING
    assert rec.function_id == fn_id
    assert rec.contract_address == address
    assert [e.phase for e in accumulator] == ["effect_verdict_unlink"]
    # The IntegrityError's str() would be the upsert SQL.
    assert accumulator[0].exc_type.endswith(".EffectVerdictUnlinked")
    assert "vanished" in accumulator[0].message and "INSERT" not in accumulator[0].message


# Cache hits carry no concrete values; an unconditional SET erased the cold first-sighting observation.

RESIDUE_ADDR = "0x" + "55" * 20


def _write(session, **kw):
    base: dict[str, Any] = {
        "chain_id": 1,
        "contract_address": RESIDUE_ADDR,
        "selector": "0x40c10f19",
        "effect_class": "value_out",
        "behavior_hash": "bh_residue",
        "verdict": "proven",
        "tier": "tier1",
    }
    base.update(kw)
    record_effect_verdict(session, **base)
    session.commit()
    session.expire_all()
    return session.query(EffectVerdict).one()


# A self-hit must not erase the producing write's deployment-plane qualifiers (PR-161 verdict 146 published a claim its
# own transcript contradicted).

FULL_WITNESS: dict[str, Any] = {
    "reason": "supply_burn",
    "observation": "executed",
    "supply_delta_sign": "burn",
    "input_seeded": True,
    "contract_balance_seeded": True,
    "backing": {"inflow_observed": False, "minted": False, "input_seeded": True, "contract_balance_seeded": False},
}
