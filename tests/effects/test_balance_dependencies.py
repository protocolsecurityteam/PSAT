"""Balance-dependent recovery: bounded work, identity changes, no economic claims."""

from types import SimpleNamespace

from services.effects.balance_dependencies import (
    MAX_ATTEMPTS,
    finish_work,
    should_block,
    token_fingerprint,
    with_relevant_tokens,
)
from services.effects.recipes import _reach_tvl_state
from services.effects.selection import Candidate, disposed_from_holdings
from services.effects.simulate import SimCallResult, SimResult

HOLDER = "0x" + "11" * 20
TOKEN = "0x" + "22" * 20
OTHER = "0x" + "33" * 20


def work():
    return SimpleNamespace(
        required_generation=0,
        consumed_generation=0,
        queued_job_id=1,
        attempts=0,
        next_attempt_at=None,
        covered_tokens=[],
        state="pending",
        reason="missing",
        input_fingerprint="unchanged",
    )


def test_retry_budget_is_durable_and_does_not_claim_completion():
    row = work()
    for _ in range(MAX_ATTEMPTS):
        finish_work(row, generation=2, tokens=[TOKEN], remaining=(), succeeded=False, job_id=None)
    assert row.state == "degraded"
    assert row.consumed_generation == 0
    assert row.covered_tokens == []
    assert row.next_attempt_at is not None


def test_token_chunk_progress_preserves_deferred_assets():
    row = work()
    finish_work(row, generation=7, tokens=[TOKEN], remaining=[OTHER], succeeded=True, job_id=None)
    assert row.state == "pending"
    assert row.reason == "token_budget"
    assert row.covered_tokens == [TOKEN]
    finish_work(row, generation=7, tokens=[OTHER], remaining=[], succeeded=True, job_id=None)
    assert row.state == "complete"
    assert row.covered_tokens == sorted([TOKEN, OTHER])
    assert row.consumed_generation == 7
    assert row.input_fingerprint == "unchanged"


def test_missing_snapshot_is_not_complete_and_price_is_not_an_identity():
    assert should_block(work(), 0)
    assert not should_block(work(), 3)
    assert token_fingerprint([TOKEN, OTHER, TOKEN]) == token_fingerprint([OTHER, TOKEN])
    assert token_fingerprint([TOKEN]) != token_fingerprint([OTHER])


def test_delivery_never_disposes_and_external_tvl_never_rejects_reach():
    assert not disposed_from_holdings(
        delivery_shape="fan_out_all", reference_shape="absent_from_universe", usd_value=None
    )
    assert _reach_tvl_state(1000, 1) == ("external_reference_only", None)


def test_named_unpriced_token_precedes_priced_holdings_and_is_chain_scoped(monkeypatch):
    import services.effects.calldata.facts as facts
    import services.effects.calldata.seeding as seeding

    monkeypatch.setattr(facts, "load_contract_facts", lambda *_: object())
    monkeypatch.setattr(facts, "resolve_function", lambda *_: object())
    monkeypatch.setattr("services.effects.balance_dependencies.needs_token_inventory", lambda *_: True)
    monkeypatch.setattr(seeding, "input_token_hints", lambda *_, **kw: ("asset()",))
    calls = []

    def simulate(batch, block, overrides):
        calls.append((batch[0].to, block))
        return SimResult((SimCallResult(True, "0x" + "0" * 24 + TOKEN[2:], None),))

    ctx = SimpleNamespace(
        chain_id=1,
        block=123,
        simulate_supported=True,
        simulate=simulate,
        effective_seeder=lambda: None,
        on_requests=None,
    )
    c = Candidate(1, 2, HOLDER, "0x12345678", "mint", False, (), input_token_addresses=(OTHER,))
    cache = {}
    enriched = with_relevant_tokens(None, c, ctx, cache=cache)
    assert enriched.input_token_addresses == (TOKEN,)
    assert enriched.deferred_token_addresses == (OTHER,)
    with_relevant_tokens(None, c, ctx, cache=cache)
    assert len(calls) == 1
    ctx.chain_id = 10
    with_relevant_tokens(None, c, ctx, cache=cache)
    assert len(calls) == 2
    assert calls[0] == (HOLDER, "0x7b")


def test_failed_required_getter_remains_pending_with_priced_fallback(monkeypatch):
    import services.effects.calldata.facts as facts
    import services.effects.calldata.seeding as seeding

    monkeypatch.setattr(facts, "load_contract_facts", lambda *_: object())
    monkeypatch.setattr(facts, "resolve_function", lambda *_: object())
    monkeypatch.setattr("services.effects.balance_dependencies.needs_token_inventory", lambda *_: True)
    monkeypatch.setattr(seeding, "input_token_hints", lambda *_, **kw: ("underlying()",))
    ctx = SimpleNamespace(
        chain_id=1,
        block=123,
        simulate_supported=True,
        simulate=lambda *_: SimResult((SimCallResult(False, "0x", None),)),
        effective_seeder=lambda: None,
        on_requests=None,
    )
    c = Candidate(1, 2, HOLDER, "0x12345678", "mint", False, (), input_token_addresses=(OTHER,))
    assert with_relevant_tokens(None, c, ctx).token_inputs_pending
    for malformed in ("0x" + "0" * 64, "0xnothex", "0x12"):
        ctx.simulate = lambda *_, data=malformed: SimResult((SimCallResult(True, data, None),))
        assert with_relevant_tokens(None, c, ctx).token_inputs_pending
    monkeypatch.setattr(
        seeding, "input_token_hints", lambda *_, **kw: ("asset()",) if kw.get("include_default_asset", True) else ()
    )
    assert not with_relevant_tokens(None, c, ctx).token_inputs_pending


def test_known_native_and_self_token_plans_do_not_need_asset_inventory(monkeypatch):
    import services.effects.calldata.facts as facts
    from services.effects.balance_dependencies import needs_token_inventory
    from services.effects.calldata.facts import FunctionFacts

    monkeypatch.setattr(facts, "load_contract_facts", lambda *_: object())
    for signature in ("withdraw(uint256)", "mint(address,uint256)"):
        fn = FunctionFacts(signature, "0x12345678", signature, {}, None, ())
        monkeypatch.setattr(facts, "resolve_function", lambda *_: fn)
        c = Candidate(1, 2, HOLDER, "0x12345678", "f", False, ())
        assert not needs_token_inventory(None, c)
        assert not should_block(work(), 0, requires_inventory=False)
    assert not should_block(work(), 0, tokens=(TOKEN,))


def test_getter_cache_keeps_required_and_optional_policy_separate_in_both_orders(monkeypatch):
    import services.effects.calldata.facts as facts
    import services.effects.calldata.seeding as seeding

    monkeypatch.setattr(facts, "load_contract_facts", lambda *_: object())
    monkeypatch.setattr(facts, "resolve_function", lambda _facts, selector: selector)
    monkeypatch.setattr("services.effects.balance_dependencies.needs_token_inventory", lambda *_: False)
    monkeypatch.setattr(
        seeding,
        "input_token_hints",
        lambda selector, **kw: ("asset()",) if kw.get("include_default_asset", True) or selector == "required" else (),
    )
    ctx = SimpleNamespace(
        chain_id=1,
        block=123,
        simulate_supported=True,
        simulate=lambda *_: SimResult((SimCallResult(False, "0x", None),)),
        effective_seeder=lambda: None,
        on_requests=None,
    )
    for order in (("required", "optional"), ("optional", "required")):
        cache = {}
        for selector in order:
            c = Candidate(1, 2, HOLDER, selector, "f", False, ())
            assert with_relevant_tokens(None, c, ctx, cache=cache).token_inputs_pending == (selector == "required")
