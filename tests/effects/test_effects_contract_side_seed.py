"""Contract-side ERC-20 seeding — the token analogue of the existing
native ``contract_balance_override``.

A payout the contract's LIVE token balance cannot cover reverts before its send.
Seeding the CONTRACT's own balance of a token it provably holds unblocks it, and
a verdict proven under that seed is a CAPABILITY claim ("would move value IF the
contract were funded"), so it carries the weaker ``contract_balance_seeded``
qualifier exactly as the ETH seed does. The token is derived from measured
holdings, never hardcoded.
"""

from __future__ import annotations

from services.effects import recipes
from services.effects.config import VERDICT_PROVEN, VERDICT_UNKNOWN
from services.effects.harness import SimContext
from services.effects.seeding import SeedBudget, SimulateSeeder
from services.effects.simulate import SimCallResult
from tests.support.effects_stubs import ASSET, PRINCIPAL, VAULT, FakeChain, RecordingStore, ok, sel, transfer_log

CTX = SimContext(chain_id=1, block=1000, hardfork="prague")
SWEEP = sel("sweep(uint256)")


class SweepChain(FakeChain):
    """Everything else is inherited so the seeder's real layout discovery runs unchanged."""

    def _vault_call(self, call, data, overrides) -> SimCallResult:
        if data.startswith(SWEEP):
            amount = int(data[10:74], 16)
            held = self._stored(overrides, VAULT, VAULT, arity=1) or 0
            if held < amount:
                return SimCallResult(False, "0x", "0x08c379a0", ())
            return ok(logs=[transfer_log(ASSET, VAULT, PRINCIPAL, amount)])
        return super()._vault_call(call, data, overrides)


def _value_out(chain, *, contract_holdings, store=None):
    return recipes.value_out(
        simulate=chain,
        store=store or RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata=SWEEP + (5).to_bytes(32, "big").hex(),
        simulate_supported=True,
        gate_ref="gate:none",
        seeded_calldata={18: SWEEP + (5).to_bytes(32, "big").hex()},
        seeder=SimulateSeeder(
            chain, chain_id=1, budget=SeedBudget(max_identity_probes=9, max_layout_discoveries=9, max_probe_retries=9)
        ),
        contract_holdings=contract_holdings,
    )


def test_contract_side_seed_flips_a_balance_gated_payout_and_marks_the_capability():
    store = RecordingStore()
    eff = _value_out(SweepChain(), contract_holdings=(ASSET,), store=store)
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["value_moved"] is True
    assert eff.details["contract_balance_seeded"] is True


def test_without_the_holding_the_payout_stays_an_honest_unknown():
    eff = _value_out(SweepChain(), contract_holdings=())
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.details["observation"] == "reverted"
