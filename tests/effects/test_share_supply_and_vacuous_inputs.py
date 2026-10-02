"""Recipe regressions for share-accounted supply and vacuous inputs.

Drives the REAL ``recipes.supply`` / ``recipes.value_out`` against minimal wire fakes and the
``effects_worker._is_cacheable`` seam: a vacuous non-observation needs its own reason AND must be refused by the cache.
"""

from __future__ import annotations

import pytest
from eth_utils.crypto import keccak

from services.effects import recipes
from services.effects.config import VERDICT_PROVEN, VERDICT_UNKNOWN
from services.effects.harness import SimContext
from services.effects.simulate import SimResult
from tests.support.effects_stubs import RecordingStore, ok, transfer_log, uint_ret
from workers.effects_worker import _is_cacheable

TOKEN = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20
ZERO = "0x" + "00" * 20
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")


def sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


MINT_SEL = sel("mintShares(address,uint256)")
MINT_CALLDATA = MINT_SEL + "00" * 64


class SharesChain:
    """Share-accounted token: ``totalSupply()`` reads a CONSTANT pooled backing while mint/burn still
    emit ``Transfer(0x0, user)`` / ``Transfer(user, 0x0)``. The vacuous-supply shape: zero delta, yet not an
    absence of supply
    change."""

    def __init__(self, *, emit: str | None, total_supply: int = 10**24) -> None:
        self.emit = emit  # "mint" | "burn" | None
        self.total_supply = total_supply
        self.blocks: list = []

    def __call__(self, calls, block_tag, overrides):
        self.blocks.append((list(calls), block_tag, overrides))
        results = []
        for call in calls:
            data = call.data
            if data.startswith(recipes.TOTAL_SUPPLY_SELECTOR):
                results.append(ok(uint_ret(self.total_supply)))
            elif data.startswith(MINT_SEL):
                logs = []
                if self.emit == "mint":
                    logs = [transfer_log(TOKEN, ZERO, PRINCIPAL, 1)]
                elif self.emit == "burn":
                    logs = [transfer_log(TOKEN, PRINCIPAL, ZERO, 1)]
                results.append(ok(logs=logs))
            else:
                results.append(ok())
        return SimResult(calls=tuple(results))


def _supply(chain, **kwargs):
    return recipes.supply(
        simulate=chain,
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata=MINT_CALLDATA,
        simulate_supported=True,
        gate_ref="gate:none",
        **kwargs,
    )


# S2 — a zero totalSupply delta with an unambiguous zero-address Transfer


@pytest.mark.parametrize("direction", [pytest.param("mint", id="mint"), pytest.param("burn", id="burn")])
def test_share_accounted_zero_delta_with_zero_address_transfer_yields_a_verdict(direction):
    eff = _supply(SharesChain(emit=direction))
    assert eff.verdict == VERDICT_PROVEN
    assert eff.reason == f"supply_{direction}"
    assert eff.details["supply_delta_sign"] == direction


def test_supply_vacuous_input_gets_its_own_uncacheable_reason():
    vac = _supply(SharesChain(emit=None), inputs_vacuous=True)
    assert vac.verdict == VERDICT_UNKNOWN
    assert vac.reason == "no_supply_delta_vacuous_input"
    assert vac.details["vacuous_input"] is True
    assert not _is_cacheable(vac)

    # The non-vacuous twin stays cacheable.
    plain = _supply(SharesChain(emit=None), inputs_vacuous=False)
    assert plain.reason == "no_supply_delta"
    assert _is_cacheable(plain)


class ExecutedNoValueChain:
    def __call__(self, calls, block_tag, overrides):
        return SimResult(calls=tuple(ok() for _ in calls))


def _value_out(chain, **kwargs):
    return recipes.value_out(
        simulate=chain,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=TOKEN,
        principal=PRINCIPAL,
        calldata=sel("manage(address[],bytes[],uint256[])") + "00" * 96,
        simulate_supported=True,
        gate_ref="gate:none",
        **kwargs,
    )


def test_value_out_vacuous_input_gets_its_own_uncacheable_reason():
    """The loop body never ran, so the negative is about the argument."""
    vac = _value_out(ExecutedNoValueChain(), inputs_vacuous=True)
    assert vac.verdict == VERDICT_UNKNOWN
    assert vac.reason == "no_value_observed_vacuous_input"
    assert vac.details["vacuous_input"] is True
    assert vac.details["observation"] == "executed"
    assert not _is_cacheable(vac)

    plain = _value_out(ExecutedNoValueChain(), inputs_vacuous=False)
    assert plain.reason == "no_value_observed"
    assert _is_cacheable(plain)
