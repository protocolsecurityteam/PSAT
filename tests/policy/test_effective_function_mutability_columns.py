"""The state-mutability witness is persisted with three states.

``effect_targets`` mixes writes with external-call heads, so it can't answer "does this write state". These
pin that ``sinks`` / ``state_writes`` / ``state_changing`` / ``writer_selectors`` reach the row, and that the row
can still say "nobody looked". Fixtures are production ``effects`` artifacts, each naming its job id.
"""

from __future__ import annotations

from typing import Any

import pytest

from db.models import Contract, EffectiveFunction
from services.policy.effective_permissions import (
    build_effective_permissions,
)
from services.policy.effective_permissions_writer import write_effective_function_rows

# Positive control (job ee44f242): a role-gated token mover with no state writes.
_SWEEP_DUST: dict[str, Any] = {
    "function": "sweepDust(address,address)",
    "selector": "0xa9fb82d6",
    "abi_signature": "sweepDust(address,address)",
    "effect_labels": ["asset_send"],
    "effect_targets": ["_token.balanceOf", "_token.safeTransfer", "token.functionCall", "target.call"],
    "action_summary": "Sends assets.",
    "state_changing": True,
    "state_writes": [],
    "writer_selectors": [],
    "sinks": [
        {
            "id": "sweepDust(address,address):sink0:external_call:_token.balanceOf",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "_token.balanceOf",
            "selector": "0x70a08231",
            "origin": "body",
        },
        {
            "id": "sweepDust(address,address):sink1:external_call:_token.safeTransfer",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "_token.safeTransfer",
            "selector": "0xd0c407e1",
            "origin": "body",
        },
        {
            "id": "sweepDust(address,address):sink2:external_call:token.functionCall",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "token.functionCall",
            "selector": "0x241b5886",
            "origin": "body",
        },
        {
            "id": "sweepDust(address,address):sink3:external_call:target.call",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "target.call",
            "selector": None,
            "origin": "body",
        },
        {
            "id": "sweepDust(address,address):sink4:external_call:roleRegistry.onlyOperatingMultisig",
            "function": "sweepDust(address,address)",
            "kind": "external_call",
            "target": "roleRegistry.onlyOperatingMultisig",
            "selector": "0x71645909",
            "origin": "guard",
        },
    ],
}

# Negative control (job 06111502): a genuine view whose ``effect_targets`` looks like ``sweepDust``'s.
_GET_RATE_IN_QUOTE: dict[str, Any] = {
    "function": "getRateInQuote(ERC20)",
    "selector": "0x1ce6e471",
    "abi_signature": "getRateInQuote(ERC20)",
    "effect_labels": ["external_contract_call"],
    "effect_targets": ["quote.decimals", "REF_136.getRate", "oneQuote.mulDivDown"],
    "action_summary": "Calls out.",
    "state_changing": False,
    "state_writes": [],
    "writer_selectors": [],
    "sinks": [
        {
            "id": "getRateInQuote(ERC20):sink0:external_call:quote.decimals",
            "function": "getRateInQuote(ERC20)",
            "kind": "external_call",
            "target": "quote.decimals",
            "selector": "0x313ce567",
            "origin": "body",
        },
        {
            "id": "getRateInQuote(ERC20):sink1:external_call:REF_136.getRate",
            "function": "getRateInQuote(ERC20)",
            "kind": "external_call",
            "target": "REF_136.getRate",
            "selector": "0x679aefce",
            "origin": "body",
        },
    ],
}

# A proven mutator (job 06111502).
_UPDATE_EXCHANGE_RATE: dict[str, Any] = {
    "function": "updateExchangeRate(uint96)",
    "selector": "0x3458113d",
    "abi_signature": "updateExchangeRate(uint96)",
    "effect_labels": ["external_contract_call"],
    "effect_targets": ["vault.totalSupply", "accountantState"],
    "action_summary": "Writes state.",
    "state_changing": True,
    "state_writes": [
        {
            "var": "accountantState",
            "declared_type": "AccountantWithRateProviders.AccountantState",
            "member_path": [],
            "granularity": "var",
            "hygiene_class": "normal",
            "origin": "body",
        }
    ],
    "writer_selectors": ["0x3458113d"],
    "sinks": [
        {
            "id": "updateExchangeRate(uint96):sink2:state_write:accountantState",
            "function": "updateExchangeRate(uint96)",
            "kind": "state_write",
            "target": "accountantState",
            "selector": None,
            "origin": "body",
        },
    ],
}

# Sentinel A (job 16aa62fb): WETH9's ``fallback()`` writes ``balanceOf`` but has no selector, so the artifact says not
# state-changing.
_WETH9_FALLBACK: dict[str, Any] = {
    "function": "fallback()",
    "selector": "0x552079dc",
    "abi_signature": "fallback()",
    "effect_labels": [],
    "effect_targets": ["balanceOf"],
    "action_summary": "Performs a contract action.",
    "state_changing": False,
    "state_writes": [
        {
            "var": "balanceOf",
            "declared_type": "mapping(address => uint256)",
            "member_path": [],
            "granularity": "var",
            "hygiene_class": "normal",
            "origin": "body",
        }
    ],
    "writer_selectors": [],
    "sinks": [
        {
            "id": "fallback():sink0:state_write:balanceOf",
            "function": "fallback()",
            "kind": "state_write",
            "target": "balanceOf",
            "selector": None,
            "origin": "body",
        }
    ],
}

# Sentinel B (job 06111502): a view over an ERC-7201 slot whose derived write contradicts ``state_changing``;
# ``assembly_state_access`` misses all 100 such records.
_PAUSED_VIEW: dict[str, Any] = {
    "function": "paused()",
    "selector": "0x5c975abb",
    "abi_signature": "paused()",
    "effect_labels": [],
    "effect_targets": ["PAUSABLE_STORAGE_SLOT"],
    "action_summary": "Performs a contract action.",
    "state_changing": False,
    "assembly_state_access": False,
    "state_writes": [
        {
            "var": "PAUSABLE_STORAGE_SLOT",
            "declared_type": "bytes32",
            "member_path": [],
            "granularity": "var",
            "hygiene_class": "normal",
            "origin": "body",
        }
    ],
    "writer_selectors": ["0x5c975abb"],
    "sinks": [
        {
            "id": "paused():sink0:state_write:PAUSABLE_STORAGE_SLOT",
            "function": "paused()",
            "kind": "state_write",
            "target": "PAUSABLE_STORAGE_SLOT",
            "selector": None,
            "origin": "body",
        }
    ],
}

_EFFECTS = {
    rec["function"]: rec
    for rec in (_SWEEP_DUST, _GET_RATE_IN_QUOTE, _UPDATE_EXCHANGE_RATE, _WETH9_FALLBACK, _PAUSED_VIEW)
}


# The worker hands the writer ``ep_data["functions"]``, not these records, so a field stopping at the record layer is
# NULL in production.


def _target_analysis() -> dict[str, Any]:
    return {"subject": {"address": "0x" + "9" * 40, "name": "W06Fixture"}}


def test_the_witness_survives_the_effective_permissions_artifact() -> None:
    payload = build_effective_permissions(
        _target_analysis(),
        capability_resolver_output={},
        effects={"functions": _EFFECTS},
    )
    by_sig = {fn["function"]: fn for fn in payload["functions"]}

    # The keys are NotRequired on the TypedDict.
    assert by_sig["sweepDust(address,address)"].get("state_changing") is True
    assert by_sig["sweepDust(address,address)"].get("state_writes") == []
    assert len(by_sig["sweepDust(address,address)"].get("sinks") or []) == 5
    assert by_sig["updateExchangeRate(uint96)"].get("writer_selectors") == ["0x3458113d"]
    assert by_sig["getRateInQuote(ERC20)"].get("state_changing") is False
    assert by_sig["fallback()"].get("state_changing") is None
    assert by_sig["paused()"].get("state_writes") is None


@pytest.fixture
def _contract(db_session):
    contract = Contract(address="0x" + "9" * 40, chain="ethereum", contract_name="W06Fixture")
    db_session.add(contract)
    db_session.flush()
    yield contract
    db_session.query(EffectiveFunction).filter_by(contract_id=contract.id).delete()
    db_session.delete(contract)
    db_session.commit()


def _write(db_session, contract, records: dict[str, Any]) -> None:
    write_effective_function_rows(
        db_session,
        contract_id=contract.id,
        function_records=list(records.values()),
        capability_by_function={},
    )
    db_session.commit()
