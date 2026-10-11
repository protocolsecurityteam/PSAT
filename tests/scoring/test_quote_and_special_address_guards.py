from types import SimpleNamespace
from typing import Any, cast

import pytest

from services.clients import etherscan
from services.policy.capability_surface import project_capability_surface
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import EvaluationContext, evaluate_tree
from services.scoring.planes.value import ASSET_UNPRICED, _asset_reading
from utils.address_evidence import special_address_reason
from utils.quote_validation import quote_refusal


@pytest.mark.parametrize("source", ["constant", "state_variable"])
@pytest.mark.parametrize("address", ["0x" + "00" * 18 + "dead", "0x" + "00" * 19 + "01"])
def test_special_address_never_becomes_exact_eoa_authority(source, address):
    operand = {"source": source, "constant_value": address, "state_variable_name": "controller"}
    tree = {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "operator": "eq",
            "authority_role": "caller_authority",
            "operands": [{"source": "msg_sender"}, operand],
        },
    }
    cap = evaluate_tree(cast(Any, tree), EvaluationContext(state_var_values={"controller": address}))
    surface = project_capability_surface(capability_to_dict(cap))
    assert not surface.authority_public
    assert not surface.principal_rows
    assert cap.kind == "unsupported"


def test_provider_price_outlier_preserves_quantity_but_not_value(monkeypatch):
    entry = {
        "TokenAddress": "0x" + "11" * 20,
        "TokenQuantity": str(11 * 10**18),
        "TokenDivisor": "18",
        "TokenPriceUSD": "26346910012134100",
        "TokenSymbol": "CTC",
    }
    monkeypatch.setattr(etherscan, "get", lambda *a, **k: {"result": [entry]})
    row = etherscan.get_token_balances_page("0x" + "22" * 20, chain_id=1).rows[0]
    assert row["balance"] == 11 * 10**18
    assert row["usd_value"] is None and row["price_usd"] is None
    assert row["price_refusal"] == "uncorroborated_price_outlier"


def test_preexisting_bad_quote_is_rejected_at_score_read_boundary():
    row = SimpleNamespace(price_usd=26346910012134100, usd_value=289816010133475100, raw_balance=str(11 * 10**18))
    assert _asset_reading(row) == (None, ASSET_UNPRICED)
    assert quote_refusal(100000, 250000000) is None
    assert special_address_reason("0x" + "12" * 20) is None
