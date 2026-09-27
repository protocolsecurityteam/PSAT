"""Only known token-input prerequisites justify collection recovery."""

import pytest

from services.effects.balance_dependencies import needs_token_inventory
from services.effects.calldata.facts import FunctionFacts
from services.effects.selection import Candidate

HOLDER = "0x" + "11" * 20


@pytest.mark.parametrize(
    "signature,names,expected",
    [
        ("withdraw(uint256)", ["amount"], False),
        ("mint(address,uint256)", ["recipient", "amount"], False),
        ("withdraw(address,uint256)", ["token", "amount"], True),
    ],
)
def test_token_parameter_is_a_dependency_but_native_and_self_token_are_not(monkeypatch, signature, names, expected):
    fn = FunctionFacts(signature, "0x12345678", signature, {"parameter_names": names}, None, ())
    monkeypatch.setattr("services.effects.calldata.facts.load_contract_facts", lambda *_: object())
    monkeypatch.setattr("services.effects.calldata.facts.resolve_function", lambda *_: fn)
    c = Candidate(1, 2, HOLDER, "0x12345678", "f", False, ())
    assert needs_token_inventory(None, c) is expected


def test_missing_static_facts_do_not_create_a_collection_dependency(monkeypatch):
    monkeypatch.setattr("services.effects.calldata.facts.load_contract_facts", lambda *_: None)
    c = Candidate(1, 2, HOLDER, "0x12345678", "f", False, ())
    assert not needs_token_inventory(None, c)
