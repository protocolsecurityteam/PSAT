"""Tests for the interaction capture log."""

from services.crawlers.dapp.interaction_log import InteractionLog


def test_add_transaction():
    log = InteractionLog()
    log.add(
        {
            "type": "sendTransaction",
            "url": "https://evil-dapp.com",
            "timestamp": 1700000000,
            "to": "0xAbC123000000000000000000000000000000dEaD",
            "value": "0x0",
            "data": "0xa9059cbb0000000000000000000000001234",
        }
    )
    assert len(log.interactions) == 1
    assert log.interactions[0].to == "0xAbC123000000000000000000000000000000dEaD"
    assert log.interactions[0].method_selector == "0xa9059cbb"


def test_get_contract_addresses():
    log = InteractionLog()
    log.add({"type": "sendTransaction", "url": "a", "timestamp": 1, "to": "0xAAA"})
    log.add({"type": "sendTransaction", "url": "b", "timestamp": 2, "to": "0xBBB"})
    log.add({"type": "sendTransaction", "url": "c", "timestamp": 3, "to": "0xAAA"})

    addresses = log.get_contract_addresses()
    assert len(addresses) == 2
    assert "0xaaa" in addresses
    assert "0xbbb" in addresses
