import pytest

from services.crawlers.dapp.interaction_log import InteractionLog


@pytest.mark.parametrize("field", ["url", "data"])
@pytest.mark.parametrize(
    "explorer,chain",
    [
        ("https://optimistic.etherscan.io/address/0x123", "optimism"),
        ("HTTPS://OPTIMISTIC.ETHERSCAN.IO:443/address/0x123", "optimism"),
        ("https://etherscan.io/address/0x123", "ethereum"),
        ("https://basescan.org/address/0x123", "base"),
        ("https://etherscan.io.attacker.invalid/address/0x123", None),
        ("https://dapp.invalid/?next=https://etherscan.io/address/0x123", None),
        ("https://etherscan.io@dapp.invalid/address/0x123", None),
    ],
)
def test_add_transaction(field, explorer, chain):
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
    address = log.interactions[0].to
    log.add({"type": "scrapedAddress", "to": address, field: explorer})
    details = log.get_address_details()
    assert len(details) == 1
    assert details[0]["address"] == address.lower()
    assert details[0]["chain"] == chain
