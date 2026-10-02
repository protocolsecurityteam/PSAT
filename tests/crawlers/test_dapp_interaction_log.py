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
