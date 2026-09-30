"""Cross-chain authority labeling.

Covers the pure recognizer, its wiring into ``build_principal_labels`` and the
FunctionPrincipal type resolver, and the mainnet byte-identity guarantee.
"""

import pytest

from services.policy.principal_enrichment import build_principal_labels
from services.resolution.cross_chain_authority import (
    CROSS_CHAIN_AUTHORITY_TYPE,
    L1_TO_L2_ALIAS_OFFSET,
    classify_cross_chain_authority,
    make_cross_chain_recognizer,
    undo_l1_to_l2_alias,
)
from tests.support.isolation import _reset_executor  # noqa: F401  (fixture, registered by import)
from utils.chains import chain_by_id
from workers.policy_worker import _make_principal_type_resolver

BASE_CHAIN_ID = 8453
BASE = chain_by_id(BASE_CHAIN_ID)
BASE_MESSENGER = "0x4200000000000000000000000000000000000007"
BASE_BRIDGE = "0x4200000000000000000000000000000000000010"


def _alias(l1: str) -> str:
    """Checked against arithmetic, not the module's own inverse."""
    return f"0x{(int(l1, 16) + L1_TO_L2_ALIAS_OFFSET) % (1 << 160):040x}"


@pytest.mark.parametrize(
    "l1",
    [
        pytest.param("0x1234000000000000000000000000000000005678", id="round-trip-is-identity"),
        pytest.param("0xffff000000000000000000000000000000000000", id="wraps-modulo-address-space"),
    ],
)
def test_alias_round_trip(l1):
    aliased = _alias(l1)
    assert aliased.startswith("0x") and len(aliased) == 42
    assert undo_l1_to_l2_alias(aliased) == l1


@pytest.mark.parametrize("bad", [None, "", "0x123", "not-hex", "0xZZ00000000000000000000000000000000000000"])
def test_alias_rejects_malformed(bad):
    assert undo_l1_to_l2_alias(bad) is None


@pytest.mark.parametrize(
    "queried, expected_address, expected_role",
    [
        pytest.param(BASE_MESSENGER, BASE_MESSENGER, "cross_domain_messenger", id="cross-domain-messenger"),
        pytest.param(BASE_BRIDGE.upper(), BASE_BRIDGE, "bridge_executor", id="bridge-executor-case-insensitive"),
    ],
)
def test_classify_recognizes_bridge_addresses(queried, expected_address, expected_role):
    result = classify_cross_chain_authority(queried, chain_info=BASE)
    assert result == (CROSS_CHAIN_AUTHORITY_TYPE, {"address": expected_address, "role": expected_role})


def test_classify_recognizes_aliased_owner_of_known_address():
    l1 = "0x00000000000000000000000000000000000000ff"
    principal = _alias(l1)
    result = classify_cross_chain_authority(principal, chain_info=BASE, known_addresses={l1})
    assert result == (
        CROSS_CHAIN_AUTHORITY_TYPE,
        {"address": principal, "role": "aliased_l1_owner", "implied_l1_address": l1},
    )


def test_classify_alias_requires_known_membership():
    l1 = "0x00000000000000000000000000000000000000ff"
    principal = _alias(l1)
    assert classify_cross_chain_authority(principal, chain_info=BASE, known_addresses=set()) is None
    assert classify_cross_chain_authority(principal, chain_info=BASE, known_addresses={BASE_BRIDGE}) is None


def test_classify_is_noop_on_chain_without_bridge_constants():
    mainnet = chain_by_id(1)
    assert mainnet.bridge_executors == () and mainnet.cross_domain_messengers == ()
    assert classify_cross_chain_authority(BASE_MESSENGER, chain_info=mainnet) is None
    l1 = "0x00000000000000000000000000000000000000ff"
    assert classify_cross_chain_authority(_alias(l1), chain_info=mainnet, known_addresses={l1}) is None


def test_classify_ignores_ordinary_address():
    assert classify_cross_chain_authority("0xabc0000000000000000000000000000000000abc", chain_info=BASE) is None


@pytest.mark.parametrize("chain_id", [1, 999999, None], ids=["mainnet", "unknown-chain", "no-chain"])
def test_recognizer_is_none(chain_id):
    assert make_cross_chain_recognizer(chain_id) is None


def _effective_permissions_with_principal(principal_addr: str) -> dict:
    return {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "L2Vault",
        "functions": [
            {
                "function": "setOwner(address)",
                "effect_labels": ["ownership_transfer"],
                "authority_public": False,
                "authority_roles": [
                    {
                        "role": 1,
                        "principals": [{"address": principal_addr, "resolved_type": "unknown", "details": {}}],
                    }
                ],
                "direct_owner": None,
            }
        ],
    }


def _classify_stub(kind: str):

    def _stub(rpc_url, address, **_kw):
        return (kind, {"address": address}, True)

    return _stub


@pytest.mark.parametrize(
    "address, role, display_name",
    [
        pytest.param(BASE_MESSENGER, "cross_domain_messenger", "Cross-domain messenger", id="messenger"),
        pytest.param(BASE_BRIDGE, "bridge_executor", "Bridge executor", id="bridge"),
    ],
)
def test_labels_classifies_as_cross_chain_authority(monkeypatch, address, role, display_name):
    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        _classify_stub("contract"),
    )
    payload = build_principal_labels(
        _effective_permissions_with_principal(address),
        rpc_url="http://rpc.example",
        cross_chain_recognizer=make_cross_chain_recognizer(BASE_CHAIN_ID),
    )
    principal = {p["address"]: p for p in payload["principals"]}[address]
    assert principal["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert principal["details"]["role"] == role
    assert principal["display_name"] == display_name
    assert "cross_chain_authority" in principal["labels"]


def test_labels_classifies_aliased_owner_with_hint(monkeypatch):
    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        _classify_stub("eoa"),
    )
    l1 = "0x00000000000000000000000000000000000000ff"
    principal_addr = _alias(l1)
    payload = build_principal_labels(
        _effective_permissions_with_principal(principal_addr),
        rpc_url="http://rpc.example",
        cross_chain_recognizer=make_cross_chain_recognizer(BASE_CHAIN_ID, known_addresses={l1}),
    )
    principal = {p["address"]: p for p in payload["principals"]}[principal_addr]
    assert principal["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert principal["details"]["role"] == "aliased_l1_owner"
    assert principal["details"]["implied_l1_address"] == l1
    assert principal["display_name"] == f"Aliased L1 owner ({l1})"


def test_labels_mainnet_output_is_byte_identical(monkeypatch):
    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        _classify_stub("eoa"),
    )
    ep = _effective_permissions_with_principal(BASE_MESSENGER)

    without_arg = build_principal_labels(ep, rpc_url="http://rpc.example")
    with_mainnet_recognizer = build_principal_labels(
        ep, rpc_url="http://rpc.example", cross_chain_recognizer=make_cross_chain_recognizer(1)
    )

    assert with_mainnet_recognizer == without_arg
    principal = {p["address"]: p for p in without_arg["principals"]}[BASE_MESSENGER]
    assert principal["resolved_type"] == "eoa"


def test_fp_resolver_prioritizes_cross_chain_over_classify(monkeypatch):
    monkeypatch.setattr(
        "workers.policy_worker.classify_resolved_address_with_status",
        _classify_stub("contract"),
    )
    resolve = _make_principal_type_resolver({}, "http://rpc.example", make_cross_chain_recognizer(BASE_CHAIN_ID))
    assert resolve(BASE_BRIDGE) == (CROSS_CHAIN_AUTHORITY_TYPE, {"address": BASE_BRIDGE, "role": "bridge_executor"})


def test_fp_resolver_without_recognizer_uses_classify(monkeypatch):
    monkeypatch.setattr(
        "workers.policy_worker.classify_resolved_address_with_status",
        _classify_stub("contract"),
    )
    resolve = _make_principal_type_resolver({}, "http://rpc.example", None)
    kind, _details = resolve(BASE_BRIDGE)
    assert kind == "contract"
