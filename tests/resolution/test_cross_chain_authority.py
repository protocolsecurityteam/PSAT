"""Cross-chain authority labeling (MULTICHAIN_INVARIANTS.md invariant 15).

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
from utils.chains import chain_by_id
from utils.concurrency import RpcExecutor
from workers.policy_worker import _make_principal_type_resolver

BASE_CHAIN_ID = 8453
BASE = chain_by_id(BASE_CHAIN_ID)
# Registry constants (utils/chains.py) — the recognizer's inputs.
BASE_MESSENGER = "0x4200000000000000000000000000000000000007"
BASE_BRIDGE = "0x4200000000000000000000000000000000000010"


@pytest.fixture(autouse=True)
def _reset_executor():
    RpcExecutor.reset_for_tests()
    yield
    RpcExecutor.reset_for_tests()


def _alias(l1: str) -> str:
    """The L2 alias of an L1 address, computed here rather than by the module
    under test, so the round trip is checked against arithmetic and not against
    its own inverse."""
    return f"0x{(int(l1, 16) + L1_TO_L2_ALIAS_OFFSET) % (1 << 160):040x}"


# --- alias arithmetic --------------------------------------------------------


def test_alias_round_trip_is_identity():
    l1 = "0x1234000000000000000000000000000000005678"
    assert undo_l1_to_l2_alias(_alias(l1)) == l1


def test_alias_wraps_modulo_address_space():
    # An address whose alias overflows 2**160 wraps rather than growing.
    high = "0xffff000000000000000000000000000000000000"
    aliased = _alias(high)
    assert aliased.startswith("0x") and len(aliased) == 42
    assert undo_l1_to_l2_alias(aliased) == high


@pytest.mark.parametrize("bad", [None, "", "0x123", "not-hex", "0xZZ00000000000000000000000000000000000000"])
def test_alias_rejects_malformed(bad):
    assert undo_l1_to_l2_alias(bad) is None


# --- classify_cross_chain_authority ------------------------------------------


def test_classify_recognizes_cross_domain_messenger():
    result = classify_cross_chain_authority(BASE_MESSENGER, chain_info=BASE)
    assert result == (CROSS_CHAIN_AUTHORITY_TYPE, {"address": BASE_MESSENGER, "role": "cross_domain_messenger"})


def test_classify_recognizes_bridge_executor():
    result = classify_cross_chain_authority(BASE_BRIDGE.upper(), chain_info=BASE)
    # Case-insensitive registry match, normalized address in the details.
    assert result == (CROSS_CHAIN_AUTHORITY_TYPE, {"address": BASE_BRIDGE, "role": "bridge_executor"})


def test_classify_recognizes_aliased_owner_of_known_address():
    l1 = "0x00000000000000000000000000000000000000ff"
    principal = _alias(l1)
    result = classify_cross_chain_authority(principal, chain_info=BASE, known_addresses={l1})
    assert result == (
        CROSS_CHAIN_AUTHORITY_TYPE,
        {"address": principal, "role": "aliased_l1_owner", "implied_l1_address": l1},
    )


def test_classify_alias_requires_known_membership():
    # Same aliased address, but the implied L1 address is NOT in scope -> no label.
    l1 = "0x00000000000000000000000000000000000000ff"
    principal = _alias(l1)
    assert classify_cross_chain_authority(principal, chain_info=BASE, known_addresses=set()) is None
    assert classify_cross_chain_authority(principal, chain_info=BASE, known_addresses={BASE_BRIDGE}) is None


def test_classify_is_noop_on_chain_without_bridge_constants():
    mainnet = chain_by_id(1)
    assert mainnet.bridge_executors == () and mainnet.cross_domain_messengers == ()
    # Even an address that IS Base's messenger is not labelled on mainnet.
    assert classify_cross_chain_authority(BASE_MESSENGER, chain_info=mainnet) is None
    l1 = "0x00000000000000000000000000000000000000ff"
    assert classify_cross_chain_authority(_alias(l1), chain_info=mainnet, known_addresses={l1}) is None


def test_classify_ignores_ordinary_address():
    assert classify_cross_chain_authority("0xabc0000000000000000000000000000000000abc", chain_info=BASE) is None


# --- make_cross_chain_recognizer factory -------------------------------------


def test_recognizer_is_none_on_mainnet():
    assert make_cross_chain_recognizer(1) is None


def test_recognizer_is_none_on_unknown_chain():
    assert make_cross_chain_recognizer(999999) is None
    assert make_cross_chain_recognizer(None) is None


def test_recognizer_bound_to_base_recognizes_messenger():
    recognize = make_cross_chain_recognizer(BASE_CHAIN_ID)
    assert recognize is not None
    assert recognize(BASE_MESSENGER) == (
        CROSS_CHAIN_AUTHORITY_TYPE,
        {"address": BASE_MESSENGER, "role": "cross_domain_messenger"},
    )


# --- build_principal_labels wiring -------------------------------------------


def _effective_permissions_with_principal(principal_addr: str) -> dict:
    """A single role-gated function granting ``principal_addr`` role 1."""
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
    """Force the generic classifier to a fixed kind so we can prove the
    cross-chain recognizer overrides it."""

    def _stub(rpc_url, address, **_kw):
        return (kind, {"address": address}, True)

    return _stub


def test_labels_classifies_messenger_as_cross_chain_authority(monkeypatch):
    # Generic classify would call this a bare contract; the recognizer wins.
    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        _classify_stub("contract"),
    )
    payload = build_principal_labels(
        _effective_permissions_with_principal(BASE_MESSENGER),
        rpc_url="http://rpc.example",
        cross_chain_recognizer=make_cross_chain_recognizer(BASE_CHAIN_ID),
    )
    principal = {p["address"]: p for p in payload["principals"]}[BASE_MESSENGER]
    assert principal["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert principal["details"]["role"] == "cross_domain_messenger"
    assert principal["display_name"] == "Cross-domain messenger"
    assert "cross_chain_authority" in principal["labels"]


def test_labels_classifies_bridge_as_cross_chain_authority(monkeypatch):
    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        _classify_stub("contract"),
    )
    payload = build_principal_labels(
        _effective_permissions_with_principal(BASE_BRIDGE),
        rpc_url="http://rpc.example",
        cross_chain_recognizer=make_cross_chain_recognizer(BASE_CHAIN_ID),
    )
    principal = {p["address"]: p for p in payload["principals"]}[BASE_BRIDGE]
    assert principal["resolved_type"] == CROSS_CHAIN_AUTHORITY_TYPE
    assert principal["details"]["role"] == "bridge_executor"
    assert principal["display_name"] == "Bridge executor"


def test_labels_classifies_aliased_owner_with_hint(monkeypatch):
    # An aliased L1 owner reads as a codeless EOA to the generic classifier.
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
    """On chain 1 the recognizer is None: an address that happens to equal
    Base's messenger is classified by the generic path, and the payload is
    identical to omitting the recognizer argument entirely."""
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


# --- FunctionPrincipal type resolver wiring ----------------------------------


def test_fp_resolver_prioritizes_cross_chain_over_classify(monkeypatch):
    # The classifier stub would return "contract"; the recognizer must win.
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
