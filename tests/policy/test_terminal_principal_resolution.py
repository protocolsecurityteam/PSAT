"""The walk's only wire is the injected ``resolve_controllers``, so every case stubs it."""

from types import SimpleNamespace
from typing import Any

from services.governance.principals import (
    resolve_terminal_principal,
)

SAFE = "0x" + "a" * 40
EOA = "0x" + "b" * 40
CONTRACT_A = "0x" + "1" * 40
CONTRACT_B = "0x" + "2" * 40
CONTRACT_C = "0x" + "3" * 40


def _dict_resolver(edges):

    def _resolve(address):
        val = edges.get(address.lower())
        if val is None:
            return None
        return val if isinstance(val, list) else [val]

    return _resolve


def test_unresolved_intermediate_fails_closed():
    # An unknown intermediate must not be guessed as terminal.
    resolver = _dict_resolver({CONTRACT_A: {"address": CONTRACT_B, "resolved_type": "unknown", "details": {}}})
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["terminal"] is False
    assert record["resolved_type"] == "unknown"
    assert record["status"] == "unknown_unfetched"


def test_cycle_detected():
    resolver = _dict_resolver(
        {
            CONTRACT_A: {"address": CONTRACT_B, "resolved_type": "contract", "details": {}},
            CONTRACT_B: {"address": CONTRACT_A, "resolved_type": "contract", "details": {}},
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["terminal"] is False
    assert record["status"] == "cycle"
    assert record["chain"] == [CONTRACT_A, CONTRACT_B, CONTRACT_A]


def test_depth_bound():
    resolver = _dict_resolver(
        {
            CONTRACT_A: {"address": CONTRACT_B, "resolved_type": "contract", "details": {}},
            CONTRACT_B: {"address": CONTRACT_C, "resolved_type": "contract", "details": {}},
            CONTRACT_C: {"address": SAFE, "resolved_type": "safe", "details": {}},
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver, max_depth=2)
    assert record["terminal"] is False
    assert record["status"] == "depth_exceeded"
    ok = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver, max_depth=4)
    assert ok["terminal"] is True
    assert ok["address"] == SAFE


def test_multi_plane_two_planes_terminating_at_different_keys():
    # Distinct control planes are never collapsed to one key.
    resolver = _dict_resolver(
        {
            CONTRACT_A: [
                {"address": SAFE, "resolved_type": "safe", "details": {}},
                {"address": EOA, "resolved_type": "eoa", "details": {}},
            ]
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["terminal"] is False
    assert record["resolved_type"] == "unknown"
    assert record["address"] is None
    assert record["status"] == "multi_plane"
    assert record["controllers"] == [SAFE, EOA]  # owner/authority order preserved
    assert [p["controller"] for p in record["planes"]] == [SAFE, EOA]
    r0, r1 = record["planes"][0]["terminal_record"], record["planes"][1]["terminal_record"]
    assert (r0["terminal"], r0["address"], r0["status"]) == (True, SAFE, "terminated")
    assert (r1["terminal"], r1["address"], r1["status"]) == (True, EOA, "terminated")


def test_multi_plane_nested_fork_fails_that_plane_closed_no_explosion():
    # A forking plane fails closed rather than re-branching.
    resolver = _dict_resolver(
        {
            CONTRACT_A: [
                {"address": SAFE, "resolved_type": "safe", "details": {}},
                {"address": CONTRACT_B, "resolved_type": "contract", "details": {}},
            ],
            CONTRACT_B: [
                {"address": CONTRACT_C, "resolved_type": "safe", "details": {}},
                {"address": EOA, "resolved_type": "eoa", "details": {}},
            ],
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["status"] == "multi_plane"
    nested = record["planes"][1]["terminal_record"]
    assert nested["status"] == "ambiguous_controllers"
    assert nested["controllers"] == [CONTRACT_C, EOA]
    assert "planes" not in nested  # no sub-plane recursion


def test_already_terminal_start_short_circuits():
    called = {"n": 0}

    def _resolver(_addr):
        called["n"] += 1
        return None

    record = resolve_terminal_principal(SAFE, "safe", resolve_controllers=_resolver)
    assert record["terminal"] is True
    assert record["resolved_type"] == "safe"
    assert called["n"] == 0  # never walked


def _fp(address, resolved_type, *, details=None, principal_type="authority_role", origin="role 1") -> Any:
    return SimpleNamespace(
        address=address,
        resolved_type=resolved_type,
        details=details,
        principal_type=principal_type,
        origin=origin,
    )


# "No such controller" and "read failed" used to be one answer (1,556 rows).


def test_no_controller_token_has_no_producer():
    """R2: the proven-absence token has no producer."""
    shapes = [
        lambda _a: [],
        lambda _a: None,
        lambda _a: [{"resolved_type": "contract"}],  # unusable steps
        _dict_resolver({CONTRACT_A.lower(): {"address": EOA, "resolved_type": "eoa", "details": {}}}),
    ]
    for resolver in shapes:
        record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
        assert record["status"] != "no_controller"


def test_policy_worker_resolver_keeps_error_and_absence_apart():
    """``if not controllers: return None`` collapsed both answers onto ``None``."""
    import workers.policy_worker as pw

    calls: dict[str, object] = {}

    def _fake_read(rpc_url, address, *, chain_id=None):
        return calls["value"]

    original_read = pw.read_contract_controllers
    original_classify = pw.classify_resolved_address_with_status
    pw.read_contract_controllers = _fake_read
    pw.classify_resolved_address_with_status = lambda rpc_url, address, chain_id=None: ("eoa", {}, True)
    try:
        resolver = pw._make_terminal_controller_resolver("http://rpc.example", chain_id=1)
        assert resolver is not None

        calls["value"] = None  # probe error
        assert resolver(CONTRACT_A) is None

        calls["value"] = []  # probed clean, no controller
        assert resolver(CONTRACT_A) == []

        calls["value"] = [EOA]  # a real controller
        steps = resolver(CONTRACT_A)
        assert steps is not None
        assert [step["address"] for step in steps] == [EOA]
    finally:
        pw.read_contract_controllers = original_read
        pw.classify_resolved_address_with_status = original_classify
