"""A4: contract-principal terminal resolution + non-terminal marking.

Covers the pure bounded/cycle-safe walk (``resolve_terminal_principal``) and the
governance-view non-terminal marking (``_function_principal_payload`` /
``_build_company_function_entry``) — SCORING plan §4. The walk's only wire is the
injected ``resolve_controllers`` callable, so every case here stubs it.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.governance.principals import (
    _build_company_function_entry,
    _function_principal_payload,
    is_terminal_principal_type,
    resolve_terminal_principal,
)

SAFE = "0x" + "a" * 40
EOA = "0x" + "b" * 40
CONTRACT_A = "0x" + "1" * 40
CONTRACT_B = "0x" + "2" * 40
CONTRACT_C = "0x" + "3" * 40


def _dict_resolver(edges):
    """address -> list[controller-step] from a plain adjacency dict; None when
    absent. A single-step value is wrapped so tests stay terse; a list value
    models parallel control planes."""

    def _resolve(address):
        val = edges.get(address.lower())
        if val is None:
            return None
        return val if isinstance(val, list) else [val]

    return _resolve


def test_is_terminal_principal_type():
    for terminal in ("safe", "eoa", "zero", "timelock", "proxy_admin", "cross_chain_authority"):
        assert is_terminal_principal_type(terminal) is True
    for non_terminal in ("contract", "unknown", "", None):
        assert is_terminal_principal_type(non_terminal) is False


def test_terminates_at_safe_controller():
    resolver = _dict_resolver({CONTRACT_A: {"address": SAFE, "resolved_type": "safe", "details": {"threshold": 2}}})
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["terminal"] is True
    assert record["resolved_type"] == "safe"
    assert record["address"] == SAFE
    assert record["status"] == "terminated"
    assert record["chain"] == [CONTRACT_A, SAFE]


def test_multi_hop_contract_chain_terminates():
    resolver = _dict_resolver(
        {
            CONTRACT_A: {"address": CONTRACT_B, "resolved_type": "contract", "details": {}},
            CONTRACT_B: {"address": EOA, "resolved_type": "eoa", "details": {}},
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["terminal"] is True
    assert record["resolved_type"] == "eoa"
    assert record["address"] == EOA
    assert record["chain"] == [CONTRACT_A, CONTRACT_B, EOA]


def test_unfetched_controller_is_unknown_not_resolved():
    # Resolver has nothing for CONTRACT_A -> the controller is unfetched/unverified.
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=_dict_resolver({}))
    assert record["terminal"] is False
    assert record["resolved_type"] == "unknown"
    assert record["address"] is None
    assert record["status"] == "unknown_unfetched"


def test_unresolved_intermediate_fails_closed():
    # An intermediate that classifies "unknown" (neither settled key nor walkable
    # contract) must not be guessed as terminal.
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
    # Same chain resolved with adequate depth terminates at the Safe.
    ok = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver, max_depth=4)
    assert ok["terminal"] is True
    assert ok["address"] == SAFE


def test_multi_plane_two_planes_terminating_at_different_keys():
    # Two distinct live control planes (Solmate/Solady Auth owner AND authority):
    # never collapse to one "the" key — walk each and record both.
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


def test_multi_plane_walks_each_contract_plane_to_its_own_terminal():
    # Both controllers are contracts that walk further to DIFFERENT Safes.
    resolver = _dict_resolver(
        {
            CONTRACT_A: [
                {"address": CONTRACT_B, "resolved_type": "contract", "details": {}},
                {"address": CONTRACT_C, "resolved_type": "contract", "details": {}},
            ],
            CONTRACT_B: [{"address": SAFE, "resolved_type": "safe", "details": {}}],
            CONTRACT_C: [{"address": EOA, "resolved_type": "eoa", "details": {}}],
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["status"] == "multi_plane"
    p_b, p_c = record["planes"]
    assert p_b["controller"] == CONTRACT_B
    assert p_b["terminal_record"]["address"] == SAFE
    assert p_b["terminal_record"]["chain"] == [CONTRACT_B, SAFE]
    assert p_c["terminal_record"]["address"] == EOA


def test_multi_plane_one_plane_unresolved_recorded_distinctly():
    # One plane is Safe-terminal, the other has no fetched controller -> each is
    # recorded honestly; the top level never claims a settled key.
    resolver = _dict_resolver(
        {
            CONTRACT_A: [
                {"address": SAFE, "resolved_type": "safe", "details": {}},
                {"address": CONTRACT_B, "resolved_type": "contract", "details": {}},
            ],
            # CONTRACT_B has no controllers -> unknown_unfetched
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["status"] == "multi_plane"
    assert record["terminal"] is False
    plane_safe, plane_unresolved = record["planes"]
    assert plane_safe["terminal_record"]["status"] == "terminated"
    assert plane_safe["terminal_record"]["address"] == SAFE
    assert plane_unresolved["terminal_record"]["status"] == "unknown_unfetched"
    assert plane_unresolved["terminal_record"]["address"] is None


def test_multi_plane_nested_fork_fails_that_plane_closed_no_explosion():
    # A plane that itself forks must NOT re-branch: it fails closed with
    # ambiguous_controllers and no nested `planes` key (bounded work).
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


def test_multi_plane_convergent_planes_not_collapsed():
    # Even when both planes converge on the SAME Safe, the walk records both
    # planes and stays terminal:false — collapsing is the scorer's call, not ours.
    resolver = _dict_resolver(
        {
            CONTRACT_A: [
                {"address": CONTRACT_B, "resolved_type": "contract", "details": {}},
                {"address": CONTRACT_C, "resolved_type": "contract", "details": {}},
            ],
            CONTRACT_B: [{"address": SAFE, "resolved_type": "safe", "details": {}}],
            CONTRACT_C: [{"address": SAFE, "resolved_type": "safe", "details": {}}],
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["status"] == "multi_plane"
    assert record["terminal"] is False
    assert record["address"] is None
    assert {p["terminal_record"]["address"] for p in record["planes"]} == {SAFE}


def test_two_getters_same_controller_not_ambiguous():
    # owner() and authority() naming the same address (case-insensitively) is one
    # controller — the walk proceeds with it, not flagged ambiguous.
    resolver = _dict_resolver(
        {
            CONTRACT_A: [
                {"address": SAFE, "resolved_type": "safe", "details": {}},
                {"address": SAFE.upper(), "resolved_type": "safe", "details": {}},
            ]
        }
    )
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["terminal"] is True
    assert record["status"] == "terminated"
    assert record["address"] == SAFE
    assert "controllers" not in record


def test_single_controller_plane_proceeds():
    # Regression guard for the sound single-plane case (owner only, no authority).
    resolver = _dict_resolver({CONTRACT_A: [{"address": SAFE, "resolved_type": "safe", "details": {}}]})
    record = resolve_terminal_principal(CONTRACT_A, "contract", resolve_controllers=resolver)
    assert record["terminal"] is True
    assert record["address"] == SAFE
    assert "controllers" not in record


def test_already_terminal_start_short_circuits():
    called = {"n": 0}

    def _resolver(_addr):
        called["n"] += 1
        return None

    record = resolve_terminal_principal(SAFE, "safe", resolve_controllers=_resolver)
    assert record["terminal"] is True
    assert record["resolved_type"] == "safe"
    assert called["n"] == 0  # never walked


# --- non-terminal marking on the governance per-function payload -------------


def _fp(address, resolved_type, *, details=None, principal_type="authority_role", origin="role 1") -> Any:
    return SimpleNamespace(
        address=address,
        resolved_type=resolved_type,
        details=details,
        principal_type=principal_type,
        origin=origin,
    )


def test_contract_principal_marked_non_terminal():
    payload = _function_principal_payload(_fp(CONTRACT_A, "contract"))
    assert payload["terminal"] is False


def test_safe_principal_marked_terminal():
    payload = _function_principal_payload(_fp(SAFE, "safe", details={"threshold": 2}))
    assert payload["terminal"] is True


def test_unknown_principal_marked_non_terminal():
    payload = _function_principal_payload(_fp(CONTRACT_A, None))
    assert payload["terminal"] is False


def test_terminal_principal_chain_surfaced_from_details():
    chain = {"terminal": True, "resolved_type": "safe", "address": SAFE, "chain": [CONTRACT_A, SAFE]}
    payload = _function_principal_payload(_fp(CONTRACT_A, "contract", details={"terminal_principal": chain}))
    assert payload["terminal"] is False  # the way-point itself is never a settled key
    assert payload["terminal_principal"] == chain


def test_lzcompose_style_permissionless_stays_blank_without_failure():
    """A permissionless function (authority_public, zero principals) must not be
    flagged as a resolution failure — blank is correct here (SCORING plan §4)."""
    ef = SimpleNamespace(
        abi_signature="lzCompose(address,bytes32,bytes,address,bytes)",
        function_name="lzCompose",
        selector="0x12345678",
        effect_labels=[],
        effect_targets=[],
        claims=[],
        action_summary=None,
        authority_public=True,
        authority_roles=None,
    )
    entry = _build_company_function_entry(cast(Any, ef), [])
    assert entry["authority_public"] is True
    assert entry["controllers"] == []
    assert entry["authority_roles"] == []
    assert entry["direct_owner"] is None
    # No principals, so no terminal marking is fabricated at the function level.
    assert "terminal" not in entry
