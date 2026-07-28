import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from services.policy.principal_enrichment import build_principal_labels
from utils.concurrency import RpcExecutor


@pytest.fixture(autouse=True)
def _reset_executor():
    """``PSAT_RPC_FANOUT`` flips per test must rebuild the shared pool."""
    RpcExecutor.reset_for_tests()
    yield
    RpcExecutor.reset_for_tests()


def test_build_principal_labels_enriches_safe_admin_and_operator(monkeypatch):
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "BoringVault",
        "functions": [
            {
                "function": "manage(address,bytes,uint256)",
                "effect_labels": ["arbitrary_external_call"],
                "authority_public": False,
                "authority_roles": [
                    {
                        "role": 1,
                        "principals": [
                            {
                                "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "resolved_type": "unknown",
                                "details": {},
                            }
                        ],
                    }
                ],
                "direct_owner": None,
            },
            {
                "function": "setAuthority(address)",
                "effect_labels": ["authority_update"],
                "authority_public": False,
                "authority_roles": [
                    {
                        "role": 8,
                        "principals": [
                            {
                                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                "resolved_type": "safe",
                                "details": {
                                    "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                    "owners": [
                                        "0xcccccccccccccccccccccccccccccccccccccccc",
                                        "0xdddddddddddddddddddddddddddddddddddddddd",
                                    ],
                                    "threshold": 2,
                                },
                            }
                        ],
                    }
                ],
                "direct_owner": None,
            },
        ],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:0x1111111111111111111111111111111111111111",
                "address": "0x1111111111111111111111111111111111111111",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "BoringVault",
                "contract_name": "BoringVault",
                "depth": 0,
                "analyzed": True,
                "details": {"address": "0x1111111111111111111111111111111111111111"},
                "artifacts": {},
            },
            {
                "id": "address:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "node_type": "principal",
                "resolved_type": "safe",
                "label": "owner",
                "contract_name": None,
                "depth": 2,
                "analyzed": False,
                "details": {
                    "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "owners": [
                        "0xcccccccccccccccccccccccccccccccccccccccc",
                        "0xdddddddddddddddddddddddddddddddddddddddd",
                    ],
                    "threshold": 2,
                },
                "artifacts": {},
            },
        ],
        "edges": [
            {
                "from_id": "address:0x1111111111111111111111111111111111111111",
                "to_id": "address:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "relation": "controller_value",
                "label": "owner",
                "source_controller_id": "state_variable:owner",
                "notes": [],
            }
        ],
    }

    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_labels(
        effective_permissions,
        resolved_control_graph=resolved_graph,
        rpc_url="http://rpc.example",
    )

    principals = {item["address"]: item for item in payload["principals"]}

    manage_principal = principals["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert manage_principal["resolved_type"] == "eoa"
    assert manage_principal["display_name"] == "BoringVault manager"
    assert "boringvault_manager" in manage_principal["labels"]
    assert "boringvault_role_1_holder" in manage_principal["labels"]

    admin_safe = principals["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    assert admin_safe["resolved_type"] == "safe"
    assert admin_safe["display_name"] == "BoringVault admin Safe"
    assert "boringvault_admin" in admin_safe["labels"]
    assert "safe_multisig" in admin_safe["labels"]


def _role_fn(name: str, role: int, principal_addr: str, *, claims=None, effect_labels=None) -> dict:
    """One authority-role-gated function granting ``principal_addr`` a role."""
    fn: dict = {
        "function": name,
        "effect_labels": list(effect_labels or []),
        "authority_public": False,
        "authority_roles": [
            {
                "role": role,
                "principals": [{"address": principal_addr, "resolved_type": "unknown", "details": {}}],
            }
        ],
        "direct_owner": None,
    }
    if claims is not None:
        fn["claims"] = claims
    return fn


def _claim(claim_id: str, tier: str = "standard_exact") -> dict:
    return {"claim_id": claim_id, "tier": tier, "witness": {}}


def test_build_principal_labels_derives_enrichment_tags_from_claims(monkeypatch):
    """Plane-1 claim families drive the admin/operator/manager tags: control-plane
    (incl. ``callee_pointer.rotate`` and ``safe.*``) → admin, flow/supply →
    operator, ``exec.arbitrary`` → manager. Legacy effect_labels on the same rows
    are ignored when claims are present (claims-first)."""
    admin_safe = "0x" + "a1" * 20
    operator_addr = "0x" + "a2" * 20
    manager_addr = "0x" + "a3" * 20
    hook_admin = "0x" + "a4" * 20
    precedence_addr = "0x" + "a5" * 20
    ctrl_admin = "0x" + "a6" * 20
    ctrl_manager = "0x" + "a7" * 20

    def _controller_fn(name: str, principal_addr: str, claims: list[dict]) -> dict:
        return {
            "function": name,
            "effect_labels": [],
            "claims": claims,
            "authority_public": False,
            "authority_roles": [],
            "direct_owner": None,
            "controllers": [
                {
                    "controller_id": "state_variable:admin",
                    "label": "admin",
                    "source": "admin",
                    "kind": "state_variable",
                    "principals": [
                        {"address": principal_addr, "resolved_type": "eoa", "details": {"address": principal_addr}}
                    ],
                }
            ],
        }

    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Vault",
        "functions": [
            _role_fn("addSigner(address)", 1, admin_safe, claims=[_claim("safe.signer_mgmt")]),
            _role_fn("withdraw(uint256)", 2, operator_addr, claims=[_claim("flow.out")]),
            _role_fn("manage(address,bytes,uint256)", 3, manager_addr, claims=[_claim("exec.arbitrary")]),
            _role_fn("setHook(address)", 4, hook_admin, claims=[_claim("callee_pointer.rotate")]),
            # Claims present (flow.out → operator) must win over the legacy
            # ownership_transfer label (which would otherwise imply admin).
            _role_fn(
                "swap(uint256)",
                5,
                precedence_addr,
                claims=[_claim("flow.out")],
                effect_labels=["ownership_transfer"],
            ),
            # Controller-path principals also earn admin/manager from claims.
            _controller_fn("upgradeTo(address)", ctrl_admin, [_claim("upgrade.implementation")]),
            _controller_fn("execute(address,bytes)", ctrl_manager, [_claim("exec.arbitrary")]),
        ],
    }

    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_labels(effective_permissions, rpc_url="http://rpc.example")
    principals = {item["address"]: set(item["labels"]) for item in payload["principals"]}

    assert "vault_admin" in principals[admin_safe]
    assert "vault_operator" in principals[operator_addr]
    assert "vault_manager" in principals[manager_addr]
    # The precise use-link idiom (formerly the diluted hook_update) IS an admin.
    assert "vault_admin" in principals[hook_admin]
    # Claims-first: flow.out grants operator; the legacy ownership label is not
    # consulted, so no admin tag leaks in.
    assert "vault_operator" in principals[precedence_addr]
    assert "vault_admin" not in principals[precedence_addr]
    # Controller-path principals (state-variable controllers): admin + manager,
    # never operator (the pre-claims controller-path parity).
    assert "vault_admin" in principals[ctrl_admin]
    assert "vault_manager" in principals[ctrl_manager]


def test_build_principal_labels_legacy_hook_update_not_admin(monkeypatch):
    """A claim-less row falls back to legacy effect_labels, but ``hook_update`` is
    dropped from the admin set — no measured prod principal depends on it."""
    hook_addr = "0x" + "b1" * 20
    real_admin = "0x" + "b2" * 20
    legacy_operator = "0x" + "b3" * 20

    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Vault",
        "functions": [
            # No ``claims`` key → legacy fallback. hook_update must NOT grant admin.
            _role_fn("setHook(address)", 1, hook_addr, effect_labels=["hook_update"]),
            # A real legacy admin label still grants admin via the fallback.
            _role_fn("transferOwnership(address)", 2, real_admin, effect_labels=["ownership_transfer"]),
            # Legacy asset label → operator via the fallback.
            _role_fn("withdraw(uint256)", 3, legacy_operator, effect_labels=["asset_send"]),
        ],
    }

    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_labels(effective_permissions, rpc_url="http://rpc.example")
    principals = {item["address"]: set(item["labels"]) for item in payload["principals"]}

    assert "vault_admin" not in principals[hook_addr]
    assert "vault_operator" not in principals[hook_addr]
    assert "vault_manager" not in principals[hook_addr]
    assert "vault_admin" in principals[real_admin]
    assert "vault_operator" in principals[legacy_operator]


def test_build_principal_labels_with_resolved_graph_admin_safe():
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Target",
        "functions": [
            {
                "function": "setAuthority(address)",
                "effect_labels": ["authority_update"],
                "authority_public": False,
                "authority_roles": [
                    {
                        "role": 8,
                        "principals": [
                            {
                                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                "resolved_type": "safe",
                                "details": {
                                    "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                    "owners": ["0xcccccccccccccccccccccccccccccccccccccccc"],
                                    "threshold": 1,
                                },
                            }
                        ],
                    }
                ],
                "direct_owner": None,
            }
        ],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:0x1111111111111111111111111111111111111111",
                "address": "0x1111111111111111111111111111111111111111",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Target",
                "contract_name": "Target",
                "depth": 0,
                "analyzed": True,
                "details": {"address": "0x1111111111111111111111111111111111111111"},
                "artifacts": {},
            },
            {
                "id": "address:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "node_type": "principal",
                "resolved_type": "safe",
                "label": "owner",
                "contract_name": None,
                "depth": 1,
                "analyzed": False,
                "details": {
                    "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "owners": ["0xcccccccccccccccccccccccccccccccccccccccc"],
                    "threshold": 1,
                },
                "artifacts": {},
            },
        ],
        "edges": [
            {
                "from_id": "address:0x1111111111111111111111111111111111111111",
                "to_id": "address:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "relation": "controller_value",
                "label": "owner",
                "source_controller_id": "state_variable:owner",
                "notes": [],
            }
        ],
    }

    payload = build_principal_labels(effective_permissions, resolved_control_graph=resolved_graph)

    assert payload["contract_name"] == "Target"
    principals = {item["address"]: item for item in payload["principals"]}
    assert principals["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]["display_name"] == "Target admin Safe"


def test_build_principal_labels_includes_generic_controller_principals(monkeypatch):
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Target",
        "functions": [
            {
                "function": "pause()",
                "effect_labels": ["pause_toggle"],
                "authority_public": False,
                "authority_roles": [],
                "direct_owner": None,
                "controllers": [
                    {
                        "controller_id": "state_variable:governance",
                        "label": "governance",
                        "source": "governance",
                        "kind": "state_variable",
                        "principals": [
                            {
                                "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "resolved_type": "eoa",
                                "details": {"address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            }
                        ],
                        "notes": [],
                    }
                ],
            }
        ],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:0x1111111111111111111111111111111111111111",
                "address": "0x1111111111111111111111111111111111111111",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Target",
                "contract_name": "Target",
                "depth": 0,
                "analyzed": True,
                "details": {"address": "0x1111111111111111111111111111111111111111"},
                "artifacts": {},
            },
            {
                "id": "address:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "node_type": "principal",
                "resolved_type": "eoa",
                "label": "governance",
                "contract_name": None,
                "depth": 1,
                "analyzed": False,
                "details": {"address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "artifacts": {},
            },
        ],
        "edges": [
            {
                "from_id": "address:0x1111111111111111111111111111111111111111",
                "to_id": "address:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "relation": "controller_value",
                "label": "governance",
                "source_controller_id": "state_variable:governance",
                "notes": [],
            }
        ],
    }

    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_labels(
        effective_permissions,
        resolved_control_graph=resolved_graph,
        rpc_url="http://rpc.example",
    )

    principals = {item["address"]: item for item in payload["principals"]}
    governance = principals["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert governance["display_name"] == "Target governance"
    assert "target_controller_governance" in governance["labels"]
    assert governance["controller_context"] == ["governance"]


def test_build_principal_labels_prefers_analyzed_contract_name_for_contract_principals():
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Target",
        "functions": [],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:0x1111111111111111111111111111111111111111",
                "address": "0x1111111111111111111111111111111111111111",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Target",
                "contract_name": "Target",
                "depth": 0,
                "analyzed": True,
                "details": {"address": "0x1111111111111111111111111111111111111111"},
                "artifacts": {},
            },
            {
                "id": "address:0x2222222222222222222222222222222222222222",
                "address": "0x2222222222222222222222222222222222222222",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "role principal",
                "contract_name": "Executor",
                "depth": 1,
                "analyzed": True,
                "details": {"address": "0x2222222222222222222222222222222222222222"},
                "artifacts": {},
            },
        ],
        "edges": [
            {
                "from_id": "address:0x1111111111111111111111111111111111111111",
                "to_id": "address:0x2222222222222222222222222222222222222222",
                "relation": "controller_value",
                "label": "governance",
                "source_controller_id": "state_variable:governance",
                "notes": [],
            }
        ],
    }

    payload = build_principal_labels(
        effective_permissions,
        resolved_control_graph=resolved_graph,
    )

    principals = {item["address"]: item for item in payload["principals"]}
    assert principals["0x2222222222222222222222222222222222222222"]["display_name"] == "Executor"


def test_build_principal_labels_uses_graph_context_for_unnamed_contract_principals():
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Target",
        "functions": [],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:0x1111111111111111111111111111111111111111",
                "address": "0x1111111111111111111111111111111111111111",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Target",
                "contract_name": "Target",
                "depth": 0,
                "analyzed": True,
                "details": {"address": "0x1111111111111111111111111111111111111111"},
                "artifacts": {},
            },
            {
                "id": "address:0x3333333333333333333333333333333333333333",
                "address": "0x3333333333333333333333333333333333333333",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "role principal",
                "contract_name": None,
                "depth": 1,
                "analyzed": False,
                "details": {"address": "0x3333333333333333333333333333333333333333"},
                "artifacts": {},
            },
        ],
        "edges": [
            {
                "from_id": "address:0x4444444444444444444444444444444444444444",
                "to_id": "address:0x3333333333333333333333333333333333333333",
                "relation": "controller_value",
                "label": "token",
                "source_controller_id": "state_variable:token",
                "notes": [],
            }
        ],
    }
    resolved_graph["nodes"].append(
        {
            "id": "address:0x4444444444444444444444444444444444444444",
            "address": "0x4444444444444444444444444444444444444444",
            "node_type": "contract",
            "resolved_type": "contract",
            "label": "TokenManager",
            "contract_name": "TokenManager",
            "depth": 0,
            "analyzed": True,
            "details": {"address": "0x4444444444444444444444444444444444444444"},
            "artifacts": {},
        }
    )

    payload = build_principal_labels(
        effective_permissions,
        resolved_control_graph=resolved_graph,
    )

    principals = {item["address"]: item for item in payload["principals"]}
    assert principals["0x3333333333333333333333333333333333333333"]["display_name"] == "TokenManager token"


def test_build_principal_labels_skips_nonterminal_contract_principals():
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Target",
        "functions": [],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:0x1111111111111111111111111111111111111111",
                "address": "0x1111111111111111111111111111111111111111",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Target",
                "contract_name": "Target",
                "depth": 0,
                "analyzed": True,
                "details": {"address": "0x1111111111111111111111111111111111111111"},
                "artifacts": {},
            },
            {
                "id": "address:0x2222222222222222222222222222222222222222",
                "address": "0x2222222222222222222222222222222222222222",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Executor",
                "contract_name": "Executor",
                "depth": 1,
                "analyzed": True,
                "details": {"address": "0x2222222222222222222222222222222222222222"},
                "artifacts": {},
            },
            {
                "id": "address:0x3333333333333333333333333333333333333333",
                "address": "0x3333333333333333333333333333333333333333",
                "node_type": "principal",
                "resolved_type": "safe",
                "label": "owner",
                "contract_name": None,
                "depth": 2,
                "analyzed": False,
                "details": {
                    "address": "0x3333333333333333333333333333333333333333",
                    "owners": ["0x4444444444444444444444444444444444444444"],
                    "threshold": 1,
                },
                "artifacts": {},
            },
        ],
        "edges": [
            {
                "from_id": "address:0x1111111111111111111111111111111111111111",
                "to_id": "address:0x2222222222222222222222222222222222222222",
                "relation": "controller_value",
                "label": "adminExecutor",
                "source_controller_id": "state_variable:adminExecutor",
                "notes": [],
            },
            {
                "from_id": "address:0x2222222222222222222222222222222222222222",
                "to_id": "address:0x3333333333333333333333333333333333333333",
                "relation": "controller_value",
                "label": "owner",
                "source_controller_id": "state_variable:owner",
                "notes": [],
            },
        ],
    }

    payload = build_principal_labels(
        effective_permissions,
        resolved_control_graph=resolved_graph,
    )

    principals = {item["address"]: item for item in payload["principals"]}
    assert "0x2222222222222222222222222222222222222222" not in principals
    assert "0x3333333333333333333333333333333333333333" in principals


def test_build_principal_labels_skips_permission_controller_contract_principals():
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Target",
        "functions": [],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:0x1111111111111111111111111111111111111111",
                "address": "0x1111111111111111111111111111111111111111",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Target",
                "contract_name": "Target",
                "depth": 0,
                "analyzed": True,
                "details": {"address": "0x1111111111111111111111111111111111111111"},
                "artifacts": {},
            },
            {
                "id": "address:0x2222222222222222222222222222222222222222",
                "address": "0x2222222222222222222222222222222222222222",
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "PermissionController",
                "contract_name": "PermissionController",
                "depth": 1,
                "analyzed": True,
                "details": {
                    "address": "0x2222222222222222222222222222222222222222",
                    "controller_label": "permissionController",
                },
                "artifacts": {},
            },
        ],
        "edges": [
            {
                "from_id": "address:0x1111111111111111111111111111111111111111",
                "to_id": "address:0x2222222222222222222222222222222222222222",
                "relation": "controller_value",
                "label": "permissionController",
                "source_controller_id": "external_contract:permissionController",
                "notes": [],
            }
        ],
    }

    payload = build_principal_labels(
        effective_permissions,
        resolved_control_graph=resolved_graph,
    )

    principals = {item["address"]: item for item in payload["principals"]}
    assert "0x2222222222222222222222222222222222222222" not in principals


# ---------------------------------------------------------------------------
# Parity: ``build_principal_labels`` produces identical output under
# ``PSAT_RPC_FANOUT=1`` (sequential) and ``=8`` (parallel). The per-job
# ``classify_cache`` must stay consistent across worker threads.
# ---------------------------------------------------------------------------


def _principal_labels_parity_helper(monkeypatch, fanout: str):
    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)

    target = "0x1111111111111111111111111111111111111111"
    # 60 distinct principal addresses: enough to fan out across 8 workers
    # multiple times and stress the classify_cache lock.
    principal_addrs = [f"0x{(i + 0x10):040x}" for i in range(60)]

    def role_principals(addrs):
        return [{"address": a, "resolved_type": "unknown", "details": {}} for a in addrs]

    effective_permissions = {
        "contract_address": target,
        "contract_name": "VaultBig",
        "functions": [
            {
                "function": "manage(address,bytes,uint256)",
                "effect_labels": ["arbitrary_external_call"],
                "authority_public": False,
                "authority_roles": [{"role": 1, "principals": role_principals(principal_addrs[:30])}],
                "direct_owner": None,
            },
            {
                "function": "setAuthority(address)",
                "effect_labels": ["authority_update"],
                "authority_public": False,
                "authority_roles": [{"role": 8, "principals": role_principals(principal_addrs[30:])}],
                "direct_owner": None,
            },
        ],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:" + target,
                "address": target,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "VaultBig",
                "contract_name": "VaultBig",
                "depth": 0,
                "analyzed": True,
                "details": {"address": target},
                "artifacts": {},
            }
        ],
        "edges": [],
    }

    # Counter is bumped every classify call so we can assert the cache
    # collapses repeated lookups even under fan-out (a benign double-miss
    # race may cost at most one extra call per address).
    call_counter = {"n": 0}

    def fake_classify(rpc_url, address, **_kw):
        call_counter["n"] += 1
        return "eoa", {"address": address}, True

    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        fake_classify,
    )

    classify_cache: dict = {}
    payload = build_principal_labels(
        effective_permissions,
        resolved_control_graph=resolved_graph,
        rpc_url="http://rpc.example",
        classify_cache=classify_cache,
    )

    canonical = sorted(
        (
            (
                p["address"],
                p["resolved_type"],
                p["display_name"],
                tuple(p["labels"]),
                p["confidence"],
                tuple(p["graph_context"]),
                tuple(p["controller_context"]),
                tuple((perm["function"], perm["role"], perm.get("controller")) for perm in p["permissions"]),
            )
            for p in payload["principals"]
        )
    )
    return canonical, dict(classify_cache), call_counter["n"]


def test_build_principal_labels_parity_parallel_vs_sequential(monkeypatch):
    """``PSAT_RPC_FANOUT=1`` and ``=8`` must produce identical principals + cache."""
    seq_principals, seq_cache, seq_calls = _principal_labels_parity_helper(monkeypatch, "1")
    par_principals, par_cache, par_calls = _principal_labels_parity_helper(monkeypatch, "8")
    assert seq_principals == par_principals
    assert seq_cache == par_cache
    # The per-job cache collapses repeated classifications even under fan-out.
    # Allow at most one duplicate per address from a benign double-miss race
    # (both threads see the cache empty before the first writes back).
    assert par_calls <= seq_calls + len(seq_cache)


def test_build_principal_labels_parallel_handles_per_address_runtimeerror(monkeypatch):
    """A classify error on one address must propagate, not silently drop principals."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", "8")
    target = "0x1111111111111111111111111111111111111111"
    bad_address = "0x" + "b" * 40
    principal_addrs = [f"0x{(i + 0x20):040x}" for i in range(5)] + [bad_address]
    effective_permissions = {
        "contract_address": target,
        "contract_name": "Vault",
        "functions": [
            {
                "function": "manage()",
                "effect_labels": ["arbitrary_external_call"],
                "authority_public": False,
                "authority_roles": [
                    {
                        "role": 1,
                        "principals": [
                            {"address": a, "resolved_type": "unknown", "details": {}} for a in principal_addrs
                        ],
                    }
                ],
                "direct_owner": None,
            }
        ],
    }
    resolved_graph = {
        "nodes": [
            {
                "id": "address:" + target,
                "address": target,
                "node_type": "contract",
                "resolved_type": "contract",
                "label": "Vault",
                "contract_name": "Vault",
                "depth": 0,
                "analyzed": True,
                "details": {"address": target},
                "artifacts": {},
            }
        ],
        "edges": [],
    }

    def fake_classify(rpc_url, address, **_kw):
        if address == bad_address:
            raise RuntimeError("classify boom")
        return "eoa", {"address": address}, True

    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        fake_classify,
    )

    with pytest.raises(RuntimeError, match="classify boom"):
        build_principal_labels(
            effective_permissions,
            resolved_control_graph=resolved_graph,
            rpc_url="http://rpc.example",
        )


def test_callee_edge_does_not_mint_controller_labels():
    """``principal_labels`` inherits the gate/callee split from the edge relation.

    G6-9: the same conflation surfaced here, labelling the Ethereum 2 deposit
    contract a *controller* of StakingManager and the Curve stETH/ETH pool a
    controller of Liquifier. Both are callees. Leg F makes the split once, at
    ``control_graph_edges.relation``; this file's producer switches on that
    field, so the fix reaches this plane without a second provenance rule.

    Positive control: the gate keeps ``controller_value`` /
    ``controller_<label>``. Negative control: the callee gets ``call_target``
    and NONE of the controller labels.
    """
    target = "0x1111111111111111111111111111111111111111"
    gate = "0x2222222222222222222222222222222222222222"
    callee = "0x3333333333333333333333333333333333333333"

    def _node(address: str, name: str) -> dict:
        return {
            "id": f"address:{address}",
            "address": address,
            "node_type": "contract",
            "resolved_type": "contract",
            "label": name,
            "contract_name": name,
            "depth": 0 if address == target else 1,
            "analyzed": address == target,
            "details": {"address": address},
            "artifacts": {},
        }

    resolved_graph = {
        "nodes": [_node(target, "StakingManager"), _node(gate, "RoleRegistry"), _node(callee, "DepositContract")],
        "edges": [
            {
                "from_id": f"address:{target}",
                "to_id": f"address:{gate}",
                "relation": "controller_value",
                "label": "roleRegistry",
                "source_controller_id": "external_contract:roleRegistry",
                "notes": ["authority_provenance=caller_gate"],
            },
            {
                "from_id": f"address:{target}",
                "to_id": f"address:{callee}",
                "relation": "external_call_target",
                "label": "depositContractEth2",
                "source_controller_id": "external_contract:depositContractEth2",
                "notes": ["authority_provenance=call_target"],
            },
        ],
    }

    payload = build_principal_labels(
        {"contract_address": target, "contract_name": "StakingManager", "functions": []},
        resolved_control_graph=resolved_graph,
    )
    principals = {item["address"]: item for item in payload["principals"]}

    gate_labels = set(principals[gate]["labels"])
    assert "controller_value" in gate_labels
    assert "controller_roleregistry" in gate_labels

    callee_labels = set(principals[callee]["labels"])
    assert "call_target" in callee_labels
    assert "stakingmanager_calls_depositcontracteth2" in callee_labels
    assert "controller_value" not in callee_labels
    assert not any(label.startswith("controller_") for label in callee_labels)


def test_authority_roles_present_with_none_does_not_crash_enrichment():
    """W2-B item 8 consumer guard: ``authority_roles`` is now PRESENT with value
    ``None`` on a role-gated function whose role identity is not determined, and
    ``dict.get(key, [])`` only supplies its default for an ABSENT key — so the
    plain default iterated ``None`` and raised. Not-determined must contribute no
    role principals, exactly as ``[]`` did."""
    from services.policy.principal_enrichment import _collect_permissions

    permissions, labels = _collect_permissions(
        {
            "contract_name": "Target",
            "contract_address": "0x" + "ab" * 20,
            "functions": [
                {
                    "function": "f()",
                    "effect_labels": [],
                    "authority_public": False,
                    "authority_roles": None,
                    "controllers": [],
                    "direct_owner": None,
                }
            ],
        }
    )
    assert permissions == {}
    assert labels == {}
