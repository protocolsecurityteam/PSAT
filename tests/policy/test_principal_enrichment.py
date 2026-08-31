import pytest

from db.models import (
    EDGE_RELATION_CONTROLLER_VALUE,
    EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED,
)
from services.concurrency import RpcExecutor
from services.policy.principal_index import build_principal_index


@pytest.fixture(autouse=True)
def _reset_executor():
    """``PSAT_RPC_FANOUT`` flips per test must rebuild the shared pool."""
    RpcExecutor.reset_for_tests()
    yield
    RpcExecutor.reset_for_tests()


def test_build_principal_index_enriches_safe_admin_and_operator(monkeypatch):
    permission_index = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "BoringVault",
        "functions": [
            {
                "function": "manage(address,bytes,uint256)",
                "claims": [_claim("exec.arbitrary")],
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
                "claims": [_claim("authority.replace")],
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
                "analysis_state": "analyzed",
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
                "analysis_state": None,
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
        "services.policy.principal_index.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_index(
        permission_index,
        resolution_graph=resolved_graph,
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


def _role_fn(name: str, role: int, principal_addr: str, *, claims=None) -> dict:
    """One authority-role-gated function granting ``principal_addr`` a role."""
    fn: dict = {
        "function": name,
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


def test_build_principal_index_derives_enrichment_tags_from_claims(monkeypatch):
    """Plane-1 claim families drive the admin/operator/manager tags: control-plane
    (incl. ``callee_pointer.rotate`` and ``safe.*``) → admin, flow/supply →
    operator, ``exec.arbitrary`` → manager
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

    permission_index = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Vault",
        "functions": [
            _role_fn("addSigner(address)", 1, admin_safe, claims=[_claim("safe.signer_mgmt")]),
            _role_fn("withdraw(uint256)", 2, operator_addr, claims=[_claim("flow.out")]),
            _role_fn("manage(address,bytes,uint256)", 3, manager_addr, claims=[_claim("exec.arbitrary")]),
            _role_fn("setHook(address)", 4, hook_admin, claims=[_claim("callee_pointer.rotate")]),
            # A flow claim grants operator authority without implying admin authority.
            _role_fn(
                "swap(uint256)",
                5,
                precedence_addr,
                claims=[_claim("flow.out")],
            ),
            # Controller-path principals also earn admin/manager from claims.
            _controller_fn("upgradeTo(address)", ctrl_admin, [_claim("upgrade.implementation")]),
            _controller_fn("execute(address,bytes)", ctrl_manager, [_claim("exec.arbitrary")]),
        ],
    }

    monkeypatch.setattr(
        "services.policy.principal_index.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_index(permission_index, rpc_url="http://rpc.example")
    principals = {item["address"]: set(item["labels"]) for item in payload["principals"]}

    assert "vault_admin" in principals[admin_safe]
    assert "vault_operator" in principals[operator_addr]
    assert "vault_manager" in principals[manager_addr]
    # The precise use-link idiom (formerly the diluted hook_update) IS an admin.
    assert "vault_admin" in principals[hook_admin]
    # Claims-first: flow.out grants operator; the unsupported ownership label is not
    # consulted, so no admin tag leaks in.
    assert "vault_operator" in principals[precedence_addr]
    assert "vault_admin" not in principals[precedence_addr]
    # Controller-path principals (state-variable controllers): admin + manager,
    # never operator (the pre-claims controller-path parity).
    assert "vault_admin" in principals[ctrl_admin]
    assert "vault_manager" in principals[ctrl_manager]


def test_build_principal_index_with_resolved_graph_admin_safe():
    permission_index = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Target",
        "functions": [
            {
                "function": "setAuthority(address)",
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
                "analysis_state": "analyzed",
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
                "analysis_state": None,
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

    payload = build_principal_index(permission_index, resolution_graph=resolved_graph)

    assert payload["contract_name"] == "Target"
    principals = {item["address"]: item for item in payload["principals"]}
    assert principals["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]["display_name"] == "Target owner Safe"


def test_build_principal_index_includes_generic_controller_principals(monkeypatch):
    permission_index = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Target",
        "functions": [
            {
                "function": "pause()",
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
                "analysis_state": "analyzed",
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
                "analysis_state": None,
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
        "services.policy.principal_index.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_index(
        permission_index,
        resolution_graph=resolved_graph,
        rpc_url="http://rpc.example",
    )

    principals = {item["address"]: item for item in payload["principals"]}
    governance = principals["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert governance["display_name"] == "Target governance"
    assert "target_controller_governance" in governance["labels"]
    assert governance["controller_context"] == ["governance"]


def test_build_principal_index_prefers_analyzed_contract_name_for_contract_principals():
    permission_index = {
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
                "analysis_state": "analyzed",
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
                "analysis_state": "analyzed",
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

    payload = build_principal_index(
        permission_index,
        resolution_graph=resolved_graph,
    )

    principals = {item["address"]: item for item in payload["principals"]}
    assert principals["0x2222222222222222222222222222222222222222"]["display_name"] == "Executor"


def test_build_principal_index_uses_graph_context_for_unnamed_contract_principals():
    permission_index = {
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
                "analysis_state": "analyzed",
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
                "analysis_state": None,
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
            "analysis_state": "analyzed",
            "details": {"address": "0x4444444444444444444444444444444444444444"},
            "artifacts": {},
        }
    )

    payload = build_principal_index(
        permission_index,
        resolution_graph=resolved_graph,
    )

    principals = {item["address"]: item for item in payload["principals"]}
    assert principals["0x3333333333333333333333333333333333333333"]["display_name"] == "TokenManager token"


def test_build_principal_index_skips_nonterminal_contract_principals():
    permission_index = {
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
                "analysis_state": "analyzed",
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
                "analysis_state": "analyzed",
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
                "analysis_state": None,
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

    payload = build_principal_index(
        permission_index,
        resolution_graph=resolved_graph,
    )

    principals = {item["address"]: item for item in payload["principals"]}
    assert "0x2222222222222222222222222222222222222222" not in principals
    assert "0x3333333333333333333333333333333333333333" in principals


def test_build_principal_index_skips_permission_controller_contract_principals():
    permission_index = {
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
                "analysis_state": "analyzed",
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
                "analysis_state": "analyzed",
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

    payload = build_principal_index(
        permission_index,
        resolution_graph=resolved_graph,
    )

    principals = {item["address"]: item for item in payload["principals"]}
    assert "0x2222222222222222222222222222222222222222" not in principals


# ---------------------------------------------------------------------------
# Parity: ``build_principal_index`` produces identical output under
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

    permission_index = {
        "contract_address": target,
        "contract_name": "VaultBig",
        "functions": [
            {
                "function": "manage(address,bytes,uint256)",
                "authority_public": False,
                "authority_roles": [{"role": 1, "principals": role_principals(principal_addrs[:30])}],
                "direct_owner": None,
            },
            {
                "function": "setAuthority(address)",
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
                "analysis_state": "analyzed",
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
        "services.policy.principal_index.classify_resolved_address_with_status",
        fake_classify,
    )

    classify_cache: dict = {}
    payload = build_principal_index(
        permission_index,
        resolution_graph=resolved_graph,
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


def test_build_principal_index_parity_parallel_vs_sequential(monkeypatch):
    """``PSAT_RPC_FANOUT=1`` and ``=8`` must produce identical principals + cache."""
    seq_principals, seq_cache, seq_calls = _principal_labels_parity_helper(monkeypatch, "1")
    par_principals, par_cache, par_calls = _principal_labels_parity_helper(monkeypatch, "8")
    assert seq_principals == par_principals
    assert seq_cache == par_cache
    # The per-job cache collapses repeated classifications even under fan-out.
    # Allow at most one duplicate per address from a benign double-miss race
    # (both threads see the cache empty before the first writes back).
    assert par_calls <= seq_calls + len(seq_cache)


def test_build_principal_index_parallel_handles_per_address_runtimeerror(monkeypatch):
    """A classify error on one address must propagate, not silently drop principals."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", "8")
    target = "0x1111111111111111111111111111111111111111"
    bad_address = "0x" + "b" * 40
    principal_addrs = [f"0x{(i + 0x20):040x}" for i in range(5)] + [bad_address]
    permission_index = {
        "contract_address": target,
        "contract_name": "Vault",
        "functions": [
            {
                "function": "manage()",
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
                "analysis_state": "analyzed",
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
        "services.policy.principal_index.classify_resolved_address_with_status",
        fake_classify,
    )

    with pytest.raises(RuntimeError, match="classify boom"):
        build_principal_index(
            permission_index,
            resolution_graph=resolved_graph,
            rpc_url="http://rpc.example",
        )


def test_callee_edge_does_not_mint_controller_labels():
    """``principal_labels`` inherits the gate/callee split from the edge relation.

    The conflation surfaced here as well, labelling the Ethereum 2 deposit
    contract a *controller* of StakingManager and the Curve stETH/ETH pool a
    controller of Liquifier. Both are callees. The split is made once, at
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
            "analysis_state": "analyzed" if address == target else None,
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

    payload = build_principal_index(
        {"contract_address": target, "contract_name": "StakingManager", "functions": []},
        resolution_graph=resolved_graph,
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


def test_unattributed_edge_does_not_mint_controller_labels():
    """``controller_value_unattributed`` must mint NO ``controller_*`` label.

    The relation means the tracked controller's ``authority_provenance`` was
    ABSENT — neither "gates callers" nor "is merely called" was answered. The
    edge exists only so the address stays visible; it moves no authority, so
    every label that asserts control has to stay off it.

    Today that holds by *fall-through*: ``_graph_labels_for_node`` has no arm for
    the relation. This test is the pin — a future arm added to that dispatch
    (however reasonable-looking) silently re-admits an unattributed edge to the
    controller vocabulary, which is the over-claim this relation was
    introduced to remove. Positive control: the sibling ``controller_value``
    edge on the same graph still earns the full controller label set, so a
    regression in the dispatch itself cannot pass by minting nothing at all.
    """
    target = "0x4444444444444444444444444444444444444444"
    gate = "0x5555555555555555555555555555555555555555"
    unattributed = "0x6666666666666666666666666666666666666666"

    def _node(address: str, name: str) -> dict:
        return {
            "id": f"address:{address}",
            "address": address,
            "node_type": "contract",
            "resolved_type": "contract",
            "label": name,
            "contract_name": name,
            "depth": 0 if address == target else 1,
            "analysis_state": "analyzed" if address == target else None,
            "details": {"address": address},
            "artifacts": {},
        }

    resolved_graph = {
        "nodes": [_node(target, "Vault"), _node(gate, "RoleRegistry"), _node(unattributed, "LegacyAuthority")],
        "edges": [
            {
                "from_id": f"address:{target}",
                "to_id": f"address:{gate}",
                "relation": EDGE_RELATION_CONTROLLER_VALUE,
                "label": "roleRegistry",
                "source_controller_id": "external_contract:roleRegistry",
                "notes": ["authority_provenance=caller_gate"],
            },
            {
                "from_id": f"address:{target}",
                "to_id": f"address:{unattributed}",
                "relation": EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED,
                "label": "legacyAuthority",
                "source_controller_id": "external_contract:legacyAuthority",
                "notes": ["authority_provenance=absent"],
            },
        ],
    }

    payload = build_principal_index(
        {"contract_address": target, "contract_name": "Vault", "functions": []},
        resolution_graph=resolved_graph,
    )
    principals = {item["address"]: item for item in payload["principals"]}

    # Positive control — the attributed gate keeps the whole controller set.
    gate_labels = set(principals[gate]["labels"])
    assert "controller_value" in gate_labels
    assert "controller_legacyauthority" not in gate_labels
    assert "controller_roleregistry" in gate_labels

    # The pin: not-determined provenance earns no control vocabulary at all.
    # ``call_target`` is equally forbidden — it is the OTHER proven answer, and
    # the relation exists precisely because neither was proven.
    unattributed_labels = set(principals[unattributed]["labels"])
    assert not any(label.startswith("controller_") for label in unattributed_labels)
    assert "controller_value" not in unattributed_labels
    assert "authority_controller" not in unattributed_labels
    assert "owner_controller" not in unattributed_labels
    assert "call_target" not in unattributed_labels


def test_authority_roles_present_with_none_does_not_crash_enrichment():
    """Consumer guard: ``authority_roles`` is now PRESENT with value
    ``None`` on a role-gated function whose role identity is not determined, and
    ``dict.get(key, [])`` only supplies its default for an ABSENT key — so the
    plain default iterated ``None`` and raised. Not-determined must contribute no
    role principals, exactly as ``[]`` did."""
    from services.policy.principal_index import _collect_permissions

    permissions, labels = _collect_permissions(
        {
            "contract_name": "Target",
            "contract_address": "0x" + "ab" * 20,
            "functions": [
                {
                    "function": "f()",
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


def test_enriched_role_grant_keeps_the_classified_quorum_witness():
    """``_enriched_role_grant`` exists so a role-granted principal
    reads as resolved as the same address under ``controllers`` — but the
    grant's ``details`` is ALWAYS the non-None ``{"source": ...}`` marker, so
    a blanket "grant's non-null fields override" replaced the classified
    ``details`` wholesale and erased the recorded quorum/delay.
    ``protocolScore.collectPrincipals`` dedups by address keeping the FIRST
    record (role grants before controllers), so the erased record is the one
    the scorer and ``principalLabel`` read: a recorded 2/3 Safe fell to the
    0.55 unknown floor and rendered without its "m/n". Details merge KEY-WISE,
    classified keys on top, grant-only keys (the source marker) surviving."""
    from services.governance.principals import _enriched_role_grant

    classified = {
        "0xaaa": {
            "address": "0xaaa",
            "resolved_type": "safe",
            "label": "Ops Safe",
            "details": {"owners": ["0x1", "0x2", "0x3"], "threshold": 2},
        }
    }
    grant = {
        "role": 8,
        "principals": [
            {"address": "0xaaa", "resolved_type": None, "details": {"source": "semantic_capability:role_grant"}}
        ],
    }
    merged = _enriched_role_grant(grant, classified)["principals"][0]
    assert merged["resolved_type"] == "safe"
    assert merged["label"] == "Ops Safe"
    # The quorum witness survives AND the grant's provenance marker survives.
    assert merged["details"]["owners"] == ["0x1", "0x2", "0x3"]
    assert merged["details"]["threshold"] == 2
    assert merged["details"]["source"] == "semantic_capability:role_grant"


def test_enriched_role_grant_details_fallbacks():
    """The two one-sided shapes: a classified record with no ``details`` keeps
    the grant's marker; a grant principal with no ``details`` keeps the
    classified witness untouched."""
    from services.governance.principals import _enriched_role_grant

    no_details_classified = {"0xaaa": {"address": "0xaaa", "resolved_type": "eoa"}}
    grant = {
        "role": 1,
        "principals": [{"address": "0xaaa", "details": {"source": "semantic_capability:role_grant"}}],
    }
    merged = _enriched_role_grant(grant, no_details_classified)["principals"][0]
    assert merged["details"] == {"source": "semantic_capability:role_grant"}
    assert merged["resolved_type"] == "eoa"

    classified = {"0xbbb": {"address": "0xbbb", "resolved_type": "timelock", "details": {"delay": 864000}}}
    bare_grant = {"role": 2, "principals": [{"address": "0xbbb", "details": None}]}
    merged = _enriched_role_grant(bare_grant, classified)["principals"][0]
    assert merged["details"] == {"delay": 864000}
