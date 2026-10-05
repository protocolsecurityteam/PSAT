import pytest

from db.models import (
    EDGE_RELATION_CONTROLLER_VALUE,
    EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED,
)
from services.policy.principal_enrichment import build_principal_labels
from tests.support.isolation import _reset_executor  # noqa: F401  (fixture, registered by import)


def test_build_principal_labels_enriches_safe_admin_and_operator(monkeypatch):
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "BoringVault",
        "functions": [
            {
                "function": "manage(address,bytes,uint256)",
                "effect_labels": ["arbitrary_external_call"],
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
                "effect_labels": ["authority_update"],
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
    """Legacy effect_labels are ignored when claims are present."""
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
            _role_fn(
                "swap(uint256)",
                5,
                precedence_addr,
                claims=[_claim("flow.out")],
                effect_labels=["ownership_transfer"],
            ),
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
    assert "vault_admin" in principals[hook_admin]
    assert "vault_operator" in principals[precedence_addr]
    assert "vault_admin" not in principals[precedence_addr]
    assert "vault_admin" in principals[ctrl_admin]
    assert "vault_manager" in principals[ctrl_manager]


def test_build_principal_labels_tags_transfer_policy_setters_as_config(monkeypatch):
    """A config write is control-plane, but neither admin nor operator."""
    setter = "0x" + "c1" * 20
    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Token",
        "functions": [
            _role_fn(
                "setTransferPolicy(address)", 4, setter, claims=[_claim("transfer_policy.configure", "policy_derived")]
            )
        ],
    }
    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_labels(effective_permissions, rpc_url="http://rpc.example")
    labels = next(set(item["labels"]) for item in payload["principals"] if item["address"] == setter)

    assert "token_config" in labels
    assert not labels & {"token_admin", "token_operator", "token_manager"}


def test_build_principal_labels_ignores_labels_without_claims(monkeypatch):
    """Effect labels are display-only: a claim-less function earns no tag whatever it is labelled."""
    labelled_owner = "0x" + "b1" * 20
    claimed_owner = "0x" + "b2" * 20
    labelled_withdrawer = "0x" + "b3" * 20

    effective_permissions = {
        "contract_address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Vault",
        "functions": [
            _role_fn("transferOwnership(address)", 1, labelled_owner, claims=[], effect_labels=["ownership_transfer"]),
            _role_fn(
                "transferOwnership(address)",
                2,
                claimed_owner,
                claims=[_claim("ownership.transfer")],
                effect_labels=["ownership_transfer"],
            ),
            _role_fn(
                "withdraw(uint256)", 3, labelled_withdrawer, effect_labels=["asset_send", "arbitrary_external_call"]
            ),
        ],
    }

    monkeypatch.setattr(
        "services.policy.principal_enrichment.classify_resolved_address_with_status",
        lambda rpc_url, address, **_kw: ("eoa", {"address": address}, True),
    )

    payload = build_principal_labels(effective_permissions, rpc_url="http://rpc.example")
    principals = {item["address"]: set(item["labels"]) for item in payload["principals"]}

    for addr in (labelled_owner, labelled_withdrawer):
        assert not principals[addr] & {"vault_admin", "vault_operator", "vault_manager", "vault_config"}, addr
    assert "vault_admin" in principals[claimed_owner]


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


# The per-job classify cache must stay consistent across threads.


def _principal_labels_parity_helper(monkeypatch, fanout: str):
    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)

    target = "0x1111111111111111111111111111111111111111"
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
                "claims": [_claim("exec.arbitrary")],
                "authority_public": False,
                "authority_roles": [{"role": 1, "principals": role_principals(principal_addrs[:30])}],
                "direct_owner": None,
            },
            {
                "function": "setAuthority(address)",
                "effect_labels": ["authority_update"],
                "claims": [_claim("authority.replace")],
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
    seq_principals, seq_cache, seq_calls = _principal_labels_parity_helper(monkeypatch, "1")
    par_principals, par_cache, par_calls = _principal_labels_parity_helper(monkeypatch, "8")
    assert seq_principals == par_principals
    assert seq_cache == par_cache
    # At most one duplicate per address from a benign double-miss race.
    assert par_calls <= seq_calls + len(seq_cache)


def test_build_principal_labels_parallel_handles_per_address_runtimeerror(monkeypatch):
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
    """The conflation labelled the ETH2 deposit contract a controller of StakingManager; callees get ``call_target``
    only.
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


def test_unattributed_edge_does_not_mint_controller_labels():
    """Its provenance was never answered, so the edge moves no authority.

    This holds by fall-through today; the pin stops a future arm re-admitting it.
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
            "analyzed": address == target,
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

    payload = build_principal_labels(
        {"contract_address": target, "contract_name": "Vault", "functions": []},
        resolved_control_graph=resolved_graph,
    )
    principals = {item["address"]: item for item in payload["principals"]}

    gate_labels = set(principals[gate]["labels"])
    assert "controller_value" in gate_labels
    assert "controller_legacyauthority" not in gate_labels
    assert "controller_roleregistry" in gate_labels

    unattributed_labels = set(principals[unattributed]["labels"])
    assert not any(label.startswith("controller_") for label in unattributed_labels)
    assert "controller_value" not in unattributed_labels
    assert "authority_controller" not in unattributed_labels
    assert "owner_controller" not in unattributed_labels
    assert "call_target" not in unattributed_labels


def test_authority_roles_present_with_none_does_not_crash_enrichment():
    """``dict.get(key, [])`` only defaults an absent key, so a present ``None`` used to be iterated."""
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


def test_enriched_role_grant_keeps_the_classified_quorum_witness():
    """The grant's ``details`` marker used to erase the classified quorum, dropping a 2/3 Safe to the 0.55 unknown
    floor; details merge key-wise.
    """
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
    assert merged["details"]["owners"] == ["0x1", "0x2", "0x3"]
    assert merged["details"]["threshold"] == 2
    assert merged["details"]["source"] == "semantic_capability:role_grant"


def test_enriched_role_grant_details_fallbacks():
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
