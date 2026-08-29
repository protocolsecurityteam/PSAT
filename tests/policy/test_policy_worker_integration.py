"""Integration tests for PolicyWorker — _resolve_authority() and process() flows."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
from tests.support.policy_builders import (
    AUTH_ADDRESS,
    TARGET_ADDRESS,
    ZERO_ADDRESS,
    _authority_bundle,
    _graph_with_nodes,
    _job,
    _minimal_contract_analysis,
    _minimal_snapshot,
    _tracking_plan,
)
from workers.policy_worker import PolicyWorker

# ---------------------------------------------------------------------------
# _resolve_authority tests (now takes session, job, graph, snapshot, nested)
# ---------------------------------------------------------------------------


class TestResolveAuthorityNoAuthority:
    """controller_values has keys but none resolve to a nested snapshot bundle."""

    def test_returns_no_authority(self) -> None:
        worker = PolicyWorker()
        session = MagicMock()
        job = _job()

        snapshot = _minimal_snapshot({"owner_slot:admin": {"value": "0xbbb"}})
        graph = _graph_with_nodes([])

        result = worker._resolve_authority(session, cast(Any, job), graph, snapshot, {})

        assert result["principal_resolution"]["status"] == "no_authority"


class TestResolveAuthorityZeroAddress:
    """Authority exists but is the zero address."""

    def test_returns_no_authority(self) -> None:
        worker = PolicyWorker()
        session = MagicMock()
        job = _job()

        snapshot = _minimal_snapshot({"state_variable:authority": {"value": ZERO_ADDRESS}})
        graph = _graph_with_nodes([])

        result = worker._resolve_authority(session, cast(Any, job), graph, snapshot, {})

        assert result["principal_resolution"]["status"] == "no_authority"
        assert "non-zero" in result["principal_resolution"]["reason"].lower()


class TestResolveAuthorityNoSnapshot:
    """A nested controller address is known but its snapshot is missing."""

    def test_returns_no_authority_snapshot(self) -> None:
        worker = PolicyWorker()
        session = MagicMock()
        job = _job()

        snapshot = _minimal_snapshot({"external_contract:policy": {"value": AUTH_ADDRESS}})
        graph = _graph_with_nodes([{"address": AUTH_ADDRESS, "artifacts": {}}])
        nested = cast(
            Any,
            {
                AUTH_ADDRESS: {
                    "analysis": {
                        "subject": {"address": AUTH_ADDRESS, "name": "Policy"},
                    }
                }
            },
        )

        result = worker._resolve_authority(session, cast(Any, job), graph, snapshot, nested)

        assert result["principal_resolution"]["status"] == "no_authority_snapshot"


class TestResolveAuthorityWithSnapshot:
    """A nested controller snapshot is joined without any policy-state backfill."""

    def test_returns_authority_snapshot(self) -> None:
        worker = PolicyWorker()
        session = MagicMock()
        job = _job()

        snapshot = _minimal_snapshot({"external_contract:policy": {"value": AUTH_ADDRESS}})
        graph = _graph_with_nodes([{"address": AUTH_ADDRESS, "artifacts": {"data_key": f"recursive:{AUTH_ADDRESS}"}}])
        nested = cast(Any, {AUTH_ADDRESS: _authority_bundle()})

        result = worker._resolve_authority(session, cast(Any, job), graph, snapshot, nested)

        assert result["authority_snapshot"] == nested[AUTH_ADDRESS]["snapshot"]
        assert result["principal_resolution"]["status"] == "complete"
        assert "semantic" in result["principal_resolution"]["reason"]


# ---------------------------------------------------------------------------
# process() integration tests
# ---------------------------------------------------------------------------


class TestProcessStoresAllArtifacts:
    """Full process() stores effective_permissions, resolved_control_graph, and principal_labels."""

    def test_all_three_artifacts_stored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = PolicyWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        contract_analysis = _minimal_contract_analysis()
        control_snapshot = _minimal_snapshot({"some_key:admin": {"value": "0xbbb"}})
        resolved_graph = _graph_with_nodes([])
        tracking_plan = _tracking_plan()

        def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
            return {
                "contract_analysis": contract_analysis,
                "control_snapshot": control_snapshot,
                "resolved_control_graph": resolved_graph,
                "control_tracking_plan": tracking_plan,
            }.get(name)

        store_calls: list[tuple[str, Any]] = []

        def fake_store_artifact(
            _session: Any,
            _job_id: Any,
            name: str,
            data: Any = None,
            text_data: Any = None,
        ) -> None:
            store_calls.append((name, data))

        monkeypatch.setattr("workers.policy_worker.get_artifact", fake_get_artifact)
        monkeypatch.setattr("workers.policy_worker.store_artifact", fake_store_artifact)
        monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *_a, **_kw: {})
        monkeypatch.setattr(
            "workers.policy_worker.build_effective_permissions",
            lambda *a, **kw: {"schema_version": "1", "functions": []},
        )
        monkeypatch.setattr(
            "workers.policy_worker.resolve_control_graph",
            lambda **kw: ({"nodes": [], "edges": [], "refreshed": True}, {}),
        )
        monkeypatch.setattr(
            "workers.policy_worker.build_principal_labels",
            lambda *a, **kw: {"principals": []},
        )

        worker.process(session, cast(Any, job))

        stored_names = [name for name, _ in store_calls]
        assert "effective_permissions" in stored_names
        assert "resolved_control_graph" in stored_names
        assert "principal_labels" in stored_names


class TestProcessSemanticInputs:
    """Missing semantic inputs are degraded instead of using a static-summary fallback."""

    def test_missing_predicate_trees_and_effects_records_degraded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = PolicyWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        contract_analysis = _minimal_contract_analysis()
        control_snapshot = _minimal_snapshot()
        resolved_graph = _graph_with_nodes([])
        tracking_plan = _tracking_plan()

        def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
            return {
                "contract_analysis": contract_analysis,
                "control_snapshot": control_snapshot,
                "resolved_control_graph": resolved_graph,
                "control_tracking_plan": tracking_plan,
            }.get(name)

        degraded: list[dict[str, Any]] = []

        def fake_record_degraded(**kwargs: Any) -> None:
            degraded.append(kwargs)

        def fake_build_ep(*_args: Any, **kwargs: Any) -> dict:
            assert kwargs["predicate_trees"] is None
            assert kwargs["capability_resolver_output"] is None
            assert kwargs["effects"] is None
            return {
                "schema_version": "0.1",
                "contract_address": TARGET_ADDRESS,
                "contract_name": "TestContract",
                "functions": [],
            }

        monkeypatch.setattr("workers.policy_worker.get_artifact", fake_get_artifact)
        monkeypatch.setattr("workers.policy_worker.store_artifact", lambda *a, **kw: None)
        monkeypatch.setattr("workers.policy_worker.record_degraded", fake_record_degraded)
        monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *_a, **_kw: {})
        monkeypatch.setattr("workers.policy_worker.build_effective_permissions", fake_build_ep)
        monkeypatch.setattr(
            "workers.policy_worker.resolve_control_graph",
            lambda **kw: ({"nodes": [], "edges": []}, {}),
        )
        monkeypatch.setattr(
            "workers.policy_worker.build_principal_labels",
            lambda *a, **kw: {"principals": []},
        )
        monkeypatch.setattr(
            PolicyWorker,
            "_enrich_cross_contract",
            lambda self, session, job, contract_analysis, control_snapshot, **kw: {},
        )

        worker.process(session, cast(Any, job))

        semantic_errors = [entry for entry in degraded if entry["phase"] == "effective_permissions_semantic_inputs"]
        assert len(semantic_errors) == 1
        assert semantic_errors[0]["context"]["missing_artifacts"] == ["effects", "predicate_trees"]


class TestGraphRefreshAfterEffectivePermissions:
    """resolve_control_graph refresh runs AFTER build_effective_permissions."""

    def test_refresh_runs_after_effective_permissions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = PolicyWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        contract_analysis = _minimal_contract_analysis()
        control_snapshot = _minimal_snapshot()
        resolved_graph = _graph_with_nodes([])
        tracking_plan = _tracking_plan()

        def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
            return {
                "contract_analysis": contract_analysis,
                "control_snapshot": control_snapshot,
                "resolved_control_graph": resolved_graph,
                "control_tracking_plan": tracking_plan,
            }.get(name)

        call_order: list[str] = []

        def fake_build_ep(*args: Any, **kwargs: Any) -> dict:
            call_order.append("effective_permissions")
            return {"schema_version": "1", "functions": []}

        def fake_resolve_graph(**kwargs: Any) -> tuple[dict, dict]:
            call_order.append("resolved_control_graph")
            return {"nodes": [], "edges": [], "refreshed": True}, {}

        def fake_build_labels(*args: Any, **kwargs: Any) -> dict:
            call_order.append("principal_labels")
            return {"principals": []}

        monkeypatch.setattr("workers.policy_worker.get_artifact", fake_get_artifact)
        monkeypatch.setattr("workers.policy_worker.store_artifact", lambda *a, **kw: None)
        monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *_a, **_kw: {})
        monkeypatch.setattr("workers.policy_worker.build_effective_permissions", fake_build_ep)
        monkeypatch.setattr("workers.policy_worker.resolve_control_graph", fake_resolve_graph)
        monkeypatch.setattr("workers.policy_worker.build_principal_labels", fake_build_labels)

        worker.process(session, cast(Any, job))

        ep_idx = call_order.index("effective_permissions")
        rg_idx = call_order.index("resolved_control_graph")
        assert ep_idx < rg_idx, (
            f"effective_permissions (index {ep_idx}) must be called "
            f"before resolved_control_graph (index {rg_idx}); "
            f"actual order: {call_order}"
        )


class TestCrossContractEnrichmentArtifactSync:
    """Cross-contract enrichment merges policy-derived claims into the
    effective_permissions artifact and leaves legacy effect_labels untouched."""

    def test_enrichment_rewrites_effective_permissions_artifact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = PolicyWorker()
        session = MagicMock()
        job = _job()

        contract_analysis = _minimal_contract_analysis()
        control_snapshot = _minimal_snapshot({"state_variable:token": {"value": AUTH_ADDRESS}})
        resolved_graph = _graph_with_nodes([])
        tracking_plan = _tracking_plan()

        def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
            return {
                "contract_analysis": contract_analysis,
                "control_snapshot": control_snapshot,
                "resolved_control_graph": resolved_graph,
                "control_tracking_plan": tracking_plan,
            }.get(name)

        store_calls: list[tuple[str, Any]] = []

        def fake_store_artifact(
            _session: Any,
            _job_id: Any,
            name: str,
            data: Any = None,
            text_data: Any = None,
        ) -> None:
            import json as _json

            store_calls.append((name, _json.loads(_json.dumps(data)) if data is not None else text_data))

        contract_row = MagicMock()
        contract_row.id = 1
        session.execute.return_value.scalar_one_or_none.return_value = contract_row

        monkeypatch.setattr("workers.policy_worker.get_artifact", fake_get_artifact)
        monkeypatch.setattr("workers.policy_worker.store_artifact", fake_store_artifact)
        monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *_a, **_kw: {})
        monkeypatch.setattr(
            "workers.policy_worker.build_effective_permissions",
            lambda *a, **kw: {
                "schema_version": "1",
                "functions": [
                    {
                        "function": "mintRewards()",
                        "effect_labels": ["role_management"],
                        "claims": [],
                        "controllers": [],
                        "authority_roles": [],
                        "direct_owner": None,
                    }
                ],
            },
        )
        monkeypatch.setattr(
            "workers.policy_worker.resolve_control_graph",
            lambda **kw: ({"nodes": [], "edges": []}, {}),
        )
        monkeypatch.setattr(
            "workers.policy_worker.build_principal_labels",
            lambda *a, **kw: {"principals": []},
        )
        policy_claim = {"claim_id": "flow.out", "tier": "policy_derived", "witness": {"callee": AUTH_ADDRESS}}
        monkeypatch.setattr(
            PolicyWorker,
            "_enrich_cross_contract",
            lambda self, session, job, contract_analysis, control_snapshot, **kw: {"mintRewards()": [policy_claim]},
        )

        worker.process(session, cast(Any, job))

        effective_payloads = [data for name, data in store_calls if name == "effective_permissions"]
        assert len(effective_payloads) == 2
        fn = effective_payloads[-1]["functions"][0]
        # The policy-derived claim merged into the claims plane; legacy labels are
        # left exactly as the static stage produced them.
        assert [c["claim_id"] for c in fn["claims"]] == ["flow.out"]
        assert fn["effect_labels"] == ["role_management"]


# ---------------------------------------------------------------------------
# Step 3 parallelism: full process() with 50+ principals must produce identical
# stored artifacts under PSAT_RPC_FANOUT=1 vs =8, and the per-job classify_cache
# must collapse repeated probes deterministically.
# ---------------------------------------------------------------------------


class TestProcessFanoutParity:
    """Drive ``PolicyWorker.process`` end-to-end (real ``build_principal_labels``)
    with a 50+ principal fixture and assert sequential vs parallel parity."""

    @staticmethod
    def _run(monkeypatch: pytest.MonkeyPatch, fanout: str) -> tuple[Any, dict[str, Any]]:
        from services.concurrency import RpcExecutor

        monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)
        RpcExecutor.reset_for_tests()

        worker = PolicyWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        target = TARGET_ADDRESS
        principal_addrs = [f"0x{(i + 0x100):040x}" for i in range(60)]

        def role_principals(addrs: list[str]) -> list[dict]:
            return [{"address": a, "resolved_type": "unknown", "details": {}} for a in addrs]

        ep_data: dict = {
            "schema_version": "0.1",
            "contract_address": target,
            "contract_name": "VaultBig",
            "functions": [
                {
                    "function": "manage(address,bytes,uint256)",
                    "abi_signature": "manage(address,bytes,uint256)",
                    "selector": "0x12345678",
                    "direct_owner": None,
                    "authority_public": False,
                    "authority_roles": [{"role": 1, "principals": role_principals(principal_addrs[:30])}],
                    "controllers": [],
                    "effect_targets": [],
                    "effect_labels": ["arbitrary_external_call"],
                    "action_summary": "Manage",
                    "notes": [],
                },
                {
                    "function": "setAuthority(address)",
                    "abi_signature": "setAuthority(address)",
                    "selector": "0x12345679",
                    "direct_owner": None,
                    "authority_public": False,
                    "authority_roles": [{"role": 8, "principals": role_principals(principal_addrs[30:])}],
                    "controllers": [],
                    "effect_targets": [],
                    "effect_labels": ["authority_update"],
                    "action_summary": "Set authority",
                    "notes": [],
                },
            ],
        }
        contract_analysis = _minimal_contract_analysis()
        control_snapshot = _minimal_snapshot({})
        resolved_graph = _graph_with_nodes(
            [
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
            ]
        )
        tracking_plan = _tracking_plan(address=target, name="VaultBig")

        def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
            return {
                "contract_analysis": contract_analysis,
                "control_snapshot": control_snapshot,
                "resolved_control_graph": resolved_graph,
                "control_tracking_plan": tracking_plan,
                "classified_addresses": None,
            }.get(name)

        store_calls: list[tuple[str, Any]] = []

        def fake_store_artifact(
            _session: Any, _job_id: Any, name: str, data: Any = None, text_data: Any = None
        ) -> None:
            store_calls.append((name, data))

        # Track every classify call so we can assert no spurious re-probes
        # leak through the parallel path.
        classify_calls: list[str] = []

        def fake_classify(_rpc, address, *, chain_id=None):
            classify_calls.append(address)
            return "eoa", {"address": address}, True

        monkeypatch.setattr("workers.policy_worker.get_artifact", fake_get_artifact)
        monkeypatch.setattr("workers.policy_worker.store_artifact", fake_store_artifact)
        monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *_a, **_kw: {})
        monkeypatch.setattr(
            "workers.policy_worker.build_effective_permissions",
            lambda *a, **kw: ep_data,
        )
        monkeypatch.setattr(
            "workers.policy_worker.resolve_control_graph",
            lambda **kw: (resolved_graph, {}),
        )
        monkeypatch.setattr(
            "services.policy.principal_enrichment.classify_resolved_address_with_status",
            fake_classify,
        )
        monkeypatch.setattr(
            PolicyWorker,
            "_enrich_cross_contract",
            lambda self, session, job, contract_analysis, control_snapshot, **kw: {},
        )

        worker.process(session, cast(Any, job))

        labels_payload = next(data for name, data in store_calls if name == "principal_labels")
        return labels_payload, {"classify_calls": classify_calls}

    def test_process_fanout_parity_50_plus_principals(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sequential and parallel runs must produce identical principal_labels."""
        seq_payload, seq_stats = self._run(monkeypatch, "1")
        par_payload, par_stats = self._run(monkeypatch, "8")

        assert seq_payload["contract_address"] == par_payload["contract_address"]
        assert seq_payload["contract_name"] == par_payload["contract_name"]
        assert len(seq_payload["principals"]) == len(par_payload["principals"])

        # Principals are emitted in sorted-address order — direct equality holds.
        for seq_p, par_p in zip(seq_payload["principals"], par_payload["principals"]):
            assert seq_p == par_p

        # Cache discipline: 60 unknown principals should each classify roughly
        # once. The parallel path tolerates a benign per-address race where
        # two threads miss before the first writes back, but the total must
        # remain bounded by 2× the sequential count — anything more means
        # the cache lock isn't collapsing concurrent misses.
        assert len(seq_stats["classify_calls"]) == 60
        assert len(par_stats["classify_calls"]) <= 60 * 2


class TestGraphRefreshRewritesTables:
    """The graph refresh must rewrite the CGN/CGE tables, not just the
    artifact — role_principal edges are projected only at this stage, and an
    artifact-only rewrite leaves the persisted plane a strict subset of what
    the artifact (and principal_labels) assert."""

    @staticmethod
    def _run_process(monkeypatch: pytest.MonkeyPatch, *, contract_row: Any) -> tuple[list[dict], dict]:
        worker = PolicyWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = contract_row
        job = _job(request={"rpc_url": "https://rpc.example", "chain_id": 1, "proxy_address": "0x" + "77" * 20})

        contract_analysis = _minimal_contract_analysis()
        control_snapshot = _minimal_snapshot()
        resolved_graph = _graph_with_nodes([])
        tracking_plan = _tracking_plan()
        refreshed_graph = {
            "schema_version": "0.1",
            "root_contract_address": TARGET_ADDRESS,
            "max_depth": 6,
            "nodes": [],
            "edges": [
                {
                    "from_id": f"address:{TARGET_ADDRESS}",
                    "to_id": "address:" + "0x" + "ee" * 20,
                    "relation": "role_principal",
                    "label": "roles 1",
                    "source_controller_id": None,
                    "notes": [],
                }
            ],
        }

        def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
            return {
                "contract_analysis": contract_analysis,
                "control_snapshot": control_snapshot,
                "resolved_control_graph": resolved_graph,
                "control_tracking_plan": tracking_plan,
            }.get(name)

        replace_calls: list[dict] = []

        def fake_replace(_session: Any, *, contract_id: int, deployment_address: Any, resolved_graph: Any):
            replace_calls.append(
                {
                    "contract_id": contract_id,
                    "deployment_address": deployment_address,
                    "resolved_graph": resolved_graph,
                }
            )
            return len(resolved_graph.get("nodes", [])), len(resolved_graph.get("edges", []))

        monkeypatch.setattr("workers.policy_worker.get_artifact", fake_get_artifact)
        monkeypatch.setattr("workers.policy_worker.store_artifact", lambda *a, **kw: None)
        monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *_a, **_kw: {})
        monkeypatch.setattr(
            "workers.policy_worker.build_effective_permissions",
            lambda *a, **kw: {"schema_version": "1", "functions": []},
        )
        monkeypatch.setattr("workers.policy_worker.resolve_control_graph", lambda **kw: (refreshed_graph, {}))
        monkeypatch.setattr("workers.policy_worker.build_principal_labels", lambda *a, **kw: {"principals": []})
        monkeypatch.setattr("workers.policy_worker.write_effective_function_rows", lambda *a, **kw: 0)
        monkeypatch.setattr("workers.policy_worker.replace_control_graph_rows", fake_replace)
        monkeypatch.setattr(
            PolicyWorker,
            "_enrich_cross_contract",
            lambda self, session, job, contract_analysis, control_snapshot, **kw: {},
        )

        worker.process(session, cast(Any, job))
        return replace_calls, refreshed_graph

    def test_refreshed_graph_is_written_to_the_tables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        contract_row = SimpleNamespace(id=42, address=TARGET_ADDRESS)
        replace_calls, refreshed_graph = self._run_process(monkeypatch, contract_row=contract_row)

        assert len(replace_calls) == 1, "policy stage must rewrite CGN/CGE once, with the refreshed graph"
        call = replace_calls[0]
        assert call["contract_id"] == 42
        # The impl-in-proxy-context deployment scoping the row writes use.
        assert call["deployment_address"] == "0x" + "77" * 20
        assert call["resolved_graph"] is refreshed_graph
        assert any(edge["relation"] == "role_principal" for edge in call["resolved_graph"]["edges"])

    def test_no_contract_row_skips_the_table_rewrite(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without a Contract row there is nothing to key the rows on; the
        artifact-only path (already loudly degraded upstream) must not crash
        or write."""
        replace_calls, _ = self._run_process(monkeypatch, contract_row=None)
        assert replace_calls == []
