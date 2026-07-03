"""Upgrade / exec-family claim matchers, proven on real corpus sources.

Two layers, both driving the production stack (registry, gates, taint helper,
``build_claims``) — nothing under test is faked:

* Slither-driven: each fixture under ``fixtures/contracts/claims_upgrade_exec``
  is compiled by the real static pipeline (``collect_contract_analysis_with_artifacts``
  → Slither → effects → the claims phase) and the minted claims are asserted.
  Every registry entry gets a positive fixture, and the corpus carries the
  mandated counterexample + adversarial near-miss (non-proxy ``upgradeTo``; plain
  ``transfer`` value send).
* Pure-facts: ``build_claims`` over synthetic ``effects``-shaped dicts locks the
  contract-level gate discrimination without a compiler, so the selector/gate
  logic is covered deterministically in every offline run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")

from services.static.claims import build_claims  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "contracts" / "claims_upgrade_exec"

# The claim families this task owns. Other matcher modules share the registry,
# so every assertion scopes to these ids (a sibling ownership/authorized_caller
# claim on the same function is legitimate and not this test's concern).
OWNED_CLAIM_IDS = frozenset(
    {
        "upgrade.implementation",
        "proxy.admin_change",
        "safe.signer_mgmt",
        "safe.module_mgmt",
        "safe.set_guard",
        "timelock.schedule",
        "timelock.execute",
        "timelock.cancel",
        "timelock.set_delay",
        "exec.arbitrary",
    }
)


# ---------------------------------------------------------------------------
# Slither-driven: the real static pipeline over compiled corpus fixtures
# ---------------------------------------------------------------------------


def _write_project(tmp_path: Path, contract_name: str, source_code: str) -> Path:
    project_dir = tmp_path / contract_name
    (project_dir / "src").mkdir(parents=True)
    (project_dir / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
    )
    (project_dir / "src" / f"{contract_name}.sol").write_text(source_code)
    (project_dir / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": "0x1111111111111111111111111111111111111111",
                "contract_name": contract_name,
                "compiler_version": "v0.8.19+commit.7dd6d404",
            }
        )
        + "\n"
    )
    (project_dir / "slither_results.json").write_text(json.dumps({"results": {"detectors": []}}) + "\n")
    return project_dir


def _pipeline_claims(tmp_path: Path, fixture_file: str, contract_name: str) -> dict[str, set[tuple[str, str]]]:
    """Run the full static pipeline and return ``{signature: {(claim_id, tier)}}``."""
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    source = (FIXTURES_DIR / fixture_file).read_text()
    project_dir = _write_project(tmp_path, contract_name, source)
    _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project_dir)
    assert effects is not None and "functions" in effects
    out: dict[str, set[tuple[str, str]]] = {}
    for signature, record in effects["functions"].items():
        # The claims phase always attaches the field, even when empty.
        assert "claims" in record, signature
        out[signature] = {(c["claim_id"], c["tier"]) for c in record["claims"]}
    return out


def _find(claims: dict[str, set[tuple[str, str]]], name: str) -> set[tuple[str, str]]:
    """Owned-family claims on the single function named ``name``."""
    matches = [sig for sig in claims if sig.split("(", 1)[0] == name]
    assert matches, f"no function named {name!r} in {sorted(claims)}"
    assert len(matches) == 1, f"ambiguous {name!r}: {matches}"
    return {claim for claim in claims[matches[0]] if claim[0] in OWNED_CLAIM_IDS}


def _owned_total(claims: dict[str, set[tuple[str, str]]]) -> int:
    return sum(1 for cset in claims.values() for claim in cset if claim[0] in OWNED_CLAIM_IDS)


def test_uups_upgrade_positive(tmp_path):
    """EETH-class UUPS: proxiableUUID gate → upgradeTo/AndCall both claim."""
    claims = _pipeline_claims(tmp_path, "uups_eeth_upgrade.sol", "EETH")
    assert _find(claims, "upgradeTo") == {("upgrade.implementation", "standard_exact")}
    assert _find(claims, "upgradeToAndCall") == {("upgrade.implementation", "standard_exact")}
    # The gate marker itself (a view) is never a claim.
    assert _find(claims, "proxiableUUID") == set()
    assert _find(claims, "mintShares") == set()


def test_proxy_shell_upgrade_and_admin_positive(tmp_path):
    """wBETH-class zos shell: delegatecall-fallback gate recovers upgradeTo, and
    changeAdmin gets proxy.admin_change (today: nothing)."""
    claims = _pipeline_claims(tmp_path, "proxy_shell_wbeth.sol", "WBETHProxy")
    assert _find(claims, "upgradeTo") == {("upgrade.implementation", "standard_exact")}
    assert _find(claims, "changeAdmin") == {("proxy.admin_change", "standard_exact")}


def test_non_proxy_upgradeto_is_near_miss_negative(tmp_path):
    """Adversarial: same selector, no proxy gate → no upgrade/admin claim."""
    claims = _pipeline_claims(tmp_path, "not_a_proxy_upgradeto.sol", "StrategyRegistry")
    assert _find(claims, "upgradeTo") == set()
    assert _find(claims, "changeAdmin") == set()


def test_safe_family_positive(tmp_path):
    """SafeL2-class: signer/module/guard control claims + exec.arbitrary on the
    execute entries, all under the getThreshold+getOwners+execTransaction gate."""
    claims = _pipeline_claims(tmp_path, "safe_wallet.sol", "SafeWallet")
    signer = ("safe.signer_mgmt", "standard_exact")
    for fn in ("addOwnerWithThreshold", "removeOwner", "swapOwner", "changeThreshold"):
        assert _find(claims, fn) == {signer}, fn
    module = ("safe.module_mgmt", "standard_exact")
    for fn in ("enableModule", "disableModule"):
        assert _find(claims, fn) == {module}, fn
    assert _find(claims, "setGuard") == {("safe.set_guard", "standard_exact")}
    arb = ("exec.arbitrary", "standard_exact")
    for fn in ("execTransaction", "execTransactionFromModule", "execTransactionFromModuleReturnData"):
        assert _find(claims, fn) == {arb}, fn
    # Gate views carry no claim.
    assert _find(claims, "getThreshold") == set()
    assert _find(claims, "getOwners") == set()
    # 4 signer + 2 module + 1 guard + 3 exec = 10 owned claims across the Safe family.
    assert _owned_total(claims) == 10


def test_oz_timelock_family_positive(tmp_path):
    """TimelockController: per-selector timelock claims; execute/executeBatch
    carry BOTH timelock.execute AND exec.arbitrary."""
    claims = _pipeline_claims(tmp_path, "oz_timelock.sol", "TimelockController")
    sched = ("timelock.schedule", "standard_exact")
    assert _find(claims, "schedule") == {sched}
    assert _find(claims, "scheduleBatch") == {sched}
    both = {("timelock.execute", "standard_exact"), ("exec.arbitrary", "standard_exact")}
    assert _find(claims, "execute") == both
    assert _find(claims, "executeBatch") == both
    assert _find(claims, "cancel") == {("timelock.cancel", "standard_exact")}
    assert _find(claims, "updateDelay") == {("timelock.set_delay", "standard_exact")}
    # 6 timelock.* claims + 2 exec.arbitrary on the execute entries.
    assert _find(claims, "getMinDelay") == set()
    assert _find(claims, "hashOperation") == set()


def test_boring_vault_manage_idiom_positive(tmp_path):
    """BoringVault.manage: parameter-tainted target + calldata → exec.arbitrary at
    the idiom tier (no standard gate)."""
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    idiom = ("exec.arbitrary", "idiom_structural")
    assert _find(claims, "manage") == {idiom}
    assert _find(claims, "manageDirect") == {idiom}


def test_plain_transfer_is_taint_near_miss_negative(tmp_path):
    """Address-tainted destination but no arbitrary calldata parameter → the
    value send earns no exec.arbitrary claim."""
    claims = _pipeline_claims(tmp_path, "plain_transfer_call.sol", "PayableToken")
    assert _find(claims, "transfer") == set()
    assert _find(claims, "withdraw") == set()
    assert _owned_total(claims) == 0


# ---------------------------------------------------------------------------
# Pure-facts: gate discrimination without a compiler
# ---------------------------------------------------------------------------


def _fn(selector: str, *, sinks: list[dict] | None = None) -> dict:
    return {"selector": selector, "sinks": sinks or [], "effect_labels": []}


def _delegatecall_fallback_sink() -> list[dict]:
    return [{"id": "fallback():sink0:delegatecall", "kind": "delegatecall", "target": "impl", "origin": "body"}]


def _external_call_sink(name: str) -> list[dict]:
    return [{"id": f"{name}:sink0:external_call", "kind": "external_call", "target": "to.call", "origin": "body"}]


def _ids(claims: list[Any]) -> set[tuple[str, str]]:
    return {(c["claim_id"], c["tier"]) for c in claims}


def test_facts_uups_gate_emits_upgrade():
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Impl",
        "functions": {
            "proxiableUUID()": _fn("0x52d1902d"),
            "upgradeTo(address)": _fn("0x3659cfe6"),
            "upgradeToAndCall(address,bytes)": _fn("0x4f1ef286"),
        },
    }
    art = build_claims(None, effects, {})
    assert _ids(art["functions"]["upgradeTo(address)"]) == {("upgrade.implementation", "standard_exact")}
    assert _ids(art["functions"]["upgradeToAndCall(address,bytes)"]) == {("upgrade.implementation", "standard_exact")}
    assert art["functions"]["proxiableUUID()"] == []


def test_facts_proxy_shell_gate_emits_upgrade_and_admin():
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Shell",
        "functions": {
            "fallback()": _fn("", sinks=_delegatecall_fallback_sink()),
            "upgradeTo(address)": _fn("0x3659cfe6"),
            "changeAdmin(address)": _fn("0x8f283970"),
        },
    }
    art = build_claims(None, effects, {})
    assert _ids(art["functions"]["upgradeTo(address)"]) == {("upgrade.implementation", "standard_exact")}
    assert _ids(art["functions"]["changeAdmin(address)"]) == {("proxy.admin_change", "standard_exact")}


def test_facts_no_gate_no_upgrade_claim():
    """Selector present, no proxiableUUID sibling / delegatecall fallback /
    marker event (contract=None ⇒ no events) → the gate blocks the claim."""
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Registry",
        "functions": {
            "upgradeTo(address)": _fn("0x3659cfe6"),
            "changeAdmin(address)": _fn("0x8f283970"),
        },
    }
    art = build_claims(None, effects, {})
    assert art["functions"]["upgradeTo(address)"] == []
    assert art["functions"]["changeAdmin(address)"] == []


def test_facts_safe_gate_emits_control_and_exec():
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Safe",
        "functions": {
            "getThreshold()": _fn("0xe75235b8"),
            "getOwners()": _fn("0xa0e67e2b"),
            "execTransaction(address,uint256,bytes,uint8,bytes)": _fn(
                "0x65bc10d3", sinks=_external_call_sink("execTransaction")
            ),
            "swapOwner(address,address,address)": _fn("0xe318b52b"),
            "enableModule(address)": _fn("0x610b5925"),
            "setGuard(address)": _fn("0xe19a9dd9"),
        },
    }
    art = build_claims(None, effects, {})
    fns = art["functions"]
    assert _ids(fns["swapOwner(address,address,address)"]) == {("safe.signer_mgmt", "standard_exact")}
    assert _ids(fns["enableModule(address)"]) == {("safe.module_mgmt", "standard_exact")}
    assert _ids(fns["setGuard(address)"]) == {("safe.set_guard", "standard_exact")}
    assert _ids(fns["execTransaction(address,uint256,bytes,uint8,bytes)"]) == {("exec.arbitrary", "standard_exact")}


def test_facts_safe_control_functions_need_the_gate():
    """swapOwner without the Safe sibling triple is not a Safe signer op."""
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "NotASafe",
        "functions": {"swapOwner(address,address,address)": _fn("0xe318b52b")},
    }
    art = build_claims(None, effects, {})
    assert art["functions"]["swapOwner(address,address,address)"] == []


def test_facts_oz_timelock_gate_emits_per_selector_and_exec():
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Timelock",
        "functions": {
            "getMinDelay()": _fn("0xf27a0c92"),
            "hashOperation(address,uint256,bytes,bytes32,bytes32)": _fn("0x8065657f"),
            "schedule(address,uint256,bytes,bytes32,bytes32,uint256)": _fn("0x01d5062a"),
            "execute(address,uint256,bytes,bytes32,bytes32)": _fn("0x134008d3", sinks=_external_call_sink("execute")),
            "cancel(bytes32)": _fn("0xc4d252f5"),
            "updateDelay(uint256)": _fn("0x64d62353"),
        },
    }
    art = build_claims(None, effects, {})
    fns = art["functions"]
    assert _ids(fns["schedule(address,uint256,bytes,bytes32,bytes32,uint256)"]) == {
        ("timelock.schedule", "standard_exact")
    }
    assert _ids(fns["execute(address,uint256,bytes,bytes32,bytes32)"]) == {
        ("timelock.execute", "standard_exact"),
        ("exec.arbitrary", "standard_exact"),
    }
    assert _ids(fns["cancel(bytes32)"]) == {("timelock.cancel", "standard_exact")}
    assert _ids(fns["updateDelay(uint256)"]) == {("timelock.set_delay", "standard_exact")}


def test_facts_manage_idiom_fails_closed_without_a_contract():
    """A body external_call sink but no Slither contract (degraded) cannot prove
    taint, so the idiom arm emits nothing rather than guessing."""
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Vault",
        "functions": {"manage(address,bytes,uint256)": _fn("0xf6e715d0", sinks=_external_call_sink("manage"))},
    }
    art = build_claims(None, effects, {})
    assert art["functions"]["manage(address,bytes,uint256)"] == []


def test_facts_all_new_claim_ids_are_registered():
    from services.static.claims import registry

    build_claims(None, {"schema_version": "semantic-2", "functions": {}}, {})  # force discovery
    registered = set(registry())
    for claim_id in (
        "upgrade.implementation",
        "proxy.admin_change",
        "safe.signer_mgmt",
        "safe.module_mgmt",
        "safe.set_guard",
        "timelock.schedule",
        "timelock.execute",
        "timelock.cancel",
        "timelock.set_delay",
        "exec.arbitrary",
    ):
        assert claim_id in registered, claim_id
