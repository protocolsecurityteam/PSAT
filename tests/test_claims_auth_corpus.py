"""Real-Slither integration for the auth-family claim matchers.

Drives the exact production static sequence — Slither compile ->
``build_predicate_artifacts_with_pause_info`` -> ``build_effects`` ->
``apply_authority_effect_labels`` -> ``build_claims`` — over Etherscan-verified
corpus contracts, then asserts the ``(selector, claim_id, tier)`` tuples each
registry entry mints. Nothing is faked: the matchers, registry, and
``ClaimContext`` are the production classes; only the compile is local.

Every auth-family registry entry is exercised here with at least one positive, a
counterexample, and an adversarial near-miss drawn from real sources (spec
§6.2/§6.3):
  * ownership.* — L1SyncPoolETH (OZ v5 ghost: setters/`owner()` NEGATIVE,
    transfer/renounce POSITIVE), TopUp (Solady handover), TopUpSource (DAR),
    RolesAuthority (owner-var write identity, no `owner()` getter).
  * authorized_caller.rotate — FiatTokenV2_2 / StakedTokenV1 (updateX POSITIVE;
    transferOwnership + one-shot `initialize` NEGATIVE near-misses).
  * roles.* / authority.replace — Dai wards, RolesAuthority (Solmate),
    EtherFiTimelock (OZ), TopUpSource (DAR); EndpointV2 composeQueue is the
    mandatory role counterexample.

The compile is pinned to the solc-select binary named by each fixture (offline,
deterministic); when that version is absent the case skips, so the suite stays
green on a runner that only preinstalls the smoke solc.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")

Functions = dict[str, Any]

CORPUS_DIR = Path(__file__).resolve().parent / "label_corpus"
sys.path.insert(0, str(CORPUS_DIR))

import harness  # noqa: E402  # pyright: ignore[reportMissingImports]

REPO_ROOT = Path(__file__).resolve().parents[1]
AUTH_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "claims_auth"


def _build_claims_for(project: Path, name: str, solc_version: str) -> Functions:
    """Compile ``project`` (a Foundry dir) with Slither pinned to ``solc_version``
    and return ``{function_full_name: [claim, ...]}`` from ``build_claims``."""
    from slither import Slither

    from services.static.claims.builder import build_claims
    from services.static.contract_analysis_pipeline.effects import (
        apply_authority_effect_labels,
        build_effects,
    )
    from services.static.contract_analysis_pipeline.predicate_artifacts import (
        build_predicate_artifacts_with_pause_info,
    )
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract

    solc_binary = harness._solc_select_binary(solc_version)
    if not solc_binary.exists():
        pytest.skip(f"solc {solc_version} not installed via solc-select (needed for {name})")

    with harness._foundry_env(solc_binary):
        slither = Slither(str(project))
        subject = _select_subject_contract(slither, name)
        assert subject is not None, f"no analyzable subject contract for {name}"
        predicate_trees, _pause = build_predicate_artifacts_with_pause_info(subject)
        effects = build_effects(subject)
        apply_authority_effect_labels(subject, effects, predicate_trees)
        artifact = build_claims(subject, effects, predicate_trees)
    return artifact["functions"]


def _manifest_entry(address: str) -> dict:
    by_addr = {e["address"]: e for e in harness.corpus_entries()}
    assert address in by_addr, f"{address} absent from label corpus manifest"
    return by_addr[address]


def _claims_for_manifest(address: str, tmp_path: Path) -> Functions:
    entry = _manifest_entry(address)
    source = REPO_ROOT / entry["source_path"]
    project = tmp_path / entry["address"]
    harness._copy_project(source, project)
    return _build_claims_for(project, entry["name"], entry["solc_version"])


def _claim_ids(functions: Functions, signature: str) -> set[str]:
    return {claim["claim_id"] for claim in functions.get(signature) or []}


# The claim ids this stage's matchers own. A function may still carry claims from
# sibling families (LayerZero OApp, flow, exec) — the negatives below assert only
# that no AUTH-family claim leaks, never that a function is claim-free.
AUTH_FAMILY = frozenset(
    {
        "ownership.transfer",
        "ownership.renounce",
        "ownership.accept",
        "authorized_caller.rotate",
        "roles.grant",
        "roles.revoke",
        "roles.configure",
        "authority.replace",
    }
)


def _auth_claim_ids(functions: Functions, signature: str) -> set[str]:
    return _claim_ids(functions, signature) & AUTH_FAMILY


def _tiers(functions: Functions, signature: str, claim_id: str) -> set[str]:
    return {c["tier"] for c in functions.get(signature) or [] if c["claim_id"] == claim_id}


# ---------------------------------------------------------------------------
# ownership.* — OZ v5 ghost-immunity (positive + negatives on one contract)
# ---------------------------------------------------------------------------


def test_l1syncpool_ownership_positive_and_setters_negative(tmp_path):
    functions = _claims_for_manifest("0x39272ee125ebd9214404f735baae50acb9d334c0", tmp_path)

    assert _claim_ids(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _tiers(functions, "transferOwnership(address)", "ownership.transfer") == {"standard_exact"}
    assert _claim_ids(functions, "renounceOwnership()") == {"ownership.renounce"}

    # OZ v5 ghost writes (OwnableStorageLocation) must NOT drive any auth-family
    # claim on the owner-gated setters, the owner() view, or the outflow sweep
    # (LayerZero OApp / flow claims from sibling matchers are fine).
    for negative in (
        "owner()",
        "setPeer(uint32,bytes32)",
        "setVault(address)",
        "setLockBox(address)",
        "setTokenOut(address)",
        "sweep(address,address,uint256)",
        "setDelegate(address)",
    ):
        assert _auth_claim_ids(functions, negative) == set(), negative


# ---------------------------------------------------------------------------
# ownership.* — Solady handover (TopUp) + DSAuth owner-var write identity
# ---------------------------------------------------------------------------


def test_topup_solady_handover(tmp_path):
    functions = _claims_for_manifest("0x5bdd4b0d644c0a573e0eb526ab7d7d332aaaa50e", tmp_path)

    assert _claim_ids(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _claim_ids(functions, "renounceOwnership()") == {"ownership.renounce"}
    assert _claim_ids(functions, "completeOwnershipHandover(address)") == {"ownership.transfer"}
    assert _claim_ids(functions, "requestOwnershipHandover()") == {"ownership.accept"}


def test_rolesauthority_owner_var_write_identity(tmp_path):
    # Solmate-fork Auth: no owner() getter in the ABI set, so ownership.transfer
    # must corroborate via owner-var write identity, and setAuthority/roles claims
    # must land on the Solmate setters.
    functions = _claims_for_manifest("0x3994741a5b29c60d0ab318de1024f9256fe959dc", tmp_path)

    assert _claim_ids(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _claim_ids(functions, "setAuthority(Authority)") == {"authority.replace"}
    assert _tiers(functions, "setAuthority(Authority)", "authority.replace") == {"standard_exact"}
    for setter in (
        "setUserRole(address,uint8,bool)",
        "setRoleCapability(uint8,address,bytes4,bool)",
        "setPublicCapability(address,bytes4,bool)",
    ):
        assert _claim_ids(functions, setter) == {"roles.configure"}, setter


def test_topupsource_default_admin_rules_and_oz_roles(tmp_path):
    # TopUpSource is a fresh committable Foundry fixture (crytic-export
    # materialized) — the only corpus contract exercising DefaultAdminRules.
    # Compile from a fresh copy so the committed fixture keeps no build output.
    project = tmp_path / "topupsource"
    harness._copy_project(AUTH_FIXTURE_DIR / "topupsource", project)
    functions = _build_claims_for(project, "TopUpSource", "0.8.24")

    assert _claim_ids(functions, "beginDefaultAdminTransfer(address)") == {"ownership.transfer"}
    assert _claim_ids(functions, "acceptDefaultAdminTransfer()") == {"ownership.accept"}
    assert _claim_ids(functions, "grantRole(bytes32,address)") == {"roles.grant"}
    assert _claim_ids(functions, "revokeRole(bytes32,address)") == {"roles.revoke"}


# ---------------------------------------------------------------------------
# authorized_caller.rotate — positive updateX; transferOwnership + initialize NEG
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "name", "solc"),
    [
        ("0x43506849d7c04f9138d1a2050bbf3a0c054402dd", "FiatTokenV2_2", "0.6.12"),
        ("0x31724ca0c982a31fbb5c57f4217ab585271fc9a5", "StakedTokenV1", "0.6.12"),
    ],
)
def test_fiattoken_family_authorized_caller_rotate(address, name, solc, tmp_path):
    functions = _claims_for_manifest(address, tmp_path)

    for rotate_fn in (
        "updatePauser(address)",
        "updateMasterMinter(address)",
        "updateBlacklister(address)",
        "updateRescuer(address)",
    ):
        assert _claim_ids(functions, rotate_fn) == {"authorized_caller.rotate"}, rotate_fn
        assert _tiers(functions, rotate_fn, "authorized_caller.rotate") == {"idiom_structural"}

    # transferOwnership carries ownership.transfer, never the rotate (canonical
    # owner excluded); the one-shot initialize seeds the same scalars but is
    # latched (no caller-authority leaf) so it gets NO rotate.
    assert _claim_ids(functions, "transferOwnership(address)") == {"ownership.transfer"}
    init = next(s for s in functions if s.startswith("initialize(") and "authorization" not in s)
    assert "authorized_caller.rotate" not in _claim_ids(functions, init)


def test_authorized_caller_rotate_renders_var_name(tmp_path):
    functions = _claims_for_manifest("0x43506849d7c04f9138d1a2050bbf3a0c054402dd", tmp_path)
    claim = next(c for c in functions["updatePauser(address)"] if c["claim_id"] == "authorized_caller.rotate")
    assert claim["witness"]["vars"] == ["pauser"]
    assert set(claim["witness"]["established_by"]) == {"pauser"}


# ---------------------------------------------------------------------------
# roles.* — Maker wards, OZ AccessControl, + the mandatory composeQueue NEG
# ---------------------------------------------------------------------------


def test_dai_wards_rely_deny(tmp_path):
    functions = _claims_for_manifest("0x6b175474e89094c44da98b954eedeac495271d0f", tmp_path)
    assert _claim_ids(functions, "rely(address)") == {"roles.grant"}
    assert _claim_ids(functions, "deny(address)") == {"roles.revoke"}
    # Maker mint/burn are wards-gated but not role management.
    assert "roles.grant" not in _claim_ids(functions, "mint(address,uint256)")
    assert "roles.revoke" not in _claim_ids(functions, "burn(address,uint256)")


def test_etherfitimelock_oz_grant_revoke(tmp_path):
    functions = _claims_for_manifest("0x9f26d4c958fd811a1f59b01b86be7dffc9d20761", tmp_path)
    assert _claim_ids(functions, "grantRole(bytes32,address)") == {"roles.grant"}
    assert _claim_ids(functions, "revokeRole(bytes32,address)") == {"roles.revoke"}


def test_endpointv2_composequeue_is_not_role_management(tmp_path):
    """MANDATORY counterexample: LayerZero composeQueue (caller-keyed data map,
    membership leaf) mints ZERO role/authority/rotate claims; ownership on the
    real owner functions is unaffected."""
    functions = _claims_for_manifest("0x1a44076050125825900e736c501f859c50fe728c", tmp_path)

    for negative in (
        "sendCompose(address,bytes32,uint16,bytes)",
        "lzCompose(address,address,bytes32,uint16,bytes,bytes)",
    ):
        assert _auth_claim_ids(functions, negative) == set(), negative

    # The genuine owner functions still resolve (not a false negative).
    assert _claim_ids(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _claim_ids(functions, "renounceOwnership()") == {"ownership.renounce"}
    # registerLibrary is owner-gated but writes no authority scalar -> no authority.replace.
    assert "authority.replace" not in _claim_ids(functions, "registerLibrary(address)")
