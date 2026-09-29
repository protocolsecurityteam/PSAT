"""End-to-end proof that the token-precondition seeding chain works on a real EVM.

Other token-slot tests stop at one seam (static slots from Slither, or hand-written slots on a
fork). This closes the loop on the SAME Solidity source: derive base slots with the production
Slither pass, deploy the bytecode compiled from that source to a local NON-FORKING anvil, seed via
the production synthesizer helpers, and run the real ``pause_recipe``. The claim that nothing is
hand-computed only holds if Slither and the EVM agree on layout, which deploying that bytecode forces.

Matrix (derive -> seed -> read-back verify -> pause blast-radius diff): plain ERC-20; OZ-v5
ERC-7201 namespaced (base+member offset); rebasing (computed ``balanceOf`` gets NO seed, ``shares``
does); wrong-slot honesty (a corrupted slot fails read-back, drops the write, and can never mint a
wrong label); ERC-721 ``ownerOf`` seeded at ``tokenId == ARG_AMOUNT``.

Gated behind ``anvil_available`` + an installed 0.8.27 solc; auto-skips otherwise. No live marker, no RPC.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.effects.anvil import (  # noqa: E402
    EntryPoint,
    ForkFixture,
    SubprocessAnvil,
    _apply_verified_fixture,
    anvil_available,
    pause_recipe,
)
from services.effects.calldata import (  # noqa: E402
    ARG_AMOUNT,
    FIXTURE_BALANCE_WEI,
    NEUTRAL_CALLER,
    SEED_AMOUNT,
    FunctionFacts,
    _arg_values,
    _mapping_entry_slot,
    _token_seed_fixtures,
    encode_calldata,
    integer_param_roles,
)
from services.effects.config import VERDICT_PROVEN, VERDICT_UNKNOWN  # noqa: E402
from services.effects.harness import SimContext  # noqa: E402
from services.resolution.differential_probe import _parse_arg_types  # noqa: E402
from services.static.contract_analysis_pipeline.token_slots import derive_token_slots  # noqa: E402

_FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "effects"

_TRANSFER_FROM = "transferFrom(address,address,uint256)"
_PAUSE = "pause()"
_OWNER = "owner()"

CTX = SimContext(chain_id=31337, block=1, hardfork="prague")


def _solc_027() -> str | None:
    """Path to the installed 0.8.27 solc, the exact compiler the fixture bytecode was built with so
    Slither's layout and the deployed bytecode agree. ``None`` (=> skip) when not installed."""
    try:
        from solc_select import solc_select as ss
    except Exception:
        return None
    if "0.8.27" not in set(ss.installed_versions()):
        return None
    return str(ss.artifact_path("0.8.27"))


_SOLC = _solc_027()

pytestmark = [
    pytest.mark.skipif(not anvil_available(), reason="anvil not on PATH"),
    pytest.mark.skipif(_SOLC is None, reason="solc 0.8.27 not installed"),
    pytest.mark.anvil,
]


class RecordingStore:
    def __init__(self) -> None:
        self.stored: list[dict[str, Any]] = []

    def __call__(self, transcript: dict[str, Any]) -> str:
        self.stored.append(transcript)
        return f"artifact://transcript/{len(self.stored)}"


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((_FIXTURE_DIR / name).read_text())


def _derive_entries(fixture: dict[str, Any], tmp_path: Path) -> list[dict[str, Any]]:
    """Run the production static pass over the fixture's source with real Slither; return its ``token_slots``."""
    contract_name = fixture["contract"]
    src = tmp_path / f"{contract_name}.sol"
    src.write_text(fixture["source"])
    sl = Slither(str(src), solc=_SOLC)
    contract = next(c for c in sl.contracts if c.name == contract_name)
    slots = derive_token_slots(contract)
    assert slots is not None, "static pass derived no token slots"
    return slots["entries"]


def _by_role(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {e["role"]: e for e in entries}


def _corrupt_slot(entry: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``entry`` with ``base_slot`` bumped by one: a plausible but wrong slot, the residual
    derivation error the read-back is a net against."""
    corrupted = dict(entry)
    corrupted["base_slot"] = "0x" + format(int(entry["base_slot"], 16) + 1, "064x")
    return corrupted


def _transfer_from_entry_point(
    fixture: dict[str, Any], caller: str, param_names: tuple[str, str, str] = ("from", "to", "amount")
) -> EntryPoint:
    """A ``transferFrom`` blast-radius probe built as the synthesizer builds it: address args
    substituted to ``caller``, the integer arg filled via the production role classifier off the
    token's declared parameter names, plus gas so an out-of-gas revert can't masquerade as the pause."""
    sig = _TRANSFER_FROM
    selector = fixture["selectors"][sig]
    types = _parse_arg_types(sig)
    assert types is not None
    fn = FunctionFacts(
        full_name=sig,
        selector=selector,
        canonical_signature=sig,
        effect_info={"parameter_names": list(param_names)},
        tree=None,
        legacy_value_flows=(),
    )
    roles = integer_param_roles(fn, types)
    calldata = encode_calldata(
        selector,
        sig,
        substitutions=_arg_values(types, identity=caller, amount=ARG_AMOUNT, integer_roles=roles).substitutions,
    )
    assert calldata is not None
    return EntryPoint(
        key="transferFrom",
        calldata=calldata,
        from_addr=caller,
        fixtures=(ForkFixture(kind="set_balance", address=caller, value=hex(FIXTURE_BALANCE_WEI)),),
    )


def _control_entry_point(fixture: dict[str, Any], caller: str) -> EntryPoint:
    """A plain ``owner()`` getter, never gated, so it can never appear in the blast radius (the diff is specific)."""
    calldata = encode_calldata(fixture["selectors"][_OWNER], _OWNER)
    assert calldata is not None
    return EntryPoint(key="owner_getter", calldata=calldata, from_addr=caller)


def _run_pause(
    anvil: SubprocessAnvil,
    fixture: dict[str, Any],
    entries: list[dict[str, Any]],
    param_names: tuple[str, str, str] = ("from", "to", "amount"),
) -> tuple[Any, RecordingStore, str]:
    """Deploy the fixture, seed the derived (or corrupted) entries for a neutral caller, and run the
    real pause recipe. Returns ``(effect, store, deployed_address)``."""
    owner = anvil.accounts()[0]
    addr = anvil.deploy(owner, fixture["creation_bytecode"])
    caller = NEUTRAL_CALLER
    seeds = _token_seed_fixtures(tuple(entries), [caller], addr)
    pause_calldata = encode_calldata(fixture["selectors"][_PAUSE], _PAUSE)
    assert pause_calldata is not None
    store = RecordingStore()
    eff = pause_recipe(
        transport=anvil,
        store=store,
        ctx=CTX,
        contract_address=addr,
        principal=owner,
        pause_calldata=pause_calldata,
        entry_points=[
            _transfer_from_entry_point(fixture, caller, param_names),
            _control_entry_point(fixture, caller),
        ],
        predicted_guard_set=["transferFrom"],
        max_pause_duration=None,
        fixtures=tuple(seeds),
    )
    return eff, store, addr


def _readbacks(store: RecordingStore) -> list[str | None]:
    tr = store.stored[-1]
    return [f.get("readback") for f in tr.get("fixtures", []) if f.get("kind") == "set_storage_at"]


# ---------------------------------------------------------------------------
# 1-3, 5. derive -> seed -> read-back -> pause blast radius, per fixture family
# ---------------------------------------------------------------------------

_OZ_BASE = "0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00"
_SLOT_1 = "0x" + "0" * 63 + "1"


# fixture json, expected derived entries by role, roles that must have NO entry, declared transferFrom
# parameter names, read-back statuses, anvil port.
@pytest.mark.parametrize(
    ("fixture_name", "expected_entries", "absent_roles", "param_names", "readbacks", "port"),
    [
        # plain ERC-20, storage_layout
        pytest.param(
            "token_plain_pausable.json",
            {
                # owner+paused pack into slot 0
                "balance": {"derivation": "storage_layout", "getter": "balanceOf(address)", "base_slot": _SLOT_1},
                "allowance": {
                    "derivation": "storage_layout",
                    "getter": "allowance(address,address)",
                    "base_slot": "0x" + "0" * 63 + "2",
                },
            },
            (),
            ("from", "to", "amount"),
            ["ok", "ok"],
            8551,
            id="plain-erc20",
        ),
        # OZ-v5 ERC-7201 namespaced: the folded StorageLocation constant is the balance base; the
        # allowance member sits exactly one slot past it (base+offset arithmetic against a real EVM).
        pytest.param(
            "token_ozv5_pausable.json",
            {
                "balance": {"derivation": "oz_v5_namespaced", "base_slot": _OZ_BASE},
                "allowance": {"derivation": "oz_v5_namespaced", "base_slot": _OZ_BASE[:-2] + "01"},
            },
            (),
            ("from", "to", "amount"),
            ["ok", "ok"],
            8552,
            id="ozv5-namespaced",
        ),
        # rebasing: no entry for the computed balanceOf (it must never be a seed anchor); a direct entry
        # for shares (the raw read the read-back anchor needs) and for allowance. Seeding shares is what
        # lets transferFrom's derived-balance requirement pass and reach the pause gate.
        pytest.param(
            "token_rebasing_pausable.json",
            {
                "shares": {"derivation": "storage_layout", "getter": "shares(address)", "base_slot": _SLOT_1},
                "allowance": {},
            },
            ("balance",),
            ("from", "to", "amount"),
            ["ok", "ok"],  # allowance + shares
            8553,
            id="rebasing-shares",
        ),
        # ERC-721 ownerOf: uint256-keyed owner mapping seeded at tokenId == ARG_AMOUNT. The third
        # argument is a token ID, not a quantity, so the probe must fill it with the id filler the
        # ownership seed is keyed at. "ok" means the uint256-keyed slot was live and ownerOf(ARG_AMOUNT)
        # echoed the caller.
        pytest.param(
            "token_nft_pausable.json",
            {
                "owner": {
                    "derivation": "storage_layout",
                    "getter": "ownerOf(uint256)",
                    "key_kind": "uint256",
                    "base_slot": _SLOT_1,
                }
            },
            (),
            ("from", "to", "tokenId"),
            ["ok"],
            8555,
            id="erc721-owner",
        ),
    ],
)
def test_token_fixture_e2e(
    tmp_path: Path, fixture_name, expected_entries, absent_roles, param_names, readbacks, port
) -> None:
    fixture = _load_fixture(fixture_name)
    entries = _derive_entries(fixture, tmp_path)
    by_role = _by_role(entries)

    for role, fields in expected_entries.items():
        assert role in by_role
        for key, value in fields.items():
            assert by_role[role][key] == value, (role, key)
    for role in absent_roles:
        assert role not in by_role, f"a computed {role} must never be a seed anchor"

    with SubprocessAnvil(port=port, hardfork_name="prague") as anvil:
        eff, store, _addr = _run_pause(anvil, fixture, entries, param_names)

    assert _readbacks(store) == readbacks
    # The previously-invisible entry point is now witnessed by the diff.
    assert eff.verdict == VERDICT_PROVEN
    assert "transferFrom" in eff.details["pre_pause_succeeding"]
    assert eff.details["observed_blast_radius"] == ["transferFrom"]
    assert eff.details["latch_flip"] is True
    # The ungated control never enters the blast radius.
    assert "owner_getter" in eff.details["pre_pause_succeeding"]
    assert SEED_AMOUNT > ARG_AMOUNT  # sanity: seed clears any amount check


# ---------------------------------------------------------------------------
# 4. wrong-slot honesty — the safety property
# ---------------------------------------------------------------------------


def test_wrong_slot_never_mints_witness(tmp_path: Path) -> None:
    fixture = _load_fixture("token_plain_pausable.json")
    entries = _derive_entries(fixture, tmp_path)
    corrupted = [_corrupt_slot(e) for e in entries]

    with SubprocessAnvil(port=8554, hardfork_name="prague") as anvil:
        eff, store, addr = _run_pause(anvil, fixture, corrupted)

        # On the real EVM every corrupted seed fails its getter read-back and is
        # dropped, so nothing is left seeded.
        assert _readbacks(store) == ["failed", "failed"]
        # transferFrom never reaches the pause gate, so the recipe falls to the honest no-observation verdict.
        assert "transferFrom" not in eff.details["pre_pause_succeeding"]
        assert eff.verdict == VERDICT_UNKNOWN
        assert eff.reason == "no_blast_radius_observed"

        # At the transport level too: a corrupted verified fixture reverts its write and the getter still returns zero.
        caller = NEUTRAL_CALLER
        bad_balance = _corrupt_slot(_by_role(entries)["balance"])
        seed = _token_seed_fixtures((bad_balance,), [caller], addr)[0]
        applied = _apply_verified_fixture(anvil, seed)
        assert applied["readback"] == "failed"
        getter_calldata = encode_calldata(
            fixture["selectors"]["balanceOf(address)"], "balanceOf(address)", substitutions={0: caller}
        )
        assert getter_calldata is not None
        res = anvil.call({"to": addr, "data": getter_calldata})
        assert res.success
        assert int(res.return_data, 16) == 0


# ---------------------------------------------------------------------------
# 6. Nested-mapping fold order pinned against the real EVM with DISTINCT keys.
# Production always seeds owner == spender == caller, which is order-blind
# (keccak(a ++ keccak(a ++ base))), so only a distinct-key write can prove the
# declaration-order-outermost fold matches solc's layout.
# ---------------------------------------------------------------------------


def test_allowance_fold_order_distinct_keys(tmp_path: Path) -> None:
    fixture = _load_fixture("token_plain_pausable.json")
    entries = _derive_entries(fixture, tmp_path)
    base = _by_role(entries)["allowance"]["base_slot"]
    owner = "0x" + "aa" * 20
    spender = "0x" + "bb" * 20

    with SubprocessAnvil(port=8556, hardfork_name="prague") as anvil:
        deployer = anvil.accounts()[0]
        addr = anvil.deploy(deployer, fixture["creation_bytecode"])

        # A real approve(spender, 777) from `owner` writes _allowances[owner][spender].
        anvil.set_balance(owner, hex(FIXTURE_BALANCE_WEI))
        anvil.impersonate(owner)
        try:
            approve = encode_calldata(
                fixture["selectors"]["approve(address,uint256)"],
                "approve(address,uint256)",
                substitutions={0: spender, 1: 777},
            )
            assert approve is not None
            anvil.send({"from": owner, "to": addr, "data": approve})
            anvil.mine()
        finally:
            anvil.stop_impersonate(owner)

        folded = _mapping_entry_slot(base, [int(owner, 16), int(spender, 16)])
        reversed_fold = _mapping_entry_slot(base, [int(spender, 16), int(owner, 16)])
        assert folded is not None and reversed_fold is not None
        stored = anvil._rpc("eth_getStorageAt", [addr, folded, "latest"])
        stored_reversed = anvil._rpc("eth_getStorageAt", [addr, reversed_fold, "latest"])
        assert int(str(stored), 16) == 777
        assert int(str(stored_reversed), 16) == 0
