"""End-to-end token-precondition seeding on a real EVM.

Derives base slots with the production Slither pass, deploys that source's bytecode to a local non-forking anvil,
seeds via the production helpers and runs the real ``pause_recipe``, so Slither and the EVM must agree on
layout. Covers plain ERC-20, ERC-7201, rebasing, wrong-slot honesty and ERC-721. Skips without anvil and solc
0.8.27.
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
    """The exact compiler the fixture bytecode was built with."""
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
    """A plausible wrong slot: the residual derivation error the read-back guards against."""
    corrupted = dict(entry)
    corrupted["base_slot"] = "0x" + format(int(entry["base_slot"], 16) + 1, "064x")
    return corrupted


def _transfer_from_entry_point(
    fixture: dict[str, Any], caller: str, param_names: tuple[str, str, str] = ("from", "to", "amount")
) -> EntryPoint:
    """Gas is set so an out-of-gas revert can't masquerade as the pause."""
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
    """Never gated, so it keeps the diff specific."""
    calldata = encode_calldata(fixture["selectors"][_OWNER], _OWNER)
    assert calldata is not None
    return EntryPoint(key="owner_getter", calldata=calldata, from_addr=caller)


def _run_pause(
    anvil: SubprocessAnvil,
    fixture: dict[str, Any],
    entries: list[dict[str, Any]],
    param_names: tuple[str, str, str] = ("from", "to", "amount"),
) -> tuple[Any, RecordingStore, str]:
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


_OZ_BASE = "0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00"
_SLOT_1 = "0x" + "0" * 63 + "1"


@pytest.mark.parametrize(
    ("fixture_name", "expected_entries", "absent_roles", "param_names", "readbacks", "port"),
    [
        pytest.param(
            "token_plain_pausable.json",
            {
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
        # The allowance member sits one slot past the folded ERC-7201 base.
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
        # The computed balanceOf is never a seed anchor; seeding shares lets transferFrom reach the pause gate.
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
        # The third argument is a token id, so it takes the id filler the ownership seed is keyed at.
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
    assert eff.verdict == VERDICT_PROVEN
    assert "transferFrom" in eff.details["pre_pause_succeeding"]
    assert eff.details["observed_blast_radius"] == ["transferFrom"]
    assert eff.details["latch_flip"] is True
    assert "owner_getter" in eff.details["pre_pause_succeeding"]
    assert SEED_AMOUNT > ARG_AMOUNT  # sanity: seed clears any amount check


def test_wrong_slot_never_mints_witness(tmp_path: Path) -> None:
    fixture = _load_fixture("token_plain_pausable.json")
    entries = _derive_entries(fixture, tmp_path)
    corrupted = [_corrupt_slot(e) for e in entries]

    with SubprocessAnvil(port=8554, hardfork_name="prague") as anvil:
        eff, store, addr = _run_pause(anvil, fixture, corrupted)

        assert _readbacks(store) == ["failed", "failed"]
        assert "transferFrom" not in eff.details["pre_pause_succeeding"]
        assert eff.verdict == VERDICT_UNKNOWN
        assert eff.reason == "no_blast_radius_observed"

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


# Production seeds owner == spender == caller, which is order-blind, so only distinct keys prove the fold order matches
# solc.


def test_allowance_fold_order_distinct_keys(tmp_path: Path) -> None:
    fixture = _load_fixture("token_plain_pausable.json")
    entries = _derive_entries(fixture, tmp_path)
    base = _by_role(entries)["allowance"]["base_slot"]
    owner = "0x" + "aa" * 20
    spender = "0x" + "bb" * 20

    with SubprocessAnvil(port=8556, hardfork_name="prague") as anvil:
        deployer = anvil.accounts()[0]
        addr = anvil.deploy(deployer, fixture["creation_bytecode"])

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
