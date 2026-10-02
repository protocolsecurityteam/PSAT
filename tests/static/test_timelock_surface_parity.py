"""C2: ``contracts.id=11`` (0xcd425f44…, "Operating Timelock") has zero ``effective_functions`` while twins id=12 and
id=472 have 12 each. The vendored verified ``EtherFiTimelock`` source must produce exactly those 12 non-view names.
``authority_openness`` is not pinned: the twins' verdicts carry deployment-specific role holders.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, cast

import pytest

from tests.support import label_corpus

pytestmark = pytest.mark.compile

TIMELOCK_ADDRESS = "0xcd425f44758a08baab3c4908f3e3de5776e45d7a"
SOLC_VERSION = "0.8.25"

EXPECTED_NON_VIEW = (
    "cancel",
    "execute",
    "executeBatch",
    "grantRole",
    "onERC1155BatchReceived",
    "onERC1155Received",
    "onERC721Received",
    "renounceRole",
    "revokeRole",
    "schedule",
    "scheduleBatch",
    "updateDelay",
)

_ENTRY = {
    "address": TIMELOCK_ADDRESS,
    "name": "EtherFiTimelock",
    "chain": "ethereum",
    "solc_version": SOLC_VERSION,
    "source_path": "tests/fixtures/contracts/etherfi_timelock",
}


def _require_solc() -> None:
    """FAIL, never skip, when the pinned solc is absent.

    `_compile_subject` raises `SolcNotInstalled` so callers can skip, and
    that courtesy silently disables the label-corpus
    gate. A parity test that skips proves nothing while reporting green."""
    binary = label_corpus._solc_select_binary(SOLC_VERSION)
    if not binary.exists():
        raise AssertionError(
            f"solc {SOLC_VERSION} is not provisioned at {binary}. This test compiles a real "
            f"verified source pinned to it and must not be skipped: run "
            f"`uv run solc-select install {SOLC_VERSION}`. CI installs it in _ci-checks.yml."
        )


@pytest.fixture(scope="module")
def compiled():
    _require_solc()
    with tempfile.TemporaryDirectory() as tmp:
        subject, effects, _trees, _claims = label_corpus._compile_subject(_ENTRY, Path(tmp))
        yield subject, effects


def _non_view_names(effects) -> list[str]:
    """``state_changing`` is the producer's own discriminator."""
    return sorted(
        full_name.split("(", 1)[0]
        for full_name, record in (effects.get("functions") or {}).items()
        if isinstance(record, dict) and record.get("state_changing")
    )


def test_non_view_surface_matches_the_twins_exactly(compiled):
    _subject, effects = compiled
    assert tuple(_non_view_names(effects)) == EXPECTED_NON_VIEW


def test_subject_is_the_verified_contract(compiled):
    subject, _effects = compiled
    assert subject.name == "EtherFiTimelock"


def test_unverified_source_writes_no_contract_row(monkeypatch):
    """A 0-function row would be indistinguishable from an analysed empty contract."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import services.clients.etherscan as etherscan_module
    from workers.discovery import DiscoveryWorker

    monkeypatch.setattr(
        etherscan_module,
        "get",
        lambda module, action, chain_id=None, **params: {
            "status": "0",
            "result": [{"SourceCode": "", "ABI": "Contract source code not verified"}],
        },
    )
    with pytest.raises(RuntimeError, match="No verified source code"):
        etherscan_module.get_source(TIMELOCK_ADDRESS, chain_id=1)

    def _raise_unverified(_addr, **_kw):
        raise RuntimeError(f"No verified source code for {TIMELOCK_ADDRESS}")

    monkeypatch.setattr("workers.discovery.fetch", _raise_unverified)
    monkeypatch.setattr("workers.discovery._batch_get_creators", lambda addresses, **kw: {})

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = SimpleNamespace(
        id="job-unverified",
        address=TIMELOCK_ADDRESS,
        name=None,
        company=None,
        protocol_id=None,
        chain_id=1,
        request={},
    )

    with pytest.raises(RuntimeError, match="No verified source code"):
        worker._process_address(session, cast(Any, job))

    session.add.assert_not_called()


def test_static_producer_mints_no_openness_verdict(compiled):
    """``authority_openness`` has no static writer, so this can't see the realistic failure (the resolver minting
    ``restricted`` from a fold that didn't happen); only the live run can.
    """
    _subject, effects = compiled
    for record in (effects.get("functions") or {}).values():
        if isinstance(record, dict):
            assert record.get("authority_openness") is None
