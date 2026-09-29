"""Producer parity for the unanalysed 2-day timelock (C2).

`contracts.id=11` (0xcd425f44758a08baab3c4908f3e3de5776e45d7a, "Operating Timelock") has NULL
`job_id` / `source_verified` / `compiler_version` and **zero** `effective_functions`, while twins
id=12 and id=472 have 12 each; its authority reaches 53 `function_principals` rows, so the scorer
publishes `timelock_proposer_unresolved` and can walk nothing.

The fix is ONE analysis job. It is verifiable because the expected output is a compiler-derived
fact: Etherscan-verified `EtherFiTimelock` v0.8.25+commit.b61c2a91 (standard-json vendored under
`tests/fixtures/contracts/etherfi_timelock/`) has exactly the 12 non-view names below, as both twins.

**Deliberately NOT pinned: `authority_openness`.** The twins' eight `restricted` verdicts are
`finite_set` capabilities with deployment-specific member addresses from on-chain role-holder
folds; asserting them offline would import the twins' role holders onto a different contract,
the substitution the C2 finding forbids. Only the resolver-independent subset is pinned.
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

#: Etherscan `getabi` on 0xcd425f44…, and the name set both twins produced.
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
    `WITNESS_INTEGRITY_LEDGER.md:584` records that courtesy silently disabling the label-corpus
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
    """Non-view function names from the production effects artifact.

    ``state_changing`` is the producer's own discriminator (true on 12/12 for both twins), so
    this reads the shipped verdict rather than re-deriving one from mutability."""
    return sorted(
        full_name.split("(", 1)[0]
        for full_name, record in (effects.get("functions") or {}).items()
        if isinstance(record, dict) and record.get("state_changing")
    )


def test_non_view_surface_matches_the_twins_exactly(compiled):
    """The success criterion for the fix's one job, known before running it: the same 12 names as both twins."""
    _subject, effects = compiled
    assert tuple(_non_view_names(effects)) == EXPECTED_NON_VIEW


def test_subject_is_the_verified_contract(compiled):
    """The compile resolved the real subject, not a library or base class (parity over the wrong
    contract proves nothing)."""
    subject, _effects = compiled
    assert subject.name == "EtherFiTimelock"


def test_unverified_source_writes_no_contract_row(monkeypatch):
    """FAIL-CLOSED. Etherscan `status: 0` / empty `SourceCode` must raise out of the fetch (job
    reaches `failed_terminal` with a `stage_error`) and leave NO `contracts` row behind.

    id=11 already exists with NULL `source_verified` and zero functions; a fabricated 0-function
    row would be indistinguishable from a contract with no functions, so the absence keeps
    "unanalysed" and "analysed, empty" different facts."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import services.clients.etherscan as etherscan_module
    from workers.discovery import DiscoveryWorker

    # 1. The producer of the failure: an unverified payload raises rather than
    #    returning an empty-but-plausible result.
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

    # 2. The worker's ordering: the raise lands at the fetch, upstream of every
    #    write, so no Contract is ever added to the session.
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
    """The refusal, made executable and SCOPED to the STATIC producer.

    `authority_openness` has no static writer (all are policy-stage,
    `effective_permissions_writer.py:119,318,332`), so this catches only a static regression that
    mints a capability verdict from source alone. It is **structurally blind to the more realistic
    failure**, the semantic resolver minting `restricted` for id=11 from a fold that did not happen;
    that is observable only in the live run and must not be reported as covered."""
    _subject, effects = compiled
    for record in (effects.get("functions") or {}).values():
        if isinstance(record, dict):
            assert record.get("authority_openness") is None
