"""Producer parity for the unanalysed 2-day timelock (C2).

`contracts.id=11` — 0xcd425f44758a08baab3c4908f3e3de5776e45d7a, "Operating
Timelock" — has `job_id`, `source_verified` and `compiler_version` all NULL and
**zero** `effective_functions`, while its twins id=12 (0x9f26d4c9…, v0.8.13) and
id=472 (0x70a64840…, v0.8.21) have 12 each. Its authority reaches 53
`function_principals` rows across 16 contracts, so the scorer publishes
`timelock_proposer_unresolved` against it and can walk nothing.

The fix is ONE analysis job, not a raised `analyze_limit`. What makes that a
verification rather than a hope is that the expected output shape is a
compiler-derived fact known in advance: the verified source is
Etherscan-verified `EtherFiTimelock` at v0.8.25+commit.b61c2a91, 60,385 chars of
standard-json vendored under `tests/fixtures/contracts/etherfi_timelock/`, and
its non-view surface is exactly the 12 names below — byte-identical to what both
twins produced.

**What this test deliberately does NOT pin: `authority_openness`.** The twins'
eight `restricted` verdicts are `finite_set` capabilities carrying concrete,
deployment-specific member addresses (contract 12's `schedule` resolves to
0xcdd57d11…), produced by the semantic capability resolver from on-chain
role-holder event folds. Asserting `restricted` for id=11 offline would mean
importing the twins' role holders onto a different contract with different role
grants — the exact substitution the C2 finding forbids. Offline we pin only the
resolver-independent subset; the eight are a live-run outcome.
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

    `_compile_subject` raises `SolcNotInstalled` precisely so callers can skip
    cleanly — and `WITNESS_INTEGRITY_LEDGER.md:584` records that exact courtesy
    silently disabling the label-corpus gate in an under-provisioned venv. A
    producer-parity test that skips proves nothing while reporting green, so
    this one refuses the skip and routes around every caller that would catch
    the exception for it.
    """
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

    ``state_changing`` is the producer's own discriminator and the same column
    the twins' 12 rows carry (``effective_functions.state_changing`` is true on
    12/12 for both), so this reads the shipped verdict rather than re-deriving
    one from mutability.
    """
    return sorted(
        full_name.split("(", 1)[0]
        for full_name, record in (effects.get("functions") or {}).items()
        if isinstance(record, dict) and record.get("state_changing")
    )


def test_solc_pin_is_provisioned_and_fails_loudly_otherwise():
    """The guard itself. If this fails, every other assertion here is vacuous —
    which is the failure mode a silent skip would have hidden."""
    _require_solc()
    assert label_corpus._solc_select_binary(SOLC_VERSION).exists()


def test_non_view_surface_matches_the_twins_exactly(compiled):
    """The success criterion for the one job the fix runs, known before running
    it: 12 names, byte-exact, the same set both twins produced."""
    _subject, effects = compiled
    assert tuple(_non_view_names(effects)) == EXPECTED_NON_VIEW


def test_subject_is_the_verified_contract(compiled):
    """The compile resolved the real subject, not a library or a base class —
    a parity assertion over the wrong contract would pass while proving
    nothing."""
    subject, _effects = compiled
    assert subject.name == "EtherFiTimelock"


def test_unverified_source_writes_no_contract_row(monkeypatch):
    """FAIL-CLOSED. Etherscan answering `status: 0` / empty `SourceCode` must
    raise out of the fetch — so the job reaches `failed_terminal` with a
    `stage_error` — and must NOT leave a `contracts` row behind.

    A fabricated 0-function row is the failure that MATTERS here: id=11 already
    exists with `source_verified` NULL and zero functions, and a row that looks
    analysed-with-nothing-found is indistinguishable from a contract that
    genuinely has no functions. The absence of the row is what keeps
    "unanalysed" and "analysed, empty" different facts.
    """
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
    """The refusal, made executable — and SCOPED: this covers the STATIC
    producer only.

    `authority_openness` has no static writer at all. Every writer is
    policy-stage (`effective_permissions_writer.py:119,318,332`;
    `effective_permissions.py:652,801,821`), so what this test can catch is a
    static regression that starts minting a capability verdict from source
    alone. It is **structurally blind to the more realistic failure**: the
    semantic resolver minting `restricted` for id=11 from a fold that did not
    happen. That one is only observable once the resolver runs, i.e. in the live
    run — it is not covered here and must not be reported as covered.
    """
    _subject, effects = compiled
    for record in (effects.get("functions") or {}).values():
        if isinstance(record, dict):
            assert record.get("authority_openness") is None
