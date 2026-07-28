"""Unit tests for ``db.storage`` that don't touch a real bucket.

The integration suite (``test_artifact_storage_integration.py``) covers the
boto3 wire path. These tests pin the in-memory contract that the API layer
relies on — specifically, ``get_many`` must surface per-key transport
failures as ``None`` rather than raising, so a flaky bucket can't take down
``/api/analyses`` or ``/api/jobs/{id}/stage_timings``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from db.storage import (  # noqa: E402
    StorageClient,
    StorageKeyAbsent,
    StorageKeyMissing,
    StorageUnavailable,
    storage_key_candidates,
)


def _bare_client() -> StorageClient:
    """Build a StorageClient without going through ``__init__`` (which
    would try to talk to boto3). The methods we exercise only touch
    ``self.get`` / ``self.bucket`` — both stubbed in the tests."""
    client = StorageClient.__new__(StorageClient)
    client.bucket = "test-bucket"
    client._client = MagicMock()
    return client


def test_get_many_returns_none_for_missing_key() -> None:
    client = _bare_client()
    with patch.object(client, "get", side_effect=lambda k: (_ for _ in ()).throw(StorageKeyMissing(k))):
        result = client.get_many(["a", "b"])
    assert result == {"a": None, "b": None}


def test_get_many_swallows_transport_errors_per_key() -> None:
    """A transport failure on one key must not raise out of get_many — the
    failed key returns ``None`` and successful keys still resolve. Pre-fix
    this raised ``StorageUnavailable`` and api.py callers had to wrap it in
    try/except, with one of the two callers forgetting (``stage_timings``).
    Pinning the contract here means a future change can't quietly regress.
    """
    client = _bare_client()

    def fake_get(k: str) -> bytes:
        if k == "boom":
            raise StorageUnavailable("simulated transport failure")
        return f"body-{k}".encode()

    with patch.object(client, "get", side_effect=fake_get):
        result = client.get_many(["ok1", "boom", "ok2"])

    assert result == {
        "ok1": b"body-ok1",
        "boom": None,
        "ok2": b"body-ok2",
    }


def test_get_many_total_outage_returns_all_none() -> None:
    """Belt-and-suspenders: if every key fails, callers see all-None and
    can choose how to surface that. The function must not raise."""
    client = _bare_client()
    with patch.object(client, "get", side_effect=StorageUnavailable("bucket gone")):
        result = client.get_many(["a", "b", "c"])
    assert result == {"a": None, "b": None, "c": None}


def test_get_many_dedupes_input_keys() -> None:
    client = _bare_client()
    calls: list[str] = []

    def fake_get(k: str) -> bytes:
        calls.append(k)
        return b"x"

    with patch.object(client, "get", side_effect=fake_get):
        result = client.get_many(["a", "a", "b", "a"])

    assert result == {"a": b"x", "b": b"x"}
    assert sorted(calls) == ["a", "b"]


def test_get_many_empty_input_no_pool_spawned() -> None:
    """Cheap shortcut: empty input must not spin up a thread pool."""
    client = _bare_client()
    with patch("db.storage.ThreadPoolExecutor") as mock_pool:
        result = client.get_many([])
    assert result == {}
    mock_pool.assert_not_called()


# ---------------------------------------------------------------------------
# Storage-key prefix normalisation
#
# Rows record the writing environment's ARTIFACT_STORAGE_PREFIX verbatim. Read
# from an environment with a different prefix, every one of those keys names an
# object that was never written there. The read path retries prefix-stripped —
# narrowly, so that a genuinely absent object stays absent.
# ---------------------------------------------------------------------------


def test_preview_prefix_yields_a_stripped_candidate() -> None:
    assert storage_key_candidates("pr-160/artifacts/job-1/effects") == [
        "pr-160/artifacts/job-1/effects",
        "artifacts/job-1/effects",
    ]
    assert storage_key_candidates("pr-7/source_files/j/abc") == [
        "pr-7/source_files/j/abc",
        "source_files/j/abc",
    ]
    assert storage_key_candidates("pr-160/contract_materializations/1/0xab/analysis.json") == [
        "pr-160/contract_materializations/1/0xab/analysis.json",
        "contract_materializations/1/0xab/analysis.json",
    ]


def test_audits_keys_are_never_stripped() -> None:
    """NEGATIVE CONTROL. ``audits/`` keys are written unprefixed and resolve
    today; they must keep resolving on the first attempt with no fallback, so
    an audit object that is genuinely gone stays reported as gone."""
    for key in ("audits/text/183.txt", "audits/scope/183.json", "audits/text/15.txt"):
        assert storage_key_candidates(key) == [key]


def test_other_bucket_namespaces_are_never_stripped() -> None:
    for key in ("artifacts/j/n", "source_files/j/h", "exa-cache/deadbeef", "tavily-cache/deadbeef"):
        assert storage_key_candidates(key) == [key]


def test_non_prefix_leading_segments_are_never_stripped() -> None:
    """Only an environment-scope-shaped head over a known namespace is
    removable. Anything else would let the fallback invent a resolution."""
    assert storage_key_candidates("customer-a/artifacts/j/n") == ["customer-a/artifacts/j/n"]
    assert storage_key_candidates("pr-160/mystery/j/n") == ["pr-160/mystery/j/n"]
    assert storage_key_candidates("pr-abc/artifacts/j/n") == ["pr-abc/artifacts/j/n"]
    assert storage_key_candidates("artifacts") == ["artifacts"]
    assert storage_key_candidates("") == []


def test_configured_env_prefix_is_also_strippable(monkeypatch) -> None:
    monkeypatch.setenv("ARTIFACT_STORAGE_PREFIX", "staging/")
    assert storage_key_candidates("staging/artifacts/j/n") == ["staging/artifacts/j/n", "artifacts/j/n"]


def test_get_falls_back_to_the_stripped_key() -> None:
    client = _bare_client()
    stored = {"artifacts/j/n": b"payload"}

    def fake_get_one(k: str) -> bytes:
        if k not in stored:
            raise StorageKeyMissing(k)
        return stored[k]

    with patch.object(client, "_get_one", side_effect=fake_get_one):
        assert client.get("pr-160/artifacts/j/n") == b"payload"


def test_get_raises_and_names_every_key_it_tried() -> None:
    """POSITIVE CONTROL shape: when no candidate holds an object the failure is
    loud and states exactly what was asked. A fallback must never convert
    proven-absent into silence."""
    client = _bare_client()
    with patch.object(client, "_get_one", side_effect=lambda k: (_ for _ in ()).throw(StorageKeyMissing(k))):
        with pytest.raises(StorageKeyMissing) as excinfo:
            client.get("pr-160/artifacts/j/n")
    assert excinfo.value.tried == ["pr-160/artifacts/j/n", "artifacts/j/n"]
    assert "pr-160/artifacts/j/n" in str(excinfo.value)
    assert "artifacts/j/n" in str(excinfo.value)


def test_get_on_an_unstripped_key_reports_one_attempt() -> None:
    client = _bare_client()
    with patch.object(client, "_get_one", side_effect=lambda k: (_ for _ in ()).throw(StorageKeyMissing(k))):
        with pytest.raises(StorageKeyMissing) as excinfo:
            client.get("audits/text/183.txt")
    assert excinfo.value.tried == ["audits/text/183.txt"]


def test_transport_failure_is_never_reported_as_absence() -> None:
    """A 500/timeout on the first candidate must propagate, not advance to the
    fallback and end up as 'the object is not there'."""
    client = _bare_client()
    with patch.object(client, "_get_one", side_effect=StorageUnavailable("bucket unreachable")):
        with pytest.raises(StorageUnavailable):
            client.get("pr-160/artifacts/j/n")


def test_empty_key_is_a_different_fact_from_a_missing_object() -> None:
    """'The row records no key' and 'the bucket has no object at this key'
    are distinct states and a consumer can tell them apart."""
    client = _bare_client()
    with pytest.raises(StorageKeyAbsent):
        client.get("")
    assert not issubclass(StorageKeyAbsent, StorageKeyMissing)
    assert not issubclass(StorageKeyMissing, StorageKeyAbsent)


def test_get_many_logs_a_missing_object_instead_of_dropping_it(caplog) -> None:
    """The None return is preserved (one bad key must not fail an API
    response) but it is no longer silent."""
    import logging

    client = _bare_client()
    with patch.object(client, "get", side_effect=lambda k: (_ for _ in ()).throw(StorageKeyMissing(k))):
        with caplog.at_level(logging.ERROR, logger="db.storage"):
            result = client.get_many(["artifacts/j/n"])
    assert result == {"artifacts/j/n": None}
    assert any("artifacts/j/n" in r.getMessage() and r.levelno >= logging.ERROR for r in caplog.records)


def test_get_many_results_keeps_absence_and_outage_apart() -> None:
    """Absence and outage stay apart at the batch layer too.

    ``get_many`` flattens both to ``None``, which is why ``get_all_artifacts``
    could not tell "the object is gone" from "the bucket is unreachable" — and
    then dropped both, so its caller could not tell either from "this job has no
    such artifact"."""
    client = _bare_client()

    def _fake(key: str) -> bytes:
        if key == "artifacts/j/gone":
            raise StorageKeyMissing(key)
        if key == "artifacts/j/outage":
            raise StorageUnavailable("bucket unreachable")
        return b"{}"

    with patch.object(client, "get", side_effect=_fake):
        reads = client.get_many_results(["artifacts/j/ok", "artifacts/j/gone", "artifacts/j/outage"])

    assert reads["artifacts/j/ok"].read
    assert not reads["artifacts/j/ok"].proven_absent
    assert not reads["artifacts/j/ok"].not_determined

    assert reads["artifacts/j/gone"].proven_absent
    assert not reads["artifacts/j/gone"].not_determined

    assert reads["artifacts/j/outage"].not_determined
    assert not reads["artifacts/j/outage"].proven_absent

    # The flattened view a cause-independent caller still gets.
    with patch.object(client, "get", side_effect=_fake):
        assert client.get_many(["artifacts/j/gone", "artifacts/j/outage"]) == {
            "artifacts/j/gone": None,
            "artifacts/j/outage": None,
        }
