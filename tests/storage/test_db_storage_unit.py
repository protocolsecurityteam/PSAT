"""``get_many`` returns ``None`` per failed key so a flaky bucket can't take down ``/api/analyses``.

The boto3 path is in ``test_artifact_storage_integration.py``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from db.storage import (
    StorageClient,
    StorageKeyMissing,
    StorageUnavailable,
    storage_key_candidates,
)


def _bare_client() -> StorageClient:
    client = StorageClient.__new__(StorageClient)
    client.bucket = "test-bucket"
    client._client = MagicMock()
    return client


def test_get_many_empty_input_no_pool_spawned() -> None:
    client = _bare_client()
    with patch("db.storage.ThreadPoolExecutor") as mock_pool:
        result = client.get_many([])
    assert result == {}
    mock_pool.assert_not_called()


# Rows record the writer's ARTIFACT_STORAGE_PREFIX, so reads retry prefix-stripped, narrowly enough that a real absence
# stays absent.


def test_non_prefix_leading_segments_are_never_stripped() -> None:
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
    client = _bare_client()
    with patch.object(client, "_get_one", side_effect=lambda k: (_ for _ in ()).throw(StorageKeyMissing(k))):
        with pytest.raises(StorageKeyMissing) as excinfo:
            client.get("pr-160/artifacts/j/n")
    assert excinfo.value.tried == ["pr-160/artifacts/j/n", "artifacts/j/n"]
    assert "pr-160/artifacts/j/n" in str(excinfo.value)
    assert "artifacts/j/n" in str(excinfo.value)


def test_get_many_logs_a_missing_object_instead_of_dropping_it(caplog) -> None:
    import logging

    client = _bare_client()
    with patch.object(client, "get", side_effect=lambda k: (_ for _ in ()).throw(StorageKeyMissing(k))):
        with caplog.at_level(logging.ERROR, logger="db.storage"):
            result = client.get_many(["artifacts/j/n"])
    assert result == {"artifacts/j/n": None}
    assert any("artifacts/j/n" in r.getMessage() and r.levelno >= logging.ERROR for r in caplog.records)


def test_get_many_results_keeps_absence_and_outage_apart() -> None:
    """``get_many`` flattens both to ``None``, which is why ``get_all_artifacts`` couldn't tell them apart."""
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

    with patch.object(client, "get", side_effect=_fake):
        assert client.get_many(["artifacts/j/gone", "artifacts/j/outage"]) == {
            "artifacts/j/gone": None,
            "artifacts/j/outage": None,
        }
