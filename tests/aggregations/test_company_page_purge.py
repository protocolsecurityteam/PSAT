"""Cloudflare outbox tests: all HTTP calls are mocked, never production."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import requests
from sqlalchemy import delete, select, update
from sqlalchemy.orm import sessionmaker

from db.models import CompanyPagePurge as Purge
from db.models import Protocol
from services import company_page_purge as purge
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_protocol


@pytest.fixture
def outbox(db_session, monkeypatch):
    monkeypatch.setattr(purge, "purge_config", lambda: ("a" * 32, "test-purge-token"))
    wire = MagicMock(return_value=MagicMock(status_code=200, json=lambda: {"success": True}))
    monkeypatch.setattr(purge.requests, "post", wire)
    return db_session, sessionmaker(bind=db_session.get_bind()), wire


@requires_postgres
def test_purge_only_after_commit_and_only_company_tag(outbox):
    session, factory, wire = outbox
    name = "company / é"
    purge.enqueue_purge(session, name)
    assert purge.purge_one(factory) == "idle"
    wire.assert_not_called()
    session.commit()
    assert purge.purge_one(factory) == "purged"
    assert wire.call_args.args == ("https://api.cloudflare.com/client/v4/zones/" + "a" * 32 + "/purge_cache",)
    kwargs = wire.call_args.kwargs
    assert kwargs["json"] == {"tags": [purge.cache_tag(name)]}
    assert purge.cache_tag(name).isascii()
    assert purge.cache_tag(name) != purge.cache_tag(name.upper())
    assert kwargs["timeout"] == (3, 5)
    assert kwargs["allow_redirects"] is False
    assert session.execute(select(Purge)).first() is None


@requires_postgres
@pytest.mark.parametrize("failure", ["timeout", "status", "rejected", "malformed"])
def test_failed_purge_retries_without_losing_the_outbox(outbox, failure):
    session, factory, wire = outbox
    purge.enqueue_purge(session, "company")
    session.commit()
    if failure == "timeout":
        wire.side_effect = requests.Timeout("mock timeout")
    elif failure == "status":
        wire.return_value.status_code = 503
    elif failure == "rejected":
        wire.return_value.json = lambda: {"success": False}
    else:
        wire.return_value.json = MagicMock(side_effect=ValueError("invalid JSON"))
    assert purge.purge_one(factory) == "failed"
    attempts, retry_at = session.execute(select(Purge.attempts, Purge.next_attempt_at)).one()
    assert attempts == 1 and retry_at > datetime.now(timezone.utc)
    assert purge.purge_one(factory) == "idle"
    wire.side_effect = None
    wire.return_value = MagicMock(status_code=200, json=lambda: {"success": True})
    session.execute(update(Purge).values(next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    session.commit()
    assert purge.purge_one(factory) == "purged"


@requires_postgres
@pytest.mark.parametrize("success", [True, False])
def test_publication_during_purge_is_not_acknowledged_or_backed_off(outbox, success):
    session, factory, wire = outbox
    purge.enqueue_purge(session, "company")
    session.commit()
    original = session.execute(select(Purge.token)).scalar_one()

    def post(*args, **kwargs):
        with factory() as publisher:
            purge.enqueue_purge(publisher, "company")
            publisher.commit()
        return MagicMock(status_code=200, json=lambda: {"success": success})

    wire.side_effect = post
    assert purge.purge_one(factory) == ("purged" if success else "failed")
    token, attempts = session.execute(select(Purge.token, Purge.attempts)).one()
    assert token != original and attempts == 0


@requires_postgres
def test_retired_names_survive_rename_and_deletion(outbox):
    session, factory, wire = outbox
    protocol = _add_protocol(session, "original")
    session.execute(update(Protocol).where(Protocol.id == protocol.id).values(name="renamed"))
    session.commit()
    session.execute(delete(Protocol).where(Protocol.id == protocol.id))
    session.commit()
    assert set(session.execute(select(Purge.company_name)).scalars()) == {"original", "renamed"}
    assert purge.purge_one(factory) == "purged"
    assert purge.purge_one(factory) == "purged"


@requires_postgres
def test_purge_is_single_flight(outbox):
    session, factory, wire = outbox
    from sqlalchemy import text

    session.execute(text("SELECT pg_advisory_xact_lock(210031, 1)"))
    assert purge.purge_one(factory) == "leased"
    wire.assert_not_called()


@pytest.mark.parametrize(
    "app,flag,zone,token",
    [
        ("psat", "0", "a" * 32, "key"),
        ("preview", "1", "a" * 32, "key"),
        ("psat", "1", "invalid", "key"),
        ("psat", "1", "a" * 32, ""),
    ],
)
def test_unconfigured_or_nonproduction_purge_never_reads_db_or_calls_provider(monkeypatch, app, flag, zone, token):
    for key, value in {
        "FLY_APP_NAME": app,
        "PSAT_COMPANY_PURGE_ENABLED": flag,
        "PSAT_CLOUDFLARE_ZONE_ID": zone,
        "PSAT_CLOUDFLARE_PURGE_TOKEN": token,
    }.items():
        monkeypatch.setenv(key, value)
    factory = MagicMock()
    wire = MagicMock()
    monkeypatch.setattr(purge.requests, "post", wire)
    assert purge.purge_one(factory) == "disabled"
    factory.assert_not_called()
    wire.assert_not_called()


def test_purge_opt_in(monkeypatch):
    monkeypatch.setenv("FLY_APP_NAME", "psat")
    monkeypatch.setenv("PSAT_COMPANY_PURGE_ENABLED", "1")
    monkeypatch.setenv("PSAT_CLOUDFLARE_ZONE_ID", "a" * 32)
    monkeypatch.setenv("PSAT_CLOUDFLARE_PURGE_TOKEN", "test")
    assert purge.purge_config() == ("a" * 32, "test")
