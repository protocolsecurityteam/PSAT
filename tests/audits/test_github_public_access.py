from types import SimpleNamespace

from services.audits import source_equivalence as eq


def reply(status, body="contract C {}", payload=None):
    return SimpleNamespace(
        status_code=status,
        headers={"content-type": "text/plain"},
        content=body.encode(),
        text=body,
        json=lambda: payload or {},
    )


def test_public_source_never_receives_unrelated_credential(monkeypatch):
    calls = []

    def get(url, **kwargs):
        calls.append(kwargs["headers"])
        return reply(404 if "Authorization" in kwargs["headers"] else 200)

    monkeypatch.setattr(eq.requests, "get", get)
    assert eq._fetch_github_raw("https://raw.githubusercontent.com/org/repo/ref/C.sol", "bad-token").status == "ok"
    assert len(calls) == 1 and "Authorization" not in calls[0]


def test_private_source_can_use_configured_credential(monkeypatch):
    calls = []

    def get(url, **kwargs):
        calls.append(kwargs["headers"])
        return reply(200 if "Authorization" in kwargs["headers"] else 404)

    monkeypatch.setattr(eq.requests, "get", get)
    assert eq._fetch_github_raw("https://raw.githubusercontent.com/org/private/ref/C.sol", "token").status == "ok"
    assert len(calls) == 2


def test_auth_failure_is_retryable_and_not_memoized(monkeypatch):
    monkeypatch.setattr(eq.requests, "get", lambda *a, **k: reply(403))
    url = "https://raw.githubusercontent.com/org/repo/ref/D.sol"
    eq._fetch_github_raw_hash.cache_clear()
    assert eq._fetch_github_raw_hash(url, "token").status == "auth_error"
    monkeypatch.setattr(eq.requests, "get", lambda *a, **k: reply(200))
    assert eq._fetch_github_raw_hash(url, "token").status == "ok"


def test_commit_existence_does_not_require_readme(monkeypatch):
    urls = []
    sha = "ab" * 20

    def get(url, **kwargs):
        urls.append(url)
        return reply(200, payload={"sha": sha}) if "/commits/" in url else reply(404)

    monkeypatch.setattr(eq.requests, "get", get)
    assert eq._commit_exists_in_repo("org/repo", sha).status == "ok"
    assert len(urls) == 1 and "README" not in urls[0]
