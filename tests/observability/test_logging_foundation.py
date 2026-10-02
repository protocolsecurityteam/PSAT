from __future__ import annotations

import json
import logging
import logging.config
import sys
import warnings

import pytest

from utils.logging import (
    CryticCompileEchoDemoter,
    JsonFormatter,
    _install_third_party_log_hygiene,
    bind_trace_context,
    stream_subprocess,
    uvicorn_log_config,
)

pytestmark = pytest.mark.compile


def test_stream_subprocess_streams_lines_at_debug_with_source(caplog):
    logger = logging.getLogger("test.stream_subprocess.ok")
    code = "import sys; print('out-line'); print('err-line', file=sys.stderr)"
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        rc = stream_subprocess(
            [sys.executable, "-c", code],
            logger=logger,
            source="probe",
        )

    assert rc == 0
    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    messages = {r.getMessage() for r in debug_records}
    assert "out-line" in messages
    assert "err-line" in messages
    assert all(getattr(r, "source", None) == "probe" for r in debug_records)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_stream_subprocess_warns_on_nonzero_exit(caplog):
    logger = logging.getLogger("test.stream_subprocess.fail")
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        rc = stream_subprocess(
            [sys.executable, "-c", "import sys; sys.exit(3)"],
            logger=logger,
            source="forge",
        )

    assert rc == 3
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    (warning,) = warnings
    assert warning.source == "forge"
    assert warning.returncode == 3


def test_stream_subprocess_respects_custom_level(caplog):
    logger = logging.getLogger("test.stream_subprocess.level")
    with caplog.at_level(logging.INFO, logger=logger.name):
        stream_subprocess(
            [sys.executable, "-c", "print('hi')"],
            logger=logger,
            source="git",
            level=logging.INFO,
        )

    info_lines = [r for r in caplog.records if r.getMessage() == "hi"]
    assert info_lines and info_lines[0].levelno == logging.INFO


def test_uvicorn_log_config_is_applicable_dictconfig():
    cfg = uvicorn_log_config()
    try:
        logging.config.dictConfig(cfg)
        handler = logging.getLogger("uvicorn.access").handlers[0]
        assert isinstance(handler.formatter, JsonFormatter)
    finally:
        logging.config.dictConfig({"version": 1, "disable_existing_loggers": False})


def test_uvicorn_log_config_level_defaults_from_env(monkeypatch):
    monkeypatch.setenv("PSAT_LOG_LEVEL", "warning")
    cfg = uvicorn_log_config()
    assert cfg["loggers"]["uvicorn"]["level"] == "WARNING"


def test_jsonformatter_scrubs_secrets_in_message_extra_and_exc_info():
    # A credentialed URL must not survive in the message, an extra field, or a traceback.
    fmt = JsonFormatter()
    secret_url = "https://eth-mainnet.g.alchemy.com/v2/SUPERSECRETKEY123"

    record = logging.LogRecord(
        name="test.scrub",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="calling %s",
        args=(secret_url,),
        exc_info=None,
    )
    record.endpoint = secret_url  # bare-string extra
    record.payload = {"rpc_url": secret_url}  # nested-dict extra
    record.count = 7  # non-string scalar passes through untouched

    out = json.loads(fmt.format(record))
    assert "SUPERSECRETKEY123" not in json.dumps(out)
    assert "<redacted>" in out["message"]
    assert "<redacted>" in json.dumps(out["payload"])
    assert out["count"] == 7

    try:
        raise RuntimeError(f"connect failed for {secret_url}")
    except RuntimeError:
        exc_record = logging.LogRecord(
            name="test.scrub",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="boom",
            args=(),
            exc_info=sys.exc_info(),
        )
    exc_out = json.loads(fmt.format(exc_record))
    assert "exc_info" in exc_out
    assert "SUPERSECRETKEY123" not in json.dumps(exc_out)


def test_bound_contextvar_shadows_a_colliding_extra_key():
    """The contextvar wins and the colliding ``extra`` is silently dropped.

    It usually looks right because the two agree, which is why it has bitten ``transcript_job_id``, ``probe_chain``,
    ``bundle_address`` and ``contract_address``. Never name an extra after one of the six contextvars unless you
    mean the ambient one.
    """
    fmt = JsonFormatter()
    record = logging.LogRecord(
        name="test.shadowing",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="reads reverted",
        args=(),
        exc_info=None,
    )
    record.address = "0x" + "ee" * 20  # the collision
    record.contract_address = "0x" + "11" * 20  # the qualified spelling
    record.chain = "base"

    with bind_trace_context(address="0x" + "99" * 20, chain="ethereum"):
        out = json.loads(fmt.format(record))

    assert out["address"] == "0x" + "99" * 20
    assert out["chain"] == "ethereum"
    assert "0x" + "ee" * 20 not in json.dumps(out)
    assert out["contract_address"] == "0x" + "11" * 20

    out_unbound = json.loads(fmt.format(record))
    assert out_unbound["address"] == "0x" + "ee" * 20


def _crytic_record(msg: str, *, args=(), exc_info=None) -> logging.LogRecord:
    record = logging.LogRecord(
        name="CryticCompile",
        level=logging.ERROR,
        pathname="/x/crytic_compile/utils/subprocess.py",
        lineno=67,
        msg=msg,
        args=args,
        exc_info=exc_info,
    )
    record.funcName = "run"
    return record


def test_crytic_unprovable_echo_stays_visible_at_warning():
    """Single-line output may name the failure, so demote to WARNING at most."""
    demoter = CryticCompileEchoDemoter()
    record = _crytic_record("Error: Encountered invalid solc version in src/Foo.sol")

    assert demoter.filter(record) is True
    assert record.levelno == logging.WARNING


def test_crytic_authored_diagnostics_keep_their_error_level():
    demoter = CryticCompileEchoDemoter()
    exit_code = _crytic_record("'%s' returned non-zero exit code %d", args=("forge", 1))
    os_error = _crytic_record("OS error executing:", exc_info=(ValueError, ValueError("x"), None))

    for record in (exit_code, os_error):
        assert demoter.filter(record) is True
        assert record.levelno == logging.ERROR


def test_crytic_demoter_ignores_records_from_other_call_sites():
    """If upstream moves the echo, the record keeps its level rather than being demoted blind."""
    demoter = CryticCompileEchoDemoter()
    record = _crytic_record("some future authored error")
    record.funcName = "compile"

    assert demoter.filter(record) is True
    assert record.levelno == logging.ERROR


def test_third_party_hygiene_is_idempotent_and_captures_warnings(caplog):
    crytic = logging.getLogger("CryticCompile")
    before = [f for f in crytic.filters if isinstance(f, CryticCompileEchoDemoter)]
    for stale in before:
        crytic.removeFilter(stale)
    try:
        with warnings.catch_warnings():
            # ``captureWarnings(True)`` is a no-op once engaged and pytest reassigns ``showwarning`` per test.
            logging.captureWarnings(False)
            warnings.simplefilter("always")

            _install_third_party_log_hygiene()
            _install_third_party_log_hygiene()
            assert len([f for f in crytic.filters if isinstance(f, CryticCompileEchoDemoter)]) == 1

            with caplog.at_level(logging.WARNING, logger="py.warnings"):
                warnings.warn("captured into logging", UserWarning)
            assert any(record.name == "py.warnings" for record in caplog.records)
    finally:
        for installed in [f for f in crytic.filters if isinstance(f, CryticCompileEchoDemoter)]:
            crytic.removeFilter(installed)
        for original in before:
            crytic.addFilter(original)
        logging.captureWarnings(False)
        logging.captureWarnings(True)


def test_serve_disables_uvicorn_access_log_and_passes_json_config(monkeypatch):
    """The api middleware already logs every request, and uvicorn takes a log config only as a file."""
    import api

    captured: dict[str, object] = {}

    class _FakeUvicorn:
        @staticmethod
        def run(app, **kwargs):
            captured["app"] = app
            captured.update(kwargs)

    monkeypatch.setitem(sys.modules, "uvicorn", _FakeUvicorn)
    monkeypatch.setenv("PSAT_API_HOST", "0.0.0.0")
    monkeypatch.setenv("PSAT_API_PORT", "8123")
    monkeypatch.setenv("PSAT_API_LIMIT_CONCURRENCY", "200")
    monkeypatch.delenv("PSAT_API_RELOAD", raising=False)

    api.serve()

    assert captured["app"] == "api:app"
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 8123
    assert captured["limit_concurrency"] == 200
    assert captured["reload"] is False
    assert captured["access_log"] is False
    log_config = captured["log_config"]
    assert isinstance(log_config, dict)
    assert log_config["formatters"]["json"]["()"].endswith("JsonFormatter")
    assert set(log_config["loggers"]) == {"uvicorn", "uvicorn.error", "uvicorn.access"}
