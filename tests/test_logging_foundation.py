"""Offline coverage for the Wave-0 shared logging primitives.

Exercises only the two new dependency-light helpers in ``utils.logging``
(subprocess-output capture + the uvicorn JSON ``dictConfig``). No DB, no
network — both run purely against stdlib ``subprocess``/``logging``.
"""

from __future__ import annotations

import logging
import logging.config
import sys

from utils.logging import JsonFormatter, stream_subprocess, uvicorn_log_config


def test_stream_subprocess_streams_lines_at_debug_with_source(caplog):
    logger = logging.getLogger("test.stream_subprocess.ok")
    code = (
        "import sys; "
        "print('out-line'); "
        "print('err-line', file=sys.stderr)"
    )
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        rc = stream_subprocess(
            [sys.executable, "-c", code],
            logger=logger,
            source="probe",
        )

    assert rc == 0
    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    messages = {r.getMessage() for r in debug_records}
    # stdout + stderr are merged and both surface as DEBUG lines.
    assert "out-line" in messages
    assert "err-line" in messages
    # Every captured line carries the source tag for queryability.
    assert all(getattr(r, "source", None) == "probe" for r in debug_records)
    # A clean exit emits no WARNING.
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


def test_uvicorn_log_config_routes_through_json_formatter():
    cfg = uvicorn_log_config(level=logging.INFO)

    assert cfg["version"] == 1
    assert cfg["disable_existing_loggers"] is False
    assert cfg["formatters"]["json"]["()"] == "utils.logging.JsonFormatter"
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        spec = cfg["loggers"][name]
        assert spec["handlers"] == ["json"]
        assert spec["level"] == logging.INFO
        assert spec["propagate"] is False


def test_uvicorn_log_config_is_applicable_dictconfig():
    # dictConfig must accept it and instantiate a real JsonFormatter.
    cfg = uvicorn_log_config()
    try:
        logging.config.dictConfig(cfg)
        handler = logging.getLogger("uvicorn.access").handlers[0]
        assert isinstance(handler.formatter, JsonFormatter)
    finally:
        # dictConfig mutates global logging state; reset so we don't leak
        # the uvicorn handlers/levels into other tests in the session.
        logging.config.dictConfig({"version": 1, "disable_existing_loggers": False})


def test_uvicorn_log_config_level_defaults_from_env(monkeypatch):
    monkeypatch.setenv("PSAT_LOG_LEVEL", "warning")
    cfg = uvicorn_log_config()
    assert cfg["loggers"]["uvicorn"]["level"] == "WARNING"
