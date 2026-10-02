import pytest

from services.concurrency import RpcExecutor
from services.resolution import tracking


@pytest.fixture(autouse=True)
def _reset_executor():
    RpcExecutor.reset_for_tests()
    yield
    RpcExecutor.reset_for_tests()


@pytest.fixture(autouse=True)
def _isolated_classify_cache():
    tracking.clear_classify_cache()
    yield
    tracking.clear_classify_cache()


@pytest.fixture(autouse=True)
def _disable_scan_confirmation_depth(monkeypatch):
    # The 12-block confirmation clamp would hide events on a short Anvil chain.
    monkeypatch.setenv("PSAT_SCAN_CONFIRMATION_DEPTH", "0")
