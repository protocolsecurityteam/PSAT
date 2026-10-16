import os
import shutil

import pytest
from hypothesis import HealthCheck, settings

from tests.fuzz.authority import SOLCS, solc_path

settings.register_profile("_base", deadline=None, suppress_health_check=[HealthCheck.too_slow], print_blob=True)
# PR CI: a fixed, reproducible sample. Nightly/local deep runs: HYPOTHESIS_PROFILE=deep.
settings.register_profile("ci", settings.get_profile("_base"), max_examples=100, derandomize=True, database=None)
settings.register_profile(
    "deep", settings.get_profile("_base"), max_examples=int(os.environ.get("HYPOTHESIS_MAX_EXAMPLES", 1000))
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))


def pytest_collection_modifyitems(items):
    missing = [v for v in SOLCS if solc_path(v) is None]
    for item in items:
        if "tests/fuzz/" not in str(item.fspath):
            continue
        if missing:
            item.add_marker(pytest.mark.skip(reason=f"solc {missing} not installed"))
        if "anvil" in item.keywords and shutil.which("anvil") is None:
            item.add_marker(pytest.mark.skip(reason="anvil not on PATH"))


@pytest.fixture(scope="module")
def anvil_url():
    from tests.support.anvil import _start_anvil, _terminate

    proc, port = _start_anvil()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        _terminate(proc)
