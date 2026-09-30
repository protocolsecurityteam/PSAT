"""EIP-1967 proxy flow: classify → resolve impl → emit classifications → spawn impl child job."""

from __future__ import annotations

import pytest

from tests.live.conftest import DEFAULT_SINGLE_TIMEOUT, LiveClient
from tests.support.live_helpers import _resolve_impl_job

USDC_PROXY = "0xA0b86991c6218b36c1D19D4a2e9Eb0cE3606eB48"  # USDC FiatTokenProxy, EIP-1967


@pytest.fixture(scope="module")
def usdc_job(live_client: LiveClient) -> dict:
    # Module-scoped so the USDC run is amortized across the four tests in this file.
    job = live_client.submit_and_wait(USDC_PROXY, timeout=DEFAULT_SINGLE_TIMEOUT)
    if job["status"] != "completed":
        pytest.fail(f"USDC proxy analysis did not complete: {job.get('error')}")
    return job


def test_contract_flags_marks_proxy(usdc_job, live_client: LiveClient):
    flags = live_client.artifact(usdc_job["job_id"], "contract_flags")
    assert isinstance(flags, dict)
    assert flags.get("is_proxy") is True, f"USDC should be detected as a proxy, got flags={flags}"


def test_implementation_is_resolved(usdc_job, live_client: LiveClient):
    flags = live_client.artifact(usdc_job["job_id"], "contract_flags")
    assert isinstance(flags, dict)
    impl = flags.get("implementation")
    assert isinstance(impl, str) and impl.startswith("0x") and len(impl) == 42, (
        f"implementation should be a 0x-prefixed address, got {impl!r}"
    )
    assert impl.lower() != USDC_PROXY.lower(), "implementation must differ from proxy (else resolution silently failed)"


def test_classifications_artifact_non_empty(usdc_job, live_client: LiveClient):
    cls = live_client.artifact(usdc_job["job_id"], "classifications")
    assert isinstance(cls, dict), "classifications artifact should exist and be JSON"
    entries = cls.get("classifications") or {}
    assert entries, "classifications map should not be empty for a proxy"


def test_implementation_job_completed(usdc_job, live_client: LiveClient):
    flags = live_client.artifact(usdc_job["job_id"], "contract_flags")
    assert isinstance(flags, dict)
    impl = (flags.get("implementation") or "").lower()
    assert impl

    # The invariant is "the impl has a completed analysis job somewhere", not "this parent spawned a child": on a
    # warm preview DB the static worker reuses the existing impl job, so the helper falls back to a full ``jobs()``
    # lookup and polls until terminal (a synchronous assert raced the impl pipeline).
    impl_job = _resolve_impl_job(live_client, parent_job_id=usdc_job["job_id"], impl_address=impl)
    assert impl_job, f"No analysis job of any age found for implementation {impl}"

    assert impl_job["status"] == "completed", (
        f"Implementation {impl} analysis is {impl_job['status']!r}: error={impl_job.get('error')}"
    )
