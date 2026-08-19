"""Storage-layout slot constants must not be emitted as controller candidates.

ERC-7201 namespaced-storage locators (``OwnableStorageLocation`` …) and EIP-1967
slot constants (``_IMPLEMENTATION_SLOT`` …) were being classified as
``role_identifier`` / ``state_variable`` controllers — producing dead
``eth_call_error`` rows (``OwnableStorageLocation()`` reverts) and, for OZ-v5
Ownable, shadowing the real owner. They are storage-layout pointers, never
controllers. The name list below is exactly the set observed erroring in the
real etherfi controller_values audit.
"""

from __future__ import annotations

import pytest

from services.static.contract_analysis_pipeline.tracking import (  # noqa: E402
    _is_storage_layout_constant,
)

# Observed erroring in prod controller_values (protocol_id=1 etherfi run).
SUPPRESSED = [
    "OwnableStorageLocation",
    "PausableStorageLocation",
    "ReentrancyGuardStorageLocation",
    "AccessControlDefaultAdminRulesStorageLocation",
    "EIP712StorageLocation",
    "BaseMessengerStorageLocation",
    "UpgradeableProxyStorageLocation",
    "INITIALIZABLE_STORAGE",
    "REENTRANCY_GUARD_STORAGE",
    "_IMPLEMENTATION_SLOT",
    "_ROLLBACK_SLOT",
    "_OWNER_SLOT",
    "__self",
]

# Real controllers/roles that MUST keep flowing through resolution.
KEPT = [
    "DEFAULT_ADMIN_ROLE",
    "MINTER_ROLE",
    "PAUSER_ROLE",
    "owner",
    "_owner",
    "authority",
    "governor",
    "etherFiAdmin",
    "liquidityPool",
    "admin",
    "pendingOwner",
]


@pytest.mark.parametrize("name", SUPPRESSED)
def test_storage_layout_constants_are_suppressed(name: str) -> None:
    assert _is_storage_layout_constant(name) is True


@pytest.mark.parametrize("name", KEPT)
def test_real_controllers_are_not_suppressed(name: str) -> None:
    assert _is_storage_layout_constant(name) is False


def test_empty_name_is_not_suppressed() -> None:
    assert _is_storage_layout_constant("") is False
