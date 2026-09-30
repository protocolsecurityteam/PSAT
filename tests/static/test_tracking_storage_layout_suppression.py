"""ERC-7201 locators and EIP-1967 slot constants produced dead ``eth_call_error`` rows and shadowed the OZ-v5 owner.

The list is exactly what errored in the etherfi controller_values audit.
"""

from __future__ import annotations

import pytest

from services.static.contract_analysis_pipeline.tracking import (
    _is_storage_layout_constant,
)

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
