"""Discovery must not emit non-authority state vars as resolvable controllers.

Two complementary admission predicates in
``build_controller_tracking`` (the single producer of controller targets):

* A bare non-address aggregate (struct/array/mapping) with no ``member_path``
  has no single storable address value — only the member-path projection of an
  address field is a controller.
* A compile-time ``constant`` address/contract consulted only by business logic
  (never under a ``caller_authority`` / ``delegated_authority`` leaf) is a
  sentinel identifier, not an authority.

Each case compiles real Solidity through Slither and drives the production
predicate/effects/tracking builders end to end.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)
from services.static.contract_analysis_pipeline.tracking import (  # noqa: E402
    _collect_state_var_authority_roles,
    build_controller_tracking,
)


def _compile(tmp_path: Path, source: str, contract_name: str):
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == contract_name)


def _build(tmp_path: Path, source: str, contract_name: str):
    contract = _compile(tmp_path, source, contract_name)
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    return build_controller_tracking(contract, tmp_path, predicate_trees, effects, semantic_control)


# ---------------------------------------------------------------------------
# Authority-role collector — the signal predicate 2 threads.
# ---------------------------------------------------------------------------


def test_authority_role_collector_groups_by_operand():
    trees = {
        "trees": {
            "a()": {
                "op": "LEAF",
                "leaf": {
                    "authority_role": "caller_authority",
                    "operands": [{"source": "state_variable", "state_variable_name": "owner"}],
                },
            },
            "b()": {
                "op": "LEAF",
                "leaf": {
                    "authority_role": "business",
                    "operands": [{"source": "state_variable", "state_variable_name": "SENTINEL"}],
                },
            },
            # A leaf with no authority_role contributes nothing.
            "c()": {
                "op": "LEAF",
                "leaf": {"operands": [{"source": "state_variable", "state_variable_name": "ROLELESS"}]},
            },
        }
    }
    roles = _collect_state_var_authority_roles(trees)
    assert roles == {"owner": {"caller_authority"}, "SENTINEL": {"business"}}


def test_authority_role_collector_handles_malformed_input():
    assert _collect_state_var_authority_roles(None) == {}
    assert _collect_state_var_authority_roles({"trees": "not-a-dict"}) == {}


# ---------------------------------------------------------------------------
# Predicate 1 — bare aggregate without member_path is dropped; the projected
# address member survives.
# ---------------------------------------------------------------------------


def test_bare_struct_dropped_member_projection_kept(tmp_path):
    """AccountantWithRateProviders shape: the whole ``accountantState`` struct is
    not a controller, but ``accountantState.payoutAddress`` is."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        struct AccountantState {
            address payoutAddress;
            uint96 highwaterMark;
            bool isPaused;
        }
        AccountantState public accountantState;
        function sweep() external view {
            require(msg.sender == accountantState.payoutAddress, "not payout");
        }
    }
    """
    by_id = {t["controller_id"]: t for t in _build(tmp_path, source, "C")}
    assert "state_variable:accountantState" not in by_id, list(by_id.keys())
    assert "state_variable:accountantState.payoutAddress" in by_id, list(by_id.keys())
    projected = dict(by_id["state_variable:accountantState.payoutAddress"]["read_spec"] or {})
    assert projected["type_kind"] == "address"
    assert projected["member_path"] == ["payoutAddress"]


def test_bare_struct_without_address_member_fully_dropped(tmp_path):
    """LRTSquaredCore ``rateLimit`` shape: a struct used in a business comparison
    with no projected address member yields no controller at all."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        struct RateLimit {
            uint256 limit;
            uint256 used;
            uint64 updatedAt;
        }
        RateLimit private rateLimit;
        uint256 public total;
        function consume(uint256 amount) external {
            require(amount + rateLimit.used <= rateLimit.limit, "rate");
            total += amount;
        }
    }
    """
    by_id = {t["controller_id"]: t for t in _build(tmp_path, source, "C")}
    assert "state_variable:rateLimit" not in by_id, list(by_id.keys())
    assert not any(cid.startswith("state_variable:rateLimit") for cid in by_id), list(by_id.keys())


# ---------------------------------------------------------------------------
# Predicate 2 — business-only compile-time constant sentinel is dropped; a
# constant the caller is gated on, and immutable business contracts, survive.
# ---------------------------------------------------------------------------


def test_business_only_constant_sentinel_dropped(tmp_path):
    """EigenPodManager shape: ``beaconChainETHStrategy`` is a constant compared
    against a function PARAMETER (business logic) — not an authority."""
    source = """
    pragma solidity ^0.8.19;
    interface IStrategy {}
    contract C {
        IStrategy public constant beaconChainETHStrategy =
            IStrategy(0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0);
        mapping(address => uint256) public shares;
        function addShares(address staker, IStrategy strategy, uint256 amount) external {
            require(strategy != beaconChainETHStrategy, "no beacon");
            shares[staker] += amount;
        }
    }
    """
    by_id = {t["controller_id"]: t for t in _build(tmp_path, source, "C")}
    assert "state_variable:beaconChainETHStrategy" not in by_id, list(by_id.keys())


def test_business_only_constant_address_sentinel_dropped(tmp_path):
    """A getter-less ``internal constant`` sentinel address consulted only in
    business logic (DEFAULT_BURN_ADDRESS / NATIVE / DEFAULT_LIB shape) is not an
    authority and is dropped — the same constant-business-only predicate as the
    contract-typed sentinel."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        address internal constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
        uint256 public total;
        function deposit(address token, uint256 amount) external {
            require(token != NATIVE, "no native");
            total += amount;
        }
    }
    """
    by_id = {t["controller_id"]: t for t in _build(tmp_path, source, "C")}
    assert "state_variable:NATIVE" not in by_id, list(by_id.keys())


def test_constant_address_caller_authority_survives(tmp_path):
    """UnwrapTokenV1ETH shape: a constant address the caller is required to equal
    (``require(msg.sender == WBETH_TOKEN_ADDRESS)``) is a real authority."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        address constant WBETH_TOKEN_ADDRESS = 0xa2E3356610840701BDf5611a53974510Ae27E2e1;
        uint256 public total;
        function burn(uint256 amount) external {
            require(msg.sender == WBETH_TOKEN_ADDRESS, "only wbeth");
            total += amount;
        }
    }
    """
    by_id = {t["controller_id"]: t for t in _build(tmp_path, source, "C")}
    assert "state_variable:WBETH_TOKEN_ADDRESS" in by_id, list(by_id.keys())


def test_immutable_business_contract_survives(tmp_path):
    """The 8 immutable business-only contracts (EIGEN, eigenStrategy, …) are
    ``is_constant == False`` and must survive even when referenced only in
    business leaves."""
    source = """
    pragma solidity ^0.8.19;
    interface IToken {}
    contract C {
        IToken public immutable EIGEN;
        uint256 public total;
        constructor(IToken eigen) { EIGEN = eigen; }
        function route(IToken token, uint256 amount) external {
            require(token == EIGEN, "only eigen");
            total += amount;
        }
    }
    """
    by_id = {t["controller_id"]: t for t in _build(tmp_path, source, "C")}
    assert "state_variable:EIGEN" in by_id, list(by_id.keys())


def test_immutable_authority_survives(tmp_path):
    """``delegationManager`` is immutable (not constant) and gated on
    (``msg.sender == delegationManager``) — must survive."""
    source = """
    pragma solidity ^0.8.19;
    interface IDelegationManager {}
    contract C {
        IDelegationManager public immutable delegationManager;
        uint256 public total;
        constructor(IDelegationManager dm) { delegationManager = dm; }
        function recordUpdate(uint256 amount) external {
            require(msg.sender == address(delegationManager), "only dm");
            total += amount;
        }
    }
    """
    by_id = {t["controller_id"]: t for t in _build(tmp_path, source, "C")}
    assert "state_variable:delegationManager" in by_id, list(by_id.keys())
