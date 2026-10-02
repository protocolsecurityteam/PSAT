"""Returns the distinct nonzero owner()/authority()/admin() set so the walk can fail closed on parallel control
planes.
"""

from __future__ import annotations

import pytest

from services.clients.rpc import EthCallResult, selector
from services.resolution import tracking
from services.resolution.tracking import read_contract_controllers

OWNER = "0x" + "a" * 40
AUTHORITY = "0x" + "b" * 40
CONTRACT = "0x" + "1" * 40
ZERO = "0x" + "0" * 40


def _word(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def _stub(monkeypatch, answers):
    """A revert is the EVM answering; a transport failure means the read didn't happen."""

    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        out = []
        by_selector = {selector(sig): value for sig, value in answers.items()}
        for call in calls:
            value = by_selector.get(call["data"], "revert")
            if value == "transport":
                out.append(EthCallResult(False, "0x", None, "connection reset"))
            elif value == "revert":
                out.append(EthCallResult(False, "0x", None, "execution reverted"))
            elif value is None:
                out.append(EthCallResult(True, "0x", None, None))
            else:
                out.append(EthCallResult(True, _word(value), None, None))
        return out

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        pytest.param({"owner()": OWNER}, [OWNER], id="owner-getter"),
        pytest.param({"authority()": AUTHORITY}, [AUTHORITY], id="authority-when-owner-absent"),
        pytest.param({"owner()": OWNER, "authority()": AUTHORITY}, [OWNER, AUTHORITY], id="distinct-both-in-order"),
        pytest.param({"owner()": OWNER, "authority()": OWNER.upper()}, [OWNER], id="same-address-deduped"),
        pytest.param({"owner()": OWNER, "authority()": ZERO}, [OWNER], id="clean-zero-single-plane"),
        pytest.param({}, [], id="no-getter-present"),
        # A second plane could hide behind the failed read.
        pytest.param({"owner()": OWNER, "authority()": "transport"}, None, id="any-getter-transport-error"),
        pytest.param(
            {"owner()": "transport", "authority()": "transport", "admin()": "transport"},
            None,
            id="all-getters-transport-error",
        ),
        # Every failure used to be one ``_PROBE_ERROR``, so a missing ``authority()`` voided the whole set
        # (``unknown_unfetched`` on 180/180 rows).
        pytest.param(
            {"owner()": OWNER, "authority()": "revert", "admin()": "revert"},
            [OWNER],
            id="reverting-getters-are-not-an-error",
        ),
        # An ownerless DepositContract and a kernel()-governed contract give the identical [].
        pytest.param(
            {"owner()": "revert", "authority()": "revert", "admin()": "revert"},
            [],
            id="all-getters-reverting-is-silence",
        ),
    ],
)
def test_reads_controllers_from_getter_answers(monkeypatch, answers, expected):
    _stub(monkeypatch, answers)
    assert read_contract_controllers("http://rpc", CONTRACT) == expected


def test_revert_with_data_is_also_definitive(monkeypatch):
    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        return [EthCallResult(False, "0x", "0x2603b7da", None) for _ in calls]

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) == []


def test_answers_every_selector_is_indeterminate_not_a_plane_set(monkeypatch):
    # An address answering the negative control too is a catch-all fallback.
    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        return [EthCallResult(True, "0x1234", None, None) for _ in calls]

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) is None
