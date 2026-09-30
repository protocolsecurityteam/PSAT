"""Wire helper: read a plain contract's controlling addresses via canonical control getters.

Probes owner()/authority()/admin() every call and returns the DISTINCT nonzero set so the
walk can fail closed on parallel control planes. Stubs the eth_call layer, never the transport."""

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
    """Map signature -> the getter's outcome at the ``eth_call`` layer.

    A value is an address string (successful read), ``"revert"`` (the EVM answered: not a
    control plane, distinct from a transport failure), ``"transport"`` (the read did not
    happen: indeterminate), or absent (== ``revert``; a missing selector reverts on chain).
    """

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
        # Parallel control planes (Solmate/Solady Auth): both witnessed, owner/authority order.
        pytest.param({"owner()": OWNER, "authority()": AUTHORITY}, [OWNER, AUTHORITY], id="distinct-both-in-order"),
        # owner() == authority() (case-insensitively) is ONE controller, not two.
        pytest.param({"owner()": OWNER, "authority()": OWNER.upper()}, [OWNER], id="same-address-deduped"),
        # authority() cleanly returns zero -> genuinely not a plane; owner() stands.
        pytest.param({"owner()": OWNER, "authority()": ZERO}, [OWNER], id="clean-zero-single-plane"),
        # An empty stub reverts every getter, the same probe-set silence as all three reverting.
        pytest.param({}, [], id="no-getter-present"),
        # owner() answers but authority() fails to be READ -> the plane set is not dispositively
        # complete (a real second plane could hide behind the failure), so None (retryable) rather
        # than a possibly-false single plane.
        pytest.param({"owner()": OWNER, "authority()": "transport"}, None, id="any-getter-transport-error"),
        pytest.param(
            {"owner()": "transport", "authority()": "transport", "admin()": "transport"},
            None,
            id="all-getters-transport-error",
        ),
        # A REVERT is the EVM answering ("not a control plane"); a TRANSPORT failure is the read not
        # happening. Every failure used to be one ``_PROBE_ERROR``, so a contract with no
        # ``authority()`` (most of them) tripped the incomplete-witness guard and the WHOLE plane set
        # came back None: terminal_principal.status was ``unknown_unfetched`` on 180/180 armed rows.
        # The common real shape: owner() answers; authority()/admin() revert (undeclared).
        pytest.param(
            {"owner()": OWNER, "authority()": "revert", "admin()": "revert"},
            [OWNER],
            id="reverting-getters-are-not-an-error",
        ),
        # All three reverting is probe-set SILENCE, NOT proof of no controller: an ownerless
        # DepositContract and a kernel()/unpauser()-governed contract give the identical [].
        # The walk publishes it as ``controllers_not_determined`` with this basis.
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


def test_whole_batch_failure_returns_none(monkeypatch):
    def _raise(*_args, **_kwargs):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(tracking, "_eth_call_batch", _raise)
    assert read_contract_controllers("http://rpc", CONTRACT) is None


# ---------------------------------------------------------------------------
# A REVERT is the EVM answering ("not a control plane"); a TRANSPORT failure is the read
# not happening. Every failure used to be one ``_PROBE_ERROR``, so a contract with no
# ``authority()`` (most of them) tripped the incomplete-witness guard and the WHOLE plane
# set came back None: terminal_principal.status was ``unknown_unfetched`` on 180/180 armed
# rows and 5 of the 6 statuses had never fired.
# ---------------------------------------------------------------------------


def test_revert_with_data_is_also_definitive(monkeypatch):
    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        # A custom-error revert carries data and no recognisable message.
        return [EthCallResult(False, "0x", "0x2603b7da", None) for _ in calls]

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) == []


def test_unrecognised_failure_stays_indeterminate(monkeypatch):
    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        # No revert data and no revert marker: fail closed (None) rather than
        # call it canonical-getter silence ([]).
        return [EthCallResult(False, "0x", None, "out of gas") for _ in calls]

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) is None


def test_answers_every_selector_is_indeterminate_not_a_plane_set(monkeypatch):
    # INVERTED from `test_undecodable_success_is_not_a_plane_and_not_an_error` (which pinned []):
    # an address answering EVERY call, including the negative-control selector, is a catch-all
    # fallback, so the set is not dispositively readable. None, never [] (that token is for
    # canonical-getter silence on an honestly-dispatching contract).
    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        return [EthCallResult(True, "0x1234", None, None) for _ in calls]

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) is None


def test_undecodable_success_with_honest_control_is_not_a_plane(monkeypatch):
    # Original arm with an honest negative control: getters answer garbage but the nonsense
    # selector reverts -> reads happened, nothing decodes -> canonical-getter silence ([]).
    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        control_selector = selector(tracking._NEGATIVE_CONTROL_SIG)
        out = []
        for call in calls:
            if call["data"] == control_selector:
                out.append(EthCallResult(False, "0x", None, "execution reverted"))
            else:
                out.append(EthCallResult(True, "0x1234", None, None))
        return out

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) == []
