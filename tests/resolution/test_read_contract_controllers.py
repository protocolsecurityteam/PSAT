"""Wire helper: read a plain contract's controlling addresses via canonical
control getters. Probes owner()/authority()/admin() every call
and returns the DISTINCT nonzero set so the walk can fail closed on parallel
control planes. Stubs the eth_call layer, never the transport."""

from __future__ import annotations

from services.resolution import tracking
from services.resolution.tracking import read_contract_controllers
from utils.rpc import EthCallResult, selector

OWNER = "0x" + "a" * 40
AUTHORITY = "0x" + "b" * 40
CONTRACT = "0x" + "1" * 40
ZERO = "0x" + "0" * 40


def _word(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def _stub(monkeypatch, answers):
    """Map signature -> the getter's outcome, at the ``eth_call`` layer (never
    the transport). A value may be:

      * an address string  -> a successful read
      * ``"revert"``       -> the EVM answered: this getter is not a control
                              plane (the shape a contract without ``authority()``
                              produces, and the case that used to be
                              indistinguishable from a transport failure)
      * ``"transport"``    -> the read did not happen: indeterminate
      * absent             -> ``revert`` (a missing selector reverts on chain)
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


def test_reads_owner_getter(monkeypatch):
    _stub(monkeypatch, {"owner()": OWNER})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER]


def test_reads_authority_when_owner_absent(monkeypatch):
    _stub(monkeypatch, {"authority()": AUTHORITY})
    assert read_contract_controllers("http://rpc", CONTRACT) == [AUTHORITY]


def test_both_owner_and_authority_distinct_returns_both_in_order(monkeypatch):
    # Parallel control planes (Solmate/Solady Auth): both are witnessed, in
    # owner/authority precedence order.
    _stub(monkeypatch, {"owner()": OWNER, "authority()": AUTHORITY})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER, AUTHORITY]


def test_same_address_from_two_getters_deduped(monkeypatch):
    # owner() == authority() (case-insensitively) is ONE controller, not two.
    _stub(monkeypatch, {"owner()": OWNER, "authority()": OWNER.upper()})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER]


def test_clean_zero_is_not_an_error_proceeds_single_plane(monkeypatch):
    # authority() cleanly returns zero -> genuinely not a plane; owner() stands.
    _stub(monkeypatch, {"owner()": OWNER, "authority()": ZERO})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER]


def test_no_getter_present_is_empty(monkeypatch):
    _stub(monkeypatch, {})
    assert read_contract_controllers("http://rpc", CONTRACT) == []


def test_any_getter_transport_error_makes_set_incomplete_returns_none(monkeypatch):
    # owner() answers but authority() fails to be READ -> the plane set is not
    # dispositively complete (a real second plane could hide behind the failure),
    # so return None (retryable) rather than a possibly-false single plane.
    _stub(monkeypatch, {"owner()": OWNER, "authority()": "transport"})
    assert read_contract_controllers("http://rpc", CONTRACT) is None


def test_all_getters_transport_error_returns_none(monkeypatch):
    _stub(monkeypatch, {"owner()": "transport", "authority()": "transport", "admin()": "transport"})
    assert read_contract_controllers("http://rpc", CONTRACT) is None


def test_whole_batch_failure_returns_none(monkeypatch):
    def _raise(*_args, **_kwargs):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(tracking, "_eth_call_batch", _raise)
    assert read_contract_controllers("http://rpc", CONTRACT) is None


# ---------------------------------------------------------------------------
# A REVERT is the EVM answering ("not a control plane"); a
# TRANSPORT failure is the read not happening. Every failure used to be the
# single ``_PROBE_ERROR``, so a contract with no ``authority()`` — which is most
# of them — tripped the incomplete-witness guard and the WHOLE plane set came
# back None. Measured: terminal_principal.status was ``unknown_unfetched`` on
# 180/180 armed rows and 5 of the 6 statuses had never fired.
# ---------------------------------------------------------------------------


def test_reverting_getter_is_not_a_control_plane_not_an_error(monkeypatch):
    # The overwhelmingly common real shape: owner() answers, authority() and
    # admin() revert because the contract does not declare them.
    _stub(monkeypatch, {"owner()": OWNER, "authority()": "revert", "admin()": "revert"})
    assert read_contract_controllers("http://rpc", CONTRACT) == [OWNER]


def test_all_getters_reverting_is_canonical_getter_silence(monkeypatch):
    # Every getter reverting is the EVM answering "these three getters name
    # nothing" — probe-set SILENCE, distinct from a transport failure but NOT
    # proof of no controller: an ownerless DepositContract and a
    # kernel()/unpauser()-governed contract produce the identical []. The walk
    # publishes it as ``controllers_not_determined`` with this basis.
    _stub(monkeypatch, {"owner()": "revert", "authority()": "revert", "admin()": "revert"})
    assert read_contract_controllers("http://rpc", CONTRACT) == []


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
    # INVERTED from `test_undecodable_success_is_not_a_plane_and_not_an_error`
    # (which pinned []): an address that answers EVERY call — including the
    # negative-control selector — is a catch-all fallback, so none of its
    # getter answers is a witnessed plane and the set is not dispositively
    # readable. None, never [] (the [] token belongs to canonical-getter
    # silence on an honestly-dispatching contract).
    def _fake(rpc_url, calls, block_tag="latest", *, chain_id=None, headers=None):
        return [EthCallResult(True, "0x1234", None, None) for _ in calls]

    monkeypatch.setattr(tracking, "_eth_call_batch", _fake)
    assert read_contract_controllers("http://rpc", CONTRACT) is None


def test_undecodable_success_with_honest_control_is_not_a_plane(monkeypatch):
    # The original arm, preserved with an honest negative control: getters
    # answer garbage but the nonsense selector reverts → the reads happened,
    # nothing decodes as an address → canonical-getter silence ([]).
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
