"""_read_erc1967_implementation decodes strictly (readiness §2.4).

"Slot is zero ⇒ not a proxy" is a typing verdict, so it is earned only by a
full 64-nibble zero word. Any shorter return is a transport artifact and must
stay ``_PROBE_ERROR`` — there is deliberately no pad-then-check path, because
padding turns an empty or truncated response into a minted zero (or, worse, a
minted implementation address). Mirrors the discipline of
``services/monitoring/restaking_reads.decode_word``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution import tracking
from services.resolution.tracking import _PROBE_ERROR, _read_erc1967_implementation

IMPL_ADDR = "00e1849b2a44a5544357b0a1b7f4b0be492f4e5e"
FULL_IMPL_WORD = "0x" + "00" * 12 + IMPL_ADDR
FULL_ZERO_WORD = "0x" + "0" * 64


def _stub_storage(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setattr(tracking, "_get_storage_at", lambda *a, **kw: raw)


def test_full_word_with_implementation_decodes_identically(monkeypatch):
    """The recall pin: a clean 32-byte word still yields the address."""
    _stub_storage(monkeypatch, FULL_IMPL_WORD)
    assert _read_erc1967_implementation("rpc", "0x" + "ab" * 20, "0x1") == "0x" + IMPL_ADDR


def test_uppercase_full_word_decodes_lowercased(monkeypatch):
    _stub_storage(monkeypatch, ("0x" + "00" * 12 + IMPL_ADDR).upper().replace("0X", "0x"))
    assert _read_erc1967_implementation("rpc", "0x" + "ab" * 20, "0x1") == "0x" + IMPL_ADDR


def test_full_zero_word_is_not_a_proxy(monkeypatch):
    _stub_storage(monkeypatch, FULL_ZERO_WORD)
    assert _read_erc1967_implementation("rpc", "0x" + "ab" * 20, "0x1") is None


@pytest.mark.parametrize(
    "raw",
    [
        "0x",  # empty return — the shape that read as "not a proxy" when padded
        "0x0",  # short zero — same class
        "0x" + "0" * 63,  # one nibble short
        "0x" + "0" * 65,  # one nibble long
        "0x" + "1",  # short NONZERO — padding would mint implementation 0x…01
        "0x" + " " * 2 + "0" * 62,  # whitespace is not hex
        "0x" + "g" + "0" * 63,  # non-hex digit
    ],
)
def test_non_word_returns_are_probe_error_not_verdicts(monkeypatch, raw):
    _stub_storage(monkeypatch, raw)
    assert _read_erc1967_implementation("rpc", "0x" + "ab" * 20, "0x1") is _PROBE_ERROR


def test_transport_raise_is_probe_error(monkeypatch):
    def _raise(*a, **kw):
        raise RuntimeError("transport")

    monkeypatch.setattr(tracking, "_get_storage_at", _raise)
    assert _read_erc1967_implementation("rpc", "0x" + "ab" * 20, "0x1") is _PROBE_ERROR
