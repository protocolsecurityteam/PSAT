"""Slither drops calldata slices (``x[a:b]`` reads as ``x``), so the statement's source is what says whether one is
there. A reading of it is taken only when it is faithful: every calldata value the statement reads appears in it by
name, and its brackets balance. Where none is (Slither's slice cut a character in two, the offsets shifted), the
statement's dynamic calldata reads ``unsupported:slice_source``, never the whole value."""

from __future__ import annotations

import pytest

from services.logic.lower import Lowerer
from services.logic.terms import reset_terms, subterms
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

contract C {
    uint256 x;
    function cut(bytes calldata d) external { require(keccak256(d[1:5]) == bytes32(uint256(7))); x = 1; }
    function arguments() external { require(keccak256(msg.data[4:]) == bytes32(uint256(7))); x = 2; }
    function plain(uint256 a) external { require(a == 7); x = a; }
}
"""


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("slices") / "C.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "C")


class _Unreadable:
    """A source mapping whose slice Slither can't decode, its offsets ending before the slice."""

    def __init__(self, real, length):
        self.start, self.length, self.filename = real.start, length, real.filename

    @property
    def content(self):
        raise UnicodeDecodeError("utf-8", b"\xe2", 0, 1, "cut through a character")


def _labels(contract, name, unreadable: bool):
    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    node = next(n for n in fn.nodes if "require" in str(n.expression))
    expression = node.expression
    real = expression.source_mapping
    if unreadable:
        text = real.content
        expression.source_mapping = _Unreadable(real, text.index("[") if "[" in text else len(text) // 2)
    try:
        formula = Lowerer(contract).success(fn)
    finally:
        expression.source_mapping = real
    return {t[1] for t in subterms(formula, "unknown")}


@pytest.mark.parametrize("name", ["cut", "arguments"])
def test_calldata_a_statement_reads_is_unknown_by_name_where_its_source_cannot_be_read(contract, name):
    assert "unsupported:slice_source" in _labels(contract, name, unreadable=True)
