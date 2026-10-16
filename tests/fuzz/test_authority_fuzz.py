"""Property tests over generated authorization shapes; see ``tests/fuzz/authority.py``.

A failure prints the shrunk ``Case``; pin it with ``@example`` once fixed.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from tests.fuzz.authority import (
    ADMIN,
    ATOMS,
    OWNER,
    PLACEMENTS,
    SENDERS,
    SOLCS,
    WRAPPERS,
    Case,
    evm_truth,
    static_verdict,
    unsound,
)

pytestmark = pytest.mark.compile

guards = st.recursive(
    st.sampled_from(sorted(ATOMS)).map(lambda a: ("atom", a)),
    lambda inner: st.one_of(
        inner.map(lambda g: ("not", g)),
        st.tuples(st.sampled_from(["and", "or"]), inner, inner),
    ),
    max_leaves=5,
)
noise = st.sampled_from([0, 3, 24])  # 24 sequential branches: anything exponential in them stalls


def cases(guard=guards, placements=PLACEMENTS):
    return st.builds(
        Case,
        guard=guard,
        wrapper=st.sampled_from(WRAPPERS),
        placement=st.sampled_from(placements),
        noise=noise,
        sender=st.sampled_from(SENDERS),
        solc=st.sampled_from(SOLCS),
    )


def verdict(case: Case):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "C.sol"
        path.write_text(case.source())
        return static_verdict(path, case), path.read_text()


@pytest.mark.anvil
@given(case=cases())
@example(case=Case(("or", ("atom", "owner"), ("atom", "member"))))  # allowlist members hidden behind an "exact" owner
def test_static_verdict_is_never_contradicted_by_execution(anvil_url, case):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "C.sol"
        path.write_text(case.source())
        result = static_verdict(path, case)
        truth = evm_truth(anvil_url, path, case)
    assert not unsound(result, truth), (unsound(result, truth), result, truth, case.source())
    assert result.seconds < 30, (result.seconds, case.source())


# Single caller checks whose principal is fully known from source plus tracked state.
RESOLVABLE = {
    "owner": OWNER,
    "owner_rev": OWNER,
    "owner_getter": OWNER,
    "admin": ADMIN,
    "constant": OWNER,
    "constant_var": OWNER,
    "immutable": ADMIN,
    "origin": OWNER,
}


@given(case=cases(st.sampled_from(sorted(RESOLVABLE)).map(lambda a: ("atom", a)), ("before", "after_write")))
@example(case=Case(("atom", "constant")))  # Slither's decimal address literal
def test_known_principal_resolves_in_every_shape(case):
    result, source = verdict(case)
    assert (result.openness, result.principals, result.complete) == ("restricted", {RESOLVABLE[case.guard[1]]}, True), (
        source
    )


@given(case=cases(placements=("before", "after_write")), other=cases())
def test_verdict_is_invariant_under_semantics_preserving_rewrites(case, other):
    """Wrapper, caller indirection, noise and compiler change no semantics, so they must change no verdict."""
    rewritten = Case(case.guard, other.wrapper, case.placement, other.noise, other.sender, other.solc)
    first, second = verdict(case)[0], verdict(rewritten)[0]
    assert (first.openness, first.principals) == (second.openness, second.principals), (
        case.source(),
        rewritten.source(),
    )


BUSINESS_ONLY = st.recursive(
    st.sampled_from(["flag", "arg", "time"]).map(lambda a: ("atom", a)),
    lambda inner: st.tuples(st.sampled_from(["and", "or"]), inner, inner),
    max_leaves=3,
)


@given(case=cases(BUSINESS_ONLY, ("before", "after_write")))
def test_check_without_a_caller_stays_open(case):
    """Pause flags, argument bounds and deadlines restrict when, not who."""
    result, source = verdict(case)
    assert result.openness == "open", source
