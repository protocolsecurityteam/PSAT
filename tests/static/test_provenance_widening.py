"""Widening of digest-churning provenance sets.

The provenance lattice must have finite height for the worklist to converge.
``callee_args_digest`` embeds a hash of the member set itself, so a
self-referential assignment (OZ ``Math.mulDiv``'s ``inverse *= 2 - denominator
* inverse`` chain) mints a fresh digest variant every iteration and burns the
full worklist cap. ``ProvenanceMap.set`` widens a variable that keeps being
rewritten — dropping the digest, which is never emitted — so the engine
converges while the caller-taint witness (``derived_from`` origins) is
preserved exactly.
"""

import textwrap

import pytest

pytest.importorskip("slither")
from slither.slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.provenance import (  # noqa: E402
    DEFAULT_WIDEN_AFTER,
    TOP,
    ProvenanceEngine,
    ProvenanceMap,
    Source,
    widen,
)

# ---------------------------------------------------------------------------
# widen() operator semantics
# ---------------------------------------------------------------------------


def test_widen_strips_digest_and_collapses_variants():
    origins = frozenset({Source(kind="parameter", parameter_index=0, parameter_name="x")})
    variants = frozenset(
        Source(kind="computed", computed_kind="BinaryType.MULTIPLICATION", callee_args_digest=d, derived_from=origins)
        for d in ("aaaa0000", "bbbb1111", "cccc2222")
    )
    widened = widen(variants)
    assert widened == frozenset(
        {
            Source(
                kind="computed",
                computed_kind="BinaryType.MULTIPLICATION",
                callee_args_digest=None,
                derived_from=origins,
            )
        }
    )


def test_widen_preserves_derived_from_origins():
    caller = Source(kind="msg_sender")
    src = Source(
        kind="view_call",
        callee="hasRole(bytes32,address)",
        callee_args_digest="deadbeef",
        derived_from=frozenset({caller}),
    )
    (out,) = widen(frozenset({src}))
    assert out.callee_args_digest is None
    assert out.derived_from == frozenset({caller})
    assert out.callee == "hasRole(bytes32,address)"


def test_widen_strips_digest_inside_derived_from():
    nested = Source(kind="computed", computed_kind="BinaryType.ADDITION", callee_args_digest="12345678")
    src = Source(kind="computed", computed_kind="BinaryType.MULTIPLICATION", derived_from=frozenset({nested}))
    (out,) = widen(frozenset({src}))
    assert out.derived_from is not None
    (origin,) = out.derived_from
    assert origin.callee_args_digest is None


def test_widen_top_and_digestless_sets_pass_through():
    assert widen(TOP) is TOP
    plain = frozenset({Source(kind="parameter", parameter_index=1, parameter_name="y"), Source(kind="msg_sender")})
    assert widen(plain) is plain


def test_widen_is_idempotent():
    s = frozenset(
        {
            Source(kind="computed", computed_kind="UnaryType.TILD", callee_args_digest="ffff0000"),
            Source(kind="state_variable", state_variable_name="owner"),
        }
    )
    once = widen(s)
    assert widen(once) == once


# ---------------------------------------------------------------------------
# ProvenanceMap.set trigger
# ---------------------------------------------------------------------------


def test_set_widens_only_after_threshold():
    pmap = ProvenanceMap(sources={})
    origins = frozenset({Source(kind="parameter", parameter_index=0, parameter_name="x")})

    def variant(i: int):
        return frozenset(
            {
                Source(
                    kind="computed",
                    computed_kind="BinaryType.MULTIPLICATION",
                    callee_args_digest=f"{i:08x}",
                    derived_from=origins,
                )
            }
        )

    for i in range(DEFAULT_WIDEN_AFTER):
        assert pmap.set("v", variant(i)) is True
    # Below the threshold the digest survives verbatim.
    assert next(iter(pmap.get("v"))).callee_args_digest is not None
    # Past it, a fresh digest variant widens to the stored (widened) form and
    # the map reports convergence after one widened store.
    assert pmap.set("v", variant(1000)) is True
    assert next(iter(pmap.get("v"))).callee_args_digest is None
    assert pmap.set("v", variant(1001)) is False


# ---------------------------------------------------------------------------
# Engine convergence on the mulDiv shape
# ---------------------------------------------------------------------------

_SELF_REF_SRC = """
contract NewtonMath {
    // OZ Math.mulDiv's convergence killer in miniature: a value repeatedly
    // reassigned from itself, so each fixpoint pass used to mint a fresh
    // digest-carrying source and the set never stabilized.
    function inverseish(uint256 x, uint256 y, uint256 denominator) public pure returns (uint256) {
        unchecked {
            uint256 inv = (3 * denominator) ^ 2;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            return x * y * inv;
        }
    }
}
"""


@pytest.fixture(scope="module")
def _newton(tmp_path_factory):
    f = tmp_path_factory.mktemp("widening") / "newton.sol"
    f.write_text(textwrap.dedent(_SELF_REF_SRC).strip() + "\n")
    return Slither(str(f))


def test_self_referential_arithmetic_converges_before_cap(_newton):
    contract = next(c for c in _newton.contracts if c.name == "NewtonMath")
    fn = next(f for f in contract.functions if f.name == "inverseish")
    caller_bound = frozenset({Source(kind="msg_sender")})
    engine = ProvenanceEngine(fn, parameter_bindings={"x": caller_bound})
    engine.run()
    # Converged (worklist stopped changing), not cap-truncated, and within a
    # small margin past the widening threshold.
    assert engine.iterations_run < engine.worklist_cap
    assert engine.iterations_run <= DEFAULT_WIDEN_AFTER + 5

    # The caller-taint witness survives widening: the bound parameter's
    # msg_sender origin is still reachable from the churned result value.
    def has_msg_sender(sources):
        for s in sources:
            if s.kind == "msg_sender":
                return True
            if any(o.kind == "msg_sender" for o in (s.derived_from or ())):
                return True
        return False

    tainted_vars = [name for name, srcs in engine.provenance.sources.items() if has_msg_sender(srcs)]
    assert "x" in tainted_vars
    # x flows into the returned product; at least one derived value carries it.
    assert len(tainted_vars) > 1
