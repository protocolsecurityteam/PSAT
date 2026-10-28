"""Exhaustive finite-domain truth, independent of solver models and sampled callers."""

import random

import pytest

from services.logic.model import Limits
from services.logic.solver import Translation, project
from services.logic.terms import CALLER, const, mk, mk_and, mk_cmp, mk_not, mk_or, unknown


class NoReads:
    block = 1

    def __getattr__(self, name):
        raise AssertionError(f"a pure formula requested {name}")


@pytest.mark.parametrize("seed", range(16))
def test_full_finite_domain_and_shared_argument_constraints(seed):
    rng = random.Random(seed)
    a = mk("arg", "choice", "uint8")
    choices = rng.sample(range(8), 4)
    owners = rng.sample(range(1, 32), 4)
    branches = [
        mk_and([mk_cmp("eq", a, const(k)), mk_cmp("eq", CALLER, const(who))]) for k, who in zip(choices, owners)
    ]
    cutoff = rng.randrange(8)
    formula = mk_and([mk_or(branches), mk_cmp("lt", a, const(cutoff))])
    # Entire permitted caller domain is bounded by these equalities; every choice is independently enumerated.
    truth = {who for k, who in zip(choices, owners) if k < cutoff}
    result = project(formula, Translation(NoReads(), {}, 10, limits=Limits(members=32)))
    assert result.complete and set(result.members) == truth


@pytest.mark.parametrize("budget", [0, 1, 2, 8])
def test_partial_materialisation_never_claims_an_incomplete_list_is_complete(budget):
    truth = {3, 7, 11}
    formula = mk_or([mk_cmp("eq", CALLER, const(who)) for who in truth])
    result = project(formula, Translation(NoReads(), {}, 10, limits=Limits(members=budget)))
    assert set(result.members) <= truth
    if result.complete:
        assert result.representation == "finite" and set(result.members) == truth
    else:
        assert result.issues


@pytest.mark.parametrize("position", ["and", "or", "nested"])
def test_missing_semantics_never_become_a_complete_proof(position):
    role = mk_cmp("eq", CALLER, const(7))
    missing = unknown("unfollowed authorization")
    formula = (
        mk_and([role, missing])
        if position == "and"
        else mk_or([role, missing])
        if position == "or"
        else mk_not(mk_and([role, missing]))
    )
    result = project(formula, Translation(NoReads(), {}, 10))
    assert result.representation == "symbolic" and result.issues


def test_a_solver_budget_is_not_an_empty_principal_set():
    result = project(mk_cmp("eq", CALLER, const(7)), Translation(NoReads(), {}, 10, limits=Limits(solver_ms=0)))
    assert not result.complete and result.issues[0].kind == "budget"


def test_unknown_labels_are_not_algebraic_value_identities():
    from services.logic.terms import FALSE, TRUE

    missing = unknown("ambiguous read")
    assert mk_cmp("eq", missing, missing) != TRUE
    assert mk_and([missing, mk_not(missing)]) != FALSE
    assert mk_or([missing, mk_not(missing)]) != TRUE
    # Two different ambiguous reads can have the same label. Do not prove their sum even.
    formula = mk_cmp("eq", mk("op", "add", (missing, missing)), const(1))
    assert Translation(NoReads(), {}, 10).truth(formula) is None
