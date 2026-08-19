"""Closure edge scope.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from services.scoring import planes as P
from tests.support.scoring_builders import (
    KEY_C,
    KEY_PROXY,
    KEY_V,
    closure_of,
)


def test_role_labels_parse_to_the_roles_they_name():
    """A multi-role label licenses every role it names, and the pair is the scope."""
    scope = P.parse_edge_scope("roles 14,16", "role_principal")
    assert (scope.kind, scope.roles) == (P.SCOPE_ROLES, (14, 16))
    assert scope.is_determined
    assert P.parse_edge_scope("roles 12", "role_principal").roles == (12,)


def test_a_label_restating_its_relation_is_not_determined_not_an_empty_scope():
    """A label that only restates its relation names no role.

    Naming no role is not the same fact as licensing none: an empty scope reads
    as "licenses nothing", and the edge has to survive to be published as the
    shortfall it is.
    """
    scope = P.parse_edge_scope("role principal", "role_principal")
    assert scope.kind == P.SCOPE_NOT_DETERMINED
    assert not scope.is_determined
    assert scope.roles == ()
    # The verbatim label is kept: the shortfall is citable, not silently dropped.
    assert scope.label == "role principal"
    assert P.parse_edge_scope(None).kind == P.SCOPE_NOT_DETERMINED


def test_a_getter_name_is_a_state_var_scope_and_never_a_role():
    """``controller_value`` labels name a state variable.

    Reading one as a role would mint a licence out of a getter name.
    """
    scope = P.parse_edge_scope("roleRegistry", "controller_value")
    assert (scope.kind, scope.state_var, scope.roles) == (P.SCOPE_STATE_VAR, "roleRegistry", ())
    assert P.parse_edge_scope("_roles", "mapping_member").state_var == "_roles"


def test_the_closure_answers_adjacency_from_the_edges_it_carries():
    """Scope rides along with reach; it does not replace it."""
    closure = closure_of({KEY_C: {KEY_V, KEY_PROXY}})
    assert closure.principals() == (KEY_C,)
    assert closure.controlled_by(KEY_C) == tuple(sorted((KEY_V, KEY_PROXY)))
    assert closure.controlled_by(KEY_V) == ()
    assert {e.relation for e in closure.edges_from(KEY_C)} == {"controller_value"}
