from __future__ import annotations

from services.scoring import planes as P


def test_role_labels_parse_to_the_roles_they_name():
    scope = P.parse_edge_scope("roles 14,16", "role_principal")
    assert (scope.kind, scope.roles) == (P.SCOPE_ROLES, (14, 16))
    assert scope.is_determined
    assert P.parse_edge_scope("roles 12", "role_principal").roles == (12,)


def test_a_label_restating_its_relation_is_not_determined_not_an_empty_scope():
    """An empty scope reads as "licenses nothing"; the edge must survive as a shortfall."""
    scope = P.parse_edge_scope("role principal", "role_principal")
    assert scope.kind == P.SCOPE_NOT_DETERMINED
    assert not scope.is_determined
    assert scope.roles == ()
    assert scope.label == "role principal"
    assert P.parse_edge_scope(None).kind == P.SCOPE_NOT_DETERMINED


def test_a_getter_name_is_a_state_var_scope_and_never_a_role():
    scope = P.parse_edge_scope("roleRegistry", "controller_value")
    assert (scope.kind, scope.state_var, scope.roles) == (P.SCOPE_STATE_VAR, "roleRegistry", ())
    assert P.parse_edge_scope("_roles", "mapping_member").state_var == "_roles"
