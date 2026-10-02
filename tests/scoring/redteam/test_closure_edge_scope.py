from __future__ import annotations

from services.scoring import planes as P


def test_a_label_restating_its_relation_is_not_determined_not_an_empty_scope():
    """An empty scope reads as "licenses nothing"; the edge must survive as a shortfall."""
    scope = P.parse_edge_scope("role principal", "role_principal")
    assert scope.kind == P.SCOPE_NOT_DETERMINED
    assert not scope.is_determined
    assert scope.roles == ()
    assert scope.label == "role principal"
    assert P.parse_edge_scope(None).kind == P.SCOPE_NOT_DETERMINED
