"""Auth-family matchers over real ``build_claims`` with Plane-0 fact data shaped like measured contracts.

Assertions intersect :data:`AUTH_FAMILY` so sibling families can't couple in.
"""

from __future__ import annotations

from services.static.claims import (
    build_claims,
)
from services.static.claims.context import selector_of

AUTH_FAMILY = frozenset(
    {
        "ownership.transfer",
        "ownership.renounce",
        "ownership.accept",
        "authorized_caller.rotate",
        "roles.grant",
        "roles.revoke",
        "roles.configure",
        "authority.replace",
    }
)


def _sw(var, declared_type, *, hygiene="normal", granularity="var"):
    return {
        "var": var,
        "declared_type": declared_type,
        "hygiene_class": hygiene,
        "granularity": granularity,
        "origin": "body",
    }


def _ca_equality_leaf(var):
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "authority_role": "caller_authority",
            "references_msg_sender": True,
            "operands": [
                {"source": "msg_sender"},
                {"source": "state_variable", "state_variable_name": var},
            ],
        },
    }


def _ca_membership_leaf():
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "membership",
            "authority_role": "caller_authority",
            "references_msg_sender": True,
            "operands": [{"source": "msg_sender"}],
        },
    }


def _delegated_authority_leaf(var):
    """``authority.replace`` reads the pointer the guard consults, not a variable named ``authority``."""
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "external_bool",
            "authority_role": "delegated_authority",
            "references_msg_sender": True,
            "operands": [{"source": "msg_sender"}, {"source": "self_address"}],
            "callee_signature": "canCall(address,address,bytes4)",
            "set_descriptor": {
                "kind": "external_set",
                "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": var}},
                "callee_signature": "canCall(address,address,bytes4)",
            },
        },
    }


def _requires_auth_tree(owner_var, authority_var):
    return {"op": "OR", "children": [_ca_equality_leaf(owner_var), _delegated_authority_leaf(authority_var)]}


def _business_leaf(var):
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "authority_role": "business",
            "references_msg_sender": False,
            "operands": [{"source": "state_variable", "state_variable_name": var}],
        },
    }


def _fn(signature, *, state_writes=None, view=False):
    return {
        "function": signature,
        "selector": selector_of(signature) or "",
        "sinks": [],
        "state_writes": list(state_writes or []),
        "effect_labels": [],
        "state_changing": not view,
    }


def _artifact(name, functions):
    effects = {
        "schema_version": "semantic-2",
        "contract_name": name,
        "functions": {sig: rec for sig, (rec, _tree) in functions.items()},
    }
    trees = {sig: tree for sig, (_rec, tree) in functions.items() if tree is not None}
    predicate_trees = {
        "trees": trees,
        "canonical_signatures": {sig: sig for sig in functions},
    }
    return effects, predicate_trees


def _run(name, functions):
    effects, trees = _artifact(name, functions)
    return build_claims(None, effects, trees)["functions"]


def _auth(functions, signature):
    return {c["claim_id"] for c in functions.get(signature) or []} & AUTH_FAMILY


def _tiers(functions, signature, claim_id):
    return {c["tier"] for c in functions.get(signature) or [] if c["claim_id"] == claim_id}


def test_oz_v5_owner_getter_sibling_positive_and_ghost_negative():
    ghost = "OwnableStorageLocation"
    functions = _run(
        "OZv5",
        {
            "owner()": (_fn("owner()", state_writes=[_sw(ghost, "bytes32", hygiene="view_writer")], view=True), None),
            "transferOwnership(address)": (
                _fn(
                    "transferOwnership(address)",
                    state_writes=[_sw(ghost, "bytes32", hygiene="storage_location_pseudo")],
                ),
                _ca_equality_leaf(ghost),
            ),
            "renounceOwnership()": (
                _fn("renounceOwnership()", state_writes=[_sw(ghost, "bytes32", hygiene="storage_location_pseudo")]),
                _ca_equality_leaf(ghost),
            ),
            "setPeer(uint32,bytes32)": (
                _fn("setPeer(uint32,bytes32)", state_writes=[_sw(ghost, "bytes32", hygiene="storage_location_pseudo")]),
                _ca_equality_leaf(ghost),
            ),
        },
    )
    assert _auth(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _tiers(functions, "transferOwnership(address)", "ownership.transfer") == {"standard_exact"}
    assert _auth(functions, "renounceOwnership()") == {"ownership.renounce"}
    assert _auth(functions, "setPeer(uint32,bytes32)") == set()
    assert _auth(functions, "owner()") == set()


def test_dsauth_owner_var_write_identity_no_getter():
    functions = _run(
        "RolesAuthority",
        {
            "transferOwnership(address)": (
                _fn("transferOwnership(address)", state_writes=[_sw("owner", "address")]),
                _ca_equality_leaf("owner"),
            ),
            "setAuthority(address)": (
                _fn("setAuthority(address)", state_writes=[_sw("authority", "Authority")]),
                _requires_auth_tree("owner", "authority"),
            ),
            "setUserRole(address,uint8,bool)": (
                _fn(
                    "setUserRole(address,uint8,bool)", state_writes=[_sw("getUserRoles", "mapping(address => bytes32)")]
                ),
                _ca_equality_leaf("owner"),
            ),
            "setRoleCapability(uint8,address,bytes4,bool)": (
                _fn("setRoleCapability(uint8,address,bytes4,bool)"),
                _ca_equality_leaf("owner"),
            ),
            "setPublicCapability(address,bytes4,bool)": (
                _fn("setPublicCapability(address,bytes4,bool)"),
                _ca_equality_leaf("owner"),
            ),
            "canCall(address,address,bytes4)": (_fn("canCall(address,address,bytes4)", view=True), None),
        },
    )
    assert _auth(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _auth(functions, "setAuthority(address)") == {"authority.replace"}
    for setter in (
        "setUserRole(address,uint8,bool)",
        "setRoleCapability(uint8,address,bytes4,bool)",
        "setPublicCapability(address,bytes4,bool)",
    ):
        assert _auth(functions, setter) == {"roles.configure"}, setter


def test_dsauth_renounce_via_owner_var_write_identity():
    functions = _run(
        "DSAuthRenounce",
        {
            "transferOwnership(address)": (
                _fn("transferOwnership(address)", state_writes=[_sw("owner", "address")]),
                _ca_equality_leaf("owner"),
            ),
            "renounceOwnership()": (
                _fn("renounceOwnership()", state_writes=[_sw("owner", "address")]),
                _ca_equality_leaf("owner"),
            ),
        },
    )
    assert _auth(functions, "renounceOwnership()") == {"ownership.renounce"}


def test_set_authority_without_authority_write_is_not_claimed():
    # This function writes a different var, so the replacement is unproven.
    functions = _run(
        "NotAuth",
        {
            "setAuthority(address)": (
                _fn("setAuthority(address)", state_writes=[_sw("somethingElse", "address")]),
                _requires_auth_tree("owner", "authority"),
            ),
            "owner()": (_fn("owner()", view=True), None),
        },
    )
    assert _auth(functions, "setAuthority(address)") == set()


def test_set_authority_without_a_consulted_authority_is_not_claimed():
    """Without a gate delegating to an external authority, nothing proves the pointer is the permission authority."""
    functions = _run(
        "NoDelegatedGate",
        {
            "setAuthority(address)": (
                _fn("setAuthority(address)", state_writes=[_sw("authority", "Authority")]),
                _ca_equality_leaf("owner"),
            ),
            "owner()": (_fn("owner()", view=True), None),
        },
    )
    assert _auth(functions, "setAuthority(address)") == set()


def test_authority_replace_ignores_the_variable_name():
    """The evidence is the IR, not the identifier."""
    functions = _run(
        "OffVocabularyAuth",
        {
            "setAuthority(address)": (
                _fn("setAuthority(address)", state_writes=[_sw("permissionOracle", "IPermissions")]),
                _requires_auth_tree("owner", "permissionOracle"),
            ),
            "owner()": (_fn("owner()", view=True), None),
        },
    )
    assert _auth(functions, "setAuthority(address)") == {"authority.replace"}
    claim = next(c for c in functions["setAuthority(address)"] if c["claim_id"] == "authority.replace")
    assert claim["tier"] == "standard_exact"
    assert claim["witness"]["write_target"] == "permissionOracle"


def test_solady_handover_family():
    functions = _run(
        "TopUp",
        {
            "owner()": (_fn("owner()", view=True), None),
            "transferOwnership(address)": (_fn("transferOwnership(address)"), None),
            "renounceOwnership()": (_fn("renounceOwnership()"), None),
            "requestOwnershipHandover()": (_fn("requestOwnershipHandover()"), None),
            "completeOwnershipHandover(address)": (_fn("completeOwnershipHandover(address)"), None),
            "cancelOwnershipHandover()": (_fn("cancelOwnershipHandover()"), None),
        },
    )
    assert _auth(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _auth(functions, "renounceOwnership()") == {"ownership.renounce"}
    assert _auth(functions, "completeOwnershipHandover(address)") == {"ownership.transfer"}
    assert _auth(functions, "requestOwnershipHandover()") == {"ownership.accept"}
    assert _auth(functions, "cancelOwnershipHandover()") == set()


def test_ownable2step_accept():
    functions = _run(
        "Ownable2Step",
        {
            "owner()": (_fn("owner()", view=True), None),
            "transferOwnership(address)": (_fn("transferOwnership(address)"), None),
            "acceptOwnership()": (_fn("acceptOwnership()"), None),
        },
    )
    assert _auth(functions, "acceptOwnership()") == {"ownership.accept"}


def test_default_admin_rules_and_oz_roles():
    functions = _run(
        "DAR",
        {
            "defaultAdmin()": (_fn("defaultAdmin()", view=True), None),
            "beginDefaultAdminTransfer(address)": (_fn("beginDefaultAdminTransfer(address)"), None),
            "acceptDefaultAdminTransfer()": (_fn("acceptDefaultAdminTransfer()"), None),
            "cancelDefaultAdminTransfer()": (_fn("cancelDefaultAdminTransfer()"), None),
            "grantRole(bytes32,address)": (_fn("grantRole(bytes32,address)"), None),
            "revokeRole(bytes32,address)": (_fn("revokeRole(bytes32,address)"), None),
            "hasRole(bytes32,address)": (_fn("hasRole(bytes32,address)", view=True), None),
            "getRoleAdmin(bytes32)": (_fn("getRoleAdmin(bytes32)", view=True), None),
        },
    )
    assert _auth(functions, "beginDefaultAdminTransfer(address)") == {"ownership.transfer"}
    assert _auth(functions, "acceptDefaultAdminTransfer()") == {"ownership.accept"}
    assert _auth(functions, "cancelDefaultAdminTransfer()") == set()
    assert _auth(functions, "grantRole(bytes32,address)") == {"roles.grant"}
    assert _auth(functions, "revokeRole(bytes32,address)") == {"roles.revoke"}


def test_grant_role_without_access_control_gate_is_not_claimed():
    functions = _run(
        "NoGate",
        {"grantRole(bytes32,address)": (_fn("grantRole(bytes32,address)"), None)},
    )
    assert _auth(functions, "grantRole(bytes32,address)") == set()


def test_authorized_caller_rotate_and_initialize_near_miss():
    functions = _run(
        "FiatToken",
        {
            "owner()": (_fn("owner()", view=True), None),
            "transferOwnership(address)": (
                _fn("transferOwnership(address)", state_writes=[_sw("_owner", "address")]),
                _ca_equality_leaf("_owner"),
            ),
            "updatePauser(address)": (
                _fn("updatePauser(address)", state_writes=[_sw("pauser", "address")]),
                _ca_equality_leaf("_owner"),
            ),
            "updateBlacklister(address)": (
                _fn("updateBlacklister(address)", state_writes=[_sw("blacklister", "address")]),
                _ca_equality_leaf("_owner"),
            ),
            "pause()": (_fn("pause()", state_writes=[_sw("paused", "bool")]), _ca_equality_leaf("pauser")),
            "blacklist(address)": (
                _fn("blacklist(address)", state_writes=[_sw("blacklisted", "mapping(address => bool)")]),
                _ca_equality_leaf("blacklister"),
            ),
            "initialize(address,address)": (
                _fn("initialize(address,address)", state_writes=[_sw("pauser", "address"), _sw("_owner", "address")]),
                _business_leaf("initialized"),
            ),
        },
    )
    assert _auth(functions, "updatePauser(address)") == {"authorized_caller.rotate"}
    assert _tiers(functions, "updatePauser(address)", "authorized_caller.rotate") == {"idiom_structural"}
    assert _auth(functions, "updateBlacklister(address)") == {"authorized_caller.rotate"}
    assert _auth(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _auth(functions, "initialize(address,address)") == set()
    assert _auth(functions, "blacklist(address)") == set()

    claim = next(c for c in functions["updatePauser(address)"] if c["claim_id"] == "authorized_caller.rotate")
    assert claim["witness"]["vars"] == ["pauser"]
    assert claim["witness"]["established_by"]["pauser"] == "pause()"


def test_rotate_skipped_when_var_is_the_only_owner():
    functions = _run(
        "BespokeOwner",
        {
            "transferOwnership(address)": (
                _fn("transferOwnership(address)", state_writes=[_sw("owner", "address")]),
                _ca_equality_leaf("owner"),
            ),
        },
    )
    assert _auth(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert "authorized_caller.rotate" not in _auth(functions, "transferOwnership(address)")


def test_maker_wards_rely_deny():
    functions = _run(
        "Dai",
        {
            "rely(address)": (
                _fn("rely(address)", state_writes=[_sw("wards", "mapping(address => uint256)")]),
                _ca_membership_leaf(),
            ),
            "deny(address)": (
                _fn("deny(address)", state_writes=[_sw("wards", "mapping(address => uint256)")]),
                _ca_membership_leaf(),
            ),
            "mint(address,uint256)": (
                _fn("mint(address,uint256)", state_writes=[_sw("balanceOf", "mapping(address => uint256)")]),
                _ca_membership_leaf(),
            ),
        },
    )
    assert _auth(functions, "rely(address)") == {"roles.grant"}
    assert _auth(functions, "deny(address)") == {"roles.revoke"}
    assert _auth(functions, "mint(address,uint256)") == set()


def test_composequeue_is_not_role_management():
    functions = _run(
        "EndpointV2",
        {
            "owner()": (_fn("owner()", view=True), None),
            "transferOwnership(address)": (
                _fn("transferOwnership(address)", state_writes=[_sw("_owner", "address")]),
                _ca_equality_leaf("_owner"),
            ),
            "renounceOwnership()": (
                _fn("renounceOwnership()", state_writes=[_sw("_owner", "address")]),
                _ca_equality_leaf("_owner"),
            ),
            "sendCompose(address,bytes32,uint16,bytes)": (
                _fn(
                    "sendCompose(address,bytes32,uint16,bytes)",
                    state_writes=[_sw("composeQueue", "mapping(address => mapping(address => bytes32))")],
                ),
                _ca_membership_leaf(),
            ),
        },
    )
    assert _auth(functions, "sendCompose(address,bytes32,uint16,bytes)") == set()
    assert _auth(functions, "transferOwnership(address)") == {"ownership.transfer"}
    assert _auth(functions, "renounceOwnership()") == {"ownership.renounce"}


def _solady_roles_surface():
    """No ``getRoleAdmin``: a flat ``uint256`` role set has no per-role admin, which is why the OZ gate refuses."""
    return {
        "setRole(address,uint256,bool)": (_fn("setRole(address,uint256,bool)"), None),
        "hasRole(address,uint256)": (_fn("hasRole(address,uint256)", view=True), None),
        "roleHolders(uint256)": (_fn("roleHolders(uint256)", view=True), None),
        "grantRole(bytes32,address)": (_fn("grantRole(bytes32,address)"), None),
        "revokeRole(bytes32,address)": (_fn("revokeRole(bytes32,address)"), None),
    }


def test_solady_enumerable_roles_wrappers_are_claimed():
    """Refusing it under the OZ gate left a live authority-mutation surface unclaimed."""
    functions = _run("SoladyRegistry", _solady_roles_surface())
    assert _auth(functions, "grantRole(bytes32,address)") == {"roles.grant"}
    assert _auth(functions, "revokeRole(bytes32,address)") == {"roles.revoke"}
    assert _tiers(functions, "grantRole(bytes32,address)", "roles.grant") == {"standard_exact"}


def test_solady_roles_witness_names_the_standard_that_proved_it():
    functions = _run("SoladyRegistry", _solady_roles_surface())
    grant = next(c for c in functions["grantRole(bytes32,address)"] if c["claim_id"] == "roles.grant")
    assert grant["witness"]["standard"] == "solady_enumerable_roles"


def test_solady_gate_needs_the_enumerable_surface_not_the_wrappers():
    """The wrappers are what the claim is about, so they can't also be its gate."""
    surface = _solady_roles_surface()
    del surface["roleHolders(uint256)"]
    functions = _run("HalfSurface", surface)
    assert _auth(functions, "grantRole(bytes32,address)") == set()
    assert _auth(functions, "revokeRole(bytes32,address)") == set()


def test_oz_registry_still_reports_oz_provenance():
    functions = _run(
        "OZRegistry",
        {
            "grantRole(bytes32,address)": (_fn("grantRole(bytes32,address)"), None),
            "revokeRole(bytes32,address)": (_fn("revokeRole(bytes32,address)"), None),
            "hasRole(bytes32,address)": (_fn("hasRole(bytes32,address)", view=True), None),
            "getRoleAdmin(bytes32)": (_fn("getRoleAdmin(bytes32)", view=True), None),
        },
    )
    grant = next(c for c in functions["grantRole(bytes32,address)"] if c["claim_id"] == "roles.grant")
    assert grant["witness"]["standard"] == "oz_access_control"
