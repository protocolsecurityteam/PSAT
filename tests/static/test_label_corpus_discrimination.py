"""The golden test is a change detector; this states the property each fixture holds so a regeneration can't absorb a
regression. Each test names the row that must move and the sibling that must not.
"""

from __future__ import annotations

import pytest

pytest.importorskip("slither")

from tests.support import label_corpus as harness

CONSTRAINED = "0x00000000000000000000000000000000000000b0"
DELEGATECALL = "0x00000000000000000000000000000000000000c0"
EXEC_BINDING = "0x00000000000000000000000000000000000000d0"
TREE_ABSENT = "0x00000000000000000000000000000000000000e0"
TIMED_LATCH = "0x00000000000000000000000000000000000000f0"
RATE_LIMITED = "0x0000000000000000000000000000000000000110"
POLICY_CALLER = "0x0000000000000000000000000000000000000100"
SELF_SERVICE = "0x0000000000000000000000000000000000000120"
PAUSE_UNTIL = "0x0000000000000000000000000000000000000130"


def _functions(address: str) -> dict[str, dict]:
    golden = harness.load_golden()
    contract = next(c for c in golden["contracts"] if c["address"] == address)
    return {f["full_name"]: f for f in contract["functions"]}


def _claim(fn: dict, claim_id: str) -> dict:
    return next(c for c in fn["claims"] if c["claim_id"] == claim_id)


def _destination(fn: dict) -> dict:
    return _claim(fn, "flow.out")["witness"]["flows"][0]["target_kind"]


def test_every_golden_claim_carries_its_witness():
    """``claims`` once held only ``{claim_id, tier}``, so a rebound call target diffed nothing."""
    golden = harness.load_golden()
    claims = [c for contract in golden["contracts"] for f in contract["functions"] for c in f["claims"]]
    assert claims, "corpus produced no claims at all"
    assert all("witness" in c for c in claims)
    assert "__unpinnable__" not in harness.format_golden(golden)


def _target_constraint(fn: dict) -> dict:
    return _claim(fn, "flow.out")["witness"]["flows"][0]["target_constraint"]


def test_the_four_param_destinations_are_told_apart_by_their_guards():
    """A4: all four are ``param``, but three are guarded and the verdict names which guard."""
    fns = _functions(CONSTRAINED)
    expected = {
        "payCommitted(IERC20,address,uint256,bytes32)": ("constrained", "hash_commitment"),
        "payAllowlisted(IERC20,address,uint256)": ("constrained", "mapping_allowlist"),
        "payTreasuryOnly(IERC20,address,uint256)": ("constrained", "equality_vs_storage"),
        # A narrowing that also moves this one is wrong.
        "payAnyone(IERC20,address,uint256)": ("unconstrained_proven", None),
    }
    for name, (state, guard) in expected.items():
        assert _destination(fns[name])["kind"] == "param", name
        verdict = _target_constraint(fns[name])
        assert verdict["state"] == state, name
        assert verdict.get("guard") == guard, name


def test_the_hash_commitment_binding_is_marked_as_flow_insensitive():
    """``derived_from`` is flow-insensitive, so the verdict records the binding and a consumer can decline it."""
    fns = _functions(CONSTRAINED)
    committed = _target_constraint(fns["payCommitted(IERC20,address,uint256,bytes32)"])
    assert committed["binding"] == "derived_from"
    assert committed["pins"] is None
    for name in ("payAllowlisted(IERC20,address,uint256)", "payTreasuryOnly(IERC20,address,uint256)"):
        verdict = _target_constraint(fns[name])
        assert verdict["binding"] == "operand", name
        assert verdict["pins"] is True, name


def test_the_constraint_is_present_in_the_corpus_even_though_the_flow_fact_ignores_it():
    """So a zero-diff after an A4 change means the change did nothing."""
    fns = _functions(CONSTRAINED)
    allowlisted = fns["payAllowlisted(IERC20,address,uint256)"]["predicate_tree"]
    anyone = fns["payAnyone(IERC20,address,uint256)"]["predicate_tree"]
    assert "membership" in allowlisted["leaf_kinds"]
    assert "membership" not in anyone["leaf_kinds"]
    assert allowlisted["leaf_count"] > anyone["leaf_count"]
    for name in ("payCommitted(IERC20,address,uint256,bytes32)", "payTreasuryOnly(IERC20,address,uint256)"):
        assert fns[name]["predicate_tree"]["leaf_count"] > anyone["leaf_count"], name


def test_the_corpus_has_delegatecall_execution_rows_at_all():
    fns = _functions(DELEGATECALL)
    labelled = [n for n, f in fns.items() if "delegatecall_execution" in f["effect_labels"]]
    assert sorted(labelled) == [
        "execBothModules(bytes)",
        "execFixedSlot(bytes)",
        "execModule(bytes)",
        "execModuleViaLibrary(bytes)",
        "execSelf(bytes)",
        "execSelfViaLibrary(bytes)",
        "execUserModule(bytes)",
        "fallback()",
    ]


def test_the_a8_claim_resolves_all_five_delegatecall_routes():
    """The sink target string differs on every route and only one names something here; both production rows are
    assembly routes, so only the corpus catches it.
    """
    fns = _functions(DELEGATECALL)
    expected = {
        "execModule(bytes)": ("storage_setter", "module"),
        "execModuleViaLibrary(bytes)": ("storage_setter", "module"),
        "fallback()": ("storage_setter", None),
        "execFixedSlot(bytes)": ("storage_no_setter", None),
        # Resolving to ``userModule`` asserts one destination where there's one per caller.
        "execUserModule(bytes)": ("indeterminate", None),
    }
    for name, (kind, variable) in expected.items():
        destination = _claim(fns[name], "delegatecall.execute")["witness"]["destination"]
        assert destination["target_kind"] == kind, name
        if variable is not None:
            assert destination["variable"] == variable, name
    assert _claim(fns["fallback()"], "delegatecall.execute")["witness"]["destination"]["writer_signatures"] == [
        "setAdminImpl(address)"
    ]
    assert (
        "writer_signatures" not in _claim(fns["execFixedSlot(bytes)"], "delegatecall.execute")["witness"]["destination"]
    )
    assert _claim(fns["execUserModule(bytes)"], "delegatecall.execute")["witness"]["destination"]["reason"] == (
        "mapping_or_array_element"
    )


def test_a_literal_address_this_destination_is_proven_self_on_both_routes():
    """``address(this)`` is proven; the mapping-element row beside it keeps ``self`` from being a catch-all.

    The library route exercises OZ v5 ``Multicall``'s binding substitution.
    """
    fns = _functions(DELEGATECALL)
    for name in ("execSelf(bytes)", "execSelfViaLibrary(bytes)"):
        witness = _claim(fns[name], "delegatecall.execute")["witness"]
        assert witness["destination"] == {"target_kind": "self"}, name
        assert witness["destination_constraint"] == {
            "state": "constrained",
            "guard": "literal_self",
            "pins": True,
            "binding": "destination_operand",
        }, name
    unsettled = _claim(fns["execUserModule(bytes)"], "delegatecall.execute")["witness"]
    assert unsettled["destination"]["target_kind"] == "indeterminate"
    assert unsettled["destination_constraint"] == {"state": "not_determined"}


def test_a_two_site_fold_publishes_the_union_never_one_sites_answer():
    """The fold used to keep the first site's writers, hiding the second site's ungated writer."""
    fns = _functions(DELEGATECALL)
    destination = _claim(fns["execBothModules(bytes)"], "delegatecall.execute")["witness"]["destination"]
    assert destination["target_kind"] == "storage_setter"
    assert destination["sites"] == 2
    assert "variable" not in destination
    assert destination["variables"] == ["module", "sideModule"]
    assert destination["writer_signatures"] == ["setModule(address)", "setSideModule(address)"]


def test_the_a8_claim_is_not_upgrade_implementation():
    """A non-standard split proxy would corrupt the EIP-1967/UUPS statistics."""
    fns = _functions(DELEGATECALL)
    for name in ("execModule(bytes)", "fallback()", "execUserModule(bytes)"):
        assert [c["claim_id"] for c in fns[name]["claims"]] == ["delegatecall.execute"], name


def test_the_library_route_records_a_symbol_that_does_not_exist_in_this_contract():
    """Fixture 9: both production A8 rows are direct routes."""
    fns = _functions(DELEGATECALL)
    direct = fns["execModule(bytes)"]["delegatecall_sinks"]
    library = fns["execModuleViaLibrary(bytes)"]["delegatecall_sinks"]
    assert direct == [{"target": "module", "origin": "body"}]
    assert library == [{"target": "target", "origin": "body"}]
    setter_targets = fns["setModule(address)"]["effect_targets"]
    assert setter_targets == ["module"]
    assert "target" not in setter_targets


def test_a_caller_keyed_mapping_destination_names_no_variable_at_all():
    sinks = _functions(DELEGATECALL)["execUserModule(bytes)"]["delegatecall_sinks"]
    assert len(sinks) == 1
    target = sinks[0]["target"]
    assert target.startswith("REF_"), target
    assert target != "userModule"


def test_the_call_target_binds_to_the_second_address_parameter():
    """Fixture 4: every prior ``exec.arbitrary`` had one address parameter."""
    fn = _functions(EXEC_BINDING)["compose(address,address,bytes,bytes)"]
    witness = _claim(fn, "exec.arbitrary")["witness"]
    assert witness["destination_kind"] == "param"
    assert witness["destination_param"] == "to"
    assert witness["destination_basis"] == "call_destination"


def test_a_destination_that_no_parameter_determines_is_not_determined():
    fns = _functions(EXEC_BINDING)
    for name in (
        "branchedParams(address,address,bytes,bool)",
        "reassignedLocal(address,address,bytes)",
        "paramWrittenAfterCall(address,address,bytes)",
    ):
        witness = _claim(fns[name], "exec.arbitrary")["witness"]
        assert witness["destination_kind"] == "not_determined", name
        assert witness["destination_param"] is None, name
    single = _claim(fns["singlyAssignedLocal(address,bytes)"], "exec.arbitrary")["witness"]
    assert single["destination_kind"] == "param"
    assert single["destination_param"] == "a"


def test_class_F_a_value_returning_forwarder_keeps_its_caller_gate():
    """Inverted (a96b2ca3): a consumed internal-call result skipped the gate recursion, leaving no tree (read as
    unguarded). ``pokeAll`` stays unchanged so a blanket fix fails.
    """
    fns = _functions(TREE_ABSENT)
    assert fns["withdrawAll()"]["predicate_tree"]["present"] is True
    assert "caller_authority" in fns["withdrawAll()"]["predicate_tree"]["authority_roles"]
    assert fns["withdrawTo(uint256)"]["predicate_tree"]["present"] is True
    assert fns["pokeAll()"]["predicate_tree"]["present"] is True
    assert fns["pokeTo(uint256)"]["predicate_tree"]["present"] is True
    assert fns["withdrawAll()"]["effect_labels"] == fns["pokeAll()"]["effect_labels"]
    assert (
        fns["withdrawAll()"]["predicate_tree"]["authority_roles"]
        == fns["pokeAll()"]["predicate_tree"]["authority_roles"]
    )


def _timed_latch_facts():
    import tempfile
    from pathlib import Path

    from services.effects import calldata as cd

    entry = next(e for e in harness.corpus_entries() if e["address"] == TIMED_LATCH)
    with tempfile.TemporaryDirectory() as tmp:
        try:
            _subject, effects, trees = harness._compile_and_attach(entry, Path(tmp))
        except harness.SolcNotInstalled as exc:  # pragma: no cover - env-dependent skip
            pytest.skip(str(exc))
    return cd.ContractFacts(
        address=TIMED_LATCH,
        job_id=None,
        effects=effects.get("functions") or {},
        trees=trees.get("trees") or {},
        canonical_signatures=trees.get("canonical_signatures") or {},
    )


def test_the_pause_duration_reader_tells_the_three_latch_states_apart():
    """``no_time_reference`` (proven indefinite) vs ``not_determined`` (no lowered leaf reads it); only the first may
    render as "indefinite latch". ``pausedUntil`` changed from ``(2592000, "guard_constant")`` to
    ``not_determined``: the recorder sorts both operands of + and - into one list, so ``+ MAX_PAUSE`` and
    ``- MAX_PAUSE`` are indistinguishable until the static plane stamps the sign. The compiled ``guard_constant``
    positive is in ``test_pause_duration_clock_opacity.py::AbsorbedWindow``.
    """
    facts = _timed_latch_facts()
    assert facts.trees, "the corpus latch produced no predicate trees"
    assert "transferTimed(address,uint256)" in facts.trees

    from services.effects import calldata as cd

    assert cd.read_max_pause_duration(facts, {"pausedUntil"}) == (None, "not_determined")
    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "no_time_reference")
    assert cd.read_max_pause_duration(facts, {"neitherLatch"}) == (None, "not_determined")


def test_the_timed_guard_leaf_carries_all_three_facts_across_operands_and_absorbed():
    """Widening ``operands`` would make the lattice fold degrade amount kinds protocol-wide."""
    facts = _timed_latch_facts()
    leaves = list(harness._tree_leaves(facts.trees["transferTimed(address,uint256)"]))
    sources = [{str(o.get("source")) for o in (leaf.get("operands") or [])} for leaf in leaves]
    assert any("block_context" in s for s in sources), "no time-shaped guard leaf at all"
    assert all(len(leaf.get("operands") or []) <= 2 for leaf in leaves)
    assert not any(
        "block_context" in s and "constant" in s and any(o.get("state_variable_name") == "pausedUntil" for o in ops)
        for s, ops in zip(sources, (leaf.get("operands") or [] for leaf in leaves), strict=True)
    )
    window = [
        leaf
        for leaf in leaves
        if any(o.get("block_context_kind") == "timestamp" for o in (leaf.get("operands") or []))
        and leaf.get("absorbed_operands")
    ]
    assert len(window) == 1, "the pausedUntil + MAX_PAUSE comparison recorded nothing absorbed"
    absorbed = window[0]["absorbed_operands"]
    assert any(o.get("state_variable_name") == "pausedUntil" for o in absorbed)
    assert any(o.get("constant_value") == "2592000" for o in absorbed)
    # Absent means no additive sub-expression, not unknown.
    frozen_leaves = list(harness._tree_leaves(facts.trees["transferFreezable(address,uint256)"]))
    assert all("absorbed_operands" not in leaf for leaf in frozen_leaves)


def test_the_golden_carries_timestamp_latch_pauses():
    """Both timed latches: the plain one beside an indefinite bool, and etherfi's ERC-7201 member beside a bool slot.
    The bool latches keep their unmarked flags."""
    timed = _functions(TIMED_LATCH)
    plain = {"var": "pausedUntil", "member": None, "latch": "timestamp"}
    assert _claim(timed["pauseTimed()"], "pause.set")["witness"]["flags"] == [plain]
    assert _claim(timed["unpauseTimed()"], "pause.unset")["witness"]["flags"] == [plain]
    assert _claim(timed["freeze()"], "pause.set")["witness"]["flags"] == [{"var": "frozen", "member": None}]

    namespaced = _functions(PAUSE_UNTIL)
    member = {"var": "PAUSABLE_UNTIL_STORAGE_SLOT", "member": "pausedUntil", "latch": "timestamp"}
    assert _claim(namespaced["pauseUntil()"], "pause.set")["witness"]["flags"] == [member]
    assert _claim(namespaced["unpauseUntil()"], "pause.unset")["witness"]["flags"] == [member]
    assert _claim(namespaced["pause()"], "pause.set")["witness"]["flags"] == [
        {"var": "PAUSABLE_STORAGE_SLOT", "member": None}
    ]
    assert namespaced["setPauseUntilDuration(uint256)"]["claims"] == []


def test_the_golden_carries_a_policy_derived_claim():
    """``policy_derived`` had zero producers across 679 claims."""
    fn = _functions(POLICY_CALLER)["depositTo(uint256)"]
    claim = _claim(fn, "flow.in")
    assert claim["tier"] == "policy_derived"
    witness = claim["witness"]
    assert witness["kind"] == "cross_contract_join"
    assert witness["callee"] == "0x00000000000000000000000000000000000000a0"
    assert witness["source_tier"] == "standard_exact"


def test_a_callee_with_an_interface_typed_parameter_is_reached_via_the_canonical_key():
    """Inverted: this pinned the join miss (declared 0x38541c00 vs ABI 0x0aeef8c8).

    The map now keys on ``abi_selector``.
    """
    fns = _functions(POLICY_CALLER)
    derived = _claim(fns["recoverVia(address,address,uint256)"], "flow.out")
    assert derived["tier"] == "policy_derived"
    assert derived["witness"]["selector"] == "0x0aeef8c8"
    assert derived["witness"]["callee"] == "0x0000000000000000000000000000000000000070"
    recovery = _functions("0x0000000000000000000000000000000000000070")
    assert _claim(recovery["sweepTo(IERC20,address,uint256)"], "flow.out")["tier"] == "standard_exact"


def test_the_rate_limiter_is_recorded_as_a_zero_weight_fact():
    fns = _functions(RATE_LIMITED)
    for name in ("withdrawLimited(address,uint256)", "withdrawTokenLimited(address,uint256)"):
        claim = _claim(fns[name], "rate_limit.consume")
        assert claim["tier"] == "idiom_structural", name
        assert claim["witness"]["severity_weight"] == 0, name
        assert claim["witness"]["mandatory"] == {"state": "proven"}, name


# The limiter's ``consume`` revert blocks the unconstrained proof, which is more conservative, never a ceiling.
_MANDATORY_GATE_FIELDS = ("amount_constraint", "amount_record_constraint", "self_service_payout")


def _lattice_only(flow_entry: dict) -> dict:
    return {k: v for k, v in flow_entry.items() if k not in _MANDATORY_GATE_FIELDS}


def test_the_limiter_does_not_change_a_single_byte_of_the_flow_witness():
    """A refilling bucket bounds throughput per window, not total loss, so the amount lattice must be byte-identical
    with or without it.
    """
    fns = _functions(RATE_LIMITED)
    limited = _claim(fns["withdrawLimited(address,uint256)"], "flow.out")
    control = _claim(fns["withdrawUnlimited(address,uint256)"], "flow.out")
    limited_flows = limited["witness"]["flows"]
    control_flows = control["witness"]["flows"]
    assert [_lattice_only(f) for f in limited_flows] == [_lattice_only(f) for f in control_flows]
    assert [f["amount_kind"] for f in limited_flows] == [f["amount_kind"] for f in control_flows]
    assert limited["tier"] == control["tier"]
    assert control_flows[0]["amount_constraint"] == {"state": "unconstrained_proven"}
    assert limited_flows[0]["amount_constraint"] == {"state": "not_determined"}
    assert [c["claim_id"] for c in fns["withdrawUnlimited(address,uint256)"]["claims"]] == ["flow.out"]


def test_the_configuration_discriminators_are_present_and_explicitly_unread():
    """G7: a zero refill rate makes a one-shot cap and zero capacity is a pause in disguise, so both are three-state
    ``not_determined``, never absent.
    """
    witness = _claim(_functions(RATE_LIMITED)["withdrawLimited(address,uint256)"], "rate_limit.consume")["witness"]
    for field in ("capacity", "refill_rate", "bounds_total_extraction"):
        assert witness[field] == {"state": "not_determined", "source": "chain_state"}, field
    assert witness["config_reader"]["get_limit_selector"] == "0xd200f8c2"
    assert "one-shot total cap" in witness["interpretation"]
    assert "pause in disguise" in witness["interpretation"]


def test_a_same_named_different_selector_callee_earns_nothing():
    fns = _functions(RATE_LIMITED)
    assert [c["claim_id"] for c in fns["withdrawDecoy(address,uint256)"]["claims"]] == ["flow.out"]


def test_the_cancel_bid_shape_proves_self_service_and_the_rescue_sibling_earns_nothing():
    """``cancelBid`` reads the caller's own cleared record, pinned whole.

    ``rescueTokens`` has a param amount behind an owner gate, so the keys are absent; an owner gate never stands in for
    a witness.
    """
    fns = _functions(SELF_SERVICE)
    cancel = _claim(fns["cancelBid(uint256)"], "flow.out")["witness"]["flows"][0]
    assert cancel["self_service_payout"] == {
        "state": "proven_self_service",
        "w1_basis": "owner_guarded_record",
        "w2_basis": "clear_dominates_calls",
        "record": "SelfServicePayout.bids",
        "disclosures": [
            "self_service_bound_conditional_on_upgrade_authority",
            "self_service_sibling_function_residual_not_proven",
        ],
    }
    assert cancel["amount_record_constraint"] == {
        "state": "constrained",
        "basis": "owner_guarded_record",
        "record": "SelfServicePayout.bids",
    }
    rescue = _claim(fns["rescueTokens(address,uint256)"], "flow.out")["witness"]["flows"][0]
    assert "self_service_payout" not in rescue
    assert "amount_record_constraint" not in rescue
    assert rescue["amount_constraint"] == {"state": "unconstrained_proven"}


def test_the_flow_plane_pins_the_record_identity_and_the_ordering_witness():
    """Unpinned, a producer that stopped resolving the record would regress every verdict with a zero-byte golden
    diff.
    """
    fns = _functions(SELF_SERVICE)
    flow = fns["cancelBid(uint256)"]["value_flows"][0]
    assert flow["amount_record_variable"] == "SelfServicePayout.bids"
    assert flow["amount_record_member_path"] == ["amount"]
    assert flow["amount_record_key_kinds"] == ["param"]
    assert flow["amount_record_key_param_indexes"] == [0]
    assert flow["record_ordering"] == {
        "state": "proven_ordering",
        "w2_basis": "clear_dominates_calls",
        "record": "SelfServicePayout.bids",
        "clearing_shape": "zero_assignment",
    }
    sibling = fns["rescueTokens(address,uint256)"]["value_flows"][0]
    assert not any(k.startswith("amount_record") for k in sibling)
    assert "record_ordering" not in sibling
