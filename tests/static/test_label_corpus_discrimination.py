"""What each corpus fixture is FOR, asserted rather than implied.

``tests/static/test_label_corpus.py`` proves the golden equals a fresh compile of every
corpus contract. That is a change detector: it says the bytes moved, never what
they were supposed to say. A fixture added for a shape the corpus was blind to is
only a gate if something states the property it was added to hold — otherwise a
later regeneration can absorb the regression the fixture existed to catch, and
the diff reads as "reviewed".

So this module pins the PROPERTY. Most assertions read the golden (which the A/B
gate has already proved equal to a live compile, so this stays fast); the pause
bound is read through the production reader against a live compile, because it is
not a golden field.

Each test names the fixture's discriminating pair: the row that must move under
the fix it gates, and the sibling that must not.
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


def _functions(address: str) -> dict[str, dict]:
    golden = harness.load_golden()
    contract = next(c for c in golden["contracts"] if c["address"] == address)
    return {f["full_name"]: f for f in contract["functions"]}


def _claim(fn: dict, claim_id: str) -> dict:
    return next(c for c in fn["claims"] if c["claim_id"] == claim_id)


def _destination(fn: dict) -> dict:
    return _claim(fn, "flow.out")["witness"]["flows"][0]["target_kind"]


# ---------------------------------------------------------------------------
# 1. the witness is pinned at all
# ---------------------------------------------------------------------------


def test_every_golden_claim_carries_its_witness():
    """The pin itself. Before this, ``claims`` held ``{claim_id, tier}`` and every
    field inside a witness was invisible to the gate — a producer could rebind a
    call target from one parameter to another and nothing diffed."""
    golden = harness.load_golden()
    claims = [c for contract in golden["contracts"] for f in contract["functions"] for c in f["claims"]]
    assert claims, "corpus produced no claims at all"
    assert all("witness" in c for c in claims)
    # And a witness that the JSON encoder could not represent is marked, not
    # dropped: a silently-omitted field is a field this gate does not protect.
    assert "__unpinnable__" not in harness.format_golden(golden)


# ---------------------------------------------------------------------------
# 2. constrained vs unconstrained param destinations (A4)
# ---------------------------------------------------------------------------


def _target_constraint(fn: dict) -> dict:
    return _claim(fn, "flow.out")["witness"]["flows"][0]["target_constraint"]


def test_the_four_param_destinations_are_told_apart_by_their_guards():
    """The A4 asymmetry, replacing the "all four are indistinguishable" pin this
    test carried before the narrowing landed (that test named itself as the
    measured *before* and asked to be replaced by exactly this).

    The lattice kind is still ``param`` on all four — the caller does name the
    destination in every one of them, and that fact did not change. What changed
    is the sentence attached to it: three of the four cannot be freely chosen,
    and the verdict names WHICH guard proved it, so a consumer can stop rendering
    them as caller-chosen without inventing a safety claim.
    """
    fns = _functions(CONSTRAINED)
    expected = {
        "payCommitted(IERC20,address,uint256,bytes32)": ("constrained", "hash_commitment"),
        "payAllowlisted(IERC20,address,uint256)": ("constrained", "mapping_allowlist"),
        "payTreasuryOnly(IERC20,address,uint256)": ("constrained", "equality_vs_storage"),
        # NEGATIVE CONTROL. Same body, same claim, same lattice kind, no guard.
        # A narrowing that also moves this one is wrong.
        "payAnyone(IERC20,address,uint256)": ("unconstrained_proven", None),
    }
    for name, (state, guard) in expected.items():
        assert _destination(fns[name])["kind"] == "param", name
        verdict = _target_constraint(fns[name])
        assert verdict["state"] == state, name
        assert verdict.get("guard") == guard, name


def test_the_hash_commitment_binding_is_marked_as_flow_insensitive():
    """``payCommitted``'s destination is proven through ``derived_from`` — the
    argument provenance of the ``keccak256(abi.encode(to, salt))`` the guard
    compares. That provenance is flow-INSENSITIVE (it misbinds one origin on a
    locally reassigned name), so the verdict records the binding it
    used. A consumer that must not rest on a flow-insensitive proof can see that
    it did; the two direct-operand shapes say ``operand``."""
    fns = _functions(CONSTRAINED)
    committed = _target_constraint(fns["payCommitted(IERC20,address,uint256,bytes32)"])
    assert committed["binding"] == "derived_from"
    # A flow-insensitive binding never publishes a proven pin: the guard is
    # real, but which parameter it confines on every path is not settled, so
    # the caller-chosen reading stays.
    assert committed["pins"] is None
    for name in ("payAllowlisted(IERC20,address,uint256)", "payTreasuryOnly(IERC20,address,uint256)"):
        verdict = _target_constraint(fns[name])
        assert verdict["binding"] == "operand", name
        assert verdict["pins"] is True, name


def test_the_constraint_is_present_in_the_corpus_even_though_the_flow_fact_ignores_it():
    """...and it is not merely absent from the fixture. The evidence a narrowing
    would read is IN the predicate tree of each constrained function and NOT in
    the negative control's, so a zero-diff after an A4 change means the change did
    nothing — not that there was nothing to find."""
    fns = _functions(CONSTRAINED)
    allowlisted = fns["payAllowlisted(IERC20,address,uint256)"]["predicate_tree"]
    anyone = fns["payAnyone(IERC20,address,uint256)"]["predicate_tree"]
    # The allowlist read is a membership leaf; the control's only leaf is its
    # owner check.
    assert "membership" in allowlisted["leaf_kinds"]
    assert "membership" not in anyone["leaf_kinds"]
    assert allowlisted["leaf_count"] > anyone["leaf_count"]
    for name in ("payCommitted(IERC20,address,uint256,bytes32)", "payTreasuryOnly(IERC20,address,uint256)"):
        assert fns[name]["predicate_tree"]["leaf_count"] > anyone["leaf_count"], name


# ---------------------------------------------------------------------------
# 3 + 9. delegatecall routes
# ---------------------------------------------------------------------------


def test_the_corpus_has_delegatecall_execution_rows_at_all():
    """There were zero, so every A8 assertion held vacuously."""
    fns = _functions(DELEGATECALL)
    claimed = [
        name
        for name, function in fns.items()
        if any(claim["claim_id"] == "delegatecall.execute" for claim in function["claims"])
    ]
    assert sorted(claimed) == [
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
    """A8's gate. The delegatecall SINK TARGET is a different string on every
    route — this contract's storage variable, the LIBRARY's own parameter, an IR
    reference, an assembly temporary — and only one of the four names something
    that exists here. A classifier reading that string publishes
    ``not_determined`` for a destination that is provably a storage setter, and
    BOTH production rows are assembly routes, so the corpus is the only place
    this can be caught.

    Each row below is a discriminating pair with the one above or below it:
    direct vs library (same real destination, different recorded target), and
    settable-slot vs unwritten-slot (same read, different writer set).
    """
    fns = _functions(DELEGATECALL)
    expected = {
        "execModule(bytes)": ("storage_setter", "module"),
        "execModuleViaLibrary(bytes)": ("storage_setter", "module"),
        "fallback()": ("storage_setter", None),
        "execFixedSlot(bytes)": ("storage_no_setter", None),
        # A caller-keyed mapping element. Resolving it to ``userModule`` would
        # assert ONE destination where there is one per caller — the worst
        # over-claim available on this field.
        "execUserModule(bytes)": ("indeterminate", None),
    }
    for name, (kind, variable) in expected.items():
        destination = _claim(fns[name], "delegatecall.execute")["witness"]["destination"]
        assert destination["target_kind"] == kind, name
        if variable is not None:
            assert destination["variable"] == variable, name
    # The two assembly rows are told apart by the WRITER, not by the read.
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
    """The corpus row for the ``self`` recognizer, and its discriminating pair is
    the whole set above: an ``address(this)`` destination is a compile-time value
    with no writer and no caller input, so it is PROVEN rather than one more
    thing the walk did not settle — and the mapping-element row next to it must
    stay ``indeterminate``, which is what keeps ``self`` from being a catch-all
    in the other direction.

    Both routes carry it because only the library one exercises the binding
    substitution; without the direct sibling a binding regression would be
    invisible, and without the library one the OZ v5 ``Multicall`` shape (the
    entire production population of this destination) would be."""
    fns = _functions(DELEGATECALL)
    for name in ("execSelf(bytes)", "execSelfViaLibrary(bytes)"):
        witness = _claim(fns[name], "delegatecall.execute")["witness"]
        assert witness["destination"] == {"target_kind": "self"}, name
        # A proven fixed destination earns a proven-constrained verdict; the
        # unsettled kinds get ``not_determined`` and must not be told apart from
        # this one only by the ``target_kind`` key.
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
    """R1 on the fold. Two delegatecall sites agreeing on ``storage_setter`` used
    to fold to the FIRST site's ``variable`` and ``writer_signatures`` — a
    complete-looking, owner-gated writer set with the second site's UNGATED
    writer invisible, and no representable "partial" state to warn a consumer.
    ``writer_signatures`` answers who can replace the code running in this
    contract's storage, so the honest fold is the union: both variables, every
    site's writers, and no singular ``variable`` key that a consumer could bind
    as the whole answer."""
    fns = _functions(DELEGATECALL)
    destination = _claim(fns["execBothModules(bytes)"], "delegatecall.execute")["witness"]["destination"]
    assert destination["target_kind"] == "storage_setter"
    assert destination["sites"] == 2
    assert "variable" not in destination
    assert destination["variables"] == ["module", "sideModule"]
    # The union is the point: the ungated writer must be visible next to the
    # gated one.
    assert destination["writer_signatures"] == ["setModule(address)", "setSideModule(address)"]


def test_the_a8_claim_is_not_upgrade_implementation():
    """Kept separate on purpose: ``upgrade.implementation`` carries the
    EIP-1967/UUPS population and its statistics, and a non-standard split proxy
    admitted into it would corrupt them. No corpus delegatecall row carries it."""
    fns = _functions(DELEGATECALL)
    for name in ("execModule(bytes)", "fallback()", "execUserModule(bytes)"):
        assert [c["claim_id"] for c in fns[name]["claims"]] == ["delegatecall.execute"], name


def test_the_library_route_records_a_symbol_that_does_not_exist_in_this_contract():
    """Fixture 9. Same real destination, two recorded sink targets: the direct
    route names this contract's storage variable, the library route names the
    LIBRARY's parameter. A classifier that reads the sink target as a subject
    state variable resolves the second one to nothing — and both pre-existing A8
    rows in production are direct routes, so nothing could have caught it."""
    fns = _functions(DELEGATECALL)
    direct = fns["execModule(bytes)"]["delegatecall_sinks"]
    library = fns["execModuleViaLibrary(bytes)"]["delegatecall_sinks"]
    assert direct == [{"target": "module", "origin": "body"}]
    assert library == [{"target": "target", "origin": "body"}]
    # "target" is the library's parameter name. It is not the direct route's
    # state variable, and that distinction remains explicit in the sink facts.


def test_a_caller_keyed_mapping_destination_names_no_variable_at_all():
    """The not-determined case. ``userModule[msg.sender]`` is an IR reference; no
    static analysis can name the address, and answering "userModule" would assert
    a single destination where there is one per caller."""
    sinks = _functions(DELEGATECALL)["execUserModule(bytes)"]["delegatecall_sinks"]
    assert len(sinks) == 1
    target = sinks[0]["target"]
    assert target.startswith("REF_"), target
    assert target != "userModule"


# ---------------------------------------------------------------------------
# 4. exec.arbitrary binding — the NON-FIRST address parameter
# ---------------------------------------------------------------------------


def test_the_call_target_binds_to_the_second_address_parameter():
    """Fixture 4. Two address parameters in the call's read set and the
    destination is the second. Every prior corpus ``exec.arbitrary`` had exactly
    one address parameter, so the pick was forced and any implementation passed —
    including one that takes an arbitrary member of the read set."""
    fn = _functions(EXEC_BINDING)["compose(address,address,bytes,bytes)"]
    witness = _claim(fn, "exec.arbitrary")["witness"]
    assert witness["destination_kind"] == "param"
    assert witness["destination_param"] == "to"
    assert witness["destination_basis"] == "call_destination"


def test_a_destination_that_no_parameter_determines_is_not_determined():
    """The siblings that keep the above from being "always name a parameter"."""
    fns = _functions(EXEC_BINDING)
    for name in (
        "branchedParams(address,address,bytes,bool)",
        "reassignedLocal(address,address,bytes)",
        "paramWrittenAfterCall(address,address,bytes)",
    ):
        witness = _claim(fns[name], "exec.arbitrary")["witness"]
        assert witness["destination_kind"] == "not_determined", name
        assert witness["destination_param"] is None, name
    # ...and one that IS determined, so "not_determined" is not unconditional.
    single = _claim(fns["singlyAssignedLocal(address,bytes)"], "exec.arbitrary")["witness"]
    assert single["destination_kind"] == "param"
    assert single["destination_param"] == "a"


# ---------------------------------------------------------------------------
# 6. classes F and R — a caller gate that produces no tree
# ---------------------------------------------------------------------------


def test_class_F_a_value_returning_forwarder_keeps_its_caller_gate():
    """INVERTED (commit a96b2ca3). This test previously asserted the
    defect: ``withdrawAll()`` forwards to a gated overload and, because the
    internal call's result was CONSUMED by the ``return``, the gate recursion
    was skipped and the function ended up with NO predicate tree — which every
    consumer reads as a positive claim of unguardedness.

    The asymmetry with ``pokeAll`` (same forwarding, result discarded, tree
    present) WAS the finding. The fix closes it, and this test now pins the
    closure plus the requirement that ``pokeAll`` is unchanged — a fix that
    simply disabled the skip everywhere would move ``pokeAll`` too.
    """
    fns = _functions(TREE_ABSENT)
    assert fns["withdrawAll()"]["predicate_tree"]["present"] is True
    assert "caller_authority" in fns["withdrawAll()"]["predicate_tree"]["authority_roles"]
    assert fns["withdrawTo(uint256)"]["predicate_tree"]["present"] is True
    assert fns["pokeAll()"]["predicate_tree"]["present"] is True
    assert fns["pokeTo(uint256)"]["predicate_tree"]["present"] is True
    # The two forwarders differ ONLY in whether the result is consumed, and
    # they must now agree on the gate.
    assert (
        fns["withdrawAll()"]["predicate_tree"]["authority_roles"]
        == fns["pokeAll()"]["predicate_tree"]["authority_roles"]
    )


def test_class_R_fallback_and_receive_are_caller_gated_and_carry_a_tree():
    """INVERTED (commit c2a2ebe0). This test previously asserted the
    defect: ``fallback`` and ``receive`` were excluded from the tree-building
    surface, so neither could ever carry a tree, and both of these require
    ``msg.sender == owner``. They are built for now, and the fabricated
    ``keccak("fallback()")`` / ``keccak("receive()")`` selectors are gone."""
    fns = _functions(TREE_ABSENT)
    for signature in ("fallback()", "receive()"):
        tree = fns[signature]["predicate_tree"]
        assert tree["present"] is True, signature
        assert "caller_authority" in tree["authority_roles"], signature
        assert fns[signature]["selector"] == "", signature


# ---------------------------------------------------------------------------
# 5. the timed latch — and the bound that cannot be read from real source
# ---------------------------------------------------------------------------


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
    """The asymmetry this fixture was built to gate, on real compiler output. The
    THREE states are the point, not the number: the indefinite latch is
    ``no_time_reference`` (PROVEN — a lowered guard reads it and no clock sits beside
    it), a latch no lowered leaf reads is ``not_determined``, and only the first may
    ever be rendered as "indefinite latch, no self-recovery".

    CHANGED: ``pausedUntil`` once asserted ``(2592000,
    "guard_constant")`` here and now asserts ``not_determined``. The guard is
    ``require(block.timestamp < pausedUntil + MAX_PAUSE)`` — absorbed group
    ``{latch, constant}`` — and the harvest is now side/operator-aware, because
    reading the largest plausible constant out of the operand union published a lead
    time (``block.timestamp + 3600 < pausedUntil`` → 3600) and a cooldown offset
    (``block.timestamp > pausedUntil + 300`` → 300) as freeze windows. This shape's
    constant IS its window, but the evidence for that is not in the artifact: the
    recorder sorts both inner operands of an ADDITION *or* a SUBTRACTION into one
    list, so ``pausedUntil + MAX_PAUSE`` and ``pausedUntil - MAX_PAUSE`` are
    indistinguishable here and only the first makes MAX_PAUSE a bound. Stamping the
    additive sign in the static plane recovers it provably; until then the honest
    answer is that the window was not established.

    The fixture still discriminates — three latch names, three different states — and
    a compiled positive for ``guard_constant`` still exists, on the difference shape
    (``test_pause_duration_clock_opacity.py::AbsorbedWindow`` and its two spellings).
    """
    facts = _timed_latch_facts()
    assert facts.trees, "the corpus latch produced no predicate trees"
    assert "transferTimed(address,uint256)" in facts.trees

    from services.effects import calldata as cd

    assert cd.read_max_pause_duration(facts, {"pausedUntil"}) == (None, "not_determined")
    # The indefinite latch must never inherit the timed one's bound — before or
    # after the fix — and its ``None`` is the PROVEN kind.
    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "no_time_reference")
    # A latch name no leaf reads: unknown, never indefinite. Same ``None``, different
    # state, and this is the pair the whole reader exists to keep apart.
    assert cd.read_max_pause_duration(facts, {"neitherLatch"}) == (None, "not_determined")


def test_the_timed_guard_leaf_carries_all_three_facts_across_operands_and_absorbed():
    """Locates the fix precisely: ``operands`` is UNCHANGED (still two slots, still
    ``{timestamp, MAX_PAUSE}``) and the third fact arrives on the sibling
    ``absorbed_operands`` list. Keeping ``operands`` byte-identical is deliberate —
    the value-flow lattice folds an operand's source set to ONE origin and degrades
    to ``indeterminate`` the moment two survive, so widening ``operands`` would have
    collapsed amount kinds protocol-wide."""
    facts = _timed_latch_facts()
    leaves = list(harness._tree_leaves(facts.trees["transferTimed(address,uint256)"]))
    sources = [{str(o.get("source")) for o in (leaf.get("operands") or [])} for leaf in leaves]
    assert any("block_context" in s for s in sources), "no time-shaped guard leaf at all"
    # Still two operands per leaf, and still no single leaf whose OPERANDS hold all
    # three facts: the recorder was not widened, a sibling list was added.
    assert all(len(leaf.get("operands") or []) <= 2 for leaf in leaves)
    assert not any(
        "block_context" in s and "constant" in s and any(o.get("state_variable_name") == "pausedUntil" for o in ops)
        for s, ops in zip(sources, (leaf.get("operands") or [] for leaf in leaves), strict=True)
    )
    # The window leaf: clock on ``operands``, latch + resolved constant absorbed.
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
    # The plain-boolean latch's guard absorbs nothing, so the key stays ABSENT
    # there — absence means "no additive sub-expression", not "unknown".
    frozen_leaves = list(harness._tree_leaves(facts.trees["transferFreezable(address,uint256)"]))
    assert all("absorbed_operands" not in leaf for leaf in frozen_leaves)


def test_the_timed_and_indefinite_latches_are_distinguishable_in_the_corpus():
    """Both latches exist and are told apart, which is the precondition for any
    per-latch bound to mean anything."""
    fns = _functions(TIMED_LATCH)
    assert _claim(fns["freeze()"], "pause.set")["witness"]["flags"] == [{"member": None, "var": "frozen"}]
    assert _claim(fns["unfreeze()"], "pause.unset")["witness"]["flags"] == [{"member": None, "var": "frozen"}]
    # The uint256 deadline latch is NOT recognised as a pause flag by the static
    # matcher. Recorded, not asserted as correct: it is why the two latches
    # cannot today be handed to the reader from the same source.
    assert fns["pauseTimed()"]["claims"] == []
    assert "comparison" in fns["transferTimed(address,uint256)"]["predicate_tree"]["leaf_kinds"]


# ---------------------------------------------------------------------------
# 10. the policy tier
# ---------------------------------------------------------------------------


def test_the_golden_carries_a_policy_derived_claim():
    """``policy_derived`` had zero producers across 679 claims, so no consumer
    that mishandles the weakest tier could be caught. It is produced here by the
    production cross-contract pass, not written into the golden."""
    fn = _functions(POLICY_CALLER)["depositTo(uint256)"]
    claim = _claim(fn, "flow.in")
    assert claim["tier"] == "policy_derived"
    witness = claim["witness"]
    assert witness["kind"] == "cross_contract_join"
    assert witness["callee"] == "0x00000000000000000000000000000000000000a0"
    # The join records the tier it inherited FROM, so a policy claim can never be
    # mistaken for the standard one it was derived from.
    assert witness["source_tier"] == "standard_exact"


def test_a_callee_with_an_interface_typed_parameter_is_reached_via_the_canonical_key():
    """INVERTED: this arm pinned the join miss as correct while the gap
    was real — ``build_callee_claim_map`` keyed the callee's claims by keccak
    of the DECLARED name, ``sweepTo(IERC20,address,uint256)`` → 0x38541c00,
    while the caller's sink records the ABI selector,
    ``sweepTo(address,address,uint256)`` → 0x0aeef8c8, so every callee taking
    an interface- or contract-typed parameter was invisible to the
    cross-contract pass. The claims pass now stamps the canonical
    ``abi_selector`` on the callee record and the map keys on it, so the join
    meets and ``recoverVia`` inherits the callee's ``flow.out`` at
    ``policy_derived`` — its own rank, not the callee's ``standard_exact``.
    """
    fns = _functions(POLICY_CALLER)
    derived = _claim(fns["recoverVia(address,address,uint256)"], "flow.out")
    assert derived["tier"] == "policy_derived"
    assert derived["witness"]["selector"] == "0x0aeef8c8"
    assert derived["witness"]["callee"] == "0x0000000000000000000000000000000000000070"
    # The callee's own claim is the standard_exact evidence the derivation
    # inherited from — the tiers must stay distinct.
    recovery = _functions("0x0000000000000000000000000000000000000070")
    assert _claim(recovery["sweepTo(IERC20,address,uint256)"], "flow.out")["tier"] == "standard_exact"


# ---------------------------------------------------------------------------
# A5. the rate limiter is a fact, and it does NOT move the amount lattice
# ---------------------------------------------------------------------------


def test_the_rate_limiter_is_recorded_as_a_zero_weight_fact():
    """The limiter is detected off its PUBLISHED selectors, and what it publishes
    is a fact carrying its own zero weight — not a member of the amount
    lattice."""
    fns = _functions(RATE_LIMITED)
    for name in ("withdrawLimited(address,uint256)", "withdrawTokenLimited(address,uint256)"):
        claim = _claim(fns[name], "rate_limit.consume")
        assert claim["tier"] == "idiom_structural", name
        assert claim["witness"]["severity_weight"] == 0, name
        assert claim["witness"]["mandatory"] == {"state": "proven"}, name


# The self-service family reads the MANDATORY-GATE surface, not the amount
# lattice: ``amount_constraint`` (SS-R3), ``amount_record_constraint`` and
# ``self_service_payout``. The limiter's own ``consume(id, amount)`` revert is a
# real effectful leaf that references the amount, so param_constraint refuses the
# unconstrained proof for it — a MORE-conservative reading, never a ceiling. The
# ceiling thesis below is about the amount LATTICE, so it compares that.
_MANDATORY_GATE_FIELDS = ("amount_constraint", "amount_record_constraint", "self_service_payout")


def _lattice_only(flow_entry: dict) -> dict:
    return {k: v for k, v in flow_entry.items() if k not in _MANDATORY_GATE_FIELDS}


def test_the_limiter_does_not_change_a_single_byte_of_the_flow_witness():
    """THE ASSERTION THAT PINS THE DECISION. ``withdrawLimited`` and
    ``withdrawUnlimited`` differ by exactly one statement — the limiter call —
    and their ``flow.out`` amount LATTICE must be byte-identical. A refilling
    bucket bounds throughput per window, not total loss, so crediting it in
    ``amount_kind`` would invent a ceiling that does not exist.

    If a later change moves the lattice for a limiter, THIS test goes red, which
    is the point: the decision is enforced, not merely documented."""
    fns = _functions(RATE_LIMITED)
    limited = _claim(fns["withdrawLimited(address,uint256)"], "flow.out")
    control = _claim(fns["withdrawUnlimited(address,uint256)"], "flow.out")
    limited_flows = limited["witness"]["flows"]
    control_flows = control["witness"]["flows"]
    # The lattice — the ceiling — is byte-identical, limiter present or not.
    assert [_lattice_only(f) for f in limited_flows] == [_lattice_only(f) for f in control_flows]
    assert [f["amount_kind"] for f in limited_flows] == [f["amount_kind"] for f in control_flows]
    assert limited["tier"] == control["tier"]
    # The ONLY thing the extra statement moves is the mandatory-gate reading of
    # the amount param, and it moves it toward LESS certainty, not a ceiling: the
    # limiter's effectful revert surface blocks the unconstrained proof.
    assert control_flows[0]["amount_constraint"] == {"state": "unconstrained_proven"}
    assert limited_flows[0]["amount_constraint"] == {"state": "not_determined"}
    # ...and the limiter-free control carries no limiter fact at all.
    assert [c["claim_id"] for c in fns["withdrawUnlimited(address,uint256)"]["claims"]] == ["flow.out"]


def test_the_configuration_discriminators_are_present_and_explicitly_unread():
    """G7's generalisation requirement, in the data. ``setRefillRate(id, 0)`` is
    one governance call away and turns a throughput cap into a one-shot total
    cap; a zero capacity reverts, which makes it a pause in disguise. So the two
    numbers are part of the fact — carried as three-state fields that say
    ``not_determined`` rather than being absent, because a consumer that read an
    absent field as 0 would read a rate limit as a freeze."""
    witness = _claim(_functions(RATE_LIMITED)["withdrawLimited(address,uint256)"], "rate_limit.consume")["witness"]
    for field in ("capacity", "refill_rate", "bounds_total_extraction"):
        assert witness[field] == {"state": "not_determined", "source": "chain_state"}, field
    # The witness names the reads that would fill them, so the follow-up is not a
    # guess about which getter holds the numbers.
    assert witness["config_reader"]["get_limit_selector"] == "0xd200f8c2"
    assert "one-shot total cap" in witness["interpretation"]
    assert "pause in disguise" in witness["interpretation"]


def test_a_same_named_different_selector_callee_earns_nothing():
    """NEGATIVE CONTROL for name-based detection. ``decoyLimiter.consume`` is
    spelled identically and publishes a different signature, so a different
    selector. Nothing here keys on the identifier."""
    fns = _functions(RATE_LIMITED)
    assert [c["claim_id"] for c in fns["withdrawDecoy(address,uint256)"]["claims"]] == ["flow.out"]


# ---------------------------------------------------------------------------
# self-service payout — the cancelBid / rescueTokens pair
# ---------------------------------------------------------------------------


def test_the_cancel_bid_shape_proves_self_service_and_the_rescue_sibling_earns_nothing():
    """The discrimination pair for the whole W1∧W2 join. ``cancelBid`` reads the
    amount out of the caller's OWN record (the guard and the amount name the
    same ``bids[_bidId]`` cell, membership by ``.bidder == msg.sender``) and
    clears it before the pay, so the verdict is the full proven dict — pinned
    whole, including the two canonical disclosure tokens, so a dropped
    disclosure or a renamed basis diffs here and not just in the golden bytes.

    ``rescueTokens`` moves value with a caller-chosen destination AND amount
    behind an owner gate: the self-service question does not exist for a param
    amount, so the keys must be ABSENT — an owner gate must never stand in for
    a witness, and absence (not a refusal record) is the fail-closed state a
    consumer reads."""
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
    # The sibling still carries the SS-R3 substrate for its param amount: the
    # owner gate does not confine WHICH amount, and the fact says so.
    assert rescue["amount_constraint"] == {"state": "unconstrained_proven"}


def test_the_flow_plane_pins_the_record_identity_and_the_ordering_witness():
    """Golden schema 6. The join's evidentiary substrate lives on the flow
    itself — which cell, which member, who chose the key, and the W2 ordering
    proof — and none of it was pinned before, so a producer that stopped
    resolving the record would have regressed every verdict to not_determined
    with a zero-byte golden diff."""
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
    # The sibling's flow carries none of the record keys: a param amount never
    # names a record, and the ordering question does not exist without one.
    sibling = fns["rescueTokens(address,uint256)"]["value_flows"][0]
    assert not any(k.startswith("amount_record") for k in sibling)
    assert "record_ordering" not in sibling
