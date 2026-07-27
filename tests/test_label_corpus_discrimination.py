"""What each W0-7 corpus fixture is FOR, asserted rather than implied.

``tests/test_label_corpus.py`` proves the golden equals a fresh compile of every
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

from tests.support import label_corpus as harness  # noqa: E402

CONSTRAINED = "0x00000000000000000000000000000000000000b0"
DELEGATECALL = "0x00000000000000000000000000000000000000c0"
EXEC_BINDING = "0x00000000000000000000000000000000000000d0"
TREE_ABSENT = "0x00000000000000000000000000000000000000e0"
TIMED_LATCH = "0x00000000000000000000000000000000000000f0"
POLICY_CALLER = "0x0000000000000000000000000000000000000100"


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


def test_all_four_param_destinations_are_currently_indistinguishable():
    """The measured "before". Three of these destinations cannot be freely
    chosen — a hash commitment, a mapping allowlist, a storage equality — and the
    fourth genuinely can, yet all four publish the same lattice value.

    This is what makes an A4 narrowing meaningful here: it must move the first
    three and leave ``payAnyone`` alone. When that lands, THIS test fails, and it
    should — replace it with the asymmetry, do not delete it.
    """
    fns = _functions(CONSTRAINED)
    constrained = [
        "payCommitted(IERC20,address,uint256,bytes32)",
        "payAllowlisted(IERC20,address,uint256)",
        "payTreasuryOnly(IERC20,address,uint256)",
    ]
    unconstrained = "payAnyone(IERC20,address,uint256)"
    for name in [*constrained, unconstrained]:
        assert _destination(fns[name])["kind"] == "param", name


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
    labelled = [n for n, f in fns.items() if "delegatecall_execution" in f["effect_labels"]]
    assert sorted(labelled) == [
        "execModule(bytes)",
        "execModuleViaLibrary(bytes)",
        "execUserModule(bytes)",
    ]


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
    # "target" is the library's parameter name. It is not a state variable here,
    # and that is the whole point.
    setter_targets = fns["setModule(address)"]["effect_targets"]
    assert setter_targets == ["module"]
    assert "target" not in setter_targets


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
# 6. G3 classes F and R — a caller gate that produces no tree
# ---------------------------------------------------------------------------


def test_class_F_a_value_returning_forwarder_keeps_its_caller_gate():
    """INVERTED (W1-A, commit a96b2ca3). This test previously asserted the
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
    # they must now agree on the gate as well as on the labels.
    assert fns["withdrawAll()"]["effect_labels"] == fns["pokeAll()"]["effect_labels"]
    assert (
        fns["withdrawAll()"]["predicate_tree"]["authority_roles"]
        == fns["pokeAll()"]["predicate_tree"]["authority_roles"]
    )


def test_class_R_fallback_and_receive_are_caller_gated_and_carry_a_tree():
    """INVERTED (W1-A, commit c2a2ebe0). This test previously asserted the
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


def test_the_pause_duration_reader_finds_no_bound_in_real_compiler_output():
    """MEASURED, and it is not the result the fixture was written to produce.

    ``read_max_pause_duration`` wants ONE guard leaf holding all three of
    ``block.timestamp``, the latch's own state variable, and a constant. The
    predicate builder cannot emit that leaf for ANY source shape, and the reason
    is structural rather than unlucky: a Solidity comparison lowers to a leaf
    with exactly TWO operands, and when one side is arithmetic the operand
    recorder keeps one sub-operand and discards the other. Five shapes were
    compiled and every one lost exactly one of the three facts —
    ``block.timestamp < pausedUntil + 2592000`` records
    ``{timestamp, pausedUntil}`` (literal gone),
    ``block.timestamp - pausedUntil < 2592000`` records
    ``{pausedUntil, 2592000}`` (clock gone). Three facts do not fit in two
    slots. So the reader returns ``None`` for the TIMED latch here — a contract
    that declares ``uint256 public constant MAX_PAUSE = 30 days`` and compares
    ``block.timestamp`` against it in the guard.

    CONSEQUENCE FOR THE GATE, stated so a later reader does not overrate it: this
    fixture does NOT discriminate timed from indefinite, because both publish
    ``None``. It discriminates a reader that INVENTS a bound (proven: forcing
    ``read_max_pause_duration`` to fall back on a scraped 2592000 turns this
    test red). A7 must widen the leaf's operand set before any compiled source
    can reach the positive branch; adding more latch fixtures cannot.

    ``None`` is published as ``duration_bound_seconds`` and read downstream as
    "indefinite latch, most severe", so nothing false is being emitted — the
    conservative answer is the one being given. What is false is the belief that
    the reader has a reachable positive branch: its only passing positive test
    builds the leaf by hand.

    This test is the gate for that fix. When the timed latch starts yielding
    2592000, it fails, and it must be updated to assert the asymmetry (timed ⇒
    2592000, indefinite ⇒ None) rather than deleted.
    """
    facts = _timed_latch_facts()
    assert facts.trees, "the corpus latch produced no predicate trees"
    assert "transferTimed(address,uint256)" in facts.trees

    from services.effects import calldata as cd

    assert cd.read_max_pause_duration(facts, {"pausedUntil"}) is None
    # The indefinite latch must never inherit a bound, before or after any fix.
    assert cd.read_max_pause_duration(facts, {"frozen"}) is None


def test_the_timed_guard_leaf_is_present_and_it_is_the_operand_set_that_is_short():
    """Locates the gap precisely, so the test above cannot be read as "the fixture
    has no timed guard". The guard IS there and IS time-shaped; what is missing is
    a constant operand beside the latch in the same leaf."""
    facts = _timed_latch_facts()
    leaves = list(harness._tree_leaves(facts.trees["transferTimed(address,uint256)"]))
    sources = [{str(o.get("source")) for o in (leaf.get("operands") or [])} for leaf in leaves]
    assert any("block_context" in s for s in sources), "no time-shaped guard leaf at all"
    assert any(
        "block_context" in s and any(str(o.get("state_variable_name")) == "pausedUntil" for o in leaf["operands"])
        for s, leaf in zip(sources, leaves, strict=True)
    ), "no leaf pairs block.timestamp with the latch"
    # ...and no leaf pairs all three.
    assert not any(
        "block_context" in s and "constant" in s and any(o.get("state_variable_name") == "pausedUntil" for o in ops)
        for s, ops in zip(sources, (leaf.get("operands") or [] for leaf in leaves), strict=True)
    )


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


def test_a_callee_with_an_interface_typed_parameter_is_unreachable_across_the_join():
    """MEASURED, and pinned EMPTY on purpose.

    ``recoverVia`` resolves onto AssetRecovery, whose ``sweepTo`` carries a
    standard_exact ``flow.out``, and derives nothing. ``build_callee_claim_map``
    keys the callee's claims by the selector on its effects record — keccak of the
    DECLARED name, ``sweepTo(IERC20,address,uint256)`` → 0x38541c00 — while the
    caller records the ABI selector, ``sweepTo(address,address,uint256)`` →
    0x0aeef8c8. Every callee taking an interface- or contract-typed parameter is
    therefore invisible to the cross-contract pass.

    This is the row that must gain a claim when that is fixed.
    """
    fns = _functions(POLICY_CALLER)
    assert fns["recoverVia(address,address,uint256)"]["claims"] == []
    assert fns["recoverVia(address,address,uint256)"]["effect_labels"] == ["external_contract_call"]
    # The callee's own claim exists and is propagatable — the gap is the key, not
    # the evidence.
    recovery = _functions("0x0000000000000000000000000000000000000070")
    assert _claim(recovery["sweepTo(IERC20,address,uint256)"], "flow.out")["tier"] == "standard_exact"
