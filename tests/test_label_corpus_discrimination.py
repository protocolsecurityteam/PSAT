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
RATE_LIMITED = "0x0000000000000000000000000000000000000110"
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
    compares. That provenance is flow-INSENSITIVE (WAVE_0 L-24: it misbinds one
    origin on a locally reassigned name), so the verdict records the binding it
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
    labelled = [n for n, f in fns.items() if "delegatecall_execution" in f["effect_labels"]]
    assert sorted(labelled) == [
        "execFixedSlot(bytes)",
        "execModule(bytes)",
        "execModuleViaLibrary(bytes)",
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


def test_class_F_a_value_returning_forwarder_loses_its_caller_gate():
    """``withdrawAll`` is callable in fact only by the operator: it forwards to a
    gated overload. Because the internal call's result is CONSUMED by the
    ``return``, the gate recursion is skipped and the function ends up with NO
    predicate tree — which every consumer reads as a positive claim of
    unguardedness.

    The sibling ``pokeAll`` forwards to the same gated shape and discards the
    result, and DOES acquire the tree. That asymmetry is the finding; a fix must
    close it without changing ``pokeAll``.
    """
    fns = _functions(TREE_ABSENT)
    assert fns["withdrawAll()"]["predicate_tree"]["present"] is False
    assert fns["withdrawTo(uint256)"]["predicate_tree"]["present"] is True
    assert fns["pokeAll()"]["predicate_tree"]["present"] is True
    assert fns["pokeTo(uint256)"]["predicate_tree"]["present"] is True
    # The two forwarders differ ONLY in whether the result is consumed.
    assert fns["withdrawAll()"]["effect_labels"] == fns["pokeAll()"]["effect_labels"]


def test_class_R_fallback_and_receive_are_caller_gated_and_treeless():
    """``fallback`` and ``receive`` can never carry a tree — they are excluded
    from the externally-callable set twice over — and both of these require
    ``msg.sender == owner``."""
    fns = _functions(TREE_ABSENT)
    assert fns["fallback()"]["predicate_tree"]["present"] is False
    assert fns["receive()"]["predicate_tree"]["present"] is False


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


def test_the_limiter_does_not_change_a_single_byte_of_the_flow_witness():
    """THE ASSERTION THAT PINS THE DECISION. ``withdrawLimited`` and
    ``withdrawUnlimited`` differ by exactly one statement — the limiter call —
    and their ``flow.out`` witnesses must be byte-identical. A refilling bucket
    bounds throughput per window, not total loss, so crediting it in
    ``amount_kind`` would invent a ceiling that does not exist.

    If a later change moves the lattice for a limiter, THIS test goes red, which
    is the point: the decision is enforced, not merely documented."""
    fns = _functions(RATE_LIMITED)
    limited = _claim(fns["withdrawLimited(address,uint256)"], "flow.out")
    control = _claim(fns["withdrawUnlimited(address,uint256)"], "flow.out")
    assert limited["witness"]["flows"] == control["witness"]["flows"]
    assert limited["tier"] == control["tier"]
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
