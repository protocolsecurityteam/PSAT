"""Effect-verdict cache read/write with kernel-vs-projection scope + a self-audit.

The persistence layer that selection → harness → verdicts is wired onto. Mirrors
``db/contract_materializations.py``: schema-version invalidation, an advisory-lock
coalesce on writes, and cross-job / cross-chain-twin reuse. Verdicts are small
(a ``details`` JSONB witness + a ``transcript_ptr`` artifact key), so there is no
blob-storage split — the multi-MB concern that shapes the materialization cache
does not apply here.

Two scopes:

* **kernel** — function-local (latch-flip, gate-mutation, code-change, supply
  sign, destination *shape*). Keyed on the resolved-function behavioral hash;
  ``contract_surface_hash`` is the empty sentinel. Transfers across every
  deployment sharing the hash, cross-chain twins included.
* **projection** — contract-scoped (pause blast radius, authorization delta).
  Keyed ADDITIONALLY on the whole-contract surface hash, because the same mixin
  kernel yields different blast radii on different surfaces.

Concrete values (the exact destination, the exact impl, the current-check
result) are NEVER cache keys — they are per-deployment state-plane
residue and live in ``effect_verdicts``.

The self-audit lives here (``kernel_verdicts_agree`` + the ``audit_*``
bookkeeping) because it is a cache-integrity concern: the first time two
functions share a kernel hash, the second sighting re-simulates and asserts the
kernel verdicts match before the free hit is *trusted*. A hashing bug that
collided two distinct behaviors is caught here instead of silently propagating a
wrong verdict across deployments.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, case, func, null, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models import EffectBehaviorCache, EffectiveFunction, EffectVerdict

logger = logging.getLogger(__name__)

# Bump to invalidate every stored verdict when the recipe/verdict output shape
# changes. Deliberately independent of a git SHA (mirrors
# ``ANALYSIS_SCHEMA_VERSION``): an unrelated deploy must not cold-miss the whole
# behavioral cache.
# v2: pause probes seed token preconditions (balance/allowance/shares/owner
# slots, read-back verified). A v1 ``unknown`` row for a surface whose entry
# points were precondition-blind would otherwise cache-hit forever and mask the
# widened observed radius.
# v3: Tier-1 value_out/supply probes retry with the caller's INPUT ASSET seeded
# (read-back verified). Every deposit-backed conversion previously cached an
# ``unknown`` from a precondition revert; those rows would otherwise hit forever
# and keep the whole ``supply.mint`` backing witness empty.
# v4: the verdict OUTPUT SHAPE changed in four ways that make a v3 row unsafe to
# serve. (a) A burn whose ``totalSupply`` wrapped was published as
# ``supply_delta_sign: mint`` with the witnessed-dilution payload — the
# strongest claim this stage makes, on a call that destroyed units — and those
# rows were written under v3, so without a bump the poisoned verdict is returned
# verbatim and never rewritten (a disagreeing re-probe only marks it
# AUDIT_FAILED, and a failed row is still served). (b) ``destination_shape`` was
# ~95% ``unknown`` because its proof branch was unreachable; it now resolves.
# (c) ``freeze_pause`` rows carry the ``observation`` discriminator every other
# class already carried. (d) Seeded holder balances are capped at the token's own
# supply, so a seeded verdict was reached from different fork state.
# v5: the input-token hints feeding the seeded retry now resolve a library-wrapped
# token receiver to its real getter (was a Slither temporary that seeded the wrong
# token or nothing), so a v4 row was reached from a different seeded fork state and
# must not be served to the new probe.
# v6: the storage read path now resolves DB-recorded keys carrying a foreign
# environment prefix. Before it, ``hydrate_predicate_trees`` returned None for
# 75/75 materializations and ``get_source_files`` returned 0 files for every job
# — so every v5 row was probed against an empty predicate-tree / empty-source
# analysis state, i.e. a different seeded fork state than the same probe reaches
# now. Serving those rows would keep the pre-fix verdict forever.
# v7: candidate ordering was a function of float rounding noise, not of the
# data — 8 PYTHONHASHSEED values produced 8 different candidate orders and 129 of
# 443 rows changed rank, because the value-at-stake sum ran over a ``set`` in
# binary float and one ulp routed equal-value candidates around the ``function_id``
# tiebreak. Order decides which candidates a ``resource_cap`` run reaches, so a v6
# row records what a probe queue built from rounding noise happened to visit; it
# is not the row the now-deterministic queue produces.
# v8: the ``exec.arbitrary`` witness now names a destination/calldata parameter
# only where the call IR puts that parameter in that operand position, and says
# ``state_var`` / ``call_argument`` / ``not_determined`` where it does not. The
# old names came from an arbitrary member of a read-set intersection over
# identity-hashed Slither objects, so they were wrong on both functions where a
# choice existed and varied with allocation order between processes. The executor
# probe builds its inner call from those two slots, so a v7 row records a call
# synthesized around a parameter that is not the destination — a different probe
# input, not merely a different label.
# v9: the same witness now answers ``not_determined`` where the destination or
# payload reaches the call through a name the function body defines more than
# once. Under v8 those resolved through whichever defining IR came first in
# source order and were published as one of the two PROOF states — a caller-
# chosen destination reported as ``state_var`` (proven absent) or as the wrong
# parameter's name. The executor probe builds its inner call from those slots and
# a non-``param`` kind takes it down the ABI-uniqueness path instead, so a v8 row
# on such a function records a verdict reached from a different synthesized call.
# Measured: every one of the 28 witnesses the production compilation units mint is
# byte-identical across the change, so this bump covers the shapes the corpus
# proves changed, not any row observed here.
# v10: a ``computed`` predicate-tree operand now carries ``derived_from`` — the
# origins that reached it through the arguments of the computation that produced
# it. A ``keccak256``/``abi.encode`` used to collapse them into a digest, so a
# hash-commitment gate arrived at the leaf builder with every parameter it
# commits already destroyed (Teller ``refundDeposit`` bound ``nonce`` and nothing
# else; ``receiver`` and four more committed parameters were unrecoverable). The
# probe reads the tree to decide what a gate constrains, so a v9 row records a
# verdict reached from a strictly smaller constraint set than the same probe
# now sees. Measured on the 88 production compilation units: the effect
# artifacts are byte-identical on 87, and on ``EtherFiOracle.unpublishReport``
# the sink *order* moved, which renumbers the ``sinkN`` ids a v9 row references.
# Order there is Slither's ``list(set(vars_written))`` over identity-hashed
# objects, so it tracks allocation addresses; the (kind, target, selector,
# origin) multiset is identical.
# v11: the ``flow.out``/``value_router`` and ``exec.arbitrary`` witnesses now
# carry a three-state destination-constraint verdict (``target_constraint`` /
# ``destination_constraint``): whether a MANDATORY revert gate between entry and
# sink references the destination parameter. A ``param`` destination was
# previously published as one undifferentiated fact and read downstream as
# "the caller can send this anywhere"; on the local artifacts 4 of 80 param
# destinations carry a proven gate and 18 more are not determined, and 7 of the
# 20 ``exec.arbitrary`` sites carry one. The probe selects and shapes its inner
# call from the destination witness, so a v10 row records a verdict reached
# without knowing whether the destination it synthesised was reachable at all —
# a different probe input, not merely a different label.
# v12: ``exec.arbitrary`` is no longer minted where the destination is PROVEN to
# be a state variable. The claim asserts a caller-supplied target and
# ``state_var`` is the proof that the caller does not supply one, so a v11 row on
# such a function carries a claim whose witness states its own negation — and
# the executor probe builds its inner call from that witness, so it synthesised a
# call around a destination the caller cannot reach. ``not_determined`` still
# mints (an open question is not a proof of absence), so this covers only the
# rows where the two contradict.
# Between v12 and v13, recorded late: the ``rate_limit.consume`` claim class — a
# zero-severity-weight FACT witness carrying the ``refillRate``/``capacity``
# discriminators — was introduced onto 10 local functions with no bump, which the
# rule above this list requires. The v13 argument below applies to it verbatim:
# the probe's candidate selection and its synthesized call both read the claim
# set, so until the enrollment-transparency restoration under the v17 entry, a
# cached row on those functions was reached with this class absent from the set
# (the same 12-13 rows that restoration names). No retroactive bump is needed for
# correctness — every row written before the class existed predates v11, and the
# later bumps already invalidate it — but the class introduction itself belongs
# in this history.
# v13: the new ``delegatecall.execute`` claim class. A function whose foreign-code
# execution was previously carried only by the legacy ``delegatecall_execution``
# label now publishes a witness naming where that code comes from
# (``storage_setter`` with its writer, ``indeterminate`` for a caller-keyed
# mapping element). The probe's candidate selection and its synthesized call both
# read the claim set, so a v12 row was reached with this class absent from it.
# v14: ``unconstrained_proven`` in the destination-constraint verdict now
# requires the leaf projection to be checkably complete (expression/parameter
# cross-check, keyed-collection reads, parameter_names presence), a computed
# operand always blocks the negative proof (its origin binding is
# flow-insensitive, so silence there is not evidence), and a proven OZ-timelock /
# Safe exec entry publishes the standard's own commitment for every parameter.
# A v13 row can carry a positive proof of absence minted from a lossy
# projection's silence — measured on the local artifacts: 4 of 32 such proofs
# were false (two timelock ``execute`` destinations that are hash-committed,
# a merkle-drop ``account`` the ``verify`` leaf touches, a Teller ``to`` gated
# by ``beforeTransferData[to].denyTo``) — and the probe shapes its call from
# that verdict, so those rows must not be served to the new probe.
# v15: every ``constrained`` destination verdict now carries ``pins`` — the
# three-state answer to whether the guard PINS the parameter (True allowlist /
# commitment, False denylist / ordering bound, None external revert surface
# whose set semantics are another contract's). A v14 row's ``constrained`` was
# one undifferentiated state that consumers rendered as "gated", which on the
# local artifacts silently promoted 4/4 blacklist-checked flow destinations
# (EtherFiRedemptionManager.redeem*) into pinned ones; the probe reads the
# verdict to decide whether a synthesized destination can be reached at all,
# so a row minted without the discriminator must not be served to the probe
# that now expects it.
# v16: the ``exec.arbitrary`` taint fragment now answers over EVERY candidate
# call op instead of the first one in body order, so the v12 suppression's
# ``state_var`` is a function-wide proof rather than a first-op fact. Under v15
# a body holding a storage-destination op ahead of a genuine
# ``target.call(data)`` — the Safe/Zodiac transaction-guard idiom — published
# NO claim and no ``arbitrary_external_call`` label, and its statement-swapped
# twin published both; the probe's candidate selection and its synthesized call
# read the claim set, so a v15 row on such a function was reached with the
# function's highest-severity claim absent for a reason that was statement
# order, not evidence.
# v17: a multi-site ``delegatecall.execute`` destination whose sites agree on a
# kind now publishes the UNION of every site's evidence (plural ``variables``,
# merged ``writer_signatures``) instead of the first site's record. A v16 row on
# a two-module body carries one module's writer set presented as the whole
# answer — an ungated second writer invisible behind a gated first — and the
# probe reads the claim witness, so such a row was reached from a witness that
# understates who can replace the executing code.
#
# Still v17 — enrollment transparency (a restoration, not a new analysis):
# ``rate_limit.consume`` and ``delegatecall.execute`` are now TRANSPARENT to the
# probe's candidate selection (``services/effects/selection.py:
# _enrolled_families``): a function whose only claims are these fact classes
# stays the blank full-synthesis candidate it is today, instead of silently
# leaving the candidate set the moment the claims plane mints the new ids (13
# local rows: LRTSquaredAdmin.depositToStrategy and the 12 EtherFiNodesManager
# rate-limited queue/consolidation functions). No bump: for those rows the
# candidate shape the probe sees — full synthesis, ``restrict_families=None`` —
# is byte-identical before and after the fact claims are minted, so a cached
# verdict remains an answer to the same probe; every other row's claim set and
# probe input are untouched.
# v18: exec-mode destination-constraint transparency is now EARNED per call op —
# an identity enters the transparency set only when IR proves that op's own
# destination parameter-rooted, and is withheld when any fixed- or unresolved-
# destination op shares it — instead of covering every body external call. A
# v17 row on a Safe/Zodiac transaction-guard body (a mandatory nonview guard
# call vetting the caller-supplied target before the arbitrary call) carries
# ``destination_constraint: unconstrained_proven`` minted from the swallowed
# guard leaf, byte-identical to a genuinely guardless function; the same walk
# now answers ``not_determined``. The probe shapes its synthesized call from
# that verdict, so such a row was reached from a proof of absence the walk can
# no longer mint. Measured: 0 of the local DB's recomputable exec/delegatecall
# rows flip (none carries a swallowed nonview guard leaf — a lower bound, not
# a population claim); the two corpus guard-idiom rows are the realised flips.
# v19: the v18 rule now reaches the VALUE-FLOW side. A routed move carries the
# identity of the call that crossed the boundary (``ValueFlow.router_ops``,
# recorded by the producer at the crossing site), and value_flow-mode
# destination-constraint transparency is granted to exactly that op — no
# longer to every body external call of a routed function. A v18 row on a
# routed body with a mandatory nonview destination guard beside the router
# (``guard.checkDestination(to)`` before ``vault.exit(to, …)``) carries
# ``target_constraint: unconstrained_proven`` minted from the swallowed guard
# leaf, byte-identical to the guard-free control; the same walk now answers
# ``not_determined``. The probe selects and shapes its inner call from the
# destination witness (the v11 argument), so such a row was reached from a
# proof of absence the walk can no longer mint. Measured: on the persisted
# (pre-``router_ops``) artifacts the two ``bulkWithdraw`` param destinations
# fall to ``not_determined`` until re-analysis records the op; on recomputed
# source the corpus router rows keep their verdicts (0 flips) and the
# guard-idiom fixture pair is the realised discrimination.
# v20: the predicate trees the probe is seeded from now cover two shapes they
# could not reach before. (a) The cross-function gate recursion was
# suppressed whenever a call's result was read anywhere, not only where it
# reaches a branch condition, so every `return gatedCallee(...)` forwarder
# arrived at the probe with the callee's gate missing — 406 function entries
# move across the 88 production compilation units, and on the corpus
# `TreeAbsentPublics.withdrawAll` goes from no tree to a caller_authority leaf.
# (b) `fallback` / `receive` had no tree BUILT at all, so a caller-gated
# fallback was seeded as unguarded; on the corpus both `TreeAbsentPublics` entry
# points gain a caller_authority leaf, and in the local corpus
# PriorityWithdrawalQueue and WithdrawRequestNFT gate `receive()` on
# `msg.sender != liquidityPool`. A pre-v20 row therefore records a verdict
# reached from a strictly smaller gate set than the same probe now sees. The
# same change also replaces the fabricated `keccak("fallback()")[:4]` /
# `keccak("receive()")[:4]` selectors with the empty-string sentinel this file
# already fixes, so pre-v20 rows for those functions are keyed on an identity no
# caller could ever produce.
# v21: candidate ordering again — ``build_authority_graph`` folded EVERY
# ``control_graph_edges`` row into the authority closure with no relation
# predicate, so a slot the contract merely CALLS propagated the callee's whole
# downstream value into the caller's ``value_at_stake``. Callee edges are now
# written as ``external_call_target`` and the closure reads only
# ``CONTROL_EDGE_RELATIONS``. Locally that removes 1,200 of 2,756
# external_contract-sourced edges from the closure and drops mutual control
# pairs 66 -> 28. Order decides which candidates a ``resource_cap`` run
# reaches (the v7 precedent), so a pre-v21 row records what a probe queue built
# from a closure containing non-control edges happened to visit; it is not the
# row the corrected closure produces.
# v21 (same version, second correction): the ``external_call_target`` demotion
# above is driven by ``authority_provenance``, which was emitted from the
# ABSENCE of predicate-tree evidence — a treeless artifact stamped every
# external-contract slot ``call_target``, including proven gates, and dropped
# them out of that same closure. Corrected in ``build_controller_tracking``.
# No bump for it: the fix shipped alongside v21's introduction, so no pre-fix
# v21 row was ever written to protect. Serving concerns are covered by
# the bump above; this note only keeps the version's stated reason matching the
# code it ships with.
# v21 (same version, third correction): the same absence one level down. The
# correction above only asked whether the artifact had ANY trees; ``caller_gate``
# is read out of the trees that were LOWERED, and the builder never lowers
# ``receive`` / ``fallback`` and produces no tree for a gate it cannot model. A
# gate living in one of those was invisible, so the address was still stamped
# ``call_target`` and still dropped out of the closure — realised on 427 of the
# 1,200 demoted edges locally. ``call_target`` is now withheld for any name an
# unlowered, caller-observing entry point reads. Same no-bump reasoning.
# (Caveat on that 427/1,200 figure: it was measured against a tree builder that
# did not lower ``fallback``/``receive``. The v20 change lowers them, so that
# subset now reaches ``caller_gate`` and the withholding branch's realised
# population is lowering FAILURES — smaller than 427, not re-measured here. The
# sentinel's firing proof is by construction:
# test_gate_in_an_unlowered_function_is_not_published_as_a_callee removes a
# lowered tree, the exact shape a degraded tree stage persists.)
# (Correction to the mutual-edge figure above: 66 -> 28 and 66 -> 44 are both
# stale. The number that reproduces from the production
# ``build_controller_tracking`` path is 66 -> 32 mutual directed edges
# (372 -> 306 distinct directed pairs); treat 66 -> 32 as canonical.)
# v22: the freeze witness now says HOW the pause window was
# established — ``duration_bound_source`` beside ``duration_bound_seconds``
# (``config.DURATION_BOUND_*``) — and the predicate leaves the reader is fed carry
# the additive sub-operands a two-slot comparison discarded
# (``absorbed_operands``). A pre-v22 row publishes ``duration_bound_seconds:
# null`` with no source, and the documented consumer contract read that pair as
# "indefinite latch, most severe": false on all four proven ``freeze_pause``
# verdicts in the local corpus, every one of them a ``pauseUntil`` timestamp latch
# whose window is a storage value. The reader also now RESOLVES a window it could
# not see before (measured: 10 of 11 compiled guard shapes went from ``None`` to
# the declared constant), and the recipe warps the fork by that bound to test
# auto-expiry — so a pre-v22 row for such a latch records a verdict reached
# without the expiry probe ever running.
# v23: ``_principals_by_function`` had no ORDER BY, and
# its first element is the identity every fork probe impersonates
# (``candidate.principal_addresses[0]``). Which holder we simulated as — and so
# which gate the probe passed, which revert it recorded, and what the witness said
# — was a function of the query plan, not of the data, on every multi-principal
# function (33 principals on one local function, 27 on two more). A pre-v23 row
# records a verdict reached as whichever holder the heap happened to return first.
# v24: ``concrete_destination`` is withheld on a
# ``caller_arbitrary`` destination shape, and the two identities this prober INVENTS
# (``SENTINEL_ADDRESS``, ``NEUTRAL_CALLER``) are excluded from the observed-
# destination capture everywhere. On 35 of 35 local caller_arbitrary rows the stored
# value was the probe's own recipient argument read back, and the one row with no
# resolved principals stored ``0x1111…1111`` — this stage's most concrete
# "destination" fact was not a fact about the contract at all. The cache row itself
# holds no destination, but the hit path's residue re-observation reads the
# shape out of ``details`` to decide whether a re-probe can yield anything, so a
# pre-v24 row drives that decision under the old rule.
# v25: the reach payload gained ``reach_determined`` and now
# publishes the acting deployment's own balance as ``observed_reach_floor_usd``
# instead of as ``observed_reach_value_usd``. The not-measured branch fires for any
# zap/router/adapter that moves value it does not hold (18 armed local flow.out
# functions on 6 zero-balance contracts), and while the floor rode the
# measured-reach key a consumer that read the number and ignored the flag scored
# "$0 reach" for a function that may move millions. Reach itself is state-plane and
# never enters a cache row — the bump is because the same probe now returns
# a different ``concrete`` shape, and the hit path re-publishes ``details`` beside
# residue written under the old contract.
# v26: reach is measured PER ASSET. The probe's holder set is
# now ``(holder, asset, usd|None)`` — native keyed on the emitter
# ``eth_simulateV1``'s traceTransfers actually uses (measured: 3 reads at head-10 + a
# pinned read at 25619159, with an ERC-20 control) — and a moved asset with no priced
# holding makes the total not-determined instead of contributing the holder's whole
# balance sheet. A pre-v26 row's reach was computed asset-blind: the weETH proxy's
# $3.489B sheet (99.99% eETH) was attributed to a synthetic native-ETH move, and two
# rows of that shape carried 64.96% of ALL published reach USD in the DB.
# v27: the reach figure now carries the outcome of a
# corroborating CEILING (``reach_tvl_check`` against ``tvl_snapshots.defillama_tvl`` —
# never ``total_usd``, which is NULL on every row) and the REASON an asset could not be
# valued, including a holdings list at the fetcher's one-page cap. A pre-v27 row's
# reach was never checked against the protocol's own TVL: the worst published row
# asserted $3.489B against a TVL of $3.297B.
# v28: the claim witness now forwards
# ``destination_shape`` and ``shape_proved_by``. NO claim in the database carried
# either, so the fork's ``caller_arbitrary`` proof on 35 rows had never reached a
# consumer, and the two approve-then-pull rows published $472M of reach with no
# destination statement at all. The cache row already held both keys in ``details``;
# the bump is because the claim projection a hit re-publishes now includes them, so a
# pre-v28 row's ``details`` is served into a consumer contract that expects them.
# v29: ``details`` is split into planes. Every key in
# ``DEPLOYMENT_PLANE_KEYS`` — ``observed_blast_radius``, ``pre_pause_succeeding``,
# ``scored_denominator``, ``input_seeded``, ``contract_balance_seeded``, ``backing`` —
# is an observation of ONE deployment's fork state and is now stripped at the write, so
# a hit serves code-plane facts only and those keys are ABSENT on the hitting
# deployment's witness (absent, not null and not false). A pre-v29 row CARRIES them: 74
# of 150 local rows do, and serving one republishes another contract's blast radius,
# seeding qualifiers and mint backing as this deployment's own witness. Same defect
# class as the reach leak that moved to ``observed_residue``, on five more fields.
# The self-audit also gained its floor here: a signature with no structural key
# is no longer trusted on agreement alone (49 of 150 rows compare ``unknown`` with
# itself), so which verdict a hitting deployment publishes can differ from a pre-v29 run.
# v30: ``duration_bound_source`` no longer asserts
# ``no_time_reference`` — PROVEN indefinite, the most severe freeze this system
# states — from a LEAF-LOCAL absence of a clock. Two shapes reproduced a false proof
# from compiled Solidity: a lowered ``||`` puts the latch and the clock in SIBLING
# leaves (``require(!frozen || block.timestamp > unpauseAt)``, a freeze that expires),
# and a tree persisted before the ``absorbed_operands`` widening drops the clock out
# of ``require(block.timestamp - pausedUntil < 2592000)`` altogether. The state now
# also requires a clock-free whole guard tree and known-complete operand lists, so a
# pre-v30 row's ``no_time_reference`` may be a proof its evidence never supported.
# v31: the OPACITY half of the ``no_time_reference`` proof
# was still leaf-local, and its opaque-source set omitted the two operand kinds that
# name a callee the builder never entered. Reproduced through the production predicate
# builder: ``require(!frozen || _clock() > unpauseAt)`` with ``_clock()`` an internal
# view returning ``block.timestamp`` — Uniswap V3's ``_blockTimestamp()``, OZ
# Governor's ``clock()`` — and the same shape through a time oracle both published
# PROVEN indefinite for a freeze that expires. No ``block_context`` operand exists
# anywhere in those trees, so the v30 whole-tree clock walk could not see it either.
# Both preconditions are now whole-tree and ``view_call``/``external_call`` are opaque,
# so a pre-v31 row's ``no_time_reference`` may be a proof its evidence never supported.
# The same (unreleased) version also covers a later clock-spelling split: the clock
# test now counts ``now``/``number`` alongside ``timestamp`` for the demotion, while
# only second-denominated kinds feed the constant harvest — no v31 row was ever
# written, so one version covers one shipped shape.
# Three further predicate-tree shape changes (the ``external_set`` self-gate
# descriptor, ``derived_from`` on view_call/external_call/Unary operands, and the
# entry-parameter-Phi frame purity) are ALSO covered by this same unreleased span:
# they are gated by ANALYSIS_SCHEMA_VERSION 3→4 on the materialization plane, the
# probe-visible ``gate_ref`` derives from leaf authority_role and so cold-misses
# rather than serving stale, and every local cache row predates v21 anyway. Noted
# here per the v10/v20 precedent rather than minting a version nothing can serve.
# v32: the CANDIDATE POPULATION changed. ``selection._has_effect_evidence``
# replaced ``array_length(effect_targets,1) > 0`` with the state-write evidence plane, so the
# stage now probes every row whose state-write evidence is NOT DETERMINED and every
# ABI-mutating entry point whose sinks the IR could not see (+49 of 1,179 on the local
# protocol-1 slice once that plane is written; 0 removed). Two honest halves, kept
# apart: (a) the newly admitted rows have no v31 verdict of their own, so for them the
# bump changes nothing — a cold miss either way; (b) they enter the SAME
# ``behavior_hash`` space as the rows already cached, and their admission ground is a
# class no v31 probe ever ran under (no proven sink at all, or evidence withheld), so a
# v31 row reached under the narrower population would be transferred onto a function
# selected by different rules. Unlike v30/v31 no mechanism was demonstrated by which a
# stored v31 PAYLOAD becomes false — the local plane cannot exhibit a hit at either
# revision (all 150 rows carry ``analysis_schema_version=5``), so the claim is not
# provable here in either direction. The bump is the fail-closed choice on an
# unobservable: re-probing costs fork time, serving a verdict selected under retired
# rules costs a witness.
# v33: the reach-vs-TVL ceiling now bears on the PARTIAL-FLOOR
# branch too. A pre-fix row on that branch published ``observed_reach_priced_usd`` with
# NO ``reach_tvl_check`` at all — an unchecked floor, and the ceiling's three-state
# answer absent rather than ``skipped`` — an evidence field must say which of proven,
# skipped or not-determined it is, never go missing. Two honest halves, per the
# v32 precedent: (a) the mechanism v27 bumped for does not apply here — the reach keys
# ride ``observed_residue`` (state plane, never a cache key), so no v32 row
# holds a ceiling outcome to serve and a HIT publishes no reach keys for this
# deployment at all; (b) v27 nevertheless minted a version when the ceiling was
# introduced on these same keys, and a deployment served from a v32 row sits beside
# rows whose residue was computed under the retired contract. The bump is the
# fail-closed choice on a shape the local plane cannot exhibit either way (no row is
# servable at any revision — all 150 carry ``analysis_schema_version=5``), stated so
# the next reader does not mistake it for a demonstrated stale-serve.
# v34: the pause-window harvest is side- and
# operator-aware. A v33 row could carry a ``duration_bound_seconds`` that is not a
# freeze window at all — a lead time (``block.timestamp + 3600 < pausedUntil`` → 3600),
# a cooldown offset (``block.timestamp > pausedUntil + 300`` → 300), a minimum-elapsed,
# or a block count harvested as seconds off a mixed-clock leaf — and the value rides
# ``details``, the code plane a hit re-publishes to every bytecode twin. The direction
# is MITIGATING (the bound is read as a severity reducer once the fork affirms it), so
# serving the stale number is the one direction this reader may not be wrong in. Same
# span also narrows the source to ``not_determined`` for the ``{latch, constant}``
# absorbed family, whose sign the static plane does not record.
# A later operand settle (``provenance._digest`` now content-derived, so the
# PYTHONHASHSEED-dependent tie-break between competing computed sources is gone)
# DOES move a witness input, and the decision not to bump is recorded here —
# not only at ANALYSIS_SCHEMA_VERSION — because the moved field feeds this cache's
# own probe: ``claims/matchers/_facts.param_constraints`` reads ``derived_from``
# on the winning ``computed`` operand and mints the constraint fragment published
# as ``target_constraint`` (flows) / ``destination_constraint``
# (exec.arbitrary, delegatecall) — the v11 destination witness the probe shapes
# its inner call from. The movement's MAGNITUDE is base-sample-dependent and
# must not be re-cited as a measurement: the pre-fix tie-break varies run-to-run
# even at a fixed PYTHONHASHSEED (allocation history participates), so one
# captured base sample showed 12 verdicts on 6 units moving
# ``constrained``/``hash_commitment``/``derived_from`` -> ``not_determined``
# while another base sample shows 0. What IS a property of the code: every
# possible move retreats FROM a proof state (the settle picks one canonical
# winner and the honest verdict for a coin-flip witness is not_determined).
# No bump, on three measured grounds: (a) every move retreats FROM a proof state
# and no unit in the 88 moves toward a stronger one (the 18 slots that gain a
# parameter origin — ``manage(address,bytes,uint256)`` param 0 on cids
# 22/47/76/80-84/94/95 — produce zero verdict change); (b) the pre-fix
# ``constrained`` was sample-luck, not evidence (four distinct base digests
# observed for the deciding slot across runs), so a cached row would hold a
# coin-flip the settle merely stops re-rolling; (c) nothing persisted serves the
# fragment — 0 local effective_functions.claims rows carry a constraint verdict,
# and the settle leaves every effects artifact byte-identical (the measured effects
# diffs attribute to the ``abi_selector`` addition on callee records and the cid-561
# identity-hash sink-order noise documented at v10).
EFFECT_CACHE_SCHEMA_VERSION = 34

# ``contract_surface_hash`` sentinel for kernel rows. A sentinel rather than
# NULL keeps the identity UniqueConstraint portable (no NULLS-NOT-DISTINCT dep) —
# matches the model's ``server_default=""``.
KERNEL_SURFACE_SENTINEL = ""

# Self-audit outcomes stamped on a kernel row.
AUDIT_PASSED = "passed"
AUDIT_FAILED = "failed"

# ``observed_residue`` keys that are BOOKKEEPING about probing, not observations
# of the contract. Everything else in the bag describes what a verdict saw, so a
# verdict flip correctly drops it; these describe how many times this deployment
# has already been re-probed, which is just as true after the flip. Losing them
# resets a cap that exists to stop an unreproducible behavior from re-probing on
# every job forever, so they survive the flip that clears the observations.
RESIDUE_BOOKKEEPING_KEYS = ("destination_probe_attempts",)

# ---------------------------------------------------------------------------
# Replay identity: what a re-run is allowed to change
# ---------------------------------------------------------------------------
# THE VIOLATION, stated rather than hidden. Recomputation over an unchanged chain is
# supposed to be byte-identical, and re-analysis without an on-chain change is supposed
# to be a no-op — and this cache MUTATES ON READ: ``bump_hit`` and ``mark_audited``
# are called from the read path
# (``workers/effects_worker.py`` — the plain-hit, audit and floor branches), so two
# identical pipeline runs over an unchanged chain leave the DB in DIFFERENT states.
# The determinism harness (``scripts/determinism_gate.sh``) closes the float
# and string-hash classes and cannot see this one: it pins the PROCESS, and this is a
# difference in what the process WROTE.
#
# DECISION: the mutation is ACCEPTED and the columns it touches are declared
# non-identity here, in the module that owns the schema, instead of being split into a
# side table. Reasons, so a later reader can reverse it knowingly:
#   * every one of these columns is bookkeeping ABOUT PROBING — how many times this row
#     was served, whether a peer corroborated it, when — and none is an observation of a
#     contract. Nothing published to a user, a claim or a score reads any of them.
#   * ``audit_status`` is deliberately durable: it exists so a caught collision is not
#     re-tested (and not re-trusted) forever. Moving it to a stats table would either
#     lose that or duplicate the identity key to carry it.
#   * a stats table would add a write to the hot read path for a value only operational
#     metrics consume.
# CONSEQUENCE, not to be softened: a replay-identity check over this table must compare
# rows MODULO these columns. A checker that diffs whole rows will report a difference on
# every second run, and it will be right — the invariant as stated is not what the code
# does, and this constant is the exact size of the gap.
#
# ``hit_count`` semantics, since the name invites misreading: it counts times this row was SERVED as
# a trusted hit, so ``0`` means "never served" (134 rows). It cannot mean "looked up and
# missed" — a lookup that misses matches NO row, so the miss is a property of the
# QUERY and is recorded where queries are: ``record_stage_metric("cache_misses", …)``
# per job in the effects worker. The two facts live in two places because they are facts
# about two different things.
REPLAY_IDENTITY_EXCLUDED_COLUMNS = (
    "hit_count",
    "audit_status",
    "audit_peer_hash",
    "audited_at",
    "updated_at",
)

# The same statement for ``effect_verdicts.observed_residue``: these keys are probe
# bookkeeping (how many hit-path re-observations this deployment has spent), and
# ``_mark_residue_gaps`` reads them to decide run N+1's probe set — so run N+1's WORK is
# a function of what run N persisted. Bounded and deliberate (without it an
# unreproducible deployment re-probes forever), and excluded from replay identity for
# the same reason as the columns above: it describes probing, never the chain.
REPLAY_IDENTITY_EXCLUDED_RESIDUE_KEYS = RESIDUE_BOOKKEEPING_KEYS


def _lock_key(behavior_hash: str, effect_class: str, scope: str, surface: str, gate_ref: str) -> str:
    return f"effect:{behavior_hash}:{effect_class}:{scope}:{surface}:{gate_ref}"


def _advisory_lock(session: Session, key: str) -> None:
    """Serialize concurrent writers for one cache identity (mirrors the
    materialization cache's ``pg_advisory_xact_lock``). ``hashtext`` is built into
    Postgres and folds the composite key into the 64-bit lock space."""
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": key})


def find_cached_verdict(
    session: Session,
    *,
    behavior_hash: str,
    effect_class: str,
    scope: str,
    contract_surface_hash: str = KERNEL_SURFACE_SENTINEL,
    gate_ref: str = "",
) -> EffectBehaviorCache | None:
    """Return the current-version cached verdict for this identity, or ``None``.

    A row stamped with a stale ``analysis_schema_version`` reads as a miss so a
    bumped recipe re-simulates rather than transferring a verdict computed under
    different rules — exactly the materialization cache's version gate.
    """
    surface = contract_surface_hash if scope != "kernel" else KERNEL_SURFACE_SENTINEL
    return session.execute(
        select(EffectBehaviorCache).where(
            EffectBehaviorCache.behavior_hash == behavior_hash,
            EffectBehaviorCache.effect_class == effect_class,
            EffectBehaviorCache.scope == scope,
            EffectBehaviorCache.contract_surface_hash == surface,
            EffectBehaviorCache.gate_ref == gate_ref,
            EffectBehaviorCache.analysis_schema_version == EFFECT_CACHE_SCHEMA_VERSION,
        )
    ).scalar_one_or_none()


def find_cached_verdicts_batch(
    session: Session,
    identities: "Any",
) -> dict[tuple[str, str, str, str, str], EffectBehaviorCache]:
    """Bulk form of :func:`find_cached_verdict` for a whole job's plan set.

    ``identities`` is any iterable of
    ``(behavior_hash, effect_class, scope, contract_surface_hash, gate_ref)``
    tuples. Returns a dict keyed by the *normalized* identity (kernel scope maps
    the surface to :data:`KERNEL_SURFACE_SENTINEL`, exactly as the single-row
    form does) whose value is the current-version cached row, if any.

    Semantics match the single-row lookup precisely: the same 5-field identity,
    the same ``analysis_schema_version`` gate (a stale-version row is a miss),
    the same kernel surface-sentinel normalization. The identity UniqueConstraint
    plus the version filter guarantee at most one row per key — so this returns
    the same row the per-plan ``SELECT`` would, in ONE composite ``IN`` query
    instead of N.
    """
    keys: set[tuple[str, str, str, str, str]] = set()
    for behavior_hash, effect_class, scope, surface, gate_ref in identities:
        surf = surface if scope != "kernel" else KERNEL_SURFACE_SENTINEL
        keys.add((behavior_hash, effect_class, scope, surf, gate_ref))
    if not keys:
        return {}
    rows = (
        session.execute(
            select(EffectBehaviorCache).where(
                tuple_(
                    EffectBehaviorCache.behavior_hash,
                    EffectBehaviorCache.effect_class,
                    EffectBehaviorCache.scope,
                    EffectBehaviorCache.contract_surface_hash,
                    EffectBehaviorCache.gate_ref,
                ).in_(list(keys)),
                EffectBehaviorCache.analysis_schema_version == EFFECT_CACHE_SCHEMA_VERSION,
            )
        )
        .scalars()
        .all()
    )
    return {(r.behavior_hash, r.effect_class, r.scope, r.contract_surface_hash, r.gate_ref): r for r in rows}


def find_verdict_residue_batch(
    session: Session,
    *,
    chain_id: int,
    identities: "Any",
) -> dict[tuple[str, str, str], tuple[str | None, bool | None, dict[str, Any] | None]]:
    """State-plane residue already persisted for a set of deployment identities.

    ``identities`` is any iterable of ``(contract_address, selector,
    effect_class)``. Returns ``{identity: (concrete_destination,
    current_check_passed, observed_residue)}`` for the rows that exist — a key
    absent from the result has no verdict row at all, which is also "no residue".

    Read-only and batched (one composite ``IN``) because the caller asks it once
    per job about every cache HIT: a hit carries no state-plane observation of
    its own, so this is how the worker learns whether THIS deployment
    ever got one, without a round-trip per plan.
    """
    keys: set[tuple[str, str, str]] = set()
    for address, selector, effect_class in identities:
        keys.add((address.lower(), selector or "", effect_class))
    if not keys:
        return {}
    rows = session.execute(
        select(
            EffectVerdict.contract_address,
            EffectVerdict.selector,
            EffectVerdict.effect_class,
            EffectVerdict.concrete_destination,
            EffectVerdict.current_check_passed,
            EffectVerdict.observed_residue,
        ).where(
            EffectVerdict.chain_id == chain_id,
            tuple_(
                EffectVerdict.contract_address,
                EffectVerdict.selector,
                EffectVerdict.effect_class,
            ).in_(list(keys)),
        )
    ).all()
    return {(r[0], r[1], r[2]): (r[3], r[4], r[5]) for r in rows}


def upsert_cached_verdict(
    session: Session,
    *,
    behavior_hash: str,
    effect_class: str,
    scope: str,
    verdict: str,
    tier: str,
    contract_surface_hash: str = KERNEL_SURFACE_SENTINEL,
    gate_ref: str = "",
    transcript_ptr: str | None = None,
    details: dict[str, Any] | None = None,
    audit_status: str | None = None,
    audit_peer_hash: str | None = None,
) -> EffectBehaviorCache:
    """Write (or refresh) a code-plane verdict row under an advisory lock.

    The row is code-plane ONLY: no concrete values enter ``details``.
    Verdicts are gate-relative: ``gate_ref`` names the gate structure,
    never an address. A concurrent sibling writing the same identity coalesces on
    the unique constraint rather than duplicating.
    """
    surface = contract_surface_hash if scope != "kernel" else KERNEL_SURFACE_SENTINEL
    _advisory_lock(session, _lock_key(behavior_hash, effect_class, scope, surface, gate_ref))
    now = datetime.now(timezone.utc)
    # Enforced at the WRITE, not by convention at the call sites: this row is served to
    # every other deployment sharing the bytecode, so a per-deployment observation may
    # not enter it (:data:`DEPLOYMENT_PLANE_KEYS`).
    details = code_plane_details(details)
    stmt = pg_insert(EffectBehaviorCache).values(
        behavior_hash=behavior_hash,
        effect_class=effect_class,
        scope=scope,
        contract_surface_hash=surface,
        gate_ref=gate_ref,
        verdict=verdict,
        tier=tier,
        transcript_ptr=transcript_ptr,
        details=details,
        analysis_schema_version=EFFECT_CACHE_SCHEMA_VERSION,
        audit_status=audit_status,
        audit_peer_hash=audit_peer_hash,
        audited_at=now if audit_status is not None else None,
        updated_at=now,
    )
    # No residue guard is needed here (unlike ``record_effect_verdict``): this row
    # is code-plane only, and the worker writes it exclusively on a cache MISS —
    # every rewrite IS a fresh simulation, so each field must take the new value.
    set_ = {
        "verdict": stmt.excluded.verdict,
        "tier": stmt.excluded.tier,
        "transcript_ptr": stmt.excluded.transcript_ptr,
        "details": stmt.excluded.details,
        "analysis_schema_version": stmt.excluded.analysis_schema_version,
        "updated_at": stmt.excluded.updated_at,
    }
    # Only advance audit bookkeeping when this write carries an audit result;
    # a plain refresh must not wipe a prior passed/failed audit.
    if audit_status is not None:
        set_["audit_status"] = stmt.excluded.audit_status
        set_["audit_peer_hash"] = stmt.excluded.audit_peer_hash
        set_["audited_at"] = stmt.excluded.audited_at
    stmt = stmt.on_conflict_do_update(constraint="uq_effect_behavior_cache_identity", set_=set_)
    session.execute(stmt)
    session.flush()
    row = find_cached_verdict(
        session,
        behavior_hash=behavior_hash,
        effect_class=effect_class,
        scope=scope,
        contract_surface_hash=surface,
        gate_ref=gate_ref,
    )
    assert row is not None  # just written under the lock
    return row


def mark_audited(session: Session, row: EffectBehaviorCache, *, passed: bool, peer_hash: str) -> None:
    """Stamp the self-audit result on a kernel row. ``peer_hash`` records the
    surface whose re-simulation was compared, so a later reader can see which
    pair was cross-checked."""
    row.audit_status = AUDIT_PASSED if passed else AUDIT_FAILED
    row.audit_peer_hash = peer_hash
    row.audited_at = datetime.now(timezone.utc)
    session.flush()


def bump_hit(session: Session, row: EffectBehaviorCache) -> None:
    """Count a trusted cache hit (supports the optional every-Nth re-audit)."""
    row.hit_count = (row.hit_count or 0) + 1
    session.flush()


# ---------------------------------------------------------------------------
# Self-audit — kernel-verdict agreement
# ---------------------------------------------------------------------------

# The code-plane structural fields that DEFINE a kernel verdict. Two functions
# sharing a behavioral hash must agree on these; a disagreement means the hash
# collided two distinct behaviors (a hashing bug) and the cache must NOT be
# trusted. Concrete/state-plane keys (destination, impl) are deliberately absent —
# they are per-deployment and are EXPECTED to differ.
#
# ``reason`` also rides ``details`` (``ObservedEffect.witness_payload``) and is
# deliberately NOT here: it is a strictly finer partition of the same verdict, and
# an unknown's reason can legitimately differ between two sightings of one
# behavior (a precondition revert here, a clean non-observation there) without any
# hash having collided. Comparing it would stamp AUDIT_FAILED — which poisons the
# key permanently — on a transient disagreement. An allowlist, not a diff, is also
# why a new witness key never needs a schema-version bump.
_KERNEL_SIGNATURE_KEYS = (
    "latch_flip",
    "gate_mutation",
    "upgradeable",
    "supply_delta_sign",
    "destination_shape",
)

# State-plane keys that must NEVER be stored on a code-plane cache row.
# Every one is an observation of ONE deployment's fork state, and the cache re-publishes
# whatever it stores to every OTHER deployment sharing the bytecode — so a hit used to
# hand deployment B deployment A's blast radius, A's pre-pause succeeding set and A's
# seeding qualifiers as B's own witness. Measured before this split: 74 of 150 cache
# rows carried at least one of these (29 freeze_pause, 21 supply, 20 value_out, 4).
#
# Stripped on WRITE, so a hit cannot serve them and they are ABSENT on the hit
# deployment's witness — absent, not ``null`` and not ``false`` (R1). The producing
# deployment keeps the full payload on its own ``effect_verdicts.witness`` row, which is
# where per-deployment observations belong. Consumers already have to treat absence as
# "unproven lower bound" (``claims_bridge._observed_summary`` states it for
# ``observed_blast_radius`` verbatim); the difference is that the absence is now HONEST
# rather than replaced by another contract's number.
DEPLOYMENT_PLANE_KEYS = (
    "observed_blast_radius",
    "pre_pause_succeeding",
    "scored_denominator",
    "input_seeded",
    "contract_balance_seeded",
    "backing",
)


def code_plane_details(details: dict[str, Any] | None) -> dict[str, Any] | None:
    """``details`` with every per-deployment observation removed."""
    if not details:
        return details
    return {k: v for k, v in details.items() if k not in DEPLOYMENT_PLANE_KEYS}


def kernel_signature(verdict: str, details: dict[str, Any] | None) -> tuple[Any, ...]:
    """The comparable kernel identity: the verdict plus its structural witness.
    Order-stable so two calls on equal inputs compare equal."""
    d = details or {}
    return (verdict, *(d.get(k) for k in _KERNEL_SIGNATURE_KEYS))


def kernel_signature_is_comparable(details: dict[str, Any] | None) -> bool:
    """Whether a signature carries ANY structural key — i.e. whether comparing it can
    falsify anything.

    THE FLOOR. 78 of 150 cache rows carry none of
    :data:`_KERNEL_SIGNATURE_KEYS` — all 49 ``authority_change`` rows plus 29
    ``freeze_pause`` rows — so with ``verdict='unknown'`` the signature is
    ``('unknown', None, None, None, None, None)`` on BOTH sides and the
    audit passes unconditionally. That is not an audit; it is the string ``unknown``
    compared with itself, and a hash collision between two different behaviors both
    answering ``unknown`` is exactly what it would have to catch. Two of the five
    allowlisted keys (``gate_mutation``, ``upgradeable``) appear in NO row at all.

    A hit whose signature cannot be compared must not be TRUSTED. The caller re-probes
    and publishes its own fresh result instead of the cached one (see
    ``effects_worker._resolve_item``): the cheap free hit is what is refused, not the
    verdict.
    """
    d = details or {}
    return any(k in d for k in _KERNEL_SIGNATURE_KEYS)


def kernel_verdicts_agree(
    cached_verdict: str,
    cached_details: dict[str, Any] | None,
    fresh_verdict: str,
    fresh_details: dict[str, Any] | None,
) -> bool:
    """Do a cached kernel verdict and a freshly re-simulated one agree?

    The self-audit trusts a free cache hit only when this returns ``True``. A
    ``False`` is a caught hash collision: the caller withholds (writes
    ``unknown`` + files a discrepancy) instead of propagating the cached verdict.

    Agreement is necessary and NOT sufficient: a signature with no structural key
    agrees with itself trivially, so the caller must also check
    :func:`kernel_signature_is_comparable`. Kept as two functions because they answer
    two different questions — "do these disagree" and "could they have".
    """
    return kernel_signature(cached_verdict, cached_details) == kernel_signature(fresh_verdict, fresh_details)


# ---------------------------------------------------------------------------
# effect_verdicts — per-deployment state-plane residue (never the cache)
# ---------------------------------------------------------------------------


def record_effect_verdict(
    session: Session,
    *,
    chain_id: int,
    contract_address: str,
    effect_class: str,
    verdict: str,
    tier: str,
    function_id: int | None = None,
    selector: str | None = None,
    behavior_hash: str | None = None,
    concrete_destination: str | None = None,
    current_check_passed: bool | None = None,
    observed_residue: dict[str, Any] | None = None,
    witness: dict[str, Any] | None = None,
    transcript_ptr: str | None = None,
) -> None:
    """Upsert the per contract-function state-plane residue for one deployment.

    This is where the concrete values live — the exact destination address, the
    exact target impl, the Tier-0 current-state check, and (in
    ``observed_residue``) the value-reach holders/USD — NEVER the
    ``effect_behavior_cache``. Keyed on the deployment coordinates
    ``(chain_id, contract_address, selector, effect_class)``; the empty-string
    ``selector`` sentinel keeps the identity constraint portable for
    fallback/receive functions.
    """
    # A candidate's function row can be replaced (delete+recreate, new id) by a
    # concurrent policy pass between selection and this write. The verdict must
    # still persist — unlinked — rather than FK-violate and roll back the whole
    # job's witnesses.
    if (
        function_id is not None
        and session.execute(select(EffectiveFunction.id).where(EffectiveFunction.id == function_id)).first() is None
    ):
        function_id = None

    def _upsert(fid: int | None):
        stmt = pg_insert(EffectVerdict).values(
            function_id=fid,
            chain_id=chain_id,
            contract_address=contract_address.lower(),
            selector=(selector or ""),
            effect_class=effect_class,
            behavior_hash=behavior_hash,
            verdict=verdict,
            tier=tier,
            concrete_destination=concrete_destination,
            current_check_passed=current_check_passed,
            # Explicit SQL NULL: a JSONB column turns a Python ``None`` into the
            # jsonb scalar ``null``, which is a VALUE — it would defeat both the
            # merge above and the "no residue" reading everywhere downstream.
            observed_residue=observed_residue if observed_residue is not None else null(),
            witness=witness,
            transcript_ptr=transcript_ptr,
        )
        existing = EffectVerdict.__table__.c

        # Did this write resolve the SAME code as the stored row? Residue is
        # per-deployment but code-relative: it describes what THIS bytecode does
        # at this address. Carrying it across a behavior_hash change would let a
        # pre-upgrade destination masquerade as the new implementation's.
        same_code = stmt.excluded.behavior_hash.is_not_distinct_from(existing.behavior_hash)
        # ...and the same ANSWER? Residue is the concrete detail OF a verdict, so
        # it is only still true while that verdict is. A proven value-move
        # rewritten as ``unknown`` keeps neither its witness nor its transcript
        # (below) precisely so a proven witness never sits beside a downgraded
        # verdict; an orphaned ``concrete_destination`` is that same contradiction
        # in another column, and ``find_verdict_residue_batch`` reads it, so the
        # orphan also permanently suppresses re-observation.
        same_verdict = stmt.excluded.verdict.is_not_distinct_from(existing.verdict)
        residue_still_stands = and_(same_code, same_verdict)

        def keep_residue(incoming, stored):
            """State-plane residue: an absent incoming value means *this* write had
            no state-plane observation, NOT that none exists. A cache-HIT resolution
            structurally carries none (the code-plane cache holds no
            concrete values), so an unconditional overwrite would erase the
            first-sighting observation on every subsequent hit — but only while the
            verdict it describes is unchanged."""
            return case((incoming.is_not(None), incoming), (residue_still_stands, stored), else_=None)

        def merge_residue(incoming, stored):
            """``observed_residue`` is a BAG of independent residue facts (value-reach
            reach, re-probe bookkeeping) written by different paths, so absent
            keys must survive an incoming write that carries only some of them —
            a key-wise ``keep_residue``. Same lifecycle: a changed verdict or a
            changed behavior hash drops the whole bag.

            ``_object`` is not defensive padding: a JSONB column renders a Python
            ``None`` as the jsonb scalar ``null`` rather than SQL NULL, and
            ``jsonb_object || jsonb_null`` concatenates into a two-element ARRAY
            instead of merging. Both sides are normalized to an object first.

            The flip branch is NOT a plain overwrite: the observation keys must go
            (they described the old verdict) but :data:`RESIDUE_BOOKKEEPING_KEYS`
            must not, or a verdict that flips hands the re-probe bound a fresh
            budget and an unreproducible deployment re-probes forever."""
            empty = text("'{}'::jsonb")

            def _object(col):
                return func.coalesce(func.nullif(col, text("'null'::jsonb")), empty)

            def _bookkeeping(col):
                """Only the bookkeeping keys of ``col``, as an object."""
                picked = func.jsonb_build_object()
                for key in RESIDUE_BOOKKEEPING_KEYS:
                    value = col.op("->")(key)
                    picked = picked.op("||")(
                        case((value.is_not(None), func.jsonb_build_object(key, value)), else_=empty)
                    )
                return picked

            merged = _object(stored).op("||")(_object(incoming))
            flipped = _bookkeeping(_object(stored)).op("||")(_object(incoming))
            return func.nullif(case((residue_still_stands, merged), else_=flipped), empty)

        return stmt.on_conflict_do_update(
            constraint="uq_effect_verdicts_identity",
            set_={
                # Linkage, not a fact about this resolution: the FK-vanished guard
                # above nulls ``fid`` when the function row was replaced mid-job.
                # The FK is ON DELETE SET NULL, so a stored non-NULL id is always
                # live — keep it rather than orphaning the row from the frontend.
                "function_id": func.coalesce(stmt.excluded.function_id, existing.function_id),
                # Current resolution facts — always the latest, even downgrades.
                "behavior_hash": stmt.excluded.behavior_hash,
                "verdict": stmt.excluded.verdict,
                "tier": stmt.excluded.tier,
                # State-plane residue — preserved across observation-less rewrites.
                "concrete_destination": keep_residue(stmt.excluded.concrete_destination, existing.concrete_destination),
                "current_check_passed": keep_residue(stmt.excluded.current_check_passed, existing.current_check_passed),
                "observed_residue": merge_residue(stmt.excluded.observed_residue, existing.observed_residue),
                # Evidence FOR the verdict above, so it moves with it: preserving a
                # "proven" witness next to a downgraded ``unknown`` verdict would
                # publish a contradiction. Deliberately not residue-preserved.
                "witness": stmt.excluded.witness,
                "transcript_ptr": stmt.excluded.transcript_ptr,
                "updated_at": text("NOW()"),
            },
        )

    try:
        with session.begin_nested():
            session.execute(_upsert(function_id))
    except IntegrityError as exc:
        # The row vanished between the existence check and the insert — the
        # savepoint keeps the job session writable; retry unlinked.
        if "effect_verdicts_function_id_fkey" not in str(exc.orig):
            raise
        with session.begin_nested():
            session.execute(_upsert(None))
    session.flush()
