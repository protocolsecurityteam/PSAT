"""The disposition determination: what delivery shape may and may not decide.

A reading is DISPOSED where every incoming delivery of that token to every
account contributing to it arrived in a transaction distributing the same token
to at least K recipients, and where the token is absent from the protocol's own
discovered address universe. The published state is a claim about DELIVERY SHAPE
and never about worth — two real tokens were measured into it on the reference
corpus — so every test here is about what the claim covers and what it must
refuse.

The corpus cannot exercise any of it: nothing has yet measured a delivery, so
the evidence table is empty and the plane disposes nothing. Every state below is
therefore built by hand, which is also what keeps these tests about the rule
rather than about one protocol's data.
"""

from __future__ import annotations

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P

KEY = "ethereum::0x" + "a" * 40
JUNK = "0x" + "1" * 40
REAL = "0x" + "2" * 40

# The carrier record the plane copies off a delivery-evidence row. Every field a
# published claim about a disposition quotes comes from here.
DELIVERED = {
    "shape": "fan_out_all",
    "fan_out_threshold_k": 25,
    "min_fan_out": 199,
    "delivery_count": 1,
    "scanned_from_block": 0,
    "measured_through_block": 21_000_000,
    "accounts": ["0x" + "a" * 40],
    "basis": ["delivery receipts read over blocks 0-21000000; every delivery fanned out to >= 25 recipients"],
}

SCANNED = {
    "source": "chain_log_sweep",
    "accounts_scanned": 1,
    "accounts_folded": 1,
    "accounts": ["0x" + "a" * 40],
    "swept_from_block": 0,
    "swept_through_block": 21_000_000,
    "basis": ["chain scan of blocks 0-21000000 over Transfer/TransferSingle/TransferBatch"],
}


def _plane(**kwargs) -> P.ValuePlane:
    plane = P.ValuePlane()
    for name, value in kwargs.items():
        setattr(plane, name, value)
    plane.contract_entities = set(plane.per_asset) | set(plane.per_asset_state)
    return plane


def _disposed_sheet(**kwargs) -> P.ValuePlane:
    """The smallest sheet whose whole content is disposed."""
    return _plane(
        per_asset_state={KEY: {JUNK: P.ASSET_AIRDROP_DELIVERED}},
        asset_disposition={KEY: {JUNK: dict(DELIVERED)}},
        **kwargs,
    )


# --- what the state is, and what it is NOT -----------------------------------


def test_a_disposed_sheet_and_a_proven_empty_one_never_collapse():
    """Two witnesses, two states, and neither may be published under the other's
    name. Proven-empty says nothing ever arrived — every quantity witnessed zero
    over a list proven whole. Airdrop-determined says what DID arrive arrived as
    a mass distribution. A reader acting on the first would conclude the accounts
    are bare, which the second does not say."""
    disposed = _disposed_sheet()
    empty = _plane(
        per_asset_state={KEY: {JUNK: P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY: SCANNED},
    )

    assert disposed.sheet_state(KEY) == P.SHEET_AIRDROP_DETERMINED
    assert empty.sheet_state(KEY) == P.SHEET_PROVEN_EMPTY
    assert P.SHEET_AIRDROP_DETERMINED != P.SHEET_PROVEN_EMPTY
    assert P.CEILING_AIRDROP_DETERMINED != P.CEILING_PROVEN_EMPTY
    # Both admit a $0 ceiling, and the reason tokens are what tell them apart.
    assert P.ceiling_for(disposed, KEY) == (0.0, P.CEILING_AIRDROP_DETERMINED)
    assert P.ceiling_for(empty, KEY) == (0.0, P.CEILING_PROVEN_EMPTY)


def test_a_disposed_sheet_admits_a_zero_ceiling_under_its_own_reason():
    """The earned negative: the sheet's determined content is nil, so replacing
    the node's code moves nothing this document can price."""
    plane = _disposed_sheet()
    usd, reason = P.ceiling_for(plane, KEY)
    assert (usd, reason) == (0.0, P.CEILING_AIRDROP_DETERMINED)
    assert reason in P.CEILING_ADMITTING_REASONS
    assert plane.total(KEY) == 0.0


def test_the_vocabulary_names_delivery_shape_and_never_worth():
    """The naming is load-bearing, not cosmetic: uniETH (fan-out 101) and HEX
    (199/399/399) are REAL tokens measured into this state, so any
    spam/scam/worthless naming would publish a claim that is false of them."""
    tokens = (P.ASSET_AIRDROP_DELIVERED, P.SHEET_AIRDROP_DETERMINED, P.CEILING_AIRDROP_DETERMINED)
    for token in tokens:
        for banned in ("spam", "scam", "worthless", "junk"):
            assert banned not in token


# --- the all-conjunct on the sheet -------------------------------------------


def test_a_sheet_holding_junk_AND_a_real_unpriced_asset_stays_unpriced():
    """The disposition covers the readings it names and nothing else.

    One asset nobody priced is a holding this document cannot value, and a sheet
    carrying one is not determined at any total however much of the rest arrived
    by mass distribution. ``unpriced`` wins over ``airdrop_determined``, and that
    ordering is the whole guard."""
    plane = _plane(
        per_asset_state={KEY: {JUNK: P.ASSET_AIRDROP_DELIVERED, REAL: P.ASSET_UNPRICED}},
        asset_disposition={KEY: {JUNK: dict(DELIVERED)}},
    )
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert plane.total(KEY) is None
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_UNPRICED)


def test_a_priced_reading_beside_a_disposed_one_still_prices_the_sheet():
    """``priced`` wins over everything: a determined non-zero reading is a floor
    over what the entity holds, and a disposition beside it removes nothing."""
    plane = _plane(
        per_asset={KEY: {REAL: 5_000.0}},
        per_asset_state={KEY: {REAL: P.ASSET_PRICED, JUNK: P.ASSET_AIRDROP_DELIVERED}},
        asset_disposition={KEY: {JUNK: dict(DELIVERED)}},
    )
    assert plane.sheet_state(KEY) == P.SHEET_PRICED
    assert plane.total(KEY) == 5_000.0


def test_a_disposed_reading_beside_a_witnessed_zero_still_determines():
    """The two determined readings compose: one arrived and contributes nothing
    the document can price, the other never arrived at all."""
    plane = _plane(
        per_asset_state={KEY: {JUNK: P.ASSET_AIRDROP_DELIVERED, REAL: P.ASSET_PROVEN_ZERO}},
        asset_disposition={KEY: {JUNK: dict(DELIVERED)}},
    )
    assert plane.sheet_state(KEY) == P.SHEET_AIRDROP_DETERMINED


# --- the four refusals -------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        (
            {"typed_receipts_unresolved": {KEY: [{"asset": REAL, "quantity_readable": False, "quantity": None}]}},
            P.DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED,
        ),
        ({"asset_set_truncated": {KEY}}, P.DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED),
        ({"asset_set_accounts_unscanned": {KEY: ["0x" + "b" * 40]}}, P.DISPOSITION_REFUSED_UNSCANNED_ACCOUNT),
        (
            {"unpriced_positions": {KEY: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 1.0}]}},
            P.DISPOSITION_REFUSED_UNPRICED_POSITIONS,
        ),
    ],
)
def test_each_conjunct_refuses_the_determination_under_its_own_token(kwargs, expected):
    """Four different facts closed by four different pipelines, so four tokens.

    A refused sheet publishes ``unpriced`` — something WAS observed here and no
    number covers it — and never a $0."""
    plane = _disposed_sheet(**kwargs)
    assert plane.disposition_refusal(KEY) == expected
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED
    assert plane.total(KEY) is None
    assert P.ceiling_for(plane, KEY)[0] is None


def test_a_truncated_sheet_refuses_however_much_of_it_is_disposed():
    """D1 parity, and it is the one completeness conjunct. The stored rows are a
    PREFIX of the holdings, so disposing every one of them says nothing about
    the entries the page never reached."""
    plane = _disposed_sheet(asset_set_truncated={KEY})
    assert plane.disposition_refusal(KEY) == P.DISPOSITION_REFUSED_ASSET_LIST_TRUNCATED
    # ``ceiling_for`` refuses under the truncation before the state is even read,
    # so the two guards agree rather than one relying on the other.
    assert P.ceiling_for(plane, KEY) == (None, P.CEILING_ASSET_LIST_TRUNCATED)


def test_unpriced_restaking_holdings_refuse_the_determination():
    """The cross-plane gate: the restaking plane already publishes quantities at
    this node with no USD column, and a determined sheet beside them would
    contradict a plane already in the same document."""
    plane = _disposed_sheet(unpriced_positions={KEY: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 1e18}]})
    assert plane.disposition_refusal(KEY) == P.DISPOSITION_REFUSED_UNPRICED_POSITIONS
    assert plane.sheet_state(KEY) == P.SHEET_UNPRICED


def test_the_refusal_vocabulary_is_its_own_and_not_proven_emptys():
    """They are asked of different claims, so they are named apart: the empty
    claim needs the asset LIST proven whole, the disposition needs it not
    observably cut off. Folding them would put a gate nobody can pass on this
    corpus in front of the disposition."""
    assert P.DISPOSITION_REFUSALS[0] == P.DISPOSITION_REFUSED_TYPED_RECEIPT_UNRESOLVED
    assert P.EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE not in P.DISPOSITION_REFUSALS
    assert len(set(P.DISPOSITION_REFUSALS)) == 4
    # A sheet with no completeness proof at all is refused an EMPTY claim and
    # still determines a disposition — which is the D1-parity ruling, measured:
    # 10 of the 14 candidate sheets carry asset_set_not_proven_complete.
    plane = _disposed_sheet()
    assert plane.proven_empty_refusal(KEY) == P.EMPTY_REFUSED_ASSET_SET_NOT_PROVEN_COMPLETE
    assert plane.disposition_refusal(KEY) is None


# --- the bar at the trim sites -----------------------------------------------


def test_a_disposed_sheet_holds_a_determined_zero_and_still_trims_nothing():
    """The bar, stated as the difference between two questions.

    ``total`` answers what the entity HOLDS, and a determined $0 is honest
    there. A trim site asks what is there to MOVE, and the disposed assets are
    still held — delivery shape says how they arrived, never what they are worth
    — so bounding a witnessed magnitude at $0 would publish "this call moves
    nothing" on evidence that says no such thing."""
    plane = _disposed_sheet()
    assert plane.total(KEY) == 0.0
    assert plane.trimming_total(KEY) is None
    # And the two accessors agree everywhere else, so the bar is this state and
    # nothing broader.
    priced = _plane(per_asset={KEY: {REAL: 7.0}}, per_asset_state={KEY: {REAL: P.ASSET_PRICED}})
    empty = _plane(
        per_asset_state={KEY: {JUNK: P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY: SCANNED},
    )
    unpriced = _plane(per_asset_state={KEY: {REAL: P.ASSET_UNPRICED}})
    for other in (priced, empty, unpriced):
        assert other.trimming_total(KEY) == other.total(KEY)


def test_neither_trim_site_bounds_a_witness_against_a_disposed_sheet():
    """Both ``min(witness, sheet)`` sites read ``trimming_total``, so a disposed
    sheet cannot trim at either. Asserted on the accessor the sites call rather
    than on a folded document, because the corpus carries no such sheet."""
    plane = _disposed_sheet()
    witness = 164_041.15
    sheet = plane.trimming_total(KEY)
    assert sheet is None
    assert (min(witness, sheet) if sheet is not None else witness) == witness


def test_a_disposed_sheet_does_not_earn_asset_set_coverage_by_itself():
    """§9.3-addendum item 2, closed. A disposition says one asset's contribution
    is nil; it does not say the LIST is whole. So a sheet carrying one clears
    the full-coverage conjunct only where the chain's own transfer history
    proves its list — and a page-capped list can never clear it at all."""
    bare = _disposed_sheet()
    assert FOLD._asset_coverage(bare, KEY)["complete"] is False

    proven = _disposed_sheet(asset_set_proven_complete={KEY: SCANNED})
    assert FOLD._asset_coverage(proven, KEY)["complete"] is True

    capped = _disposed_sheet(asset_set_proven_complete={KEY: SCANNED}, asset_set_truncated={KEY})
    assert FOLD._asset_coverage(capped, KEY)["complete"] is False

    # The disposed assets are PUBLISHED beside the verdict, never suppressed.
    assert FOLD._asset_coverage(bare, KEY)["assets_disposed"] == [JUNK]
    assert FOLD._asset_coverage(bare, KEY)["per_asset"] == [
        {"asset": JUNK, "usd": None, "state": P.ASSET_AIRDROP_DELIVERED}
    ]


# --- the resolver's own conjuncts --------------------------------------------


class _Universe:
    """The shape ``load_protocol_universe`` returns, built by hand."""

    def __init__(self, *addresses: str):
        self.addresses = frozenset(addresses)
        self.sources = {"contracts": len(addresses)}
        self.basis = "hand-built"


class _Fact:
    def __init__(self, holder: str, token: str, shape: str = "fan_out_all"):
        self.chain_id = 1
        self.holder_address = holder
        self.token_address = token
        self.shape = shape
        self.delivery_count = 1
        self.unreadable_deliveries = 0
        self.min_fan_out = 199
        self.fan_out_threshold_k = 25
        self.scanned_from_block = 0
        self.measured_through_block = 21_000_000
        self.basis = "delivery receipts read over blocks 0-21000000"

    @property
    def is_airdrop_only(self) -> bool:
        return self.shape == "fan_out_all"


ACCOUNT_A = "0x" + "a" * 40
ACCOUNT_B = "0x" + "b" * 40


def _resolve(monkeypatch, *, universe, facts, buckets, state=P.ASSET_UNPRICED):
    plane = P.ValuePlane()
    plane.per_asset_state = {KEY: dict.fromkeys({asset for _, asset in buckets}, state)}
    monkeypatch.setattr(
        "services.monitoring.delivery_evidence.load_delivery_evidence",
        lambda session, holders: facts,
    )
    disposition, census = P._resolve_asset_disposition(None, plane, buckets, universe)  # type: ignore[arg-type]
    return disposition, census


def test_no_universe_disposes_nothing(monkeypatch):
    """Fail closed at the top. The predicate condemns what is ABSENT from the
    universe, so an absent universe would condemn everything — and an unset
    argument means the caller could not build one."""
    disposition, _ = _resolve(
        monkeypatch,
        universe=None,
        facts={(1, ACCOUNT_A, JUNK): _Fact(ACCOUNT_A, JUNK)},
        buckets={(KEY, JUNK): {("ethereum", ACCOUNT_A)}},
    )
    assert disposition == {}


def test_a_token_the_protocol_refers_to_is_not_disposed_however_it_arrived(monkeypatch):
    """The HEX class, and it is the reason P4 is a conjunct at all.

    HEX is a real token whose deliveries ARE genuine mass distributions
    (199/399/399). Presence in the protocol's discovered universe spares it —
    and on the reference corpus that presence rests on a single effect_verdicts
    row, which is why the anti-monotone ruling is registered on the model."""
    disposition, _ = _resolve(
        monkeypatch,
        universe=_Universe(REAL),
        facts={(1, ACCOUNT_A, REAL): _Fact(ACCOUNT_A, REAL)},
        buckets={(KEY, REAL): {("ethereum", ACCOUNT_A)}},
    )
    assert disposition == {}


def test_an_undetermined_delivery_shape_does_not_dispose(monkeypatch):
    """The all-quantifier's third state. An unread receipt is not a small
    fan-out and it is not a large one, and "nothing contradicted it" is not a
    witness."""
    disposition, _ = _resolve(
        monkeypatch,
        universe=_Universe(),
        facts={(1, ACCOUNT_A, JUNK): _Fact(ACCOUNT_A, JUNK, shape="not_determined")},
        buckets={(KEY, JUNK): {("ethereum", ACCOUNT_A)}},
    )
    assert disposition == {}


def test_a_settled_direct_delivery_does_not_dispose(monkeypatch):
    """The earned negative on the other side: one delivery below K settles the
    pair, and it is published as its own shape rather than folded into the gap
    state."""
    disposition, _ = _resolve(
        monkeypatch,
        universe=_Universe(),
        facts={(1, ACCOUNT_A, JUNK): _Fact(ACCOUNT_A, JUNK, shape="has_direct_delivery")},
        buckets={(KEY, JUNK): {("ethereum", ACCOUNT_A)}},
    )
    assert disposition == {}


def test_a_missing_fact_for_one_of_two_contributing_accounts_refuses(monkeypatch):
    """The entity's holding is the SUM over its accounts, so evidence at one
    account answers nothing about the other's. A folded sheet whose second
    account nobody measured is not determined."""
    both = {(KEY, JUNK): {("ethereum", ACCOUNT_A), ("ethereum", ACCOUNT_B)}}
    facts = {(1, ACCOUNT_A, JUNK): _Fact(ACCOUNT_A, JUNK)}
    disposition, _ = _resolve(monkeypatch, universe=_Universe(), facts=facts, buckets=both)
    assert disposition == {}

    # With BOTH accounts measured it determines, and the record carries the
    # weakest end of the two scans rather than the strongest.
    facts[(1, ACCOUNT_B, JUNK)] = _Fact(ACCOUNT_B, JUNK)
    facts[(1, ACCOUNT_B, JUNK)].measured_through_block = 20_000_000
    disposition, _ = _resolve(monkeypatch, universe=_Universe(), facts=facts, buckets=both)
    assert disposition[KEY][JUNK]["accounts"] == [ACCOUNT_A, ACCOUNT_B]
    assert disposition[KEY][JUNK]["measured_through_block"] == 20_000_000
    assert disposition[KEY][JUNK]["delivery_count"] == 2


def test_a_priced_reading_is_never_disposed(monkeypatch):
    """Disposition is pricing-agnostic in one direction only: dust airdrops in
    ``priced_below_resolution`` are annotated, but a reading with a determined
    dollar figure is never deleted from the document on evidence about how the
    token arrived."""
    for state in (P.ASSET_UNPRICED, P.ASSET_BELOW_RESOLUTION):
        disposition, _ = _resolve(
            monkeypatch,
            universe=_Universe(),
            facts={(1, ACCOUNT_A, JUNK): _Fact(ACCOUNT_A, JUNK)},
            buckets={(KEY, JUNK): {("ethereum", ACCOUNT_A)}},
            state=state,
        )
        assert disposition[KEY][JUNK]["shape"] == "fan_out_all"

    disposition, _ = _resolve(
        monkeypatch,
        universe=_Universe(),
        facts={(1, ACCOUNT_A, JUNK): _Fact(ACCOUNT_A, JUNK)},
        buckets={(KEY, JUNK): {("ethereum", ACCOUNT_A)}},
        state=P.ASSET_PRICED,
    )
    assert disposition == {}


def test_the_native_asset_is_never_disposed(monkeypatch):
    """Native ETH emits no Transfer log, so it has no delivery shape to read and
    there is no evidence a disposition could rest on."""
    disposition, _ = _resolve(
        monkeypatch,
        universe=_Universe(),
        facts={(1, ACCOUNT_A, P.NATIVE_ASSET): _Fact(ACCOUNT_A, P.NATIVE_ASSET)},
        buckets={(KEY, P.NATIVE_ASSET): {("ethereum", ACCOUNT_A)}},
    )
    assert disposition == {}


def test_an_unknown_chain_name_refuses_rather_than_guessing_one(monkeypatch):
    """The evidence table is keyed by chain id and the plane carries names. A
    name nothing maps to has no row to ask for, and a guessed id would ask a
    different chain's question."""
    disposition, _ = _resolve(
        monkeypatch,
        universe=_Universe(),
        facts={(1, ACCOUNT_A, JUNK): _Fact(ACCOUNT_A, JUNK)},
        buckets={(KEY, JUNK): {("no-such-chain", ACCOUNT_A)}},
    )
    assert disposition == {}


def test_an_account_with_no_recorded_identity_refuses(monkeypatch):
    """A reading whose observed account is missing cannot have its deliveries
    quantified over: there is no address to have measured."""
    disposition, _ = _resolve(
        monkeypatch,
        universe=_Universe(),
        facts={(1, ACCOUNT_A, JUNK): _Fact(ACCOUNT_A, JUNK)},
        buckets={(KEY, JUNK): {("ethereum", "")}},
    )
    assert disposition == {}
