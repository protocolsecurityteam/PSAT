"""A diff's movement claims must rest on rows proven to be the same row.

It once read subsumed rows only at the top level (CLI documents keep them under ``provenance``) and fuzzy-matched on
addresses even when identities matched. A document diffed against itself moves nothing.
"""

from __future__ import annotations

import copy
import itertools
import json
from datetime import datetime, timezone
from typing import Any

from services.scoring.cli import differential, document_json
from services.scoring.schema import ScoreDocument


def _row(unit: str, capability: str, access_path: str, **overrides: Any) -> dict[str, Any]:
    address = unit.split("::", 1)[-1]
    row = {
        "principal_unit": unit,
        "capability": capability,
        "access_path": access_path,
        "principal": f"Safe 2/3 {address}",
        "unit_members": [address],
        "principal_addresses": [address],
        "raw_points": 12.15,
        "weakness": 0.35,
        "severity_proven": 0.9,
        "severity_basis": ["caller_arbitrary_proven"],
        "value_band": ">= $100k-$1M",
        "value_at_stake_basis": "proven floor over 5 entity(ies)",
        "witness_notes": [],
    }
    row.update(overrides)
    return row


def _document(findings: list[dict[str, Any]], subsumed: list[dict[str, Any]]) -> ScoreDocument:
    return ScoreDocument(
        protocol_id=1,
        model_version="1.1.0-provisional",
        computed_at=datetime(2026, 8, 6, tzinfo=timezone.utc),
        trigger="manual",
        perimeter_state="settled",
        grade_state="computed",
        grade_lambda=62.3179,
        grade_exposure=19_438_110.14,
        confidence_pct=18.6,
        findings=findings,
        earned_negatives=[],
        warnings=[],
        model_parameters={},
        provenance={"subsumed_rows": subsumed},
    )


def _corpus() -> ScoreDocument:
    return _document(
        [
            _row("ethereum::0xf8553c85", "authority.replace", "direct"),
            _row("ethereum::0xcea8039", "authority.replace", "direct", raw_points=44.5, weakness=0.5),
            _row("base::0x183fe888", "flow.out", "direct", raw_points=0.315, severity_proven=0.1),
        ],
        [
            _row("ethereum::0xf8553c85", "authority.replace", "via_timelock_5d", raw_points=7.03, weakness=0.1674),
            _row("ethereum::0xcea8039", "flow.out", "direct", raw_points=1.59, severity_proven=0.1),
        ],
    )


def test_self_differential_of_a_written_document_moves_nothing():
    """The oracle is the CLI's shape, which the top-level-only read missed."""
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))

    assert "subsumed_rows" not in oracle, "document_json nests subsumed rows under provenance"
    assert len(oracle["provenance"]["subsumed_rows"]) == 2

    result = differential(document, oracle)

    assert result["oracle_subsumed_rows_source"] == "provenance"
    assert result["counts"]["rows"] == {"oracle": 5, "scorer": 5}
    assert result["counts"]["added"] == 0
    assert result["counts"]["changed"] == 0
    assert result["counts"]["removed"] == 0
    assert result["counts"]["split_by_access_path"] == 0
    assert result["added"] == []
    assert result["changed"] == []
    assert result["removed"] == []
    assert result["split_by_access_path"] == []


def test_self_differential_of_a_top_level_oracle_moves_nothing():
    document = _corpus()
    payload = copy.deepcopy(document_json(document))
    oracle = {k: v for k, v in payload.items() if k != "provenance"}
    oracle["subsumed_rows"] = payload["provenance"]["subsumed_rows"]

    result = differential(document, oracle)

    assert result["oracle_subsumed_rows_source"] == "top_level"
    assert result["counts"]["rows"] == {"oracle": 5, "scorer": 5}
    assert (
        result["counts"]["added"],
        result["counts"]["changed"],
        result["counts"]["removed"],
        result["counts"]["split_by_access_path"],
    ) == (0, 0, 0, 0)


def test_an_oracle_with_no_subsumed_rows_anywhere_is_its_own_state():
    document = _corpus()
    payload = copy.deepcopy(document_json(document))
    oracle = {k: v for k, v in payload.items() if k != "provenance"}

    result = differential(document, oracle)

    assert result["oracle_subsumed_rows_source"] == "absent"
    assert result["counts"]["rows"] == {"oracle": 3, "scorer": 5}
    assert result["counts"]["added"] == 2

    empty = dict(oracle, subsumed_rows=[])
    assert differential(document, empty)["oracle_subsumed_rows_source"] == "top_level"
    assert differential(document, empty)["oracle_subsumed_rows_ignored_under_provenance"] is None


def test_an_oracle_carrying_both_shapes_counts_the_population_it_did_not_read():
    """Top level wins, but the losing rows are counted or they come back as ``added``."""
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    oracle["subsumed_rows"] = [oracle["provenance"]["subsumed_rows"][0]]

    result = differential(document, oracle)

    assert result["oracle_subsumed_rows_source"] == "top_level_over_provenance"
    assert result["oracle_subsumed_rows_ignored_under_provenance"] == 2
    assert result["counts"]["rows"] == {"oracle": 4, "scorer": 5}
    assert result["counts"]["added"] == 1


def test_identity_match_beats_the_address_set_and_reports_the_real_movement():
    document = _corpus()
    payload = copy.deepcopy(document_json(document))
    oracle = payload
    for row in oracle["provenance"]["subsumed_rows"]:
        if row["access_path"] == "via_timelock_5d":
            row["raw_points"] = 3.5
            row["weakness"] = 0.1674
            row["value_band"] = ">= $10k-$100k"

    result = differential(document, oracle)

    assert result["counts"]["added"] == 0
    assert result["counts"]["removed"] == 0
    assert result["counts"]["split_by_access_path"] == 0
    assert result["counts"]["changed"] == 1
    (moved,) = result["changed"]
    assert moved["raw_before"] == 3.5
    assert moved["raw_after"] == 7.03
    assert moved["matched_by"] == "row_identity"
    # Published so rows differing only by chain or access path stay distinguishable.
    assert (moved["principal_unit"], moved["capability"], moved["access_path"]) == (
        "ethereum::0xf8553c85",
        "authority.replace",
        "via_timelock_5d",
    )
    assert moved["caused_by"] == ["value_band >= $10k-$100k -> >= $100k-$1M (proven floor over 5 entity(ies))"]


def test_a_new_access_path_is_added_not_a_split_when_the_old_row_still_exists():
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    oracle["provenance"]["subsumed_rows"] = [
        row for row in oracle["provenance"]["subsumed_rows"] if row["access_path"] != "via_timelock_5d"
    ]

    result = differential(document, oracle)

    assert result["counts"]["split_by_access_path"] == 0
    assert result["counts"]["changed"] == 0
    assert result["counts"]["added"] == 1
    assert result["added"][0]["access_path"] == "via_timelock_5d"


def test_a_rekeyed_unit_still_splits_and_names_the_row_its_causes_came_from():
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    oracle["findings"] = [
        _row(
            "ethereum::0x2aca7102",  # the prototype named the merged unit by another member
            "authority.replace",
            "the_prototype_had_one_path",
            unit_members=["0x2aca7102", "0xf8553c85"],
            principal_addresses=["0x2aca7102", "0xf8553c85"],
        )
    ]
    oracle["provenance"]["subsumed_rows"] = []

    result = differential(document, oracle)

    assert result["counts"]["split_by_access_path"] == 1
    (split,) = result["split_by_access_path"]
    assert {r["access_path"] for r in split["rows_after"]} == {"direct", "via_timelock_5d"}
    assert split["cause_computed_against"]["chosen_by"] == "highest raw_points"
    assert split["cause_computed_against"]["access_path"] == "direct"
    assert split["arithmetic_changed"] is False


def test_a_split_prefers_the_identity_twin_for_its_causes():
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    # A degenerate oracle with a duplicated identity leaves the twin among the address-set candidates.
    twin = _row("ethereum::0xf8553c85", "authority.replace", "direct", raw_points=99.0)
    oracle["findings"] = [
        _row("ethereum::0xf8553c85", "authority.replace", "direct"),
        twin,
    ]
    oracle["provenance"]["subsumed_rows"] = []

    result = differential(document, oracle)

    assert result["counts"]["split_by_access_path"] == 1
    (split,) = result["split_by_access_path"]
    assert split["cause_computed_against"]["chosen_by"] == "row identity"
    assert split["cause_computed_against"]["access_path"] == "direct"
    assert split["caused_by"] == ["raw_points 99.0 -> 12.15"]


def test_a_claimed_row_is_not_offered_as_another_rows_recovery_single_candidate():
    """Lending a matched row to another old row fabricates a movement and hides a real disappearance."""
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    oracle["findings"].append(
        _row(
            "ethereum::0xdead2222",
            "flow.out",
            "direct",
            raw_points=99.0,
            unit_members=["0xdead2222", "0x183fe888"],
            principal_addresses=["0xdead2222", "0x183fe888"],
        )
    )

    result = differential(document, oracle)

    assert result["counts"]["changed"] == 0
    assert result["counts"]["split_by_access_path"] == 0
    assert result["counts"]["added"] == 0
    assert result["counts"]["removed"] == 1
    (gone,) = result["removed"]
    assert gone["raw_before"] == 99.0
    assert gone["access_path"] == "direct"


def test_a_claimed_row_is_not_offered_as_another_rows_recovery_split():
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    oracle["findings"].append(
        _row(
            "ethereum::0xdead1111",
            "authority.replace",
            "direct",
            raw_points=99.0,
            unit_members=["0xdead1111", "0xf8553c85"],
            principal_addresses=["0xdead1111", "0xf8553c85"],
        )
    )

    result = differential(document, oracle)

    assert result["counts"]["split_by_access_path"] == 0
    assert result["counts"]["changed"] == 0
    assert result["counts"]["added"] == 0
    assert result["counts"]["removed"] == 1
    assert result["removed"][0]["principal"].endswith("0xdead1111")


def test_a_fuzzy_changed_row_says_when_identity_decided_the_comparison():
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    oracle["findings"] = [
        _row("base::0x183fe888", "flow.out", "direct", raw_points=0.315, severity_proven=0.1),
        _row("base::0x183fe888", "flow.out", "direct", raw_points=0.5, severity_proven=0.1),
    ]
    oracle["provenance"]["subsumed_rows"] = []

    result = differential(document, oracle)

    assert result["counts"]["split_by_access_path"] == 0
    assert result["counts"]["changed"] == 1
    (moved,) = result["changed"]
    assert moved["matched_by"] == "row_identity"
    assert moved["access_path"] == "direct"
    assert moved["caused_by"] == ["raw_points 0.5 -> 0.315"]


def test_the_identity_pass_runs_before_any_address_match_whatever_the_row_order():
    """Identity is settled over the whole document before any address-set candidate is offered."""
    document = _corpus()
    payload = copy.deepcopy(document_json(document))
    rekeyed = _row(
        "ethereum::0x2aca7102",
        "authority.replace",
        "the_prototype_had_one_path",
        unit_members=["0x2aca7102", "0xf8553c85"],
        principal_addresses=["0x2aca7102", "0xf8553c85"],
    )
    oracle = dict(payload, findings=[rekeyed] + list(payload["findings"]))

    result = differential(document, oracle)

    assert result["counts"]["split_by_access_path"] == 0
    assert result["counts"]["changed"] == 0
    assert result["counts"]["added"] == 0
    assert result["counts"]["removed"] == 1
    assert result["removed"][0]["access_path"] == "the_prototype_had_one_path"


def _signature(result: dict[str, Any]) -> str:
    return json.dumps(
        {
            "counts": result["counts"],
            "source": result["oracle_subsumed_rows_source"],
            **{k: sorted(json.dumps(e, sort_keys=True) for e in result[k]) for k in ("added", "changed", "removed")},
            "split": sorted(json.dumps(e, sort_keys=True) for e in result["split_by_access_path"]),
        },
        sort_keys=True,
    )


def test_the_report_does_not_depend_on_the_order_the_rows_are_listed_in():
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    oracle["findings"][0]["raw_points"] = 6.075
    oracle["provenance"]["subsumed_rows"].pop()
    oracle["findings"].append(
        _row("ethereum::0xdeadbeef", "authority.replace", "direct", unit_members=[], principal_addresses=["0xdeadbeef"])
    )
    baseline = _signature(differential(document, oracle))

    for findings, subsumed, old_findings in itertools.product(
        itertools.permutations(document.findings),
        itertools.permutations(document.provenance["subsumed_rows"]),
        itertools.permutations(oracle["findings"]),
    ):
        shuffled = _document(list(findings), list(subsumed))
        permuted = dict(copy.deepcopy(oracle), findings=list(old_findings))
        assert _signature(differential(shuffled, permuted)) == baseline


def test_a_row_that_really_disappeared_is_still_reported_removed():
    document = _corpus()
    oracle = copy.deepcopy(document_json(document))
    oracle["findings"].append(
        _row(
            "ethereum::0xdeadbeef",
            "authority.replace",
            "direct",
            unit_members=[],
            principal_addresses=["0x" + "b1" * 20],
            principal="EOA 0x" + "b1" * 20,
        )
    )

    result = differential(document, oracle)

    assert result["counts"]["removed"] == 1
    (gone,) = result["removed"]
    assert gone["principal"] == "EOA 0x" + "b1" * 20
    assert (gone["principal_unit"], gone["capability"], gone["access_path"]) == (
        "ethereum::0xdeadbeef",
        "authority.replace",
        "direct",
    )
    assert result["counts"]["added"] == 0
