"""The corpus-run pass condition: what fails a run, and what it always reports."""

from __future__ import annotations

import json

from scripts.logic_run_passes import main

A, B = "0x" + "a" * 40, "0x" + "b" * 40


def _row(**fields):
    return {"contract": "C", "address": "0x" + "c" * 40, "function": "f()", **fields}


def _run(tmp_path, old, new, *flags, capsys=None):
    (tmp_path / "corpus_x_old_s1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in old))
    (tmp_path / "corpus_x_new_s1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in new))
    code = main(
        ["--old", str(tmp_path / "corpus_x_old_s1.jsonl"), "--new", str(tmp_path / "corpus_x_new_s1.jsonl"), *flags]
    )
    return code, capsys.readouterr().out if capsys else ""


def test_a_row_turning_self_scoped_doesnt_hide_lost_holders(tmp_path, capsys):
    old = [_row(lego="restricted", lego_principals=[A], checks={A: True})]
    new = [_row(lego="restricted", lego_principals=[], lego_scope="self")]
    code, out = _run(tmp_path, old, new, capsys=capsys)
    assert code == 1 and "(b) lost 1" in out
    assert "scope None -> self, 1 replay-confirmed" in out


def test_rows_self_scoped_in_both_runs_are_exempt(tmp_path, capsys):
    old = [_row(lego="restricted", lego_principals=[A], checks={A: True}, lego_scope="self")]
    new = [_row(lego="restricted", lego_principals=[], lego_scope="self")]
    assert _run(tmp_path, old, new, capsys=capsys)[0] == 0


def test_failing_reads_may_not_open_an_undetermined_row_or_change_a_complete_list(tmp_path, capsys):
    old = [
        _row(lego="not_determined"),
        _row(function="g()", lego="restricted", lego_complete=True, lego_principals=[A]),
    ]
    new = [_row(lego="open"), _row(function="g()", lego="restricted", lego_complete=True, lego_principals=[B])]
    code, out = _run(tmp_path, old, new, "--faulty", capsys=capsys)
    assert code == 1 and "not_determined -> open" in out and "a complete list changed" in out


def test_a_row_missing_from_the_new_run_fails_unless_it_is_a_subset_run(tmp_path, capsys):
    old = [_row(lego="restricted"), _row(function="g()", lego="restricted")]
    new = [_row(lego="restricted")]
    code, out = _run(tmp_path, old, new, capsys=capsys)
    assert code == 1 and "(m) missing" in out
    assert _run(tmp_path, old, new, "--only-new", capsys=capsys)[0] == 0
