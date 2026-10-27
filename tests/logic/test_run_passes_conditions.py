"""The corpus-run pass condition on holders listed only on conditions: listed like any other, a move between now and
conditional reported apart from losses, a replay-confirmed holder neither run lists counted lost, a conditional
holder whose call goes through now reported, and a resumed run's re-decided row taking the place of an older
commit's."""

from __future__ import annotations

import json

import pytest

from scripts.logic_run_passes import DuplicateRow, main

A, B = "0x" + "a" * 40, "0x" + "b" * 40


def _row(**fields):
    return {"contract": "C", "address": "0x" + "c" * 40, "function": "f()", **fields}


def _run(tmp_path, old, new, *flags, capsys):
    (tmp_path / "corpus_x_old_s1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in old))
    (tmp_path / "corpus_x_new_s1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in new))
    code = main(
        ["--old", str(tmp_path / "corpus_x_old_s1.jsonl"), "--new", str(tmp_path / "corpus_x_new_s1.jsonl"), *flags]
    )
    return code, capsys.readouterr().out


def test_a_holder_moving_from_now_to_conditional_is_reported_not_lost(tmp_path, capsys):
    old = [_row(lego="restricted", lego_principals=[A], checks={A: True})]
    new = [_row(lego="restricted", lego_principals=[], lego_conditions={hex(int(A, 16)): "business"})]
    code, out = _run(tmp_path, old, new, capsys=capsys)
    assert code == 0, out
    assert "holders moved between now and conditional: 1" in out and "1 now -> conditional" in out
    assert "(b) lost" not in out


def test_a_conditional_holder_whose_call_goes_through_now_is_reported(tmp_path, capsys):
    old = [_row(lego="restricted", lego_principals=[A])]
    new = [_row(lego="restricted", lego_conditions={hex(int(A, 16)): "business"}, checks={A: True})]
    code, out = _run(tmp_path, old, new, capsys=capsys)
    assert code == 0 and "rows listing a conditional holder whose call goes through now: 1" in out


def test_a_replay_confirmed_holder_neither_run_lists_is_a_loss(tmp_path, capsys):
    old = [_row(lego="restricted", lego_principals=[B], checks={A: True, B: True})]
    new = [_row(lego="restricted", lego_principals=[B])]
    code, out = _run(tmp_path, old, new, capsys=capsys)
    assert code == 1 and "(b) missed 1" in out and A in out
    new = [_row(lego="restricted", lego_principals=[B], lego_conditions={hex(int(A, 16)): "business"})]
    assert _run(tmp_path, old, new, capsys=capsys)[0] == 0
    new = [_row(lego="open")]
    assert _run(tmp_path, old, new, capsys=capsys)[0] == 0


def test_a_resumed_run_keeps_the_row_written_last_across_commits(tmp_path, capsys):
    old = [_row(lego="restricted", lego_principals=[A], checks={A: True})]
    stale = _row(lego="restricted", lego_principals=[], lego_commit="aaaa", written=1.0)
    fresh = _row(lego="restricted", lego_principals=[A], lego_commit="bbbb", written=2.0)
    assert _run(tmp_path, old, [stale, fresh], capsys=capsys)[0] == 0
    assert _run(tmp_path, old, [fresh, stale], capsys=capsys)[0] == 0
    with pytest.raises(DuplicateRow):
        _run(tmp_path, old, [fresh, {**fresh, "written": 3.0}], capsys=capsys)
