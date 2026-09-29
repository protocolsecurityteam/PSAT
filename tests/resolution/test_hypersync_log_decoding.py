"""HyperSync response/log decoding shared by the inline resolution scans."""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from services.resolution.hypersync_bound import data_words_from_log, logs_from_response, topics_from_log

WORD_A = "0x" + "AB" * 32
WORD_B = "0x" + "cd" * 32


@pytest.mark.parametrize(
    "response, expected",
    [
        pytest.param(NS(data=NS(logs=["a", "b"])), ["a", "b"], id="data-object-with-logs"),
        pytest.param(NS(data=NS(logs=None)), [], id="data-object-null-logs"),
        pytest.param(NS(data=["a"]), ["a"], id="data-is-list"),
        pytest.param(NS(data=None, logs=["a"]), ["a"], id="top-level-logs"),
        pytest.param(NS(), [], id="nothing"),
    ],
)
def test_logs_from_response(response, expected):
    assert logs_from_response(response) == expected


@pytest.mark.parametrize(
    "log, expected",
    [
        pytest.param(NS(topics=["0xAA", "0xbb", None, "zz"]), ["0xaa", "0xbb"], id="topics-list-drops-non-hex"),
        pytest.param(
            NS(topic0="0xAA", topic1="0x", topic2="0x0", topic3="0xCC"), ["0xaa", "0xcc"], id="topicN-skips-empty"
        ),
        pytest.param(NS(), [], id="no-topics"),
    ],
)
def test_topics_from_log(log, expected):
    assert topics_from_log(log) == expected


@pytest.mark.parametrize(
    "log, expected",
    [
        pytest.param(NS(data=WORD_A + WORD_B[2:]), [WORD_A.lower(), WORD_B], id="two-words-lowercased"),
        pytest.param(NS(data="0x"), [], id="empty"),
        pytest.param(NS(data=None), [], id="null-data"),
        pytest.param(NS(data="deadbeef"), [], id="no-0x-prefix"),
        pytest.param(NS(data="0x" + "ab" * 31), [], id="not-word-aligned"),
    ],
)
def test_data_words_from_log(log, expected):
    assert data_words_from_log(log) == expected
