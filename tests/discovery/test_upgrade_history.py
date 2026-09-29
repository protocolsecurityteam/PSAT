import pytest

from services.discovery import upgrade_history as uh


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _topic_for(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


def _admin_data(old: str, new: str) -> str:
    return "0x" + "0" * 24 + old[2:] + "0" * 24 + new[2:]


def _make_log(
    address, topic0, topic1=None, data="0x", block="0x1", tx="0xaaa", log_index="0x0", timestamp="0x65a00000"
):
    log = {
        "address": address,
        "topics": [topic0] + ([topic1] if topic1 else []),
        "data": data,
        "blockNumber": block,
        "transactionHash": tx,
        "logIndex": log_index,
        "timeStamp": timestamp,
    }
    return log


def _write_deps(_tmp_path, target, deps_dict):
    """Build a unified-dependencies dict (kept as ``_write_deps`` so call sites stay readable)."""
    return {"address": target, "dependencies": deps_dict}


def _write_deps_target_proxy(_tmp_path, target, proxy_type, implementation, deps_dict=None):
    """Unified-dependencies dict with the TARGET classified as a proxy (only the target is processed)."""
    return {
        "address": target,
        "target_classification": {
            "type": "proxy",
            "proxy_type": proxy_type,
            "implementation": implementation,
        },
        "dependencies": deps_dict or {},
    }


def _mock_no_enrichment(monkeypatch):
    from services.clients import etherscan

    monkeypatch.setattr(etherscan, "get_contract_info", lambda addr, **_kw: (None, {}))


# ---------------------------------------------------------------------------
# parse_upgrade_log — boundary between raw Etherscan data and domain model
# ---------------------------------------------------------------------------


class TestParseUpgradeLog:
    def test_all_event_types(self):
        upgraded_log = _make_log(
            ADDR(1),
            uh.UPGRADED_TOPIC0,
            _topic_for(ADDR(42)),
            block="0xa",
            tx="0xabc",
            log_index="0x1",
        )
        admin_log = _make_log(
            ADDR(1),
            uh.ADMIN_CHANGED_TOPIC0,
            data=_admin_data(ADDR(1), ADDR(2)),
            block="0x14",
        )
        beacon_log = _make_log(
            ADDR(1),
            uh.BEACON_UPGRADED_TOPIC0,
            _topic_for(ADDR(99)),
            block="0x1e",
        )

        upgraded = uh.parse_upgrade_log(upgraded_log)
        assert upgraded is not None
        assert upgraded["event_type"] == "upgraded"
        assert upgraded.get("implementation") == ADDR(42)
        assert upgraded["block_number"] == 10
        assert upgraded["tx_hash"] == "0xabc"
        assert upgraded.get("log_index") == 1
        assert (upgraded.get("timestamp") or 0) > 0
        assert upgraded.get("_emitter") == ADDR(1)

        admin = uh.parse_upgrade_log(admin_log)
        assert admin is not None
        assert admin["event_type"] == "admin_changed"
        assert admin.get("previous_admin") == ADDR(1)
        assert admin.get("new_admin") == ADDR(2)

        beacon = uh.parse_upgrade_log(beacon_log)
        assert beacon is not None
        assert beacon["event_type"] == "beacon_upgraded"
        assert beacon.get("beacon") == ADDR(99)

    def test_malformed_logs_return_none(self):
        assert uh.parse_upgrade_log({"topics": [], "data": "0x", "blockNumber": "0x1"}) is None
        assert uh.parse_upgrade_log(_make_log(ADDR(1), "0xdeadbeef" * 8)) is None

    def test_partial_data(self):
        """Upgraded without topic1 and admin_changed with short data still parse."""
        upgraded_no_impl = uh.parse_upgrade_log(_make_log(ADDR(1), uh.UPGRADED_TOPIC0))
        assert upgraded_no_impl is not None
        assert upgraded_no_impl["event_type"] == "upgraded"
        assert "implementation" not in upgraded_no_impl

        admin_short_data = uh.parse_upgrade_log(_make_log(ADDR(1), uh.ADMIN_CHANGED_TOPIC0, data="0x00"))
        assert admin_short_data is not None
        assert admin_short_data["event_type"] == "admin_changed"
        assert "previous_admin" not in admin_short_data

    def test_hex_to_int_edge_cases(self):
        assert uh._hex_to_int("0x") == 0
        assert uh._hex_to_int("0x0") == 0
        assert uh._hex_to_int("") == 0
        assert uh._hex_to_int(0) == 0
        assert uh._hex_to_int("0xa") == 10
        assert uh._hex_to_int(42) == 42

    def test_bare_hex_log_index(self):
        """Etherscan sometimes returns '0x' for logIndex — must not crash."""
        log = _make_log(
            ADDR(1),
            uh.UPGRADED_TOPIC0,
            _topic_for(ADDR(42)),
            log_index="0x",
        )
        event = uh.parse_upgrade_log(log)
        assert event is not None
        assert event.get("log_index") == 0

    @pytest.mark.parametrize(
        "log, event_type, expected_fields",
        [
            # OZ legacy proxies emit Upgraded(address) with impl in data, not topics.
            pytest.param(
                _make_log(ADDR(1), uh.UPGRADED_TOPIC0, data="0x" + "0" * 24 + ADDR(42)[2:]),
                "upgraded",
                {"implementation": ADDR(42)},
                id="non-indexed-upgraded",
            ),
            pytest.param(
                _make_log(ADDR(1), uh.BEACON_UPGRADED_TOPIC0, data="0x" + "0" * 24 + ADDR(99)[2:]),
                "beacon_upgraded",
                {"beacon": ADDR(99)},
                id="non-indexed-beacon-upgraded",
            ),
            pytest.param(
                {
                    "address": ADDR(1),
                    "topics": [uh.ADMIN_CHANGED_TOPIC0, _topic_for(ADDR(50)), _topic_for(ADDR(51))],
                    "data": "0x",
                    "blockNumber": "0x1",
                    "transactionHash": "0xaaa",
                    "logIndex": "0x0",
                    "timeStamp": "0x65a00000",
                },
                "admin_changed",
                {"previous_admin": ADDR(50), "new_admin": ADDR(51)},
                id="indexed-admin-changed",
            ),
        ],
    )
    def test_parse_event_variants(self, log, event_type, expected_fields):
        event = uh.parse_upgrade_log(log)
        assert event is not None
        assert event["event_type"] == event_type
        for key, value in expected_fields.items():
            assert event.get(key) == value

    def test_none_in_topics_array(self):
        log = {
            "address": ADDR(1),
            "topics": [uh.UPGRADED_TOPIC0, None],
            "data": "0x",
            "blockNumber": "0x1",
            "transactionHash": "0xaaa",
            "logIndex": "0x0",
            "timeStamp": "0x65a00000",
        }
        event = uh.parse_upgrade_log(log)
        assert event is not None
        assert event["event_type"] == "upgraded"
        assert "implementation" not in event


# ---------------------------------------------------------------------------
# build_upgrade_history — full pipeline integration tests
# ---------------------------------------------------------------------------


class TestBuildUpgradeHistory:
    """Mocks only at the boundary: _fetch_logs_etherscan and get_contract_info."""

    def test_no_proxies_returns_empty_schema(self, tmp_path):
        deps_path = _write_deps(
            tmp_path,
            ADDR(0),
            {
                ADDR(1): {"type": "regular"},
                ADDR(2): {"type": "library"},
            },
        )
        result = uh.build_upgrade_history(deps_path)
        assert result["schema_version"] == "0.1"
        assert result["target_address"] == ADDR(0)
        assert result["proxies"] == {}
        assert result["total_upgrades"] == 0

    def test_single_proxy_full_output(self, monkeypatch, tmp_path):
        target = ADDR(1)
        impl_v1, impl_v2 = ADDR(10), ADDR(11)
        deps_path = _write_deps_target_proxy(tmp_path, target, "eip1967", impl_v2)

        def mock_fetch(address, topic0, from_block=0, chain_id=1):
            if topic0 != uh.UPGRADED_TOPIC0:
                return []
            return [
                _make_log(
                    target, uh.UPGRADED_TOPIC0, _topic_for(impl_v1), block="0x64", tx="0xa", timestamp="0x65a00000"
                ),
                _make_log(
                    target, uh.UPGRADED_TOPIC0, _topic_for(impl_v2), block="0xc8", tx="0xb", timestamp="0x65b00000"
                ),
            ]

        monkeypatch.setattr(uh, "_fetch_logs_etherscan", mock_fetch)
        from services.clients import etherscan

        monkeypatch.setattr(etherscan, "get_contract_info", lambda addr, **_kw: ("ImplContract", {}))

        result = uh.build_upgrade_history(deps_path)

        assert result["schema_version"] == "0.1"
        assert result["target_address"] == target
        assert result["total_upgrades"] == 2

        h = result["proxies"][target]
        assert h["proxy_address"] == target
        assert h["proxy_type"] == "eip1967"
        assert h["current_implementation"] == impl_v2
        assert h["upgrade_count"] == 2
        assert h["first_upgrade_block"] == 0x64
        assert h["last_upgrade_block"] == 0xC8

        impls = h["implementations"]
        assert len(impls) == 2
        assert impls[0].get("address") == impl_v1
        assert impls[0].get("block_introduced") == 0x64
        assert impls[0].get("timestamp_introduced") == 0x65A00000
        assert impls[0].get("block_replaced") == 0xC8
        assert impls[0].get("timestamp_replaced") == 0x65B00000
        assert "block_replaced" not in impls[1]

        assert impls[0].get("contract_name") == "ImplContract"

        assert len(h["events"]) == 2
        for event in h["events"]:
            assert "_emitter" not in event
            assert "event_type" in event
            assert "block_number" in event

    def test_dependency_proxies_are_ignored(self, monkeypatch, tmp_path):
        """Proxies under ``dependencies`` are NOT processed: upgrade history only
        runs for the target; each dependency builds its own history in its job."""
        target = ADDR(0)  # regular (non-proxy) target
        proxy_a, proxy_b = ADDR(1), ADDR(2)
        deps_path = _write_deps(
            tmp_path,
            target,
            {
                proxy_a: {"type": "proxy", "proxy_type": "eip1967", "implementation": ADDR(10)},
                proxy_b: {"type": "proxy", "proxy_type": "eip1967", "implementation": ADDR(21)},
            },
        )

        # Any fetch call would be unexpected.
        def fail_fetch(address, topic0, from_block=0, chain_id=1):
            pytest.fail(f"_fetch_logs_etherscan should not be called (addr={address})")

        monkeypatch.setattr(uh, "_fetch_logs_etherscan", fail_fetch)
        _mock_no_enrichment(monkeypatch)

        result = uh.build_upgrade_history(deps_path)

        assert result["schema_version"] == "0.1"
        assert result["target_address"] == target
        assert result["proxies"] == {}
        assert result["total_upgrades"] == 0

    def test_admin_changed_events_in_output(self, monkeypatch, tmp_path):
        target = ADDR(1)
        deps_path = _write_deps_target_proxy(tmp_path, target, "eip1967", ADDR(10))

        def mock_fetch(address, topic0, from_block=0, chain_id=1):
            if topic0 == uh.UPGRADED_TOPIC0:
                return [_make_log(target, uh.UPGRADED_TOPIC0, _topic_for(ADDR(10)), block="0x64", tx="0xa")]
            if topic0 == uh.ADMIN_CHANGED_TOPIC0:
                return [
                    _make_log(
                        target, uh.ADMIN_CHANGED_TOPIC0, data=_admin_data(ADDR(50), ADDR(51)), block="0x65", tx="0xb"
                    )
                ]
            return []

        monkeypatch.setattr(uh, "_fetch_logs_etherscan", mock_fetch)
        _mock_no_enrichment(monkeypatch)

        result = uh.build_upgrade_history(deps_path)
        h = result["proxies"][target]
        assert h["upgrade_count"] == 1
        assert len(h["implementations"]) == 1
        event_types = [e["event_type"] for e in h["events"]]
        assert "upgraded" in event_types
        assert "admin_changed" in event_types
        admin_event = next(e for e in h["events"] if e["event_type"] == "admin_changed")
        assert admin_event.get("previous_admin") == ADDR(50)
        assert admin_event.get("new_admin") == ADDR(51)

    def test_implementation_as_dict_in_target_classification(self, monkeypatch, tmp_path):
        """A dict-shaped implementation in target_classification yields the
        address; a dependency entry with the same impl name provides the
        known-name shortcut so Etherscan is never called."""
        target = ADDR(1)
        impl = ADDR(10)
        # Known name comes from the dependencies side so _enrich_implementations
        # reuses it.
        deps_path = _write_deps_target_proxy(
            tmp_path,
            target,
            "eip1967",
            {"address": impl, "contract_name": "KnownImpl"},
            deps_dict={impl: {"type": "implementation", "contract_name": "KnownImpl"}},
        )

        def mock_fetch(address, topic0, from_block=0, chain_id=1):
            if topic0 == uh.UPGRADED_TOPIC0:
                return [_make_log(target, uh.UPGRADED_TOPIC0, _topic_for(impl), block="0x64", tx="0xa")]
            return []

        monkeypatch.setattr(uh, "_fetch_logs_etherscan", mock_fetch)
        from services.clients import etherscan

        monkeypatch.setattr(
            etherscan,
            "get_contract_info",
            lambda addr, **_kw: pytest.fail(f"get_contract_info should not be called for known address {addr}"),
        )

        result = uh.build_upgrade_history(deps_path)
        assert result["proxies"][target]["implementations"][0].get("contract_name") == "KnownImpl"

    def test_enrichment_calls_etherscan_for_unknown_implementations(self, monkeypatch, tmp_path):
        target = ADDR(1)
        old_impl, new_impl = ADDR(10), ADDR(11)
        deps_path = _write_deps_target_proxy(
            tmp_path,
            target,
            "eip1967",
            new_impl,
            deps_dict={new_impl: {"type": "implementation", "contract_name": "ImplV2"}},
        )

        def mock_fetch(address, topic0, from_block=0, chain_id=1):
            if topic0 == uh.UPGRADED_TOPIC0:
                return [
                    _make_log(target, uh.UPGRADED_TOPIC0, _topic_for(old_impl), block="0x64", tx="0xa"),
                    _make_log(target, uh.UPGRADED_TOPIC0, _topic_for(new_impl), block="0xc8", tx="0xb"),
                ]
            return []

        monkeypatch.setattr(uh, "_fetch_logs_etherscan", mock_fetch)
        from services.clients import etherscan

        monkeypatch.setattr(etherscan, "get_contract_info", lambda addr, **_kw: ("ImplV1", {}))

        result = uh.build_upgrade_history(deps_path)
        impls = result["proxies"][target]["implementations"]
        assert impls[0].get("contract_name") == "ImplV1"  # fetched via etherscan
        assert impls[1].get("contract_name") == "ImplV2"  # reused from deps

    def test_enrichment_deduplicates_calls(self, monkeypatch, tmp_path):
        """get_contract_info is called at most once per unique unknown address,
        even when an impl repeats (rolled back then re-upgraded)."""
        target = ADDR(1)
        shared_impl = ADDR(10)
        deps_path = _write_deps_target_proxy(tmp_path, target, "eip1967", shared_impl)

        def mock_fetch(address, topic0, from_block=0, chain_id=1):
            if topic0 == uh.UPGRADED_TOPIC0:
                return [
                    _make_log(target, uh.UPGRADED_TOPIC0, _topic_for(shared_impl), block="0x64", tx="0xa"),
                    _make_log(target, uh.UPGRADED_TOPIC0, _topic_for(shared_impl), block="0xc8", tx="0xb"),
                ]
            return []

        monkeypatch.setattr(uh, "_fetch_logs_etherscan", mock_fetch)
        from services.clients import etherscan

        call_count = [0]

        def counting_get_info(addr, **_kw):
            call_count[0] += 1
            return ("SharedImpl", {})

        monkeypatch.setattr(etherscan, "get_contract_info", counting_get_info)

        result = uh.build_upgrade_history(deps_path)
        assert call_count[0] == 1
        impls = result["proxies"][target]["implementations"]
        assert len(impls) == 2
        for impl in impls:
            assert impl.get("contract_name") == "SharedImpl"

    def test_enrich_false_skips_etherscan_but_applies_known_names(self, monkeypatch, tmp_path):
        target = ADDR(1)
        old_impl, new_impl = ADDR(10), ADDR(11)
        deps_path = _write_deps_target_proxy(
            tmp_path,
            target,
            "eip1967",
            new_impl,
            deps_dict={new_impl: {"type": "implementation", "contract_name": "ImplV2"}},
        )

        def mock_fetch(address, topic0, from_block=0, chain_id=1):
            if topic0 == uh.UPGRADED_TOPIC0:
                return [
                    _make_log(target, uh.UPGRADED_TOPIC0, _topic_for(old_impl), block="0x64", tx="0xa"),
                    _make_log(target, uh.UPGRADED_TOPIC0, _topic_for(new_impl), block="0xc8", tx="0xb"),
                ]
            return []

        monkeypatch.setattr(uh, "_fetch_logs_etherscan", mock_fetch)
        from services.clients import etherscan

        monkeypatch.setattr(
            etherscan,
            "get_contract_info",
            lambda addr: pytest.fail("get_contract_info should not be called when enrich=False"),
        )

        result = uh.build_upgrade_history(deps_path, enrich=False)
        impls = result["proxies"][target]["implementations"]
        assert impls[1].get("contract_name") == "ImplV2"  # known name applied
        assert "contract_name" not in impls[0]  # unknown, not fetched

    @pytest.mark.parametrize(
        "proxy_type",
        ["eip1967", "transparent", "uups"],
    )
    def test_empty_events_with_current_impl(self, monkeypatch, tmp_path, proxy_type):
        target = ADDR(1)
        impl = ADDR(10)

        deps_path = _write_deps_target_proxy(tmp_path, target, proxy_type, impl)
        monkeypatch.setattr(uh, "_fetch_logs_etherscan", lambda addr, t, from_block=0, chain_id=1: [])
        _mock_no_enrichment(monkeypatch)

        result = uh.build_upgrade_history(deps_path)

        assert result["total_upgrades"] == 0
        assert target in result["proxies"]
        h = result["proxies"][target]
        assert h["proxy_type"] == proxy_type
        assert h["current_implementation"] == impl
        assert h["upgrade_count"] == 0
        assert h["first_upgrade_block"] is None
        assert h["last_upgrade_block"] is None
        assert h["events"] == []
        assert len(h["implementations"]) == 1
        assert h["implementations"][0].get("address") == impl


# ---------------------------------------------------------------------------
# fetch_upgrade_events parity: parallel + sequential produce identical events.
# ---------------------------------------------------------------------------


def _fetch_events_parity_helper(monkeypatch, fanout: str, tmp_path):
    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)
    target = ADDR(0xA)
    impl_v1, impl_v2 = ADDR(0xB), ADDR(0xC)

    fetch_calls: list[tuple[str, str]] = []

    def mock_fetch(addr, topic0, from_block=0, chain_id=1):
        fetch_calls.append((addr, topic0))
        if addr != target or topic0 != uh.UPGRADED_TOPIC0:
            return []
        return [
            {
                "address": target,
                "topics": [uh.UPGRADED_TOPIC0, _topic_for(impl_v1)],
                "data": "0x",
                "blockNumber": "0x10",
                "transactionHash": "0xa1",
                "logIndex": "0x0",
                "timeStamp": "0x65a00000",
            },
            {
                "address": target,
                "topics": [uh.UPGRADED_TOPIC0, _topic_for(impl_v2)],
                "data": "0x",
                "blockNumber": "0x20",
                "transactionHash": "0xa2",
                "logIndex": "0x0",
                "timeStamp": "0x65b00000",
            },
        ]

    monkeypatch.setattr(uh, "_fetch_logs_etherscan", mock_fetch)
    events = uh.fetch_upgrade_events([target])
    return events, fetch_calls


def test_fetch_upgrade_events_parity_parallel_vs_sequential(monkeypatch, tmp_path):
    seq_events, seq_calls = _fetch_events_parity_helper(monkeypatch, "1", tmp_path)
    par_events, par_calls = _fetch_events_parity_helper(monkeypatch, "8", tmp_path)
    assert seq_events == par_events
    # The (addr, topic) task list is enumerated identically in both modes;
    # only the dispatch order across threads differs, which is invisible to
    # the deterministic post-sort.
    assert sorted(seq_calls) == sorted(par_calls)


# ---------------------------------------------------------------------------
# Multichain (M1.1): chain_id threading to the Etherscan getLogs query
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs, expected_chain_id",
    [
        pytest.param({"chain_id": 8453}, 8453, id="non-mainnet-chain-threaded"),
        pytest.param({}, 1, id="defaults-to-mainnet"),
    ],
)
def test_build_upgrade_history_threads_chain_id_to_getlogs(monkeypatch, kwargs, expected_chain_id):
    import services.clients.etherscan as etherscan_mod

    seen_chain_ids = []

    def fake_get(_module, action, **kw):
        seen_chain_ids.append(kw.get("chain_id"))
        return {"result": []}

    # _fetch_logs_etherscan does `from services.clients.etherscan import get` at call time,
    # so patching the module attribute intercepts the real wire call.
    monkeypatch.setattr(etherscan_mod, "get", fake_get)
    # Stub the name-enrichment wrapper so the test never leaves the machine.
    monkeypatch.setattr(etherscan_mod, "get_contract_info", lambda addr, **_kw: (None, {}))

    target = ADDR(0xABC)
    deps = {
        "address": target,
        "target_classification": {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": ADDR(2),
        },
        "dependencies": {},
    }

    uh.build_upgrade_history(deps, **kwargs)

    assert seen_chain_ids, "getLogs was never called"
    assert set(seen_chain_ids) == {expected_chain_id}
