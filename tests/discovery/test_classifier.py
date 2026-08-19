import pytest

from services.discovery import classifier as cls


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


RPC = "https://rpc.example"
BIG_BYTECODE = "0x" + "60" * 500
SHORT_BYTECODE = "0x" + "6000" * 10 + "f4" + "00" * 5
ZERO_SLOT = "0x" + "0" * 64


@pytest.fixture(autouse=True)
def _stub_classifier_slot_rpc(monkeypatch):
    """Offline: the batched proxy-slot read (``rpc_batch_request_with_status``)
    hits the wire. Return all-error so the code falls back to the per-slot
    ``rpc_call`` reader (defaulted to empty here); proxy tests set ``cls.rpc_call``
    in-body and the fallback uses their slot values."""
    monkeypatch.setattr(
        cls,
        "rpc_batch_request_with_status",
        lambda rpc_url, calls, *a, **k: [(None, True)] * len(calls),
    )
    monkeypatch.setattr(
        cls,
        "rpc_call",
        lambda rpc, method, params, retries=1, chain_id=None: ZERO_SLOT if method == "eth_getStorageAt" else None,
    )


def _slot_for(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


def _abi_encode_address_array(addrs: list[str]) -> str:
    """Minimal ABI encoder for address[] return values."""
    buf = (0x20).to_bytes(32, "big")  # offset
    buf += len(addrs).to_bytes(32, "big")  # length
    for a in addrs:
        buf += bytes.fromhex(a[2:].zfill(64))
    return "0x" + buf.hex()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_helper_functions():
    assert cls._slot_to_address(ZERO_SLOT) is None
    assert cls._slot_to_address(_slot_for(ADDR(2))) == ADDR(2)
    # A nonzero word whose low 20 bytes are zero carries no address.
    assert cls._slot_to_address("0x" + "01" + "00" * 31) is None
    # "None for zero/empty" is a VERDICT and only a full 64-nibble word earns
    # it: short, empty, over-long, or non-hex words are transport artifacts and
    # must read as failures, never as empty slots (the old pad-then-slice
    # minted the address 0x…001 out of a truncated "0x1").
    for malformed in ("0x", "0x0", "0x1", None, "0x" + "0" * 63, "0x" + "0" * 65, "0x" + " " * 2 + "0" * 62):
        with pytest.raises(ValueError):
            cls._slot_to_address(malformed)  # pyright: ignore[reportArgumentType]

    impl = "aabbccddee11223344556677889900aabbccddee"
    assert cls.detect_eip1167("0x" + cls.EIP1167_PREFIX + impl + cls.EIP1167_SUFFIX) == "0x" + impl
    assert cls.detect_eip1167("0x60016000") is None

    assert cls._bytecode_has_delegatecall("0x6000f4") is True
    assert cls._bytecode_has_delegatecall("0x61f400") is False  # 0xf4 inside PUSH2
    assert cls._bytecode_has_delegatecall("0x61f400f4") is True
    assert cls._bytecode_has_delegatecall("0x600") is False  # odd-length hex
    assert cls._bytecode_has_delegatecall("0xZZZZ") is False  # invalid hex

    # _decode_address_array
    encoded = _abi_encode_address_array([ADDR(1), ADDR(2)])
    assert cls._decode_address_array(encoded) == [ADDR(1), ADDR(2)]
    assert cls._decode_address_array("0x") is None
    assert cls._decode_address_array("0x" + "00" * 64) is None  # length=0
    # length > 100 rejected
    big = (0x20).to_bytes(32, "big") + (101).to_bytes(32, "big") + b"\x00" * (101 * 32)
    assert cls._decode_address_array("0x" + big.hex()) is None


# ---------------------------------------------------------------------------
# Full classification pipeline: all proxy types, probe paths, phases 1-3
# ---------------------------------------------------------------------------


class _Pipeline:
    """Addresses, wire stubs and the one ``classify_contracts`` result the
    phase tests below read.

    This used to be a single 274-line test with 63 assertions covering every
    proxy type, all three phases and the polling rule — one red line named
    seventeen distinct behaviours. The call is unchanged; only the assertions
    are split, so a failure now names the pattern that broke.
    """

    def __init__(self, monkeypatch):
        self.target = ADDR(1)
        self.eip1167 = ADDR(2)
        self.eip1967 = ADDR(3)
        self.beacon_proxy = ADDR(4)
        self.uups = ADDR(5)
        self.oz = ADDR(6)
        self.diamond = ADDR(7)
        self.custom = ADDR(8)
        self.geth_proxy = ADDR(9)  # short bytecode — probe confirms via Geth
        self.parity_proxy = "0x" + "aa" * 20  # short bytecode — Geth fails, Parity confirms
        self.lib_dep = "0x" + "bb" * 20  # short bytecode — probe rejects (library)
        self.static_proxy = "0x" + "cc" * 20  # short bytecode — tracing unavailable
        self.factory = "0x" + "dd" * 20
        self.not_lib = "0x" + "ee" * 20  # CALL + DELEGATECALL — stays regular
        self.large_dc = "0x" + "ff" * 20  # large bytecode with DELEGATECALL — regular
        self.gnosis = ADDR(10)  # GnosisSafe — masterCopy()
        self.compound = ADDR(11)  # Compound — comptrollerImplementation()
        self.synthetix = ADDR(12)  # Synthetix — target()

        # Implementation / facet addresses
        self.eip1967_impl = "0x" + "01" * 20
        self.eip1967_admin = "0x" + "02" * 20
        self.beacon_addr = "0x" + "03" * 20
        self.uups_impl = "0x" + "04" * 20
        self.oz_impl = "0x" + "05" * 20
        self.facet1 = "0x" + "06" * 20
        self.facet2 = "0x" + "07" * 20
        self.custom_impl = "0x" + "08" * 20
        self.geth_impl = "0x" + "09" * 20
        self.parity_impl = "0x" + "0a" * 20
        self.beacon_impl = "0x" + "0b" * 20
        self.gnosis_impl = "0x" + "0c" * 20
        self.compound_impl = "0x" + "0d" * 20
        self.synthetix_impl = "0x" + "0e" * 20
        self.impl_hex = "aabbccddee11223344556677889900aabbccddee"
        eip1167_bc = "0x" + cls.EIP1167_PREFIX + self.impl_hex + cls.EIP1167_SUFFIX

        # Bytecode containing DELEGATECALL but longer than SHORT_BYTECODE_THRESHOLD
        # so the heuristic won't fire — protocol-specific getters catch these instead.
        MEDIUM_DC_BYTECODE = "0x" + "60" * 400 + "f4"

        # GnosisSafe proxy bytecode: contains the slot-0 pattern (PUSH20 mask + PUSH1(0) + SLOAD + AND)
        # followed by DELEGATECALL.  Mirrors real GnosisSafe proxy deployed bytecode.
        GNOSIS_BYTECODE = "0x6080604052" + cls.GNOSIS_SLOT0_PATTERN + "3660008037600080366000845af4" + "00" * 10

        short_addrs = {self.geth_proxy, self.parity_proxy, self.lib_dep, self.static_proxy}

        def fake_code(_rpc, addr, chain_id=None):
            if addr == self.eip1167:
                return eip1167_bc
            if addr in short_addrs:
                return SHORT_BYTECODE
            if addr == self.large_dc:
                return "0x" + "60" * 400 + "f4"
            if addr == self.gnosis:
                return GNOSIS_BYTECODE
            # Protocol-specific proxies: longer bytecode with DELEGATECALL
            if addr in (self.compound, self.synthetix):
                return MEDIUM_DC_BYTECODE
            return BIG_BYTECODE

        storage = {
            (self.eip1967, cls.EIP1967_IMPL_SLOT): _slot_for(self.eip1967_impl),
            (self.eip1967, cls.EIP1967_ADMIN_SLOT): _slot_for(self.eip1967_admin),
            (self.beacon_proxy, cls.EIP1967_BEACON_SLOT): _slot_for(self.beacon_addr),
            (self.uups, cls.EIP1822_LOGIC_SLOT): _slot_for(self.uups_impl),
            (self.oz, cls.OZ_LEGACY_IMPL_SLOT): _slot_for(self.oz_impl),
            (self.gnosis, "0x0"): _slot_for(self.gnosis_impl),  # GnosisSafe slot 0
        }

        def fake_rpc(_rpc, method, params, retries=1, chain_id=None):
            if method == "eth_getStorageAt":
                return storage.get((params[0], params[1]), ZERO_SLOT)
            if method == "eth_getCode":
                return fake_code(_rpc, params[0])
            if method == "eth_call":
                addr = params[0].get("to", "")
                sel = params[0].get("data", "")[:10]
                if addr == self.diamond and sel == cls.FACET_ADDRESSES_SELECTOR:
                    return _abi_encode_address_array([self.facet1, self.facet2])
                if addr == self.custom and sel == cls.IMPLEMENTATION_SELECTOR:
                    return _slot_for(self.custom_impl)
                if addr == self.beacon_addr and sel == cls.IMPLEMENTATION_SELECTOR:
                    return _slot_for(self.beacon_impl)
                # Protocol-specific getters
                if addr == self.gnosis and sel == cls.MASTER_COPY_SELECTOR:
                    return _slot_for(self.gnosis_impl)
                if addr == self.compound and sel == cls.COMPTROLLER_IMPL_SELECTOR:
                    return _slot_for(self.compound_impl)
                if addr == self.synthetix and sel == cls.TARGET_SELECTOR:
                    return _slot_for(self.synthetix_impl)
                raise RuntimeError("revert")
            if method in ("debug_traceCall", "trace_call"):
                addr = params[0].get("to", "")
                if addr == self.geth_proxy and method == "debug_traceCall":
                    return {
                        "type": "CALL",
                        "calls": [{"type": "DELEGATECALL", "from": self.geth_proxy, "to": self.geth_impl}],
                    }
                if addr == self.lib_dep and method == "debug_traceCall":
                    return {"type": "CALL", "calls": []}
                if addr == self.parity_proxy:
                    if method == "debug_traceCall":
                        raise RuntimeError("debug not available")
                    return [
                        {
                            "type": "call",
                            "action": {
                                "callType": "delegatecall",
                                "from": self.parity_proxy,
                                "to": self.parity_impl,
                            },
                        }
                    ]
                raise RuntimeError("tracing unavailable")
            return ZERO_SLOT

        monkeypatch.setattr(cls, "get_code", fake_code)
        monkeypatch.setattr(cls, "rpc_call", fake_rpc)

        edges = [
            {"from": self.target, "to": self.lib_dep, "op": "DELEGATECALL"},
            {"from": self.factory, "to": ADDR(1), "op": "CREATE2"},
            {"from": self.target, "to": self.not_lib, "op": "DELEGATECALL"},
            {"from": self.target, "to": self.not_lib, "op": "CALL"},
            {
                "from": self.geth_proxy,
                "to": ADDR(1),
                "op": "CREATE2",
            },  # should NOT override proxy
        ]

        deps = [
            self.eip1167,
            self.eip1967,
            self.beacon_proxy,
            self.uups,
            self.oz,
            self.diamond,
            self.custom,
            self.gnosis,
            self.compound,
            self.synthetix,
            self.geth_proxy,
            self.parity_proxy,
            self.lib_dep,
            self.static_proxy,
            self.factory,
            self.not_lib,
            self.large_dc,
        ]
        self.result = cls.classify_contracts(self.target, deps, RPC, dynamic_edges=edges)
        self.c = self.result["classifications"]


@pytest.fixture()
def pipeline(monkeypatch):
    return _Pipeline(monkeypatch)


# --- Phase 1: every proxy type ---


@pytest.mark.parametrize(
    "addr_attr,proxy_type,impl_attr",
    [
        ("eip1967", "eip1967", "eip1967_impl"),
        ("beacon_proxy", "beacon_proxy", "beacon_impl"),  # resolved through beacon
        ("uups", "eip1822", "uups_impl"),
        ("oz", "oz_legacy", "oz_impl"),
        ("custom", "custom", "custom_impl"),
        ("gnosis", "gnosis_safe", "gnosis_impl"),
        ("compound", "compound", "compound_impl"),
        ("synthetix", "synthetix", "synthetix_impl"),
    ],
)
def test_phase1_detects_proxy_type_and_implementation(pipeline, addr_attr, proxy_type, impl_attr):
    entry = pipeline.c[getattr(pipeline, addr_attr)]
    assert entry["proxy_type"] == proxy_type
    assert entry["implementation"] == getattr(pipeline, impl_attr)


def test_phase1_eip1167_implementation_comes_from_bytecode(pipeline):
    assert pipeline.c[pipeline.eip1167]["proxy_type"] == "eip1167"
    assert pipeline.c[pipeline.eip1167]["implementation"] == "0x" + pipeline.impl_hex


def test_phase1_eip1967_admin_slot_is_read(pipeline):
    assert pipeline.c[pipeline.eip1967]["admin"] == pipeline.eip1967_admin


def test_phase1_beacon_pointer_is_recorded_alongside_the_impl(pipeline):
    assert pipeline.c[pipeline.beacon_proxy]["beacon"] == pipeline.beacon_addr


def test_phase1_diamond_reports_its_facets(pipeline):
    assert pipeline.c[pipeline.diamond]["proxy_type"] == "eip2535"
    assert set(pipeline.c[pipeline.diamond]["facets"]) == {pipeline.facet1, pipeline.facet2}


def test_phase1_heuristic_probe_confirmed_by_geth_extracts_impl(pipeline):
    assert pipeline.c[pipeline.geth_proxy]["proxy_type"] == "unknown"
    assert pipeline.c[pipeline.geth_proxy]["implementation"] == pipeline.geth_impl


def test_phase1_heuristic_probe_confirmed_by_parity_fallback_extracts_impl(pipeline):
    assert pipeline.c[pipeline.parity_proxy]["proxy_type"] == "unknown"
    assert pipeline.c[pipeline.parity_proxy]["implementation"] == pipeline.parity_impl


def test_phase1_heuristic_probe_rejected_is_a_library(pipeline):
    # Probe rejected — stays regular, Phase 3 marks library.
    assert pipeline.c[pipeline.lib_dep]["type"] == "library"


def test_phase1_heuristic_probe_unavailable_falls_back_to_static(pipeline):
    assert pipeline.c[pipeline.static_proxy]["proxy_type"] == "unknown"


def test_phase1_large_bytecode_with_delegatecall_stays_regular(pipeline):
    assert pipeline.c[pipeline.large_dc]["type"] == "regular"


# --- Phase 2: relational discovery ---


@pytest.mark.parametrize(
    "impl_attr",
    ["eip1967_impl", "gnosis_impl", "compound_impl", "synthetix_impl", "facet1", "facet2"],
)
def test_phase2_pointer_targets_are_discovered_as_implementations(pipeline, impl_attr):
    impl = getattr(pipeline, impl_attr)
    assert impl in pipeline.result["discovered_addresses"]
    assert pipeline.c[impl]["type"] == "implementation"


@pytest.mark.parametrize("impl_attr", ["geth_impl", "parity_impl", "custom_impl"])
def test_phase2_probe_and_getter_impls_are_classified(pipeline, impl_attr):
    assert pipeline.c[getattr(pipeline, impl_attr)]["type"] == "implementation"


def test_phase2_beacon_is_a_beacon_not_a_proxy(pipeline):
    # Beacon classified as beacon (not custom proxy), impl preserved from Phase 1.
    entry = pipeline.c[pipeline.beacon_addr]
    assert entry["type"] == "beacon"
    assert pipeline.beacon_proxy in entry["proxies"]
    assert entry["implementation"] == pipeline.beacon_impl
    assert "proxy_type" not in entry  # cleaned up from Phase 1


# --- Phase 3: behavioral ---


def test_phase3_create2_edge_makes_a_factory(pipeline):
    assert pipeline.c[pipeline.factory]["type"] == "factory"


def test_phase3_call_plus_delegatecall_is_not_a_library(pipeline):
    assert pipeline.c[pipeline.not_lib]["type"] == "regular"


def test_phase3_create2_edge_does_not_override_proxy(pipeline):
    assert pipeline.c[pipeline.geth_proxy]["type"] == "proxy"


# --- needs_polling ---


@pytest.mark.parametrize(
    "addr_attr",
    ["eip1167", "eip1967", "beacon_proxy", "uups", "oz", "diamond", "gnosis", "compound", "synthetix"],
)
def test_needs_polling_false_for_known_event_proxy_types(pipeline, addr_attr):
    # Known-event types: monitor detects their upgrade events → no polling.
    assert pipeline.c[getattr(pipeline, addr_attr)]["needs_polling"] is False


@pytest.mark.parametrize("addr_attr", ["custom", "geth_proxy", "parity_proxy", "static_proxy"])
def test_needs_polling_true_for_custom_and_unknown(pipeline, addr_attr):
    # No known event pattern → need polling.
    assert pipeline.c[getattr(pipeline, addr_attr)]["needs_polling"] is True


# ---------------------------------------------------------------------------


def test_classify_contracts_handles_rpc_failure(monkeypatch):
    """RPC failure for one address falls back to 'regular', doesn't block others."""

    def fake_classify(addr, _rpc, bytecode=None, code_cache=None, chain_id=None):
        if addr == ADDR(2):
            raise RuntimeError("RPC error")
        return {"address": addr, "type": "regular"}

    monkeypatch.setattr(cls, "classify_single", fake_classify)

    result = cls.classify_contracts(ADDR(1), [ADDR(2), ADDR(3)], RPC)
    assert result["classifications"][ADDR(2)]["type"] == "regular"
    assert result["classifications"][ADDR(3)]["type"] == "regular"


def test_classify_contracts_pre_classified_skips_rpc(monkeypatch):
    """pre_classified entries are reused in Phase 1 — classify_single is not called for them."""
    target = ADDR(1)
    dep = ADDR(2)
    impl = ADDR(3)

    pre_classified_result = {
        "address": target,
        "type": "proxy",
        "proxy_type": "eip1967",
        "implementation": impl,
    }

    calls = []

    def tracking_classify(addr, _rpc, bytecode=None, code_cache=None, chain_id=None):
        calls.append(addr)
        return {"address": addr, "type": "regular"}

    monkeypatch.setattr(cls, "classify_single", tracking_classify)

    result = cls.classify_contracts(
        target,
        [dep],
        RPC,
        pre_classified={target: pre_classified_result},
    )

    # Target should use the pre_classified result, not call classify_single
    assert target not in calls
    assert dep in calls
    assert result["classifications"][target]["type"] == "proxy"
    assert result["classifications"][target]["proxy_type"] == "eip1967"
    # Dependency was classified normally
    assert result["classifications"][dep]["type"] == "regular"
    # Implementation discovered from pre_classified proxy slots
    assert impl in result["discovered_addresses"]


# ---------------------------------------------------------------------------
# Direct classify_single tests
# ---------------------------------------------------------------------------


def test_classify_single_eip1967_proxy(monkeypatch):
    """classify_single detects an EIP-1967 proxy via storage slots."""
    addr = ADDR(0xA)
    impl = ADDR(0xB)
    admin = ADDR(0xC)

    storage = {
        (addr, cls.EIP1967_IMPL_SLOT): _slot_for(impl),
        (addr, cls.EIP1967_ADMIN_SLOT): _slot_for(admin),
    }

    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: BIG_BYTECODE)
    monkeypatch.setattr(
        cls,
        "rpc_call",
        lambda _rpc, method, params, retries=1, chain_id=None: (
            storage.get((params[0], params[1]), ZERO_SLOT)
            if method == "eth_getStorageAt"
            else (_ for _ in ()).throw(RuntimeError("unexpected"))
        ),
    )

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "eip1967"
    assert result["implementation"] == impl
    assert result["admin"] == admin


def test_classify_single_eip1167(monkeypatch):
    """classify_single detects an EIP-1167 minimal proxy from bytecode."""
    impl_hex = "aabbccddee11223344556677889900aabbccddee"
    bytecode = "0x" + cls.EIP1167_PREFIX + impl_hex + cls.EIP1167_SUFFIX
    addr = ADDR(0xD)

    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: bytecode)

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "eip1167"
    assert result["implementation"] == "0x" + impl_hex


def test_classify_single_regular(monkeypatch):
    """classify_single returns 'regular' when no proxy pattern is found."""
    addr = ADDR(0xE)

    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: BIG_BYTECODE)
    monkeypatch.setattr(
        cls,
        "rpc_call",
        lambda _rpc, method, params, retries=1, chain_id=None: (
            ZERO_SLOT if method == "eth_getStorageAt" else (_ for _ in ()).throw(RuntimeError("revert"))
        ),
    )

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "regular"


def test_classify_single_with_bytecode_param(monkeypatch):
    """Passing bytecode= skips the get_code call."""
    impl_hex = "aabbccddee11223344556677889900aabbccddee"
    bytecode = "0x" + cls.EIP1167_PREFIX + impl_hex + cls.EIP1167_SUFFIX

    monkeypatch.setattr(cls, "get_code", lambda *a: (_ for _ in ()).throw(AssertionError("should not be called")))
    result = cls.classify_single(ADDR(0xF), RPC, bytecode=bytecode)
    assert result["type"] == "proxy"
    assert result["implementation"] == "0x" + impl_hex


def test_classify_single_large_impl_getter_is_regular(monkeypatch):
    """A large logic contract exposing implementation() as a domain getter
    (not a delegation pointer) classifies as 'regular', not a custom proxy.

    Regression for EtherFi's StakingManager: 16.5 KB UUPS logic that returns the
    EtherFiNode beacon template from implementation(). Without the size guard it
    was mis-tagged proxy_type=custom → EtherFiNode, so its own functions were
    never analyzed and it surfaced no governance controller."""
    addr = ADDR(0x30)
    domain_target = ADDR(0x31)
    big_logic = "0x" + "60" * (cls.GENERIC_IMPL_PROXY_MAX_BYTES + 1000)  # > ceiling, no DELEGATECALL

    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: big_logic)

    def fake_rpc(_rpc, method, params, retries=1, chain_id=None):
        if method == "eth_getStorageAt":
            return ZERO_SLOT
        if method == "eth_call" and params[0].get("data", "")[:10] == cls.IMPLEMENTATION_SELECTOR:
            return _slot_for(domain_target)  # answered — must be ignored at this bytecode size
        raise RuntimeError("revert")

    monkeypatch.setattr(cls, "rpc_call", fake_rpc)

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "regular"
    assert result.get("proxy_type") is None


def test_classify_single_small_impl_getter_still_custom(monkeypatch):
    """A small custom proxy that exposes implementation() is still detected —
    the size guard must not break the legitimate non-standard-slot proxy path."""
    addr = ADDR(0x32)
    impl = ADDR(0x33)
    small_proxy = "0x" + "60" * 200  # 200 bytes, well under the ceiling

    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: small_proxy)

    def fake_rpc(_rpc, method, params, retries=1, chain_id=None):
        if method == "eth_getStorageAt":
            return ZERO_SLOT
        if method == "eth_call" and params[0].get("data", "")[:10] == cls.IMPLEMENTATION_SELECTOR:
            return _slot_for(impl)
        raise RuntimeError("revert")

    monkeypatch.setattr(cls, "rpc_call", fake_rpc)

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "custom"
    assert result["implementation"] == impl


# ---------------------------------------------------------------------------
# UpgradeableBeacon discriminator (revert-proof regression)
# ---------------------------------------------------------------------------


def test_classify_single_upgradeable_beacon(monkeypatch):
    """A true UpgradeableBeacon — exposes implementation() AND owner(), empty
    EIP-1967 slots, NO DELEGATECALL in bytecode — classifies type='beacon'
    (not proxy/custom) so the static worker analyses it and discovers its
    owner(), the upgrade authority of every governed instance.

    Regression for EtherFi AvsOperator/EtherFiNode beacons (0x29b1c223 /
    0x3c55986c): misclassified proxy/custom, they short-circuited controller
    discovery so beacon.owner() was never attributed."""
    addr = ADDR(0x40)
    impl = ADDR(0x41)
    owner = ADDR(0x42)
    # No DELEGATECALL: a beacon is a {implementation, owner} registry that
    # callers read; it never forwards a call itself.
    beacon_bc = "0x" + "60" * 300

    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: beacon_bc)

    def fake_rpc(_rpc, method, params, retries=1, chain_id=None):
        if method == "eth_getStorageAt":
            return ZERO_SLOT
        if method == "eth_call":
            sel = params[0].get("data", "")[:10]
            if sel == cls.IMPLEMENTATION_SELECTOR:
                return _slot_for(impl)
            if sel == cls.OWNER_SELECTOR:
                return _slot_for(owner)
        raise RuntimeError("revert")

    monkeypatch.setattr(cls, "rpc_call", fake_rpc)

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "beacon"
    assert result["implementation"] == impl
    assert result["owner"] == owner
    assert result.get("proxy_type") is None


def test_classify_single_forwarding_proxy_with_delegatecall_stays_proxy(monkeypatch):
    """A forwarding proxy that exposes implementation() but contains
    DELEGATECALL must STAY a proxy — never reclassified as a beacon — even if
    it also answered owner(). Mirrors Aragon AppProxyUpgradeable (Lido stETH,
    cid 340): DELEGATECALL present, so it forwards calls and is a real proxy."""
    addr = ADDR(0x43)
    impl = ADDR(0x44)
    # Custom proxy: small bytecode WITH a real DELEGATECALL (0xf4).
    proxy_bc = "0x" + "60" * 100 + "f4"

    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: proxy_bc)

    def fake_rpc(_rpc, method, params, retries=1, chain_id=None):
        if method == "eth_getStorageAt":
            return ZERO_SLOT
        if method == "eth_call":
            sel = params[0].get("data", "")[:10]
            if sel == cls.IMPLEMENTATION_SELECTOR:
                return _slot_for(impl)
            # Even if it answered owner(), DELEGATECALL keeps it a proxy.
            if sel == cls.OWNER_SELECTOR:
                return _slot_for(ADDR(0x45))
        # No tracing available -> protocol-specific getters revert.
        raise RuntimeError("revert")

    monkeypatch.setattr(cls, "rpc_call", fake_rpc)

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "custom"
    assert result["implementation"] == impl


def test_classify_single_impl_getter_without_owner_is_not_beacon(monkeypatch):
    """A no-DELEGATECALL contract that exposes implementation() but NOT owner()
    is not a beacon — it falls through to the size-gated custom-proxy path. The
    owner() requirement separates a beacon from a bare immutable-impl getter."""
    addr = ADDR(0x46)
    impl = ADDR(0x47)
    bc = "0x" + "60" * 200  # no DELEGATECALL, under the custom-proxy size ceiling

    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: bc)

    def fake_rpc(_rpc, method, params, retries=1, chain_id=None):
        if method == "eth_getStorageAt":
            return ZERO_SLOT
        if method == "eth_call":
            sel = params[0].get("data", "")[:10]
            if sel == cls.IMPLEMENTATION_SELECTOR:
                return _slot_for(impl)
            # owner() reverts -> not a beacon.
        raise RuntimeError("revert")

    monkeypatch.setattr(cls, "rpc_call", fake_rpc)

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "custom"
    assert result["implementation"] == impl


# ---------------------------------------------------------------------------
# Slot-batching parity: ``classify_single`` issues one batched
# eth_getStorageAt instead of five sequential calls.
# ---------------------------------------------------------------------------


def test_classify_single_uses_batched_storage_reads(monkeypatch):
    """The five proxy-detection slot reads are issued via one ``rpc_batch_request_with_status``
    call; sequential ``eth_getStorageAt`` is reserved for the per-slot fallback path."""
    addr = ADDR(0xA)
    impl = ADDR(0xB)

    batch_calls: list[list] = []

    def fake_batch(rpc_url, calls, chain_id=None):
        batch_calls.append(list(calls))
        # Slot order is impl, beacon, admin, uups, oz — return impl on slot 0,
        # zero on the rest.
        return [
            (_slot_for(impl), False),
            ("0x" + "0" * 64, False),
            ("0x" + "0" * 64, False),
            ("0x" + "0" * 64, False),
            ("0x" + "0" * 64, False),
        ]

    monkeypatch.setattr(cls, "rpc_batch_request_with_status", fake_batch)
    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: BIG_BYTECODE)
    monkeypatch.setattr(
        cls,
        "rpc_call",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("storage reads must come from the batch")),
    )

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "eip1967"
    assert result["implementation"] == impl
    assert len(batch_calls) == 1
    assert len(batch_calls[0]) == 5
    assert all(c[0] == "eth_getStorageAt" for c in batch_calls[0])


def test_classify_single_falls_back_when_batch_returns_errors(monkeypatch):
    """Whole-batch failure falls through to per-slot ``eth_getStorageAt`` so
    the classifier still recognises proxies on RPCs that reject batches."""
    addr = ADDR(0xA)
    impl = ADDR(0xB)

    def fake_batch_errored(_rpc, calls, chain_id=None):
        return [(None, True) for _ in calls]

    storage = {(addr, cls.EIP1967_IMPL_SLOT): _slot_for(impl)}

    monkeypatch.setattr(cls, "rpc_batch_request_with_status", fake_batch_errored)
    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: BIG_BYTECODE)
    monkeypatch.setattr(
        cls,
        "rpc_call",
        lambda _rpc, method, params, retries=1, chain_id=None: (
            storage.get((params[0], params[1]), ZERO_SLOT)
            if method == "eth_getStorageAt"
            else (_ for _ in ()).throw(RuntimeError("unexpected"))
        ),
    )

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "eip1967"
    assert result["implementation"] == impl


def test_batched_slot_read_treats_short_words_as_failed_reads(monkeypatch):
    """A SUCCESSFUL response carrying a short word (``"0x0"``) is a transport
    artifact, not an empty slot: it must set ``any_read_failed`` rather than
    decode into "confirmed non-proxy" via padding."""

    def fake_batch(_rpc, calls, chain_id=None):
        return [("0x0", False) for _ in calls]

    monkeypatch.setattr(cls, "rpc_batch_request_with_status", fake_batch)
    decoded, any_read_failed = cls._read_proxy_slots_batched(RPC, ADDR(0xA))
    assert decoded == (None, None, None, None, None)
    assert any_read_failed is True


# ---------------------------------------------------------------------------
# #121 — proxy-slot read failure must fail closed, not fabricate 'regular'
# ---------------------------------------------------------------------------


def test_classify_single_unread_slots_raise_incomplete(monkeypatch):
    """A transient RPC outage that fails BOTH the batched read and the per-slot
    fallback for a would-be-'regular' contract raises ClassificationIncompleteError
    instead of returning a confident non-proxy. Returning 'regular' here would
    silently drop a real implementation's access-control surface."""
    addr = ADDR(0xDEAD)
    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: BIG_BYTECODE)
    # Batch errors (autouse fixture) AND the single-call fallback also raises:
    # the slot read genuinely failed — distinct from a slot that read empty.
    monkeypatch.setattr(
        cls,
        "rpc_call",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("rpc down")),
    )

    with pytest.raises(cls.ClassificationIncompleteError):
        cls.classify_single(addr, RPC)


def test_classify_single_proxy_detected_despite_unread_admin_slot(monkeypatch):
    """The fail-closed gate is BEHIND the would-be-'regular' fallthrough: a proxy
    whose impl slot reads fine is still classified proxy even when another slot
    (admin) was genuinely unreadable — no false raise."""
    addr = ADDR(0xA)
    impl = ADDR(0xB)

    def fake_batch(_rpc, calls, chain_id=None):
        # impl(0) reads back; admin(2) errors; the rest read empty.
        return [
            (_slot_for(impl), False),
            (ZERO_SLOT, False),
            (None, True),
            (ZERO_SLOT, False),
            (ZERO_SLOT, False),
        ]

    monkeypatch.setattr(cls, "rpc_batch_request_with_status", fake_batch)
    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: BIG_BYTECODE)
    # The admin-slot single-call fallback raises (genuinely unread → any_read_failed
    # True), but impl was read so the proxy verdict returns before the fallthrough.
    monkeypatch.setattr(
        cls,
        "rpc_call",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("admin slot read failed")),
    )

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "proxy"
    assert result["proxy_type"] == "eip1967"
    assert result["implementation"] == impl
    assert "admin" not in result  # admin slot unread → None → omitted, never guessed


def test_classify_single_clean_empty_slots_stay_regular(monkeypatch):
    """Genuinely-empty slots (read succeeds, returns zero) still classify
    'regular' — the flag is set only on a read *failure*, so a real non-proxy is
    never spuriously raised."""
    addr = ADDR(0xE)
    monkeypatch.setattr(cls, "get_code", lambda _rpc, _addr, chain_id=None: BIG_BYTECODE)
    # All reads succeed and return the zero slot; eth_call probes revert (non-proxy).
    monkeypatch.setattr(
        cls,
        "rpc_call",
        lambda _rpc, method, params, retries=1, chain_id=None: (
            ZERO_SLOT if method == "eth_getStorageAt" else (_ for _ in ()).throw(RuntimeError("revert"))
        ),
    )

    result = cls.classify_single(addr, RPC)
    assert result["type"] == "regular"


def test_classify_contracts_incomplete_marks_unknown_not_regular(monkeypatch):
    """At the orchestration layer, a ClassificationIncompleteError surfaces as
    {type:'unknown', classification_incomplete:True} — NOT a confident 'regular'
    that would drop the proxy edge — and trips the degraded machinery."""
    target = ADDR(1)
    incomplete = ADDR(2)
    ok = ADDR(3)

    def fake_classify(addr, _rpc, bytecode=None, code_cache=None, chain_id=None):
        if addr == incomplete:
            raise cls.ClassificationIncompleteError("slots unread")
        return {"address": addr, "type": "regular"}

    monkeypatch.setattr(cls, "classify_single", fake_classify)

    degraded: dict = {}

    def fake_record_degraded(*, phase, exc, context):
        degraded["phase"] = phase
        degraded["exc"] = exc

    monkeypatch.setattr(cls, "record_degraded", fake_record_degraded)

    result = cls.classify_contracts(target, [incomplete, ok], RPC)
    c = result["classifications"]

    assert c[incomplete]["type"] == "unknown"
    assert c[incomplete]["classification_incomplete"] is True
    assert c[incomplete]["type"] != "regular"  # the silent-downgrade is closed
    assert c[ok]["type"] == "regular"  # other addresses unaffected
    assert degraded["phase"] == "classify"
    assert isinstance(degraded["exc"], cls.ClassificationIncompleteError)


# ---------------------------------------------------------------------------
# classify_contracts parity: parallel + sequential produce identical output
# (modulo dict iteration order).
# ---------------------------------------------------------------------------


def _classify_contracts_parity_helper(monkeypatch, fanout: str):
    """Drive ``classify_contracts`` with a fixture that hits every Phase 1
    detection branch. Returns the canonicalised classifications dict."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)

    target = ADDR(1)
    deps = [ADDR(2), ADDR(3), ADDR(4), ADDR(5), ADDR(6)]

    impl_for: dict[str, str] = {target: ADDR(0xA), deps[0]: ADDR(0xB)}

    def fake_classify_single(addr, _rpc, bytecode=None, code_cache=None, chain_id=None):
        info: dict = {"address": addr, "type": "regular"}
        if addr in impl_for:
            info["type"] = "proxy"
            info["proxy_type"] = "eip1967"
            info["implementation"] = impl_for[addr]
        return info

    monkeypatch.setattr(cls, "classify_single", fake_classify_single)

    out = cls.classify_contracts(target, deps, RPC)
    # Canonicalise: sort the classifications dict by address so iteration
    # order doesn't matter when comparing sequential vs parallel runs.
    return {
        addr: {k: info[k] for k in sorted(info.keys())} for addr, info in sorted(out["classifications"].items())
    }, sorted(out["discovered_addresses"])


def test_classify_contracts_parity_parallel_vs_sequential(monkeypatch):
    """``PSAT_RPC_FANOUT=1`` and ``=8`` must produce identical classifications."""
    seq_classifications, seq_discovered = _classify_contracts_parity_helper(monkeypatch, "1")
    par_classifications, par_discovered = _classify_contracts_parity_helper(monkeypatch, "8")
    assert seq_classifications == par_classifications
    assert seq_discovered == par_discovered


def test_classify_contracts_parallel_handles_per_address_runtimeerror(monkeypatch):
    """A RuntimeError on one address falls back to ``regular`` without
    poisoning the parallel batch — same surface as the serial loop."""
    monkeypatch.setenv("PSAT_RPC_FANOUT", "8")
    target = ADDR(1)
    deps = [ADDR(2), ADDR(3), ADDR(4)]

    def fake_classify_single(addr, _rpc, bytecode=None, code_cache=None, chain_id=None):
        if addr == ADDR(3):
            raise RuntimeError("RPC borked")
        return {"address": addr, "type": "regular"}

    monkeypatch.setattr(cls, "classify_single", fake_classify_single)

    out = cls.classify_contracts(target, deps, RPC)
    assert out["classifications"][ADDR(3)]["type"] == "regular"
    assert out["classifications"][ADDR(2)]["type"] == "regular"
    assert out["classifications"][ADDR(4)]["type"] == "regular"
