"""Tier-2 anvil fork transport + the §4.1 pause recipe (EFFECTS_RESOLUTION_SPEC).

Tier 2 is reserved for effects that need SEQUENCING or TIME — proving a freeze's
blast radius and that it auto-expires at the contract's own
``MAX_PAUSE_DURATION`` — which ``eth_call``/``eth_simulateV1`` cannot express.
The fork lives behind the injectable :class:`AnvilTransport` interface, the same
seam discipline as ``call_batch``/``Simulate``: exactly one place
(:class:`SubprocessAnvil`) does real subprocess + localhost JSON-RPC I/O;
everything else takes the transport injected and is tested against a stub.

Hard rules honored here: the hardfork is PINNED and ASSERTED and recorded per
transcript (§8.7, inv. 14 — post-Cancun EIP-6780 is why a stale fork mints wrong
witnesses); the anvil/foundry version is recorded per transcript; fork access is
single-flight (inv. 16 — snapshot/revert is process-global, the worker runs
``PSAT_EFFECTS_JOB_CONCURRENCY=1``); ``MAX_PAUSE_DURATION`` is READ FROM SOURCE by
the caller and passed in, never hardcoded (inv. 10). Agents NEVER run a FORKING
anvil or real RPC — that is the user's preview step; the offline integration test
uses a local NON-FORKING anvil with a checked-in fixture.
"""

from __future__ import annotations

import logging
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from services.effects.config import (
    EFFECT_CLASS_FREEZE_PAUSE,
    OBSERVATION_EXECUTED,
    OBSERVATION_REVERTED,
    SCOPE_PROJECTION,
    TIER_FORK,
)
from services.effects.exceptions import AnvilSpawnError, ForkRpcTimeoutError
from services.effects.harness import (
    Discrepancy,
    ObservedEffect,
    SimContext,
    TranscriptStore,
    emit,
    new_transcript,
    proven,
    unknown,
)
from utils.memory import rss_bytes_for_pid
from utils.rpc import EthCallResult

logger = logging.getLogger(__name__)

# Post-Cancun forks that carry EIP-6780 (and later) semantics. A fork pinned to
# anything earlier can mint witnesses wrong for the live chain (§8.7).
POST_CANCUN_HARDFORKS = frozenset({"cancun", "prague", "osaka"})


@dataclass(frozen=True)
class ForkFixture:
    """One piece of fork state a probe needs before it can be meaningful — a
    funded caller, a storage slot holding a precondition. Applied INSIDE the
    recipe's snapshot so it is reverted with everything else.

    ``kind`` is ``set_balance`` (``address``/``value``) or ``set_storage_at``
    (``address``/``slot``/``value``). An unknown kind is ignored, never guessed.

    A ``set_storage_at`` fixture MAY carry a read-back spec (``verify_to`` +
    ``verify_calldata`` + ``verify_expected``): after the slot is written, the
    contract's OWN getter is called and its 32-byte word compared to
    ``verify_expected``. What this proves is that the getter NOW echoes the
    seeded word — the precondition the probe will read is satisfied. It does
    not prove the write is what the getter reads: a wrong-slot write is kept
    when the getter already returned the expected word (e.g. an earlier seed
    satisfied it). That is safe — seeds are constants of the pre/post diff, so
    a stray write can only shrink the observed lower bound, never flip an
    entry point across the pause — but the guarantee is precondition-holds,
    not write-landed. Absent (all ``None``) ⇒ the fixture is applied as-is,
    exactly as before."""

    kind: str
    address: str
    value: str
    slot: str | None = None
    verify_to: str | None = None
    verify_calldata: str | None = None
    verify_expected: str | None = None


@dataclass(frozen=True)
class EntryPoint:
    """One state-changing entry point to probe for the blast-radius diff.

    ``key`` is a stable identity (selector or ``name`` — never used to CLASSIFY,
    only to label which points reverted); ``calldata`` + ``from_addr`` are the
    probe call. ``to`` defaults to the recipe's contract when ``None``.
    ``fixtures`` is the fork state THIS probe needs to be able to succeed
    pre-pause (gas for its caller, a balance/allowance slot); carried per entry
    point so it stays inspectable and tunable, applied once with the rest."""

    key: str
    calldata: str
    from_addr: str | None = None
    to: str | None = None
    fixtures: tuple["ForkFixture", ...] = ()


class AnvilTransport(Protocol):
    """Fork transport seam. ``call`` is read-only (``eth_call``); ``send``
    executes an impersonated tx against the LOCAL fork only (never mainnet)."""

    def hardfork(self) -> str: ...

    def versions(self) -> dict[str, str]: ...

    def snapshot(self) -> str: ...

    def revert(self, snapshot_id: str) -> bool: ...

    def impersonate(self, address: str) -> None: ...

    def stop_impersonate(self, address: str) -> None: ...

    def call(self, tx: dict[str, Any]) -> EthCallResult: ...

    def send(self, tx: dict[str, Any]) -> str: ...

    def increase_time(self, seconds: int) -> None: ...

    def mine(self) -> None: ...

    def set_balance(self, address: str, value: str) -> None: ...

    def set_storage_at(self, address: str, slot: str, value: str) -> None: ...


def assert_post_cancun(transport: AnvilTransport) -> str:
    """Assert the fork's hardfork carries post-Cancun semantics and return it for
    the transcript (§8.7). Raises ``ValueError`` on a stale fork — a witness minted
    on pre-Cancun semantics is unsafe, so we fail rather than record it."""
    hf = transport.hardfork().strip().lower()
    if hf not in POST_CANCUN_HARDFORKS:
        raise ValueError(
            f"fork hardfork {hf!r} is not post-Cancun ({sorted(POST_CANCUN_HARDFORKS)}) — refusing to probe"
        )
    return hf


def pause_recipe(
    *,
    transport: AnvilTransport,
    store: TranscriptStore,
    ctx: SimContext,
    contract_address: str,
    principal: str,
    pause_calldata: str,
    entry_points: Sequence[EntryPoint],
    predicted_guard_set: Sequence[str],
    max_pause_duration: int | None,
    gate_ref: str = "",
    fixtures: Sequence[ForkFixture] = (),
) -> ObservedEffect:
    """§4.1 freeze/pause: snapshot → record the pre-pause SUCCEEDING entry-point
    set → impersonate principal + call F → re-probe → the newly-reverting set is
    the OBSERVED blast radius (a LOWER bound) → warp time by the source-read
    ``max_pause_duration`` → re-probe for auto-expiry. snapshot/revert isolates
    the probe (inv. 16). The SCORED denominator is static's ``predicted_guard_set``
    (§4.1/§8.8); simulation only upgrades observed members to witnessed tier and
    NEVER becomes the denominator — the pre-pause succeeding set is recorded so
    consumers see it."""
    hardfork = assert_post_cancun(transport)
    ctx = SimContext(
        chain_id=ctx.chain_id,
        block=ctx.block,
        hardfork=hardfork,
        anvil_version=transport.versions().get("anvil"),
        foundry_version=transport.versions().get("foundry"),
    )
    tr = new_transcript(ctx, feature="pause", tier=TIER_FORK, effect_class=EFFECT_CLASS_FREEZE_PAUSE)
    tr["contract_address"] = contract_address.lower()
    tr["predicted_guard_set"] = sorted(predicted_guard_set)
    tr["max_pause_duration"] = max_pause_duration

    snap = transport.snapshot()
    try:
        # Fixtures go inside the snapshot and before the pre-pause probe: an entry
        # point that reverts for an unfunded caller / unmet precondition would
        # silently shrink the observed blast radius (which the diff treats as
        # "pause did not freeze it").
        _apply_fixtures(transport, [*fixtures, *(fx for ep in entry_points for fx in ep.fixtures)], tr)
        pre_succeeding = _succeeding_set(transport, entry_points, contract_address, tr, "pre_pause")

        # §1 A2 probe follow-up — verify the pause can actually take effect before
        # reading the freeze. An ``eth_call`` of the pauser from the principal runs
        # the same EVM logic a ``send`` would, so a revert here means the resolved
        # pauser cannot enact the pause on this forked state (missing authority, an
        # active per-pauser cooldown, an unmet precondition). The freeze was then
        # NEVER TESTED, so an empty blast radius would be INDETERMINATE — reported as
        # its own ``pause_ineffective`` unknown with the raw revert, never conflated
        # with a genuine "pause froze nothing" (the §1 fallback: an empty
        # ``observed_blast_radius`` ≠ no-freeze). This split is what lets the live
        # cycle tell the recoverable ineffective-pause verdicts from the correct
        # no-blast ones instead of seeing one undifferentiated pile of empties.
        pause_probe = transport.call({"from": principal, "to": contract_address, "data": pause_calldata})
        tr["results"].append(
            {"label": "pause_effectiveness", "success": pause_probe.success, "revert": pause_probe.revert_data}
        )
        if not pause_probe.success:
            tr["pause_effective"] = False
            tr["pre_pause_succeeding"] = sorted(pre_succeeding)
            tr["observed_blast_radius"] = []
            return emit(
                store,
                unknown(
                    EFFECT_CLASS_FREEZE_PAUSE,
                    tier=TIER_FORK,
                    scope=SCOPE_PROJECTION,
                    gate_ref=gate_ref,
                    reason="pause_ineffective",
                    details={
                        # The pause call itself REVERTED, so the freeze was never
                        # tested: the empty blast radius below describes a probe
                        # that did not happen, not a pause that froze nothing.
                        "observation": OBSERVATION_REVERTED,
                        "pause_effective": False,
                        "pre_pause_succeeding": sorted(pre_succeeding),
                        "observed_blast_radius": [],
                        "scored_denominator": sorted(str(g) for g in predicted_guard_set),
                    },
                    transcript=tr,
                ),
            )
        tr["pause_effective"] = True

        transport.impersonate(principal)
        try:
            transport.send({"from": principal, "to": contract_address, "data": pause_calldata})
            transport.mine()
        finally:
            transport.stop_impersonate(principal)

        post_succeeding = _succeeding_set(transport, entry_points, contract_address, tr, "post_pause")
        observed_blast = pre_succeeding - post_succeeding

        auto_expiry: bool | None = None
        if max_pause_duration is not None and observed_blast:
            # The caller passes the latch's declared MAXIMUM. The live window is
            # whatever the contract's own duration state (or its MIN fallback)
            # says, which is always ≤ that maximum — so warping past the max is a
            # sound over-warp, and a latch that has NOT expired by then is
            # genuinely indefinite. An indefinite latch passes ``None`` and is
            # never warped at all.
            transport.increase_time(max_pause_duration + 1)
            transport.mine()
            expiry_succeeding = _succeeding_set(transport, entry_points, contract_address, tr, "post_expiry")
            # Auto-expiry proven iff every point the pause froze succeeds again.
            auto_expiry = observed_blast.issubset(expiry_succeeding)
    finally:
        transport.revert(snap)

    tr["pre_pause_succeeding"] = sorted(pre_succeeding)
    tr["observed_blast_radius"] = sorted(observed_blast)
    tr["auto_expiry"] = auto_expiry

    predicted = {str(g) for g in predicted_guard_set}
    # A member observed reverting that static did NOT predict = static under-
    # enumerated its guard set: a §9 discrepancy (vocabulary growth), not a
    # harness failure. The reverse (predicted-but-not-observed) is EXPECTED —
    # business preconditions hide points from the diff — so it is not flagged.
    unpredicted = observed_blast - predicted
    disc = (
        Discrepancy(
            kind="observed_guard_not_predicted",
            effect_class=EFFECT_CLASS_FREEZE_PAUSE,
            detail={"unpredicted_members": sorted(unpredicted)},
        )
        if unpredicted
        else None
    )

    if not observed_blast:
        return emit(
            store,
            unknown(
                EFFECT_CLASS_FREEZE_PAUSE,
                tier=TIER_FORK,
                scope=SCOPE_PROJECTION,
                gate_ref=gate_ref,
                reason="no_blast_radius_observed",
                details={
                    # The pause ran. The empty blast radius below is therefore a
                    # measurement, which is exactly what separates this row from
                    # the reverted one above.
                    "observation": OBSERVATION_EXECUTED,
                    # pause_effective True + empty blast = a GENUINE no-blast: the
                    # pause took effect yet froze nothing observable. This is at the
                    # bar (correct to leave unknown), and distinct from the
                    # pause_ineffective branch above where the freeze was untested.
                    "pause_effective": True,
                    "pre_pause_succeeding": sorted(pre_succeeding),
                    "observed_blast_radius": [],
                    "scored_denominator": sorted(predicted),
                },
                transcript=tr,
                discrepancy=disc,
            ),
        )

    eff = proven(
        EFFECT_CLASS_FREEZE_PAUSE,
        tier=TIER_FORK,
        scope=SCOPE_PROJECTION,
        gate_ref=gate_ref,
        reason="pause_froze_entry_points",
        details={
            "observation": OBSERVATION_EXECUTED,
            # Kernel witness (latch flip caused reverts) + projection witness
            # (which points). The scored denominator stays static's set (§8.8);
            # the observed set is a lower bound recorded alongside it.
            "latch_flip": True,
            "pause_effective": True,
            "observed_blast_radius": sorted(observed_blast),
            "pre_pause_succeeding": sorted(pre_succeeding),
            "scored_denominator": sorted(predicted),
            "auto_expiry": auto_expiry,
            "duration_bound_seconds": max_pause_duration,
        },
        transcript=tr,
    )
    eff.discrepancy = disc
    return emit(store, eff)


def _has_verify_spec(fx: ForkFixture) -> bool:
    return fx.verify_to is not None and fx.verify_calldata is not None and fx.verify_expected is not None


def _apply_fixtures(transport: AnvilTransport, fixtures: Sequence[ForkFixture], transcript: dict[str, Any]) -> None:
    """Apply the fork-state fixtures, recording each in the transcript so a replay
    reproduces the same starting state. A cheatcode that fails is recorded and
    skipped — a missing fixture can only shrink the observed radius (a lower
    bound), never manufacture one.

    Plain fixtures are applied first; storage fixtures carrying a read-back spec
    are applied AFTER so their getter observes the final gas/balance state. Each
    verified write goes under an inner snapshot: if the contract's own getter does
    not echo the seeded word, the write is reverted (never left half-applied) and
    recorded ``readback: failed``. A kept write records ``readback: ok``."""
    plain = [fx for fx in fixtures if not _has_verify_spec(fx)]
    verified = [fx for fx in fixtures if _has_verify_spec(fx)]

    applied: list[dict[str, Any]] = []
    for fx in plain:
        entry: dict[str, Any] = {"kind": fx.kind, "address": fx.address, "slot": fx.slot, "value": fx.value}
        try:
            if fx.kind == "set_balance":
                transport.set_balance(fx.address, fx.value)
            elif fx.kind == "set_storage_at" and fx.slot is not None:
                transport.set_storage_at(fx.address, fx.slot, fx.value)
            else:
                entry["skipped"] = "unknown_kind"
        except Exception as exc:  # noqa: BLE001 - recorded, never fatal
            entry["error"] = str(exc)
        applied.append(entry)

    for fx in verified:
        applied.append(_apply_verified_fixture(transport, fx))

    if applied:
        transcript["fixtures"] = applied


def _apply_verified_fixture(transport: AnvilTransport, fx: ForkFixture) -> dict[str, Any]:
    """Apply one read-back-verified storage fixture. The write is kept only if the
    contract's own getter echoes ``verify_expected`` afterwards (the precondition
    holds — not proof this particular write is what the getter reads; see
    ``ForkFixture``); otherwise the inner snapshot is reverted so the failed write
    leaves no state behind. Never raises."""
    entry: dict[str, Any] = {"kind": fx.kind, "address": fx.address, "slot": fx.slot, "value": fx.value}
    if fx.kind != "set_storage_at" or fx.slot is None:
        entry["skipped"] = "unknown_kind"
        return entry
    inner = transport.snapshot()
    try:
        transport.set_storage_at(fx.address, fx.slot, fx.value)
        res = transport.call({"to": fx.verify_to, "data": fx.verify_calldata})
        ok = res.success and _word_eq(res.return_data, fx.verify_expected)
    except Exception as exc:  # noqa: BLE001 - a failed read-back only drops the fixture
        entry["error"] = str(exc)
        ok = False
    if ok:
        entry["readback"] = "ok"
        return entry
    transport.revert(inner)
    entry["readback"] = "failed"
    logger.info(
        "effects fork: dropped storage fixture at %s slot %s (read-back mismatch)",
        fx.address,
        fx.slot,
    )
    return entry


def _word_eq(return_data: str | None, expected: str | None) -> bool:
    """A direct getter returns exactly one 32-byte word; compare its low 32 bytes
    to the seeded word, ignoring 0x-prefix and case."""
    if not isinstance(return_data, str) or not isinstance(expected, str):
        return False
    got = return_data[2:] if return_data.lower().startswith("0x") else return_data
    want = expected[2:] if expected.lower().startswith("0x") else expected
    if len(got) < 64 or len(want) < 64:
        return False
    return got[-64:].lower() == want[-64:].lower()


def _succeeding_set(
    transport: AnvilTransport,
    entry_points: Sequence[EntryPoint],
    contract_address: str,
    transcript: dict[str, Any],
    label: str,
) -> set[str]:
    succeeding: set[str] = set()
    for ep in entry_points:
        tx: dict[str, Any] = {"to": ep.to or contract_address, "data": ep.calldata}
        if ep.from_addr is not None:
            tx["from"] = ep.from_addr
        res = transport.call(tx)
        transcript["results"].append(
            {"label": label, "entry_point": ep.key, "success": res.success, "revert": res.revert_data}
        )
        if res.success:
            succeeding.add(ep.key)
    return succeeding


# ---------------------------------------------------------------------------
# The single real-I/O transport. Spawns a localhost anvil; NEVER a forking anvil
# or real RPC from an agent (the fork-url path is the user's preview step).
# ---------------------------------------------------------------------------


def _build_anvil_cmd(
    anvil_bin: str,
    port: int,
    hardfork_name: str,
    fork_url: str | None,
    fork_headers: Mapping[str, str] | None,
) -> list[str]:
    cmd = [anvil_bin, "--port", str(port), "--hardfork", hardfork_name, "--silent"]
    if fork_url is not None:
        cmd += ["--fork-url", fork_url]
        # eRPC (the production upstream) authenticates via a header, not the URL —
        # without this the fork upstream is unauthenticated and every lazy
        # getStorageAt/getCode fails. anvil applies each --fork-header to its fork
        # RPC requests.
        for key, value in (fork_headers or {}).items():
            cmd += ["--fork-header", f"{key}: {value}"]
    return cmd


class SubprocessAnvil:
    """Real anvil transport: one subprocess, localhost JSON-RPC (loopback, so the
    netguard allows it). Non-forking by default (offline integration test); a
    ``fork_url`` (+ optional ``fork_headers`` for an authenticated upstream like
    eRPC) is accepted for the user's preview step but agents never pass one.
    """

    def __init__(
        self,
        *,
        port: int = 8546,
        hardfork_name: str = "prague",
        fork_url: str | None = None,
        fork_headers: Mapping[str, str] | None = None,
        anvil_bin: str = "anvil",
        startup_timeout: float = 20.0,
    ) -> None:
        self._url = f"http://127.0.0.1:{port}"
        self._hardfork = hardfork_name
        cmd = _build_anvil_cmd(anvil_bin, port, hardfork_name, fork_url, fork_headers)
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, ValueError) as exc:
            raise AnvilSpawnError(f"failed to spawn anvil: {exc}") from exc
        self._foundry_version = _anvil_version(anvil_bin)
        self._wait_ready(startup_timeout)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def __enter__(self) -> SubprocessAnvil:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def rss_mb(self) -> int:
        """Resident set size of the anvil subprocess in whole MB; 0 if it has
        exited (poll reaps it, so a reused pid is never sampled) or /proc is
        unreadable. Never raises — RSS sampling must not fail a probe."""
        if self._proc.poll() is not None:
            return 0
        return rss_bytes_for_pid(self._proc.pid) // (1024 * 1024)

    def _wait_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise AnvilSpawnError("anvil exited during startup")
            try:
                self._rpc("web3_clientVersion", [])
                return
            except Exception:
                time.sleep(0.1)
        raise ForkRpcTimeoutError("anvil did not become ready in time")

    # -- transport surface -------------------------------------------------

    def hardfork(self) -> str:
        return self._hardfork

    def versions(self) -> dict[str, str]:
        return {"anvil": self._foundry_version, "foundry": self._foundry_version}

    def snapshot(self) -> str:
        return str(self._rpc("evm_snapshot", []))

    def revert(self, snapshot_id: str) -> bool:
        return bool(self._rpc("evm_revert", [snapshot_id]))

    def impersonate(self, address: str) -> None:
        self._rpc("anvil_impersonateAccount", [address])
        # Fund the impersonated account so gas never masks an authorization gate.
        self._rpc("anvil_setBalance", [address, hex(10**19)])

    def stop_impersonate(self, address: str) -> None:
        self._rpc("anvil_stopImpersonatingAccount", [address])

    def call(self, tx: dict[str, Any]) -> EthCallResult:
        try:
            result = self._rpc("eth_call", [tx, "latest"])
        except _RpcError as exc:
            return EthCallResult(False, "0x", exc.revert_data, exc.message)
        return EthCallResult(True, result if isinstance(result, str) else "0x", None, None)

    def send(self, tx: dict[str, Any]) -> str:
        return str(self._rpc("eth_sendTransaction", [tx]))

    def deploy(self, from_addr: str, creation_bytecode: str) -> str:
        """Deploy ``creation_bytecode`` from an unlocked account and return the
        new contract address. Used only by the offline integration test's fixture
        setup on a non-forking anvil."""
        tx_hash = self._rpc("eth_sendTransaction", [{"from": from_addr, "data": creation_bytecode}])
        receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
        return str(receipt["contractAddress"])

    def accounts(self) -> list[str]:
        return list(self._rpc("eth_accounts", []))

    def set_balance(self, address: str, value: str) -> None:
        self._rpc("anvil_setBalance", [address, value])

    def set_storage_at(self, address: str, slot: str, value: str) -> None:
        self._rpc("anvil_setStorageAt", [address, slot, value])

    def increase_time(self, seconds: int) -> None:
        self._rpc("evm_increaseTime", [hex(seconds)])

    def mine(self) -> None:
        self._rpc("evm_mine", [])

    # -- wire --------------------------------------------------------------

    def _rpc(self, method: str, params: list[Any]) -> Any:
        import requests

        try:
            resp = requests.post(
                self._url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException as exc:
            raise ForkRpcTimeoutError(f"anvil rpc {method} failed: {exc}") from exc
        if isinstance(payload, dict) and payload.get("error"):
            err = payload["error"]
            data = err.get("data") if isinstance(err, dict) else None
            revert = data if isinstance(data, str) and data.startswith("0x") else None
            raise _RpcError(str(err.get("message") if isinstance(err, dict) else err), revert)
        return payload.get("result") if isinstance(payload, dict) else None


class _RpcError(Exception):
    def __init__(self, message: str, revert_data: str | None) -> None:
        super().__init__(message)
        self.message = message
        self.revert_data = revert_data


def _anvil_version(anvil_bin: str) -> str:
    try:
        out = subprocess.run([anvil_bin, "--version"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip().splitlines()[0] if out.stdout else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def anvil_available(anvil_bin: str = "anvil") -> bool:
    """Whether a local anvil binary exists — gate for the offline integration
    test so a clone without foundry auto-skips rather than errors."""
    try:
        subprocess.run([anvil_bin, "--version"], capture_output=True, timeout=10, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
