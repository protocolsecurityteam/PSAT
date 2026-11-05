"""Build verified sources and publish versioned formula analyses as an auxiliary artifact."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from services.clients.logic_reads import ChainReads

from .abi_values import abi_signature
from .continuation import PendingCompilation, generate_function
from .expansion import Selection, expand_formula, formula_hash
from .linker import Linker, _Overlay, _selector, special_entry
from .lower import Lowerer
from .model import Limits, ReadError, decode_formula, encode
from .source_context import ContextContracts, build_bundle, build_context
from .terms import const, reset_terms, subterms

logger = logging.getLogger(__name__)


def _hex20(value):
    return f"0x{value:040x}"


def parse_project(project: Path) -> Any:
    """Slither over a scaffolded project, built as the static pipeline builds it (the verified viaIR on a retry). A
    bundle whose code sits under ``script/`` or ``test/`` builds nothing in crytic's default Foundry build, which
    skips those directories, so it gets one build of everything."""
    import json

    from services.static.contract_analysis_pipeline.core import _parse_with_ir_fallback

    try:
        meta = json.loads((project / "contract_meta.json").read_text())
    except (OSError, ValueError):
        meta = {}
    slither = _parse_with_ir_fallback(project, meta)
    for unit in slither.compilation_units:
        unit.context["psat_evm_version"] = meta.get("evm_version_used")
    return slither


class Builds(Mapping):
    """Address -> the Slither contract whose code runs there (a proxy's implementation), built from verified source on
    first use into a temporary project; ``None``-valued for an address with no verified source."""

    def __init__(
        self,
        source: Callable[[str], dict | None],
        implementation: Callable[[str], str | None],
        workdir: Path,
        reads=None,
    ):
        self._source = source
        self._implementation = implementation
        self._workdir = workdir
        self._built: dict[str, Any] = {}
        self.reads = reads
        self.resolved: dict[int, int] = {}
        self._resolving: set[int] = set()
        self.discover = True

    def code_address(self, address: int) -> int:
        if address in self.resolved:
            return self.resolved[address]
        if address in self._resolving:
            return address
        if not self.discover:
            return address
        self._resolving.add(address)
        try:
            target = self._discover_target(address) if self.reads is not None else None
            if target is None:
                own = self.own_code(address) if self.reads is not None else None
                # A metadata implementation pointer does not make a verified contract
                # forward unknown selectors when it has no fallback at all.
                hint = (
                    self._implementation(_hex20(address))
                    if own is None or special_entry(own, "fallback") is not None
                    else None
                )
                target = int(hint, 16) if hint else address
            self.resolved[address] = target
            return target
        finally:
            self._resolving.remove(address)

    def _discover_target(self, address: int, code: int | None = None) -> int | None:
        """Resolve concrete delegate targets from verified fallback IR, without enumerating identities.

        This supplies code locations only. Formula compilation separately proves dispatch for each selector.
        """
        if self.reads is None:
            return None
        code = address if code is None else code
        own = self.own_code(code)
        fallback = special_entry(own, "fallback") if own is not None else None
        if fallback is None:
            return None
        lowerer = Lowerer(own, this=const(address, "address"), code=const(code, "address"))
        lowerer.success(fallback)
        linker = Linker(
            self.reads,
            _Overlay(self, address, own),
            address,
            Limits(),
            lambda other: code if other == address else self.code_address(other),
            own_code=self.own_code,
        )
        delegates = set()
        for exit_ in lowerer.exits:
            delegates.update(subterms(exit_.pc, "delegate"))
            delegates.update(k[1] for k in exit_.store if k[0] == "act" and k[1][0] == "delegate")
        # Discovery supplies an inventory candidate, not a forwarding proof. An
        # upgrade branch with a symbolic future target must not hide the current one.
        targets = {value for d in delegates if (value := linker.concrete(linker.expand(d[1]))) is not None}
        if len(targets) != 1:
            return None
        target = targets.pop()
        return target if target is not None and 0 < target < 2**160 and target != address else None

    def use_saved_locations(self, locations: dict[str, str]) -> None:
        """Expansion uses the code locations captured during generation; it does not re-lower dispatch."""
        self.resolved = {int(at, 16): int(code, 16) for at, code in locations.items()}
        self.discover = False

    def own_code(self, address: int) -> Any:
        """The contract deployed at ``address`` itself, a proxy's own code rather than its implementation's."""
        return self.build(_hex20(address))

    def build(self, hexaddr: str) -> Any:
        hexaddr = hexaddr.lower()
        if hexaddr not in self._built:
            result = self._source(hexaddr)
            if result is None:
                self._built[hexaddr] = None
                return None
            from services.discovery.fetch import scaffold

            project = self._workdir / hexaddr
            scaffold(hexaddr, result, project)
            slither = parse_project(project)
            name = result.get("ContractName")
            contract = next((c for c in slither.contracts if c.name == name and not c.is_interface), None)
            if contract is None:
                raise ReadError(f"verified build does not contain {name}")
            self._built[hexaddr] = contract
        return self._built[hexaddr]

    def __getitem__(self, address: Any) -> Any:
        if not isinstance(address, int):
            raise KeyError(address)
        contract = self.build(_hex20(self.code_address(address)))
        if contract is None:
            raise KeyError(address)
        return contract

    def __contains__(self, address: object) -> bool:
        return isinstance(address, int) and not isinstance(address, bool) and self.get(address) is not None

    def get(self, address: Any, default: Any = None) -> Any:
        if not isinstance(address, int) or isinstance(address, bool):
            return default
        contract = self.build(_hex20(self.code_address(address)))
        return default if contract is None else contract

    def __iter__(self) -> Iterator[Any]:
        return iter(())

    def __len__(self) -> int:
        return 0


def _is_getter(contract: Any, fn: Any) -> bool:
    """An interface declaration (not marked ``view``) that a public state variable implements: a read."""
    return fn.entry_point is None and any(
        v.name == fn.name and v.visibility == "public" for v in contract.state_variables
    )


@contextmanager
def _deployment_inputs(session: Session, chain_id: int, rpc_url: str, block: int | None):
    from db.models import Contract, Job
    from services.clients.etherscan import VerifiedSourceUnavailable
    from services.clients.rpc import rpc_request
    from services.discovery.fetch import fetch

    def rpc(method, params):
        return rpc_request(rpc_url, method, params, retries=0, chain_id=chain_id)

    def source(hexaddr):
        # Acquisition failures must propagate; they are not evidence of unverified code.
        try:
            result = fetch(hexaddr, chain_id=chain_id)
        except VerifiedSourceUnavailable:
            return None
        return result if isinstance(result, dict) and result.get("SourceCode") else None

    if block is None:
        raw = rpc("eth_blockNumber", [])
        if not isinstance(raw, str):
            raise ReadError("block number unanswered")
        block = int(raw, 16)
    debug_url = os.getenv(f"PSAT_DEBUG_RPC_URL_{chain_id}") or (os.getenv("QUICK_NODE_ETH") if chain_id == 1 else None)

    def debug_rpc(method, params):
        return rpc_request(debug_url or rpc_url, method, params, retries=0, chain_id=chain_id)

    from services.clients.logic_trace import trace_hash_preimages

    def trace_reader(method, params):
        return trace_hash_preimages(
            debug_url or rpc_url, method, params, chain_id=chain_id, word_limit=chain.word_limit
        )

    chain = ChainReads(rpc, block, debug=debug_rpc if debug_url else None, trace_reader=trace_reader)
    implementations = {}

    def implementation(hexaddr):
        # Discovery metadata is a code-location hint, never a proof of proxy dispatch: compile_function
        # verifies it from the proxy's own fallback and the implementation it reads at the block.
        if hexaddr not in implementations:
            row = session.execute(
                select(Contract.implementation)
                .join(Job, Contract.job_id == Job.id)
                .where(
                    func.lower(Contract.address) == hexaddr,
                    Job.chain_id == chain_id,
                    Contract.implementation.isnot(None),
                )
                .order_by(Contract.id.desc())
                .limit(1)
            ).first()
            implementations[hexaddr] = row[0].lower() if row and row[0] else None
        return implementations[hexaddr]

    workdir = Path(tempfile.mkdtemp(prefix="psat_formula_"))
    try:
        builds = Builds(source, implementation, workdir, chain)
        yield chain, builds
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def deployment_formulas(
    session: Session,
    address: str,
    chain_id: int,
    rpc_url: str,
    *,
    signatures: set[str] | None = None,
    block: int | None = None,
    related_addresses: tuple[str, ...] | None = None,
    context_chars: int | None = None,
    expansion_steps: int = 5000,
    loop_iterations: int = 32,
    callee_depth: int = 8,
    value_steps: int = 50_000,
    resume: dict | None = None,
) -> dict[str, Any]:
    """Generate formulas only. No holder enumeration or address-set queries are scheduled."""
    scope = resume.get("generation_scope", {}) if resume is not None else {}
    if related_addresses is None:
        related_addresses = tuple(scope.get("related_addresses", ()))
    if context_chars is None:
        context_chars = scope.get("context_chars", 48_000)
    if resume is not None and signatures is None and scope.get("signatures") is not None:
        signatures = set(scope["signatures"])
    if not isinstance(context_chars, int) or context_chars <= 0 or len(related_addresses) > 32:
        raise ValueError("positive context size and at most 32 explicit related addresses required")
    if resume is not None:
        if (resume.get("kind"), resume.get("chain_id"), resume.get("address", "").lower()) != (
            "formulas",
            chain_id,
            address.lower(),
        ):
            raise ValueError("generation resume identity mismatch")
        if block is not None and block != resume["block"]:
            raise ValueError("generation resume block mismatch")
        if not resume.get("pending_functions"):
            raise ValueError("generation has no pending functions")
        block = resume["block"]
        previous_scope = resume.get("generation_scope", {})
        if previous_scope != {
            "signatures": sorted(signatures) if signatures is not None else None,
            "related_addresses": sorted(related_addresses),
            "context_chars": context_chars,
        }:
            raise ValueError("generation resume scope mismatch")
    related = set()
    for value in related_addresses:
        address_value = int(value, 16)
        if not 0 < address_value < 2**160:
            raise ValueError("invalid related address")
        related.add(address_value)
    with _deployment_inputs(session, chain_id, rpc_url, block) as (chain, builds):
        at = int(address, 16)
        header = {"schema": 2, "kind": "formulas", "chain_id": chain_id, "address": address, "block": chain.block}
        contract = builds.get(at)
        if contract is None:
            return {**header, "status": "not_verified", "functions": {}}
        out, contexts, compiled = {}, {}, {}
        pending = {}
        previous = resume.get("pending_functions", {}) if resume is not None else {}
        finished = resume.get("functions", {}) if resume is not None else {}
        associated, missing = {at: contract}, set()
        own = builds.own_code(at)
        primary_code = builds.code_address(at)
        # Follow code while keeping storage at this deployment. Earlier layers own
        # selector collisions; each deeper entry still needs its full dispatch proof.
        layers = [(at, own)] if own is not None else []
        if primary_code != at or not layers:
            layers.append((primary_code, contract))
        seen_codes = {code for code, _ in layers}
        current = primary_code
        # Discover the finite, cycle-checked inventory before spending per-function
        # proof depth, so a depth cut produces a resumable function, not a missing one.
        while special_entry(layers[-1][1], "fallback") is not None:
            target = builds._discover_target(at, current)
            if target is None or target in seen_codes:
                break
            child = builds.own_code(target)
            if child is None:
                missing.add(target)
                break
            layers.append((target, child))
            seen_codes.add(target)
            current = target
        entries, claimed = [], set()
        for code, owner in layers:
            # Getters first: a public state variable overrides a same-signature base function.
            getters = {_selector(abi_signature(v)) for v in owner.state_variables if v.visibility == "public"}
            for fn in owner.functions_entry_points:
                if fn.is_shadowed:  # overridden fallback/receive, which Slither keeps listed
                    continue
                sig = abi_signature(fn)
                key = sig if fn.is_fallback or fn.is_receive else _selector(sig)
                if key not in claimed and key not in getters:
                    entries.append((fn, owner, code))
                    claimed.add(key)
            claimed.update(getters)
        if resume is not None and (set(previous) | set(finished)) != {
            abi_signature(fn)
            for fn, owner, entry_code in entries
            if not (fn.is_constructor or not abi_signature(fn))
            and (signatures is None or abi_signature(fn) in signatures)
            and not _is_getter(owner, fn)
        }:
            raise ValueError("generation resume entrypoints changed")
        entry_codes, code_contexts = {}, {}
        for fn, entry_contract, entry_code in entries:
            if fn.is_constructor or not abi_signature(fn) or _is_getter(entry_contract, fn):
                continue
            if signatures is not None and abi_signature(fn) not in signatures:
                continue
            reset_terms()
            source_view = _Overlay(builds, at, entry_contract)
            tracked = ContextContracts(source_view, at, entry_contract)

            def code_of(other, selected=entry_code):
                return selected if other == at else builds.code_address(other)

            signature = abi_signature(fn)
            if signature in finished:
                formula = decode_formula(finished[signature])
            else:
                formula = generate_function(
                    entry_contract,
                    fn,
                    at,
                    chain,
                    tracked,
                    Limits(callee_depth=callee_depth),
                    code_of=code_of,
                    own_code=builds.own_code,
                    steps=expansion_steps,
                    loop_iterations=loop_iterations,
                    value_steps=value_steps,
                    checkpoint=previous.get(signature, {}).get("checkpoint"),
                )
            entry_codes[signature] = _hex20(entry_code)
            if isinstance(formula, PendingCompilation):
                from dataclasses import asdict

                pending[signature] = asdict(formula)
            else:
                out[signature] = encode(formula)
                compiled[signature] = (formula, fn)
            associated.update(tracked.used)
            code_contexts.update(tracked.code_contexts)
            associated[at] = contract
            missing.update(tracked.missing)
        # Keep the context of completed functions when resuming only their unfinished siblings.
        if resume is not None:
            related.update(int(a, 16) for a in resume.get("code_locations", {}))
            missing.update(int(a, 16) for a in resume.get("source_scope", {}).get("unverified_addresses", ()))
            for context in resume.get("source_bundle", {}).get("deployments", ()):
                storage_address, code = int(context["address"], 16), int(context["code_address"], 16)
                source = builds.own_code(code)
                if source is None:
                    missing.add(code)
                else:
                    code_contexts[storage_address, code] = source
        for other in sorted(related - associated.keys()):
            found = builds.get(other)
            if found is None:
                missing.add(other)
            else:
                associated[other] = found
        code_addresses = {other: builds.code_address(other) for other in associated}
        bundle = build_bundle(
            associated,
            max_chars=context_chars,
            code_addresses=code_addresses,
            code_contexts={
                **code_contexts,
                **{
                    (other, other): builds.own_code(other)
                    for other, code in code_addresses.items()
                    if other != code and builds.own_code(other) is not None
                },
                **{(at, code): owner for code, owner in layers},
            },
            missing_sources=tuple(f"unverified:{other:#x}" for other in sorted(missing)),
        )
        for signature, (formula, fn) in compiled.items():
            contexts[signature] = build_context(formula, fn, bundle)
        return {
            **header,
            "functions": out,
            "pending_functions": pending,
            "status": "incomplete" if pending else "available",
            "generation_scope": {
                "signatures": sorted(signatures) if signatures is not None else None,
                "related_addresses": sorted(related_addresses),
                "context_chars": context_chars,
            },
            "code_locations": {_hex20(other): _hex20(code) for other, code in code_addresses.items()},
            "entry_code_addresses": entry_codes,
            "contexts": contexts,
            "source_bundle": bundle,
            "source_scope": {
                "discovery": "callees followed while compiling selected entrypoints, plus explicit related addresses",
                "related_addresses": [_hex20(other) for other in sorted(related)],
                "unverified_addresses": [_hex20(other) for other in sorted(missing)],
                "context_chars": context_chars,
                "complete_dependency_graph": False,
            },
        }


def saved_contracts(artifact: dict, signature: str, builds):
    """The layout/code view captured for this saved entry, shared by assessment and expansion."""
    if not isinstance(builds, Builds):
        return builds
    if "code_locations" not in artifact or "entry_code_addresses" not in artifact:
        raise ValueError("regenerate legacy formula artifact: saved code locations are missing")
    builds.use_saved_locations(artifact["code_locations"])
    address = int(artifact["address"], 16)
    code = artifact.get("entry_code_addresses", {}).get(signature)
    if code is None:
        raise ValueError(f"saved entry code is missing: {signature}")
    return _Overlay(builds, address, builds.own_code(int(code, 16)))


def deployment_expansions(
    session: Session, artifact: dict, rpc_url: str, selections: Mapping[str, Selection], *, limits: Limits = Limits()
) -> dict[str, Any]:
    """Expand only explicitly selected saved functions/effects, preserving the input artifact."""
    if artifact.get("schema") != 2 or artifact.get("kind") != "formulas":
        raise ValueError("expected a formula-only artifact")
    if not selections:
        raise ValueError("select at least one function or effect to expand")
    chain_id, block = artifact["chain_id"], artifact["block"]
    if type(chain_id) is not int or chain_id <= 0 or type(block) is not int or block < 0:
        raise ValueError("invalid artifact chain or block")
    address = int(artifact["address"], 16)
    chosen = {}
    # Validate the whole request before obtaining a provider or spending any reads.
    for signature, selection in selections.items():
        if signature not in artifact["functions"]:
            raise ValueError(f"function not present in artifact: {signature}")
        formula = decode_formula(artifact["functions"][signature])
        if (formula.address, formula.block, formula.signature) != (address, block, signature):
            raise ValueError("formula identity does not match artifact")
        selection.validate(formula)
        chosen[signature] = formula
    out = {}
    with _deployment_inputs(session, chain_id, rpc_url, block) as (reads, builds):
        for signature, formula in chosen.items():
            view = saved_contracts(artifact, signature, builds)
            accounting = {}
            result = expand_formula(
                formula, reads, view, selection=selections[signature], limits=limits, accounting=accounting
            )
            out[signature] = {
                "formula_hash": formula_hash(formula),
                "expansion": encode(result),
                "storage_accounting": accounting,
            }
    return {
        "schema": 2,
        "kind": "address_expansions",
        "storage_steps": limits.storage_steps,
        "chain_id": chain_id,
        "address": artifact["address"],
        "block": block,
        "functions": out,
    }
