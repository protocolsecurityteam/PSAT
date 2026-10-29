"""Build verified sources and publish versioned formula analyses as an auxiliary artifact."""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from services.clients.logic_reads import ChainReads

from .expansion import Selection, expand_formula, formula_hash
from .formula import compile_function
from .model import Limits, ReadError, decode_formula, encode
from .source_context import ContextContracts, build_bundle, build_context
from .terms import reset_terms

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
    return _parse_with_ir_fallback(project, meta)


class Builds(Mapping):
    """Address -> the Slither contract whose code runs there (a proxy's implementation), built from verified source on
    first use into a temporary project; ``None``-valued for an address with no verified source."""

    def __init__(
        self,
        source: Callable[[str], dict | None],
        implementation: Callable[[str], str | None],
        workdir: Path,
    ):
        self._source = source
        self._implementation = implementation
        self._workdir = workdir
        self._built: dict[str, Any] = {}

    def code_address(self, address: int) -> int:
        hexaddr = _hex20(address)
        impl = self._implementation(hexaddr)
        return int(impl, 16) if impl else address

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
    from services.clients.rpc import rpc_request
    from services.discovery.fetch import fetch

    def rpc(method, params):
        return rpc_request(rpc_url, method, params, retries=0, chain_id=chain_id)

    def source(hexaddr):
        # Acquisition failures must propagate; they are not evidence of unverified code.
        result = fetch(hexaddr, chain_id=chain_id)
        return result if isinstance(result, dict) and result.get("SourceCode") else None

    if block is None:
        raw = rpc("eth_blockNumber", [])
        if not isinstance(raw, str):
            raise ReadError("block number unanswered")
        block = int(raw, 16)
    chain = ChainReads(rpc, block)
    implementations = {}

    def implementation(hexaddr):
        # Discovery metadata is a code-location hint, never a proof of proxy dispatch.
        # compile_function marks this explicitly until dispatch is verified from the proxy code.
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
        builds = Builds(source, implementation, workdir)
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
    related_addresses: tuple[str, ...] = (),
    context_chars: int = 48_000,
) -> dict[str, Any]:
    """Generate formulas only. No holder enumeration or address-set queries are scheduled."""
    if context_chars <= 0 or len(related_addresses) > 32:
        raise ValueError("positive context size and at most 32 explicit related addresses required")
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
        associated, missing = {at: contract}, set()
        for fn in contract.functions_entry_points:
            if fn.view or fn.pure or fn.is_constructor or not fn.solidity_signature or _is_getter(contract, fn):
                continue
            if signatures is not None and fn.solidity_signature not in signatures:
                continue
            reset_terms()
            tracked = ContextContracts(builds, at, contract)
            formula = compile_function(contract, fn, at, chain, tracked, code_of=builds.code_address)
            out[fn.solidity_signature] = encode(formula)
            compiled[fn.solidity_signature] = (formula, fn)
            associated.update(tracked.used)
            missing.update(tracked.missing)
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
            missing_sources=tuple(f"unverified:{other:#x}" for other in sorted(missing)),
        )
        for signature, (formula, fn) in compiled.items():
            contexts[signature] = build_context(formula, fn, bundle)
        return {
            **header,
            "functions": out,
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
            result = expand_formula(formula, reads, builds, selection=selections[signature], limits=limits)
            out[signature] = {"formula_hash": formula_hash(formula), "expansion": encode(result)}
    return {
        "schema": 2,
        "kind": "address_expansions",
        "chain_id": chain_id,
        "address": artifact["address"],
        "block": block,
        "functions": out,
    }
