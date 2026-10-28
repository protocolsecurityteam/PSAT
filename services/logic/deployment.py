"""Build verified sources and publish versioned formula analyses as an auxiliary artifact."""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from services.clients.logic_reads import ChainReads

from .formula import analyze_function
from .model import ReadError, encode
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


def deployment_formulas(
    session: Session,
    address: str,
    chain_id: int,
    rpc_url: str,
    *,
    signatures: set[str] | None = None,
    block: int | None = None,
) -> dict[str, Any]:
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
        at = int(address, 16)
        contract = builds.get(at)
        if contract is None:
            return {
                "schema": 2,
                "chain_id": chain_id,
                "address": address,
                "block": block,
                "status": "not_verified",
                "functions": {},
            }
        out = {}
        for fn in contract.functions_entry_points:
            if fn.view or fn.pure or fn.is_constructor or not fn.solidity_signature or _is_getter(contract, fn):
                continue
            if signatures is not None and fn.solidity_signature not in signatures:
                continue
            reset_terms()
            result = analyze_function(contract, fn, at, chain, builds, code_of=builds.code_address)
            out[fn.solidity_signature] = encode(result)
        return {"schema": 2, "chain_id": chain_id, "address": address, "block": block, "functions": out}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
