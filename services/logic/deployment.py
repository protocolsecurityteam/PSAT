"""The logic engine over one deployment: build the code that runs there and at every address its checks reach, read
the chain at one block, take event history from the indexed log table, and decide each state-changing function."""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .decide import LOG_ROWS, Chain, batch_results
from .terms import reset_terms
from .verdict import function_verdict

logger = logging.getLogger(__name__)

# Words read for the fallback "every event this address emitted" candidate scan.
ALL_LOG_ROWS = 20_000
# Blocks the indexer may trail the decision's block by and still count as holding the history (about an hour).
INDEX_LAG = 300
# Seconds one whole-history ``eth_getLogs`` may take: a short history answers in one or two, a busy one never does.
HISTORY_TIMEOUT = 5.0


class IndexedChain(Chain):
    """Chain reads at one block; logs from ``indexed_event_logs`` instead of ``eth_getLogs`` over all history."""

    def __init__(self, session: Session, chain_id: int, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.session = session
        self.chain_id = chain_id

    def _creation(self, address: int) -> Any:
        """The address's ``getcontractcreation`` record (Postgres-cached), or ``None``."""
        key = ("creation_record", address)
        if key not in self._memo:
            from services.clients.etherscan import get, parse_creation_record

            try:
                data = get("contract", "getcontractcreation", chain_id=self.chain_id, contractaddresses=_hex20(address))
            except Exception as exc:
                if isinstance(exc, TimeoutError):
                    raise
                data = {}
            records = [parse_creation_record(item) for item in (data.get("result") or [])]
            self._memo[key] = next((r for r in records if r is not None and r.address == _hex20(address)), None)
        return self._memo[key]

    def creation_block(self, address: int) -> int | None:
        record = self._creation(address)
        return record.block if record is not None else None

    def creation_tx(self, address: int) -> str | None:
        record = self._creation(address)
        return record.tx_hash if record is not None else None

    def _rows(self, where: str, params: dict, order: str, limit: int) -> list:
        sql = f"select topics, data_words from indexed_event_logs where {where} order by {order} limit :n"
        return list(self.session.execute(text(sql), {**params, "n": limit}))

    def covered(self, address: int, topics: frozenset[str] | None = None) -> bool:
        """Whether the indexer holds the address's whole history of ``topics`` (any, when ``None``) up to near the
        block: backfilled from deployment and advanced to within ``INDEX_LAG`` blocks of it."""
        key = ("db_cover", address, topics)
        if key not in self._memo:
            where = "chain_id = :c and event_address = :a" + (" and topic0 = any(:t)" if topics else "")
            sql = f"select topic0, backfill_complete, last_indexed_block from indexed_event_cursors where {where}"
            params = {"c": self.chain_id, "a": _hex20(address), "t": sorted(topics or ())}
            rows = list(self.session.execute(text(sql), params))
            ready = {t for t, done, last in rows if done and last is not None and last >= self.block - INDEX_LAG}
            wanted = set(topics) if topics else {t for t, _, _ in rows}
            self._memo[key] = bool(wanted) and wanted <= ready
        return self._memo[key]

    def logs(self, address: int, topics: frozenset[str]) -> list[tuple[list[int], list[int]]]:
        if not topics:
            return []
        covered = self.covered(address, topics)
        key = ("db_logs", address, topics)
        if key not in self._memo:
            params = {"c": self.chain_id, "a": _hex20(address), "t": sorted(topics), "b": self.block}
            where = "chain_id = :c and event_address = :a and topic0 = any(:t) and block_number <= :b"
            rows = self._rows(where, params, "block_number, log_index", LOG_ROWS + 1)
            if len(rows) > LOG_ROWS:
                # Too long to read whole: the earliest half (deployment-time grants) and the latest.
                late = self._rows(where, params, "block_number desc, log_index desc", LOG_ROWS // 2)
                rows = rows[: LOG_ROWS // 2] + late[::-1]
                self.truncated.add(address)
            if not covered and not rows:
                return super().logs(address, topics)  # never indexed: the chain's own history (usually short)
            if not covered:
                self.truncated.add(address)  # indexing unfinished or behind: what it holds, marked partial
            self._memo[key] = [(_words(t), _words(d)) for t, d in rows]
        return self._memo[key]

    def all_log_words(self, address: int) -> set[int]:
        key = ("db_all", address)
        if key not in self._memo and not self.covered(address):
            self.truncated.add(address)  # words of a history the indexer doesn't hold: some are missing
        if key not in self._memo:
            params = {"c": self.chain_id, "a": _hex20(address), "b": self.block}
            rows = self._rows(
                "chain_id = :c and event_address = :a and block_number <= :b", params, "block_number", ALL_LOG_ROWS
            )
            if len(rows) >= ALL_LOG_ROWS:
                self.truncated.add(address)
            words: set[int] = set()
            for topics, data in rows:
                words.update(_words(topics)[1:])
                words.update(_words(data))
            self._memo[key] = words
        return self._memo[key]


def _hex20(value: int) -> str:
    return "0x" + format(value % 2**160, "040x")


def _words(values: list | None) -> list[int]:
    out = []
    for value in values or []:
        try:
            out.append(int(value, 16))
        except (TypeError, ValueError):
            out.append(0)
    return out


def parse_project(project: Path) -> Any:
    """Slither over a scaffolded project, built as the static pipeline builds it (the verified viaIR on a retry). A
    bundle whose code sits under ``script/`` or ``test/`` builds nothing in crytic's default Foundry build, which
    skips those directories, so it gets one build of everything."""
    import json

    from slither import Slither

    from services.static.contract_analysis_pipeline.core import _parse_with_ir_fallback

    try:
        meta = json.loads((project / "contract_meta.json").read_text())
    except (OSError, ValueError):
        meta = {}
    try:
        return _parse_with_ir_fallback(project, meta)
    except Exception as exc:
        if isinstance(exc, TimeoutError) or not (project / "foundry.toml").exists():
            raise
        return Slither(str(project), foundry_compile_all=True)


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
            self._built[hexaddr] = None
            result = self._source(hexaddr)
            if result is None:
                return None
            from services.discovery.fetch import scaffold

            project = self._workdir / hexaddr
            try:
                scaffold(hexaddr, result, project)
                slither = parse_project(project)
            except Exception as exc:  # an unbuildable dependency is an unanalysed one, not a failed decision
                if isinstance(exc, TimeoutError):
                    raise
                logger.info("logic engine: no build for %s: %s", hexaddr, exc)
                return None
            name = result.get("ContractName")
            self._built[hexaddr] = next((c for c in slither.contracts if c.name == name and not c.is_interface), None)
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
        try:
            return self[address]
        except KeyError:
            return default

    def __iter__(self) -> Iterator[Any]:
        return iter(())

    def __len__(self) -> int:
        return 0


def deployment_verdicts(
    session: Session,
    address: str,
    chain_id: int,
    rpc_url: str,
    *,
    signatures: set[str] | None = None,
    block: int | None = None,
) -> dict[str, Any]:
    """Each state-changing function of the deployment at ``address``: openness, the principals singled out, whether
    that list is complete, and the arguments that let each through. Pinned to one block."""
    from db.models import Contract
    from services.clients.rpc import rpc_batch_request_classified, rpc_request
    from services.discovery.fetch import fetch

    def rpc(method: str, params: list) -> Any:
        return rpc_request(rpc_url, method, params, retries=2, chain_id=chain_id)

    def history(method: str, params: list) -> Any:
        limit = {"timeout": HISTORY_TIMEOUT, "total_timeout": HISTORY_TIMEOUT}
        return rpc_request(rpc_url, method, params, retries=0, chain_id=chain_id, **limit)

    def batch(calls: list[tuple[str, list]]) -> list[Any]:
        return batch_results(rpc_batch_request_classified(rpc_url, calls, chain_id=chain_id, keep_errors=True))

    def source(hexaddr: str) -> dict | None:
        try:
            result = fetch(hexaddr, chain_id=chain_id)
        except Exception as exc:
            if isinstance(exc, TimeoutError):
                raise
            return None
        return result if isinstance(result, dict) and result.get("SourceCode") else None

    implementations: dict[str, str | None] = {}

    def implementation(hexaddr: str) -> str | None:
        if hexaddr not in implementations:
            row = session.execute(
                select(Contract.implementation)
                .where(func.lower(Contract.address) == hexaddr, Contract.implementation.isnot(None))
                .limit(1)
            ).first()
            implementations[hexaddr] = row[0].lower() if row and row[0] else None
        return implementations[hexaddr]

    if block is None:
        block = int(rpc("eth_blockNumber", []), 16)
    workdir = Path(tempfile.mkdtemp(prefix="psat_logic_"))
    try:
        builds = Builds(source, implementation, workdir)
        deployment = int(address, 16)
        contract = builds.get(deployment)
        if contract is None:
            return {"block": block, "error": "no verified source", "functions": {}}
        out: dict[str, Any] = {}
        reset_terms()
        chain = IndexedChain(session, chain_id, rpc, block, batch, history)
        for fn in contract.functions_entry_points:
            if fn.view or fn.pure or fn.is_constructor or not fn.solidity_signature or _is_getter(contract, fn):
                continue
            if signatures is not None and fn.solidity_signature not in signatures:
                continue
            started = time.monotonic()
            try:
                verdict, _ = function_verdict(contract, fn, deployment, chain, builds, {}, builds.code_address)
            except Exception as exc:
                if isinstance(exc, TimeoutError):
                    raise
                out[fn.solidity_signature] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
                continue
            out[fn.solidity_signature] = {
                "openness": verdict.openness,
                "principals": sorted(_hex20(p) for p in verdict.principals),
                # Singled out by who they are; their call shown to pass only with these conditions freed.
                "conditional": {_hex20(p): freed for p, freed in sorted(verdict.conditions.items())},
                "signers": sorted(_hex20(p) for p in verdict.signers),
                "complete": verdict.complete,
                "allowed": verdict.allowed if verdict.openness == "open" else None,
                "after": [{"function": sig, "arguments": _jsonable(args)} for sig, args in verdict.after],
                "requires": [
                    {"contract": _hex20(at) if at is not None else None, "holding": what, "least": need}
                    for at, what, need in verdict.requires
                ],
                "gaps": list(verdict.gaps),
                "undecided": len(verdict.undecided),
                "witnesses": {_hex20(who): _jsonable(args) for who, args in verdict.witnesses.items()},
                "seconds": round(time.monotonic() - started, 3),
            }
        return {"block": block, "functions": out}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _jsonable(values: dict[str, Any]) -> dict[str, Any]:
    return {k: (str(v) if isinstance(v, int) and not isinstance(v, bool) else v) for k, v in values.items()}


def _is_getter(contract: Any, fn: Any) -> bool:
    """An interface declaration (not marked ``view``) that a public state variable implements: a read."""
    return fn.entry_point is None and any(
        v.name == fn.name and v.visibility == "public" for v in contract.state_variables
    )
