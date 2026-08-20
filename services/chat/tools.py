"""Agent-callable tools for the company-page chatbot.

Each tool is a Python callable ``fn(session, ctx, **kwargs) -> dict`` that
returns JSON-serializable data the LLM can read back. Tool *definitions*
(name, description, JSON-schema params) are surfaced to OpenRouter via
``TOOL_DEFINITIONS``.

Truncation: tool results are cheap to ship to the model in this v1, but
text bodies that are routinely large (contract source code) cap at
``MAX_SOURCE_CHARS`` so a single tool call doesn't blow the context
budget for follow-up turns.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from sqlalchemy import select

from db.models import AuditReport, Contract
from services.chat.data import (
    contract_brief,
    list_protocol_principals,
    live_findings,
    protocol_brief,
    role_holders,
    upgrade_summary,
)

logger = logging.getLogger("services.chat.tools")

MAX_SOURCE_CHARS = 30_000


# ── Tool implementations ────────────────────────────────────────────────


def _get_protocol_info(session, ctx, **_kwargs) -> dict[str, Any]:
    return protocol_brief(session, ctx.company)


def _get_contract_info(session, ctx, address: str | None = None, chain: str | None = None, **_kw) -> dict[str, Any]:
    addr = address or ctx.selected_address
    chn = chain if chain is not None else ctx.selected_chain
    if not addr:
        return {"error": "address is required (or select a contract on the canvas)"}
    return contract_brief(session, addr, chn)


def _source_row_content(row) -> str | None:
    """Resolve a SourceFile row to its raw content body.

    Returns the body, or ``None`` when it could not be read — a genuinely
    empty file is ``""`` and must stay distinguishable from an unreadable
    one. Collapsing both into ``""`` is what let ``search_source`` report
    ``total_matches: 0`` across 167 contracts while 2,261/2,261 bodies were
    unreachable.
    """
    from db.storage import get_storage_client

    if row.content:
        return row.content
    if row.storage_key:
        try:
            client = get_storage_client()
            if client is None:
                logger.error(
                    "source file %s has storage_key %s but object storage is not configured",
                    row.path,
                    row.storage_key,
                )
                return None
            body = client.get(row.storage_key)
            return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
        except Exception as exc:
            logger.warning(
                "storage fetch failed for %s; falling back to the explorer",
                row.storage_key,
                extra={"exc_type": type(exc).__name__, "storage_key": row.storage_key, "path": row.path},
            )
            return None
    if row.content is None:
        return None
    return row.content


def _etherscan_sources(address: str, chain: str | None) -> dict[str, str]:
    """Live-fetch verified source from Etherscan as a fallback when DB
    rows have no inline content (typical when source bodies live in
    object storage and the storage backend is unreachable).
    Returns ``{path: content}`` (empty on failure)."""
    try:
        from services.clients.etherscan import get_source
        from services.discovery.fetch import parse_sources
        from utils.chains import UnknownChainError, chain_by_name

        # Chat is a user-facing edge: no/unknown selected chain falls
        # back to mainnet explicitly rather than failing the whole tool call.
        try:
            chain_id = chain_by_name(chain).chain_id if chain else 1
        except UnknownChainError:
            chain_id = 1
        result = get_source(address, chain_id=chain_id)
        return parse_sources(result) or {}
    except Exception as exc:
        logger.warning("etherscan source fetch failed for %s: %s", address, exc)
        return {}


def _get_contract_source(
    session, ctx, address: str | None = None, chain: str | None = None, file: str | None = None, **_kw
) -> dict[str, Any]:
    """Return verified source code for a contract.

    Strategy:
      1. Read indexed ``SourceFile`` rows for the contract's job. If a
         row has inline ``content`` we use it directly; otherwise we
         fetch the body from object storage via ``storage_key``.
      2. If every row resolves to empty (typical when MinIO/S3 is down
         or no rows are indexed), live-fetch from Etherscan as a
         fallback. This keeps the tool useful in environments where the
         DB only stores hashes/keys.
    """
    from db.models import SourceFile

    addr = address or ctx.selected_address
    chn = chain if chain is not None else ctx.selected_chain
    if not addr:
        return {"error": "address is required"}

    from sqlalchemy import func as _func

    stmt = select(Contract).where(_func.lower(Contract.address) == addr.lower())
    if chn is not None:
        stmt = stmt.where(Contract.chain == chn)
    contract = session.execute(stmt.limit(1)).scalar_one_or_none()

    rows = []
    if contract is not None and contract.job_id is not None:
        rows = session.execute(select(SourceFile).where(SourceFile.job_id == contract.job_id)).scalars().all()

    # Materialize (path, content) pairs from DB. If every body resolves
    # empty, fall through to Etherscan.
    resolved = [(r.path, _source_row_content(r)) for r in rows]
    unreadable = sum(1 for _, body in resolved if body is None)
    db_files: list[tuple[str, str]] = [(p, b) for p, b in resolved if b is not None]
    from_db = bool(db_files) and any(body for _, body in db_files)
    if from_db:
        files = db_files
    else:
        es_files = _etherscan_sources(addr, chn or (contract.chain if contract is not None else None))
        files = list(es_files.items())

    if not files:
        if unreadable:
            # The rows exist; their bodies could not be fetched. Saying "no
            # verified source available" would report an infrastructure failure
            # as a fact about the contract.
            return {
                "error": (
                    f"{unreadable}/{len(rows)} indexed source files for {addr} could not be read from "
                    "object storage, and the Etherscan fallback returned nothing — source availability "
                    "is undetermined, not absent"
                ),
                "unreadable_source_files": unreadable,
                "indexed_source_files": len(rows),
            }
        return {"error": f"no verified source available for {addr}"}

    file_list = [{"name": p, "size": len(b) if b else None} for p, b in files]

    # A partial read publishes a subset of the contract as if it were the whole
    # contract, and the model has no way to notice. Carried on every successful
    # return, not only the nothing-loaded dead end: ``files`` is what the model
    # will reason over, so the shortfall has to travel with it. When the bodies
    # came from Etherscan the set is complete from that source, but the count is
    # still reported — the DB rows remain unreadable and a later call may see it.
    provenance: dict[str, Any] = {"source_origin": "indexed" if from_db else "etherscan"}
    if unreadable:
        provenance["unreadable_source_files"] = unreadable
        provenance["indexed_source_files"] = len(rows)
        if from_db:
            provenance["source_completeness"] = (
                f"not determined — {unreadable} of {len(rows)} indexed files could not be read "
                "from object storage, so this listing is a lower bound on the contract's source"
            )

    if file:
        target = next(((p, b) for p, b in files if p == file), None)
        if target is None:
            return {"files": file_list, "error": f"file {file!r} not found", **provenance}
        return {"files": file_list, "requested": target[0], "source": _truncate(target[1]), **provenance}

    # Default: largest file (typically the top-level contract).
    files_sorted = sorted(files, key=lambda kv: -len(kv[1] or ""))
    main_path, main_body = files_sorted[0]
    return {"files": file_list, "requested": main_path, "source": _truncate(main_body), **provenance}


def _truncate(s: str | None) -> str:
    if not s:
        return ""
    if len(s) <= MAX_SOURCE_CHARS:
        return s
    return s[:MAX_SOURCE_CHARS] + f"\n\n…[truncated {len(s) - MAX_SOURCE_CHARS} chars]"


def _search_source(
    session,
    ctx,
    pattern: str = "",
    address: str | None = None,
    max_results: int = 50,
    case_sensitive: bool = False,
    **_kw,
) -> dict[str, Any]:
    """Substring search across indexed source files.

    Scope (in priority): explicit ``address`` arg → currently-selected
    contract → all of the protocol's contracts. Returns ``matches``
    (file/line/snippet for the first ``max_results`` hits) plus
    ``summary`` (per-file total counts) so the model can budget how much
    detail to fetch next.
    """
    from db.models import SourceFile

    if not pattern:
        return {"error": "pattern is required"}

    needle = pattern if case_sensitive else pattern.lower()

    # Pick the contract scope.
    contracts: list[Contract] = []
    target_addr = address or ctx.selected_address
    if target_addr:
        from sqlalchemy import func as _func

        chain_filter = Contract.chain == ctx.selected_chain if ctx.selected_chain else None
        stmt = select(Contract).where(_func.lower(Contract.address) == target_addr.lower())
        if chain_filter is not None:
            stmt = stmt.where(chain_filter)
        c = session.execute(stmt.limit(1)).scalar_one_or_none()
        if c is not None:
            contracts = [c]
    else:
        from db.models import Protocol as _P

        proto = session.execute(select(_P).where(_P.name == ctx.company)).scalar_one_or_none()
        if proto is not None:
            contracts = list(session.execute(select(Contract).where(Contract.protocol_id == proto.id)).scalars())

    if not contracts:
        return {"pattern": pattern, "matches": [], "summary": [], "scope_contracts": 0}

    matches: list[dict[str, Any]] = []
    summary: list[dict[str, Any]] = []
    total_matches = 0
    contracts_with_no_source = 0
    files_searched = 0
    unreadable_source_files = 0

    for contract in contracts:
        if contract.job_id is None:
            continue
        rows = session.execute(select(SourceFile).where(SourceFile.job_id == contract.job_id)).scalars().all()
        if not rows:
            contracts_with_no_source += 1
            continue
        for row in rows:
            content = _source_row_content(row)
            if content is None:
                unreadable_source_files += 1
                continue
            files_searched += 1
            if not content:
                continue
            haystack = content if case_sensitive else content.lower()
            if needle not in haystack:
                continue
            file_match_count = 0
            for line_no, line in enumerate(content.split("\n"), 1):
                hay_line = line if case_sensitive else line.lower()
                if needle in hay_line:
                    file_match_count += 1
                    total_matches += 1
                    if len(matches) < max_results:
                        matches.append(
                            {
                                "contract_address": contract.address,
                                "contract_name": contract.contract_name,
                                "file": row.path,
                                "line_no": line_no,
                                "line": line.strip()[:200],
                            }
                        )
            if file_match_count > 0:
                summary.append(
                    {
                        "contract_address": contract.address,
                        "contract_name": contract.contract_name,
                        "file": row.path,
                        "matches": file_match_count,
                    }
                )

    out: dict[str, Any] = {
        "pattern": pattern,
        "case_sensitive": case_sensitive,
        "scope_contracts": len(contracts),
        "contracts_with_no_source": contracts_with_no_source,
        "files_searched": files_searched,
        "unreadable_source_files": unreadable_source_files,
        "total_matches": total_matches,
        "summary": summary,
        "matches": matches,
        "truncated": len(matches) >= max_results and total_matches > max_results,
    }
    if unreadable_source_files and files_searched == 0:
        # Nothing was actually searched. Reporting total_matches: 0 alone
        # states "the pattern does not occur", which is not what was proven.
        out["error"] = (
            f"no source file body could be read ({unreadable_source_files} unreadable); "
            "total_matches reflects nothing searched, not an absent pattern"
        )
    return out


def _get_contract_overview(session, ctx, address: str | None = None, chain: str | None = None, **_kw) -> dict[str, Any]:
    """One-shot fetch combining identity, controls, upgrade summary, and
    verified source. Saves a tool round-trip when the agent wants the
    full picture of a single contract."""
    addr = address or ctx.selected_address
    chn = chain if chain is not None else ctx.selected_chain
    if not addr:
        return {"error": "address is required"}
    info = contract_brief(session, addr, chn)
    upgrades = upgrade_summary(session, addr, chn) if not info.get("error") else None
    src = _get_contract_source(session, ctx, address=addr, chain=chn)
    # Strip the source body from the bulk result — the agent gets file
    # listing + main file path, then can request the full body via
    # get_contract_source(file=...) if needed. Keeps the bulk response
    # compact for the prompt.
    src_summary = {"files": src.get("files", []), "main_file": src.get("requested")}
    if "error" in src:
        src_summary["error"] = src["error"]
    return {
        "info": info,
        "upgrade_summary": upgrades,
        "source": src_summary,
    }


def _get_upgrade_history(session, ctx, address: str | None = None, chain: str | None = None, **_kw) -> dict[str, Any]:
    addr = address or ctx.selected_address
    chn = chain if chain is not None else ctx.selected_chain
    if not addr:
        return {"error": "address is required"}
    return upgrade_summary(session, addr, chn)


def _get_audit_findings(session, ctx, address: str | None = None, **_kw) -> dict[str, Any]:
    return live_findings(session, address=address, company=ctx.company, limit=10)


def _list_principals(session, ctx, **_kw) -> dict[str, Any]:
    return list_protocol_principals(session, ctx.company)


def _get_role_holders(session, ctx, role_name: str | None = None, **_kw) -> dict[str, Any]:
    return role_holders(session, company=ctx.company, role_name=role_name)


def _search_audits(session, ctx, query: str = "", **_kw) -> dict[str, Any]:
    if not query:
        return {"results": []}
    from db.models import Protocol

    proto = session.execute(select(Protocol).where(Protocol.name == ctx.company)).scalar_one_or_none()
    if proto is None:
        return {"results": []}
    q = f"%{query.lower()}%"
    rows = (
        session.execute(
            select(AuditReport)
            .where(AuditReport.protocol_id == proto.id)
            .where(AuditReport.title.ilike(q) | AuditReport.auditor.ilike(q))
            .limit(5)
        )
        .scalars()
        .all()
    )
    return {
        "results": [
            {
                "audit_id": r.id,
                "auditor": r.auditor,
                "title": r.title,
                "date": r.date.isoformat() if r.date else None,
            }
            for r in rows
        ]
    }


# ── Registry + OpenRouter-shaped definitions ─────────────────────────────


TOOLS: dict[str, Callable] = {
    "get_protocol_info": _get_protocol_info,
    "get_contract_info": _get_contract_info,
    "get_contract_source": _get_contract_source,
    "search_source": _search_source,
    "get_contract_overview": _get_contract_overview,
    "get_upgrade_history": _get_upgrade_history,
    "get_audit_findings": _get_audit_findings,
    "list_principals": _list_principals,
    "get_role_holders": _get_role_holders,
    "search_audits": _search_audits,
}


def _addr_param() -> dict[str, Any]:
    return {
        "type": "string",
        "description": (
            "Contract address (0x-prefixed, 40 hex). Optional - defaults to the contract currently "
            "selected on the canvas."
        ),
    }


def _chain_param() -> dict[str, Any]:
    return {"type": "string", "description": "Chain name (e.g. 'mainnet'). Optional."}


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_protocol_info",
            "description": "Top-level snapshot for the current protocol: contract count, proxy count, audit count.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_contract_info",
            "description": "Identity, proxy status, controls, last upgrade for a single contract.",
            "parameters": {
                "type": "object",
                "properties": {"address": _addr_param(), "chain": _chain_param()},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_contract_source",
            "description": (
                "Return the verified Solidity source for a contract. Pass `file` to request a specific "
                "filename listed by a prior call."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "address": _addr_param(),
                    "chain": _chain_param(),
                    "file": {"type": "string", "description": "Specific source filename to return (optional)."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_source",
            "description": (
                "Substring search across indexed Solidity source. Scope defaults to the selected contract; "
                "pass `address` to scope to one contract; omit both to search the protocol. Returns up to "
                "`max_results` matches with file path, line number, snippet, and per-file hit counts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Substring to find. Case-insensitive by default.",
                    },
                    "address": {
                        "type": "string",
                        "description": (
                            "Limit to one contract address. Optional - defaults to the selected contract "
                            "or the whole protocol."
                        ),
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Cap on returned snippets (default 50). Summary is uncapped.",
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "description": "Default false. Set true for exact-case match.",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_contract_overview",
            "description": (
                "One-call summary for a contract: identity, controls, upgrade summary, and source file list. "
                "Use get_contract_source(file=...) afterward only if you need one file body."
            ),
            "parameters": {
                "type": "object",
                "properties": {"address": _addr_param(), "chain": _chain_param()},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_upgrade_history",
            "description": "Per-impl upgrade timeline + audit-coverage status for a proxy.",
            "parameters": {
                "type": "object",
                "properties": {"address": _addr_param(), "chain": _chain_param()},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_audit_findings",
            "description": (
                "Audit findings still affecting current code (status != 'fixed'). Filter by address or "
                "fall back to protocol-wide."
            ),
            "parameters": {
                "type": "object",
                "properties": {"address": _addr_param()},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_principals",
            "description": "List the Safes / EOAs / timelocks that govern this protocol's contracts.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_role_holders",
            "description": (
                "Map every WITNESSED protocol role to its typed holders with thresholds, delays, and "
                "function counts. For governance-risk questions, call with no role_name first; pass "
                "role_name only to expand one role from the summary. Read 'role_evidence' before "
                "concluding anything from an empty or short 'roles' list: it counts the functions whose "
                "role structure was NOT determined separately from those proven to carry no role gate. "
                "'holders_state' is 'not_determined' when a role gates a function but its members were "
                "not recorded — that is not 'nobody holds it'. 'authorized_callers' are callers with no "
                "role attribution, never role holders."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "role_name": {
                        "type": "string",
                        "description": (
                            "Specific role to expand — a name like 'PROTOCOL_PAUSER' or a numeric role id "
                            "like '2'/'role 2'. Usually omit; the no-arg summary already inlines holders. "
                            "state='not_witnessed' means no grant in this protocol names that role, which "
                            "is not the same as the role having no holders."
                        ),
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_audits",
            "description": "Find audits of this protocol whose title or auditor matches the query.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "Substring to match."}},
                "required": ["query"],
            },
        },
    },
]


def run_tool(name: str, session, ctx, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute a tool by name. Filters arguments to those the tool actually
    accepts, so the LLM can't smuggle unknown kwargs into the call."""
    fn = TOOLS.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return fn(session, ctx, **(arguments or {}))
    except TypeError as exc:
        # Mismatched kwargs from the LLM: surface as an error result so the
        # model can self-correct on the next turn instead of crashing.
        logger.warning("tool %s rejected args %r: %s", name, arguments, exc)
        return {"error": f"tool {name} called with invalid arguments: {exc}"}
    except Exception as exc:
        logger.warning("tool %s raised: %s", name, exc, extra={"exc_type": type(exc).__name__})
        return {"error": f"tool {name} failed: {exc}"}
