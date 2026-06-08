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

from sqlalchemy import func, select

from db.models import AuditReport, Contract, Job, JobStatus
from services.chat.data import (
    contract_brief,
    list_protocol_principals,
    live_findings,
    protocol_brief,
    role_holders,
    upgrade_summary,
)
from utils.rpc import require_supported_chain_id

logger = logging.getLogger("services.chat.tools")

MAX_SOURCE_CHARS = 30_000


# ── Tool implementations ────────────────────────────────────────────────


def _get_protocol_info(session, ctx, **_kwargs) -> dict[str, Any]:
    return protocol_brief(session, ctx.company)


def _get_contract_info(session, ctx, address: str | None = None, chain_id: int | None = None, **_kw) -> dict[str, Any]:
    addr = address or ctx.selected_address
    chain_id = _effective_chain_id(ctx, chain_id, context=f"chat contract info for {addr or 'selected contract'}")
    if not addr:
        return {"error": "address is required (or select a contract on the canvas)"}
    return contract_brief(session, addr, chain_id=chain_id)


def _source_row_content(row) -> str:
    """Resolve a SourceFile row to its raw content body. Inline content
    wins; ``storage_key`` falls back to object storage. Empty string on
    any failure (caller decides what to do)."""
    from db.storage import get_storage_client

    if row.content:
        return row.content
    if row.storage_key:
        try:
            client = get_storage_client()
            if client is None:
                return ""
            body = client.get(row.storage_key)
            return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
        except Exception as exc:
            logger.warning("storage fetch failed for %s: %s", row.storage_key, exc)
    return ""


def _source_rows_for_contract(session, source_file_model, contract: Contract) -> list[Any]:
    chain_id = require_supported_chain_id(
        chain_id=contract.chain_id,
        context=f"chat source lookup for contract {contract.id}",
    )
    source_job_id = session.execute(
        select(Job.id)
        .join(source_file_model, source_file_model.job_id == Job.id)
        .where(
            func.lower(Job.address) == contract.address.lower(),
            Job.chain_id == chain_id,
            ~Job.status.in_((JobStatus.failed, JobStatus.failed_terminal)),
        )
        .order_by(Job.updated_at.desc(), Job.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if source_job_id is None:
        return []
    return list(session.execute(select(source_file_model).where(source_file_model.job_id == source_job_id)).scalars())


def _effective_chain_id(ctx: Any, chain_id: int | None = None, *, context: str = "chat tool") -> int | None:
    if chain_id is not None:
        return require_supported_chain_id(chain_id=chain_id, context=context)
    selected = getattr(ctx, "selected_chain_id", None)
    if selected is not None:
        return require_supported_chain_id(chain_id=selected, context=f"{context} selected contract")
    return None


def _get_contract_source(
    session, ctx, address: str | None = None, chain_id: int | None = None, file: str | None = None, **_kw
) -> dict[str, Any]:
    """Return verified source code for a contract.

    Reads indexed ``SourceFile`` rows for the contract's job. If a row has
    inline ``content`` we use it directly; otherwise we fetch the body from
    object storage via ``storage_key``. Missing indexed source is reported as
    unavailable instead of fetching from a secondary source.
    """
    from db.models import SourceFile

    addr = address or ctx.selected_address
    chain_id = _effective_chain_id(ctx, chain_id, context=f"chat source lookup for {addr or 'selected contract'}")
    if not addr:
        return {"error": "address is required"}
    try:
        chain_id = require_supported_chain_id(chain_id=chain_id, context=f"chat source lookup for {addr}")
    except RuntimeError as exc:
        return {"error": str(exc), "address": addr}

    stmt = select(Contract).where(func.lower(Contract.address) == addr.lower(), Contract.chain_id == chain_id)
    contract = session.execute(stmt.limit(1)).scalar_one_or_none()
    if contract is None:
        return {"error": f"contract not found: {addr} on chain_id={chain_id}"}

    rows = _source_rows_for_contract(session, SourceFile, contract)

    if not rows:
        return {"error": f"no indexed source rows available for {addr} on chain_id={chain_id}"}
    files: list[tuple[str, str]] = [(r.path, body) for r in rows if (body := _source_row_content(r))]
    if not files:
        logger.warning("indexed source content unavailable for %s chain_id=%s", addr, chain_id)
        return {"error": f"indexed source content unavailable for {addr} on chain_id={chain_id}"}

    file_list = [{"name": p, "size": len(b) if b else None} for p, b in files]

    if file:
        target = next(((p, b) for p, b in files if p == file), None)
        if target is None:
            return {"files": file_list, "error": f"file {file!r} not found"}
        return {"files": file_list, "requested": target[0], "source": _truncate(target[1])}

    # Default: largest file (typically the top-level contract).
    files_sorted = sorted(files, key=lambda kv: -len(kv[1] or ""))
    main_path, main_body = files_sorted[0]
    return {"files": file_list, "requested": main_path, "source": _truncate(main_body)}


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
    chain_id: int | None = None,
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

        chain_id = _effective_chain_id(ctx, chain_id, context=f"chat source search for {target_addr}")
        try:
            chain_id = require_supported_chain_id(chain_id=chain_id, context=f"chat source search for {target_addr}")
        except RuntimeError as exc:
            return {"error": str(exc), "pattern": pattern, "matches": [], "summary": [], "scope_contracts": 0}
        stmt = select(Contract).where(
            _func.lower(Contract.address) == target_addr.lower(),
            Contract.chain_id == chain_id,
        )
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

    for contract in contracts:
        rows = _source_rows_for_contract(session, SourceFile, contract)
        if not rows:
            contracts_with_no_source += 1
            continue
        for row in rows:
            content = _source_row_content(row)
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

    return {
        "pattern": pattern,
        "case_sensitive": case_sensitive,
        "scope_contracts": len(contracts),
        "contracts_with_no_source": contracts_with_no_source,
        "total_matches": total_matches,
        "summary": summary,
        "matches": matches,
        "truncated": len(matches) >= max_results and total_matches > max_results,
    }


def _get_contract_overview(
    session,
    ctx,
    address: str | None = None,
    chain_id: int | None = None,
    **_kw,
) -> dict[str, Any]:
    """One-shot fetch combining identity, controls, upgrade summary, and
    verified source. Saves a tool round-trip when the agent wants the
    full picture of a single contract."""
    addr = address or ctx.selected_address
    chain_id = _effective_chain_id(ctx, chain_id, context=f"chat contract overview for {addr or 'selected contract'}")
    if not addr:
        return {"error": "address is required"}
    info = contract_brief(session, addr, chain_id=chain_id)
    upgrades = upgrade_summary(session, addr, chain_id=chain_id) if not info.get("error") else None
    src = _get_contract_source(session, ctx, address=addr, chain_id=chain_id)
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


def _get_upgrade_history(
    session,
    ctx,
    address: str | None = None,
    chain_id: int | None = None,
    **_kw,
) -> dict[str, Any]:
    addr = address or ctx.selected_address
    chain_id = _effective_chain_id(ctx, chain_id, context=f"chat upgrade history for {addr or 'selected contract'}")
    if not addr:
        return {"error": "address is required"}
    return upgrade_summary(session, addr, chain_id=chain_id)


def _get_audit_findings(
    session,
    ctx,
    address: str | None = None,
    chain_id: int | None = None,
    **_kw,
) -> dict[str, Any]:
    return live_findings(
        session,
        address=address,
        chain_id=_effective_chain_id(ctx, chain_id, context=f"chat audit findings for {address}") if address else None,
        company=ctx.company,
        limit=10,
    )


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


def _chain_id_param() -> dict[str, Any]:
    return {
        "type": "integer",
        "description": "EIP-155 chain id. Required unless the selected contract already supplies one.",
    }


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
                "properties": {"address": _addr_param(), "chain_id": _chain_id_param()},
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
                    "chain_id": _chain_id_param(),
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
                    "chain_id": _chain_id_param(),
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
                "properties": {"address": _addr_param(), "chain_id": _chain_id_param()},
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
                "properties": {"address": _addr_param(), "chain_id": _chain_id_param()},
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
                "return protocol-wide findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {"address": _addr_param(), "chain_id": _chain_id_param()},
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
                "Map every protocol role to its typed holders with thresholds, delays, and function counts. "
                "For governance-risk questions, call with no role_name first; pass role_name only to expand "
                "one role from the summary."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "role_name": {
                        "type": "string",
                        "description": (
                            "Specific role to expand, e.g. 'PROTOCOL_PAUSER'. Usually omit; the no-arg "
                            "summary already inlines holders."
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
