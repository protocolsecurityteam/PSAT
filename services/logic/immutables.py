"""Where a contract's immutables sit in its deployed code.

The compiler writes each immutable's value into the runtime bytecode at fixed offsets and records them in the build
artifact (``deployedBytecode.immutableReferences``, keyed by the declaration's AST id). Joining those ids to the
declarations by source position names each offset, so a value with no getter is still one ``eth_getCode`` away.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def immutable_offsets(contract: Any) -> dict[str, tuple[int, ...]]:
    """Immutable name -> byte offsets of its 32-byte value in ``contract``'s deployed code; empty when the build left
    no artifact to read (a platform other than Foundry, or a contract with no immutables)."""
    if not hasattr(contract, "_psat_immutable_offsets"):
        try:
            contract._psat_immutable_offsets = _offsets(contract)
        except (OSError, ValueError, KeyError, AttributeError):
            contract._psat_immutable_offsets = {}
    return contract._psat_immutable_offsets


def immutable_value(code: bytes, offsets: tuple[int, ...]) -> int | None:
    """The value the code holds at every one of ``offsets``; ``None`` when they disagree or fall outside it (the
    code isn't the one compiled)."""
    words = {int.from_bytes(code[o : o + 32], "big") for o in offsets if o + 32 <= len(code)}
    if len(words) != 1 or any(o + 32 > len(code) for o in offsets):
        return None
    return words.pop()


def _offsets(contract: Any) -> dict[str, tuple[int, ...]]:
    # Declared along the whole inheritance chain: ``state_variables`` leaves out a parent's private ones.
    immutables = [
        v
        for declaring in [contract, *contract.inheritance]
        for v in declaring.state_variables_declared
        if getattr(v, "is_immutable", False)
    ]
    if not immutables:
        return {}
    out_dir = _out_dir(contract)
    if out_dir is None:
        return {}
    source = contract.source_mapping.filename.absolute
    artifact = next(
        (
            data
            for path in sorted(out_dir.glob(f"*/{contract.name}*.json"))
            for data in [json.loads(path.read_text())]
            if source.endswith(str(data.get("ast", {}).get("absolutePath", "\0")))
        ),
        None,
    )
    if artifact is None:
        return {}
    references = artifact.get("deployedBytecode", {}).get("immutableReferences") or {}
    declarations = {i: d for i, d in _declarations(out_dir).items() if i in references}
    out: dict[str, tuple[int, ...]] = {}
    for var in immutables:
        mapping = var.source_mapping
        for ast_id, (path, start, length) in declarations.items():
            if (start, length) == (mapping.start, mapping.length) and mapping.filename.absolute.endswith(path):
                out[var.name] = tuple(entry["start"] for entry in references[ast_id])
    return out


def _out_dir(contract: Any) -> Path | None:
    root = Path(contract.compilation_unit.crytic_compile.target).resolve()
    if root.is_file():
        root = root.parent
    out = "out"
    config = root / "foundry.toml"
    if config.exists():
        found = re.search(r'^\s*out\s*=\s*"([^"]+)"', config.read_text(), re.MULTILINE)
        out = found.group(1) if found else out
    path = root / out
    return path if path.is_dir() else None


_DECLARATIONS: dict[Path, dict[str, tuple[str, int, int]]] = {}
_DECLARES_IMMUTABLE = re.compile(r'"mutability"\s*:\s*"immutable"')
_ABSOLUTE_PATH = re.compile(r'"ast"\s*:\s*\{\s*"absolutePath"\s*:\s*"([^"]*)"')


def _declarations(out_dir: Path) -> dict[str, tuple[str, int, int]]:
    """AST id -> (source path, start, length) of every immutable declared in the build, from each artifact's AST (an
    inherited immutable is declared in its own file). Read once per build."""
    if out_dir in _DECLARATIONS:
        return _DECLARATIONS[out_dir]
    found: dict[str, tuple[str, int, int]] = {}
    read: set[str] = set()
    for path in sorted(out_dir.glob("*/*.json")):
        try:
            text = path.read_text()
            # Most artifacts declare no immutable, and every contract of a file repeats that file's whole AST:
            # parsing is what costs (a gigabyte build takes half a minute), so only what declares one, once per
            # source file.
            if not _DECLARES_IMMUTABLE.search(text):
                continue
            named = _ABSOLUTE_PATH.search(text)
            if named is not None and named.group(1) in read:
                continue
            ast = json.loads(text).get("ast")
        except (OSError, ValueError):
            continue
        if not isinstance(ast, dict):
            continue
        source = str(ast.get("absolutePath", ""))
        if source in read:
            continue
        read.add(source)
        stack: list[Any] = [ast]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                if node.get("nodeType") == "VariableDeclaration" and node.get("mutability") == "immutable":
                    start, length, *_ = (int(x) for x in str(node["src"]).split(":"))
                    found[str(node["id"])] = (source, start, length)
                stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
            elif isinstance(node, list):
                stack.extend(node)
    _DECLARATIONS[out_dir] = found
    return found
