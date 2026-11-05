"""Yul text, as Solidity before 0.6 leaves inline assembly to Slither: parsed into statements whose expressions are
nested builtin calls, so the lowering can follow them like any other code instead of matching patterns.

Only straight-line code is read: ``let`` and assignments, nested blocks, and calls as statements. Control flow
(``if``, ``for``, ``switch``, functions) raises ``Unsupported``, and the caller retains the
assembly as an unfinished operation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class Unsupported(Exception):
    """Yul this reader doesn't follow."""


@dataclass(frozen=True)
class Call:
    name: str
    args: tuple


@dataclass(frozen=True)
class Name:
    name: str


@dataclass(frozen=True)
class Number:
    value: int


@dataclass(frozen=True)
class Assign:
    targets: tuple[str, ...]
    value: object | None  # ``let x`` alone: zero
    declared: bool = False


@dataclass(frozen=True)
class Block:
    statements: tuple


@dataclass(frozen=True)
class Effect:
    call: Call


_TOKEN = re.compile(
    r"\s+|//[^\n]*|/\*.*?\*/|(?P<num>0x[0-9a-fA-F]+|\d+)|(?P<str>\"(?:[^\"\\]|\\.)*\")|"
    r"(?P<id>[A-Za-z_$][\w$.]*)|(?P<op>:=|[{}(),:])",
    re.S,
)
_CONTROL = frozenset({"if", "for", "switch", "case", "default", "function", "break", "continue", "leave"})


def _tokens(text: str) -> list[tuple[str, str]]:
    out, at = [], 0
    while at < len(text):
        found = _TOKEN.match(text, at)
        if found is None:
            raise Unsupported(f"unreadable at {text[at : at + 20]!r}")
        at = found.end()
        for kind in ("num", "str", "id", "op"):
            if found.group(kind) is not None:
                out.append((kind, found.group(kind)))
                break
    return out


def parse(text: str) -> list:
    """The statements of an assembly block's text (its braces optional), in order, nested lexical blocks preserved."""
    tokens = _tokens(text)
    at = [0]

    def peek(offset: int = 0) -> tuple[str, str] | None:
        i = at[0] + offset
        return tokens[i] if i < len(tokens) else None

    def take(expected: str | None = None) -> tuple[str, str]:
        token = peek()
        if token is None or (expected is not None and token[1] != expected):
            raise Unsupported(f"expected {expected!r}, got {token!r}")
        at[0] += 1
        return token

    def expression():
        kind, value = take()
        if kind == "num":
            return Number(int(value, 0))
        if kind == "str":
            raise Unsupported("string literal")
        if kind == "id" and value in ("true", "false"):
            return Number(int(value == "true"))
        if kind != "id" or value in _CONTROL:
            raise Unsupported(f"expression at {value!r}")
        if (next_token := peek()) is not None and next_token[1] == "(":
            take("(")
            args = []
            while (next_token := peek()) is not None and next_token[1] != ")":
                args.append(expression())
                if (next_token := peek()) is not None and next_token[1] == ",":
                    take(",")
            take(")")
            return Call(value, tuple(args))
        return Name(value)

    def statements(until: str | None) -> list:
        out: list = []
        while (next_token := peek()) is not None and (until is None or next_token[1] != until):
            kind, value = next_token
            if value == "{":
                take("{")
                out.append(Block(tuple(statements("}"))))
                take("}")
            elif value in _CONTROL:
                raise Unsupported(value)
            elif value == "let":
                take("let")
                names = [take()[1]]
                while (next_token := peek()) is not None and next_token[1] == ",":
                    take(",")
                    names.append(take()[1])
                if (next_token := peek()) is not None and next_token[1] == ":=":
                    take(":=")
                    out.append(Assign(tuple(names), expression(), declared=True))
                else:
                    out.append(Assign(tuple(names), None, declared=True))
            elif kind == "id" and (following := peek(1)) is not None and following[1] in (":=", ","):
                names = [take()[1]]
                while (next_token := peek()) is not None and next_token[1] == ",":
                    take(",")
                    names.append(take()[1])
                take(":=")
                out.append(Assign(tuple(names), expression()))
            else:
                call = expression()
                if not isinstance(call, Call):
                    raise Unsupported("a bare value as a statement")
                out.append(Effect(call))
        return out

    parsed = statements(None)
    if at[0] != len(tokens):
        raise Unsupported("trailing tokens")
    return parsed
