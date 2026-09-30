"""Fail if any changed .py file differs from BASE in more than comments/docstrings.

Usage: uv run python scripts/check_prose_only.py [BASE]   (default: origin/main)
"""

import ast
import subprocess
import sys


def _strip(tree: ast.AST) -> str:
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) or not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            body = body[1:]
        # A docstring-only body needs a placeholder once the docstring goes.
        only = body[0] if len(body) == 1 else None
        if isinstance(only, ast.Pass) or (
            isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant) and only.value.value is ...
        ):
            body = []
        node.body = body
    return ast.dump(tree, include_attributes=False)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    changed = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=M", base, "--", "*.py"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    bad = []
    for path in changed:
        old = subprocess.run(["git", "show", f"{base}:{path}"], capture_output=True, text=True, check=True).stdout
        with open(path) as f:
            new = f.read()
        if _strip(ast.parse(old)) != _strip(ast.parse(new)):
            bad.append(path)
    for path in bad:
        print(f"code changed: {path}")
    print(f"{len(changed) - len(bad)}/{len(changed)} files prose-only")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
