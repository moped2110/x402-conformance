"""Enforce one-line-or-better docstrings on production and executable helpers."""

from __future__ import annotations

import argparse
import ast
from collections.abc import Iterable, Sequence
from pathlib import Path

DEFAULT_ROOTS = (Path("src"), Path("tools"))


def iter_python_files(roots: Iterable[Path]) -> list[Path]:
    """Return every Python source below the requested roots in stable path order."""
    return sorted(path for root in roots for path in root.rglob("*.py") if path.is_file())


def missing_function_docstrings(path: Path) -> list[tuple[int, str]]:
    """Return line/name pairs for all sync or async functions lacking a docstring."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    function_nodes = (
        node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    return [
        (node.lineno, node.name)
        for node in function_nodes
        if not (ast.get_docstring(node, clean=False) or "").strip()
    ]


def check_function_docs(roots: Iterable[Path] = DEFAULT_ROOTS) -> list[str]:
    """Collect actionable diagnostics for undocumented functions below the roots."""
    return [
        f"{path.as_posix()}:{line}: {name} is missing a docstring"
        for path in iter_python_files(roots)
        for line, name in missing_function_docstrings(path)
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the documentation gate and return a shell-friendly success status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", type=Path, default=list(DEFAULT_ROOTS))
    args = parser.parse_args(argv)
    issues = check_function_docs(args.roots)
    if issues:
        print("\n".join(issues))
        print(f"Function documentation check failed: {len(issues)} issue(s).")
        return 1
    print("Function documentation check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
