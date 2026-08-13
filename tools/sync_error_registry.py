#!/usr/bin/env python3
"""Regenerate ``src/x402_conformance/error_registry.py`` from an upstream clone.

Why this exists
---------------
``FA-ERR-001`` fails a facilitator whose ``invalidReason`` is not in
``KNOWN_ERROR_CODES``. For a long time that set could be maintained by hand,
because upstream funnelled every wire code through one Zod enum
(``ErrorReasons`` in ``typescript/packages/legacy/x402/.../x402Specs.ts``).

The package split ended that. The enum still exists, still validates, and still
has 41 entries — but it lives under ``legacy/`` and upstream no longer adds to
it. Current mechanisms declare their own codes and return them directly, so the
enum now describes a shrinking minority of what a conformant facilitator can
legitimately put on the wire. Tracking ~344 codes across 28 files by hand is not
maintainable, and getting it wrong is not a missing feature — it is us failing a
correct implementation.

So: generate, commit, and diff. The generated module is reviewed like any other
source file, and ``tests/test_error_reason_drift.py`` re-runs this extraction
against a live clone to catch the next split.

Usage
-----
    python tools/sync_error_registry.py --upstream /path/to/x402      # rewrite
    python tools/sync_error_registry.py --upstream /path/to/x402 --check

``--check`` exits non-zero when the committed module is stale, without writing.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path

#: How an error code is declared, per language. Each pattern must capture the
#: wire string (group 2) — the identifier (group 1) is matched only to avoid
#: sweeping up unrelated string constants.
_PATTERNS: dict[str, re.Pattern[str]] = {
    # `export const ErrFoo = "..."`, allowing prettier's wrap before the value.
    ".ts": re.compile(r'export const (Err\w+)\s*=\s*\n?\s*"([a-z0-9_]+)"'),
    # Go const blocks: `ErrFoo = "..."` (aliases to another const are skipped,
    # since the pattern requires a string literal — the alias target is picked
    # up at its own declaration site).
    ".go": re.compile(r'\b(Err\w+)\s*=\s*"([a-z0-9_]+)"'),
    ".py": re.compile(r'\b(ERR_\w+)\s*=\s*"([a-z0-9_]+)"'),
}

# What this deliberately does NOT collect
# ---------------------------------------
# Upstream also has reasons that look exactly like wire codes and are not:
# `unsupported_payment_flow`, `unsupported_asset_transfer_method`,
# `missing_scheme`, `missing_facilitator`. Those are `RouteValidationError`
# values, raised when a resource server *starts up* with a route it cannot serve
# (go/http/server.go, packages/core/src/http/x402HTTPResourceServer.ts). They are
# never carried on a VerifyResponse or SettleResponse.
#
# They are missed by the patterns below because they are inline string literals
# and union members rather than exported constants — which is luck, not design,
# so this note is the design. FA-ERR-001 fails a facilitator whose invalidReason
# is outside KNOWN_ERROR_CODES; widening that set with codes that can never
# legitimately reach a client makes the check accept things it should catch. If a
# future pattern starts matching them, exclude them explicitly rather than
# letting them in.

#: Path fragments that never hold a shipped declaration. Tests in particular
#: assert on *invalid* codes, which must not enter the accepted vocabulary.
_EXCLUDED = (
    "node_modules",
    "/dist/",
    "/build/",
    "/.next/",
    "/examples/",
    "_test.",
    "/tests/",
    "/test/",
    ".test.",
    ".spec.",
)

_HEADER = '''"""Wire error codes declared by upstream x402 mechanisms.

GENERATED FILE — do not edit by hand. Regenerate with::

    python tools/sync_error_registry.py --upstream /path/to/x402

Why this is separate from ``SPEC_ERROR_REASONS``: that set is the legacy
``ErrorReasons`` Zod enum, which upstream froze under ``legacy/`` and stopped
extending. These are the codes current mechanisms declare and return directly.
``FA-ERR-001`` accepts the union, because a facilitator built on today's
packages returns codes from *both* halves and failing it for that would be our
bug, not its.

Extracted from {source_count} declaring files in the upstream tree; see
``tools/sync_error_registry.py`` for the declaration patterns and exclusions.
"""

from __future__ import annotations

'''


def _iter_sources(upstream: Path) -> Iterable[Path]:
    """Yield every upstream file that may declare wire error codes."""
    for path in sorted(upstream.rglob("*")):
        if path.suffix not in _PATTERNS or not path.is_file():
            continue
        rel = "/" + str(path.relative_to(upstream)).replace("\\", "/")
        if any(fragment in rel for fragment in _EXCLUDED):
            continue
        yield path


def extract(upstream: Path) -> dict[str, set[str]]:
    """Map each declaring file (upstream-relative) to the wire codes it declares."""
    found: dict[str, set[str]] = {}
    for path in _iter_sources(upstream):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        codes = {m.group(2) for m in _PATTERNS[path.suffix].finditer(text)}
        if codes:
            found[str(path.relative_to(upstream)).replace("\\", "/")] = codes
    return found


def render(by_file: dict[str, set[str]]) -> str:
    """Render the generated module: codes grouped by declaring file, sorted."""
    all_codes = sorted(set().union(*by_file.values()) if by_file else set())
    out = [_HEADER.format(source_count=len(by_file))]
    out.append("#: Every wire error code declared outside the legacy `ErrorReasons` enum.\n")
    out.append(f"#: {len(all_codes)} codes from {len(by_file)} files.\n")
    out.append("MECHANISM_ERROR_CODES = frozenset(\n    {\n")
    # Group by declaring file so a diff shows which mechanism moved, not just
    # that the flat set changed size.
    seen: set[str] = set()
    for source in sorted(by_file):
        fresh = sorted(by_file[source] - seen)
        if not fresh:
            continue
        out.append(f"        # {source}\n")
        for code in fresh:
            out.append(f'        "{code}",\n')
        seen.update(fresh)
    out.append("    }\n)\n")
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    """Regenerate or verify the committed error registry."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=Path, help="path to an x402 clone")
    parser.add_argument(
        "--check", action="store_true", help="exit non-zero if the committed file is stale"
    )
    args = parser.parse_args(argv)

    upstream: Path = args.upstream
    if not (upstream / "specs").is_dir():
        print(f"not an x402 clone (no specs/ directory): {upstream}", file=sys.stderr)
        return 2

    target = Path(__file__).resolve().parents[1] / "src" / "x402_conformance" / "error_registry.py"
    rendered = render(extract(upstream))

    if args.check:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current == rendered:
            print(f"{target.name} is in sync with {upstream}")
            return 0
        print(
            f"{target.name} is stale against {upstream}; "
            f"rerun: python tools/sync_error_registry.py --upstream {upstream}",
            file=sys.stderr,
        )
        return 1

    target.write_text(rendered, encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
