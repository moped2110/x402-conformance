"""Keep the catalog's "Implementation status" section equal to what actually ships.

The section had drifted twice: its heading still said v0.3.0 at v0.6.0, and its list
missed RS-PR-023…026, RS-SEC-012, DI-004 and RS-HS-008, while the count beside it was
already right. Both halves are now derived and compared, not trusted.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from x402_conformance.report import _explain_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "conformance-catalog.md"

# A check ID prefix plus its first number, then any run of "/NNN" (a list) or "…NNN"
# (an inclusive range), e.g. RS-NEG-001/002/011 or RS-PR-001…026.
_ID_GROUP = re.compile(r"((?:[A-Z]+-)+)(\d{3})((?:[/…]\d{3})*)")


def _status_section() -> tuple[str, str, str]:
    """Return the heading version, the stated count and the implemented-list text."""
    text = CATALOG.read_text(encoding="utf-8")
    heading = re.search(r"^## Implementation status \(v(\d+\.\d+\.\d+)\)$", text, re.M)
    assert heading, "the catalog lost its '## Implementation status (vX.Y.Z)' heading"
    block = re.search(
        r"^\*\*Implemented & tested \((\d+) checks\):\*\*\n((?:- .*\n)+)",
        text[heading.end() :],
        re.M,
    )
    assert block, "the implementation-status section lost its implemented-check list"
    return heading.group(1), block.group(1), block.group(2)


def _expand(listing: str) -> list[str]:
    """Expand every ID group in the listing into the individual check IDs it names."""
    ids: list[str] = []
    for prefix, first, rest in _ID_GROUP.findall(listing):
        previous = int(first)
        ids.append(f"{prefix}{first}")
        for sep, number in re.findall(r"([/…])(\d{3})", rest):
            if sep == "…":
                ids.extend(f"{prefix}{n:03d}" for n in range(previous + 1, int(number) + 1))
            else:
                ids.append(f"{prefix}{number}")
            previous = int(number)
    return ids


def test_expand_reads_lists_and_ranges() -> None:
    """The expander understands the two notations the section uses."""
    assert _expand("RS-PR-001…003, RS-NEG-007/009 + FA-SET-001") == [
        "RS-PR-001",
        "RS-PR-002",
        "RS-PR-003",
        "RS-NEG-007",
        "RS-NEG-009",
        "FA-SET-001",
    ]


def _listed_ids(listing: str) -> list[str]:
    """Read the IDs each bullet assigns to a mode, ignoring IDs mentioned in its prose.

    Each bullet is one or more ``IDs — mode`` segments separated by ``;``; any later
    sentence that names a check again (e.g. "RS-PR-008 does full EIP-55 …") is prose.
    """
    ids: list[str] = []
    for bullet in listing.splitlines():
        for segment in bullet.removeprefix("- ").split(";"):
            if " — " in segment:
                ids.extend(_expand(segment.split(" — ", 1)[0]))
    return ids


def test_implemented_list_matches_the_shipped_catalog() -> None:
    """Every shipped check is listed once, nothing unshipped is, and the count agrees."""
    _, count, listing = _status_section()
    listed = _listed_ids(listing)
    shipped = set(_explain_catalog())

    assert len(listed) == len(set(listed)), "a check is listed twice"
    assert sorted(set(listed) - shipped) == [], "listed but not shipped"
    assert sorted(shipped - set(listed)) == [], "shipped but not listed"
    assert int(count) == len(shipped)


def test_heading_names_the_current_release() -> None:
    """A version bump must refresh the section, or the heading goes stale again."""
    version, _, _ = _status_section()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert version == project["project"]["version"], (
        "docs/conformance-catalog.md: update '## Implementation status (v…)' and its "
        "list for this release"
    )
