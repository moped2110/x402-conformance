"""RS-SEC-012 — paywall bypass via request-path encoding.

A paywall is applied by matching the request path against a protected route. If
the matcher and the application's router disagree about what a path *is*, a
request can miss the paywall and still reach the handler — the resource is served
with no payment verification and no settlement. The money leaks and the endpoint
looks healthy.

This is not hypothetical. Upstream fixed the same class three times in three
weeks, in three languages:

  * x402#3036 (TypeScript) — the wildcard route regex expanded ``*`` to ``.*?``
    without ``dotAll``, so a path whose wildcard tail held a line terminator did
    not match its own protected route.
  * x402#3055 (Python) — the identical bug in ``re`` without ``re.DOTALL``.
    Upstream's own description: "The route then misses, ``requires_payment()``
    returns False, and the middleware serves the protected resource with no
    payment verification or settlement."
  * x402#3044 (Go) — middleware matched the *decoded* path while routing happened
    on the escaped one, so percent-encoded separators slipped past.

So the check sends the protected URL again under encodings that a correct server
must still treat as paywalled, and looks for a 2xx.

Honesty about false positives
-----------------------------
An endpoint that answers 2xx for *every* path (an SPA catch-all, a permissive
proxy) would light up every variant while having no bypass at all. So the probe
also sends one deliberately-nonsense sibling path as a control. If the control is
also served, the endpoint cannot distinguish paths for us and the check SKIPs
with that reason rather than inventing a critical finding.

Variant selection is deliberately narrow. Trailing slashes, letter case and
``;params`` can legitimately address a different resource, so a 2xx there proves
nothing; they are excluded. What remains is either RFC 3986-equivalent to the
protected path (percent-encoded unreserved characters, dot-segments) or a
concrete upstream-demonstrated bypass (line terminators, encoded separators).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from .base import Severity, Status, register

if TYPE_CHECKING:
    from ..probe import ProbeSession

_CORE = "x402-specification-v2.md"
PATH_VARIANT_CHECK_ID = "RS-SEC-012"
_TITLE = "Paywall cannot be bypassed by re-encoding the request path"
_SPEC_REF = f"{_CORE} §10.1 + x402#3036/#3044/#3055"

#: Label used for the catch-all control probe. Not a bypass candidate.
CONTROL_LABEL = "control (nonexistent sibling)"


@dataclass(frozen=True)
class PathVariant:
    """One rewritten request path plus why a correct server must still gate it."""

    label: str
    url: str
    rationale: str


def _rebuild(parts: tuple[str, str, str, str, str], path: str) -> str:
    """Reassemble a URL with ``path`` substituted, preserving query and fragment."""
    scheme, netloc, _, query, fragment = parts
    return urlunsplit((scheme, netloc, path, query, fragment))


def build_variants(target_url: str) -> list[PathVariant]:
    """Derive the bypass candidates plus the control probe for ``target_url``.

    Pure and deterministic, so the variant set is unit-tested without HTTP. An
    empty list means the URL has no path to rewrite (nothing to test).
    """
    parts = urlsplit(target_url)
    path = parts.path
    if not path or path == "/":
        return []
    split = (parts.scheme, parts.netloc, parts.path, parts.query, parts.fragment)

    # Line terminators, the class upstream fixed three times. Two placements are
    # needed, because the two runtimes fail on different ones:
    #   * trailing — JavaScript's `$` only matches end-of-input, so a route regex
    #     without `dotAll` misses a path ending in a terminator (x402#3036).
    #   * embedded — Python's `$` also matches *just before* a trailing newline,
    #     so a trailing LF still matches and only a terminator with something
    #     after it exposes the missing `re.DOTALL` (x402#3055).
    # Probing only the trailing form would have passed every vulnerable Python
    # server, which is the mistake this comment exists to prevent.
    variants: list[PathVariant] = [
        PathVariant(
            "trailing line feed",
            _rebuild(split, path + "%0A"),
            "x402#3036: a wildcard route regex without dotAll misses a path whose "
            "tail ends in a decoded LF, so the middleware never runs",
        ),
        PathVariant(
            "embedded line feed",
            _rebuild(split, _in_wildcard_tail(path, "%0A")),
            "x402#3055: Python's `$` forgives a *trailing* newline, so only an LF "
            "with a character after it exposes a route compiled without re.DOTALL",
        ),
        PathVariant(
            "trailing carriage return",
            _rebuild(split, path + "%0D"),
            "same terminator class as x402#3036; JavaScript's `.` excludes CR too, "
            "while Python's does not — so CR catches the JS side specifically",
        ),
        PathVariant(
            "unicode line separator",
            _rebuild(split, _in_wildcard_tail(path, "%E2%80%A8")),
            "U+2028 is a line terminator to JavaScript's `.` but not to Python's — "
            "the other half of the dotAll gap in x402#3036",
        ),
    ]

    # Encoded separator: only meaningful when there is a separator to encode.
    if "/" in path.strip("/"):
        head, _, tail = path.strip("/").rpartition("/")
        variants.append(
            PathVariant(
                "encoded separator",
                _rebuild(split, f"/{head}%2F{tail}"),
                "x402#3044: matching the decoded path while routing on the escaped "
                "one lets %2F slip past the gate",
            )
        )

    # Dot-segments: RFC 3986 §5.2.4 removes these, so the result is the *same*
    # resource. A server that serves it unpaid has a normalisation gap.
    variants.append(
        PathVariant(
            "current-directory segment",
            _rebuild(split, path.rsplit("/", 1)[0] + "/./" + path.rsplit("/", 1)[1]),
            "RFC 3986 §5.2.4 removes '/./', so this is the same resource",
        )
    )
    variants.append(
        PathVariant(
            "parent-directory segment",
            _rebuild(split, path.rsplit("/", 1)[0] + "/x/../" + path.rsplit("/", 1)[1]),
            "RFC 3986 §5.2.4 resolves '/x/..', so this is the same resource",
        )
    )

    # Percent-encoding an unreserved character: RFC 3986 §6.2.2.2 says the encoded
    # and decoded forms are equivalent, so this is unambiguously the same resource.
    encoded = _encode_last_unreserved(path)
    if encoded is not None:
        variants.append(
            PathVariant(
                "percent-encoded unreserved character",
                _rebuild(split, encoded),
                "RFC 3986 §6.2.2.2: percent-encoded unreserved characters are "
                "equivalent to their decoded form — same resource",
            )
        )

    variants.append(
        PathVariant(
            CONTROL_LABEL,
            _rebuild(split, path.rstrip("/") + "-x402-conformance-control"),
            "control: a path that should not exist. If this is served too, the "
            "endpoint answers everything and the other variants prove nothing.",
        )
    )
    return variants


def _in_wildcard_tail(path: str, encoded: str) -> str:
    """Append ``encoded`` followed by one more character.

    The terminator has to land *inside* a wildcard tail, which means after the
    whole path: a protected route like ``/premium*`` only matches strings that
    still start with ``/premium``, so injecting into the middle would corrupt the
    prefix and the request would simply miss the route as an unrelated URL rather
    than exercising the matcher.

    The extra character is what makes this differ from the plain trailing form —
    Python's ``$`` matches just before a trailing newline, so a terminator needs
    something after it to expose a route compiled without ``re.DOTALL``. The
    path's own last character is reused so no foreign token is introduced.
    """
    suffix = path[-1] if path and path[-1].isalnum() else "a"
    return path + encoded + suffix


def _encode_last_unreserved(path: str) -> str | None:
    """Percent-encode the final alphanumeric character of ``path``.

    Returns ``None`` when the path has no alphanumeric character to encode.
    """
    for i in range(len(path) - 1, -1, -1):
        ch = path[i]
        if ch.isalnum() and ch.isascii():
            return f"{path[:i]}%{ord(ch):02X}{path[i + 1 :]}"
    return None


def classify_variants(
    outcomes: list[tuple[PathVariant, int | None, bool]],
    *,
    marker_seen: dict[str, bool] | None = None,
) -> tuple[Status, str]:
    """Grade the variant probes.

    ``outcomes`` is ``(variant, status_code, has_body)`` per probe; ``status_code``
    is ``None`` when the request failed at the transport layer (treated as "not
    served", since nothing reached the client). ``marker_seen`` optionally maps a
    variant label to whether the protected content marker appeared in the body —
    when a marker was supplied, only a body actually containing it counts.

    Pure, so every branch is unit-tested without HTTP.
    """
    if not outcomes:
        return Status.SKIP, "target URL has no path to re-encode"

    control = [o for o in outcomes if o[0].label == CONTROL_LABEL]
    if control and _is_served(control[0], marker_seen):
        return Status.SKIP, (
            "endpoint served a deliberately-nonexistent sibling path "
            f"(HTTP {control[0][1]}) — it answers any path, so a 2xx on a "
            "re-encoded path would not distinguish a bypass from a catch-all"
        )

    tested = [o for o in outcomes if o[0].label != CONTROL_LABEL]
    bypassed = [o for o in tested if _is_served(o, marker_seen)]
    if bypassed:
        detail = "; ".join(f"{v.label} -> HTTP {code} ({v.rationale})" for v, code, _ in bypassed)
        return Status.FAIL, (
            f"{len(bypassed)} of {len(tested)} re-encoded paths were served without "
            f"payment while the canonical path returns 402: {detail}"
        )
    return Status.PASS, (
        f"all {len(tested)} re-encoded paths stayed gated (control path correctly not served)"
    )


@register(PATH_VARIANT_CHECK_ID, _TITLE, Severity.CRITICAL, _SPEC_REF)
def sec_012(s: ProbeSession) -> tuple[Status, str]:
    """Evaluate RS-SEC-012: paywall cannot be bypassed by re-encoding the path."""
    if s.path_variants is None:
        # The runner only probes variants behind a live paywall. No 402 means
        # there is no gate to get around, not that the gate held.
        return Status.SKIP, "no 402 paywall on the canonical path — nothing to bypass"
    return classify_variants(s.path_variants, marker_seen=s.path_variant_marker)


def _is_served(
    outcome: tuple[PathVariant, int | None, bool], marker_seen: dict[str, bool] | None
) -> bool:
    """True when a probe returned protected content rather than a gate/miss."""
    variant, code, has_body = outcome
    if code is None or not (200 <= code < 300) or not has_body:
        return False
    if marker_seen is not None:
        # With a marker we know what the protected content looks like, so a 2xx
        # body that lacks it is some other page, not a leak of the paid resource.
        return marker_seen.get(variant.label, False)
    return True
