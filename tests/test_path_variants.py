"""RS-SEC-012 — paywall bypass via request-path encoding.

The end-to-end tests here do not hand-wave a 200. They rebuild upstream's actual
bug: the route regex that expands ``*`` to ``.*?`` and is compiled *without*
``DOTALL``, so a wildcard tail containing a line feed fails to match its own
protected route, `requires_payment()` returns False, and the handler runs unpaid
(x402#3036 in TypeScript, #3055 in Python). A bypass check that never fires
against the real bug is worthless, so that case is asserted explicitly.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest
from conftest import TARGET_URL, encode_header

from x402_conformance.checks.base import Status
from x402_conformance.checks.path_variants import (
    CONTROL_LABEL,
    PATH_VARIANT_CHECK_ID,
    PathVariant,
    build_variants,
    classify_variants,
)
from x402_conformance.runner import run_checks

PROTECTED_BODY = "PREMIUM-CONTENT-MARKER payload"


# --------------------------------------------------------------------------
# build_variants — pure
# --------------------------------------------------------------------------


def test_variants_cover_the_upstream_bug_classes() -> None:
    labels = {v.label for v in build_variants("https://api.example.com/a/premium-data")}
    # the terminator class, in both placements — see test_both_terminator_placements
    assert "trailing line feed" in labels  # x402#3036 (JS)
    assert "embedded line feed" in labels  # x402#3055 (Python)
    assert "trailing carriage return" in labels
    assert "unicode line separator" in labels
    assert "encoded separator" in labels  # x402#3044 (Go)
    # RFC 3986 same-resource forms
    assert "encoded current-directory segment" in labels
    assert "encoded parent-directory segment" in labels
    assert "raw backslash" in labels  # x402#3116
    assert "encoded backslash" in labels
    assert "percent-encoded unreserved character" in labels
    # and always the control
    assert CONTROL_LABEL in labels


def test_both_terminator_placements_are_probed() -> None:
    """Trailing and embedded are not interchangeable.

    Python's `$` matches just before a trailing newline, so a vulnerable Python
    route still matches `/x%0A` and only fails on a terminator with something
    after it. Probing one placement would miss one runtime entirely.
    """
    by_label = {v.label: v.url for v in build_variants(TARGET_URL)}
    assert by_label["trailing line feed"].endswith("%0A")
    embedded = by_label["embedded line feed"]
    assert not embedded.endswith("%0A")
    assert "%0A" in embedded


def test_no_variant_is_inert_on_the_wire() -> None:
    """Every variant must actually differ from the canonical request.

    This is the guard that was missing. The literal dot-segment forms ("/./x",
    "/a/../x") were probed for a week and tested nothing: RFC 3986 requires the
    *client* to remove dot segments, so httpx canonicalised them back to the
    protected path before the request left. A probe identical to the baseline
    always sees the baseline's 402 and always passes, which reads as coverage and
    is not.
    """
    for target in ("https://api.example.com/premium-data", "https://api.example.com/a/b/c"):
        canonical = httpx.URL(target).raw_path
        for v in build_variants(target):
            assert httpx.URL(v.url).raw_path != canonical, (
                f"{v.label} sends the canonical path — the client normalised it away, "
                "so this variant probes nothing"
            )


def test_backslash_variants_are_probed_in_both_forms() -> None:
    """x402#3116 was reachable raw on Express and encoded on Hono, because the
    adapters differ in how much they decode before the middleware sees the path."""
    by_label = {v.label: httpx.URL(v.url).raw_path for v in build_variants(TARGET_URL)}
    assert b"\\" in by_label["raw backslash"]
    assert b"%5C" in by_label["encoded backslash"]


def test_variants_preserve_query_and_host() -> None:
    for v in build_variants("https://api.example.com/a/b?k=1"):
        parts = httpx.URL(v.url)
        assert parts.host == "api.example.com"
        assert parts.query == b"k=1"


def test_line_feed_variant_is_percent_encoded_not_raw() -> None:
    lf = next(v for v in build_variants(TARGET_URL) if v.label == "trailing line feed")
    # A raw LF in a request line would be rejected by the client/server as a
    # malformed request; the bug is reached with the *encoded* form.
    assert lf.url.endswith("%0A")
    assert "\n" not in lf.url


def test_ambiguous_forms_are_excluded() -> None:
    """Trailing slash, letter case and ;params may address a different resource,
    so a 2xx there proves nothing and must not be gated on."""
    variants = build_variants(TARGET_URL)
    labels = {v.label for v in variants}
    assert not {label for label in labels if "trailing slash" in label or "case" in label}
    assert all(";" not in v.url for v in variants)
    # no variant is just the path with a slash appended
    assert not any(v.url.rstrip("/") != v.url for v in variants)


def test_root_path_has_no_variants() -> None:
    assert build_variants("https://api.example.com/") == []
    assert build_variants("https://api.example.com") == []


def test_encoded_separator_only_when_a_separator_exists() -> None:
    labels = {v.label for v in build_variants("https://api.example.com/single")}
    assert "encoded separator" not in labels
    labels = {v.label for v in build_variants("https://api.example.com/a/b")}
    assert "encoded separator" in labels


# --------------------------------------------------------------------------
# classify_variants — pure
# --------------------------------------------------------------------------


def _v(label: str) -> PathVariant:
    return PathVariant(label, "https://x/y", "because")


def test_all_gated_passes() -> None:
    outcomes = [(_v("embedded line feed"), 402, True), (_v(CONTROL_LABEL), 404, False)]
    status, detail = classify_variants(outcomes)
    assert status is Status.PASS
    assert "stayed gated" in detail


def test_served_variant_fails_and_names_it() -> None:
    outcomes = [
        (_v("embedded line feed"), 200, True),
        (_v("encoded parent-directory segment"), 402, True),
        (_v(CONTROL_LABEL), 404, False),
    ]
    status, detail = classify_variants(outcomes)
    assert status is Status.FAIL
    assert "embedded line feed" in detail
    assert "1 of 2" in detail


def test_catch_all_endpoint_skips_instead_of_false_failing() -> None:
    """The control path being served means the endpoint answers anything — a 2xx
    on a re-encoded path then distinguishes nothing."""
    outcomes = [(_v("embedded line feed"), 200, True), (_v(CONTROL_LABEL), 200, True)]
    status, detail = classify_variants(outcomes)
    assert status is Status.SKIP
    assert "catch-all" in detail


def test_transport_failure_is_not_a_bypass() -> None:
    outcomes = [(_v("embedded line feed"), None, False), (_v(CONTROL_LABEL), 404, False)]
    assert classify_variants(outcomes)[0] is Status.PASS


def test_empty_body_2xx_is_not_a_bypass() -> None:
    """A 2xx with nothing in it did not leak the protected resource."""
    outcomes = [(_v("embedded line feed"), 200, False), (_v(CONTROL_LABEL), 404, False)]
    assert classify_variants(outcomes)[0] is Status.PASS


def test_marker_required_when_supplied() -> None:
    outcomes = [
        (_v("embedded line feed"), 200, True),
        (_v("encoded parent-directory segment"), 200, True),
        (_v(CONTROL_LABEL), 404, False),
    ]
    marker = {
        "embedded line feed": False,
        "encoded parent-directory segment": True,
        CONTROL_LABEL: False,
    }
    status, detail = classify_variants(outcomes, marker_seen=marker)
    assert status is Status.FAIL
    # only the variant that actually leaked the protected content is reported
    assert "encoded parent-directory segment" in detail
    assert "embedded line feed" not in detail


def test_no_outcomes_skips() -> None:
    assert classify_variants([])[0] is Status.SKIP


# --------------------------------------------------------------------------
# End to end, against a faithful reproduction of upstream's bug
# --------------------------------------------------------------------------


def _route_regex(pattern: str, *, dotall: bool) -> re.Pattern[str]:
    """Upstream's route matcher: `*` becomes `.*?`, anchored.

    ``dotall=False`` is the bug (x402#3036/#3055) — `.` then does not match a
    line feed, so a wildcard tail containing one misses its own route.
    """
    body = "^" + re.escape(pattern).replace(r"\*", ".*?") + "$"
    return re.compile(body, re.DOTALL if dotall else 0)


def _paywall_transport(
    payload: dict[str, Any], *, dotall: bool, protected: str = "/premium-data*"
) -> httpx.MockTransport:
    """A resource server whose paywall uses the route matcher above.

    A request matching the protected route gets 402. Anything else is treated as
    unprotected and served — exactly the failure mode upstream described.
    """
    route = _route_regex(protected, dotall=dotall)
    header = encode_header(payload)

    def handler(request: httpx.Request) -> httpx.Response:
        # The decoded path is what both the matcher and the handler see.
        path = request.url.path
        if route.match(path):
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": header}, json={})
        # Not gated. The app still routes the premium prefix to its handler.
        if path.startswith("/premium-data"):
            return httpx.Response(200, text=PROTECTED_BODY)
        return httpx.Response(404, text="not found")

    return httpx.MockTransport(handler)


def _sec_012(results: list[Any]) -> Any:
    return next(r for r in results if r.check_id == PATH_VARIANT_CHECK_ID)


def test_fixed_server_passes(valid_payload: dict[str, Any]) -> None:
    """With DOTALL — upstream's fix — every variant stays gated."""
    results = run_checks(TARGET_URL, transport=_paywall_transport(valid_payload, dotall=True))
    result = _sec_012(results)
    assert result.status is Status.PASS, result.detail


def test_line_feed_bypass_is_detected(valid_payload: dict[str, Any]) -> None:
    """Without DOTALL — upstream's bug — the LF variant is served unpaid and the
    check must FAIL. This is the regression that justifies RS-SEC-012 existing."""
    results = run_checks(TARGET_URL, transport=_paywall_transport(valid_payload, dotall=False))
    result = _sec_012(results)
    assert result.status is Status.FAIL, result.detail
    assert "line feed" in result.detail
    assert result.severity.value == "critical"


def test_marker_narrows_the_finding(valid_payload: dict[str, Any]) -> None:
    """With a marker, the served body must actually contain the protected content."""
    transport = _paywall_transport(valid_payload, dotall=False)
    hit = run_checks(TARGET_URL, transport=transport, resource_marker="PREMIUM-CONTENT-MARKER")
    assert _sec_012(hit).status is Status.FAIL
    miss = run_checks(TARGET_URL, transport=transport, resource_marker="SOMETHING-ELSE")
    assert _sec_012(miss).status is Status.PASS


def test_catch_all_server_skips(valid_payload: dict[str, Any]) -> None:
    """An endpoint that answers every path must not produce a critical finding."""
    header = encode_header(valid_payload)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/premium-data":
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": header}, json={})
        return httpx.Response(200, text="SPA shell")

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    result = _sec_012(results)
    assert result.status is Status.SKIP
    assert "catch-all" in result.detail


def test_unpaywalled_target_skips() -> None:
    """No 402 means there is no gate to get around."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="open")

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    result = _sec_012(results)
    assert result.status is Status.SKIP
    assert "nothing to bypass" in result.detail


@pytest.mark.parametrize("code", [401, 403, 404, 405])
def test_rejecting_variants_pass(valid_payload: dict[str, Any], code: int) -> None:
    """A variant that is refused or unknown is not a bypass."""
    header = encode_header(valid_payload)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/premium-data":
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": header}, json={})
        return httpx.Response(code, text="nope")

    results = run_checks(TARGET_URL, transport=httpx.MockTransport(handler))
    assert _sec_012(results).status is Status.PASS


# --- x402#3116: the "\" -> "/" rewrite in normalizePath ---------------------------


def _backslash_transport(payload: dict[str, Any], *, fixed: bool) -> httpx.MockTransport:
    """A server carrying upstream's pre-fix normalizePath.

    The bug: normalizePath rewrote every "\\" to "/" *after* decoding, so a
    backslash in a segment split the middleware's view of the path. The route's
    `:param` regex `[^/]+` then missed, lookup returned nothing, and the request
    fell through to the handler unpaid — while the framework router, which never
    did that rewrite, still dispatched it to the protected handler.

    ``fixed=True`` is a correct server: it resolves dot segments and matches on
    the same normalised form the router dispatches on, and it does not fold the
    backslash. Both halves are needed — an earlier version of this fixture fixed
    only the backslash and still decoded-then-matched, so the dot-segment variants
    rightly failed it. That was the fixture being wrong, not the check.
    """
    header = encode_header(payload)
    # Route "/premium-data/:id" — one param segment, exactly the shape that broke.
    route = re.compile(r"^/premium-data/[^/]+$")

    def handler(request: httpx.Request) -> httpx.Response:
        import posixpath
        from urllib.parse import unquote

        decoded = unquote(request.url.path)
        if fixed:
            # One canonical form for both the gate and the dispatch.
            canonical = posixpath.normpath(decoded)
            seen_by_middleware = dispatched = canonical
        else:
            seen_by_middleware = decoded.replace("\\", "/")  # the x402#3116 rewrite
            dispatched = decoded
        if route.match(seen_by_middleware):
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": header}, json={})
        # Middleware saw no protected route. The router still dispatches on the
        # real path, so the paid handler runs.
        if dispatched.startswith("/premium-data/"):
            return httpx.Response(200, text=PROTECTED_BODY)
        return httpx.Response(404, text="not found")

    return httpx.MockTransport(handler)


_PARAM_TARGET = "https://api.example.com/premium-data/42"


def test_backslash_bypass_is_detected(valid_payload: dict[str, Any]) -> None:
    """The regression that justifies the backslash variants existing."""
    results = run_checks(_PARAM_TARGET, transport=_backslash_transport(valid_payload, fixed=False))
    result = _sec_012(results)
    assert result.status is Status.FAIL, result.detail
    assert "backslash" in result.detail


def test_backslash_fixed_server_passes(valid_payload: dict[str, Any]) -> None:
    """With the fix — escape rather than fold — every variant stays gated."""
    results = run_checks(_PARAM_TARGET, transport=_backslash_transport(valid_payload, fixed=True))
    assert _sec_012(results).status is Status.PASS, _sec_012(results).detail
