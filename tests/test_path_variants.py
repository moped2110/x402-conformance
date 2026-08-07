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
    assert "current-directory segment" in labels
    assert "parent-directory segment" in labels
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
    assert not {label for label in labels if "slash" in label or "case" in label}
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
        (_v("parent-directory segment"), 402, True),
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
        (_v("parent-directory segment"), 200, True),
        (_v(CONTROL_LABEL), 404, False),
    ]
    marker = {"embedded line feed": False, "parent-directory segment": True, CONTROL_LABEL: False}
    status, detail = classify_variants(outcomes, marker_seen=marker)
    assert status is Status.FAIL
    # only the variant that actually leaked the protected content is reported
    assert "parent-directory segment" in detail
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
