"""Central redaction helpers for persisted and rendered diagnostics."""

from __future__ import annotations

import hashlib
import os
import re
from urllib.parse import urlsplit

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def sanitize_url(url: str | None) -> str | None:
    """Return a display-safe origin, removing credentials, path, query, and fragment."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except (TypeError, ValueError):
        return "<unparseable>"
    if parts.scheme.lower() not in {"http", "https"} or not hostname:
        return "<redacted>"
    host = hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    return f"{parts.scheme.lower()}://{host}"


#: A path segment that looks like a credential (an API key, token or capability id
#: embedded in the path) is replaced, not shown: at least 20 URL-safe characters
#: mixing letters and digits, or anything longer than 64 characters.
_SECRETISH_SEGMENT = re.compile(r"^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9_\-.~%+=]{20,}$")
_MAX_SEGMENT = 64
#: RFC 3986 pchar. A segment with anything else (a backtick, a space, a quote) is
#: replaced too, so a crafted path cannot break out of Markdown or SARIF rendering.
_PCHAR_SEGMENT = re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=:@%]*$")

#: Set to 1 to drop the path from report targets entirely — for capability-URL
#: endpoints whose path segments are themselves secrets but don't look like it.
REDACT_PATH_ENV = "X402_CONFORMANCE_REDACT_PATH"


def _redact_segment(segment: str) -> str:
    """Return a path segment unchanged, or ``<redacted>`` if it may carry a secret."""
    if (
        len(segment) > _MAX_SEGMENT
        or _SECRETISH_SEGMENT.match(segment)
        or not _PCHAR_SEGMENT.match(segment)
    ):
        return "<redacted>"
    return segment


def sanitize_target_url(url: str | None) -> str | None:
    """Return the display-safe origin plus path, so two endpoints on one host differ.

    Credentials, query and fragment are always dropped, as in :func:`sanitize_url`.
    The path is kept, but any segment that looks like an embedded secret is
    replaced with ``<redacted>``. ``X402_CONFORMANCE_REDACT_PATH=1`` drops the path
    altogether.
    """
    origin = sanitize_url(url)
    if not url or origin is None or origin.startswith("<"):
        return origin
    if os.environ.get(REDACT_PATH_ENV, "").strip().lower() in {"1", "true", "yes"}:
        return origin
    path = urlsplit(url).path
    if not path or path == "/":
        return origin
    segments = "/".join(_redact_segment(seg) for seg in path.split("/"))
    return f"{origin}{segments}"


def url_fingerprint(url: str) -> str:
    """Stable opaque identifier for correlating a redacted target across runs."""
    return "sha256:" + hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()


def sanitize_text(text: str | None, *, sensitive_values: tuple[str, ...] = ()) -> str | None:
    """Remove known sensitive values and URL credentials/components from diagnostics."""
    if text is None:
        return None
    cleaned = text
    for value in sorted((v for v in sensitive_values if v), key=len, reverse=True):
        cleaned = cleaned.replace(value, sanitize_url(value) or "<redacted>")
    return _URL_RE.sub(lambda match: sanitize_url(match.group(0)) or "<redacted>", cleaned)
