"""Central redaction helpers for persisted and rendered diagnostics."""

from __future__ import annotations

import hashlib
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
