"""
URL validation and normalization helpers.

Kept separate from the engines because both the SEO engine and the
Security engine need the same "is this a sane, publicly-resolvable
HTTP(S) URL" logic, and the future FastAPI layer will need it again
at the request-validation boundary.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


class InvalidURLError(ValueError):
    """Raised when a URL is structurally invalid or unsafe to fetch."""


@dataclass
class NormalizedURL:
    original: str
    normalized: str
    scheme: str
    hostname: str
    is_ip_literal: bool


def normalize_url(raw_url: str) -> NormalizedURL:
    """
    Normalize a user-supplied URL string.

    - Adds https:// if no scheme was supplied.
    - Rejects schemes other than http/https.
    - Rejects obviously malformed input.

    Does NOT perform DNS resolution or SSRF-style private-IP blocking
    here; that's left to the caller's deployment context (a public CLI
    tool run locally has different trust boundaries than a hosted API
    accepting arbitrary user URLs — see api/fastapi_app.py for where
    that check should be added before this tool is exposed as a
    public-facing service).
    """
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise InvalidURLError("Empty URL supplied.")

    if "://" not in raw_url:
        raw_url = f"https://{raw_url}"

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise InvalidURLError(f"Unsupported URL scheme: '{parsed.scheme}'.")

    if not parsed.hostname:
        raise InvalidURLError(f"Could not determine a hostname from '{raw_url}'.")

    is_ip_literal = False
    try:
        ipaddress.ip_address(parsed.hostname)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    # Rebuild without fragment; fragments are irrelevant server-side.
    cleaned = parsed._replace(fragment="")
    normalized = urlunparse(cleaned)

    return NormalizedURL(
        original=raw_url,
        normalized=normalized,
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        is_ip_literal=is_ip_literal,
    )


def hostname_resolves(hostname: str, timeout: float = 5.0) -> bool:
    """Best-effort DNS resolution check, used for a fast fail-fast path."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(hostname)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False
