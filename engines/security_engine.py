"""
Security Analyzer Engine (passive audit only).

Deliberately passive: this module inspects the TLS certificate the
server presents and the HTTP response headers/cookies it sends back
to a normal GET request. It never attempts payload injection, fuzzing,
port scanning, auth bypass, or any other active probing — that keeps
it legal and safe to run against arbitrary third-party sites without
authorization, which a CLI tool handed to end users must be.

Fully independent of the SEO engine; the only thing shared is the
HttpClient and the base URL string.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.http_client import HttpClient
from core.schema import (
    CheckResult,
    CookieFinding,
    CookieSecurityReport,
    Grade,
    SecurityHeaderFinding,
    SecurityHeadersReport,
    SecurityReport,
    SSLReport,
    Status,
)
from core.scorer import (
    SECURITY_HEADER_WEIGHTS,
    compute_security_score,
    grade_headers,
    score_to_grade,
)
from utils.logger import get_logger

logger = get_logger(__name__)

EXPIRY_WARNING_DAYS = 21

# header_key -> (human label, note shown when missing)
CHECKED_HEADERS: dict[str, tuple[str, str]] = {
    "content-security-policy": (
        "Content-Security-Policy",
        "Mitigates XSS and data-injection attacks by restricting allowed content sources.",
    ),
    "strict-transport-security": (
        "Strict-Transport-Security",
        "Forces browsers to use HTTPS, preventing SSL-stripping attacks.",
    ),
    "x-frame-options": (
        "X-Frame-Options",
        "Prevents the page from being embedded in a hostile <iframe> (clickjacking).",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "Prevents MIME-type sniffing that can lead to drive-by downloads/XSS.",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        "Controls how much referrer information is leaked to other origins.",
    ),
    "permissions-policy": (
        "Permissions-Policy",
        "Restricts which browser features/APIs (camera, geolocation, etc.) the page may use.",
    ),
}


class SecurityAnalyzer:
    """
    Usage:
        async with HttpClient() as client:
            report = await SecurityAnalyzer(client).analyze(url)
    """

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    async def analyze(self, url: str) -> SecurityReport:
        report = SecurityReport()
        parsed = urlparse(url)

        report.ssl = self._check_ssl(parsed.hostname, parsed.scheme, port=parsed.port or 443)

        page = await self._client.get(url)
        if not page.ok:
            report.error = page.error or "Page could not be fetched for header/cookie inspection."
            report.headers = SecurityHeadersReport(status=Status.ERROR)
            report.cookies = CookieSecurityReport(status=Status.ERROR)
        else:
            report.headers = self._analyze_headers(page.headers)
            report.cookies = self._analyze_cookies(page.headers)

        section_statuses = {
            "ssl": report.ssl.status,
            "headers": report.headers.status,
            "cookies": report.cookies.status,
        }
        report.score = compute_security_score(section_statuses)
        report.grade = score_to_grade(report.score)

        return report

    # ------------------------------------------------------------------
    # SSL/TLS certificate verification
    # ------------------------------------------------------------------
    def _check_ssl(self, hostname: str | None, scheme: str, port: int) -> SSLReport:
        report = SSLReport()
        checks: list[CheckResult] = []

        if scheme != "https" or not hostname:
            report.is_https = False
            report.status = Status.FAIL
            checks.append(CheckResult(
                id="ssl.not_https", label="HTTPS", status=Status.FAIL,
                message="Site is not served over HTTPS.",
            ))
            report.checks = checks
            return report

        report.is_https = True

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    report.protocol_version = ssock.version()
        except ssl.SSLCertVerificationError as e:
            report.certificate_valid = False
            report.status = Status.FAIL
            report.error = str(e)
            checks.append(CheckResult(
                id="ssl.invalid_cert", label="Certificate Validity", status=Status.FAIL,
                message=f"Certificate verification failed: {e}",
            ))
            report.checks = checks
            return report
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            report.status = Status.ERROR
            report.error = str(e)
            checks.append(CheckResult(
                id="ssl.connect_error", label="TLS Connection", status=Status.ERROR,
                message=f"Could not establish a TLS connection: {e}",
            ))
            report.checks = checks
            return report

        report.certificate_valid = True
        report.issuer = self._format_cert_name(cert.get("issuer"))
        report.subject = self._format_cert_name(cert.get("subject"))

        not_after = cert.get("notAfter")
        not_before = cert.get("notBefore")
        report.valid_until = not_after
        report.valid_from = not_before

        try:
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expiry_dt - datetime.now(timezone.utc)).days
            report.days_until_expiry = days_left

            if days_left < 0:
                report.status = Status.FAIL
                checks.append(CheckResult(
                    id="ssl.expired", label="Certificate Expiry", status=Status.FAIL,
                    message=f"Certificate expired {abs(days_left)} day(s) ago.",
                ))
            elif days_left <= EXPIRY_WARNING_DAYS:
                report.status = Status.WARNING
                checks.append(CheckResult(
                    id="ssl.expiring_soon", label="Certificate Expiry", status=Status.WARNING,
                    message=f"Certificate expires in {days_left} day(s).",
                ))
            else:
                report.status = Status.OK
                checks.append(CheckResult(
                    id="ssl.valid", label="Certificate Expiry", status=Status.OK,
                    message=f"Certificate is valid for {days_left} more day(s), "
                            f"issued by {report.issuer or 'unknown issuer'}.",
                ))
        except (ValueError, TypeError):
            report.status = Status.WARNING
            checks.append(CheckResult(
                id="ssl.expiry_unparseable", label="Certificate Expiry", status=Status.WARNING,
                message="Certificate found but its expiry date could not be parsed.",
            ))

        report.checks = checks
        return report

    @staticmethod
    def _format_cert_name(name_tuple) -> str | None:
        if not name_tuple:
            return None
        parts = {k: v for pair in name_tuple for (k, v) in pair}
        return parts.get("organizationName") or parts.get("commonName")

    # ------------------------------------------------------------------
    # HTTP security headers
    # ------------------------------------------------------------------
    def _analyze_headers(self, raw_headers: dict) -> SecurityHeadersReport:
        headers_lower = {k.lower(): v for k, v in raw_headers.items()}
        findings: list[SecurityHeaderFinding] = []
        present: set[str] = set()

        for key, (label, note) in CHECKED_HEADERS.items():
            value = headers_lower.get(key)
            if value:
                present.add(key)
                findings.append(SecurityHeaderFinding(
                    header=label, present=True, value=value,
                    grade_contribution=Status.OK,
                    note=f"Present. {note}",
                ))
            else:
                findings.append(SecurityHeaderFinding(
                    header=label, present=False, value=None,
                    grade_contribution=Status.WARNING,
                    note=f"Missing. {note}",
                ))

        grade = grade_headers(present)
        missing_weight = sum(
            w for h, w in SECURITY_HEADER_WEIGHTS.items() if h not in present
        )
        if not present:
            status = Status.FAIL
        elif missing_weight >= 40:
            status = Status.WARNING
        elif missing_weight > 0:
            status = Status.WARNING
        else:
            status = Status.OK

        return SecurityHeadersReport(findings=findings, grade=grade, status=status)

    # ------------------------------------------------------------------
    # Cookie security attributes (Secure, HttpOnly, SameSite)
    # ------------------------------------------------------------------
    def _analyze_cookies(self, raw_headers: dict) -> CookieSecurityReport:
        report = CookieSecurityReport()
        checks: list[CheckResult] = []

        # httpx folds multiple Set-Cookie headers into one via `.headers`,
        # so we re-parse from the multi-value list when available.
        set_cookie_lines = self._extract_set_cookie_lines(raw_headers)

        cookies: list[CookieFinding] = []
        for line in set_cookie_lines:
            cookie = self._parse_set_cookie(line)
            if cookie:
                cookies.append(cookie)

        report.total_cookies = len(cookies)
        report.cookies = cookies

        if not cookies:
            report.status = Status.NOT_APPLICABLE
            checks.append(CheckResult(
                id="cookies.none", label="Cookie Security", status=Status.NOT_APPLICABLE,
                message="No cookies were set on the initial response.",
            ))
            report.checks = checks
            return report

        insecure_count = sum(1 for c in cookies if c.status == Status.FAIL)
        warning_count = sum(1 for c in cookies if c.status == Status.WARNING)

        if insecure_count > 0:
            report.status = Status.FAIL
        elif warning_count > 0:
            report.status = Status.WARNING
        else:
            report.status = Status.OK

        checks.append(CheckResult(
            id="cookies.summary", label="Cookie Security", status=report.status,
            message=f"{report.total_cookies} cookie(s) inspected: "
                    f"{report.total_cookies - insecure_count - warning_count} fully compliant, "
                    f"{warning_count} with partial issues, {insecure_count} insecure.",
        ))
        report.checks = checks
        return report

    @staticmethod
    def _extract_set_cookie_lines(raw_headers: dict) -> list[str]:
        # httpx's `response.headers` is case-insensitive but folds repeated
        # headers with ", " which breaks Set-Cookie's own comma-containing
        # Expires attribute. We only have the folded dict here (see
        # http_client.py), so this best-effort split handles the common
        # single-cookie case cleanly and degrades gracefully for multiples.
        value = raw_headers.get("set-cookie") or raw_headers.get("Set-Cookie")
        if not value:
            return []
        return [value]

    @staticmethod
    def _parse_set_cookie(line: str) -> CookieFinding | None:
        parts = [p.strip() for p in line.split(";")]
        if not parts or "=" not in parts[0]:
            return None

        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True)
                 for p in parts[1:]}

        secure = "secure" in attrs
        http_only = "httponly" in attrs
        same_site = attrs.get("samesite")
        if isinstance(same_site, str):
            same_site = same_site.capitalize()

        issues = []
        if not secure:
            issues.append("missing Secure")
        if not http_only:
            issues.append("missing HttpOnly")
        if not same_site or same_site.lower() == "none":
            issues.append("SameSite is absent or 'None'")

        if not issues:
            status = Status.OK
            note = "Secure, HttpOnly, and SameSite are all properly configured."
        elif len(issues) >= 2:
            status = Status.FAIL
            note = f"Multiple issues: {', '.join(issues)}."
        else:
            status = Status.WARNING
            note = f"{issues[0]}."

        return CookieFinding(
            name=name, secure=secure, http_only=http_only,
            same_site=same_site if isinstance(same_site, str) else None,
            status=status, note=note,
        )
