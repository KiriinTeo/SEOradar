"""
The stable JSON contract.

Every field the frontend will ever bind to should be defined here as
a dataclass, not assembled ad-hoc as dicts in the engines. Engines
populate these dataclasses; `to_dict()` is the single place that
turns them into the JSON payload, so the shape never drifts between
runs.

Design rule: a field is either populated with real data OR set to
None/[] with a companion `error` note — it is never *omitted*. A
frontend should never have to guess whether a missing key means
"not implemented", "check failed", or "0 results".
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Grade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    NOT_APPLICABLE = "N/A"


class Status(str, Enum):
    OK = "ok"
    WARNING = "warning"
    FAIL = "fail"
    ERROR = "error"          # could not even be checked (network/parsing failure)
    NOT_APPLICABLE = "not_applicable"


# --------------------------------------------------------------------------
# Shared building blocks
# --------------------------------------------------------------------------

@dataclass
class CheckResult:
    """A single, atomic pass/fail/warn check with a human-readable explanation."""
    id: str
    label: str
    status: Status
    message: str
    details: Optional[dict[str, Any]] = None


@dataclass
class Recommendation:
    id: str
    severity: str          # "critical" | "high" | "medium" | "low" | "info"
    category: str          # "seo" | "security"
    title: str
    description: str


# --------------------------------------------------------------------------
# SEO section
# --------------------------------------------------------------------------

@dataclass
class MetaTagsReport:
    title: Optional[str] = None
    title_length: Optional[int] = None
    title_status: Status = Status.NOT_APPLICABLE
    description: Optional[str] = None
    description_length: Optional[int] = None
    description_status: Status = Status.NOT_APPLICABLE
    canonical_url: Optional[str] = None
    canonical_status: Status = Status.NOT_APPLICABLE
    open_graph: dict[str, str] = field(default_factory=dict)
    open_graph_status: Status = Status.NOT_APPLICABLE
    twitter_card: dict[str, str] = field(default_factory=dict)
    twitter_card_status: Status = Status.NOT_APPLICABLE
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class HeadingNode:
    level: int
    text: str


@dataclass
class ContentHierarchyReport:
    h1_count: int = 0
    heading_counts: dict[str, int] = field(default_factory=dict)  # {"h1": 1, "h2": 4, ...}
    headings: list[HeadingNode] = field(default_factory=list)
    status: Status = Status.NOT_APPLICABLE
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class ImageAuditReport:
    total_images: int = 0
    images_missing_alt: int = 0
    missing_alt_sources: list[str] = field(default_factory=list)
    status: Status = Status.NOT_APPLICABLE
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class TechnicalFilesReport:
    robots_txt_found: bool = False
    robots_txt_status_code: Optional[int] = None
    robots_txt_disallows_all: bool = False
    robots_txt_sitemap_refs: list[str] = field(default_factory=list)
    sitemap_found: bool = False
    sitemap_status_code: Optional[int] = None
    sitemap_url_count: Optional[int] = None
    sitemap_is_valid_xml: Optional[bool] = None
    status: Status = Status.NOT_APPLICABLE
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class PerformanceReport:
    response_time_ms: Optional[float] = None
    http_status_code: Optional[int] = None
    redirect_count: int = 0
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    status: Status = Status.NOT_APPLICABLE
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class SEOReport:
    score: Optional[int] = None            # 0-100
    grade: Grade = Grade.NOT_APPLICABLE
    meta_tags: MetaTagsReport = field(default_factory=MetaTagsReport)
    content_hierarchy: ContentHierarchyReport = field(default_factory=ContentHierarchyReport)
    images: ImageAuditReport = field(default_factory=ImageAuditReport)
    technical_files: TechnicalFilesReport = field(default_factory=TechnicalFilesReport)
    performance: PerformanceReport = field(default_factory=PerformanceReport)
    error: Optional[str] = None


# --------------------------------------------------------------------------
# Security section
# --------------------------------------------------------------------------

@dataclass
class SSLReport:
    is_https: bool = False
    certificate_valid: Optional[bool] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_until_expiry: Optional[int] = None
    protocol_version: Optional[str] = None
    status: Status = Status.NOT_APPLICABLE
    checks: list[CheckResult] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class SecurityHeaderFinding:
    header: str
    present: bool
    value: Optional[str] = None
    grade_contribution: Status = Status.NOT_APPLICABLE
    note: str = ""


@dataclass
class SecurityHeadersReport:
    findings: list[SecurityHeaderFinding] = field(default_factory=list)
    grade: Grade = Grade.NOT_APPLICABLE
    status: Status = Status.NOT_APPLICABLE


@dataclass
class CookieFinding:
    name: str
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    status: Status = Status.NOT_APPLICABLE
    note: str = ""


@dataclass
class CookieSecurityReport:
    total_cookies: int = 0
    cookies: list[CookieFinding] = field(default_factory=list)
    status: Status = Status.NOT_APPLICABLE
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class SecurityReport:
    score: Optional[int] = None
    grade: Grade = Grade.NOT_APPLICABLE
    ssl: SSLReport = field(default_factory=SSLReport)
    headers: SecurityHeadersReport = field(default_factory=SecurityHeadersReport)
    cookies: CookieSecurityReport = field(default_factory=CookieSecurityReport)
    error: Optional[str] = None


# --------------------------------------------------------------------------
# Envelope
# --------------------------------------------------------------------------

@dataclass
class AnalysisMeta:
    target_url: str
    normalized_url: str
    analyzed_at_utc: str
    tool_version: str = "1.0.0"
    total_duration_ms: Optional[float] = None


@dataclass
class AnalysisReport:
    meta: AnalysisMeta
    overall_status: Status = Status.OK
    seo: SEOReport = field(default_factory=SEOReport)
    security: SecurityReport = field(default_factory=SecurityReport)
    recommendations: list[Recommendation] = field(default_factory=list)
    fatal_error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
