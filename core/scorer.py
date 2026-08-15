"""
Scoring and grading logic.

Kept out of the engines deliberately: engines are responsible for
*observing facts* (title length is 71 chars, HSTS header is absent),
while this module is responsible for *judging* those facts. That
separation means the grading rubric can be tuned in one place without
touching extraction/parsing code, and the frontend team can be handed
this file alone if they want to propose rubric changes.
"""
from __future__ import annotations

from core.schema import Grade, Status


def score_to_grade(score: int) -> Grade:
    if score >= 97:
        return Grade.A_PLUS
    if score >= 90:
        return Grade.A
    if score >= 80:
        return Grade.B
    if score >= 70:
        return Grade.C
    if score >= 60:
        return Grade.D
    return Grade.F


def clamp(value: float, lo: float = 0, hi: float = 100) -> int:
    return int(max(lo, min(hi, round(value))))


# ---------------------------------------------------------------------
# SEO scoring weights (sum to 100)
# ---------------------------------------------------------------------
SEO_WEIGHTS = {
    "meta_tags": 25,
    "content_hierarchy": 20,
    "images": 15,
    "technical_files": 20,
    "performance": 20,
}

STATUS_MULTIPLIER = {
    Status.OK: 1.0,
    Status.WARNING: 0.5,
    Status.FAIL: 0.0,
    Status.ERROR: 0.0,
    Status.NOT_APPLICABLE: 1.0,  # don't penalize checks that couldn't run
}


def compute_seo_score(section_statuses: dict[str, Status]) -> int:
    """
    section_statuses maps each SEO_WEIGHTS key to its overall Status.
    """
    total = 0.0
    for section, weight in SEO_WEIGHTS.items():
        status = section_statuses.get(section, Status.NOT_APPLICABLE)
        total += weight * STATUS_MULTIPLIER.get(status, 0.0)
    return clamp(total)


# ---------------------------------------------------------------------
# Security scoring weights
# ---------------------------------------------------------------------
SECURITY_WEIGHTS = {
    "ssl": 35,
    "headers": 45,
    "cookies": 20,
}


def compute_security_score(section_statuses: dict[str, Status]) -> int:
    total = 0.0
    for section, weight in SECURITY_WEIGHTS.items():
        status = section_statuses.get(section, Status.NOT_APPLICABLE)
        total += weight * STATUS_MULTIPLIER.get(status, 0.0)
    return clamp(total)


# Per-header weight, used by the Security engine to derive a
# SecurityHeadersReport.grade independently of the overall score.
SECURITY_HEADER_WEIGHTS = {
    "content-security-policy": 25,
    "strict-transport-security": 25,
    "x-frame-options": 15,
    "x-content-type-options": 15,
    "referrer-policy": 10,
    "permissions-policy": 10,
}


def grade_headers(present_headers: set[str]) -> Grade:
    total = 0
    for header, weight in SECURITY_HEADER_WEIGHTS.items():
        if header in present_headers:
            total += weight
    return score_to_grade(total)
