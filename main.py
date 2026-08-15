#!/usr/bin/env python3
"""
SEO & Security Analyzer — CLI entry point.

Orchestrates the two independent engines and assembles their output
into the single AnalysisReport JSON contract defined in core/schema.py.
This file contains NO analysis logic itself — only wiring, CLI
argument handling, and top-level error containment so that a fatal
failure anywhere still results in a valid JSON payload on stdout.

Usage:
    python main.py https://example.com
    python main.py https://example.com --output report.json
    python main.py https://example.com --pretty --quiet
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

from core.http_client import HttpClient
from core.schema import (
    AnalysisMeta,
    AnalysisReport,
    Recommendation,
    Status,
    now_iso,
)
from engines.security_engine import SecurityAnalyzer
from engines.seo_engine import SEOAnalyzer
from utils.logger import get_logger, set_global_level
from utils.validators import InvalidURLError, normalize_url

logger = get_logger("main")

TOOL_VERSION = "1.0.0"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seo-security-analyzer",
        description="Passively audit a URL's SEO profile and security posture, "
                     "emitting a structured JSON report.",
    )
    parser.add_argument("url", help="Target URL to analyze, e.g. https://example.com")
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write the JSON report to FILE instead of (in addition to) stdout.",
    )
    parser.add_argument(
        "--pretty", action="store_true",
        help="Pretty-print JSON with 2-space indentation (default: compact-ish, still valid JSON).",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress log lines on stderr; only the JSON report is printed to stdout.",
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Do not verify TLS certificates when fetching pages "
             "(SSL grading itself is unaffected — it always verifies independently).",
    )
    return parser


def build_recommendations(report: AnalysisReport) -> list[Recommendation]:
    """
    Translate FAIL/WARNING checks scattered across both engines into a
    single flat, prioritized action list — this is the section a
    frontend "Top fixes" widget would bind to directly.
    """
    recs: list[Recommendation] = []

    def add(id_: str, severity: str, category: str, title: str, description: str) -> None:
        recs.append(Recommendation(id=id_, severity=severity, category=category,
                                    title=title, description=description))

    seo = report.seo
    if seo.meta_tags.title_status == Status.FAIL:
        add("seo.title.missing", "high", "seo", "Add a <title> tag",
            "The page has no title tag, which is one of the strongest on-page ranking signals.")
    elif seo.meta_tags.title_status == Status.WARNING:
        add("seo.title.length", "medium", "seo", "Adjust title length",
            f"Title is {seo.meta_tags.title_length} characters; aim for 30-60 characters.")

    if seo.meta_tags.description_status == Status.FAIL:
        add("seo.description.missing", "high", "seo", "Add a meta description",
            "No meta description was found; search engines will auto-generate a snippet instead.")
    elif seo.meta_tags.description_status == Status.WARNING:
        add("seo.description.length", "low", "seo", "Adjust meta description length",
            f"Description is {seo.meta_tags.description_length} characters; "
            f"aim for 70-160 characters.")

    if seo.content_hierarchy.h1_count == 0:
        add("seo.h1.missing", "high", "seo", "Add an H1 tag",
            "The page has no H1 heading, hurting both SEO and accessibility.")
    elif seo.content_hierarchy.h1_count > 1:
        add("seo.h1.multiple", "medium", "seo", "Reduce to a single H1",
            f"{seo.content_hierarchy.h1_count} H1 tags found; consolidate to one per page.")

    if seo.images.images_missing_alt > 0:
        add("seo.images.alt", "medium", "seo", "Add alt text to images",
            f"{seo.images.images_missing_alt} of {seo.images.total_images} images "
            f"are missing alt attributes, hurting accessibility and image SEO.")

    if not seo.technical_files.robots_txt_found:
        add("seo.robots.missing", "low", "seo", "Add a robots.txt file",
            "No robots.txt was found; add one to guide crawler behavior explicitly.")
    if not seo.technical_files.sitemap_found:
        add("seo.sitemap.missing", "medium", "seo", "Add an XML sitemap",
            "No sitemap.xml was found; a sitemap helps search engines discover all pages.")

    sec = report.security
    if not sec.ssl.is_https:
        add("sec.https.missing", "critical", "security", "Serve the site over HTTPS",
            "The site is not using HTTPS at all, exposing all traffic to interception.")
    elif sec.ssl.status == Status.FAIL:
        add("sec.ssl.invalid", "critical", "security", "Fix the TLS certificate",
            sec.ssl.error or "The TLS certificate failed validation.")
    elif sec.ssl.status == Status.WARNING and sec.ssl.days_until_expiry is not None:
        add("sec.ssl.expiring", "high", "security", "Renew the TLS certificate soon",
            f"Certificate expires in {sec.ssl.days_until_expiry} day(s).")

    for finding in sec.headers.findings:
        if not finding.present:
            severity = "high" if finding.header in (
                "Content-Security-Policy", "Strict-Transport-Security"
            ) else "medium"
            add(f"sec.header.{finding.header.lower()}", severity, "security",
                f"Add the {finding.header} header", finding.note)

    for cookie in sec.cookies.cookies:
        if cookie.status in (Status.WARNING, Status.FAIL):
            add(f"sec.cookie.{cookie.name}", "medium", "security",
                f"Harden cookie '{cookie.name}'", cookie.note)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    recs.sort(key=lambda r: severity_order.get(r.severity, 99))
    return recs


async def run_analysis(raw_url: str, verify_ssl: bool = True) -> AnalysisReport:
    start = time.perf_counter()

    normalized = normalize_url(raw_url)  # raises InvalidURLError, caught by caller
    meta = AnalysisMeta(
        target_url=raw_url,
        normalized_url=normalized.normalized,
        analyzed_at_utc=now_iso(),
        tool_version=TOOL_VERSION,
    )
    report = AnalysisReport(meta=meta)

    async with HttpClient(verify_ssl=verify_ssl) as client:
        # Run both engines concurrently — they share nothing but the client.
        seo_task = asyncio.create_task(
            _safe_run(SEOAnalyzer(client).analyze, normalized.normalized, "SEO")
        )
        security_task = asyncio.create_task(
            _safe_run(SecurityAnalyzer(client).analyze, normalized.normalized, "Security")
        )
        seo_report, security_report = await asyncio.gather(seo_task, security_task)

    if seo_report is not None:
        report.seo = seo_report
    else:
        report.seo.error = "SEO engine crashed unexpectedly; see logs."

    if security_report is not None:
        report.security = security_report
    else:
        report.security.error = "Security engine crashed unexpectedly; see logs."

    report.recommendations = build_recommendations(report)

    has_errors = bool(report.seo.error or report.security.error)
    has_fails = any(
        rec.severity in ("critical", "high") for rec in report.recommendations
    )
    if has_errors:
        report.overall_status = Status.ERROR
    elif has_fails:
        report.overall_status = Status.WARNING
    else:
        report.overall_status = Status.OK

    report.meta.total_duration_ms = round((time.perf_counter() - start) * 1000, 2)
    return report


async def _safe_run(coro_fn, url: str, engine_name: str):
    """
    Last line of defense: even if an engine has a bug that raises instead
    of returning an error-populated dataclass, the CLI still emits valid
    JSON instead of a stack trace.
    """
    try:
        return await coro_fn(url)
    except Exception:  # noqa: BLE001 - intentional, see docstring
        logger.exception("%s engine raised an unhandled exception for %s", engine_name, url)
        return None


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.quiet:
        import logging
        set_global_level(logging.CRITICAL)

    try:
        report = asyncio.run(run_analysis(args.url, verify_ssl=not args.insecure))
    except InvalidURLError as e:
        error_payload = {
            "meta": {"target_url": args.url, "analyzed_at_utc": now_iso()},
            "overall_status": Status.ERROR.value,
            "fatal_error": str(e),
        }
        print(json.dumps(error_payload, indent=2 if args.pretty else None))
        return 2
    except Exception as e:  # noqa: BLE001 - top-level safety net for the whole CLI
        logger.exception("Fatal error during analysis")
        error_payload = {
            "meta": {"target_url": args.url, "analyzed_at_utc": now_iso()},
            "overall_status": Status.ERROR.value,
            "fatal_error": f"Unhandled error: {e}",
        }
        print(json.dumps(error_payload, indent=2 if args.pretty else None))
        return 1

    payload = report.to_dict()
    json_text = json.dumps(payload, indent=2 if args.pretty else None, default=str)

    print(json_text)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_text)
        logger.info("Report written to %s", args.output)

    return 0 if report.overall_status != Status.ERROR else 1


if __name__ == "__main__":
    sys.exit(main())
