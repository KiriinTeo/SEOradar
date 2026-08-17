"""
SEO Analyzer Engine.

Fully independent of the Security engine. Given a base URL, it fetches
the page once and reuses that DOM for every check (meta tags, headings,
images), then makes a small number of additional requests for
robots.txt / sitemap.xml. Every method degrades gracefully: a parsing
or network failure inside one sub-check never prevents the others from
running, and always leaves a Status.ERROR trail in the output rather
than raising.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from bs4 import BeautifulSoup

from core.http_client import FetchResult, HttpClient
from core.schema import (
    CheckResult,
    ContentHierarchyReport,
    HeadingNode,
    ImageAuditReport,
    MetaTagsReport,
    PerformanceReport,
    SEOReport,
    Status,
    TechnicalFilesReport,
)
from core.scorer import SEO_WEIGHTS, compute_seo_score
from utils.logger import get_logger

logger = get_logger(__name__)

TITLE_MIN, TITLE_MAX = 30, 60
DESCRIPTION_MIN, DESCRIPTION_MAX = 70, 160
SLOW_RESPONSE_MS = 1000
VERY_SLOW_RESPONSE_MS = 3000


class SEOAnalyzer:
    """
    Usage:
        async with HttpClient() as client:
            report = await SEOAnalyzer(client).analyze(url)
    """

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    async def analyze(self, url: str) -> SEOReport:
        report = SEOReport()

        page = await self._client.get(url)
        if not page.ok or page.text is None:
            report.error = page.error or "Page could not be fetched or returned no text content."
            report.performance = self._build_performance_report(url, page)
            report.grade = None
            return report

        soup = BeautifulSoup(page.text, "lxml")

        report.meta_tags = self._analyze_meta_tags(soup, page)
        report.content_hierarchy = self._analyze_headings(soup)
        report.images = self._analyze_images(soup, page)
        report.performance = self._build_performance_report(url, page)
        report.technical_files = await self._analyze_technical_files(url)

        section_statuses = {
            "meta_tags": self._worst_status(report.meta_tags.checks),
            "content_hierarchy": self._worst_status(report.content_hierarchy.checks),
            "images": self._worst_status(report.images.checks),
            "technical_files": self._worst_status(report.technical_files.checks),
            "performance": self._worst_status(report.performance.checks),
        }
        report.score = compute_seo_score(section_statuses)
        from core.scorer import score_to_grade  # local import avoids a cycle at module load
        report.grade = score_to_grade(report.score)

        return report

    # ------------------------------------------------------------------
    # Meta tags: title, description, canonical, Open Graph, Twitter Card
    # ------------------------------------------------------------------
    def _analyze_meta_tags(self, soup: BeautifulSoup, page: FetchResult) -> MetaTagsReport:
        report = MetaTagsReport()
        checks: list[CheckResult] = []

        title_tag = soup.find("title")
        title_text = title_tag.get_text(strip=True) if title_tag else None
        report.title = title_text
        report.title_length = len(title_text) if title_text else 0

        if not title_text:
            report.title_status = Status.FAIL
            checks.append(CheckResult(
                id="title.missing", label="Title Tag", status=Status.FAIL,
                message="No <title> tag found.",
            ))
        elif TITLE_MIN <= len(title_text) <= TITLE_MAX:
            report.title_status = Status.OK
            checks.append(CheckResult(
                id="title.length", label="Title Length", status=Status.OK,
                message=f"Title length ({len(title_text)} chars) is within the ideal "
                        f"{TITLE_MIN}-{TITLE_MAX} char range.",
            ))
        else:
            report.title_status = Status.WARNING
            checks.append(CheckResult(
                id="title.length", label="Title Length", status=Status.WARNING,
                message=f"Title length ({len(title_text)} chars) is outside the ideal "
                        f"{TITLE_MIN}-{TITLE_MAX} char range.",
            ))

        desc_tag = soup.find("meta", attrs={"name": "description"})
        desc_text = desc_tag.get("content", "").strip() if desc_tag else None
        report.description = desc_text
        report.description_length = len(desc_text) if desc_text else 0

        if not desc_text:
            report.description_status = Status.FAIL
            checks.append(CheckResult(
                id="description.missing", label="Meta Description", status=Status.FAIL,
                message="No meta description tag found.",
            ))
        elif DESCRIPTION_MIN <= len(desc_text) <= DESCRIPTION_MAX:
            report.description_status = Status.OK
            checks.append(CheckResult(
                id="description.length", label="Description Length", status=Status.OK,
                message=f"Description length ({len(desc_text)} chars) is within the ideal "
                        f"{DESCRIPTION_MIN}-{DESCRIPTION_MAX} char range.",
            ))
        else:
            report.description_status = Status.WARNING
            checks.append(CheckResult(
                id="description.length", label="Description Length", status=Status.WARNING,
                message=f"Description length ({len(desc_text)} chars) is outside the ideal "
                        f"{DESCRIPTION_MIN}-{DESCRIPTION_MAX} char range.",
            ))

        canonical_tag = soup.find("link", attrs={"rel": "canonical"})
        canonical_href = canonical_tag.get("href") if canonical_tag else None
        report.canonical_url = canonical_href
        if canonical_href:
            report.canonical_status = Status.OK
            checks.append(CheckResult(
                id="canonical.present", label="Canonical URL", status=Status.OK,
                message=f"Canonical URL is set to '{canonical_href}'.",
            ))
        else:
            report.canonical_status = Status.WARNING
            checks.append(CheckResult(
                id="canonical.missing", label="Canonical URL", status=Status.WARNING,
                message="No canonical link tag found; risk of duplicate-content indexing.",
            ))

        og_tags = {
            m.get("property", "").replace("og:", ""): m.get("content", "")
            for m in soup.find_all("meta", attrs={"property": lambda p: p and p.startswith("og:")})
        }
        report.open_graph = og_tags
        required_og = {"title", "description", "image", "url"}
        missing_og = required_og - og_tags.keys()
        if not missing_og:
            report.open_graph_status = Status.OK
            checks.append(CheckResult(
                id="og.complete", label="Open Graph Tags", status=Status.OK,
                message="All core Open Graph tags (title, description, image, url) are present.",
            ))
        elif og_tags:
            report.open_graph_status = Status.WARNING
            checks.append(CheckResult(
                id="og.partial", label="Open Graph Tags", status=Status.WARNING,
                message=f"Missing Open Graph tags: {', '.join(sorted(missing_og))}.",
            ))
        else:
            report.open_graph_status = Status.FAIL
            checks.append(CheckResult(
                id="og.missing", label="Open Graph Tags", status=Status.FAIL,
                message="No Open Graph tags found; link previews on social platforms will be poor.",
            ))

        twitter_tags = {
            m.get("name", "").replace("twitter:", ""): m.get("content", "")
            for m in soup.find_all("meta", attrs={"name": lambda n: n and n.startswith("twitter:")})
        }
        report.twitter_card = twitter_tags
        if twitter_tags.get("card"):
            report.twitter_card_status = Status.OK
            checks.append(CheckResult(
                id="twitter.present", label="Twitter Card", status=Status.OK,
                message=f"Twitter card type set to '{twitter_tags['card']}'.",
            ))
        else:
            report.twitter_card_status = Status.WARNING
            checks.append(CheckResult(
                id="twitter.missing", label="Twitter Card", status=Status.WARNING,
                message="No twitter:card meta tag found.",
            ))

        report.checks = checks
        return report

    # ------------------------------------------------------------------
    # Content hierarchy: H1-H6 structure
    # ------------------------------------------------------------------
    def _analyze_headings(self, soup: BeautifulSoup) -> ContentHierarchyReport:
        report = ContentHierarchyReport()
        checks: list[CheckResult] = []

        counts = {f"h{i}": 0 for i in range(1, 7)}
        headings: list[HeadingNode] = []
        for level in range(1, 7):
            tags = soup.find_all(f"h{level}")
            counts[f"h{level}"] = len(tags)
            for t in tags:
                text = t.get_text(strip=True)
                headings.append(HeadingNode(level=level, text=text[:200]))

        report.heading_counts = counts
        report.headings = headings
        report.h1_count = counts["h1"]

        if report.h1_count == 0:
            report.status = Status.FAIL
            checks.append(CheckResult(
                id="h1.missing", label="H1 Tag", status=Status.FAIL,
                message="No H1 tag found on the page.",
            ))
        elif report.h1_count > 1:
            report.status = Status.WARNING
            checks.append(CheckResult(
                id="h1.multiple", label="H1 Tag", status=Status.WARNING,
                message=f"Multiple H1 tags found ({report.h1_count}); a page should generally "
                        f"have exactly one.",
            ))
        else:
            report.status = Status.OK
            checks.append(CheckResult(
                id="h1.single", label="H1 Tag", status=Status.OK,
                message="Exactly one H1 tag found.",
            ))

        # Detect skipped levels, e.g. H2 -> H4 with no H3 in between.
        present_levels = [lvl for lvl in range(1, 7) if counts[f"h{lvl}"] > 0]
        skipped = any(
            b - a > 1 for a, b in zip(present_levels, present_levels[1:])
        )
        if skipped:
            checks.append(CheckResult(
                id="hierarchy.skipped_level", label="Heading Order", status=Status.WARNING,
                message="Heading levels are skipped (e.g. H2 directly followed by H4), "
                        "which can confuse assistive technology and crawlers.",
            ))
            if report.status == Status.OK:
                report.status = Status.WARNING

        report.checks = checks
        return report

    # ------------------------------------------------------------------
    # Images: missing alt attributes
    # ------------------------------------------------------------------
    def _analyze_images(self, soup: BeautifulSoup, page: FetchResult) -> ImageAuditReport:
        report = ImageAuditReport()
        checks: list[CheckResult] = []

        images = soup.find_all("img")
        report.total_images = len(images)

        missing = []
        for img in images:
            alt = img.get("alt")
            if alt is None or alt.strip() == "":
                src = img.get("src") or img.get("data-src") or "(no src attribute)"
                # Resolve to absolute URL for the frontend to display/link.
                try:
                    resolved = urljoin(page.final_url or page.url, src)
                except ValueError:
                    resolved = src
                missing.append(resolved)

        report.images_missing_alt = len(missing)
        report.missing_alt_sources = missing[:50]  # cap payload size on image-heavy pages

        if report.total_images == 0:
            report.status = Status.NOT_APPLICABLE
            checks.append(CheckResult(
                id="images.none", label="Image Alt Attributes", status=Status.NOT_APPLICABLE,
                message="No <img> tags found on the page.",
            ))
        elif report.images_missing_alt == 0:
            report.status = Status.OK
            checks.append(CheckResult(
                id="images.alt_complete", label="Image Alt Attributes", status=Status.OK,
                message=f"All {report.total_images} images have alt attributes.",
            ))
        else:
            ratio = report.images_missing_alt / report.total_images
            status = Status.FAIL if ratio > 0.5 else Status.WARNING
            report.status = status
            checks.append(CheckResult(
                id="images.alt_missing", label="Image Alt Attributes", status=status,
                message=f"{report.images_missing_alt} of {report.total_images} images "
                        f"are missing alt attributes.",
            ))

        report.checks = checks
        return report

    # ------------------------------------------------------------------
    # Performance: response time, redirects, canonical consistency
    # ------------------------------------------------------------------
    def _build_performance_report(self, requested_url: str, page: FetchResult) -> PerformanceReport:
        report = PerformanceReport()
        checks: list[CheckResult] = []

        report.http_status_code = page.status_code
        report.response_time_ms = page.elapsed_ms
        report.redirect_count = len(page.redirect_chain)
        report.redirect_chain = [
            {"url": hop.url, "status_code": hop.status_code} for hop in page.redirect_chain
        ]

        if not page.ok:
            report.status = Status.ERROR
            checks.append(CheckResult(
                id="performance.fetch_failed", label="Page Fetch", status=Status.ERROR,
                message=page.error or "Unknown fetch error.",
            ))
            report.checks = checks
            return report

        if page.status_code and page.status_code >= 400:
            report.status = Status.FAIL
            checks.append(CheckResult(
                id="performance.http_error", label="HTTP Status", status=Status.FAIL,
                message=f"Page returned HTTP {page.status_code}.",
            ))
        elif page.elapsed_ms and page.elapsed_ms > VERY_SLOW_RESPONSE_MS:
            report.status = Status.FAIL
            checks.append(CheckResult(
                id="performance.very_slow", label="Response Time", status=Status.FAIL,
                message=f"Response took {page.elapsed_ms:.0f}ms, well above the "
                        f"{VERY_SLOW_RESPONSE_MS}ms threshold.",
            ))
        elif page.elapsed_ms and page.elapsed_ms > SLOW_RESPONSE_MS:
            report.status = Status.WARNING
            checks.append(CheckResult(
                id="performance.slow", label="Response Time", status=Status.WARNING,
                message=f"Response took {page.elapsed_ms:.0f}ms, above the "
                        f"{SLOW_RESPONSE_MS}ms comfort threshold.",
            ))
        else:
            report.status = Status.OK
            checks.append(CheckResult(
                id="performance.fast", label="Response Time", status=Status.OK,
                message=f"Response returned in {page.elapsed_ms:.0f}ms.",
            ))

        if report.redirect_count > 2:
            checks.append(CheckResult(
                id="performance.many_redirects", label="Redirect Chain", status=Status.WARNING,
                message=f"{report.redirect_count} redirects before reaching the final URL; "
                        f"each hop adds latency and dilutes link equity.",
            ))
            if report.status == Status.OK:
                report.status = Status.WARNING
        elif report.redirect_count > 0:
            checks.append(CheckResult(
                id="performance.redirects", label="Redirect Chain", status=Status.OK,
                message=f"{report.redirect_count} redirect(s) before the final URL.",
            ))

        report.checks = checks
        return report

    # ------------------------------------------------------------------
    # Technical SEO files: robots.txt, sitemap.xml
    # ------------------------------------------------------------------
    async def _analyze_technical_files(self, base_url: str) -> TechnicalFilesReport:
        report = TechnicalFilesReport()
        checks: list[CheckResult] = []

        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"

        robots_result = await self._client.get(urljoin(root, "/robots.txt"))
        sitemap_refs: list[str] = []

        if robots_result.ok and robots_result.status_code == 200 and robots_result.text:
            report.robots_txt_found = True
            report.robots_txt_status_code = robots_result.status_code

            lines = [ln.strip() for ln in robots_result.text.splitlines()]
            disallow_all = any(
                ln.lower().replace(" ", "") in ("disallow:/", "disallow:*") for ln in lines
            )
            report.robots_txt_disallows_all = disallow_all
            sitemap_refs = [
                ln.split(":", 1)[1].strip()
                for ln in lines
                if ln.lower().startswith("sitemap:") and ":" in ln
            ]
            report.robots_txt_sitemap_refs = sitemap_refs

            if disallow_all:
                checks.append(CheckResult(
                    id="robots.disallow_all", label="robots.txt", status=Status.FAIL,
                    message="robots.txt disallows all crawlers from the entire site.",
                ))
            else:
                checks.append(CheckResult(
                    id="robots.found", label="robots.txt", status=Status.OK,
                    message="robots.txt found and does not block the entire site.",
                ))
        else:
            report.robots_txt_found = False
            report.robots_txt_status_code = robots_result.status_code
            checks.append(CheckResult(
                id="robots.missing", label="robots.txt", status=Status.WARNING,
                message="robots.txt was not found (or did not return 200 OK).",
            ))

        sitemap_url = sitemap_refs[0] if sitemap_refs else urljoin(root, "/sitemap.xml")
        sitemap_result = await self._client.get(sitemap_url)

        if sitemap_result.ok and sitemap_result.status_code == 200 and sitemap_result.text:
            report.sitemap_found = True
            report.sitemap_status_code = sitemap_result.status_code
            try:
                xml_root = ElementTree.fromstring(sitemap_result.text.encode("utf-8"))
                # Namespace-agnostic count of <url> or <sitemap> children.
                url_count = sum(
                    1 for el in xml_root.iter() if el.tag.rsplit("}", 1)[-1] in ("url", "sitemap")
                )
                report.sitemap_url_count = url_count
                report.sitemap_is_valid_xml = True
                checks.append(CheckResult(
                    id="sitemap.valid", label="sitemap.xml", status=Status.OK,
                    message=f"sitemap.xml is valid XML and references {url_count} entries.",
                ))
            except ElementTree.ParseError as e:
                report.sitemap_is_valid_xml = False
                checks.append(CheckResult(
                    id="sitemap.invalid_xml", label="sitemap.xml", status=Status.FAIL,
                    message=f"sitemap.xml was found but is not valid XML: {e}",
                ))
        else:
            report.sitemap_found = False
            report.sitemap_status_code = sitemap_result.status_code
            checks.append(CheckResult(
                id="sitemap.missing", label="sitemap.xml", status=Status.WARNING,
                message=f"No sitemap found at '{sitemap_url}'.",
            ))

        statuses = [c.status for c in checks]
        report.status = self._worst_status(checks)
        report.checks = checks
        return report

    # ------------------------------------------------------------------
    @staticmethod
    def _worst_status(checks: list[CheckResult]) -> Status:
        """FAIL/ERROR > WARNING > OK > N/A, used to roll many checks into one section status."""
        priority = {
            Status.ERROR: 4,
            Status.FAIL: 3,
            Status.WARNING: 2,
            Status.OK: 1,
            Status.NOT_APPLICABLE: 0,
        }
        if not checks:
            return Status.NOT_APPLICABLE
        return max((c.status for c in checks), key=lambda s: priority[s])
