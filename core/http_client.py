"""
Shared async HTTP client wrapper.

Both engines fetch through this module instead of calling httpx
directly, so timing, redirect-chain capture, and error normalization
happen exactly once and stay consistent between the SEO and Security
reports (they should agree on "how long did this take" and "what did
the redirect chain look like").
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT = httpx.Timeout(connect=8.0, read=10.0, write=8.0, pool=8.0)
DEFAULT_USER_AGENT = (
    "SEOSecurityAnalyzer/1.0 (+passive-audit-bot; "
    "contact: not-configured) Mozilla/5.0 compatible"
)


@dataclass
class RedirectHop:
    url: str
    status_code: int


@dataclass
class FetchResult:
    ok: bool
    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    headers: dict = field(default_factory=dict)
    text: Optional[str] = None
    elapsed_ms: Optional[float] = None
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    error: Optional[str] = None
    error_type: Optional[str] = None
    cookies: dict = field(default_factory=dict)


class HttpClient:
    """Thin async wrapper around httpx.AsyncClient with consistent error handling."""

    def __init__(
        self,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_ssl: bool = True,
        max_redirects: int = 10,
    ) -> None:
        self._timeout = timeout
        self._headers = {"User-Agent": user_agent}
        self._verify_ssl = verify_ssl
        self._max_redirects = max_redirects
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "HttpClient":
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            headers=self._headers,
            verify=self._verify_ssl,
            follow_redirects=True,
            max_redirects=self._max_redirects,
            http2=True,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def get(self, url: str) -> FetchResult:
        """
        GET a URL, capturing timing + redirect chain.
        Never raises — all failure modes are captured in FetchResult.
        """
        assert self._client is not None, "HttpClient must be used as an async context manager"

        start = time.perf_counter()
        try:
            response = await self._client.get(url)
        except httpx.ConnectTimeout:
            return self._error_result(url, "connect_timeout", "Connection timed out.")
        except httpx.ReadTimeout:
            return self._error_result(url, "read_timeout", "Server took too long to respond.")
        except httpx.ConnectError as e:
            return self._error_result(url, "connect_error", f"Could not connect: {e}")
        except httpx.TooManyRedirects:
            return self._error_result(url, "too_many_redirects", "Redirect loop detected.")
        except httpx.HTTPError as e:
            return self._error_result(url, "http_error", str(e))
        except Exception as e:  # noqa: BLE001 - last line of defense, tool must not crash
            logger.exception("Unexpected error fetching %s", url)
            return self._error_result(url, "unexpected_error", str(e))

        elapsed_ms = (time.perf_counter() - start) * 1000

        redirect_chain = [
            RedirectHop(url=str(r.url), status_code=r.status_code)
            for r in response.history
        ]

        cookies = {c.name: {
            "value_present": bool(c.value),
            "domain": c.domain,
            "path": c.path,
            "secure": c.secure,
            # httpx's cookiejar doesn't expose HttpOnly/SameSite directly;
            # those are parsed from the raw Set-Cookie header in the
            # Security engine, which has access to raw header text.
        } for c in response.cookies.jar}

        return FetchResult(
            ok=True,
            url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text if self._is_textual(response) else None,
            elapsed_ms=round(elapsed_ms, 2),
            redirect_chain=redirect_chain,
            cookies=cookies,
        )

    @staticmethod
    def _is_textual(response: httpx.Response) -> bool:
        content_type = response.headers.get("content-type", "")
        return any(t in content_type for t in ("text/", "application/xml", "application/json"))

    @staticmethod
    def _error_result(url: str, error_type: str, message: str) -> FetchResult:
        logger.warning("Fetch failed for %s [%s]: %s", url, error_type, message)
        return FetchResult(ok=False, url=url, error=message, error_type=error_type)
