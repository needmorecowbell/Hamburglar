"""Web URL scanner module for Hamburglar.

This module provides the WebScanner class which handles scanning web URLs
for secrets and sensitive information. It can fetch URL content, extract
text from HTML, follow links to a configurable depth, and scan inline
and external JavaScript.

The scanner supports:
- Fetching URL content with configurable user agent
- HTML text extraction using BeautifulSoup
- Link following to configurable depth
- Robots.txt respect
- JavaScript file extraction and scanning
- Inline script scanning
- Common encoding handling
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, AsyncIterator
from urllib.parse import urljoin, urlparse

try:
    import httpx
    from bs4 import BeautifulSoup

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from hamburglar.core.exceptions import ScanError
from hamburglar.core.models import Finding, ScanResult
from hamburglar.core.progress import ScanProgress
from hamburglar.scanners import BaseScanner, ProgressCallback

if TYPE_CHECKING:
    from hamburglar.detectors import BaseDetector

logger = logging.getLogger(__name__)

# Default user agent for HTTP requests
DEFAULT_USER_AGENT = (
    "Hamburglar/2.0 (Security Scanner; +https://github.com/needmorecowbell/Hamburglar)"
)

# Default timeout for HTTP requests (seconds)
DEFAULT_TIMEOUT = 30.0

# Default depth for link following
DEFAULT_DEPTH = 1


@dataclass
class RobotsTxt:
    """Parsed robots.txt rules.

    Attributes:
        disallow_patterns: List of disallowed path patterns.
        allow_patterns: List of allowed path patterns (take precedence).
        crawl_delay: Optional crawl delay in seconds.
    """

    disallow_patterns: list[str]
    allow_patterns: list[str]
    crawl_delay: float | None = None


class WebScanner(BaseScanner):
    """Web URL scanner that scans web pages for secrets.

    The WebScanner fetches content from URLs, extracts text from HTML,
    follows links to a configurable depth, and passes content through
    detectors to find sensitive information.

    Features:
    - Configurable user agent
    - HTML text extraction using BeautifulSoup
    - Link following with depth control
    - Robots.txt respect
    - JavaScript file extraction and scanning
    - Inline script scanning
    - Handles common encodings

    Attributes:
        url: The starting URL to scan.
        depth: Maximum depth for following links (0 = only scan the URL).
        include_scripts: Whether to extract and scan JavaScript files.
        user_agent: User agent string for HTTP requests.
        timeout: Timeout for HTTP requests in seconds.
        respect_robots_txt: Whether to respect robots.txt rules.
    """

    def __init__(
        self,
        url: str,
        detectors: list["BaseDetector"] | None = None,
        progress_callback: ProgressCallback | None = None,
        depth: int = DEFAULT_DEPTH,
        include_scripts: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = DEFAULT_TIMEOUT,
        respect_robots_txt: bool = True,
    ):
        """Initialize the web scanner.

        Args:
            url: The starting URL to scan.
            detectors: List of detector instances to use for scanning.
                      If None, no detections will be performed.
            progress_callback: Optional callback function for progress updates.
            depth: Maximum depth for following links (default 1).
                  0 means only scan the starting URL.
            include_scripts: Whether to extract and scan JavaScript files.
            user_agent: User agent string for HTTP requests.
            timeout: Timeout for HTTP requests in seconds.
            respect_robots_txt: Whether to respect robots.txt rules.

        Raises:
            ImportError: If httpx or beautifulsoup4 are not installed.
        """
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "WebScanner requires httpx and beautifulsoup4. "
                "Install them with: pip install httpx beautifulsoup4"
            )

        super().__init__(detectors=detectors, progress_callback=progress_callback)
        self.url = url
        self.depth = depth
        self.include_scripts = include_scripts
        self.user_agent = user_agent
        self.timeout = timeout
        self.respect_robots_txt = respect_robots_txt

        # Internal state
        self._cancel_event = asyncio.Event()
        self._visited_urls: set[str] = set()
        self._robots_cache: dict[str, RobotsTxt | None] = {}

        # Progress tracking
        self._start_time: float = 0.0
        self._urls_scanned: int = 0
        self._scripts_scanned: int = 0
        self._findings_count: int = 0
        self._current_url: str = ""
        self._errors: list[str] = []

    @property
    def scanner_type(self) -> str:
        """Return the type identifier for this scanner.

        Returns:
            'web' - identifies this as a web URL scanner.
        """
        return "web"

    @property
    def is_cancelled(self) -> bool:
        """Check if the scan has been cancelled.

        Returns:
            True if cancellation has been requested, False otherwise.
        """
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        """Request cancellation of the ongoing scan.

        This sets the cancellation event, which will cause the scan to
        stop processing and return partial results.
        """
        self._cancel_event.set()
        logger.info("Web scan cancellation requested")

    def _reset(self) -> None:
        """Reset the scanner state for a new scan."""
        self._cancel_event.clear()
        self._visited_urls.clear()
        self._robots_cache.clear()
        self._start_time = 0.0
        self._urls_scanned = 0
        self._scripts_scanned = 0
        self._findings_count = 0
        self._current_url = ""
        self._errors = []

    def _get_progress(self) -> ScanProgress:
        """Get the current scan progress.

        Returns:
            ScanProgress dataclass with current scan statistics.
        """
        return ScanProgress(
            total_files=0,  # We don't know total upfront for web
            scanned_files=self._urls_scanned + self._scripts_scanned,
            current_file=self._current_url,
            bytes_processed=0,
            findings_count=self._findings_count,
            elapsed_time=time.time() - self._start_time if self._start_time else 0.0,
        )

    def _report_progress_internal(self) -> None:
        """Report progress via callback if one is configured."""
        if self.progress_callback is not None:
            try:
                self.progress_callback(self._get_progress())
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL for comparison.

        Removes fragments, normalizes scheme and trailing slashes.

        Args:
            url: URL to normalize.

        Returns:
            Normalized URL string.
        """
        parsed = urlparse(url)
        # Remove fragment and normalize
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        # Remove trailing slash for consistency (except for root)
        if normalized.endswith("/") and parsed.path != "/":
            normalized = normalized[:-1]
        return normalized

    def _get_base_url(self, url: str) -> str:
        """Get the base URL (scheme + netloc) from a URL.

        Args:
            url: The URL to extract base from.

        Returns:
            Base URL string.
        """
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if a URL is on the same domain as the base URL.

        Args:
            url: URL to check.
            base_url: Base URL for comparison.

        Returns:
            True if same domain, False otherwise.
        """
        url_parsed = urlparse(url)
        base_parsed = urlparse(base_url)
        return url_parsed.netloc == base_parsed.netloc

    async def _fetch_url(
        self,
        url: str,
        client: "httpx.AsyncClient",
    ) -> tuple[str, str] | None:
        """Fetch content from a URL.

        Args:
            url: URL to fetch.
            client: httpx AsyncClient to use.

        Returns:
            Tuple of (content, content_type) or None if fetch failed.
        """
        try:
            response = await client.get(url, follow_redirects=True)
            response.raise_for_status()

            content_type = response.headers.get("content-type", "text/html")

            # Handle different encodings
            try:
                content = response.text
            except Exception:
                # Fall back to bytes if text decoding fails
                content = response.content.decode("utf-8", errors="replace")

            return content, content_type

        except httpx.TimeoutException:
            logger.warning(f"Timeout fetching {url}")
            self._errors.append(f"Timeout: {url}")
            return None
        except httpx.HTTPStatusError as e:
            logger.warning(f"HTTP error {e.response.status_code} for {url}")
            self._errors.append(f"HTTP {e.response.status_code}: {url}")
            return None
        except httpx.RequestError as e:
            logger.warning(f"Request error for {url}: {e}")
            self._errors.append(f"Request error: {url} - {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
            self._errors.append(f"Error: {url} - {e}")
            return None

    async def _fetch_robots_txt(
        self,
        base_url: str,
        client: "httpx.AsyncClient",
    ) -> RobotsTxt | None:
        """Fetch and parse robots.txt for a domain.

        Args:
            base_url: Base URL (scheme + netloc) to fetch robots.txt from.
            client: httpx AsyncClient to use.

        Returns:
            Parsed RobotsTxt or None if not found/parseable.
        """
        robots_url = f"{base_url}/robots.txt"

        try:
            response = await client.get(robots_url, follow_redirects=True)
            if response.status_code != 200:
                return None

            return self._parse_robots_txt(response.text)

        except Exception as e:
            logger.debug(f"Could not fetch robots.txt from {base_url}: {e}")
            return None

    def _parse_robots_txt(self, content: str) -> RobotsTxt:
        """Parse robots.txt content.

        Args:
            content: robots.txt file content.

        Returns:
            Parsed RobotsTxt object.
        """
        disallow_patterns: list[str] = []
        allow_patterns: list[str] = []
        crawl_delay: float | None = None
        user_agent_match = False

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Split on first colon
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            if key == "user-agent":
                # Match all user agents (*) or our specific agent
                user_agent_match = value == "*" or "hamburglar" in value.lower()
            elif user_agent_match:
                if key == "disallow" and value:
                    disallow_patterns.append(value)
                elif key == "allow" and value:
                    allow_patterns.append(value)
                elif key == "crawl-delay":
                    try:
                        crawl_delay = float(value)
                    except ValueError:
                        pass

        return RobotsTxt(
            disallow_patterns=disallow_patterns,
            allow_patterns=allow_patterns,
            crawl_delay=crawl_delay,
        )

    def _is_allowed_by_robots(self, url: str, robots: RobotsTxt | None) -> bool:
        """Check if a URL is allowed by robots.txt rules.

        Args:
            url: URL to check.
            robots: Parsed robots.txt or None.

        Returns:
            True if allowed, False if disallowed.
        """
        if robots is None:
            return True

        parsed = urlparse(url)
        path = parsed.path or "/"

        # Check allow patterns first (they take precedence)
        for pattern in robots.allow_patterns:
            if path.startswith(pattern):
                return True

        # Check disallow patterns
        for pattern in robots.disallow_patterns:
            if path.startswith(pattern):
                return False

        return True

    def _extract_text_from_html(self, html: str) -> str:
        """Extract text content from HTML.

        Args:
            html: HTML content to extract text from.

        Returns:
            Extracted text content.
        """
        soup = BeautifulSoup(html, "html.parser")

        # Remove script and style elements
        for element in soup(["script", "style"]):
            element.decompose()

        # Get text with preserved whitespace
        text = soup.get_text(separator="\n", strip=True)

        return text

    def _extract_inline_scripts(self, html: str) -> list[str]:
        """Extract inline script content from HTML.

        Args:
            html: HTML content to extract scripts from.

        Returns:
            List of inline script contents.
        """
        soup = BeautifulSoup(html, "html.parser")
        scripts = []

        for script in soup.find_all("script"):
            # Only get inline scripts (not external ones with src)
            if not script.get("src") and script.string:
                scripts.append(script.string)

        return scripts

    def _extract_script_urls(self, html: str, base_url: str) -> list[str]:
        """Extract external script URLs from HTML.

        Args:
            html: HTML content to extract script URLs from.
            base_url: Base URL for resolving relative URLs.

        Returns:
            List of absolute script URLs.
        """
        soup = BeautifulSoup(html, "html.parser")
        script_urls = []

        for script in soup.find_all("script", src=True):
            src = script.get("src")
            if src:
                # Resolve relative URLs
                absolute_url = urljoin(base_url, src)
                script_urls.append(absolute_url)

        return script_urls

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract links from HTML.

        Args:
            html: HTML content to extract links from.
            base_url: Base URL for resolving relative URLs.

        Returns:
            List of absolute link URLs.
        """
        soup = BeautifulSoup(html, "html.parser")
        links = []

        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                # Resolve relative URLs
                absolute_url = urljoin(base_url, href)
                links.append(absolute_url)

        return links

    async def _scan_content(
        self,
        content: str,
        source: str,
        context: dict | None = None,
    ) -> list[Finding]:
        """Scan content with all detectors.

        Args:
            content: Content to scan.
            source: Source identifier (URL, script path, etc.).
            context: Additional context to add to findings.

        Returns:
            List of findings from all detectors.
        """
        findings: list[Finding] = []

        for detector in self.detectors:
            if self.is_cancelled:
                break
            try:
                detector_findings = detector.detect(content, source)
                # Add context to findings if provided
                if context:
                    for finding in detector_findings:
                        finding.metadata.update(context)
                findings.extend(detector_findings)
                self._findings_count += len(detector_findings)
            except Exception as e:
                logger.error(f"Detector {detector.name} failed on {source}: {e}")
                self._errors.append(f"Detector {detector.name} error on {source}: {e}")

        return findings

    async def _scan_url(
        self,
        url: str,
        client: "httpx.AsyncClient",
        current_depth: int,
        robots: RobotsTxt | None,
    ) -> tuple[list[Finding], list[str]]:
        """Scan a single URL and extract findings and links.

        Args:
            url: URL to scan.
            client: httpx AsyncClient to use.
            current_depth: Current depth in link following.
            robots: Parsed robots.txt for this domain.

        Returns:
            Tuple of (findings, discovered_links).
        """
        findings: list[Finding] = []
        discovered_links: list[str] = []

        # Check robots.txt
        if self.respect_robots_txt and not self._is_allowed_by_robots(url, robots):
            logger.debug(f"Skipping {url} due to robots.txt")
            return findings, discovered_links

        self._current_url = url
        self._report_progress_internal()

        # Fetch the URL
        result = await self._fetch_url(url, client)
        if result is None:
            return findings, discovered_links

        content, content_type = result
        self._urls_scanned += 1

        # Determine if this is HTML content
        is_html = "text/html" in content_type.lower()

        if is_html:
            # Extract and scan text from HTML
            text = self._extract_text_from_html(content)
            if text:
                text_findings = await self._scan_content(
                    text,
                    url,
                    context={"source_type": "html_text", "url": url},
                )
                findings.extend(text_findings)

            # Scan inline scripts
            inline_scripts = self._extract_inline_scripts(content)
            for i, script in enumerate(inline_scripts):
                if self.is_cancelled:
                    break
                script_findings = await self._scan_content(
                    script,
                    f"{url}#inline-script-{i}",
                    context={
                        "source_type": "inline_script",
                        "url": url,
                        "script_index": i,
                    },
                )
                findings.extend(script_findings)

            # Extract and scan external JavaScript files
            if self.include_scripts:
                script_urls = self._extract_script_urls(content, url)
                for script_url in script_urls:
                    if self.is_cancelled:
                        break
                    script_findings = await self._scan_script(
                        script_url, client, robots
                    )
                    findings.extend(script_findings)

            # Extract links for following (if we haven't reached max depth)
            if current_depth < self.depth:
                links = self._extract_links(content, url)
                base_url = self._get_base_url(url)

                for link in links:
                    normalized = self._normalize_url(link)
                    # Only follow links on the same domain
                    if (
                        self._is_same_domain(link, base_url)
                        and normalized not in self._visited_urls
                    ):
                        discovered_links.append(normalized)

        else:
            # For non-HTML content (e.g., JavaScript), scan directly
            content_findings = await self._scan_content(
                content,
                url,
                context={"source_type": content_type, "url": url},
            )
            findings.extend(content_findings)

        return findings, discovered_links

    async def _scan_script(
        self,
        script_url: str,
        client: "httpx.AsyncClient",
        robots: RobotsTxt | None,
    ) -> list[Finding]:
        """Scan an external JavaScript file.

        Args:
            script_url: URL of the script to scan.
            client: httpx AsyncClient to use.
            robots: Parsed robots.txt for this domain.

        Returns:
            List of findings from the script.
        """
        # Check if already visited
        normalized = self._normalize_url(script_url)
        if normalized in self._visited_urls:
            return []

        self._visited_urls.add(normalized)

        # Check robots.txt
        if self.respect_robots_txt and not self._is_allowed_by_robots(script_url, robots):
            logger.debug(f"Skipping script {script_url} due to robots.txt")
            return []

        self._current_url = script_url
        self._report_progress_internal()

        result = await self._fetch_url(script_url, client)
        if result is None:
            return []

        content, _ = result
        self._scripts_scanned += 1

        return await self._scan_content(
            content,
            script_url,
            context={"source_type": "external_script", "url": script_url},
        )

    async def scan(self) -> ScanResult:
        """Execute the scan operation.

        Fetches the starting URL, extracts and scans content, follows links
        to the configured depth, and scans JavaScript files.

        Returns:
            ScanResult containing all findings and scan statistics.

        Raises:
            ScanError: If the URL is invalid or inaccessible.
        """
        self._reset()
        self._start_time = time.time()

        # Validate URL
        parsed = urlparse(self.url)
        if parsed.scheme not in ("http", "https"):
            raise ScanError(
                f"Invalid URL scheme: {parsed.scheme}",
                context={"url": self.url, "expected": "http or https"},
            )

        if not parsed.netloc:
            raise ScanError(
                "Invalid URL: missing domain",
                context={"url": self.url},
            )

        base_url = self._get_base_url(self.url)
        all_findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
        ) as client:
            # Fetch robots.txt if respecting it
            robots: RobotsTxt | None = None
            if self.respect_robots_txt:
                robots = await self._fetch_robots_txt(base_url, client)
                self._robots_cache[base_url] = robots

            # Initialize with starting URL
            normalized_start = self._normalize_url(self.url)
            urls_to_scan = [(normalized_start, 0)]  # (url, depth)
            self._visited_urls.add(normalized_start)

            while urls_to_scan and not self.is_cancelled:
                url, current_depth = urls_to_scan.pop(0)

                findings, discovered_links = await self._scan_url(
                    url, client, current_depth, robots
                )
                all_findings.extend(findings)

                # Add discovered links to queue
                for link in discovered_links:
                    if link not in self._visited_urls:
                        self._visited_urls.add(link)
                        urls_to_scan.append((link, current_depth + 1))

                # Respect crawl delay if specified
                if robots and robots.crawl_delay and urls_to_scan:
                    await asyncio.sleep(robots.crawl_delay)

        scan_duration = time.time() - self._start_time
        logger.info(
            f"Web scan complete: {self._urls_scanned} URLs, "
            f"{self._scripts_scanned} scripts, {len(all_findings)} findings"
            + (" (cancelled)" if self.is_cancelled else "")
        )

        return ScanResult(
            target_path=self.url,
            findings=all_findings,
            scan_duration=scan_duration,
            stats={
                "urls_scanned": self._urls_scanned,
                "scripts_scanned": self._scripts_scanned,
                "total_findings": len(all_findings),
                "cancelled": self.is_cancelled,
                "errors": self._errors,
                "depth": self.depth,
                "include_scripts": self.include_scripts,
            },
        )

    async def scan_stream(self) -> AsyncIterator[Finding]:
        """Execute the scan and stream findings as they're discovered.

        This is an async generator that yields findings as they're found,
        allowing for real-time processing of results.

        Yields:
            Finding objects as they're discovered during the scan.

        Raises:
            ScanError: If the URL is invalid or inaccessible.
        """
        self._reset()
        self._start_time = time.time()

        # Validate URL
        parsed = urlparse(self.url)
        if parsed.scheme not in ("http", "https"):
            raise ScanError(
                f"Invalid URL scheme: {parsed.scheme}",
                context={"url": self.url, "expected": "http or https"},
            )

        if not parsed.netloc:
            raise ScanError(
                "Invalid URL: missing domain",
                context={"url": self.url},
            )

        base_url = self._get_base_url(self.url)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
        ) as client:
            # Fetch robots.txt if respecting it
            robots: RobotsTxt | None = None
            if self.respect_robots_txt:
                robots = await self._fetch_robots_txt(base_url, client)
                self._robots_cache[base_url] = robots

            # Initialize with starting URL
            normalized_start = self._normalize_url(self.url)
            urls_to_scan = [(normalized_start, 0)]  # (url, depth)
            self._visited_urls.add(normalized_start)

            while urls_to_scan and not self.is_cancelled:
                url, current_depth = urls_to_scan.pop(0)

                findings, discovered_links = await self._scan_url(
                    url, client, current_depth, robots
                )

                for finding in findings:
                    yield finding

                # Add discovered links to queue
                for link in discovered_links:
                    if link not in self._visited_urls:
                        self._visited_urls.add(link)
                        urls_to_scan.append((link, current_depth + 1))

                # Respect crawl delay if specified
                if robots and robots.crawl_delay and urls_to_scan:
                    await asyncio.sleep(robots.crawl_delay)

        logger.info(
            f"Web stream scan complete: {self._urls_scanned} URLs, "
            f"{self._scripts_scanned} scripts"
        )

    def get_stats(self) -> dict:
        """Get current scan statistics.

        Returns:
            Dictionary with current scan statistics.
        """
        return {
            "urls_scanned": self._urls_scanned,
            "scripts_scanned": self._scripts_scanned,
            "findings_count": self._findings_count,
            "elapsed_time": time.time() - self._start_time if self._start_time else 0.0,
            "cancelled": self.is_cancelled,
            "errors": self._errors,
        }
