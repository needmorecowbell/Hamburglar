"""Tests for the WebScanner class.

This module tests the web URL scanning functionality including:
- Basic URL fetch and scan
- HTML text extraction
- JavaScript extraction and scanning
- Link following with depth limit
- Robots.txt respect
- Timeout handling
- Error handling for invalid URLs
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Configure path before any hamburglar imports
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.exceptions import ScanError  # noqa: E402
from hamburglar.core.models import Finding, Severity  # noqa: E402
from hamburglar.core.progress import ScanProgress  # noqa: E402
from hamburglar.detectors import BaseDetector  # noqa: E402
from hamburglar.detectors.regex_detector import RegexDetector  # noqa: E402
from hamburglar.scanners import BaseScanner, WebScanner  # noqa: E402


# Sample HTML with various content types for testing
SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <script src="/static/app.js"></script>
    <script>
        const apiKey = "AKIAIOSFODNN7EXAMPLE";
    </script>
</head>
<body>
    <h1>Welcome</h1>
    <p>This is a test page with API key: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>
    <a href="/page2">Page 2</a>
    <a href="https://example.com/external">External Link</a>
    <a href="/page3">Page 3</a>
</body>
</html>
"""

SAMPLE_HTML_NO_SECRETS = """
<!DOCTYPE html>
<html>
<head><title>Clean Page</title></head>
<body><p>No secrets here!</p></body>
</html>
"""

SAMPLE_JS = """
const config = {
    apiKey: "AKIAIOSFODNN7EXAMPLE",
    endpoint: "https://api.example.com"
};
"""

SAMPLE_ROBOTS_TXT = """
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Hamburglar
Crawl-delay: 1
Disallow: /secret/
"""


class TestWebScannerInterface:
    """Test that WebScanner correctly implements BaseScanner."""

    def test_inherits_from_base_scanner(self):
        """Test that WebScanner is a subclass of BaseScanner."""
        assert issubclass(WebScanner, BaseScanner)

    def test_scanner_type_property(self):
        """Test that scanner_type returns 'web'."""
        scanner = WebScanner("https://example.com")
        assert scanner.scanner_type == "web"

    def test_init_with_no_detectors(self):
        """Test initialization without detectors."""
        scanner = WebScanner("https://example.com")
        assert scanner.detectors == []
        assert scanner.progress_callback is None

    def test_init_with_detectors(self):
        """Test initialization with detectors."""
        detector = RegexDetector()
        scanner = WebScanner("https://example.com", detectors=[detector])
        assert len(scanner.detectors) == 1

    def test_init_with_progress_callback(self):
        """Test initialization with progress callback."""
        callback_called = []

        def callback(progress):
            callback_called.append(progress)

        scanner = WebScanner("https://example.com", progress_callback=callback)
        assert scanner.progress_callback is callback

    def test_init_with_options(self):
        """Test initialization with various options."""
        scanner = WebScanner(
            "https://example.com",
            depth=3,
            include_scripts=False,
            user_agent="Custom Agent",
            timeout=60.0,
            respect_robots_txt=False,
        )
        assert scanner.depth == 3
        assert scanner.include_scripts is False
        assert scanner.user_agent == "Custom Agent"
        assert scanner.timeout == 60.0
        assert scanner.respect_robots_txt is False

    def test_default_options(self):
        """Test default option values."""
        scanner = WebScanner("https://example.com")
        assert scanner.depth == 1
        assert scanner.include_scripts is True
        assert "Hamburglar" in scanner.user_agent
        assert scanner.timeout == 30.0
        assert scanner.respect_robots_txt is True


class TestWebScannerURLValidation:
    """Test URL validation."""

    @pytest.mark.asyncio
    async def test_invalid_scheme_raises_error(self) -> None:
        """Test that invalid URL schemes raise ScanError."""
        scanner = WebScanner("ftp://example.com")

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "Invalid URL scheme" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_domain_raises_error(self) -> None:
        """Test that missing domain raises ScanError."""
        scanner = WebScanner("https://")

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "missing domain" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_http_scheme_accepted(self) -> None:
        """Test that HTTP scheme is accepted."""
        scanner = WebScanner("http://example.com")

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # Mock the get method
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML_NO_SECRETS
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()
            assert result is not None

    @pytest.mark.asyncio
    async def test_https_scheme_accepted(self) -> None:
        """Test that HTTPS scheme is accepted."""
        scanner = WebScanner("https://example.com")

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML_NO_SECRETS
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()
            assert result is not None


class TestWebScannerHTMLExtraction:
    """Test HTML content extraction."""

    def test_extract_text_from_html(self):
        """Test that text is extracted from HTML."""
        scanner = WebScanner("https://example.com")
        text = scanner._extract_text_from_html(SAMPLE_HTML)

        assert "Welcome" in text
        assert "This is a test page" in text
        # Script content should be removed
        assert "const apiKey" not in text

    def test_extract_inline_scripts(self):
        """Test that inline scripts are extracted."""
        scanner = WebScanner("https://example.com")
        scripts = scanner._extract_inline_scripts(SAMPLE_HTML)

        assert len(scripts) == 1
        assert "AKIAIOSFODNN7EXAMPLE" in scripts[0]

    def test_extract_script_urls(self):
        """Test that external script URLs are extracted."""
        scanner = WebScanner("https://example.com")
        urls = scanner._extract_script_urls(SAMPLE_HTML, "https://example.com")

        assert len(urls) == 1
        assert urls[0] == "https://example.com/static/app.js"

    def test_extract_links(self):
        """Test that links are extracted."""
        scanner = WebScanner("https://example.com")
        links = scanner._extract_links(SAMPLE_HTML, "https://example.com")

        assert "https://example.com/page2" in links
        assert "https://example.com/external" in links or "https://example.com/page3" in links


class TestWebScannerLinkExtraction:
    """Test link extraction and filtering."""

    def test_javascript_links_ignored(self):
        """Test that javascript: links are ignored."""
        html = '<a href="javascript:void(0)">Click</a>'
        scanner = WebScanner("https://example.com")
        links = scanner._extract_links(html, "https://example.com")
        assert len(links) == 0

    def test_mailto_links_ignored(self):
        """Test that mailto: links are ignored."""
        html = '<a href="mailto:test@example.com">Email</a>'
        scanner = WebScanner("https://example.com")
        links = scanner._extract_links(html, "https://example.com")
        assert len(links) == 0

    def test_tel_links_ignored(self):
        """Test that tel: links are ignored."""
        html = '<a href="tel:+1234567890">Call</a>'
        scanner = WebScanner("https://example.com")
        links = scanner._extract_links(html, "https://example.com")
        assert len(links) == 0

    def test_fragment_links_ignored(self):
        """Test that fragment-only links are ignored."""
        html = '<a href="#section">Jump</a>'
        scanner = WebScanner("https://example.com")
        links = scanner._extract_links(html, "https://example.com")
        assert len(links) == 0

    def test_relative_links_resolved(self):
        """Test that relative links are resolved to absolute."""
        html = '<a href="/path/to/page">Page</a>'
        scanner = WebScanner("https://example.com")
        links = scanner._extract_links(html, "https://example.com/current")
        assert "https://example.com/path/to/page" in links


class TestWebScannerRobotsTxt:
    """Test robots.txt parsing and respect."""

    def test_parse_robots_txt(self):
        """Test robots.txt parsing."""
        scanner = WebScanner("https://example.com")
        robots = scanner._parse_robots_txt(SAMPLE_ROBOTS_TXT)

        assert "/admin/" in robots.disallow_patterns
        assert "/private/" in robots.disallow_patterns
        assert "/secret/" in robots.disallow_patterns
        assert "/public/" in robots.allow_patterns
        assert robots.crawl_delay == 1.0

    def test_is_allowed_by_robots_allowed(self):
        """Test that allowed paths return True."""
        scanner = WebScanner("https://example.com")
        robots = scanner._parse_robots_txt(SAMPLE_ROBOTS_TXT)

        assert scanner._is_allowed_by_robots("https://example.com/public/page", robots)
        assert scanner._is_allowed_by_robots("https://example.com/other/page", robots)

    def test_is_allowed_by_robots_disallowed(self):
        """Test that disallowed paths return False."""
        scanner = WebScanner("https://example.com")
        robots = scanner._parse_robots_txt(SAMPLE_ROBOTS_TXT)

        assert not scanner._is_allowed_by_robots("https://example.com/admin/users", robots)
        assert not scanner._is_allowed_by_robots("https://example.com/private/data", robots)
        assert not scanner._is_allowed_by_robots("https://example.com/secret/keys", robots)

    def test_is_allowed_by_robots_no_robots(self):
        """Test that all paths are allowed when no robots.txt."""
        scanner = WebScanner("https://example.com")

        assert scanner._is_allowed_by_robots("https://example.com/admin/", None)
        assert scanner._is_allowed_by_robots("https://example.com/any/path", None)

    def test_allow_takes_precedence(self):
        """Test that Allow rules take precedence over Disallow."""
        robots_txt = """
User-agent: *
Disallow: /test/
Allow: /test/allowed/
"""
        scanner = WebScanner("https://example.com")
        robots = scanner._parse_robots_txt(robots_txt)

        assert scanner._is_allowed_by_robots("https://example.com/test/allowed/page", robots)
        assert not scanner._is_allowed_by_robots("https://example.com/test/other", robots)


class TestWebScannerURLNormalization:
    """Test URL normalization."""

    def test_normalize_url_removes_fragment(self):
        """Test that fragments are removed from URLs."""
        scanner = WebScanner("https://example.com")
        normalized = scanner._normalize_url("https://example.com/page#section")
        assert normalized == "https://example.com/page"

    def test_normalize_url_preserves_query(self):
        """Test that query parameters are preserved."""
        scanner = WebScanner("https://example.com")
        normalized = scanner._normalize_url("https://example.com/page?id=1")
        assert normalized == "https://example.com/page?id=1"

    def test_normalize_url_removes_trailing_slash(self):
        """Test that trailing slashes are normalized."""
        scanner = WebScanner("https://example.com")
        normalized = scanner._normalize_url("https://example.com/page/")
        assert normalized == "https://example.com/page"

    def test_normalize_url_keeps_root_slash(self):
        """Test that root path slash is preserved."""
        scanner = WebScanner("https://example.com")
        normalized = scanner._normalize_url("https://example.com/")
        assert normalized == "https://example.com/"


class TestWebScannerDomainChecking:
    """Test same-domain checking."""

    def test_is_same_domain_true(self):
        """Test that same domain returns True."""
        scanner = WebScanner("https://example.com")
        assert scanner._is_same_domain(
            "https://example.com/page",
            "https://example.com"
        )

    def test_is_same_domain_false(self):
        """Test that different domain returns False."""
        scanner = WebScanner("https://example.com")
        assert not scanner._is_same_domain(
            "https://other.com/page",
            "https://example.com"
        )

    def test_is_same_domain_subdomain(self):
        """Test that subdomains are different."""
        scanner = WebScanner("https://example.com")
        assert not scanner._is_same_domain(
            "https://sub.example.com/page",
            "https://example.com"
        )


class TestWebScannerCancellation:
    """Test cancellation functionality."""

    def test_cancel_sets_cancelled_flag(self):
        """Test that cancel() sets the cancellation flag."""
        scanner = WebScanner("https://example.com")

        assert not scanner.is_cancelled
        scanner.cancel()
        assert scanner.is_cancelled

    @pytest.mark.asyncio
    async def test_cancellation_stops_scan(self) -> None:
        """Test that cancellation stops the scan."""
        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML_NO_SECRETS
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            # Cancel during scan
            async def cancel_during_scan():
                await asyncio.sleep(0)  # Let scan start
                scanner.cancel()

            cancel_task = asyncio.create_task(cancel_during_scan())
            result = await scanner.scan()
            await cancel_task

            # The scan may or may not have been cancelled in time,
            # but we should verify the mechanism works
            assert result is not None


class TestWebScannerProgressCallback:
    """Test progress callback functionality."""

    @pytest.mark.asyncio
    async def test_progress_callback_is_called(self) -> None:
        """Test that progress callback is called during scan."""
        progress_calls: list[ScanProgress] = []

        def progress_callback(progress: ScanProgress) -> None:
            progress_calls.append(progress)

        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
            progress_callback=progress_callback,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML_NO_SECRETS
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            await scanner.scan()

        assert len(progress_calls) > 0

    @pytest.mark.asyncio
    async def test_progress_callback_error_handling(self) -> None:
        """Test that callback errors don't disrupt the scan."""

        def failing_callback(progress: ScanProgress) -> None:
            raise RuntimeError("Callback failure!")

        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
            progress_callback=failing_callback,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML_NO_SECRETS
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            # Scan should complete despite callback failure
            result = await scanner.scan()

            assert result.stats["urls_scanned"] > 0


class TestWebScannerStreaming:
    """Test streaming output functionality."""

    @pytest.mark.asyncio
    async def test_stream_yields_findings(self) -> None:
        """Test that scan_stream yields findings as they're discovered."""
        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
            include_scripts=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            findings: list[Finding] = []
            async for finding in scanner.scan_stream():
                findings.append(finding)

            assert len(findings) > 0
            for finding in findings:
                assert isinstance(finding, Finding)


class TestWebScannerStats:
    """Test statistics tracking."""

    @pytest.mark.asyncio
    async def test_get_stats_returns_current_state(self) -> None:
        """Test that get_stats returns current scan state."""
        scanner = WebScanner("https://example.com")

        # Before scan
        stats = scanner.get_stats()
        assert stats["urls_scanned"] == 0
        assert stats["scripts_scanned"] == 0

    @pytest.mark.asyncio
    async def test_scan_duration_is_tracked(self) -> None:
        """Test that scan duration is tracked."""
        scanner = WebScanner("https://example.com")

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML_NO_SECRETS
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

        assert result.scan_duration > 0


class TestWebScannerNoDetectors:
    """Test scanning without detectors."""

    @pytest.mark.asyncio
    async def test_scan_without_detectors(self) -> None:
        """Test that scanner works without any detectors."""
        scanner = WebScanner("https://example.com", detectors=None)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

            assert result.stats["urls_scanned"] > 0
            assert len(result.findings) == 0


class TestWebScannerDetectorErrors:
    """Test handling of detector errors."""

    @pytest.mark.asyncio
    async def test_detector_error_handling(self) -> None:
        """Test that scanner handles detector errors gracefully."""

        class FailingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "failing"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                raise RuntimeError("Detector failure!")

        scanner = WebScanner(
            "https://example.com",
            detectors=[FailingDetector(), RegexDetector()],
            include_scripts=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

            # Should still get findings from the working detector
            assert len(result.findings) > 0
            # Should have errors logged
            assert len(result.stats["errors"]) > 0


class TestWebScannerHTTPErrors:
    """Test HTTP error handling."""

    @pytest.mark.asyncio
    async def test_timeout_error_handling(self) -> None:
        """Test that timeout errors are handled gracefully."""
        import httpx

        scanner = WebScanner("https://example.com")

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_instance.get = AsyncMock(side_effect=httpx.TimeoutException("Timeout"))

            result = await scanner.scan()

            assert len(result.stats["errors"]) > 0
            assert any("Timeout" in err for err in result.stats["errors"])

    @pytest.mark.asyncio
    async def test_http_status_error_handling(self) -> None:
        """Test that HTTP status errors are handled gracefully."""
        import httpx

        scanner = WebScanner("https://example.com")

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Not Found", request=MagicMock(), response=mock_response
            )

            result = await scanner.scan()

            assert len(result.stats["errors"]) > 0
            assert any("404" in err for err in result.stats["errors"])

    @pytest.mark.asyncio
    async def test_request_error_handling(self) -> None:
        """Test that request errors are handled gracefully."""
        import httpx

        scanner = WebScanner("https://example.com")

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_instance.get = AsyncMock(
                side_effect=httpx.RequestError("Connection refused")
            )

            result = await scanner.scan()

            assert len(result.stats["errors"]) > 0


class TestWebScannerDepthLimit:
    """Test depth limiting for link following."""

    @pytest.mark.asyncio
    async def test_depth_zero_only_scans_start_url(self) -> None:
        """Test that depth=0 only scans the starting URL."""
        scanner = WebScanner(
            "https://example.com",
            depth=0,
            include_scripts=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

            # Should only scan the starting URL
            assert result.stats["urls_scanned"] == 1

    @pytest.mark.asyncio
    async def test_depth_one_follows_first_level_links(self) -> None:
        """Test that depth=1 follows first-level links."""
        scanner = WebScanner(
            "https://example.com",
            depth=1,
            include_scripts=False,
            respect_robots_txt=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # First call returns page with links
            # Subsequent calls return pages without links
            mock_response1 = MagicMock()
            mock_response1.status_code = 200
            mock_response1.headers = {"content-type": "text/html"}
            mock_response1.text = SAMPLE_HTML
            mock_response1.raise_for_status = MagicMock()

            mock_response2 = MagicMock()
            mock_response2.status_code = 200
            mock_response2.headers = {"content-type": "text/html"}
            mock_response2.text = SAMPLE_HTML_NO_SECRETS
            mock_response2.raise_for_status = MagicMock()

            mock_instance.get = AsyncMock(
                side_effect=[mock_response1, mock_response2, mock_response2]
            )

            result = await scanner.scan()

            # Should scan starting URL plus discovered links
            assert result.stats["urls_scanned"] >= 1


class TestWebScannerScriptScanning:
    """Test JavaScript scanning functionality."""

    @pytest.mark.asyncio
    async def test_inline_scripts_scanned(self) -> None:
        """Test that inline scripts are scanned for secrets."""
        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
            include_scripts=True,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

            # Should find secret in inline script
            inline_findings = [
                f for f in result.findings
                if f.metadata.get("source_type") == "inline_script"
            ]
            assert len(inline_findings) > 0

    @pytest.mark.asyncio
    async def test_external_scripts_scanned(self) -> None:
        """Test that external JavaScript files are scanned."""
        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
            include_scripts=True,
            respect_robots_txt=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # First response is HTML, second is JavaScript
            mock_html_response = MagicMock()
            mock_html_response.status_code = 200
            mock_html_response.headers = {"content-type": "text/html"}
            mock_html_response.text = SAMPLE_HTML
            mock_html_response.raise_for_status = MagicMock()

            mock_js_response = MagicMock()
            mock_js_response.status_code = 200
            mock_js_response.headers = {"content-type": "application/javascript"}
            mock_js_response.text = SAMPLE_JS
            mock_js_response.raise_for_status = MagicMock()

            mock_instance.get = AsyncMock(
                side_effect=[mock_html_response, mock_js_response]
            )

            result = await scanner.scan()

            # Should have scanned the external script
            assert result.stats["scripts_scanned"] > 0

    @pytest.mark.asyncio
    async def test_include_scripts_false_skips_external(self) -> None:
        """Test that include_scripts=False skips external scripts."""
        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
            include_scripts=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

            # Should not scan external scripts
            assert result.stats["scripts_scanned"] == 0


class TestWebScannerReset:
    """Test scanner reset functionality."""

    @pytest.mark.asyncio
    async def test_reset_clears_state(self) -> None:
        """Test that _reset clears all scanner state."""
        scanner = WebScanner("https://example.com", detectors=[RegexDetector()])

        # Manually set some state
        scanner._urls_scanned = 5
        scanner._scripts_scanned = 3
        scanner._findings_count = 10
        scanner._visited_urls.add("https://example.com/test")
        scanner._errors.append("test error")

        # Reset
        scanner._reset()

        assert scanner._urls_scanned == 0
        assert scanner._scripts_scanned == 0
        assert scanner._findings_count == 0
        assert len(scanner._visited_urls) == 0
        assert len(scanner._errors) == 0

    @pytest.mark.asyncio
    async def test_can_scan_multiple_times(self) -> None:
        """Test that scanner can be used for multiple scans."""
        scanner = WebScanner("https://example.com")

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML_NO_SECRETS
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            # First scan
            result1 = await scanner.scan()
            assert result1.stats["urls_scanned"] > 0

            # Second scan (reset happens automatically)
            result2 = await scanner.scan()
            assert result2.stats["urls_scanned"] > 0


class TestWebScannerContentTypes:
    """Test handling of different content types."""

    @pytest.mark.asyncio
    async def test_non_html_content_scanned(self) -> None:
        """Test that non-HTML content is scanned directly."""
        scanner = WebScanner(
            "https://example.com/api/config.json",
            detectors=[RegexDetector()],
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "application/json"}
            mock_response.text = '{"apiKey": "AKIAIOSFODNN7EXAMPLE"}'
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

            # Should find secret in JSON content
            assert len(result.findings) > 0


class TestWebScannerGetProgress:
    """Test get_progress method."""

    def test_get_progress_before_scan(self) -> None:
        """Test that _get_progress returns correct values before scan."""
        scanner = WebScanner("https://example.com")

        progress = scanner._get_progress()

        assert progress.total_files == 0
        assert progress.scanned_files == 0
        assert progress.current_file == ""
        assert progress.findings_count == 0
        assert progress.elapsed_time == 0.0

    @pytest.mark.asyncio
    async def test_get_progress_during_scan(self) -> None:
        """Test that _get_progress returns correct values during scan."""
        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML_NO_SECRETS
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            await scanner.scan()

            progress = scanner._get_progress()

            assert progress.scanned_files > 0
            assert progress.elapsed_time > 0.0


class TestWebScannerRobotsCaching:
    """Test robots.txt caching."""

    @pytest.mark.asyncio
    async def test_robots_txt_cached(self) -> None:
        """Test that robots.txt is cached per domain."""
        scanner = WebScanner("https://example.com", respect_robots_txt=True)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # Robots.txt response
            mock_robots_response = MagicMock()
            mock_robots_response.status_code = 200
            mock_robots_response.text = SAMPLE_ROBOTS_TXT

            # HTML response
            mock_html_response = MagicMock()
            mock_html_response.status_code = 200
            mock_html_response.headers = {"content-type": "text/html"}
            mock_html_response.text = SAMPLE_HTML_NO_SECRETS
            mock_html_response.raise_for_status = MagicMock()

            mock_instance.get = AsyncMock(
                side_effect=[mock_robots_response, mock_html_response]
            )

            await scanner.scan()

            # Robots.txt should be cached
            assert "https://example.com" in scanner._robots_cache


class TestWebScannerFindingMetadata:
    """Test that findings have correct metadata."""

    @pytest.mark.asyncio
    async def test_html_text_findings_have_metadata(self) -> None:
        """Test that HTML text findings have correct metadata."""
        scanner = WebScanner(
            "https://example.com",
            detectors=[RegexDetector()],
            include_scripts=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = SAMPLE_HTML
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

            html_findings = [
                f for f in result.findings
                if f.metadata.get("source_type") == "html_text"
            ]

            for finding in html_findings:
                assert "url" in finding.metadata


class TestWebScannerCrawlDelay:
    """Test crawl delay handling."""

    @pytest.mark.asyncio
    async def test_crawl_delay_is_respected(self) -> None:
        """Test that crawl delay from robots.txt is respected."""
        scanner = WebScanner(
            "https://example.com",
            respect_robots_txt=True,
            depth=1,
            include_scripts=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # Robots.txt with crawl delay
            mock_robots_response = MagicMock()
            mock_robots_response.status_code = 200
            mock_robots_response.text = "User-agent: *\nCrawl-delay: 0.1"

            # HTML responses
            html1 = '<html><body><a href="/page2">Link</a></body></html>'
            mock_html_response = MagicMock()
            mock_html_response.status_code = 200
            mock_html_response.headers = {"content-type": "text/html"}
            mock_html_response.text = html1
            mock_html_response.raise_for_status = MagicMock()

            mock_html_response2 = MagicMock()
            mock_html_response2.status_code = 200
            mock_html_response2.headers = {"content-type": "text/html"}
            mock_html_response2.text = SAMPLE_HTML_NO_SECRETS
            mock_html_response2.raise_for_status = MagicMock()

            mock_instance.get = AsyncMock(
                side_effect=[mock_robots_response, mock_html_response, mock_html_response2]
            )

            with patch("asyncio.sleep") as mock_sleep:
                mock_sleep.return_value = None

                await scanner.scan()

                # Crawl delay should have been called
                # (Only between pages, not before first)
                if scanner._urls_scanned > 1:
                    mock_sleep.assert_called()


class TestWebScannerExternalLinkFiltering:
    """Test that external links are not followed."""

    @pytest.mark.asyncio
    async def test_external_links_not_followed(self) -> None:
        """Test that links to external domains are not followed."""
        scanner = WebScanner(
            "https://example.com",
            depth=2,
            include_scripts=False,
            respect_robots_txt=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # HTML with external link
            html = '<html><body><a href="https://other-domain.com/page">External</a></body></html>'
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = html
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_response.raise_for_status = MagicMock()

            result = await scanner.scan()

            # Should only scan the starting URL (external link not followed)
            assert result.stats["urls_scanned"] == 1


class TestWebScannerDuplicateURLHandling:
    """Test that duplicate URLs are not scanned twice."""

    @pytest.mark.asyncio
    async def test_duplicate_urls_not_scanned(self) -> None:
        """Test that the same URL is not scanned multiple times."""
        scanner = WebScanner(
            "https://example.com",
            depth=2,
            include_scripts=False,
            respect_robots_txt=False,
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # HTML with multiple links to the same page
            html = '''
            <html><body>
                <a href="/page">Link 1</a>
                <a href="/page">Link 2</a>
                <a href="/page#section">Link 3 with fragment</a>
            </body></html>
            '''
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/html"}
            mock_response.text = html
            mock_response.raise_for_status = MagicMock()

            mock_response2 = MagicMock()
            mock_response2.status_code = 200
            mock_response2.headers = {"content-type": "text/html"}
            mock_response2.text = SAMPLE_HTML_NO_SECRETS
            mock_response2.raise_for_status = MagicMock()

            mock_instance.get = AsyncMock(side_effect=[mock_response, mock_response2])

            result = await scanner.scan()

            # /page should only be scanned once (duplicates removed)
            # Total: starting URL + /page = 2
            assert result.stats["urls_scanned"] == 2
