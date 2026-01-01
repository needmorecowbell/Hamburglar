"""Tests for the high-level API functions.

This module tests the simplified API functions:
- scan_directory: Scan a directory or file for secrets
- scan_git: Scan a git repository for secrets
- scan_url: Scan a URL for secrets

These functions provide a simpler interface than using the scanner classes directly.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hamburglar.api import (
    scan_directory,
    scan_git,
    scan_url,
    scan,
    scan_dir,
    scan_repo,
    scan_web,
    _create_detectors,
)
from hamburglar.core.exceptions import ScanError
from hamburglar.core.models import ScanResult, Severity
from hamburglar.detectors.regex_detector import RegexDetector
from hamburglar.detectors.patterns import PatternCategory, Confidence


class TestCreateDetectors:
    """Test the _create_detectors helper function."""

    def test_creates_regex_detector_by_default(self):
        """Test that _create_detectors creates a RegexDetector by default."""
        detectors = _create_detectors()
        assert len(detectors) == 1
        assert isinstance(detectors[0], RegexDetector)

    def test_use_expanded_patterns(self):
        """Test that use_expanded_patterns enables all pattern categories."""
        detectors = _create_detectors(use_expanded_patterns=True)
        assert len(detectors) == 1
        detector = detectors[0]
        assert isinstance(detector, RegexDetector)
        # Expanded patterns should have more patterns than default
        assert detector.get_pattern_count() > 20

    def test_enabled_categories(self):
        """Test that enabled_categories filters patterns."""
        detectors = _create_detectors(
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS]
        )
        detector = detectors[0]
        assert detector.get_enabled_categories() == [PatternCategory.API_KEYS]

    def test_disabled_categories(self):
        """Test that disabled_categories excludes patterns."""
        detectors = _create_detectors(
            use_expanded_patterns=True,
            disabled_categories=[PatternCategory.NETWORK]
        )
        detector = detectors[0]
        assert detector.get_disabled_categories() == [PatternCategory.NETWORK]

    def test_min_confidence(self):
        """Test that min_confidence filters low-confidence patterns."""
        detectors = _create_detectors(
            use_expanded_patterns=True,
            min_confidence=Confidence.HIGH
        )
        detector = detectors[0]
        assert detector.get_min_confidence() == Confidence.HIGH

    def test_custom_patterns(self):
        """Test that custom_patterns adds custom patterns."""
        custom = {
            "Custom Test Pattern": {
                "pattern": r"CUSTOM-[0-9]{8}",
                "severity": Severity.HIGH,
                "description": "Custom test pattern",
            }
        }
        detectors = _create_detectors(custom_patterns=custom)
        detector = detectors[0]
        patterns = detector.get_patterns()
        assert "Custom Test Pattern" in patterns


class TestScanDirectory:
    """Test the scan_directory API function."""

    @pytest.mark.asyncio
    async def test_scan_directory_with_secrets(self, temp_directory: Path):
        """Test scanning a directory with known secrets."""
        result = await scan_directory(temp_directory)

        assert isinstance(result, ScanResult)
        assert result.target_path == str(temp_directory)
        assert len(result.findings) > 0
        assert result.stats["files_scanned"] > 0

    @pytest.mark.asyncio
    async def test_scan_directory_with_string_path(self, temp_directory: Path):
        """Test that scan_directory accepts string paths."""
        result = await scan_directory(str(temp_directory))

        assert isinstance(result, ScanResult)
        assert result.target_path == str(temp_directory)

    @pytest.mark.asyncio
    async def test_scan_directory_non_recursive(self, temp_directory: Path):
        """Test non-recursive directory scanning."""
        result_recursive = await scan_directory(temp_directory, recursive=True)
        result_non_recursive = await scan_directory(temp_directory, recursive=False)

        # Non-recursive should scan fewer files
        assert result_non_recursive.stats["files_scanned"] <= result_recursive.stats["files_scanned"]

    @pytest.mark.asyncio
    async def test_scan_directory_with_expanded_patterns(self, temp_directory: Path):
        """Test scanning with expanded patterns."""
        result = await scan_directory(
            temp_directory,
            use_expanded_patterns=True
        )

        assert isinstance(result, ScanResult)
        # Should find at least as many findings with expanded patterns
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scan_directory_with_blacklist(self, temp_directory: Path):
        """Test scanning with blacklist patterns."""
        result = await scan_directory(
            temp_directory,
            blacklist=["subdir", "*.txt"]
        )

        # Should not scan files matching blacklist
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_scan_directory_with_whitelist(self, temp_directory: Path):
        """Test scanning with whitelist patterns."""
        result = await scan_directory(
            temp_directory,
            whitelist=["*.py"]
        )

        # Should only scan .py files
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_scan_directory_with_custom_detectors(self, temp_directory: Path):
        """Test scanning with custom detectors."""
        custom_detector = RegexDetector(
            patterns={
                "Test Only Pattern": {
                    "pattern": r"AKIAIOSFODNN7EXAMPLE",
                    "severity": Severity.CRITICAL,
                    "description": "Test AWS key pattern",
                }
            },
            use_defaults=False,
        )

        result = await scan_directory(
            temp_directory,
            detectors=[custom_detector]
        )

        assert isinstance(result, ScanResult)
        # Should find the AWS key
        aws_findings = [f for f in result.findings if "AKIAIOSFODNN7EXAMPLE" in str(f.matches)]
        assert len(aws_findings) > 0

    @pytest.mark.asyncio
    async def test_scan_directory_with_category_filter(self, temp_directory: Path):
        """Test scanning with category filtering."""
        result = await scan_directory(
            temp_directory,
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS]
        )

        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_scan_directory_single_file(self, temp_directory: Path):
        """Test scanning a single file."""
        single_file = temp_directory / "secrets.txt"
        result = await scan_directory(single_file)

        assert isinstance(result, ScanResult)
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scan_directory_nonexistent_path(self, tmp_path: Path):
        """Test scanning a nonexistent path raises ScanError."""
        with pytest.raises(ScanError):
            await scan_directory(tmp_path / "nonexistent")


class TestScanGit:
    """Test the scan_git API function."""

    @pytest.mark.asyncio
    async def test_scan_git_local_repo(self, git_repo_with_current_secret: Path):
        """Test scanning a local git repository."""
        result = await scan_git(
            str(git_repo_with_current_secret),
            include_history=False  # Faster test without history
        )

        assert isinstance(result, ScanResult)
        assert result.target_path == str(git_repo_with_current_secret)
        # Should find secrets in current files
        assert result.stats["files_scanned"] > 0

    @pytest.mark.asyncio
    async def test_scan_git_with_history(self, git_repo_with_current_secret: Path):
        """Test scanning a git repository with history enabled."""
        result = await scan_git(
            str(git_repo_with_current_secret),
            include_history=True
        )

        assert isinstance(result, ScanResult)
        assert result.stats.get("include_history") is True

    @pytest.mark.asyncio
    async def test_scan_git_with_depth(self, git_repo_with_current_secret: Path):
        """Test scanning with commit depth limit."""
        result = await scan_git(
            str(git_repo_with_current_secret),
            depth=1
        )

        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_scan_git_with_expanded_patterns(self, git_repo_with_current_secret: Path):
        """Test scanning git repo with expanded patterns."""
        result = await scan_git(
            str(git_repo_with_current_secret),
            use_expanded_patterns=True,
            include_history=False
        )

        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_scan_git_nonexistent_repo(self, tmp_path: Path):
        """Test scanning nonexistent git repo raises ScanError."""
        with pytest.raises(ScanError):
            await scan_git(str(tmp_path / "nonexistent"))

    @pytest.mark.asyncio
    async def test_scan_git_not_a_repo(self, tmp_path: Path):
        """Test scanning a non-git directory raises ScanError."""
        (tmp_path / "file.txt").write_text("test")

        with pytest.raises(ScanError):
            await scan_git(str(tmp_path))


class TestScanUrl:
    """Test the scan_url API function."""

    @pytest.mark.asyncio
    async def test_scan_url_invalid_scheme(self):
        """Test scanning URL with invalid scheme raises ScanError."""
        with pytest.raises(ScanError):
            await scan_url("ftp://example.com")

    @pytest.mark.asyncio
    async def test_scan_url_missing_domain(self):
        """Test scanning URL without domain raises ScanError."""
        with pytest.raises(ScanError):
            await scan_url("http://")

    @pytest.mark.asyncio
    async def test_scan_url_mock_request(self):
        """Test scan_url with mocked HTTP request."""
        # Create mock response content
        mock_html = """
        <html>
        <head><title>Test</title></head>
        <body>
            <p>API key: AKIAIOSFODNN7EXAMPLE</p>
            <script>var secret = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";</script>
        </body>
        </html>
        """

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client_class.return_value.__aexit__.return_value = None

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = mock_html
            mock_response.content = mock_html.encode()
            mock_response.headers = {"content-type": "text/html"}
            mock_response.raise_for_status = MagicMock()

            mock_client.get.return_value = mock_response

            result = await scan_url(
                "https://example.com",
                depth=0,  # Don't follow links
                include_scripts=False,  # Don't fetch external scripts
            )

            assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_scan_url_with_options(self):
        """Test scan_url accepts various options."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client_class.return_value.__aexit__.return_value = None

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "<html><body>No secrets</body></html>"
            mock_response.content = mock_response.text.encode()
            mock_response.headers = {"content-type": "text/html"}
            mock_response.raise_for_status = MagicMock()

            mock_client.get.return_value = mock_response

            result = await scan_url(
                "https://example.com",
                depth=2,
                include_scripts=True,
                respect_robots_txt=False,
                user_agent="Custom Agent",
                timeout=60.0,
                use_expanded_patterns=True,
            )

            assert isinstance(result, ScanResult)


class TestAliases:
    """Test that API function aliases work correctly."""

    def test_scan_is_alias_for_scan_directory(self):
        """Test that scan is an alias for scan_directory."""
        assert scan is scan_directory

    def test_scan_dir_is_alias_for_scan_directory(self):
        """Test that scan_dir is an alias for scan_directory."""
        assert scan_dir is scan_directory

    def test_scan_repo_is_alias_for_scan_git(self):
        """Test that scan_repo is an alias for scan_git."""
        assert scan_repo is scan_git

    def test_scan_web_is_alias_for_scan_url(self):
        """Test that scan_web is an alias for scan_url."""
        assert scan_web is scan_url


class TestPackageExports:
    """Test that API functions are exported from the hamburglar package."""

    def test_scan_directory_exported(self):
        """Test that scan_directory is exported from hamburglar."""
        import hamburglar
        assert hasattr(hamburglar, "scan_directory")
        assert callable(hamburglar.scan_directory)
        # Verify it's the same function by name
        assert hamburglar.scan_directory.__name__ == "scan_directory"

    def test_scan_git_exported(self):
        """Test that scan_git is exported from hamburglar."""
        import hamburglar
        assert hasattr(hamburglar, "scan_git")
        assert callable(hamburglar.scan_git)
        assert hamburglar.scan_git.__name__ == "scan_git"

    def test_scan_url_exported(self):
        """Test that scan_url is exported from hamburglar."""
        import hamburglar
        assert hasattr(hamburglar, "scan_url")
        assert callable(hamburglar.scan_url)
        assert hamburglar.scan_url.__name__ == "scan_url"

    def test_aliases_exported(self):
        """Test that aliases are exported from hamburglar."""
        import hamburglar
        assert hasattr(hamburglar, "scan")
        assert hasattr(hamburglar, "scan_dir")
        assert hasattr(hamburglar, "scan_repo")
        assert hasattr(hamburglar, "scan_web")
        # Check the aliases point to the right functions
        assert hamburglar.scan.__name__ == "scan_directory"
        assert hamburglar.scan_dir.__name__ == "scan_directory"
        assert hamburglar.scan_repo.__name__ == "scan_git"
        assert hamburglar.scan_web.__name__ == "scan_url"


class TestOptionsPassthrough:
    """Test that options are correctly passed through to scanners."""

    @pytest.mark.asyncio
    async def test_custom_patterns_used(self, temp_directory: Path):
        """Test that custom patterns are used in the scan."""
        custom_patterns = {
            "Custom Pattern": {
                "pattern": r"CUSTOM_TEST_[0-9]+",
                "severity": Severity.HIGH,
                "description": "Custom test pattern",
            }
        }

        # Add a file with the custom pattern
        (temp_directory / "custom.txt").write_text("Found: CUSTOM_TEST_12345")

        result = await scan_directory(
            temp_directory,
            custom_patterns=custom_patterns
        )

        # Should find the custom pattern
        custom_findings = [f for f in result.findings if "Custom Pattern" in f.detector_name]
        assert len(custom_findings) > 0

    @pytest.mark.asyncio
    async def test_concurrency_limit(self, temp_directory: Path):
        """Test that concurrency_limit is passed through."""
        # Create many files to test concurrency
        for i in range(20):
            (temp_directory / f"file_{i}.txt").write_text(f"api_key = 'key_{i}'")

        result = await scan_directory(
            temp_directory,
            concurrency_limit=2  # Low limit for testing
        )

        assert isinstance(result, ScanResult)
        assert result.stats["files_scanned"] > 0


class TestLibraryUsagePattern:
    """Test the documented library usage pattern."""

    @pytest.mark.asyncio
    async def test_basic_usage_example(self, temp_directory: Path):
        """Test the basic usage example from the docstring."""
        # This is the example from the docstring
        result = await scan_directory(temp_directory)

        for finding in result.findings:
            # Verify finding has expected attributes
            assert hasattr(finding, "file_path")
            assert hasattr(finding, "detector_name")
            assert hasattr(finding, "matches")
            assert hasattr(finding, "severity")

    @pytest.mark.asyncio
    async def test_comprehensive_scan_example(self, temp_directory: Path):
        """Test comprehensive scan with all patterns."""
        result = await scan_directory(
            temp_directory,
            use_expanded_patterns=True
        )

        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_category_filtered_scan_example(self, temp_directory: Path):
        """Test category-filtered scan example."""
        result = await scan_directory(
            temp_directory,
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS, PatternCategory.CREDENTIALS]
        )

        assert isinstance(result, ScanResult)
