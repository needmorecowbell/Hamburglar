"""High-level API functions for Hamburglar.

This module provides simple, high-level functions for scanning directories,
git repositories, and URLs for secrets. These functions abstract away the
complexity of creating scanners and detectors, making it easy to integrate
Hamburglar as a library.

Example usage::

    import asyncio
    from hamburglar.api import scan_directory, scan_git, scan_url

    # Scan a directory
    result = asyncio.run(scan_directory("/path/to/code"))
    for finding in result.findings:
        print(f"{finding.file_path}: {finding.detector_name}")

    # Scan a git repository
    result = asyncio.run(scan_git("https://github.com/user/repo"))

    # Scan a URL
    result = asyncio.run(scan_url("https://example.com"))
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hamburglar.core.models import ScanConfig, ScanResult
from hamburglar.detectors import BaseDetector
from hamburglar.detectors.patterns import Confidence, PatternCategory
from hamburglar.detectors.regex_detector import RegexDetector
from hamburglar.scanners.directory import DirectoryScanner
from hamburglar.scanners.git import GitScanner
from hamburglar.scanners.web import WebScanner


def _create_detectors(
    use_expanded_patterns: bool = False,
    enabled_categories: list[PatternCategory] | None = None,
    disabled_categories: list[PatternCategory] | None = None,
    min_confidence: Confidence | None = None,
    custom_patterns: dict[str, dict[str, Any]] | None = None,
) -> list[BaseDetector]:
    """Create default detectors for scanning.

    Args:
        use_expanded_patterns: If True, use all pattern categories for
            comprehensive secret detection. Defaults to False for faster scans.
        enabled_categories: If provided, only use patterns from these categories.
        disabled_categories: If provided, exclude patterns from these categories.
        min_confidence: If provided, only use patterns with this confidence or higher.
        custom_patterns: Optional custom patterns to add to the detector.

    Returns:
        List of detector instances configured for scanning.
    """
    detector = RegexDetector(
        use_expanded_patterns=use_expanded_patterns,
        enabled_categories=enabled_categories,
        disabled_categories=disabled_categories,
        min_confidence=min_confidence,
        patterns=custom_patterns,
    )
    return [detector]


async def scan_directory(
    path: str | Path,
    *,
    recursive: bool = True,
    use_expanded_patterns: bool = False,
    enabled_categories: list[PatternCategory] | None = None,
    disabled_categories: list[PatternCategory] | None = None,
    min_confidence: Confidence | None = None,
    custom_patterns: dict[str, dict[str, Any]] | None = None,
    blacklist: list[str] | None = None,
    whitelist: list[str] | None = None,
    detectors: list[BaseDetector] | None = None,
    concurrency_limit: int = 50,
) -> ScanResult:
    """Scan a directory or file for secrets.

    This is the simplest way to scan local files for sensitive information.
    It creates a DirectoryScanner with sensible defaults and runs the scan.

    Args:
        path: Path to the directory or file to scan.
        recursive: Whether to scan subdirectories. Defaults to True.
        use_expanded_patterns: If True, use all pattern categories for
            comprehensive detection. Defaults to False for faster scans.
        enabled_categories: If provided, only use patterns from these categories.
        disabled_categories: If provided, exclude patterns from these categories.
        min_confidence: If provided, only use patterns with this confidence or higher.
        custom_patterns: Optional dictionary of custom patterns to add.
        blacklist: List of glob patterns to exclude from scanning.
            Defaults to common non-code directories like .git, node_modules.
        whitelist: If provided, only scan files matching these patterns.
        detectors: Optional list of custom detector instances. If provided,
            pattern configuration options are ignored.
        concurrency_limit: Maximum number of concurrent file operations.
            Defaults to 50.

    Returns:
        ScanResult containing all findings and scan statistics.

    Raises:
        ScanError: If the path does not exist or cannot be accessed.

    Example::

        import asyncio
        from hamburglar.api import scan_directory

        # Basic scan
        result = asyncio.run(scan_directory("/path/to/code"))

        # Comprehensive scan with all patterns
        result = asyncio.run(scan_directory(
            "/path/to/code",
            use_expanded_patterns=True
        ))

        # Only scan for API keys and credentials
        from hamburglar.detectors.patterns import PatternCategory
        result = asyncio.run(scan_directory(
            "/path/to/code",
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS, PatternCategory.CREDENTIALS]
        ))
    """
    target_path = Path(path) if isinstance(path, str) else path

    # Build config
    config_kwargs: dict[str, Any] = {
        "target_path": target_path,
        "recursive": recursive,
    }
    if blacklist is not None:
        config_kwargs["blacklist"] = blacklist
    if whitelist is not None:
        config_kwargs["whitelist"] = whitelist

    config = ScanConfig(**config_kwargs)

    # Create detectors if not provided
    if detectors is None:
        detectors = _create_detectors(
            use_expanded_patterns=use_expanded_patterns,
            enabled_categories=enabled_categories,
            disabled_categories=disabled_categories,
            min_confidence=min_confidence,
            custom_patterns=custom_patterns,
        )

    # Create and run scanner
    scanner = DirectoryScanner(
        config=config,
        detectors=detectors,
        concurrency_limit=concurrency_limit,
    )

    return await scanner.scan()


async def scan_git(
    url_or_path: str,
    *,
    include_history: bool = True,
    depth: int | None = None,
    branch: str | None = None,
    clone_dir: str | Path | None = None,
    use_expanded_patterns: bool = False,
    enabled_categories: list[PatternCategory] | None = None,
    disabled_categories: list[PatternCategory] | None = None,
    min_confidence: Confidence | None = None,
    custom_patterns: dict[str, dict[str, Any]] | None = None,
    detectors: list[BaseDetector] | None = None,
) -> ScanResult:
    """Scan a git repository for secrets.

    This function scans git repositories for secrets, including both current
    files and commit history (diffs). It can scan remote repositories (HTTP/SSH)
    or local git directories.

    Args:
        url_or_path: Git repository URL (HTTP/SSH) or path to local git directory.
        include_history: Whether to scan commit history for removed secrets.
            Defaults to True.
        depth: Number of commits to examine. None for all history.
        branch: Specific branch to scan. None for current/default branch.
        clone_dir: Optional directory to clone remote repositories into.
            If not provided, a temporary directory is used and cleaned up.
        use_expanded_patterns: If True, use all pattern categories for
            comprehensive detection. Defaults to False.
        enabled_categories: If provided, only use patterns from these categories.
        disabled_categories: If provided, exclude patterns from these categories.
        min_confidence: If provided, only use patterns with this confidence or higher.
        custom_patterns: Optional dictionary of custom patterns to add.
        detectors: Optional list of custom detector instances.

    Returns:
        ScanResult containing all findings and scan statistics.

    Raises:
        ScanError: If the repository cannot be accessed or cloned.

    Example::

        import asyncio
        from hamburglar.api import scan_git

        # Scan a remote repository
        result = asyncio.run(scan_git("https://github.com/user/repo"))

        # Scan only the last 100 commits
        result = asyncio.run(scan_git(
            "https://github.com/user/repo",
            depth=100
        ))

        # Scan a local git directory without history
        result = asyncio.run(scan_git(
            "/path/to/local/repo",
            include_history=False
        ))
    """
    # Create detectors if not provided
    if detectors is None:
        detectors = _create_detectors(
            use_expanded_patterns=use_expanded_patterns,
            enabled_categories=enabled_categories,
            disabled_categories=disabled_categories,
            min_confidence=min_confidence,
            custom_patterns=custom_patterns,
        )

    # Handle clone_dir path conversion
    clone_path = None
    if clone_dir is not None:
        clone_path = Path(clone_dir) if isinstance(clone_dir, str) else clone_dir

    # Create and run scanner
    scanner = GitScanner(
        target=url_or_path,
        detectors=detectors,
        include_history=include_history,
        depth=depth,
        branch=branch,
        clone_dir=clone_path,
    )

    return await scanner.scan()


async def scan_url(
    url: str,
    *,
    depth: int = 1,
    include_scripts: bool = True,
    respect_robots_txt: bool = True,
    user_agent: str | None = None,
    timeout: float = 30.0,
    use_expanded_patterns: bool = False,
    enabled_categories: list[PatternCategory] | None = None,
    disabled_categories: list[PatternCategory] | None = None,
    min_confidence: Confidence | None = None,
    custom_patterns: dict[str, dict[str, Any]] | None = None,
    detectors: list[BaseDetector] | None = None,
) -> ScanResult:
    """Scan a URL for secrets.

    This function scans web pages for secrets. It extracts text from HTML,
    scans inline and external JavaScript files, and optionally follows links
    to a configurable depth.

    Args:
        url: The starting URL to scan.
        depth: Maximum depth for following links. 0 means only scan the
            starting URL. Defaults to 1.
        include_scripts: Whether to extract and scan JavaScript files.
            Defaults to True.
        respect_robots_txt: Whether to respect robots.txt rules.
            Defaults to True.
        user_agent: Optional custom user agent string.
        timeout: Timeout for HTTP requests in seconds. Defaults to 30.0.
        use_expanded_patterns: If True, use all pattern categories for
            comprehensive detection. Defaults to False.
        enabled_categories: If provided, only use patterns from these categories.
        disabled_categories: If provided, exclude patterns from these categories.
        min_confidence: If provided, only use patterns with this confidence or higher.
        custom_patterns: Optional dictionary of custom patterns to add.
        detectors: Optional list of custom detector instances.

    Returns:
        ScanResult containing all findings and scan statistics.

    Raises:
        ScanError: If the URL is invalid or inaccessible.
        ImportError: If httpx or beautifulsoup4 are not installed.

    Example::

        import asyncio
        from hamburglar.api import scan_url

        # Scan a single page
        result = asyncio.run(scan_url("https://example.com"))

        # Scan with link following (up to depth 2)
        result = asyncio.run(scan_url(
            "https://example.com",
            depth=2
        ))

        # Scan without JavaScript extraction
        result = asyncio.run(scan_url(
            "https://example.com",
            include_scripts=False
        ))
    """
    # Create detectors if not provided
    if detectors is None:
        detectors = _create_detectors(
            use_expanded_patterns=use_expanded_patterns,
            enabled_categories=enabled_categories,
            disabled_categories=disabled_categories,
            min_confidence=min_confidence,
            custom_patterns=custom_patterns,
        )

    # Build scanner kwargs
    scanner_kwargs: dict[str, Any] = {
        "url": url,
        "detectors": detectors,
        "depth": depth,
        "include_scripts": include_scripts,
        "respect_robots_txt": respect_robots_txt,
        "timeout": timeout,
    }
    if user_agent is not None:
        scanner_kwargs["user_agent"] = user_agent

    # Create and run scanner
    scanner = WebScanner(**scanner_kwargs)

    return await scanner.scan()


# Convenience aliases for common operations
scan = scan_directory
scan_dir = scan_directory
scan_repo = scan_git
scan_web = scan_url


__all__ = [
    # Main API functions
    "scan_directory",
    "scan_git",
    "scan_url",
    # Convenience aliases
    "scan",
    "scan_dir",
    "scan_repo",
    "scan_web",
]
