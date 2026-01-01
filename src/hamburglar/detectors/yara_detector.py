"""YARA-based detector for file type and malware detection.

This module provides a detector that uses YARA rules to identify
file types, malware signatures, and other patterns in file content.

The yara-python library is an optional dependency. When not installed,
the detector will be unavailable but the rest of Hamburglar will work.

Features:
- Async detection via thread pool for non-blocking operation
- Rule caching for compiled YARA rules
- Configurable scan timeout
- Streaming match results for real-time processing
- Batch detection for efficient multi-file scanning
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from hamburglar.core.exceptions import YaraCompilationError
from hamburglar.core.logging import get_logger
from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector

# YARA is an optional dependency
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore[assignment]
    YARA_AVAILABLE = False


# Default maximum file size for YARA matching (100MB)
# YARA can handle large files but performance degrades significantly
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024

# Default timeout for YARA matching in seconds
DEFAULT_YARA_TIMEOUT = 60

# Class-level rule cache to avoid recompiling identical rule sets
# Key: hash of rule files content, Value: (compiled rules, rule count, mtime)
_RULE_CACHE: dict[str, tuple[yara.Rules, int, float]] = {}


def is_yara_available() -> bool:
    """Check if yara-python is installed and available.

    Returns:
        True if yara-python is available, False otherwise.
    """
    return YARA_AVAILABLE


class YaraDetector(BaseDetector):
    """Detector that uses YARA rules to find patterns in content.

    The YaraDetector compiles YARA rules from a directory and matches
    them against file content to detect file types, malware, and other
    patterns defined in the rules.

    Example:
        detector = YaraDetector("/path/to/yara/rules")
        findings = detector.detect(file_content, "path/to/file.bin")

    Note:
        This detector requires the optional yara-python dependency.
        Use `is_yara_available()` to check if YARA is available.
    """

    def __init__(
        self,
        rules_path: str | Path,
        severity_mapping: dict[str, Severity] | None = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        timeout: int = DEFAULT_YARA_TIMEOUT,
        use_cache: bool = True,
    ) -> None:
        """Initialize the YaraDetector.

        Args:
            rules_path: Path to a directory containing .yar/.yara files,
                       or path to a single YARA rule file.
            severity_mapping: Optional dictionary mapping rule names to severity
                             levels. Rules not in this mapping use MEDIUM severity.
            max_file_size: Maximum file size in bytes to scan (default 100MB).
                          Files larger than this will be skipped with a warning.
            timeout: Timeout in seconds for YARA matching (default 60s).
            use_cache: If True, cache compiled rules to avoid recompilation
                      when the same rules are used multiple times (default True).

        Raises:
            ImportError: If yara-python is not installed.
            FileNotFoundError: If the rules_path doesn't exist.
            YaraCompilationError: If any YARA rule has syntax errors.
        """
        if not YARA_AVAILABLE:
            raise ImportError(
                "yara-python is not installed. Install it with: pip install yara-python"
            )

        self._rules_path = Path(rules_path)
        self._severity_mapping = severity_mapping or {}
        self._rules: yara.Rules | None = None
        self._rule_count = 0
        self._max_file_size = max_file_size
        self._timeout = timeout
        self._use_cache = use_cache
        self._cache_key: str | None = None
        self._logger = get_logger()

        if not self._rules_path.exists():
            raise FileNotFoundError(f"YARA rules path not found: {rules_path}")

        self._compile_rules()

    def _get_cache_key(self, rule_files: list[Path]) -> str:
        """Generate a cache key based on rule file content hashes.

        Args:
            rule_files: List of rule file paths.

        Returns:
            A hash string that uniquely identifies the rule set.
        """
        hasher = hashlib.sha256()
        for rule_file in sorted(rule_files):
            hasher.update(str(rule_file).encode())
            try:
                hasher.update(rule_file.read_bytes())
            except OSError:
                # If we can't read the file, include mtime as fallback
                hasher.update(str(rule_file.stat().st_mtime).encode())
        return hasher.hexdigest()

    def _compile_rules(self) -> None:
        """Compile YARA rules from the configured path.

        This method discovers all .yar and .yara files in the rules path
        (recursively if it's a directory) and compiles them together.
        When caching is enabled, it checks if rules are already cached
        and reuses them if unchanged.

        Raises:
            YaraCompilationError: If any YARA rule has syntax errors.
            ValueError: If no valid YARA rule files are found.
        """
        rules_path = self._rules_path

        try:
            if rules_path.is_file():
                rule_files = [rules_path]
            else:
                # Directory - find all .yar and .yara files
                rule_files = list(rules_path.glob("**/*.yar")) + list(rules_path.glob("**/*.yara"))

                if not rule_files:
                    raise ValueError(f"No YARA rule files found in {rules_path}")

            # Check cache if enabled
            if self._use_cache:
                cache_key = self._get_cache_key(rule_files)
                self._cache_key = cache_key

                if cache_key in _RULE_CACHE:
                    cached_rules, cached_count, cached_mtime = _RULE_CACHE[cache_key]
                    # Verify mtime hasn't changed (quick check)
                    current_mtime = max(f.stat().st_mtime for f in rule_files)
                    if current_mtime <= cached_mtime:
                        self._rules = cached_rules
                        self._rule_count = cached_count
                        self._logger.debug("Using cached YARA rules (cache key: %s)", cache_key[:8])
                        return

            # Compile rules
            if rules_path.is_file():
                self._rules = yara.compile(filepath=str(rules_path))
                self._rule_count = 1
            else:
                # Compile all rule files together using filepaths dict
                filepaths = {f.stem: str(f) for f in rule_files}
                self._rules = yara.compile(filepaths=filepaths)
                self._rule_count = len(rule_files)

            # Store in cache if enabled
            if self._use_cache and self._cache_key:
                current_mtime = max(f.stat().st_mtime for f in rule_files)
                _RULE_CACHE[self._cache_key] = (
                    self._rules,
                    self._rule_count,
                    current_mtime,
                )
                self._logger.debug(
                    "Cached compiled YARA rules (cache key: %s)", self._cache_key[:8]
                )

        except yara.SyntaxError as e:
            # Extract helpful information from the YARA syntax error
            error_msg = str(e)
            rule_file = str(rules_path) if rules_path.is_file() else None

            # Try to parse line/column info from the error message
            context: dict[str, str | int] = {}
            if "line " in error_msg.lower():
                # Try to extract line number
                import re

                line_match = re.search(r"line\s+(\d+)", error_msg, re.IGNORECASE)
                if line_match:
                    context["line"] = int(line_match.group(1))

            raise YaraCompilationError(
                f"Failed to compile YARA rules: {error_msg}",
                rule_file=rule_file,
                context=context if context else None,
            ) from e
        except yara.Error as e:
            # Handle other YARA errors (e.g., warnings treated as errors)
            raise YaraCompilationError(
                f"YARA compilation error: {e}",
                rule_file=str(rules_path) if rules_path.is_file() else None,
            ) from e

    @property
    def name(self) -> str:
        """Return the detector name."""
        return "yara"

    @property
    def rule_count(self) -> int:
        """Return the number of rule files loaded."""
        return self._rule_count

    @property
    def max_file_size(self) -> int:
        """Return the maximum file size in bytes."""
        return self._max_file_size

    @property
    def timeout(self) -> int:
        """Return the timeout in seconds."""
        return self._timeout

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect YARA rule matches in the given content.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each matched YARA rule.
        """
        if self._rules is None:
            return []

        # YARA expects bytes for matching
        content_bytes = content.encode("utf-8", errors="replace")

        # Check file size before processing
        content_size = len(content_bytes)
        if content_size > self._max_file_size:
            self._logger.warning(
                "Skipping file %s: size %d bytes exceeds YARA max %d bytes",
                file_path,
                content_size,
                self._max_file_size,
            )
            return []

        return self._match_and_extract(content_bytes, file_path)

    def detect_bytes(self, content: bytes, file_path: str = "") -> list[Finding]:
        """Detect YARA rule matches in raw byte content.

        This is a convenience method for scanning binary content directly
        without encoding conversion.

        Args:
            content: The raw byte content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each matched YARA rule.
        """
        if self._rules is None:
            return []

        # Check file size before processing
        content_size = len(content)
        if content_size > self._max_file_size:
            self._logger.warning(
                "Skipping file %s: size %d bytes exceeds YARA max %d bytes",
                file_path,
                content_size,
                self._max_file_size,
            )
            return []

        return self._match_and_extract(content, file_path)

    def _match_and_extract(self, content: bytes, file_path: str) -> list[Finding]:
        """Match YARA rules against content and extract findings.

        Args:
            content: The byte content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each matched YARA rule.
        """
        if self._rules is None:
            return []

        findings: list[Finding] = []
        start_time = time.perf_counter()

        try:
            # Use timeout parameter for YARA matching
            matches = self._rules.match(data=content, timeout=self._timeout)

            for match in matches:
                rule_name = match.rule
                severity = self._severity_mapping.get(rule_name, Severity.MEDIUM)

                # Extract match strings
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            matched_data = instance.matched_data.decode("utf-8", errors="replace")
                        except AttributeError:
                            matched_data = str(instance.matched_data)
                        matched_strings.append(matched_data)

                # Extract metadata from the rule
                metadata = dict(match.meta) if match.meta else {}
                metadata["rule_name"] = rule_name
                metadata["namespace"] = match.namespace
                metadata["tags"] = list(match.tags) if match.tags else []

                findings.append(
                    Finding(
                        file_path=file_path,
                        detector_name=f"yara:{rule_name}",
                        matches=matched_strings if matched_strings else [rule_name],
                        severity=severity,
                        metadata=metadata,
                    )
                )

        except yara.TimeoutError:
            elapsed = time.perf_counter() - start_time
            self._logger.warning(
                "YARA matching timed out on file %s after %.1fs (limit: %ds)",
                file_path,
                elapsed,
                self._timeout,
            )
        except yara.Error as e:
            # Handle other YARA matching errors gracefully
            self._logger.debug(
                "YARA error on file %s: %s",
                file_path,
                str(e),
            )
        except Exception as e:
            # Handle other errors (e.g., encoding issues)
            self._logger.debug(
                "Unexpected error during YARA matching on file %s: %s",
                file_path,
                str(e),
            )

        # Log performance metrics in verbose mode
        elapsed = time.perf_counter() - start_time
        self._logger.debug(
            "YaraDetector processed %s in %.3fs: %d findings",
            file_path,
            elapsed,
            len(findings),
        )

        return findings

    def get_rules_path(self) -> Path:
        """Return the path to the YARA rules.

        Returns:
            The Path object for the rules directory or file.
        """
        return self._rules_path

    def reload_rules(self) -> None:
        """Reload and recompile YARA rules from the configured path.

        This can be used to pick up changes to rule files without
        recreating the detector instance. If caching is enabled,
        the old cache entry will be invalidated.

        Raises:
            yara.SyntaxError: If any YARA rule has syntax errors.
        """
        # Invalidate old cache entry if it exists
        if self._use_cache and self._cache_key and self._cache_key in _RULE_CACHE:
            del _RULE_CACHE[self._cache_key]
            self._cache_key = None
        self._compile_rules()

    @property
    def use_cache(self) -> bool:
        """Return whether rule caching is enabled."""
        return self._use_cache

    @property
    def cache_key(self) -> str | None:
        """Return the cache key for the current rules, or None if not cached."""
        return self._cache_key

    @classmethod
    def get_cache_stats(cls) -> dict[str, Any]:
        """Get statistics about the rule cache.

        Returns:
            Dictionary with cache statistics including size and keys.
        """
        return {
            "size": len(_RULE_CACHE),
            "keys": list(_RULE_CACHE.keys()),
        }

    @classmethod
    def clear_cache(cls) -> int:
        """Clear all cached YARA rules.

        Returns:
            Number of cache entries cleared.
        """
        count = len(_RULE_CACHE)
        _RULE_CACHE.clear()
        return count

    async def detect_async(self, content: str, file_path: str = "") -> list[Finding]:
        """Asynchronously detect YARA rule matches in the given content.

        This method runs the synchronous detect() method in a thread pool
        using asyncio.to_thread(), allowing it to be called from async code
        without blocking the event loop.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each matched YARA rule.
        """
        return await asyncio.to_thread(self.detect, content, file_path)

    async def detect_bytes_async(self, content: bytes, file_path: str = "") -> list[Finding]:
        """Asynchronously detect YARA rule matches in raw byte content.

        This method runs the synchronous detect_bytes() method in a thread pool
        using asyncio.to_thread(), allowing it to be called from async code
        without blocking the event loop.

        Args:
            content: The raw byte content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each matched YARA rule.
        """
        return await asyncio.to_thread(self.detect_bytes, content, file_path)

    def detect_batch(self, contents: list[tuple[bytes, str]]) -> dict[str, list[Finding]]:
        """Detect YARA rule matches in multiple byte contents efficiently.

        This method processes multiple pieces of content in a batch,
        reusing the compiled rules for better performance.

        Args:
            contents: List of (content_bytes, file_path) tuples to analyze.

        Returns:
            Dictionary mapping file paths to their findings.
        """
        results: dict[str, list[Finding]] = {}

        for content_bytes, file_path in contents:
            findings = self.detect_bytes(content_bytes, file_path)
            results[file_path] = findings

        return results

    async def detect_batch_async(
        self,
        contents: list[tuple[bytes, str]],
        concurrency_limit: int = 10,
    ) -> dict[str, list[Finding]]:
        """Asynchronously detect YARA matches in multiple contents.

        This method processes multiple pieces of content concurrently using a
        semaphore to limit the number of parallel operations.

        Args:
            contents: List of (content_bytes, file_path) tuples to analyze.
            concurrency_limit: Maximum number of concurrent detection operations.

        Returns:
            Dictionary mapping file paths to their findings.
        """
        semaphore = asyncio.Semaphore(concurrency_limit)
        results: dict[str, list[Finding]] = {}
        lock = asyncio.Lock()

        async def process_content(content_bytes: bytes, file_path: str) -> None:
            async with semaphore:
                findings = await asyncio.to_thread(self.detect_bytes, content_bytes, file_path)
                async with lock:
                    results[file_path] = findings

        tasks = [process_content(content, path) for content, path in contents]
        await asyncio.gather(*tasks)

        return results

    async def detect_stream(self, content: bytes, file_path: str = "") -> AsyncIterator[Finding]:
        """Stream YARA rule matches as they are discovered.

        This async generator yields findings one at a time as they are
        discovered during matching, allowing for real-time processing
        of results without waiting for all matches to complete.

        Args:
            content: The raw byte content to analyze.
            file_path: The path to the file being analyzed.

        Yields:
            Finding objects as they are discovered.
        """
        if self._rules is None:
            return

        # Check file size before processing
        content_size = len(content)
        if content_size > self._max_file_size:
            self._logger.warning(
                "Skipping file %s: size %d bytes exceeds YARA max %d bytes",
                file_path,
                content_size,
                self._max_file_size,
            )
            return

        # Run matching in thread pool
        try:
            matches = await asyncio.to_thread(
                self._rules.match, data=content, timeout=self._timeout
            )

            for match in matches:
                rule_name = match.rule
                severity = self._severity_mapping.get(rule_name, Severity.MEDIUM)

                # Extract match strings
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            matched_data = instance.matched_data.decode("utf-8", errors="replace")
                        except AttributeError:
                            matched_data = str(instance.matched_data)
                        matched_strings.append(matched_data)

                # Extract metadata from the rule
                metadata = dict(match.meta) if match.meta else {}
                metadata["rule_name"] = rule_name
                metadata["namespace"] = match.namespace
                metadata["tags"] = list(match.tags) if match.tags else []

                yield Finding(
                    file_path=file_path,
                    detector_name=f"yara:{rule_name}",
                    matches=matched_strings if matched_strings else [rule_name],
                    severity=severity,
                    metadata=metadata,
                )

        except yara.TimeoutError:
            self._logger.warning(
                "YARA streaming match timed out on file %s (limit: %ds)",
                file_path,
                self._timeout,
            )
        except yara.Error as e:
            self._logger.debug(
                "YARA error during streaming on file %s: %s",
                file_path,
                str(e),
            )
        except Exception as e:
            self._logger.debug(
                "Unexpected error during YARA streaming on file %s: %s",
                file_path,
                str(e),
            )

    def get_detector_stats(self) -> dict[str, Any]:
        """Get statistics about the detector configuration.

        Returns:
            Dictionary with detector statistics including rule count,
            timeout settings, and cache status.
        """
        return {
            "name": self.name,
            "rule_count": self._rule_count,
            "rules_path": str(self._rules_path),
            "max_file_size": self._max_file_size,
            "timeout": self._timeout,
            "use_cache": self._use_cache,
            "cache_key": self._cache_key,
            "is_cached": self._cache_key in _RULE_CACHE if self._cache_key else False,
        }
