"""File filter module for Hamburglar.

This module provides the FileFilter class which implements efficient file
filtering using glob patterns and gitignore-style patterns. It supports
both sync and async interfaces and caches compiled patterns for reuse.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CompiledPattern:
    """A compiled pattern for efficient matching.

    Attributes:
        original: The original pattern string.
        regex: Compiled regex pattern for matching.
        is_negation: Whether this is a negation pattern (starts with !).
        is_dir_only: Whether this pattern only matches directories (ends with /).
        anchored: Whether this pattern is anchored to a specific path level.
    """

    original: str
    regex: re.Pattern[str]
    is_negation: bool = False
    is_dir_only: bool = False
    anchored: bool = False


@dataclass
class FilterResult:
    """Result of filtering operation.

    Attributes:
        path: The path that was checked.
        included: Whether the path should be included.
        matched_pattern: The pattern that determined the result (if any).
        reason: Human-readable reason for the decision.
    """

    path: Path
    included: bool
    matched_pattern: str | None = None
    reason: str = ""


class FileFilter:
    """File filter with efficient glob and gitignore-style pattern matching.

    Provides both sync and async interfaces for filtering files based on
    patterns. Compiles and caches patterns for efficient reuse.

    Features:
    - Standard glob patterns (*, **, ?, [])
    - Gitignore-style patterns:
      - ! prefix for negation
      - / suffix for directory-only
      - Leading / for root-anchored patterns
      - ** for matching any number of directories
    - Pattern caching for performance
    - Both include and exclude patterns

    Example:
        >>> filter = FileFilter(
        ...     exclude=["*.pyc", "__pycache__", "node_modules/"],
        ...     include=["*.py", "*.js"],
        ... )
        >>> filter.should_include(Path("src/main.py"))
        True
        >>> filter.should_include(Path("cache.pyc"))
        False

        >>> # Async usage
        >>> paths = [Path("a.py"), Path("b.pyc"), Path("c.py")]
        >>> async for path in filter.filter_paths_async(paths):
        ...     print(path)
    """

    # Pattern cache is shared across instances for patterns
    _pattern_cache: dict[str, CompiledPattern] = {}

    def __init__(
        self,
        exclude: list[str] | None = None,
        include: list[str] | None = None,
        base_path: Path | None = None,
        case_sensitive: bool = True,
    ):
        """Initialize the file filter.

        Args:
            exclude: Patterns to exclude (gitignore-style). Files matching
                    any of these patterns are excluded unless re-included.
            include: Patterns to include. If specified, only files matching
                    these patterns (and not excluded) are included.
                    If None, all non-excluded files are included.
            base_path: Base path for anchored patterns. Patterns starting
                      with / are relative to this path. Defaults to cwd.
            case_sensitive: Whether pattern matching is case-sensitive.
                           Defaults to True.
        """
        self.exclude_patterns = exclude or []
        self.include_patterns = include or []
        self.base_path = base_path or Path.cwd()
        self.case_sensitive = case_sensitive

        # Compile all patterns
        self._compiled_excludes: list[CompiledPattern] = []
        self._compiled_includes: list[CompiledPattern] = []

        for pattern in self.exclude_patterns:
            compiled = self._compile_pattern(pattern)
            if compiled:
                self._compiled_excludes.append(compiled)

        for pattern in self.include_patterns:
            compiled = self._compile_pattern(pattern)
            if compiled:
                self._compiled_includes.append(compiled)

    def _compile_pattern(self, pattern: str) -> CompiledPattern | None:
        """Compile a gitignore-style pattern to a regex.

        Args:
            pattern: The pattern to compile.

        Returns:
            CompiledPattern or None if pattern is empty/comment.
        """
        # Skip empty patterns and comments
        pattern = pattern.strip()
        if not pattern or pattern.startswith("#"):
            return None

        # Create cache key including case sensitivity
        cache_key = f"{pattern}:{self.case_sensitive}"
        if cache_key in self._pattern_cache:
            return self._pattern_cache[cache_key]

        original = pattern
        is_negation = False
        is_dir_only = False
        anchored = False

        # Check for negation (! prefix)
        if pattern.startswith("!"):
            is_negation = True
            pattern = pattern[1:]

        # Check for directory-only (trailing /)
        if pattern.endswith("/"):
            is_dir_only = True
            pattern = pattern[:-1]

        # Check for anchored pattern (leading /)
        if pattern.startswith("/"):
            anchored = True
            pattern = pattern[1:]
        elif "/" in pattern and not pattern.startswith("**/"):
            # Patterns with / in the middle are also anchored
            anchored = True

        # Convert glob pattern to regex
        regex_pattern = self._glob_to_regex(pattern)

        # Compile with case sensitivity
        flags = 0 if self.case_sensitive else re.IGNORECASE
        try:
            compiled_regex = re.compile(regex_pattern, flags)
        except re.error as e:
            logger.warning(f"Invalid pattern '{original}': {e}")
            return None

        compiled = CompiledPattern(
            original=original,
            regex=compiled_regex,
            is_negation=is_negation,
            is_dir_only=is_dir_only,
            anchored=anchored,
        )

        self._pattern_cache[cache_key] = compiled
        return compiled

    def _glob_to_regex(self, pattern: str) -> str:
        """Convert a glob pattern to a regex pattern.

        Handles:
        - * matches anything except /
        - ** matches anything including /
        - ? matches any single character except /
        - [abc] matches character classes
        - Escapes other regex special characters

        Args:
            pattern: Glob pattern to convert.

        Returns:
            Regex pattern string.
        """
        regex_parts: list[str] = []
        i = 0
        n = len(pattern)

        while i < n:
            c = pattern[i]

            if c == "*":
                # Check for ** (matches any path components)
                if i + 1 < n and pattern[i + 1] == "*":
                    # Check for **/ (matches zero or more directories)
                    if i + 2 < n and pattern[i + 2] == "/":
                        regex_parts.append("(?:.*/)?")
                        i += 3
                    else:
                        # ** at end or before non-slash
                        regex_parts.append(".*")
                        i += 2
                else:
                    # Single * matches anything except /
                    regex_parts.append("[^/]*")
                    i += 1
            elif c == "?":
                # ? matches any single character except /
                regex_parts.append("[^/]")
                i += 1
            elif c == "[":
                # Character class - find closing ]
                j = i + 1
                if j < n and pattern[j] == "!":
                    j += 1
                if j < n and pattern[j] == "]":
                    j += 1
                while j < n and pattern[j] != "]":
                    j += 1
                if j >= n:
                    # No closing ], treat [ as literal
                    regex_parts.append(re.escape(c))
                else:
                    # Extract character class
                    char_class = pattern[i : j + 1]
                    # Convert ! to ^ for negation
                    if len(char_class) > 1 and char_class[1] == "!":
                        char_class = "[^" + char_class[2:]
                    regex_parts.append(char_class)
                    i = j + 1
                    continue
                i += 1
            elif c == "/":
                regex_parts.append("/")
                i += 1
            else:
                # Escape special regex characters
                regex_parts.append(re.escape(c))
                i += 1

        # Build final pattern
        regex_str = "".join(regex_parts)

        # For non-anchored patterns, allow matching anywhere in path
        # For anchored patterns, match from start
        # Always match to end of string or before /
        return (
            f"(?:^|.*/){regex_str}(?:/.*)?$"
            if not self._is_simple_name(pattern)
            else f"(?:^|.*/){regex_str}$"
        )

    def _is_simple_name(self, pattern: str) -> bool:
        """Check if pattern is a simple filename (no directory components).

        Args:
            pattern: Pattern to check.

        Returns:
            True if pattern contains no slashes.
        """
        return "/" not in pattern

    def _match_path(self, path: Path, compiled: CompiledPattern) -> bool:
        """Check if a path matches a compiled pattern.

        Args:
            path: Path to check.
            compiled: Compiled pattern to match against.

        Returns:
            True if the path matches the pattern.
        """
        # For directory-only patterns, only match directories
        if compiled.is_dir_only and path.is_file():
            return False

        # Get the path string relative to base if anchored
        if compiled.anchored:
            try:
                rel_path = path.relative_to(self.base_path)
                path_str = str(rel_path)
            except ValueError:
                # Path is not relative to base, use full path
                path_str = str(path)
        else:
            path_str = str(path)

        # Normalize path separators
        path_str = path_str.replace("\\", "/")

        # Try matching against the full path
        if compiled.regex.search(path_str):
            return True

        # Also try matching just the filename for simple patterns
        if self._is_simple_name(compiled.original.lstrip("!").rstrip("/")):
            if compiled.regex.search(path.name):
                return True

        return False

    def should_include(self, path: Path) -> bool:
        """Check if a path should be included based on filter patterns.

        The matching logic follows gitignore conventions:
        1. Check exclude patterns - if matched, tentatively exclude
        2. Check for negation patterns in excludes - may re-include
        3. If include patterns exist, path must match at least one
        4. Include patterns also support negation

        Args:
            path: Path to check.

        Returns:
            True if the path should be included, False otherwise.
        """
        # Phase 1: Check exclude patterns
        excluded = False
        matched_exclude: str | None = None

        for compiled in self._compiled_excludes:
            if self._match_path(path, compiled):
                if compiled.is_negation:
                    # Negation pattern - re-include
                    excluded = False
                    matched_exclude = None
                else:
                    # Regular exclude pattern
                    excluded = True
                    matched_exclude = compiled.original

        if excluded:
            logger.debug(f"Excluded {path} by pattern '{matched_exclude}'")
            return False

        # Phase 2: Check include patterns (if specified)
        if not self._compiled_includes:
            # No include patterns means include everything not excluded
            return True

        included = False
        for compiled in self._compiled_includes:
            if self._match_path(path, compiled):
                if compiled.is_negation:
                    # Negation pattern - exclude
                    included = False
                else:
                    # Regular include pattern
                    included = True

        return included

    def filter_path(self, path: Path) -> FilterResult:
        """Filter a path and return detailed result.

        Args:
            path: Path to check.

        Returns:
            FilterResult with detailed matching information.
        """
        # Check exclude patterns first
        for compiled in self._compiled_excludes:
            if self._match_path(path, compiled):
                if compiled.is_negation:
                    return FilterResult(
                        path=path,
                        included=True,
                        matched_pattern=compiled.original,
                        reason="Re-included by negation pattern",
                    )
                else:
                    return FilterResult(
                        path=path,
                        included=False,
                        matched_pattern=compiled.original,
                        reason="Excluded by pattern",
                    )

        # Check include patterns
        if self._compiled_includes:
            for compiled in self._compiled_includes:
                if self._match_path(path, compiled):
                    if compiled.is_negation:
                        return FilterResult(
                            path=path,
                            included=False,
                            matched_pattern=compiled.original,
                            reason="Excluded by negation include pattern",
                        )
                    else:
                        return FilterResult(
                            path=path,
                            included=True,
                            matched_pattern=compiled.original,
                            reason="Included by pattern",
                        )

            # Has include patterns but none matched
            return FilterResult(
                path=path,
                included=False,
                matched_pattern=None,
                reason="No include pattern matched",
            )

        # No include patterns - include by default
        return FilterResult(
            path=path,
            included=True,
            matched_pattern=None,
            reason="Included by default (no exclude matched)",
        )

    def filter_paths(self, paths: list[Path] | Iterator[Path]) -> Iterator[Path]:
        """Filter a list of paths synchronously.

        Args:
            paths: Paths to filter.

        Yields:
            Paths that should be included.
        """
        for path in paths:
            if self.should_include(path):
                yield path

    async def should_include_async(self, path: Path) -> bool:
        """Async version of should_include.

        Runs the matching in a thread pool to avoid blocking.

        Args:
            path: Path to check.

        Returns:
            True if the path should be included.
        """
        return await asyncio.to_thread(self.should_include, path)

    async def filter_path_async(self, path: Path) -> FilterResult:
        """Async version of filter_path.

        Args:
            path: Path to check.

        Returns:
            FilterResult with detailed matching information.
        """
        return await asyncio.to_thread(self.filter_path, path)

    async def filter_paths_async(
        self,
        paths: list[Path],
        concurrency_limit: int = 50,
    ):
        """Filter paths asynchronously with concurrency control.

        Args:
            paths: Paths to filter.
            concurrency_limit: Maximum concurrent filter operations.

        Yields:
            Paths that should be included.
        """
        semaphore = asyncio.Semaphore(concurrency_limit)

        async def check_path(path: Path) -> tuple[Path, bool]:
            async with semaphore:
                included = await self.should_include_async(path)
                return path, included

        # Process in batches for better throughput
        tasks = [check_path(p) for p in paths]
        for task in asyncio.as_completed(tasks):
            path, included = await task
            if included:
                yield path

    def add_exclude(self, pattern: str) -> None:
        """Add an exclude pattern.

        Args:
            pattern: Pattern to add to exclude list.
        """
        compiled = self._compile_pattern(pattern)
        if compiled:
            self.exclude_patterns.append(pattern)
            self._compiled_excludes.append(compiled)

    def add_include(self, pattern: str) -> None:
        """Add an include pattern.

        Args:
            pattern: Pattern to add to include list.
        """
        compiled = self._compile_pattern(pattern)
        if compiled:
            self.include_patterns.append(pattern)
            self._compiled_includes.append(compiled)

    def remove_exclude(self, pattern: str) -> bool:
        """Remove an exclude pattern.

        Args:
            pattern: Pattern to remove.

        Returns:
            True if pattern was found and removed.
        """
        if pattern in self.exclude_patterns:
            self.exclude_patterns.remove(pattern)
            self._compiled_excludes = [c for c in self._compiled_excludes if c.original != pattern]
            return True
        return False

    def remove_include(self, pattern: str) -> bool:
        """Remove an include pattern.

        Args:
            pattern: Pattern to remove.

        Returns:
            True if pattern was found and removed.
        """
        if pattern in self.include_patterns:
            self.include_patterns.remove(pattern)
            self._compiled_includes = [c for c in self._compiled_includes if c.original != pattern]
            return True
        return False

    @classmethod
    def from_gitignore(
        cls,
        gitignore_path: Path,
        base_path: Path | None = None,
    ) -> FileFilter:
        """Create a FileFilter from a .gitignore file.

        Args:
            gitignore_path: Path to the .gitignore file.
            base_path: Base path for pattern matching.
                      Defaults to the parent of gitignore_path.

        Returns:
            FileFilter configured with patterns from the gitignore file.
        """
        patterns: list[str] = []

        try:
            with open(gitignore_path, encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip("\n\r")
                    # Skip empty lines and comments
                    if line.strip() and not line.strip().startswith("#"):
                        patterns.append(line)
        except OSError as e:
            logger.warning(f"Could not read gitignore file {gitignore_path}: {e}")
            return cls(exclude=[], base_path=base_path)

        return cls(
            exclude=patterns,
            base_path=base_path or gitignore_path.parent,
        )

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the pattern cache.

        Useful for testing or when memory needs to be freed.
        """
        cls._pattern_cache.clear()

    def __repr__(self) -> str:
        """Return string representation of the filter."""
        return f"FileFilter(exclude={self.exclude_patterns!r}, include={self.include_patterns!r})"
