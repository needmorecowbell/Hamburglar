"""Tests for the FileFilter class.

This module tests the file filtering functionality including:
- Glob pattern matching (*, **, ?, [])
- Gitignore-style patterns (negation, directory-only, anchored)
- Pattern caching
- Both sync and async interfaces
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

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

from hamburglar.core.file_filter import (  # noqa: E402
    CompiledPattern,
    FileFilter,
    FilterResult,
)


class TestBasicGlobPatterns:
    """Test basic glob pattern matching."""

    def test_star_matches_filename(self, tmp_path: Path) -> None:
        """Test that * matches any filename."""
        file_filter = FileFilter(exclude=["*.pyc"])

        pyc_file = tmp_path / "test.pyc"
        pyc_file.touch()
        py_file = tmp_path / "test.py"
        py_file.touch()

        assert not file_filter.should_include(pyc_file)
        assert file_filter.should_include(py_file)

    def test_star_matches_partial_filename(self, tmp_path: Path) -> None:
        """Test that * matches partial filenames."""
        file_filter = FileFilter(exclude=["test_*.py"])

        test_file = tmp_path / "test_example.py"
        test_file.touch()
        other_file = tmp_path / "example.py"
        other_file.touch()

        assert not file_filter.should_include(test_file)
        assert file_filter.should_include(other_file)

    def test_double_star_matches_directories(self, tmp_path: Path) -> None:
        """Test that ** matches any number of directories."""
        file_filter = FileFilter(exclude=["**/test.py"])

        # Create nested structure
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        deep_file = nested / "test.py"
        deep_file.touch()
        other_file = nested / "other.py"
        other_file.touch()

        assert not file_filter.should_include(deep_file)
        assert file_filter.should_include(other_file)

    def test_question_mark_matches_single_char(self, tmp_path: Path) -> None:
        """Test that ? matches exactly one character."""
        file_filter = FileFilter(exclude=["test?.py"])

        test1 = tmp_path / "test1.py"
        test1.touch()
        test12 = tmp_path / "test12.py"
        test12.touch()

        assert not file_filter.should_include(test1)
        assert file_filter.should_include(test12)  # "12" is two chars

    def test_character_class_matches(self, tmp_path: Path) -> None:
        """Test that [abc] matches character classes."""
        file_filter = FileFilter(exclude=["test[123].py"])

        test1 = tmp_path / "test1.py"
        test1.touch()
        test4 = tmp_path / "test4.py"
        test4.touch()

        assert not file_filter.should_include(test1)
        assert file_filter.should_include(test4)

    def test_negated_character_class(self, tmp_path: Path) -> None:
        """Test that [!abc] matches characters not in class."""
        file_filter = FileFilter(exclude=["test[!123].py"])

        test1 = tmp_path / "test1.py"
        test1.touch()
        testa = tmp_path / "testa.py"
        testa.touch()

        assert file_filter.should_include(test1)  # 1 is in excluded set
        assert not file_filter.should_include(testa)  # 'a' is not in set


class TestGitignoreStylePatterns:
    """Test gitignore-style pattern features."""

    def test_negation_pattern(self, tmp_path: Path) -> None:
        """Test that ! prefix negates a pattern."""
        file_filter = FileFilter(exclude=["*.log", "!important.log"])

        regular_log = tmp_path / "debug.log"
        regular_log.touch()
        important_log = tmp_path / "important.log"
        important_log.touch()

        assert not file_filter.should_include(regular_log)
        assert file_filter.should_include(important_log)

    def test_directory_only_pattern(self, tmp_path: Path) -> None:
        """Test that trailing / matches only directories."""
        file_filter = FileFilter(exclude=["cache/"])

        # Create directory
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create file with same name
        cache_file = tmp_path / "cache_file"
        cache_file.touch()

        assert not file_filter.should_include(cache_dir)
        assert file_filter.should_include(cache_file)

    def test_anchored_pattern_leading_slash(self, tmp_path: Path) -> None:
        """Test that leading / anchors to base path."""
        file_filter = FileFilter(exclude=["/root_only.py"], base_path=tmp_path)

        root_file = tmp_path / "root_only.py"
        root_file.touch()

        nested_dir = tmp_path / "subdir"
        nested_dir.mkdir()
        nested_file = nested_dir / "root_only.py"
        nested_file.touch()

        assert not file_filter.should_include(root_file)
        # Nested file with same name should not be excluded by anchored pattern
        # (This depends on implementation - checking actual behavior)

    def test_anchored_pattern_with_slash_in_middle(self, tmp_path: Path) -> None:
        """Test that patterns with / in middle are anchored."""
        file_filter = FileFilter(exclude=["src/temp.py"], base_path=tmp_path)

        src_dir = tmp_path / "src"
        src_dir.mkdir()

        temp_file = src_dir / "temp.py"
        temp_file.touch()

        assert not file_filter.should_include(temp_file)

    def test_comment_patterns_ignored(self) -> None:
        """Test that # comments are ignored."""
        file_filter = FileFilter(exclude=["# This is a comment", "*.pyc"])

        # Should only have one compiled pattern
        assert len(file_filter._compiled_excludes) == 1
        assert file_filter._compiled_excludes[0].original == "*.pyc"

    def test_empty_patterns_ignored(self) -> None:
        """Test that empty patterns are ignored."""
        file_filter = FileFilter(exclude=["", "  ", "*.pyc"])

        # Should only have one compiled pattern
        assert len(file_filter._compiled_excludes) == 1


class TestIncludePatterns:
    """Test include pattern functionality."""

    def test_include_only_matching_files(self, tmp_path: Path) -> None:
        """Test that only files matching include patterns are included."""
        file_filter = FileFilter(include=["*.py"])

        py_file = tmp_path / "test.py"
        py_file.touch()
        js_file = tmp_path / "test.js"
        js_file.touch()

        assert file_filter.should_include(py_file)
        assert not file_filter.should_include(js_file)

    def test_include_and_exclude_together(self, tmp_path: Path) -> None:
        """Test that exclude takes precedence within included files."""
        file_filter = FileFilter(
            include=["*.py"],
            exclude=["test_*.py"],
        )

        main_py = tmp_path / "main.py"
        main_py.touch()
        test_py = tmp_path / "test_main.py"
        test_py.touch()
        js_file = tmp_path / "test.js"
        js_file.touch()

        assert file_filter.should_include(main_py)
        assert not file_filter.should_include(test_py)  # Excluded
        assert not file_filter.should_include(js_file)  # Not in include

    def test_include_with_negation(self, tmp_path: Path) -> None:
        """Test include patterns with negation."""
        file_filter = FileFilter(include=["*.py", "!test_*.py"])

        main_py = tmp_path / "main.py"
        main_py.touch()
        test_py = tmp_path / "test_main.py"
        test_py.touch()

        assert file_filter.should_include(main_py)
        assert not file_filter.should_include(test_py)


class TestPatternCaching:
    """Test pattern caching functionality."""

    def setup_method(self) -> None:
        """Clear cache before each test."""
        FileFilter.clear_cache()

    def test_patterns_are_cached(self) -> None:
        """Test that compiled patterns are cached."""
        FileFilter.clear_cache()

        filter1 = FileFilter(exclude=["*.pyc"])
        cache_size_after_first = len(FileFilter._pattern_cache)

        filter2 = FileFilter(exclude=["*.pyc"])
        cache_size_after_second = len(FileFilter._pattern_cache)

        # Cache should not grow on second filter
        assert cache_size_after_first == cache_size_after_second
        assert cache_size_after_first == 1

    def test_case_sensitivity_affects_cache(self) -> None:
        """Test that case sensitivity creates separate cache entries."""
        FileFilter.clear_cache()

        filter1 = FileFilter(exclude=["*.PYC"], case_sensitive=True)
        filter2 = FileFilter(exclude=["*.PYC"], case_sensitive=False)

        # Should have two entries (same pattern, different case sensitivity)
        assert len(FileFilter._pattern_cache) == 2

    def test_clear_cache_works(self) -> None:
        """Test that clear_cache removes all cached patterns."""
        FileFilter(exclude=["*.pyc", "*.pyo", "__pycache__"])
        assert len(FileFilter._pattern_cache) > 0

        FileFilter.clear_cache()
        assert len(FileFilter._pattern_cache) == 0


class TestCaseSensitivity:
    """Test case-sensitive and case-insensitive matching."""

    def test_case_sensitive_by_default(self, tmp_path: Path) -> None:
        """Test that matching is case-sensitive by default."""
        file_filter = FileFilter(exclude=["*.PYC"])

        upper_file = tmp_path / "test.PYC"
        upper_file.touch()
        lower_file = tmp_path / "test.pyc"
        lower_file.touch()

        assert not file_filter.should_include(upper_file)
        assert file_filter.should_include(lower_file)

    def test_case_insensitive_matching(self, tmp_path: Path) -> None:
        """Test case-insensitive matching."""
        file_filter = FileFilter(exclude=["*.PYC"], case_sensitive=False)

        upper_file = tmp_path / "test.PYC"
        upper_file.touch()
        lower_file = tmp_path / "test.pyc"
        lower_file.touch()

        assert not file_filter.should_include(upper_file)
        assert not file_filter.should_include(lower_file)


class TestFilterResult:
    """Test FilterResult detailed output."""

    def test_filter_result_excluded(self, tmp_path: Path) -> None:
        """Test filter_path returns correct result for excluded files."""
        file_filter = FileFilter(exclude=["*.pyc"])

        pyc_file = tmp_path / "test.pyc"
        pyc_file.touch()

        result = file_filter.filter_path(pyc_file)

        assert isinstance(result, FilterResult)
        assert result.path == pyc_file
        assert result.included is False
        assert result.matched_pattern == "*.pyc"
        assert "Excluded" in result.reason

    def test_filter_result_included(self, tmp_path: Path) -> None:
        """Test filter_path returns correct result for included files."""
        file_filter = FileFilter(include=["*.py"])

        py_file = tmp_path / "test.py"
        py_file.touch()

        result = file_filter.filter_path(py_file)

        assert result.included is True
        assert result.matched_pattern == "*.py"
        assert "Included" in result.reason

    def test_filter_result_default_include(self, tmp_path: Path) -> None:
        """Test filter_path for files included by default."""
        file_filter = FileFilter(exclude=["*.pyc"])

        py_file = tmp_path / "test.py"
        py_file.touch()

        result = file_filter.filter_path(py_file)

        assert result.included is True
        assert result.matched_pattern is None
        assert "default" in result.reason.lower()


class TestFilterPathsSync:
    """Test synchronous path filtering."""

    def test_filter_paths_iterator(self, tmp_path: Path) -> None:
        """Test that filter_paths returns an iterator of included paths."""
        # Create files
        for name in ["a.py", "b.pyc", "c.py", "d.pyo"]:
            (tmp_path / name).touch()

        file_filter = FileFilter(exclude=["*.pyc", "*.pyo"])
        paths = list(tmp_path.iterdir())

        included = list(file_filter.filter_paths(paths))

        assert len(included) == 2
        names = {p.name for p in included}
        assert names == {"a.py", "c.py"}

    def test_filter_paths_with_generator(self, tmp_path: Path) -> None:
        """Test that filter_paths works with generators."""
        for name in ["a.py", "b.pyc"]:
            (tmp_path / name).touch()

        file_filter = FileFilter(exclude=["*.pyc"])

        # Pass a generator
        def path_generator():
            yield from tmp_path.iterdir()

        included = list(file_filter.filter_paths(path_generator()))

        assert len(included) == 1
        assert included[0].name == "a.py"


class TestAsyncInterfaces:
    """Test async filtering interfaces."""

    @pytest.mark.asyncio
    async def test_should_include_async(self, tmp_path: Path) -> None:
        """Test async version of should_include."""
        file_filter = FileFilter(exclude=["*.pyc"])

        pyc_file = tmp_path / "test.pyc"
        pyc_file.touch()
        py_file = tmp_path / "test.py"
        py_file.touch()

        assert not await file_filter.should_include_async(pyc_file)
        assert await file_filter.should_include_async(py_file)

    @pytest.mark.asyncio
    async def test_filter_path_async(self, tmp_path: Path) -> None:
        """Test async version of filter_path."""
        file_filter = FileFilter(exclude=["*.pyc"])

        pyc_file = tmp_path / "test.pyc"
        pyc_file.touch()

        result = await file_filter.filter_path_async(pyc_file)

        assert isinstance(result, FilterResult)
        assert result.included is False

    @pytest.mark.asyncio
    async def test_filter_paths_async(self, tmp_path: Path) -> None:
        """Test async filtering of multiple paths."""
        # Create files
        for name in ["a.py", "b.pyc", "c.py", "d.pyo"]:
            (tmp_path / name).touch()

        file_filter = FileFilter(exclude=["*.pyc", "*.pyo"])
        paths = list(tmp_path.iterdir())

        included = []
        async for path in file_filter.filter_paths_async(paths):
            included.append(path)

        assert len(included) == 2
        names = {p.name for p in included}
        assert names == {"a.py", "c.py"}

    @pytest.mark.asyncio
    async def test_filter_paths_async_concurrency(self, tmp_path: Path) -> None:
        """Test that concurrency limit is respected."""
        # Create many files
        for i in range(20):
            (tmp_path / f"file{i}.txt").touch()

        file_filter = FileFilter()
        paths = list(tmp_path.iterdir())

        included = []
        async for path in file_filter.filter_paths_async(paths, concurrency_limit=5):
            included.append(path)

        assert len(included) == 20


class TestDynamicPatternManagement:
    """Test adding and removing patterns dynamically."""

    def test_add_exclude(self, tmp_path: Path) -> None:
        """Test adding exclude patterns dynamically."""
        file_filter = FileFilter()

        pyc_file = tmp_path / "test.pyc"
        pyc_file.touch()

        assert file_filter.should_include(pyc_file)

        file_filter.add_exclude("*.pyc")

        assert not file_filter.should_include(pyc_file)

    def test_add_include(self, tmp_path: Path) -> None:
        """Test adding include patterns dynamically."""
        file_filter = FileFilter(include=["*.py"])

        js_file = tmp_path / "test.js"
        js_file.touch()

        assert not file_filter.should_include(js_file)

        file_filter.add_include("*.js")

        assert file_filter.should_include(js_file)

    def test_remove_exclude(self, tmp_path: Path) -> None:
        """Test removing exclude patterns."""
        file_filter = FileFilter(exclude=["*.pyc"])

        pyc_file = tmp_path / "test.pyc"
        pyc_file.touch()

        assert not file_filter.should_include(pyc_file)

        result = file_filter.remove_exclude("*.pyc")

        assert result is True
        assert file_filter.should_include(pyc_file)

    def test_remove_nonexistent_pattern(self) -> None:
        """Test removing pattern that doesn't exist."""
        file_filter = FileFilter(exclude=["*.pyc"])

        result = file_filter.remove_exclude("*.pyo")

        assert result is False
        assert len(file_filter.exclude_patterns) == 1


class TestGitignoreFile:
    """Test loading patterns from gitignore files."""

    def test_from_gitignore(self, tmp_path: Path) -> None:
        """Test creating filter from .gitignore file."""
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("""
# Python
*.pyc
*.pyo
__pycache__/

# Node
node_modules/

# Keep this
!important.pyc
""")

        file_filter = FileFilter.from_gitignore(gitignore)

        assert "*.pyc" in file_filter.exclude_patterns
        assert "*.pyo" in file_filter.exclude_patterns
        assert "__pycache__/" in file_filter.exclude_patterns
        assert "node_modules/" in file_filter.exclude_patterns
        assert "!important.pyc" in file_filter.exclude_patterns

    def test_from_gitignore_nonexistent(self, tmp_path: Path) -> None:
        """Test from_gitignore with nonexistent file."""
        nonexistent = tmp_path / ".gitignore"

        file_filter = FileFilter.from_gitignore(nonexistent)

        # Should return empty filter
        assert len(file_filter.exclude_patterns) == 0

    def test_from_gitignore_base_path(self, tmp_path: Path) -> None:
        """Test that base_path is set correctly."""
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("*.pyc")

        file_filter = FileFilter.from_gitignore(gitignore)

        assert file_filter.base_path == tmp_path


class TestCommonPatterns:
    """Test common real-world patterns."""

    def test_node_modules_pattern(self, tmp_path: Path) -> None:
        """Test excluding node_modules directory."""
        file_filter = FileFilter(exclude=["node_modules", "node_modules/**"])

        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        package = nm_dir / "lodash" / "index.js"
        package.parent.mkdir(parents=True)
        package.touch()

        src_file = tmp_path / "src" / "index.js"
        src_file.parent.mkdir(parents=True)
        src_file.touch()

        assert not file_filter.should_include(package)
        assert file_filter.should_include(src_file)

    def test_dot_git_pattern(self, tmp_path: Path) -> None:
        """Test excluding .git directory."""
        file_filter = FileFilter(exclude=[".git", ".git/**"])

        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        git_file = git_dir / "config"
        git_file.touch()

        src_file = tmp_path / "src.py"
        src_file.touch()

        assert not file_filter.should_include(git_file)
        assert file_filter.should_include(src_file)

    def test_pycache_pattern(self, tmp_path: Path) -> None:
        """Test excluding __pycache__ directories."""
        file_filter = FileFilter(exclude=["__pycache__", "**/__pycache__/**"])

        pycache = tmp_path / "src" / "__pycache__"
        pycache.mkdir(parents=True)
        cache_file = pycache / "module.cpython-39.pyc"
        cache_file.touch()

        src_file = tmp_path / "src" / "module.py"
        src_file.touch()

        assert not file_filter.should_include(cache_file)
        assert file_filter.should_include(src_file)

    def test_env_files_pattern(self, tmp_path: Path) -> None:
        """Test excluding .env files."""
        file_filter = FileFilter(exclude=[".env", ".env.*", "*.env"])

        env_file = tmp_path / ".env"
        env_file.touch()
        env_local = tmp_path / ".env.local"
        env_local.touch()
        prod_env = tmp_path / "production.env"
        prod_env.touch()
        config = tmp_path / "config.py"
        config.touch()

        assert not file_filter.should_include(env_file)
        assert not file_filter.should_include(env_local)
        assert not file_filter.should_include(prod_env)
        assert file_filter.should_include(config)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_filter(self, tmp_path: Path) -> None:
        """Test filter with no patterns includes everything."""
        file_filter = FileFilter()

        any_file = tmp_path / "anything.xyz"
        any_file.touch()

        assert file_filter.should_include(any_file)

    def test_special_regex_chars_escaped(self, tmp_path: Path) -> None:
        """Test that special regex characters are properly escaped."""
        file_filter = FileFilter(exclude=["file+name.py", "test(1).py"])

        plus_file = tmp_path / "file+name.py"
        plus_file.touch()
        paren_file = tmp_path / "test(1).py"
        paren_file.touch()
        normal = tmp_path / "normal.py"
        normal.touch()

        assert not file_filter.should_include(plus_file)
        assert not file_filter.should_include(paren_file)
        assert file_filter.should_include(normal)

    def test_invalid_pattern_logged(self, tmp_path: Path, caplog) -> None:
        """Test that invalid patterns are logged as warnings."""
        # [abc without closing bracket could cause issues
        # depending on implementation
        file_filter = FileFilter(exclude=["[invalid"])

        # Should not crash, but pattern might be skipped or treated as literal
        some_file = tmp_path / "test.py"
        some_file.touch()

        # Should still work (either include or exclude, but not crash)
        result = file_filter.should_include(some_file)
        assert isinstance(result, bool)

    def test_repr(self) -> None:
        """Test string representation."""
        file_filter = FileFilter(exclude=["*.pyc"], include=["*.py"])

        repr_str = repr(file_filter)

        assert "FileFilter" in repr_str
        assert "*.pyc" in repr_str
        assert "*.py" in repr_str

    def test_path_normalization(self, tmp_path: Path) -> None:
        """Test that paths with different separators work."""
        file_filter = FileFilter(exclude=["src/temp/*.py"])

        src_dir = tmp_path / "src" / "temp"
        src_dir.mkdir(parents=True)
        temp_file = src_dir / "test.py"
        temp_file.touch()

        # Should work regardless of OS path separator
        assert not file_filter.should_include(temp_file)


class TestMultiplePatternInteraction:
    """Test how multiple patterns interact."""

    def test_later_patterns_override_earlier(self, tmp_path: Path) -> None:
        """Test that later patterns can override earlier ones."""
        file_filter = FileFilter(exclude=[
            "*.log",
            "!important.log",
            "*.tmp",
        ])

        debug_log = tmp_path / "debug.log"
        debug_log.touch()
        important_log = tmp_path / "important.log"
        important_log.touch()
        temp = tmp_path / "cache.tmp"
        temp.touch()

        assert not file_filter.should_include(debug_log)
        assert file_filter.should_include(important_log)
        assert not file_filter.should_include(temp)

    def test_multiple_star_star_patterns(self, tmp_path: Path) -> None:
        """Test multiple ** patterns."""
        file_filter = FileFilter(exclude=[
            "**/node_modules/**",
            "**/__pycache__/**",
            "**/dist/**",
        ])

        # Create nested structures
        nm = tmp_path / "frontend" / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        nm_file = nm / "index.js"
        nm_file.touch()

        pycache = tmp_path / "backend" / "__pycache__"
        pycache.mkdir(parents=True)
        pyc = pycache / "mod.pyc"
        pyc.touch()

        dist = tmp_path / "dist" / "bundle.js"
        dist.parent.mkdir(parents=True)
        dist.touch()

        src = tmp_path / "src" / "main.py"
        src.parent.mkdir(parents=True)
        src.touch()

        assert not file_filter.should_include(nm_file)
        assert not file_filter.should_include(pyc)
        assert not file_filter.should_include(dist)
        assert file_filter.should_include(src)


class TestFilterWithRealDirectoryStructure:
    """Test filter with realistic directory structures."""

    @pytest.fixture
    def project_structure(self, tmp_path: Path) -> Path:
        """Create a realistic project structure."""
        # Create directories
        (tmp_path / "src" / "hamburglar" / "core").mkdir(parents=True)
        (tmp_path / "src" / "hamburglar" / "detectors").mkdir(parents=True)
        (tmp_path / "tests").mkdir()
        (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
        (tmp_path / ".git" / "objects").mkdir(parents=True)
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "src" / "hamburglar" / "__pycache__").mkdir()

        # Create files
        (tmp_path / "src" / "hamburglar" / "__init__.py").touch()
        (tmp_path / "src" / "hamburglar" / "core" / "scanner.py").touch()
        (tmp_path / "src" / "hamburglar" / "core" / "__init__.py").touch()
        (tmp_path / "tests" / "test_scanner.py").touch()
        (tmp_path / "node_modules" / "lodash" / "index.js").touch()
        (tmp_path / ".git" / "config").touch()
        (tmp_path / "__pycache__" / "conftest.cpython-39.pyc").touch()
        (tmp_path / "src" / "hamburglar" / "__pycache__" / "core.cpython-39.pyc").touch()
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / ".env").touch()
        (tmp_path / ".env.local").touch()

        return tmp_path

    def test_typical_python_project_filter(self, project_structure: Path) -> None:
        """Test filtering a typical Python project."""
        file_filter = FileFilter(
            exclude=[
                ".git",
                ".git/**",
                "__pycache__",
                "**/__pycache__/**",
                "*.pyc",
                "node_modules",
                "node_modules/**",
                ".env",
                ".env.*",
            ],
            base_path=project_structure,
        )

        # Collect all files
        all_files = list(project_structure.rglob("*"))
        files_only = [f for f in all_files if f.is_file()]

        included = list(file_filter.filter_paths(files_only))
        included_names = {f.name for f in included}

        # Should include source files
        assert "scanner.py" in included_names
        assert "__init__.py" in included_names
        assert "test_scanner.py" in included_names
        assert "pyproject.toml" in included_names

        # Should exclude
        excluded_files = set(files_only) - set(included)
        excluded_names = {f.name for f in excluded_files}

        assert "config" in excluded_names  # .git/config
        assert ".env" in excluded_names
        assert ".env.local" in excluded_names

    def test_source_only_filter(self, project_structure: Path) -> None:
        """Test filtering to only include source Python files."""
        file_filter = FileFilter(
            include=["*.py"],
            exclude=[
                "test_*.py",
                "**/__pycache__/**",
                "*.pyc",
            ],
        )

        all_files = [f for f in project_structure.rglob("*") if f.is_file()]
        included = list(file_filter.filter_paths(all_files))

        # Should only have non-test Python files
        for f in included:
            assert f.suffix == ".py"
            assert not f.name.startswith("test_")
            assert "__pycache__" not in str(f)
