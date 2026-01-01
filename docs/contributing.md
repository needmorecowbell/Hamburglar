# Contributing to Hamburglar

Thank you for your interest in contributing to Hamburglar! This guide covers everything you need to get started, from setting up your development environment to submitting your first pull request.

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style Guide](#code-style-guide)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting Guidelines](#issue-reporting-guidelines)
- [Architecture Overview](#architecture-overview)
- [Adding New Features](#adding-new-features)
- [Getting Help](#getting-help)

---

## Development Setup

### Prerequisites

Before you begin, ensure you have:

- **Python 3.9 or higher** - Hamburglar supports Python 3.9, 3.10, 3.11, and 3.12
- **Git** - For version control
- **A code editor** - VS Code, PyCharm, Neovim, etc.
- **YARA** (optional) - For YARA rule development; install with your system package manager

### Forking and Cloning

1. **Fork the repository** on GitHub by clicking the "Fork" button at [github.com/needmorecowbell/Hamburglar](https://github.com/needmorecowbell/Hamburglar)

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Hamburglar.git
   cd Hamburglar
   ```

3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/needmorecowbell/Hamburglar.git
   ```

### Setting Up Your Environment

1. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

   This installs:
   - All runtime dependencies (typer, rich, pydantic, yara-python, etc.)
   - Development tools: pytest, pytest-cov, pytest-asyncio, ruff, mypy

3. **Verify the installation**:
   ```bash
   # Check the CLI works
   hamburglar --version

   # Run the test suite
   pytest

   # Check linting
   ruff check .
   ```

### IDE Configuration

#### VS Code

Install the recommended extensions:
- Python (Microsoft)
- Ruff (Astral Software)

Create `.vscode/settings.json`:
```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "editor.formatOnSave": true,
    "[python]": {
        "editor.defaultFormatter": "charliermarsh.ruff"
    },
    "python.analysis.typeCheckingMode": "basic"
}
```

#### PyCharm

1. Set the project interpreter to your virtual environment
2. Enable Ruff as the formatter (Settings → Tools → Ruff)
3. Configure the Python 3.9 target version

### Keeping Your Fork Updated

Before starting new work, sync with upstream:
```bash
git fetch upstream
git checkout master
git merge upstream/master
git push origin master
```

---

## Code Style Guide

Consistent code style is enforced via automated tools. Run these before committing.

### Formatting and Linting with Ruff

We use [Ruff](https://docs.astral.sh/ruff/) for both linting and formatting:

```bash
# Check for issues
ruff check .

# Auto-fix issues where possible
ruff check --fix .

# Format code
ruff format .

# Check formatting without modifying
ruff format --check .
```

### Ruff Configuration

Our `ruff.toml` configuration:

| Setting | Value | Notes |
|---------|-------|-------|
| Line length | 100 | Slightly longer than PEP 8's 79 |
| Target version | Python 3.9 | Minimum supported version |
| Quote style | Double | Use `"string"` not `'string'` |
| Indent style | Spaces | 4-space indentation |

**Enabled rule sets:**
- `E` - pycodestyle errors
- `F` - pyflakes
- `I` - isort (import sorting)
- `UP` - pyupgrade (modernize syntax)
- `B` - flake8-bugbear (bug prevention)
- `SIM` - flake8-simplify (simplification)
- `TCH` - flake8-type-checking (type import optimization)

### Type Checking with mypy

We use [mypy](https://mypy.readthedocs.io/) for static type analysis:

```bash
mypy src/hamburglar
```

**Type annotation requirements:**
- All public functions and methods must have type annotations
- Use modern type syntax: `list[str]` not `List[str]`, `str | None` not `Optional[str]`
- Use `from __future__ import annotations` for forward references (Python 3.9 compatibility)

### Style Guidelines

#### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Modules | lowercase_with_underscores | `regex_detector.py` |
| Classes | PascalCase | `RegexDetector` |
| Functions | lowercase_with_underscores | `detect_secrets()` |
| Constants | UPPERCASE_WITH_UNDERSCORES | `DEFAULT_TIMEOUT` |
| Private members | leading_underscore | `_internal_cache` |

#### Import Order

Imports are automatically sorted by Ruff. The order is:
1. Standard library imports
2. Third-party imports
3. Local imports (hamburglar.*)

```python
import asyncio
from pathlib import Path

from pydantic import BaseModel
from rich.console import Console

from hamburglar.core.models import Finding
from hamburglar.detectors import BaseDetector
```

#### Docstrings

Use Google-style docstrings for all public modules, classes, and functions:

```python
def detect_secrets(
    content: str,
    file_path: str | None = None,
    categories: list[str] | None = None,
) -> list[Finding]:
    """Detect secrets in the given content.

    Scans the provided content using all registered detectors
    and returns any findings.

    Args:
        content: The file content to scan for secrets.
        file_path: Optional path to the file for Finding context.
            Used in output and filtering decisions.
        categories: Optional list of pattern categories to enable.
            If None, all categories are enabled.

    Returns:
        A list of Finding objects representing detected secrets.
        Each Finding contains match location, severity, and metadata.

    Raises:
        ValueError: If content is empty and empty_error=True.
        DetectorError: If detector initialization fails.

    Example:
        >>> findings = detect_secrets("api_key = 'AKIAEXAMPLE123'")
        >>> print(findings[0].detector_name)
        'aws_access_key_id'
    """
```

#### Code Organization

- One class per file for major components
- Related utilities can share a file
- Keep functions focused and under 50 lines when possible
- Use descriptive variable names; avoid single letters except for indices

---

## Testing Requirements

Hamburglar maintains high test coverage to ensure reliability.

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=hamburglar --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=hamburglar --cov-report=html
# Open htmlcov/index.html in your browser

# Run specific test file
pytest tests/test_regex_detector.py

# Run specific test
pytest tests/test_regex_detector.py::TestRegexDetector::test_detect_aws_key

# Run tests matching a pattern
pytest -k "aws"

# Skip integration tests (faster)
pytest -m "not integration"

# Run only integration tests
pytest -m "integration"
```

### Coverage Requirements

- **Minimum coverage: 90%**
- All new code must have tests
- Coverage is enforced in CI; PRs below threshold will fail

Check your changes' coverage:
```bash
pytest --cov=hamburglar --cov-report=term-missing tests/
```

### Test Organization

Tests live in the `tests/` directory:

```
tests/
├── conftest.py                 # Shared fixtures
├── fixtures/                   # Test data fixtures
│   └── git/                    # Git-specific fixtures
│       └── conftest.py
├── test_*.py                   # Test modules
```

### Writing Tests

#### Test Naming

Use descriptive names following `test_<function>_<scenario>_<expected>`:

```python
def test_detect_aws_key_valid_format_returns_finding():
    """Test that valid AWS access keys are detected."""
    ...

def test_detect_empty_content_returns_empty_list():
    """Test that empty content produces no findings."""
    ...

def test_scan_nonexistent_path_raises_error():
    """Test that scanning missing paths raises ScanError."""
    ...
```

#### Using Fixtures

Define reusable fixtures in `conftest.py`:

```python
import pytest
from hamburglar.detectors.regex_detector import RegexDetector

@pytest.fixture
def regex_detector():
    """Create a RegexDetector instance for testing."""
    return RegexDetector()

@pytest.fixture
def sample_content_with_secrets():
    """Return sample content containing various secrets."""
    return '''
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    password = "super_secret_123"
    api_key: sk-1234567890abcdef
    '''

@pytest.fixture
def temp_scan_dir(tmp_path):
    """Create a temporary directory with test files."""
    (tmp_path / "config.py").write_text('API_KEY = "test123"')
    (tmp_path / "readme.md").write_text("# Project Readme")
    return tmp_path
```

#### Test Examples

**Basic unit test:**
```python
import pytest
from hamburglar.detectors.regex_detector import RegexDetector
from hamburglar.core.models import Severity

class TestRegexDetector:
    @pytest.fixture
    def detector(self):
        return RegexDetector()

    def test_detect_aws_access_key_returns_finding(self, detector):
        content = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = detector.detect(content, "config.py")

        assert len(findings) == 1
        assert findings[0].detector_name == "aws_access_key_id"
        assert findings[0].severity == Severity.HIGH
        assert "AKIAIOSFODNN7EXAMPLE" in findings[0].matches

    def test_detect_empty_content_returns_empty_list(self, detector):
        findings = detector.detect("", "empty.txt")
        assert findings == []

    def test_detect_no_secrets_returns_empty_list(self, detector):
        content = "This is just regular code without secrets."
        findings = detector.detect(content, "regular.py")
        assert findings == []
```

**Async test:**
```python
import pytest
from hamburglar import scan_directory

@pytest.mark.asyncio
async def test_scan_directory_finds_secrets(temp_scan_dir):
    """Test that directory scanning finds secrets in files."""
    result = await scan_directory(str(temp_scan_dir))

    assert result.files_scanned > 0
    assert len(result.findings) >= 1

@pytest.mark.asyncio
async def test_scan_directory_respects_exclude_patterns(temp_scan_dir):
    """Test that exclude patterns filter out files."""
    result = await scan_directory(
        str(temp_scan_dir),
        exclude_patterns=["*.md"]
    )

    # Should not scan readme.md
    scanned_files = [f.file_path for f in result.findings]
    assert not any("readme.md" in f for f in scanned_files)
```

**Parametrized test:**
```python
import pytest
from hamburglar.core.models import Severity

@pytest.mark.parametrize("secret,expected_severity", [
    ("AKIAIOSFODNN7EXAMPLE", Severity.HIGH),
    ("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", Severity.HIGH),
    ("password123", Severity.LOW),
])
def test_detect_severity_levels(detector, secret, expected_severity):
    """Test that different secrets have correct severity levels."""
    content = f"secret = '{secret}'"
    findings = detector.detect(content, "test.py")

    assert len(findings) == 1
    assert findings[0].severity == expected_severity
```

**Integration test marker:**
```python
import pytest

@pytest.mark.integration
def test_docker_scan_works():
    """Test scanning works in Docker environment."""
    # This test requires Docker and is skipped in normal runs
    ...
```

### Test Best Practices

1. **Test one thing per test** - Keep tests focused and atomic
2. **Use descriptive assertions** - `assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"`
3. **Test edge cases** - Empty input, None values, malformed data
4. **Test error conditions** - Verify exceptions are raised when expected
5. **Avoid test interdependence** - Tests should be runnable in any order
6. **Mock external dependencies** - Network calls, file I/O outside fixtures
7. **Keep tests fast** - Individual tests should complete in under 1 second

---

## Pull Request Process

### Before You Start

1. **Check existing issues** - Is there already an issue or PR for this?
2. **Open an issue for large changes** - Discuss design before implementation
3. **Keep changes focused** - One feature or fix per PR

### Creating Your Branch

```bash
# Sync with upstream
git fetch upstream
git checkout master
git merge upstream/master

# Create a feature branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions/fixes

### Making Changes

1. **Write your code** following the style guide
2. **Add or update tests** for your changes
3. **Update documentation** if behavior changes
4. **Run all checks locally**:
   ```bash
   # All of these must pass
   ruff check .
   ruff format --check .
   mypy src/hamburglar
   pytest
   ```

### Committing

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```bash
git add .
git commit -m "feat: add detection for Azure service principal credentials"
```

Commit types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `test:` - Adding or updating tests
- `refactor:` - Code change that neither fixes a bug nor adds a feature
- `perf:` - Performance improvement
- `chore:` - Maintenance tasks

Examples:
```
feat: add SARIF output format for IDE integration
fix: handle UTF-16 encoded files in scanner
docs: update installation instructions for Docker
test: add coverage for entropy detector edge cases
refactor: simplify pattern matching logic in regex detector
```

### Submitting Your PR

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** on GitHub

3. **Fill out the PR template**:
   - Clear description of changes
   - Reference any related issues (`Fixes #123`)
   - Note any breaking changes
   - Add screenshots for UI changes

4. **Respond to review feedback** - Make requested changes, push updates

### PR Checklist

Before marking ready for review, ensure:

- [ ] Code follows the style guide (ruff passes)
- [ ] Type annotations are complete (mypy passes)
- [ ] All tests pass (pytest)
- [ ] New code has tests (coverage maintained)
- [ ] Documentation is updated if needed
- [ ] Commit messages follow conventions
- [ ] PR description is complete

### After Merging

- Delete your feature branch
- Pull the latest master to your local clone
- Celebrate your contribution! 🎉

---

## Issue Reporting Guidelines

### Bug Reports

When reporting a bug, include:

**Environment information:**
```bash
hamburglar --version
python --version
uname -a  # or systeminfo on Windows
```

**Bug report template:**

```markdown
## Description
A clear description of the bug.

## Steps to Reproduce
1. Run `hamburglar scan /path/to/dir`
2. Wait for scan to complete
3. See error

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened, including error messages.

## Environment
- Hamburglar version: 2.0.0
- Python version: 3.11.5
- OS: Ubuntu 22.04

## Additional Context
- Sample files (redacted) that reproduce the issue
- Configuration used (ham.conf or env vars)
- Relevant logs
```

### Feature Requests

When requesting a feature, include:

```markdown
## Feature Description
Clear description of the feature.

## Use Case
Why do you need this? What problem does it solve?

## Proposed Solution
How might this work? (Optional but helpful)

## Alternatives Considered
What other approaches could work?

## Additional Context
Examples, mockups, or references to similar features.
```

### Security Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

See [SECURITY.md](../SECURITY.md) for our security policy and how to report vulnerabilities responsibly.

---

## Architecture Overview

Understanding Hamburglar's architecture helps you contribute effectively.

### Project Structure

```
src/hamburglar/
├── __init__.py           # Package root, exports public API
├── api.py                # High-level convenience functions
│
├── cli/                  # Command-line interface
│   ├── __init__.py
│   └── main.py           # Typer CLI application
│
├── core/                 # Core scanning engine
│   ├── models.py         # Pydantic data models (Finding, ScanConfig, etc.)
│   ├── scanner.py        # Main Scanner class
│   ├── async_scanner.py  # Async scanning implementation
│   ├── file_reader.py    # File reading with encoding detection
│   ├── file_filter.py    # Pattern-based file filtering
│   ├── http_client.py    # HTTP client for web scanning
│   ├── exceptions.py     # Custom exception classes
│   ├── logging.py        # Logging configuration
│   ├── progress.py       # Progress tracking
│   └── stats.py          # Scan statistics
│
├── detectors/            # Detection implementations
│   ├── __init__.py       # BaseDetector, DetectorRegistry
│   ├── regex_detector.py # Regex-based pattern detection
│   ├── yara_detector.py  # YARA rule-based detection
│   ├── entropy_detector.py # Entropy-based secret detection
│   └── patterns/         # Pattern definition modules
│       ├── __init__.py   # Pattern categories
│       ├── api_keys.py   # API key patterns
│       ├── credentials.py # Credential patterns
│       └── ...           # Other pattern categories
│
├── scanners/             # Target-specific scanners
│   ├── __init__.py       # BaseScanner abstract class
│   ├── directory.py      # Local file/directory scanning
│   ├── git.py            # Git repository scanning
│   ├── git_history.py    # Git commit history analysis
│   └── web.py            # URL/website scanning
│
├── outputs/              # Output format implementations
│   ├── __init__.py       # BaseOutput, OutputRegistry
│   ├── json_output.py    # JSON format
│   ├── table_output.py   # Human-readable tables
│   ├── csv_output.py     # CSV format
│   ├── html_output.py    # HTML reports
│   ├── markdown_output.py # Markdown format
│   ├── sarif.py          # SARIF format (CI/IDE integration)
│   └── streaming.py      # Real-time streaming output
│
├── config/               # Configuration management
│   ├── __init__.py       # Config loading and merging
│   ├── schema.py         # Pydantic configuration schema
│   ├── loader.py         # Config file loading
│   └── env.py            # Environment variable handling
│
├── storage/              # Scan history persistence
│   ├── __init__.py       # Storage base classes
│   ├── json_file.py      # JSON file storage
│   └── sqlite.py         # SQLite database storage
│
├── plugins/              # Plugin system
│   ├── __init__.py       # PluginManager
│   ├── detector_plugin.py # Detector plugin interface
│   ├── output_plugin.py  # Output plugin interface
│   └── discovery.py      # Plugin discovery mechanisms
│
└── rules/                # YARA rule management
    ├── __init__.py       # Rule loading and compilation
    └── *.yar             # YARA rule files
```

### Core Concepts

#### 1. Data Models (`core/models.py`)

All data flows through Pydantic models:

- **`Finding`** - A single detection result with file path, detector name, matches, severity, and metadata
- **`GitFinding`** - Extends Finding with commit hash, author, date
- **`WebFinding`** - Extends Finding with URL and element type
- **`ScanConfig`** - Configuration for a scan operation
- **`ScanResult`** - Complete results including findings, stats, and metadata
- **`Severity`** - Enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **`OutputFormat`** - Enum: JSON, TABLE, SARIF, CSV, HTML, MARKDOWN

#### 2. Detectors

Detectors find secrets in content. All inherit from `BaseDetector`:

```python
class BaseDetector(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique detector identifier."""
        pass

    @abstractmethod
    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect secrets in content."""
        pass
```

Built-in detectors:
- **RegexDetector** - Pattern matching with 190+ regex patterns
- **YaraDetector** - YARA rule-based detection for binary patterns
- **EntropyDetector** - Shannon entropy analysis for random strings

#### 3. Scanners

Scanners handle different target types. All inherit from `BaseScanner`:

- **DirectoryScanner** - Local files and directories
- **GitScanner** - Clone and scan git repositories
- **GitHistoryScanner** - Analyze git commit history
- **WebScanner** - Fetch and analyze web pages

#### 4. Outputs

Output formatters convert results to different formats. All inherit from `BaseOutput`:

- Table (human-readable)
- JSON (machine-readable)
- CSV (spreadsheets)
- HTML (reports)
- Markdown (documentation)
- SARIF (security tools)
- NDJSON (streaming)

#### 5. Plugin System

Extend Hamburglar via plugins:

```python
from hamburglar.plugins import detector_plugin

@detector_plugin
class MyCustomDetector:
    name = "my_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        # Custom detection logic
        ...
```

### Data Flow

```
User Input (CLI/API)
        │
        ▼
┌──────────────────┐
│   ScanConfig     │ ← Configuration (files, CLI, env)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│     Scanner      │ ← DirectoryScanner/GitScanner/WebScanner
└────────┬─────────┘
         │
         │ For each file:
         ▼
┌──────────────────┐
│  File Reader     │ ← Encoding detection, content extraction
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Detectors      │ ← RegexDetector, YaraDetector, EntropyDetector
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│    Findings      │ ← Pattern matches with metadata
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   ScanResult     │ ← Aggregated findings + statistics
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Output Format   │ ← JSON, Table, SARIF, etc.
└────────┬─────────┘
         │
         ▼
    User Output
```

### Key Design Principles

1. **Modularity** - Components are loosely coupled with clear interfaces
2. **Extensibility** - Plugin system for custom detectors and outputs
3. **Performance** - Async scanning, concurrent file processing
4. **Type Safety** - Pydantic models and type annotations throughout
5. **Testability** - Dependency injection, interfaces for mocking

---

## Adding New Features

### Adding a Detection Pattern

1. Identify the appropriate category in `src/hamburglar/detectors/patterns/`
2. Add the pattern:
   ```python
   # In patterns/api_keys.py
   PATTERNS.append({
       "name": "new_service_api_key",
       "pattern": r"new_service_[a-zA-Z0-9]{32}",
       "severity": "high",
       "confidence": "high",
       "description": "New Service API Key",
   })
   ```
3. Add tests in `tests/test_patterns_api_keys.py`

### Adding a New Detector

1. Create `src/hamburglar/detectors/my_detector.py`:
   ```python
   from hamburglar.detectors import BaseDetector
   from hamburglar.core.models import Finding

   class MyDetector(BaseDetector):
       @property
       def name(self) -> str:
           return "my_detector"

       def detect(self, content: str, file_path: str = "") -> list[Finding]:
           findings = []
           # Detection logic here
           return findings
   ```
2. Register in `src/hamburglar/detectors/__init__.py`
3. Add tests in `tests/test_my_detector.py`

### Adding an Output Format

1. Create `src/hamburglar/outputs/my_output.py`:
   ```python
   from hamburglar.outputs import BaseOutput
   from hamburglar.core.models import ScanResult

   class MyOutput(BaseOutput):
       format_name = "myformat"

       def format(self, result: ScanResult) -> str:
           # Format logic here
           return formatted_output
   ```
2. Register in `src/hamburglar/outputs/__init__.py`
3. Add CLI option in `src/hamburglar/cli/main.py`
4. Add tests in `tests/test_my_output.py`

---

## Getting Help

- **Documentation**: [docs/](.)
- **Issues**: [GitHub Issues](https://github.com/needmorecowbell/Hamburglar/issues)
- **Discussions**: [GitHub Discussions](https://github.com/needmorecowbell/Hamburglar/discussions)

## Code of Conduct

We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Please be respectful and inclusive in all interactions.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](../LICENSE).
