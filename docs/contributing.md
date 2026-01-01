# Contributing to Hamburglar

Thank you for your interest in contributing to Hamburglar! This guide will help you get started.

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- A code editor (VS Code, PyCharm, etc.)

### Setting Up Your Environment

1. Fork the repository on GitHub

2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Hamburglar.git
   cd Hamburglar
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

5. Verify the setup:
   ```bash
   pytest
   hamburglar --version
   ```

## Code Style

### Formatting and Linting

We use `ruff` for both linting and formatting:

```bash
# Check for issues
ruff check .

# Auto-fix issues
ruff check --fix .

# Format code
ruff format .
```

### Type Checking

We use `mypy` for static type checking:

```bash
mypy src/hamburglar
```

### Style Guidelines

- Follow PEP 8 conventions
- Use type hints for all function signatures
- Maximum line length: 100 characters
- Use descriptive variable and function names
- Write docstrings for public functions and classes

### Docstring Format

Use Google-style docstrings:

```python
def detect_secrets(content: str, file_path: str | None = None) -> list[Finding]:
    """Detect secrets in the given content.

    Args:
        content: The file content to scan.
        file_path: Optional path to the file for context.

    Returns:
        A list of Finding objects representing detected secrets.

    Raises:
        ValueError: If content is empty.
    """
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=hamburglar --cov-report=html

# Run specific test file
pytest tests/test_detectors.py

# Run specific test
pytest tests/test_detectors.py::test_aws_key_detection

# Run tests matching a pattern
pytest -k "test_aws"
```

### Test Coverage

We aim for 90%+ test coverage. Check coverage locally:

```bash
pytest --cov=hamburglar --cov-report=term-missing
```

### Writing Tests

- Place tests in the `tests/` directory
- Mirror the source structure (e.g., `src/hamburglar/detectors/` → `tests/test_detectors/`)
- Use descriptive test names: `test_<function>_<scenario>_<expected_result>`
- Use fixtures for common test data
- Test edge cases and error conditions

Example test:

```python
import pytest
from hamburglar.detectors.regex_detector import RegexDetector

class TestRegexDetector:
    @pytest.fixture
    def detector(self):
        return RegexDetector()

    def test_detect_aws_access_key_finds_valid_key(self, detector):
        content = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = detector.detect(content)

        assert len(findings) == 1
        assert findings[0].pattern_name == "aws_access_key_id"
        assert findings[0].severity.value == "high"

    def test_detect_empty_content_returns_empty_list(self, detector):
        findings = detector.detect("")
        assert findings == []

    def test_detect_no_secrets_returns_empty_list(self, detector):
        content = "This is just regular code without secrets."
        findings = detector.detect(content)
        assert findings == []
```

## Pull Request Process

### Before Submitting

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit:
   ```bash
   git add .
   git commit -m "Add feature: description of changes"
   ```

3. Run all checks:
   ```bash
   ruff check .
   ruff format --check .
   mypy src/hamburglar
   pytest
   ```

4. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

### PR Guidelines

- Fill out the PR template completely
- Reference any related issues
- Include tests for new functionality
- Update documentation if needed
- Keep PRs focused and reasonably sized
- Respond to review feedback promptly

### PR Title Format

Use conventional commit format:

- `feat: Add new detection pattern for XYZ`
- `fix: Handle empty files in scanner`
- `docs: Update installation instructions`
- `test: Add tests for entropy detector`
- `refactor: Simplify pattern matching logic`

## Issue Reporting

### Bug Reports

Include:
- Hamburglar version (`hamburglar --version`)
- Python version (`python --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

### Feature Requests

Include:
- Clear description of the feature
- Use case / motivation
- Proposed implementation (if any)
- Alternatives considered

## Architecture Overview

```
src/hamburglar/
├── cli/           # Command-line interface (Typer)
├── core/          # Core scanning engine
│   ├── models.py  # Pydantic data models
│   ├── scanner.py # Base scanner class
│   └── ...
├── detectors/     # Detection implementations
│   ├── regex_detector.py
│   ├── yara_detector.py
│   └── patterns/  # Pattern definitions
├── scanners/      # Target-specific scanners
│   ├── directory.py
│   ├── git.py
│   └── web.py
├── outputs/       # Output formatters
├── config/        # Configuration management
├── storage/       # Scan history storage
└── plugins/       # Plugin system
```

### Key Design Principles

1. **Modularity**: Components are loosely coupled
2. **Extensibility**: Plugin system for custom behavior
3. **Performance**: Async/concurrent scanning
4. **Type Safety**: Pydantic models and type hints
5. **Testability**: Dependency injection and interfaces

## Getting Help

- Open an issue for bugs or features
- Start a discussion for questions
- Join our community chat (if available)

## Code of Conduct

Please be respectful and inclusive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
