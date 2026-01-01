# Contributing to Hamburglar

Thank you for your interest in contributing to Hamburglar! Whether you're fixing a bug, adding a feature, or improving documentation, your contributions are welcome.

## Quick Start

1. **Fork the repository** on [GitHub](https://github.com/needmorecowbell/Hamburglar)

2. **Clone your fork and set up the development environment**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Hamburglar.git
   cd Hamburglar
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make your changes** following our coding standards

5. **Run checks before committing**:
   ```bash
   ruff check .           # Linting
   ruff format .          # Formatting
   mypy src/hamburglar    # Type checking
   pytest                 # Tests
   ```

6. **Commit with a descriptive message**:
   ```bash
   git commit -m "feat: add your feature description"
   ```

7. **Push and open a Pull Request**

## Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Adding or updating tests
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

## Full Documentation

For comprehensive contribution guidelines, including:

- Development environment setup
- Code style guide and conventions
- Testing requirements (90% coverage)
- Pull request process
- Architecture overview
- Adding new detectors and output formats

See the **[full contributing guide](docs/contributing.md)**.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold a welcoming, inclusive, and respectful environment.

## Reporting Issues

- **Bugs**: [Open a bug report](https://github.com/needmorecowbell/Hamburglar/issues/new?template=bug_report.md)
- **Features**: [Request a feature](https://github.com/needmorecowbell/Hamburglar/issues/new?template=feature_request.md)
- **Security**: See [SECURITY.md](SECURITY.md) for reporting vulnerabilities

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
