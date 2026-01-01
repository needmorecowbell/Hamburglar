# Hamburglar

<p align="center">
    <img src="https://user-images.githubusercontent.com/7833164/51336290-29a79600-1a52-11e9-96a1-beac9207fdab.gif" alt="Hamburglar Logo">
</p>

<p align="center">
    <strong>A static analysis tool for extracting sensitive information from files, git repositories, and URLs using regex patterns and YARA rules</strong>
</p>

<p align="center">
    <a href="https://pypi.org/project/hamburglar/"><img src="https://img.shields.io/pypi/v/hamburglar" alt="PyPI"></a>
    <a href="https://pypi.org/project/hamburglar/"><img src="https://img.shields.io/pypi/pyversions/hamburglar" alt="Python Versions"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
</p>

---

## Features

- **Multi-source scanning**: Scan local files/directories, git repositories (with history), and web URLs
- **Secret detection**: Find API keys, credentials, private keys, tokens, and other sensitive data
- **YARA rules**: Use YARA rules for advanced pattern matching and file signature detection
- **Multiple output formats**: JSON, SARIF, CSV, HTML, Markdown, and table formats
- **Async architecture**: Fast, concurrent scanning with configurable concurrency limits
- **Library API**: Use as a Python library or command-line tool
- **Docker support**: Run in containers with Docker and Docker Compose

## What Hamburglar Can Find

- API keys (AWS, GCP, Azure, GitHub, Stripe, etc.)
- Credentials and passwords
- Private keys (RSA, DSA, EC, SSH)
- Database connection strings
- OAuth tokens and JWTs
- IPv4/IPv6 addresses
- Email addresses
- URLs and endpoints
- Cryptocurrency addresses
- Custom patterns via regex or YARA rules

---

## Installation

### From PyPI (Recommended)

```bash
pip install hamburglar
```

### From Source

```bash
git clone https://github.com/needmorecowbell/Hamburglar.git
cd Hamburglar
pip install -e .
```

### Using Docker

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/needmorecowbell/hamburglar:latest

# Or build locally
docker build -t hamburglar .
```

### Development Installation

```bash
git clone https://github.com/needmorecowbell/Hamburglar.git
cd Hamburglar
pip install -e ".[dev]"
```

---

## Quick Start

### Command Line

```bash
# Scan a directory for secrets
hamburglar scan /path/to/code

# Scan with JSON output
hamburglar scan /path/to/code --format json --output results.json

# Scan a git repository (includes commit history)
hamburglar scan-git https://github.com/user/repo

# Scan a website
hamburglar scan-web https://example.com

# Use YARA rules for detection
hamburglar scan /path/to/code --yara

# Only scan for specific categories
hamburglar scan /path/to/code --categories api_keys,credentials
```

### Python Library

```python
import asyncio
from hamburglar import scan_directory, scan_git, scan_url

# Scan a directory
result = asyncio.run(scan_directory("/path/to/code"))
for finding in result.findings:
    print(f"{finding.file_path}: {finding.detector_name} - {finding.match}")

# Scan a git repository
result = asyncio.run(scan_git("https://github.com/user/repo"))

# Scan a URL
result = asyncio.run(scan_url("https://example.com"))
```

---

## CLI Usage

### Main Commands

```
hamburglar --help

Commands:
  scan       Scan a file or directory for secrets
  scan-git   Scan a git repository (local or remote) for secrets
  scan-web   Scan a URL for secrets
  history    View and manage scan history
  report     Generate reports from stored scan results
```

### Scanning Files and Directories

```bash
# Basic directory scan
hamburglar scan /path/to/code

# Recursive scan (default)
hamburglar scan /path/to/code --recursive

# Non-recursive scan
hamburglar scan /path/to/code --no-recursive

# Specify output format
hamburglar scan /path/to/code --format json
hamburglar scan /path/to/code --format sarif
hamburglar scan /path/to/code --format csv
hamburglar scan /path/to/code --format html
hamburglar scan /path/to/code --format markdown

# Save output to file
hamburglar scan /path/to/code --output results.json --format json

# Use expanded patterns (more comprehensive)
hamburglar scan /path/to/code --expanded

# Filter by minimum severity
hamburglar scan /path/to/code --severity high

# Only specific pattern categories
hamburglar scan /path/to/code --categories api_keys,credentials,private_keys

# Exclude certain categories
hamburglar scan /path/to/code --exclude-categories urls,emails

# Use YARA rules
hamburglar scan /path/to/code --yara
hamburglar scan /path/to/code --yara --yara-rules /path/to/rules

# Blacklist/whitelist patterns
hamburglar scan /path/to/code --blacklist "*.log,node_modules/*"
hamburglar scan /path/to/code --whitelist "*.py,*.js"

# Verbose output
hamburglar scan /path/to/code --verbose

# Quiet mode (minimal output)
hamburglar scan /path/to/code --quiet

# Fail with exit code 1 if findings detected (useful for CI/CD)
hamburglar scan /path/to/code --fail-on-findings
```

### Scanning Git Repositories

```bash
# Scan a remote repository
hamburglar scan-git https://github.com/user/repo

# Scan a local git directory
hamburglar scan-git /path/to/local/repo

# Include commit history (default)
hamburglar scan-git https://github.com/user/repo --history

# Skip commit history
hamburglar scan-git https://github.com/user/repo --no-history

# Limit history depth
hamburglar scan-git https://github.com/user/repo --depth 100

# Scan specific branch
hamburglar scan-git https://github.com/user/repo --branch develop

# Specify clone directory
hamburglar scan-git https://github.com/user/repo --clone-dir /tmp/repo-clone

# Output format
hamburglar scan-git https://github.com/user/repo --format json --output results.json
```

### Scanning Web URLs

```bash
# Scan a single page
hamburglar scan-web https://example.com

# Follow links to specified depth
hamburglar scan-web https://example.com --depth 2

# Include JavaScript files (default)
hamburglar scan-web https://example.com --scripts

# Skip JavaScript scanning
hamburglar scan-web https://example.com --no-scripts

# Ignore robots.txt
hamburglar scan-web https://example.com --no-robots

# Custom timeout
hamburglar scan-web https://example.com --timeout 60

# Output format
hamburglar scan-web https://example.com --format json --output results.json
```

### Scan History and Reports

```bash
# View recent scans
hamburglar history

# View last N scans
hamburglar history --limit 20

# Generate report from a previous scan
hamburglar report --scan-id <scan-id> --format html --output report.html
```

---

## Library Usage

### High-Level API

The high-level API provides simple functions for common scanning tasks:

```python
import asyncio
from hamburglar import scan_directory, scan_git, scan_url

# Basic directory scan
async def scan_my_code():
    result = await scan_directory("/path/to/code")

    print(f"Scanned {result.files_scanned} files")
    print(f"Found {len(result.findings)} potential secrets")

    for finding in result.findings:
        print(f"  [{finding.severity}] {finding.file_path}:{finding.line_number}")
        print(f"    {finding.detector_name}: {finding.match}")

asyncio.run(scan_my_code())
```

### Configuring Pattern Detection

```python
import asyncio
from hamburglar import scan_directory
from hamburglar.detectors.patterns import PatternCategory, Confidence

# Only scan for API keys and credentials
result = asyncio.run(scan_directory(
    "/path/to/code",
    use_expanded_patterns=True,
    enabled_categories=[PatternCategory.API_KEYS, PatternCategory.CREDENTIALS]
))

# Exclude URLs and emails
result = asyncio.run(scan_directory(
    "/path/to/code",
    disabled_categories=[PatternCategory.URLS, PatternCategory.EMAILS]
))

# Only high-confidence matches
result = asyncio.run(scan_directory(
    "/path/to/code",
    min_confidence=Confidence.HIGH
))
```

### Git Repository Scanning

```python
import asyncio
from hamburglar import scan_git

# Scan a remote repository with history
result = asyncio.run(scan_git(
    "https://github.com/user/repo",
    include_history=True,
    depth=100  # Last 100 commits
))

# Scan a local git directory
result = asyncio.run(scan_git(
    "/path/to/local/repo",
    include_history=False  # Only current files
))
```

### URL Scanning

```python
import asyncio
from hamburglar import scan_url

# Scan with link following
result = asyncio.run(scan_url(
    "https://example.com",
    depth=2,              # Follow links 2 levels deep
    include_scripts=True  # Scan JavaScript files
))
```

### Low-Level API

For more control, use the Scanner classes directly:

```python
import asyncio
from pathlib import Path
from hamburglar import Scanner, ScanConfig, Finding

async def advanced_scan():
    config = ScanConfig(
        target_path=Path("/path/to/scan"),
        recursive=True,
        blacklist=["node_modules", ".git", "*.log"],
    )

    scanner = Scanner(config)
    result = await scanner.scan()

    return result

result = asyncio.run(advanced_scan())
```

### Custom Detectors

```python
from hamburglar import BaseDetector, Finding, Severity
from hamburglar.detectors import RegexDetector

# Create a custom regex detector
custom_patterns = {
    "internal_api_key": {
        "pattern": r"INTERNAL_KEY_[A-Z0-9]{32}",
        "severity": "high",
        "description": "Internal API key detected"
    }
}

detector = RegexDetector(patterns=custom_patterns)
```

---

## Docker Usage

### Basic Docker Commands

```bash
# Scan a local directory
docker run --rm -v /path/to/code:/data hamburglar scan /data

# Scan with JSON output saved to host
docker run --rm \
    -v /path/to/code:/data:ro \
    -v /path/to/output:/output \
    hamburglar scan /data --format json --output /output/results.json

# Scan a git repository
docker run --rm hamburglar scan-git https://github.com/user/repo

# Use YARA rules
docker run --rm -v /path/to/code:/data hamburglar scan /data --yara

# Interactive shell for debugging
docker run --rm -it --entrypoint /bin/bash hamburglar
```

### Docker Compose

The project includes a `docker-compose.yml` for easy container management:

```yaml
# docker-compose.yml is included in the repository
# Mount your target directory and run scans

# Build the image
docker compose build

# Scan a directory (mount to ./target)
docker compose run --rm hamburglar scan /data

# Scan with output saved
docker compose run --rm hamburglar scan /data --format json --output /output/results.json

# Scan a git repository
docker compose run --rm hamburglar scan-git https://github.com/user/repo
```

#### Docker Compose Configuration

```yaml
services:
  hamburglar:
    build: .
    image: hamburglar:latest
    volumes:
      # Mount your target directory here
      - ./target:/data:ro
      # Mount output directory for results
      - ./output:/output
    environment:
      - PYTHONUNBUFFERED=1
      # - HAMBURGLAR_LOG_LEVEL=DEBUG
```

#### Volume Mounts

| Mount Point | Purpose |
|-------------|---------|
| `/data` | Target directory to scan (read-only recommended) |
| `/output` | Output directory for scan results |

---

## Output Formats

Hamburglar supports multiple output formats:

| Format | Extension | Description |
|--------|-----------|-------------|
| `table` | `.txt` | Human-readable table (default) |
| `json` | `.json` | Machine-readable JSON |
| `sarif` | `.sarif.json` | SARIF format for IDE/CI integration |
| `csv` | `.csv` | CSV for spreadsheet analysis |
| `html` | `.html` | HTML report with styling |
| `markdown` | `.md` | Markdown for documentation |

### Example JSON Output

```json
{
  "scan_id": "abc123",
  "target": "/path/to/code",
  "timestamp": "2024-01-15T10:30:00Z",
  "files_scanned": 150,
  "findings": [
    {
      "file_path": "/path/to/code/config.py",
      "line_number": 42,
      "detector_name": "aws_access_key",
      "match": "AKIA...",
      "severity": "critical",
      "confidence": "high"
    }
  ]
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Hamburglar
        run: pip install hamburglar

      - name: Run security scan
        run: hamburglar scan . --fail-on-findings --format sarif --output results.sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: hamburglar
        name: Hamburglar Security Scan
        entry: hamburglar scan . --fail-on-findings --quiet
        language: system
        pass_filenames: false
```

---

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `HAMBURGLAR_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Pattern Categories

Available pattern categories for filtering:

- `api_keys` - API keys and tokens
- `credentials` - Passwords and authentication credentials
- `private_keys` - RSA, DSA, EC, and SSH private keys
- `cloud` - Cloud provider credentials (AWS, GCP, Azure)
- `database` - Database connection strings
- `urls` - URLs and endpoints
- `emails` - Email addresses
- `crypto` - Cryptocurrency addresses and keys

---

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=hamburglar --cov-report=html

# Run integration tests (requires Docker)
pytest -m integration
```

### Code Quality

```bash
# Lint with ruff
ruff check src/ tests/

# Type check with mypy
mypy src/hamburglar

# Format code
ruff format src/ tests/
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

Thank you to all contributors:
- [adi928](https://github.com/adi928)
- [jaeger-2601](https://github.com/jaeger-2601)
- [tijko](https://github.com/tijko)
- [joanbono](https://github.com/joanbono) and [Xumeiquer](https://github.com/Xumeiquer) for the rules from [yara-forensics](https://github.com/Xumeiquer/yara-forensics)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Links

- [GitHub Repository](https://github.com/needmorecowbell/Hamburglar)
- [Issue Tracker](https://github.com/needmorecowbell/Hamburglar/issues)
- [Changelog](https://github.com/needmorecowbell/Hamburglar/releases)
