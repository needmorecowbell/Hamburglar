# Hamburglar

<p align="center">
    <img src="https://user-images.githubusercontent.com/7833164/51336290-29a79600-1a52-11e9-96a1-beac9207fdab.gif" alt="Hamburglar Logo">
</p>

<p align="center">
    <strong>Stop secrets from escaping. Scan files, git repos, and URLs for API keys, credentials, and sensitive data.</strong>
</p>

<p align="center">
    <a href="https://pypi.org/project/hamburglar/"><img src="https://img.shields.io/pypi/v/hamburglar" alt="PyPI"></a>
    <a href="https://pypi.org/project/hamburglar/"><img src="https://img.shields.io/pypi/pyversions/hamburglar" alt="Python Versions"></a>
    <a href="https://hub.docker.com/r/hamburglar/hamburglar"><img src="https://img.shields.io/docker/v/hamburglar/hamburglar?label=docker" alt="Docker"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
</p>

---

## Demo

<!-- TODO: Replace with actual asciicast recording -->
<p align="center">
    <img src="https://via.placeholder.com/800x400?text=Demo+Coming+Soon" alt="Hamburglar Demo">
</p>

<p align="center"><em>See Hamburglar in action: scanning a codebase for secrets in seconds</em></p>

---

## Why Hamburglar?

Secrets in source code are a leading cause of security breaches. Hamburglar helps you find them before attackers do:

- **Catch secrets early** - Scan during development, in CI/CD, or before commits
- **Comprehensive detection** - 160+ patterns for API keys, credentials, private keys, tokens, and more
- **Multiple sources** - Local files, git repositories (including history), and web URLs
- **Fast** - Async architecture scans large codebases in seconds
- **Extensible** - Add custom patterns, YARA rules, or build plugins

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-Source Scanning** | Scan local files/directories, git repositories (with full commit history), and web URLs |
| **160+ Detection Patterns** | API keys, credentials, private keys, tokens, connection strings, crypto wallets, and more |
| **YARA Rules** | Use 19 built-in YARA rules or add your own for advanced pattern matching |
| **Entropy Detection** | Find high-entropy strings that may be secrets |
| **7 Output Formats** | Table, JSON, CSV, HTML, Markdown, SARIF, and NDJSON |
| **Plugin System** | Extend with custom detectors and output formats |
| **CI/CD Ready** | SARIF output for GitHub/GitLab security integration |
| **Docker Support** | Run in containers with Docker and Docker Compose |
| **Python Library** | Use programmatically with async/await support |

---

## What Hamburglar Finds

<table>
<tr>
<td width="50%">

**API Keys & Tokens**
- AWS Access Keys
- Google Cloud credentials
- Azure credentials
- GitHub/GitLab tokens
- Stripe, Twilio, Slack tokens
- 30+ more services

</td>
<td width="50%">

**Credentials & Secrets**
- Passwords in config files
- Database connection strings
- OAuth tokens & JWTs
- Basic auth headers
- SMTP/email credentials

</td>
</tr>
<tr>
<td>

**Private Keys**
- RSA/DSA/EC private keys
- SSH private keys
- PGP private keys
- SSL/TLS certificates

</td>
<td>

**Other Sensitive Data**
- IPv4/IPv6 addresses
- URLs and endpoints
- Email addresses
- Cryptocurrency addresses
- Custom patterns you define

</td>
</tr>
</table>

---

## Installation

### From PyPI (Recommended)

```bash
pip install hamburglar
```

### Using Docker

```bash
docker pull ghcr.io/needmorecowbell/hamburglar:latest
```

### From Source

```bash
git clone https://github.com/needmorecowbell/Hamburglar.git
cd Hamburglar
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/needmorecowbell/Hamburglar.git
cd Hamburglar
pip install -e ".[dev]"
```

---

## Quick Start

### Scan a Directory

```bash
hamburglar scan /path/to/code
```

### Scan with JSON Output

```bash
hamburglar scan /path/to/code --format json --output results.json
```

### Scan a Git Repository (Including History)

```bash
hamburglar scan-git https://github.com/user/repo
```

### Scan a Website

```bash
hamburglar scan-web https://example.com
```

### Use YARA Rules

```bash
hamburglar scan /path/to/code --yara
```

### Filter by Category

```bash
hamburglar scan /path/to/code --categories api_keys,credentials
```

### CI/CD Integration (Fail on Findings)

```bash
hamburglar scan . --fail-on-findings --format sarif --output results.sarif
```

---

## Python Library

```python
import asyncio
from hamburglar import scan_directory, scan_git, scan_url

# Scan a directory
result = asyncio.run(scan_directory("/path/to/code"))

for finding in result.findings:
    print(f"[{finding.severity}] {finding.file_path}:{finding.line_number}")
    print(f"  {finding.detector_name}: {finding.match}")

# Scan a git repository (including commit history)
result = asyncio.run(scan_git("https://github.com/user/repo", include_history=True))

# Scan a URL
result = asyncio.run(scan_url("https://example.com", depth=2))
```

---

## Docker Usage

```bash
# Scan a local directory
docker run --rm -v /path/to/code:/data hamburglar scan /data

# Scan with JSON output
docker run --rm \
    -v /path/to/code:/data:ro \
    -v /path/to/output:/output \
    hamburglar scan /data --format json --output /output/results.json

# Scan a git repository
docker run --rm hamburglar scan-git https://github.com/user/repo
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

```yaml
# .pre-commit-config.yaml
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

## Output Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| `table` | Human-readable table (default) | Interactive use |
| `json` | Structured JSON | Programmatic processing |
| `sarif` | SARIF 2.1.0 format | GitHub/GitLab/Azure DevOps integration |
| `csv` | Comma-separated values | Spreadsheet analysis |
| `html` | Styled HTML report | Sharing with stakeholders |
| `markdown` | Markdown table | Documentation |
| `ndjson` | Newline-delimited JSON | Streaming/log processing |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation](docs/installation.md) | Detailed installation instructions and requirements |
| [Quickstart](docs/quickstart.md) | Get started with common use cases |
| [CLI Reference](docs/cli-reference.md) | Complete command-line documentation |
| [Configuration](docs/configuration.md) | Configuration files and environment variables |
| [Detectors](docs/detectors.md) | Detection patterns, categories, and YARA rules |
| [Outputs](docs/outputs.md) | Output format details and integrations |
| [Plugins](docs/plugins.md) | Creating custom detector and output plugins |
| [Contributing](docs/contributing.md) | Development setup and contribution guidelines |
| [Changelog](CHANGELOG.md) | Version history and release notes |

---

## Contributing

We welcome contributions! Here's how to get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`pytest && ruff check src/`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines, code style, and development setup.

### Contributors

Thank you to everyone who has contributed to Hamburglar:

- [adi928](https://github.com/adi928)
- [jaeger-2601](https://github.com/jaeger-2601)
- [tijko](https://github.com/tijko)
- [joanbono](https://github.com/joanbono) and [Xumeiquer](https://github.com/Xumeiquer) for YARA rules from [yara-forensics](https://github.com/Xumeiquer/yara-forensics)

---

## Security

For information about reporting security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## License

Hamburglar is released under the [MIT License](LICENSE).

---

## Links

- **GitHub Repository**: [github.com/needmorecowbell/Hamburglar](https://github.com/needmorecowbell/Hamburglar)
- **Issue Tracker**: [github.com/needmorecowbell/Hamburglar/issues](https://github.com/needmorecowbell/Hamburglar/issues)
- **PyPI Package**: [pypi.org/project/hamburglar](https://pypi.org/project/hamburglar/)
- **Docker Hub**: [hub.docker.com/r/hamburglar/hamburglar](https://hub.docker.com/r/hamburglar/hamburglar)
