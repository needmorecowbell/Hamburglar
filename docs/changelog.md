# Changelog

All notable changes to Hamburglar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024

### Overview

Version 2.0.0 is a complete rewrite of Hamburglar with a modern architecture, async/await support, enhanced detection capabilities, and comprehensive documentation. This is a major release with breaking changes from 1.x.

### Added

- **New CLI powered by Typer**
  - Modern command-line interface with rich output
  - Main commands: `scan`, `scan-git`, `scan-web`, `history`, `report`
  - Plugin management: `plugins list`, `plugins info`
  - Configuration management: `config show`, `config init`, `config validate`
  - Shell completion support for bash, zsh, and fish
  - Colored output with progress indicators
  - Exit codes: 0 (success with findings), 1 (error), 2 (no findings)

- **Enhanced Detection Engine**
  - Regex-based pattern detection with 160+ patterns across 7 categories
  - YARA rule support for binary file detection with 19 built-in rules
  - Entropy-based detection for encoded secrets (Shannon entropy)
  - Categorized patterns: api_keys, credentials, private_keys, cloud, crypto, network, generic
  - Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
  - Confidence levels: HIGH, MEDIUM, LOW

- **Multiple Output Formats**
  - Table (human-readable terminal output with color-coded severity)
  - JSON (machine-readable with full metadata)
  - CSV (RFC 4180 compliant for spreadsheet analysis)
  - HTML (standalone self-contained reports)
  - Markdown (GitHub-flavored with severity badges)
  - SARIF (SARIF 2.1.0 for GitHub/GitLab/Azure DevOps integration)
  - NDJSON (streaming newline-delimited JSON)

- **Git Integration**
  - Scan remote repositories via HTTPS or SSH URLs
  - Scan local git repositories
  - Git history scanning to find secrets in past commits
  - Branch selection with `--branch` flag
  - Configurable history depth with `--depth`
  - Secret timeline tracking

- **Web Scanning**
  - Fetch and scan web URLs for secrets
  - HTML content extraction with JavaScript scanning
  - Link following with configurable depth
  - Robots.txt parsing and respect

- **Configuration System**
  - YAML, TOML, and JSON configuration file support
  - 15 environment variables with `HAMBURGLAR_` prefix
  - Hierarchical config search (CWD → parent directories → ~/.config/hamburglar)
  - Per-project and global configuration
  - Configuration validation with `config validate` command

- **Plugin System**
  - Custom detector plugins with full API access
  - Custom output format plugins
  - Four plugin discovery methods (entry points, directories, decorators, manual)
  - Plugin configuration via YAML and environment variables

- **Scan History & Storage**
  - SQLite storage backend for persistent results
  - View past scans with `history` command
  - Generate reports with `report` command
  - Filter by date range, severity, detector, file path

- **Async/Concurrent Architecture**
  - Fully async implementation with asyncio
  - Parallel file scanning with configurable concurrency
  - Streaming results as they're discovered
  - Cancellation support

- **Python Library API**
  - High-level functions: `scan_directory()`, `scan_git()`, `scan_url()`
  - Low-level `AsyncScanner` class for fine-grained control
  - Pydantic models for data validation
  - Type hints throughout

- **Docker Support**
  - Multi-stage Dockerfile for minimal image size
  - Docker Compose configuration included

- **Comprehensive Documentation**
  - Installation guide
  - Quickstart tutorial
  - CLI reference
  - Configuration guide
  - Detector documentation
  - Output format guide
  - Plugin development guide
  - Contributing guidelines

### Changed

- Complete rewrite in modern Python (3.9+)
- Pydantic models for data validation
- Modular architecture with clear separation of concerns
- Standardized severity levels (critical, high, medium, low)
- Confidence scores for all findings
- Improved pattern accuracy and reduced false positives

### Breaking Changes

- **CLI Interface**: The command-line interface has completely changed
  - Old: `hamburglar -u URL` → New: `hamburglar scan-web URL`
  - Old: `hamburglar -p PATH` → New: `hamburglar scan PATH`
  - Old: `hamburglar -g REPO` → New: `hamburglar scan-git REPO`

- **Output Format**: JSON output structure has changed
  - Findings now include more metadata
  - Different field names and structure

- **Configuration**: Configuration file format has changed
  - Old INI-style `ham.conf` is no longer supported
  - Use YAML, TOML, or JSON configuration files

- **Python Version**: Requires Python 3.9+ (was 3.6+)

### Migration Guide

#### CLI Migration

| Old Command | New Command |
|-------------|-------------|
| `hamburglar -u https://example.com` | `hamburglar scan-web https://example.com` |
| `hamburglar -p /path/to/dir` | `hamburglar scan /path/to/dir` |
| `hamburglar -g https://github.com/user/repo` | `hamburglar scan-git https://github.com/user/repo` |
| `hamburglar -w wordlist.txt` | Use custom patterns in config |

#### Configuration Migration

Old `ham.conf`:
```ini
[paths]
wordlist = wordlist.txt

[options]
output = output.json
```

New `hamburglar.yml`:
```yaml
patterns:
  custom:
    - name: my_pattern
      pattern: "pattern_regex"
      severity: high

output:
  format: json
  file: output.json
```

#### Script Migration

Old Python usage:
```python
from hamburglar import Hamburglar
h = Hamburglar(url="https://example.com")
results = h.analyze()
```

New Python usage:
```python
from hamburglar import scan_url
results = scan_url("https://example.com")
for finding in results.findings:
    print(f"{finding.severity}: {finding.pattern_name}")
```

### Deprecated

- Legacy `ham.conf` configuration file (use YAML/TOML/JSON)
- Direct script execution (`python hamburglar.py`)

### Removed

- Python 3.6, 3.7, 3.8 support
- Old CLI interface
- Legacy pattern format
- Built-in wordlist functionality (replaced by pattern system)

## [1.x] - Previous Versions

For changes in version 1.x and earlier, see the [legacy changelog](https://github.com/needmorecowbell/Hamburglar/blob/v1/CHANGELOG.md).
